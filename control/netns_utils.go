/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	NsName        = "daens"
	HostVethName  = "dae0"
	NsVethName    = "dae0peer"
	DaeVethTxQLen = 1000
)

var (
	daeNetns     *DaeNetns
	once         sync.Once
	setNetnsFunc = netns.Set
	// The named-netns lifecycle below touches /run/netns, the kernel and the
	// host links. These seams keep its tests hermetic: the real calls would
	// create or destroy real namespaces, mount over /run/netns, or delete a
	// live dae0 on a developer host, and the setupNetns fail-fast test must
	// prove NewNamed stays unreached rather than observe a real one appear.
	deleteNamedNetnsFunc = DeleteNamedNetns
	newNamedNetnsFunc    = netns.NewNamed
	deleteLinkFunc       = DeleteLink
	unmountFunc          = unix.Unmount
	mountFunc            = unix.Mount
	// netnsNamedDir holds the named netns mount points; tests redirect it to a
	// scratch directory.
	netnsNamedDir = "/run/netns"
)

type DaeNetns struct {
	log           *logrus.Logger
	kernelVersion *internal.Version
	useNetkit     bool // Whether Netkit device is being used

	setupDone atomic.Bool
	mu        sync.Mutex

	handlesInitialized bool

	dae0, dae0peer netlink.Link
	hostNs, daeNs  netns.NsHandle
}

func InitDaeNetns(log *logrus.Logger) {
	once.Do(func() {
		daeNetns = &DaeNetns{
			hostNs: netns.None(),
			daeNs:  netns.None(),
		}
	})
	ns := GetDaeNetns()
	// The shared instance stays reachable by the previous control-plane
	// generation while a reload builds the next one, so every mutable field
	// is written under ns.mu and all readers take the same mutex.
	// Initialize kernel version for Netkit support detection
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		log.WithError(err).Warn("Failed to get kernel version, Netkit support disabled")
		kernelVersion = internal.Version{0, 0, 0}
	}
	ns.mu.Lock()
	ns.log = log
	ns.kernelVersion = &kernelVersion
	ns.mu.Unlock()
}

func GetDaeNetns() *DaeNetns {
	return daeNetns
}

func (ns *DaeNetns) NetnsID() (int, error) {
	ns.mu.Lock()
	daeNs := ns.daeNs
	ns.mu.Unlock()
	return netlink.GetNetNsIdByFd(int(daeNs))
}

func (ns *DaeNetns) Dae0() netlink.Link {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.dae0
}

func (ns *DaeNetns) Dae0Peer() netlink.Link {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.dae0peer
}

// DeviceType returns the type of the dae0 device ("netkit" or "veth").
func (ns *DaeNetns) DeviceType() string {
	ns.mu.Lock()
	useNetkit := ns.useNetkit
	ns.mu.Unlock()
	if useNetkit {
		return "netkit"
	}
	return "veth"
}

// IsUsingNetkit returns true if Netkit device is being used.
func (ns *DaeNetns) IsUsingNetkit() bool {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.useNetkit
}

func (ns *DaeNetns) Setup() (err error) {
	_, err = ns.SetupWithOwnership()
	return err
}

// SetupWithOwnership creates the dae network namespace when needed and reports
// whether this call created it. Callers that own the created namespace can
// release it if a later construction step fails.
func (ns *DaeNetns) SetupWithOwnership() (created bool, err error) {
	if ns.setupDone.Load() {
		return false, nil
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.setupDone.Load() {
		return false, nil
	}
	if !ns.handlesInitialized {
		ns.hostNs = netns.None()
		ns.daeNs = netns.None()
		ns.handlesInitialized = true
	}
	if err = ns.setup(); err != nil {
		return true, err
	}
	ns.setupDone.Store(true)
	return true, nil
}

func (ns *DaeNetns) Close() (err error) {
	if ns == nil {
		return nil
	}

	ns.mu.Lock()
	// cleanupErr is reported after the deferred unlock: a slow log writer must
	// not stall the other DaeNetns readers, which take this same mutex.
	var cleanupErr error
	log := ns.log
	defer func() {
		ns.mu.Unlock()
		if cleanupErr == nil || log == nil {
			return
		}
		// A mount point that survives this shutdown is the first occurrence
		// of the stuck state (issue #1109). The next start recovers by
		// covering the directory with a fresh tmpfs, or fail-fasts with the
		// real errnos when the environment denies that mount; report it here
		// while the cause is fresh, but do not fail the shutdown for it: the
		// namespace dies with the process anyway, and the setup-failure and
		// reload handoff callers must not treat a leftover mount as a
		// lifecycle failure.
		log.WithError(cleanupErr).Warnf("Failed to clean up named netns %s; the leftover mount point may block the next start", NsName)
	}()

	if !ns.handlesInitialized {
		ns.setupDone.Store(false)
		return nil
	}
	cleanupErr = deleteNamedNetnsFunc(NsName)
	_ = deleteLinkFunc(HostVethName)

	var errs []error
	if ns.daeNs.IsOpen() {
		if e := ns.daeNs.Close(); e != nil {
			errs = append(errs, e)
		}
	}
	if ns.hostNs.IsOpen() {
		if e := ns.hostNs.Close(); e != nil {
			errs = append(errs, e)
		}
	}
	ns.dae0 = nil
	ns.dae0peer = nil
	ns.hostNs = netns.None()
	ns.daeNs = netns.None()
	ns.useNetkit = false
	ns.handlesInitialized = false
	ns.setupDone.Store(false)
	return stderrors.Join(errs...)
}

func duplicateNetnsHandle(handle netns.NsHandle) (netns.NsHandle, error) {
	if !handle.IsOpen() {
		return netns.None(), fmt.Errorf("network namespace handle is closed")
	}
	fd, err := unix.FcntlInt(uintptr(handle), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return netns.None(), err
	}
	return netns.NsHandle(fd), nil
}

func (ns *DaeNetns) snapshotHandles() (hostNs, daeNs netns.NsHandle, err error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if !ns.setupDone.Load() || !ns.handlesInitialized {
		return netns.None(), netns.None(), fmt.Errorf("dae netns is not initialized")
	}
	hostNs, err = duplicateNetnsHandle(ns.hostNs)
	if err != nil {
		return netns.None(), netns.None(), fmt.Errorf("duplicate host netns handle: %w", err)
	}
	daeNs, err = duplicateNetnsHandle(ns.daeNs)
	if err != nil {
		_ = hostNs.Close()
		return netns.None(), netns.None(), fmt.Errorf("duplicate dae netns handle: %w", err)
	}
	return hostNs, daeNs, nil
}

// With runs f synchronously on a dedicated OS thread in dae netns and restores
// the host namespace before returning.
func (ns *DaeNetns) With(f func() error) error {
	if f == nil {
		return fmt.Errorf("dae netns callback is nil")
	}
	if err := ns.Setup(); err != nil {
		return fmt.Errorf("failed to setup dae netns: %w", err)
	}
	hostNs, daeNs, err := ns.snapshotHandles()
	if err != nil {
		return fmt.Errorf("snapshot dae netns handles: %w", err)
	}

	type result struct {
		err        error
		panicValue any
	}
	resultCh := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		var (
			switchErr        error
			callbackErr      error
			switched         bool
			callbackStarted  bool
			callbackReturned bool
		)
		defer func() {
			panicValue := recover()
			if callbackStarted && !callbackReturned && panicValue == nil {
				callbackErr = stderrors.New("dae netns callback exited without returning")
			}
			var restoreErr error
			if switched {
				restoreErr = setNetnsFunc(hostNs)
			}
			closeErr := stderrors.Join(
				closeNetnsSnapshot("dae", daeNs),
				closeNetnsSnapshot("host", hostNs),
			)
			if !switched || restoreErr == nil {
				runtime.UnlockOSThread()
			}
			// A goroutine that exits while locked causes the runtime to discard its
			// OS thread. This prevents a failed restore from returning a daens-bound
			// thread to the scheduler.
			resultCh <- result{
				err: stderrors.Join(
					switchErr,
					wrapDaeNetnsCallbackError(callbackErr),
					wrapDaeNetnsRestoreError(restoreErr),
					closeErr,
				),
				panicValue: panicValue,
			}
		}()

		if err := setNetnsFunc(daeNs); err != nil {
			switchErr = fmt.Errorf("failed to switch to daens: %w", err)
			return
		}
		switched = true
		callbackStarted = true
		callbackErr = f()
		callbackReturned = true
	}()

	callResult := <-resultCh
	if callResult.panicValue != nil {
		panic(callResult.panicValue)
	}
	return callResult.err
}

func closeNetnsSnapshot(name string, handle netns.NsHandle) error {
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close %s netns snapshot: %w", name, err)
	}
	return nil
}

func wrapDaeNetnsCallbackError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("failed to run func in dae netns: %w", err)
}

func wrapDaeNetnsRestoreError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("failed to restore host netns: %w", err)
}

// WithRequired runs f in dae netns and wraps the error with operation context.
func (ns *DaeNetns) WithRequired(op string, f func() error) error {
	if err := ns.With(f); err != nil {
		if op == "" {
			return err
		}
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// WithBestEffort runs f in dae netns and only logs debug info on failure.
func (ns *DaeNetns) WithBestEffort(op string, f func() error) {
	err := ns.With(f)
	if err == nil {
		return
	}
	ns.mu.Lock()
	log := ns.log
	ns.mu.Unlock()
	if log == nil {
		return
	}
	if op == "" {
		log.WithError(err).Debug("best-effort dae netns operation failed")
		return
	}
	log.WithError(err).Debugf("best-effort dae netns operation failed: %s", op)
}

// supportsNetkit checks if the kernel supports Netkit devices (requires 6.7+).
func (ns *DaeNetns) supportsNetkit() bool {
	if ns.kernelVersion == nil {
		return false
	}
	return !ns.kernelVersion.Less(consts.NetkitFeatureVersion)
}

// setupVethOrNetkit creates a veth or Netkit device pair based on kernel support.
// It tries Netkit first (kernel 6.7+) and falls back to veth if Netkit fails.
func (ns *DaeNetns) setupVethOrNetkit() (err error) {
	// Try Netkit first if kernel supports it
	if ns.supportsNetkit() {
		ns.log.Infof("Kernel %s supports Netkit, attempting to create Netkit device pair",
			ns.kernelVersion.String())
		err := ns.tryCreateNetkit()
		if err == nil {
			ns.useNetkit = true
			ns.log.Infof("Successfully created Netkit device pair (performance mode)")
			return nil
		}
		// Netkit failed, fall back to veth
		ns.log.WithFields(logrus.Fields{
			"error":  err.Error(),
			"kernel": ns.kernelVersion.String(),
		}).Warn("Failed to create Netkit device, falling back to veth")
	}

	// Fall back to veth
	// The fallback itself is already reported by the Warn above (or by the
	// kernel-version Info below when Netkit was never attempted); this line
	// only adds the step to the debug trace.
	ns.log.Debug("Falling back to veth device creation")
	ns.useNetkit = false
	if err := ns.setupVeth(); err != nil {
		return fmt.Errorf("failed to create veth device: %w", err)
	}

	if ns.supportsNetkit() {
		ns.log.Infof("Created veth device pair (compatibility mode; Netkit was attempted but failed)")
	} else {
		ns.log.Infof("Created veth device pair (kernel %s does not support Netkit)",
			ns.kernelVersion.String())
	}
	return nil
}

// tryCreateNetkit attempts to create a Netkit device pair.
// createNetkitDevice prefers netlink and falls back to iproute2.
func (ns *DaeNetns) tryCreateNetkit() (err error) {
	ns.log.Debug("Starting Netkit device creation")

	// Delete existing link if present
	ns.log.Debugf("Deleting existing link %s if present", HostVethName)
	_ = DeleteLink(HostVethName)

	// Try to create Netkit device
	// Configure scrub=NONE to preserve skb->mark across the netkit boundary.
	// bpf_redirect_peer() is only enabled on kernels containing the
	// CVE-2025-37959 fix (checked by the loader at BPF load time).
	ns.log.Debugf("Creating Netkit device pair: %s <-> %s", HostVethName, NsVethName)
	if err := createNetkitDevice(ns.log, HostVethName, NsVethName, DaeVethTxQLen, true); err != nil {
		// The wrapped error is reported (with its cause) by setupVethOrNetkit
		// and, on a real failure, by the caller of DaeNetns setup. Logging it
		// here as well would print the same failure twice per level.
		ns.log.Debugf("createNetkitDevice failed: %v", err)
		return fmt.Errorf("failed to create Netkit device: %w", err)
	}
	ns.log.Debug("Netkit device created successfully")

	// Get link references
	ns.log.Debugf("Getting link reference for %s", HostVethName)
	if ns.dae0, err = netlink.LinkByName(HostVethName); err != nil {
		// The returned error carries this cause (%w) and is reported once by
		// the caller of DaeNetns setup (With/WithRequired -> the serve loop),
		// so the inner line only adds the same failure a second time.
		ns.log.Debugf("Failed to get link %s: %v", HostVethName, err)
		return fmt.Errorf("failed to get link dae0: %w", err)
	}
	ns.log.Debug("Got link reference for dae0")

	ns.log.Debugf("Getting link reference for %s", NsVethName)
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		ns.log.Debugf("Failed to get link %s: %v", NsVethName, err)
		return fmt.Errorf("failed to get link dae0peer: %w", err)
	}
	ns.log.Debug("Got link reference for dae0peer")

	if err = requireNetkitL2WithMAC(ns.dae0, ns.dae0peer); err != nil {
		ns.log.Warnf("Rejecting Netkit pair: %v", err)
		_ = DeleteLink(HostVethName)
		ns.dae0 = nil
		ns.dae0peer = nil
		return err
	}

	// Set link up
	ns.log.Debug("Setting link dae0 up")
	if err = netlink.LinkSetUp(ns.dae0); err != nil {
		ns.log.Debugf("Failed to set link dae0 up: %v", err)
		return fmt.Errorf("failed to set link dae0 up: %w", err)
	}
	ns.log.Debug("Netkit device setup completed successfully")

	return nil
}

func (ns *DaeNetns) setup() (err error) {
	ns.log.Trace("setting up dae netns")

	// Capture the host namespace on the caller's thread before spawning the
	// worker below: goroutines may start on any OS thread, and the setup
	// steps switch namespaces, so the worker needs an explicit host reference
	// to start from and restore into.
	hostNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get host netns: %w", err)
	}
	ns.hostNs = hostNs // persistent handle; released by Close

	type setupResult struct {
		err        error
		panicValue any
	}
	resultCh := make(chan setupResult, 1)
	go func() {
		runtime.LockOSThread()
		var setupErr error
		restored := false
		defer func() {
			panicValue := recover()
			if restored {
				runtime.UnlockOSThread()
			} else if restoreErr := setNetnsFunc(hostNs); restoreErr != nil {
				// Last authoritative restore attempt. If it fails (e.g.
				// setns(2) ENOMEM), keep the thread locked and exit: a
				// goroutine that exits while still locked makes the runtime
				// discard its OS thread, quarantining a thread that would
				// otherwise run arbitrary code in the dae namespace.
				ns.log.WithError(restoreErr).Errorln("Failed to restore host netns after dae netns setup; quarantining setup thread")
				setupErr = stderrors.Join(setupErr, fmt.Errorf("failed to restore host netns: %w", restoreErr))
			} else {
				runtime.UnlockOSThread()
			}
			resultCh <- setupResult{err: setupErr, panicValue: panicValue}
		}()

		// Start deterministically in the host namespace regardless of which
		// OS thread the scheduler picked for this goroutine. This is the
		// setup's namespace prerequisite: without it the destructive link
		// setup below would run in whatever namespace the worker thread was
		// in. Fail closed instead of continuing (the deferred restore above
		// also publishes the error before the caller waits on resultCh).
		if setupErr = setNetnsFunc(hostNs); setupErr != nil {
			setupErr = fmt.Errorf("failed to switch setup thread to host netns: %w", setupErr)
			return
		}

		if setupErr = ns.setupVethOrNetkit(); setupErr != nil {
			return
		}
		if setupErr = ns.setupNetns(); setupErr != nil {
			return
		}
		if setupErr = ns.setupSysctl(); setupErr != nil {
			return
		}
		if setupErr = ns.setupIPv4Datapath(); setupErr != nil {
			return
		}
		if setupErr = ns.setupIPv6Datapath(); setupErr != nil {
			return
		}
		if setupErr = ns.setupRoutingPolicy(); setupErr != nil {
			return
		}
		// Success: re-enter the host namespace on this worker before it is
		// released back to the scheduler.
		if setupErr = setNetnsFunc(hostNs); setupErr == nil {
			restored = true
		}
	}()

	res := <-resultCh
	if res.panicValue != nil {
		panic(res.panicValue)
	}
	return res.err
}

func (ns *DaeNetns) setupRoutingPolicy() (err error) {
	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %w", err)
	}
	defer func() { _ = netns.Set(ns.hostNs) }()

	/// Insert ip rule / ip route.
	var table = 2023

	/** ip table
	ip route add local default dev lo table 2023
	ip -6 route add local default dev lo table 2023
	*/
	routes := []netlink.Route{{
		Scope:     unix.RT_SCOPE_HOST,
		LinkIndex: consts.LoopbackIfIndex,
		Dst: &net.IPNet{
			IP:   []byte{0, 0, 0, 0},
			Mask: net.CIDRMask(0, 32),
		},
		Table: table,
		Type:  unix.RTN_LOCAL,
	}, {
		Scope:     unix.RT_SCOPE_HOST,
		LinkIndex: consts.LoopbackIfIndex,
		Dst: &net.IPNet{
			IP:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			Mask: net.CIDRMask(0, 128),
		},
		Table: table,
		Type:  unix.RTN_LOCAL,
	}}
	for _, route := range routes {
		if err = netlink.RouteAdd(&route); err != nil {
			if len(route.Dst.IP) == net.IPv6len {
				// ipv6
				ns.log.Warnln("IpRouteAdd: Bad IPv6 support. Perhaps your machine disabled IPv6.")
				continue
			}
			return fmt.Errorf("IpRouteAdd: %w", err)
		}
	}

	/** ip rule
	ip rule add fwmark 0x8000000/0x8000000 table 2023
	ip -6 rule add fwmark 0x8000000/0x8000000 table 2023
	*/
	rules := []netlink.Rule{{
		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Goto:              -1,
		Flow:              -1,
		Family:            unix.AF_INET,
		Table:             table,
		Mark:              consts.TproxyMark,
		Mask:              new(consts.TproxyMark),
	}, {
		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Goto:              -1,
		Flow:              -1,
		Family:            unix.AF_INET6,
		Table:             table,
		Mark:              consts.TproxyMark,
		Mask:              new(consts.TproxyMark),
	}}

	for _, rule := range rules {
		if err = netlink.RuleAdd(&rule); err != nil {
			if rule.Family == unix.AF_INET6 {
				// ipv6
				ns.log.Warnln("IpRuleAdd: Bad IPv6 support. Perhaps your machine disabled IPv6 (need CONFIG_IPV6_MULTIPLE_TABLES).")
				continue
			}
			return fmt.Errorf("IpRuleAdd: %w", err)
		}
	}
	return nil
}
func (ns *DaeNetns) setupVeth() (err error) {
	// ip l a dae0 type veth peer name dae0peer
	_ = DeleteLink(HostVethName)
	if err = netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   HostVethName,
			TxQLen: DaeVethTxQLen,
		},
		PeerName:   NsVethName,
		PeerTxQLen: DaeVethTxQLen,
	}); err != nil {
		return fmt.Errorf("failed to add veth pair: %w", err)
	}
	if ns.dae0, err = netlink.LinkByName(HostVethName); err != nil {
		return fmt.Errorf("failed to get link dae0: %w", err)
	}
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("failed to get link dae0peer: %w", err)
	}
	// ip l s dae0 up
	if err = netlink.LinkSetUp(ns.dae0); err != nil {
		return fmt.Errorf("failed to set link dae0 up: %w", err)
	}
	return
}

// staleNetnsError is the surviving-entry error of DeleteNamedNetns. It keeps
// which stage produced which errno so the locked-mount predicate can match
// the exact per-stage signature instead of relying on where errors.Is finds
// an errno in the chain; Unwrap keeps every errno matchable for callers.
type staleNetnsError struct {
	path      string
	syncErr   error
	lazyErr   error
	removeErr error
}

// Error renders on one line on purpose: errors.Join separates causes with a
// newline, which splits a daemon log entry in two. The %v rendering keeps the
// three stage errnos in the order the operations run; Unwrap keeps every one
// of them matchable through errors.Is.
func (e *staleNetnsError) Error() string {
	if e.lazyErr != nil {
		return fmt.Sprintf("unmount %s: %v; lazy unmount: %v; %v", e.path, e.syncErr, e.lazyErr, e.removeErr)
	}
	return fmt.Sprintf("unmount %s: %v; %v", e.path, e.syncErr, e.removeErr)
}

func (e *staleNetnsError) Unwrap() []error {
	var errs []error
	for _, err := range []error{e.syncErr, e.lazyErr, e.removeErr} {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// isKernelLockedMount reports the incident signature from issue #1109: both
// umount(2) attempts rejected with EINVAL and the removal refused with EBUSY,
// each from its own operation. The per-stage match is exact on purpose: the
// errno pair alone (an EINVAL anywhere plus an EBUSY anywhere in the chain)
// would also match mixed shapes no real kernel produces for one mount point,
// and the recovery cover must not fire on those (review feedback on #1111).
func isKernelLockedMount(err error) bool {
	var stale *staleNetnsError
	if !stderrors.As(err, &stale) {
		return false
	}
	return stderrors.Is(stale.syncErr, unix.EINVAL) &&
		stderrors.Is(stale.lazyErr, unix.EINVAL) &&
		stderrors.Is(stale.removeErr, unix.EBUSY)
}

// coverNamedNetnsDir recovers from a kernel-locked stale entry the only way
// the kernel allows: hide it under a fresh tmpfs instead of trying to unmount
// it (issue #1109 — MNT_LOCKED rejects every umount(2) flag, so no retry or
// ordering can ever clear the mount). The cover is deliberate and persistent:
// it must outlive this process, or the next start hits the same locked entry
// again. Named netns owned by other tools in the same directory are hidden,
// not destroyed; nothing in /run survives a reboot, so those names return
// only when their owning tool recreates them. Mounting is the same class of
// privileged system mutation dae already performs during setup (bpffs, the
// named netns itself, sysctls).
func (ns *DaeNetns) coverNamedNetnsDir() error {
	if entries, err := os.ReadDir(netnsNamedDir); err == nil {
		var hidden []string
		for _, entry := range entries {
			if entry.Name() != NsName {
				hidden = append(hidden, entry.Name())
			}
		}
		if len(hidden) > 0 && ns.log != nil {
			ns.log.Warnf("Covering %s with a fresh tmpfs to recover from a kernel-locked mount point; hiding named netns %s until the next reboot", netnsNamedDir, strings.Join(hidden, ", "))
		}
	}
	if err := mountFunc("tmpfs", netnsNamedDir, "tmpfs", 0, "mode=755"); err != nil {
		return err
	}
	if ns.log != nil {
		ns.log.Warnf("Covered %s with a fresh tmpfs to recover from a kernel-locked mount point (issue #1109); the stale entry stays hidden until the next reboot", netnsNamedDir)
	}
	return nil
}

// prepareNamedNetns makes netnsNamedDir ready for NewNamed(NsName): the
// directory exists and no stale entry survives under that name. A stale entry
// that cannot be deleted must not leak into NewNamed — with the entry still
// present, its O_CREATE|O_EXCL can only report the misleading "file exists"
// instead of the real cause (issue #1109).
func (ns *DaeNetns) prepareNamedNetns() error {
	if err := os.MkdirAll(netnsNamedDir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", netnsNamedDir, err)
	}
	staleErr := deleteNamedNetnsFunc(NsName)
	if staleErr == nil {
		return nil
	}
	if !isKernelLockedMount(staleErr) {
		// The tmpfs recovery belongs to the locked signature only. A
		// transient EBUSY (another instance still shutting down) clears on a
		// retry, and a stray non-mount entry fails its removal with
		// ENOTEMPTY/EACCES — covering the directory would answer those with
		// an action that hides /run/netns for no reason. Errnos are named
		// symbolically because the message the operator's umount(1) prints is
		// localised.
		return fmt.Errorf("failed to clean up the stale named netns %s: %w", NsName, staleErr)
	}
	if coverErr := ns.coverNamedNetnsDir(); coverErr != nil {
		return fmt.Errorf("failed to clean up the stale named netns %s: %w; automatic recovery by covering %s with a fresh tmpfs failed: %w; cover it manually (mount -t tmpfs -o mode=755 tmpfs %s) or reboot, then start dae again", NsName, staleErr, netnsNamedDir, coverErr, netnsNamedDir)
	}
	if err := deleteNamedNetnsFunc(NsName); err != nil {
		// The cover already hid the locked entry, so this failure is about
		// the covered directory, not the stale mount itself.
		return fmt.Errorf("failed to clear the name %s after covering %s with a fresh tmpfs: %w", NsName, netnsNamedDir, err)
	}
	return nil
}

func (ns *DaeNetns) setupNetns() (err error) {
	// ip netns a daens
	// prepareNamedNetns removes any stale entry, and when the kernel holds it
	// locked it recovers by covering the directory with a fresh tmpfs; both
	// outcomes are logged there.
	if err = ns.prepareNamedNetns(); err != nil {
		return err
	}
	ns.daeNs, err = newNamedNetnsFunc(NsName)
	if err != nil {
		return fmt.Errorf("failed to create netns: %w", err)
	}
	// NewNamed() will switch to the new netns, switch back to host netns
	if err = netns.Set(ns.hostNs); err != nil {
		return fmt.Errorf("failed to switch to host netns: %w", err)
	}
	// ip l s dae0peer netns daens
	if err = netlink.LinkSetNsFd(ns.dae0peer, int(ns.daeNs)); err != nil {
		return fmt.Errorf("failed to move dae0peer to daens: %w", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %w", err)
	}
	defer func() { _ = netns.Set(ns.hostNs) }()
	// (ip net e daens) ip l s dae0peer up
	if err = netlink.LinkSetUp(ns.dae0peer); err != nil {
		return fmt.Errorf("failed to set link dae0peer up: %w", err)
	}
	// re-fetch dae0peer to make sure we have the latest mac address
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("failed to get link dae0peer: %w", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get link lo: %w", err)
	}
	// (ip net e daens) ip l s lo up
	if err = netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("failed to set link lo up: %w", err)
	}
	return
}

func (ns *DaeNetns) setupSysctl() (err error) {
	// Restore the host-side IPv4 sysctls from the original UDP port-conflict
	// workaround. Replies injected from dae netns re-enter the host via dae0
	// with a remote source address, so host routing and ARP validation must not
	// treat them as martian or filter them back to the wrong interface.
	if err = sysctl.Keyf("net.ipv4.conf.%s.rp_filter", HostVethName).Set("0", true); err != nil {
		return fmt.Errorf("failed to set rp_filter for dae0: %w", err)
	}
	if err = sysctl.Keyf("net.ipv4.conf.all.rp_filter").Set("0", true); err != nil {
		return fmt.Errorf("failed to set rp_filter for all: %w", err)
	}
	if err = sysctl.Keyf("net.ipv4.conf.%s.arp_filter", HostVethName).Set("0", true); err != nil {
		return fmt.Errorf("failed to set arp_filter for dae0: %w", err)
	}
	if err = sysctl.Keyf("net.ipv4.conf.all.arp_filter").Set("0", true); err != nil {
		return fmt.Errorf("failed to set arp_filter for all: %w", err)
	}
	if err = sysctl.Keyf("net.ipv4.conf.%s.accept_local", HostVethName).Set("1", true); err != nil {
		return fmt.Errorf("failed to set accept_local for dae0: %w", err)
	}

	// sysctl net.ipv6.conf.dae0.disable_ipv6=0
	if err = sysctl.Keyf("net.ipv6.conf.%s.disable_ipv6", HostVethName).Set("0", true); err != nil {
		return fmt.Errorf("failed to set disable_ipv6 for dae0: %w", err)
	}
	// sysctl net.ipv6.conf.dae0.forwarding=1
	if err = sysctl.Keyf("net.ipv6.conf.%s.forwarding", HostVethName).Set("1", true); err != nil {
		return fmt.Errorf("failed to set forwarding for dae0: %w", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %w", err)
	}
	defer func() { _ = netns.Set(ns.hostNs) }()

	// *_early_demux is not mandatory, but it's recommended to enable it for better performance
	_ = sysctl.Keyf("net.ipv4.tcp_early_demux").Set("1", false)
	_ = sysctl.Keyf("net.ipv4.ip_early_demux").Set("1", false)

	// (ip net e daens) sysctl net.ipv4.conf.dae0peer.accept_local=1
	// This is to prevent kernel from dropping skb due to "martian source" check: https://elixir.bootlin.com/linux/v6.6/source/net/ipv4/fib_frontend.c#L381
	if err = sysctl.Keyf("net.ipv4.conf.%s.accept_local", NsVethName).Set("1", false); err != nil {
		return fmt.Errorf("failed to set accept_local for dae0peer: %w", err)
	}
	return
}

func (ns *DaeNetns) setupIPv4Datapath() (err error) {
	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %w", err)
	}
	defer func() { _ = netns.Set(ns.hostNs) }()

	// (ip net e daens) ip a a 169.254.0.11 dev dae0peer
	// Although transparent UDP socket doesn't use this IP, it's still needed to make proper L3 header
	ip, ipNet, err := net.ParseCIDR("169.254.0.11/32")
	ipNet.IP = ip
	if err != nil {
		return fmt.Errorf("failed to parse ip 169.254.0.11: %w", err)
	}
	if err = netlink.AddrAdd(ns.dae0peer, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("failed to add v4 addr to dae0peer: %w", err)
	}
	// (ip net e daens) ip r a 169.254.0.1 dev dae0peer
	// 169.254.0.1 is the link-local address used for ARP caching
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("169.254.0.1"), Mask: net.CIDRMask(32, 32)},
		Gw:        nil,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("failed to add v4 route1 to dae0peer: %w", err)
	}
	// (ip net e daens) ip r a default via 169.254.0.1 dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		Gw:        net.ParseIP("169.254.0.1"),
	}); err != nil {
		return fmt.Errorf("failed to add v4 route2 to dae0peer: %w", err)
	}
	// (ip net e daens) ip n r 169.254.0.1 dev dae0peer lladdr $mac_dae0 nud permanent
	if err = netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("169.254.0.1"),
		HardwareAddr: ns.dae0.Attrs().HardwareAddr,
		LinkIndex:    ns.dae0peer.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("failed to add neigh to dae0peer: %w", err)
	}
	return
}

// dae0IPv6LinkLocal is the hardcoded next-hop used by dae netns IPv6 NDP.
// IFA_F_NODAD skips Duplicate Address Detection so the address is usable
// immediately; a tentative LL on netkit delays or blocks the default route.
func dae0IPv6LinkLocal() *netlink.Addr {
	return &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP("fe80::ecee:eeff:feee:eeee"),
			Mask: net.CIDRMask(128, 128),
		},
		Flags: unix.IFA_F_NODAD,
	}
}

func (ns *DaeNetns) setupIPv6Datapath() (err error) {
	// ip -6 a a fe80::ecee:eeff:feee:eeee/128 dev dae0 scope link nodad
	// fe80::ecee:eeff:feee:eeee/128 is the link-local address used for L2 NDP addressing
	if err = netlink.AddrAdd(ns.dae0, dae0IPv6LinkLocal()); err != nil {
		return fmt.Errorf("failed to add v6 addr to dae0: %w", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %w", err)
	}
	defer func() { _ = netns.Set(ns.hostNs) }()

	// (ip net e daens) ip -6 r a default via fe80::ecee:eeff:feee:eeee dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:        net.ParseIP("fe80::ecee:eeff:feee:eeee"),
	}); err != nil {
		return fmt.Errorf("failed to add v6 route to dae0peer: %w", err)
	}
	// (ip net e daens) ip n r fe80::ecee:eeff:feee:eeee dev dae0peer lladdr $mac_dae0 nud permanent
	if err = netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("fe80::ecee:eeff:feee:eeee"),
		HardwareAddr: ns.dae0.Attrs().HardwareAddr,
		LinkIndex:    ns.dae0peer.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("failed to add neigh to dae0peer: %w", err)
	}
	return
}

func DeleteNamedNetns(name string) error {
	if name == "" || name != path.Base(name) || name == "." || name == ".." {
		return fmt.Errorf("invalid named netns %q", name)
	}
	namedPath := path.Join(netnsNamedDir, name)
	// Try a synchronous unmount first; MNT_DETACH alone is lazy and may leave
	// the mount point behind (os.Remove then fails with EBUSY), which leaks
	// /run/netns/<name> and breaks a subsequent restart. Fall back to lazy
	// unmount only if the synchronous one fails (e.g. device busy).
	syncErr := unmountFunc(namedPath, 0)
	var lazyErr error
	if syncErr != nil {
		lazyErr = unmountFunc(namedPath, unix.MNT_DETACH)
	}
	removeErr := os.Remove(namedPath)
	if removeErr == nil || stderrors.Is(removeErr, os.ErrNotExist) {
		// The entry is gone; the unmount errors above are the normal
		// EINVAL/ENOENT noise for a non-mount or already-missing entry.
		return nil
	}
	if syncErr == nil {
		return removeErr
	}
	return &staleNetnsError{path: namedPath, syncErr: syncErr, lazyErr: lazyErr, removeErr: removeErr}
}

func DeleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err == nil {
		return netlink.LinkDel(link)
	}
	return err
}
