/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/safchain/ethtool"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// coreFlip should be 0 or 1; accessed atomically.
var coreFlip int32

type controlPlaneCore struct {
	mu sync.Mutex

	log        *logrus.Logger
	deferFuncs []func() error
	// bpfHookDetachFuncs contains only BPF hook detachment functions (FilterDel, tc detach)
	// These are tracked separately so they can be detached immediately on SIGTERM
	// before other cleanup that might take longer (like dialer shutdown).
	// Protected by bpfHookMu to avoid deadlock with c.mu in _bindLan/_bindWan.
	bpfHookDetachFuncs []func() error
	bpfHookMu          sync.Mutex
	bpf                *bpfObjects
	outboundId2Name    map[uint8]string
	tcpRelayOffload    bool

	kernelVersion *internal.Version

	flip             int
	isReload         bool
	bpfEjected       bool
	bpfHooksDetached bool // Track if BPF hooks were already detached

	closed context.Context
	close  context.CancelFunc
	ifmgr  *component.InterfaceManager
}

func newControlPlaneCore(log *logrus.Logger,
	bpf *bpfObjects,
	outboundId2Name map[uint8]string,
	kernelVersion *internal.Version,
	isReload bool,
) *controlPlaneCore {
	var flip int
	if isReload {
		flip = int(atomic.LoadInt32(&coreFlip)&1 ^ 1)
		atomic.StoreInt32(&coreFlip, int32(flip))
	} else {
		flip = int(atomic.LoadInt32(&coreFlip))
	}
	var deferFuncs []func() error
	if !isReload {
		deferFuncs = append(deferFuncs, bpf.Close)
	}
	closed, toClose := context.WithCancel(context.Background())
	ifmgr := component.NewInterfaceManager(log)
	deferFuncs = append(deferFuncs, ifmgr.Close)
	return &controlPlaneCore{
		log:                log,
		deferFuncs:         deferFuncs,
		bpfHookDetachFuncs: make([]func() error, 0),
		bpf:                bpf,
		outboundId2Name:    outboundId2Name,
		kernelVersion:      kernelVersion,
		flip:               flip,
		isReload:           isReload,
		bpfEjected:         false,
		bpfHooksDetached:   false,
		ifmgr:              ifmgr,
		closed:             closed,
		close:              toClose,
	}
}

func (c *controlPlaneCore) Flip() {
	// Use CAS loop to avoid race condition between Load and Store.
	for {
		old := atomic.LoadInt32(&coreFlip)
		newVal := old&1 ^ 1
		if atomic.CompareAndSwapInt32(&coreFlip, old, newVal) {
			break
		}
	}
}

// addBpfHookDetach adds a BPF hook detachment function to the dedicated list.
// These functions will be executed immediately on SIGTERM before other cleanup.
// Uses bpfHookMu to avoid deadlock with c.mu held by callers like _bindLan/_bindWan.
func (c *controlPlaneCore) addBpfHookDetach(detachFunc func() error) {
	c.bpfHookMu.Lock()
	defer c.bpfHookMu.Unlock()
	c.bpfHookDetachFuncs = append(c.bpfHookDetachFuncs, detachFunc)
}

// DetachBpfHooks immediately detaches all BPF hooks from the system.
// This should be called first when receiving SIGTERM to ensure network is restored
// even if the rest of the shutdown process takes too long and gets SIGKILL'd.
// This is safe to call multiple times - subsequent calls will be no-ops.
func (c *controlPlaneCore) DetachBpfHooks() error {
	c.bpfHookMu.Lock()
	defer c.bpfHookMu.Unlock()

	// Already detached, skip
	if c.bpfHooksDetached {
		return nil
	}

	c.log.Infoln("[Shutdown] Detaching BPF hooks immediately to restore network")

	var errs []error
	// Execute in reverse order (last attached, first detached)
	for i := len(c.bpfHookDetachFuncs) - 1; i >= 0; i-- {
		if e := c.bpfHookDetachFuncs[i](); e != nil {
			// Log but continue detaching other hooks
			c.log.WithError(e).Warnln("[Shutdown] Failed to detach BPF hook")
			errs = append(errs, e)
		}
	}

	c.bpfHooksDetached = true
	c.log.Infoln("[Shutdown] BPF hooks detached, network should be restored")

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// attachTc attaches a TC program with TCX (kernel 6.6+) or falls back to traditional TC.
// It uses unified priority (1) for all interfaces and Anchor Head() for LIFO execution order in TCX.
func (c *controlPlaneCore) attachTc(link netlink.Link, prog *ebpf.Program, attachType ebpf.AttachType, priority uint32, handle uint32, handleBits uint16, name string) (func() error, error) {
	// Build TC filter info first (needed for both TCX cleanup and TC fallback)
	var parent uint32
	if attachType == ebpf.AttachTCXIngress {
		parent = netlink.HANDLE_MIN_INGRESS
	} else {
		parent = netlink.HANDLE_MIN_EGRESS
	}

	tcFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    netlink.MakeHandle(uint16(handle), handleBits+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  uint16(priority),
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}

	// Try TCX attachment first if kernel supports it
	if !c.kernelVersion.Less(consts.TcxFeatureVersion) {
		l, err := ciliumLink.AttachTCX(ciliumLink.TCXOptions{
			Interface: link.Attrs().Index,
			Program:   prog,
			Attach:    attachType,
			Anchor:    ciliumLink.Head(), // LIFO: last attached program executes first
		})
		if err == nil {
			// TCX succeeded - cleanup old TC filters and return TCX-specific detachFunc
			c.cleanupTcFilters(tcFilter)
			tcxLink := l
			c.log.Infof("Attached %v using TCX (kernel %v)", name, c.kernelVersion.String())

			return func() error {
				if err := tcxLink.Close(); err != nil {
					return fmt.Errorf("TCX.Close(%v): %w", name, err)
				}
				return nil
			}, nil
		}
		c.log.WithError(err).Warnf("failed to attach TCX for %s, falling back to TC", name)
	}

	// TCX failed or not supported - cleanup then use TC fallback
	c.cleanupTcFilters(tcFilter)
	if err := netlink.FilterAdd(tcFilter); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("cannot attach ebpf object to filter %s: %w", name, err)
	}
	c.log.Infof("Attached %v using TC (fallback)", name)

	// Return TC-specific detachFunc
	return func() error {
		if err := netlink.FilterDel(tcFilter); err != nil {
			if !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.EINVAL) {
				return fmt.Errorf("FilterDel(%v): %w", name, err)
			}
		}
		return nil
	}, nil
}

func (c *controlPlaneCore) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	// Invoke defer funcs in reverse order and collect errors.
	// Use errors.Join (Go 1.20+) for clean multi-error handling.
	var errs []error
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			errs = append(errs, e)
		}
	}
	c.close()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		return bpfIfParams{}, nil
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		return bpfIfParams{}, nil
	}
	if features["tx-checksum-ip-generic"] {
		ifParams.TxL4CksmIp4Offload = true
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["tx-checksum-ipv4"] {
		ifParams.TxL4CksmIp4Offload = true
	}
	if features["tx-checksum-ipv6"] {
		ifParams.TxL4CksmIp6Offload = true
	}
	if features["rx-checksum"] {
		ifParams.RxCksmOffload = true
	}
	switch {
	case regexp.MustCompile(`^docker\d+$`).MatchString(link.Attrs().Name):
		ifParams.UseNonstandardOffloadAlgorithm = true
	default:
	}
	return ifParams, nil
}

func (c *controlPlaneCore) linkHdrLen(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	var linkHdrLen uint32
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		linkHdrLen = consts.LinkHdrLen_None
	case "ether":
		linkHdrLen = consts.LinkHdrLen_Ethernet
	default:
		c.log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		linkHdrLen = consts.LinkHdrLen_Ethernet
	}
	return linkHdrLen, nil
}

func buildClsactQdisc(link netlink.Link) *netlink.GenericQdisc {
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
}

func (c *controlPlaneCore) addQdisc(link netlink.Link) error {
	qdisc := buildClsactQdisc(link)
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(link netlink.Link) error {
	qdisc := buildClsactQdisc(link)
	if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("cannot delete clsact qdisc: %w", err)
	} else if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		c.log.Debugf("delQdisc: clsact qdisc or link not found for %v (already gone)", link.Attrs().Name)
	}
	return nil
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		if err := c._bindLan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindLan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
		if err := c.delQdisc(link); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindLan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to LAN: %v", ifname)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = CheckIpforward(ifname); err != nil {
		return err
	}
	if err = CheckSendRedirects(ifname); err != nil {
		return err
	}
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(link)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}
	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	// Attach ingress program using unified attachTc function
	progIngress := c.bpf.bpfPrograms.TproxyLanIngressL3
	nameIngress := consts.AppName + "_lan_ingress_l3"
	if linkHdrLen > 0 {
		progIngress = c.bpf.bpfPrograms.TproxyLanIngressL2
		nameIngress = consts.AppName + "_lan_ingress_l2"
	}
	detachFunc, err := c.attachTc(link, progIngress, ebpf.AttachTCXIngress, 1, 0x2023, 0b100, nameIngress)
	if err != nil {
		return err
	}
	c.deferFuncs = append(c.deferFuncs, detachFunc)
	c.addBpfHookDetach(detachFunc)

	// Attach egress program using unified attachTc function
	progEgress := c.bpf.bpfPrograms.TproxyLanEgressL3
	nameEgress := consts.AppName + "_lan_egress_l3"
	if linkHdrLen > 0 {
		progEgress = c.bpf.bpfPrograms.TproxyLanEgressL2
		nameEgress = consts.AppName + "_lan_egress_l2"
	}
	egressDetachFunc, err := c.attachTc(link, progEgress, ebpf.AttachTCXEgress, 1, 0x2023, 0b010, nameEgress)
	if err != nil {
		return err
	}
	c.deferFuncs = append(c.deferFuncs, egressDetachFunc)
	c.addBpfHookDetach(egressDetachFunc)

	return nil
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	/// Set-up SrcPidMapper.
	/// Attach programs to support pname routing.
	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return err
	}
	// Bind cg programs
	type cgProg struct {
		Name   string
		Prog   *ebpf.Program
		Attach ebpf.AttachType
	}
	cgProgs := []cgProg{
		{Prog: c.bpf.TproxyWanCgSockCreate, Attach: ebpf.AttachCGroupInetSockCreate},
		{Prog: c.bpf.TproxyWanCgSockRelease, Attach: ebpf.AttachCgroupInetSockRelease},
		{Prog: c.bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		{Prog: c.bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		{Prog: c.bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		{Prog: c.bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, prog := range cgProgs {
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			return fmt.Errorf("AttachCgroup: %v: %w", prog.Prog.String(), err)
		}
		detachFunc := func() error {
			if err := attached.Close(); err != nil {
				return fmt.Errorf("inet6Bind.Close(): %w", err)
			}
			return nil
		}
		c.deferFuncs = append(c.deferFuncs, detachFunc)
		c.addBpfHookDetach(detachFunc)
	}
	return nil
}

func (c *controlPlaneCore) setupTCPRelayOffload() error {
	if os.Getenv("DAE_DISABLE_TCP_RELAY_OFFLOAD") == "1" {
		c.log.Debug("TCP relay eBPF offload disabled by DAE_DISABLE_TCP_RELAY_OFFLOAD=1")
		return nil
	}
	if c.bpf.FastSock == nil ||
		c.bpf.TproxyFastRedirectParser == nil ||
		c.bpf.TproxyFastRedirectVerdict == nil {
		return nil
	}

	attachments := []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{
		{prog: c.bpf.TproxyFastRedirectParser, attach: ebpf.AttachSkSKBStreamParser},
		{prog: c.bpf.TproxyFastRedirectVerdict, attach: ebpf.AttachSkSKBStreamVerdict},
	}

	var attached []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}
	for _, item := range attachments {
		if err := ciliumLink.RawAttachProgram(ciliumLink.RawAttachProgramOptions{
			Target:  c.bpf.FastSock.FD(),
			Program: item.prog,
			Attach:  item.attach,
		}); err != nil {
			for i := len(attached) - 1; i >= 0; i-- {
				_ = ciliumLink.RawDetachProgram(ciliumLink.RawDetachProgramOptions{
					Target:  c.bpf.FastSock.FD(),
					Program: attached[i].prog,
					Attach:  attached[i].attach,
				})
			}
			c.log.WithError(err).Debug("TCP relay eBPF offload is not supported by the current kernel/environment; falling back to userspace relay")
			return nil
		}
		attached = append(attached, item)
	}

	c.tcpRelayOffload = true
	detachFunc := func() error {
		var errs []error
		for i := len(attached) - 1; i >= 0; i-- {
			if err := ciliumLink.RawDetachProgram(ciliumLink.RawDetachProgramOptions{
				Target:  c.bpf.FastSock.FD(),
				Program: attached[i].prog,
				Attach:  attached[i].attach,
			}); err != nil {
				// Ignore ENOENT (program already detached) and EINVAL (invalid target)
				// as these are benign conditions during cleanup
				if os.IsNotExist(err) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
					c.log.Debugf("SkSKB program %s already detached or target closed: %v", attached[i].prog.String(), err)
				} else {
					errs = append(errs, fmt.Errorf("detach %s: %w", attached[i].prog.String(), err))
				}
			}
		}
		return errors.Join(errs...)
	}
	c.deferFuncs = append(c.deferFuncs, detachFunc)
	c.addBpfHookDetach(detachFunc)
	return nil
}

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if err := c._bindWan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindWan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
		if err := c.delQdisc(link); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
}

func (c *controlPlaneCore) _bindWan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	c.log.Infof("Bind to WAN: %v", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if link.Attrs().Index == consts.LoopbackIfIndex {
		return fmt.Errorf("cannot bind to loopback interface")
	}
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(link)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
		return err
	}

	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}

	// Attach egress program using unified attachTc function
	progEgress := c.bpf.bpfPrograms.TproxyWanEgressL3
	nameEgress := consts.AppName + "_wan_egress_l3"
	if linkHdrLen > 0 {
		progEgress = c.bpf.bpfPrograms.TproxyWanEgressL2
		nameEgress = consts.AppName + "_wan_egress_l2"
	}
	egressDetachFunc, err := c.attachTc(link, progEgress, ebpf.AttachTCXEgress, 1, 0x2023, 0b100, nameEgress)
	if err != nil {
		return err
	}
	c.deferFuncs = append(c.deferFuncs, egressDetachFunc)
	c.addBpfHookDetach(egressDetachFunc)

	// Attach ingress program using unified attachTc function
	progIngress := c.bpf.bpfPrograms.TproxyWanIngressL3
	nameIngress := consts.AppName + "_wan_ingress_l3"
	if linkHdrLen > 0 {
		progIngress = c.bpf.bpfPrograms.TproxyWanIngressL2
		nameIngress = consts.AppName + "_wan_ingress_l2"
	}
	ingressDetachFunc, err := c.attachTc(link, progIngress, ebpf.AttachTCXIngress, 1, 0x2023, 0b010, nameIngress)
	if err != nil {
		return err
	}
	c.deferFuncs = append(c.deferFuncs, ingressDetachFunc)
	c.addBpfHookDetach(ingressDetachFunc)

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := GetDaeNetns()

	// tproxy_dae0peer_ingress@eth0 at dae netns
	// Best effort: qdisc may already exist and tx queue tuning is non-critical.
	daens.WithBestEffort("set dae0peer tx queue and add clsact qdisc", func() error {
		err := netlink.LinkSetTxQLen(daens.Dae0Peer(), DaeVethTxQLen)
		if err == nil {
			err = c.addQdisc(daens.Dae0Peer())
		}
		return err
	})

	// Attach dae0peer ingress using unified attachTc function
	var detachFunc func() error
	if err = daens.WithRequired("attach dae0peer ingress", func() error {
		var err error
		innerDetachFunc, err := c.attachTc(daens.Dae0Peer(), c.bpf.bpfPrograms.TproxyDae0peerIngress, ebpf.AttachTCXIngress, 1, 0x2022, 0b010, consts.AppName+"_dae0peer_ingress")
		if err != nil {
			return err
		}
		detachFunc = func() error {
			return daens.WithRequired("detach dae0peer ingress", func() error {
				return innerDetachFunc()
			})
		}
		return nil
	}); err != nil {
		return err
	}
	c.deferFuncs = append(c.deferFuncs, detachFunc)
	c.addBpfHookDetach(detachFunc)

	// tproxy_dae0_ingress@dae0 at host netns
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(daens.Dae0())
	dae0DetachFunc, err := c.attachTc(daens.Dae0(), c.bpf.bpfPrograms.TproxyDae0Ingress, ebpf.AttachTCXIngress, 1, 0x2022, 0b010, consts.AppName+"_dae0_ingress")
	if err != nil {
		return err
	}
	c.deferFuncs = append(c.deferFuncs, dae0DetachFunc)
	c.addBpfHookDetach(dae0DetachFunc)
	return
}

// cleanupTcFilters removes TC filters based on the reload scenario.
//
// Scenarios:
// 1. Fresh start (!c.isReload):
//    - Removes current flip filter (may exist from crashed process)
//    - Removes opposite flip filter (stale from previous run)
//    - Goal: Ensure clean state, remove all stale resources
//
// 2. Reload (c.isReload):
//    - Removes only current flip filter
//    - Preserves opposite flip filter (belongs to old process)
//    - Goal: Allow old process to clean up its own resources
//
// This is critical when transitioning between TC and TCX:
// - Old TC filters may interfere with new TCX programs
// - Complete cleanup prevents traffic processing conflicts
func (c *controlPlaneCore) cleanupTcFilters(tcFilter *netlink.BpfFilter) {
	// Always clean up current flip filter (may exist from previous attempt)
	_ = netlink.FilterDel(tcFilter)

	// Clean up opposite flip filter ONLY on non-reload
	// In reload scenario, opposite flip resources belong to old process
	if !c.isReload {
		tryDeleteFlippedFilter(tcFilter)
	}
}

// tryDeleteFlippedFilter deletes the TC filter obtained by flipping the
// low bit of the handle. Used during non-reload startup to remove any
// stale filter from a previous run that used the opposite flip value.
func tryDeleteFlippedFilter(f *netlink.BpfFilter) {
	flipped := deepcopy.Copy(f).(*netlink.BpfFilter)
	flipped.FilterAttrs.Handle ^= 1
	_ = netlink.FilterDel(flipped)
}

// extractIpsFromDnsCache returns the unique, valid non-unspecified IP addresses
// contained in the A/AAAA records of a DNS cache entry.
func extractIpsFromDnsCache(cache *DnsCache) []netip.Addr {
	var ips []netip.Addr
	for _, ans := range cache.Answer {
		var (
			ip netip.Addr
			ok bool
		)
		switch body := ans.(type) {
		case *dnsmessage.A:
			ip, ok = netip.AddrFromSlice(body.A)
		case *dnsmessage.AAAA:
			ip, ok = netip.AddrFromSlice(body.AAAA)
		}
		if !ok || ip.IsUnspecified() {
			continue
		}
		ips = append(ips, ip)
	}
	return ips
}

// BatchUpdateDomainRouting update bpf map domain_routing. Since one IP may have multiple domains, this function should
// be invoked every A/AAAA-record lookup.
func (c *controlPlaneCore) BatchUpdateDomainRouting(cache *DnsCache) error {
	ips := extractIpsFromDnsCache(cache)
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
	// OPTIMIZATION: Pre-allocate capacity to avoid multiple allocations.
	numIps := len(ips)
	keys := make([][4]uint32, 0, numIps)
	vals := make([]bpfDomainRouting, 0, numIps)

	// Pre-check bitmap length compatibility once
	if len(cache.DomainBitmap) != len(bpfDomainRouting{}.Bitmap) {
		return fmt.Errorf("domain bitmap length not sync with kern program")
	}

	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
		r := bpfDomainRouting{}
		copy(r.Bitmap[:], cache.DomainBitmap)
		vals = append(vals, r)
	}

	if _, err := BpfMapBatchUpdate(c.bpf.DomainRoutingMap, keys, vals, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		return err
	}
	return nil
}

// BatchRemoveDomainRouting remove bpf map domain_routing.
func (c *controlPlaneCore) BatchRemoveDomainRouting(cache *DnsCache) error {
	ips := extractIpsFromDnsCache(cache)
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and BpfMapBatchDelete.
	var keys [][4]uint32
	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
	}
	if _, err := BpfMapBatchDelete(c.bpf.DomainRoutingMap, keys); err != nil {
		return err
	}
	return nil
}

// EjectBpf will resect bpf from destroying life-cycle of control plane core.
func (c *controlPlaneCore) EjectBpf() *bpfObjects {
	if c.bpfEjected {
		return c.bpf
	}
	if !c.isReload {
		c.deferFuncs = c.deferFuncs[1:]
	}
	c.bpfEjected = true

	// Stop link watcher immediately during handover period to avoid race condition
	// between old and new control planes reacting to link events (e.g. PPPoE flapping).
	_ = c.ifmgr.Close()

	return c.bpf
}

// InjectBpf will inject bpf back.
func (c *controlPlaneCore) InjectBpf(bpf *bpfObjects) {
	if c.bpfEjected {
		c.bpfEjected = false
		c.deferFuncs = append([]func() error{bpf.Close}, c.deferFuncs...)
	}
	return
}
