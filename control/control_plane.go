/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/daedns"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type ControlPlane struct {
	log          *logrus.Logger
	directDialer netproxy.Dialer

	runtimeStats *runtimeStats

	core       *controlPlaneCore
	deferFuncs []func() error
	listenIp   string

	controlPlaneGenerationState
	inConnections         sync.Map
	rejectNewConnections  atomic.Bool
	sessionManagerMu      sync.Mutex
	sessionManager        *SessionManager
	ownsSessionManager    bool
	sessionManagerBinding atomic.Pointer[controlPlaneSessionManagerBinding]
	egressRuntime         *egressRuntime
	drainTracker          *controlPlaneDrainTracker
	// key: ConnMetricKey, value: *atomic.Uint64
	tcpConnectionTotals sync.Map
	udpConnectionTotals sync.Map

	controlPlaneRoutingEpochRuntime
	controlPlaneDNSRuntime
	dnsHandoffMu         sync.Mutex
	dnsHandoffController atomic.Pointer[DnsController]
	onceNetworkReady     sync.Once

	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	readyOnce sync.Once

	// serveLoopErr stores the first terminal ingress loop failure; Serve
	// returns it after the context cancellation that fatalIngressLoopError
	// triggers, so the run loop can fail fast instead of silently
	// blackholing hijacked traffic.
	serveLoopErrMu sync.Mutex
	serveLoopErr   error

	controlPlaneRealDomainRuntime
	controlPlaneDatapathJanitor
	bpfMaintenance *bpfMaintenanceBinding

	// Datapath counter report state. Unlike a per-alert timestamp, the baselines
	// it holds are what let a resource alert describe the interval since the
	// previous line instead of the lifetime total, which never returns to zero
	// for a map shared across generations. See
	// control/datapath_overflow_report.go.
	datapathOverflowReport controlPlaneDatapathOverflowReport

	// Datapath passthrough report state, on the same terms and the same tick:
	// the two by-design passthrough counters are not part of the report above,
	// because they are normal rather than resource exhaustion. See
	// control/datapath_passthrough_report.go.
	datapathPassthroughReport controlPlaneDatapathPassthroughReport

	wanInterface []string
	lanInterface []string

	sniffingTimeout        time.Duration
	tproxyPortProtect      bool
	soMarkFromDae          uint32
	mptcp                  bool
	udpRouteScopeSensitive bool
	controlPlaneUDPRuntime
	lastConnectionErrorLogTime     atomic.Int64
	lastDnsFastPathErrorLogTime    atomic.Int64
	lastDnsFastPathServfailLogTime atomic.Int64
	lastHandlePktEpochWarnTime     atomic.Int64
	tcpConnPanicCount              atomic.Uint64
	// The janitor map-capacity alerts are paced one per condition, not one per
	// janitor run: see pacedAlert. They are per-map so that one saturated map
	// cannot pace another map's alert out of the log.
	redirectTrackCapacityAlert  pacedAlert
	cookiePidCapacityAlert      pacedAlert
	routingHandoffCapacityAlert pacedAlert
	// Per-packet datapath conditions that hold for every packet of every
	// affected flow until the underlying state changes. Each has its own pace
	// so one condition cannot suppress the report of another.
	udpRoutingTupleWarnAlert    pacedAlert
	udpDNSRoutingTupleWarnAlert pacedAlert
	udpHandlePktWarnAlert       pacedAlert
	// checkBpfMapHealthWarnAlert paces the datapath-counter read failure. The
	// health check runs on every janitor tick (5s), and a read that fails once
	// usually fails for as long as the underlying condition lasts, so an
	// unpaced warn would write one line per 5s with no transition behind it.
	checkBpfMapHealthWarnAlert pacedAlert
	// udpDirectDispatchPanicCount and udpIngressLoopPanicCount count recovered
	// panics on the two UDP packet-path goroutines that have no convoy wrapper:
	// the direct-dispatch task (DNS/SIP/RTP/STUN exceptions) and the ingress
	// read loop itself.
	udpDirectDispatchPanicCount atomic.Uint64
	udpIngressLoopPanicCount    atomic.Uint64
	controlPlaneListenerRuntime
	preparedDatapathCommit         bool
	autoConfigKernelParameter      bool
	routingKernspaceSnapshot       *routingKernspaceSnapshot
	pendingDnsReloadCache          map[string]*DnsCache
	dnsReloadCacheSourceMu         sync.Mutex
	dnsReloadCacheSource           func() map[string]*DnsCache
	dnsReloadCacheStreamSource     func(func(string, *DnsCache) error) error
	dnsReloadCacheStreamSourceHash [32]byte
	sharedBpfReload                bool
	// dnsRoutingUnchanged indicates that DNS routing configuration (excluding
	// runtime-tunable parameters like OptimisticCache) did not change from the
	// previous generation. It is retained for staged DNS handoff decisions;
	// routing epoch projection is always isolated by its target slot.
	dnsRoutingUnchanged bool
	closeOnce           sync.Once
	closeErr            error
}

var policyEpochSequence atomic.Uint64

// ControlPlaneBuildOptions selects generation-mode behavior for
// NewControlPlaneWithContextOptions. DelayDatapathCommit and
// DelayDNSListenerStart build a prepared candidate that does not touch the
// kernel datapath until CommitPreparedDatapath; IsReload selects reload-mode
// TC handle flipping and skips startup-only stale hook purges.
type ControlPlaneBuildOptions struct {
	DelayDatapathCommit   bool
	DelayDNSListenerStart bool
	DNSRoutingUnchanged   bool
	IsReload              bool
	DirectDialer          netproxy.Dialer
	FullconeDirectDialer  netproxy.Dialer
	SystemDNSResolver     *netutils.SystemDNSResolver
}

var (
	// realDomainNegativeCacheTTL controls how long failed real-domain probes are cached.
	// Keep it short to avoid stale negatives while still damping bursty probe storms.
	realDomainNegativeCacheTTL = 10 * time.Second
	// gracefulShutdownWaitTimeout bounds how long shutdown waits for background
	// janitors and workers before continuing teardown.
	gracefulShutdownWaitTimeout = 5 * time.Second
	// controlPlaneDeferredCleanupTimeout bounds non-critical Close tail work
	// such as old-generation dialer, DNS, and hook cleanup during reload.
	controlPlaneDeferredCleanupTimeout = 5 * time.Second
	preparedDNSWarmupTimeout           = 15 * time.Second
	// realDomainProbeTimeout bounds synchronous probe latency on connection setup path.
	// Keep it sub-second to avoid hurting first-paint responsiveness under DNS jitter.
	// Reduced from 800ms to 500ms for faster fallback under poor network conditions.
	realDomainProbeTimeout = 500 * time.Millisecond
	// dnsDialerSnapshotTTL caches dialer selection results to reduce selection overhead.
	// Set to 2s since dialer health status only updates every 30s (default CheckInterval).
	// This provides good cache hit rate without missing dialer state changes.
	dnsDialerSnapshotTTL         = 2 * time.Second
	dnsDialerPenaltyTTL          = 5 * time.Second
	realDomainNegJanitorInterval = 30 * time.Second

	// redirectTrackJanitorPressureInterval is used when maps are under pressure.
	redirectTrackJanitorPressureInterval = 5 * time.Second
	// redirectTrackJanitorSteadyInterval is sufficient for the redirect cache
	// because stale entries have a limited blast radius.
	redirectTrackJanitorSteadyInterval = 30 * time.Second
	// cookiePidMapTimeout bounds stale cookie metadata when sock_release backstop
	// is missed for any reason. Active sockets refresh this timestamp from BPF.
	cookiePidMapTimeout = 5 * time.Minute
	// routingHandoffTimeout bounds the tuple-miss metadata bridge between eBPF
	// and userspace. Keep it short so the handoff map does not become a second
	// long-lived conn-state cache.
	routingHandoffTimeout = 10 * time.Second
	// routingHandoffPressureInterval lets the janitor react quickly when the
	// handoff map is churning under repeated tuple misses.
	routingHandoffPressureInterval = 1 * time.Second
	// routingHandoffSteadyInterval is sufficient because RetrieveRoutingResult
	// also rejects expired handoff entries on read.
	routingHandoffSteadyInterval = 5 * time.Second
	dnsFastPathErrorLogInterval  = 5 * time.Second
	handlePktEpochWarnInterval   = 5 * time.Second

	// Test seams: injected in tests to avoid external DNS dependency.
	resolveIp46ForBootstrap       = netutils.ResolveIp46
	resolveIp46ForRealDomainProbe = netutils.ResolveIp46
)

// containerMountHint explains the container case without making it the only
// hypothesis: an LXC container whose host does not expose bpffs cannot fix this
// from inside.
const containerMountHint = " (inside a container the host must expose a bpffs mount; if it cannot, use higher virtualization such as kvm/qemu)"

// ensureBpfPinDir creates the BPF pin directory and, when that fails, reports
// the actual state of the pin root instead of a fixed hypothesis. The previous
// message blamed containers for every mkdir failure, which sent users after the
// wrong cause: dae has already created its datapath devices by this point, a
// container with a proper bpffs mount works fine, and the raw mkdir text never
// told anyone what to do.
func ensureBpfPinDir(pinPath string, log *logrus.Logger) error {
	err := os.MkdirAll(pinPath, 0o755)
	if err == nil || os.IsExist(err) {
		return nil
	}
	wrapped := bpfPinDirError(pinPath, err, isBpfPinRootMounted())
	if log != nil {
		log.Warnln(wrapped)
	}
	return wrapped
}

// bpfPinDirError builds the message from the observed state of the pin root.
// Only a missing mount makes the mount advice actionable; a permission or
// not-a-directory failure keeps its raw cause and gains no container hint, so
// the message never points at the wrong problem.
func bpfPinDirError(pinPath string, mkdirErr error, pinRootMounted bool) error {
	if !pinRootMounted {
		return fmt.Errorf("bpf pin root %s is not a bpffs mount, so %s cannot be created: %w; mount it with \"mount -t bpf bpffs %s\"%s",
			consts.BpfPinRoot, pinPath, mkdirErr, consts.BpfPinRoot, containerMountHint)
	}
	return fmt.Errorf("cannot create bpf pin directory %s: %w", pinPath, mkdirErr)
}

// bpfPinRootMountedFrom reports whether /proc/mounts content contains a bpffs
// mount at root. It is split out so the parser can be tested against fixtures
// instead of trusting the host's own mount table.
func bpfPinRootMountedFrom(mounts string) bool {
	for line := range strings.Lines(mounts) {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == consts.BpfPinRoot && fields[2] == "bpf" {
			return true
		}
	}
	return false
}

// isBpfPinRootMounted reports whether bpffs is mounted at the pin root, read
// from /proc/mounts so the diagnosis matches the running kernel.
func isBpfPinRootMounted() bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return bpfPinRootMountedFrom(string(data))
}

func isIPLikeDomain(domain string) bool {
	if domain == "" {
		return false
	}
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		domain = domain[1 : len(domain)-1]
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return true
	}
	if host, _, err := net.SplitHostPort(domain); err == nil {
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return true
		}
	}
	return false
}

// NewControlPlaneWithContextOptions is the single control-plane constructor;
// the previous New{,Reload,Prepared,PreparedReload}ControlPlaneWithContext
// wrapper family collapsed into this options-based entry point.
func NewControlPlaneWithContextOptions(
	ctx context.Context,
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
	buildOpts ControlPlaneBuildOptions,
) (plane *ControlPlane, err error) {
	var freshDatapathState *FreshDatapathState
	if state, ok := _bpf.(*FreshDatapathState); ok {
		freshDatapathState = state
		_bpf = nil
	}
	// The ctx parameter may carry a preparation timeout from the caller (e.g.
	// context.WithTimeout in cmd/run.go). All long-lived objects owned by the
	// ControlPlane — its lifecycle context, dialer contexts, goroutines — MUST
	// derive from a background context so they are not cancelled when the
	// preparation deadline expires. The caller's ctx is only consulted at
	// cooperative checkpoints between slow build stages so a stalled build can
	// be aborted; it is never used as a parent for any perennial context below.
	checkCtx := func(stage string) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("control plane build canceled at %s: %w", stage, err)
		}
		return nil
	}
	if err := checkCtx("prepare"); err != nil {
		return nil, err
	}

	// Clear failed QUIC DCID cache on reload/startup.
	// Network conditions may have changed, so we should allow retrying sniffing
	// for DCIDs that previously failed.
	ClearFailedQuicDcids()

	if global.SoMarkFromDae == 0 {
		var autoSelected bool
		global.SoMarkFromDae, autoSelected = common.ResolveSoMarkFromDae(global.SoMarkFromDae, global.SoMarkFromDaeSet)
		if autoSelected {
			log.Warnf("so_mark_from_dae is unset; using internal socket mark %#x to prevent dae UDP self-capture", global.SoMarkFromDae)
		}
	}

	// Register the cache clear function with dialer package so health checks
	// can clear the failed DCID cache when network conditions improve.
	dialer.SetQuicDcidCacheClearFunc(ClearFailedQuicDcids)

	bootstrapResolvers, err := config.BootstrapResolvers(global)
	if err != nil {
		return nil, err
	}

	if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
		_ = os.Setenv("QUIC_GO_DISABLE_GSO", "1")
	}

	kernelVersion, e := internal.KernelVersion()
	if e != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", e)
	}
	/// Check linux kernel requirements.
	// Check version from high to low to reduce the number of user upgrading kernel.
	if kernelVersion.Less(consts.BpfLoopFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support bpf_loop (needed by routing); expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			consts.BpfLoopFeatureVersion.String())
	}
	if requirement := consts.ChecksumFeatureVersion; kernelVersion.Less(requirement) {
		return nil, fmt.Errorf("your kernel version %v does not support checksum related features; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.BpfTimerFeatureVersion; len(global.WanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to WAN; expect >=%v; remove wan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.SkAssignFeatureVersion; len(global.LanInterface) > 0 && kernelVersion.Less(requirement) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to LAN; expect >=%v; remove lan_interface in config file and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if kernelVersion.Less(consts.BasicFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not satisfy basic requirement; expect >=%v",
			kernelVersion.String(),
			consts.BasicFeatureVersion.String())
	}

	var deferFuncs []func() error

	/// Allow the current process to lock memory for eBPF resources.
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}

	InitDaeNetns(log)
	if err = InitSysctlManager(log); err != nil {
		return nil, err
	}

	daeNetns := GetDaeNetns()
	netnsCreated, setupErr := daeNetns.SetupWithOwnership()
	if setupErr != nil {
		if netnsCreated {
			if cleanupErr := daeNetns.Close(); cleanupErr != nil && log != nil {
				log.WithError(cleanupErr).Warn("failed to clean dae netns after setup failure")
			}
		}
		return nil, fmt.Errorf("failed to setup dae netns: %w", setupErr)
	}
	defer func() {
		if err == nil || !netnsCreated {
			return
		}
		if cleanupErr := daeNetns.Close(); cleanupErr != nil && log != nil {
			log.WithError(cleanupErr).Warn("failed to clean dae netns after control plane build failure")
		}
	}()
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	ephemeralPinPath := false
	if _bpf == nil && buildOpts.IsReload {
		pinPath = filepath.Join(pinPath, fmt.Sprintf("reload-%d-%d", os.Getpid(), time.Now().UnixNano()))
		ephemeralPinPath = true
	}
	if err = ensureBpfPinDir(pinPath, log); err != nil {
		return nil, err
	}
	if ephemeralPinPath {
		defer func() {
			if err == nil {
				return
			}
			if cleanupErr := os.RemoveAll(pinPath); cleanupErr != nil && log != nil {
				log.WithError(cleanupErr).Warnf("Failed to clean reload BPF pin directory %s after build error", pinPath)
			}
		}()
	}

	/// Load pre-compiled programs and maps into the kernel.
	if _bpf == nil {
		// Conn-state maps are preserved across in-process reload via object handoff,
		// so fresh loads should not inherit stale bpffs pins from previous processes.
		if !ephemeralPinPath {
			cleanupEphemeralBpfPinDirs(log, pinPath)
			cleanupPinnedConnStateMapFiles(log, pinPath)
		}
		if err := checkCtx("load eBPF objects"); err != nil {
			return nil, err
		}
		log.Infof("Loading eBPF programs and maps into the kernel...")
		log.Infof("The loading process takes about 120MB free memory, which will be released after loading. Insufficient memory will cause loading failure.")
	}
	// var bpf bpfObjects
	ProgramOptions := ebpf.ProgramOptions{
		KernelTypes: nil,
	}
	if log.Level == logrus.PanicLevel {
		ProgramOptions.LogLevel = ebpf.LogLevelBranch | ebpf.LogLevelStats
		// ProgramOptions.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
	}
	collectionOpts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ProgramOptions,
	}
	connStateMapMaxEntries := global.BpfConnStateMapSize
	if freshDatapathState != nil {
		connStateMapMaxEntries, err = freshDatapathState.apply(collectionOpts, connStateMapMaxEntries, log)
		if err != nil {
			return nil, err
		}
	}

	var bpf *bpfObjects
	if _bpf != nil {
		if obj, ok := _bpf.(*bpfObjects); ok {
			bpf = obj
		} else {
			return nil, fmt.Errorf("unexpected bpf type: %T", _bpf)
		}
	} else {
		bpf = new(bpfObjects)
		datapathGeneration := nextDatapathGeneration()
		if err = fullLoadBpfObjects(log, bpf, &loadBpfOptions{
			PinPath:                pinPath,
			CollectionOptions:      collectionOpts,
			ConnStateMapMaxEntries: connStateMapMaxEntries,
			DatapathGeneration:     datapathGeneration,
		}, global.SoMarkFromDae); err != nil {
			if log.Level == logrus.PanicLevel {
				log.Panicln(err)
			}
			return nil, fmt.Errorf("load eBPF objects: %w", err)
		}
		registerBpfDatapathGeneration(bpf, datapathGeneration)
	}
	sharedBpfReload := _bpf != nil
	// Ensure critical maps are always present. DNS fast-path optimizations only
	// skip per-flow map updates, never map object creation.
	if err = validateRequiredBpfMapsLoaded(bpf); err != nil {
		// On a fresh load the objects are solely owned here: no core, no
		// deferFuncs, and LoadAndAssign already moved every object out of
		// the loader. Close them explicitly or the whole set leaks until
		// process exit (shared reloads keep ownership elsewhere and must
		// not close here).
		if !sharedBpfReload {
			_ = bpf.Close()
		}
		return nil, fmt.Errorf("validate bpf maps: %w", err)
	}
	log.Infof("Loaded eBPF programs and maps")
	// outboundId2Name can be modified later.
	outboundId2Name := make(map[uint8]string)
	core := newControlPlaneCore(
		log,
		bpf,
		outboundId2Name,
		&kernelVersion,
		buildOpts.IsReload,
		!sharedBpfReload,
	)
	// A prepared shared-BPF routing-epoch generation must not overwrite the
	// active generation's health map while it is still only a candidate. The
	// runtime supervisor resumes its writes after publish, or leaves it paused
	// while rollback restores the old generation.
	if buildOpts.DelayDatapathCommit && sharedBpfReload {
		core.pauseOutboundConnectivityUpdates()
	}
	if ephemeralPinPath {
		core.addDeferFunc(func() error {
			return os.RemoveAll(pinPath)
		})
	}
	var constructedPlane *ControlPlane
	defer func() {
		if err != nil {
			if constructedPlane != nil {
				_ = constructedPlane.Close()
			} else {
				// Fallback cleanup if plane was not yet fully constructed.
				for i := len(deferFuncs) - 1; i >= 0; i-- {
					_ = deferFuncs[i]()
				}
				_ = core.Close()
			}
		}
	}()

	/// DialerGroups (outbounds).
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	directDialer := buildOpts.DirectDialer
	if directDialer == nil {
		directDialer = direct.SymmetricDirect
	}
	fullconeDirectDialer := buildOpts.FullconeDirectDialer
	if fullconeDirectDialer == nil {
		fullconeDirectDialer = direct.FullconeDirect
	}
	systemDNSResolver := buildOpts.SystemDNSResolver
	if systemDNSResolver == nil {
		systemDNSResolver = netutils.NewSystemDNSResolver(netip.MustParseAddrPort(global.FallbackResolver))
	}

	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	option := dialer.NewGlobalOption(global, log)
	option.SetRuntimeDependencies(directDialer, fullconeDirectDialer, systemDNSResolver)

	// A proxy transport may have to resolve a peer-supplied domain-typed address
	// on its datagram read path. Point that lookup at this generation's DNS view
	// -- the system resolver with its configured fallback -- instead of the bare
	// process resolver: inside a netns, or on a host whose /etc/resolv.conf is
	// empty or points back at dae itself, the process resolver hangs or fails.
	// The answer becomes the source address of a datagram sent to a client, so
	// it must be a real record: no routing rewrite, no synthetic address.
	protocol.SetDatapathResolver(func(ctx context.Context, host string) (netip.Addr, error) {
		dns, err := systemDNSResolver.SystemDNS()
		if err != nil {
			return netip.Addr{}, err
		}
		ips, err4, err6 := netutils.ResolveIp46(ctx, directDialer, dns, host, "udp", true)
		if ips.Ip4.IsValid() {
			return ips.Ip4, nil
		}
		if ips.Ip6.IsValid() {
			return ips.Ip6, nil
		}
		if err4 != nil {
			return netip.Addr{}, err4
		}
		if err6 != nil {
			return netip.Addr{}, err6
		}
		return netip.Addr{}, fmt.Errorf("no address for %q", host)
	})

	option.DaeDNS, err = daedns.NewWithOption(log, global, dnsConfig, &daedns.NewOption{
		LocationFinder: locationFinder,
		DirectDialer:   directDialer,
	})
	if err != nil {
		return nil, err
	}
	if option.DaeDNS != nil {
		deferFuncs = append(deferFuncs, option.DaeDNS.Close)
	}

	// Dial mode.
	dialMode, err := consts.ParseDialMode(global.DialMode)
	if err != nil {
		return nil, err
	}
	sniffingTimeout := global.SniffingTimeout
	if dialMode == consts.DialMode_Ip {
		sniffingTimeout = 0
	}
	disableKernelAliveCallback := dialMode != consts.DialMode_Ip
	_direct, directProperty := dialer.NewDirectDialer(option, true)
	direct := dialer.NewDialerContext(context.Background(), _direct, option, dialer.InstanceOption{DisableCheck: true}, directProperty)
	_block, blockProperty := dialer.NewBlockDialer(option, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialerContext(context.Background(), _block, option, dialer.InstanceOption{DisableCheck: true}, blockProperty)
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(),
			[]*dialer.Dialer{direct}, []*dialer.Annotation{{}},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, core.outboundAliveChangeCallback(0, disableKernelAliveCallback)),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(),
			[]*dialer.Dialer{block}, []*dialer.Annotation{{}},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, core.outboundAliveChangeCallback(1, disableKernelAliveCallback)),
	}

	// Filter out groups.
	if err := checkCtx("resolve subscription links"); err != nil {
		return nil, err
	}
	dialerSet := outbound.NewDialerSetFromLinksContext(context.Background(), option, tagToNodeList)
	deferFuncs = append(deferFuncs, dialerSet.Close)
	deferFuncs = append(deferFuncs, func() error {
		dialer.CleanupTransportCacheNamespace(option.TransportCacheNamespace)
		return nil
	})
	for _, group := range groups {
		// Parse policy.
		policy, err := outbound.NewDialerSelectionPolicyFromGroupParam(&group)
		if err != nil {
			return nil, fmt.Errorf("failed to create group %v: %w", group.Name, err)
		}
		// Filter nodes with user given filters.
		dialers, annos, err := dialerSet.FilterAndAnnotate(group.Filter, group.FilterAnnotation)
		if err != nil {
			return nil, fmt.Errorf(`failed to create group "%v": %w`, group.Name, err)
		}
		// Convert node links to dialers.
		if log.IsLevelEnabled(logrus.DebugLevel) {
			log.Debugf(`Group "%v" node list:`, group.Name)
			for _, d := range dialers {
				log.Debugln("\t" + d.Property().Name)
			}
			if len(dialers) == 0 {
				log.Debugln("\t<Empty>")
			}
		}
		groupOption, err := parseGroupOverrideOptionWithRuntime(group, *global, log, option)
		finalOption := option
		if err == nil && groupOption != nil {
			newDialers := make([]*dialer.Dialer, 0)
			for _, d := range dialers {
				newDialer := d.CloneWithGlobalOptionContext(context.Background(), groupOption)
				deferFuncs = append(deferFuncs, newDialer.Close)
				newDialers = append(newDialers, newDialer)
			}
			log.Infof(`Group "%v"'s check option has been override.`, group.Name)
			dialers = newDialers
			finalOption = groupOption
		}
		// Create dialer group and append it to outbounds.
		dialerGroup := outbound.NewDialerGroup(finalOption, group.Name, dialers, annos, *policy,
			core.outboundAliveChangeCallback(uint8(len(outbounds)), disableKernelAliveCallback))
		outbounds = append(outbounds, dialerGroup)
	}

	registeredDialerCallbacks := make(map[*dialer.Dialer]struct{})
	for _, group := range outbounds {
		for _, d := range group.Dialers {
			if _, ok := registeredDialerCallbacks[d]; ok {
				continue
			}
			registeredDialerCallbacks[d] = struct{}{}
			d.RegisterAliveTransitionCallback(core.dialerAliveTransitionCallback(d))
		}
	}

	/// Routing.
	// Generate outboundName2Id from outbounds.
	if len(outbounds) > int(consts.OutboundUserDefinedMax) {
		return nil, fmt.Errorf("too many outbounds")
	}
	outboundName2Id := make(map[string]uint8)
	for i, o := range outbounds {
		if _, exist := outboundName2Id[o.Name]; exist {
			return nil, fmt.Errorf("duplicated outbound name: %v", o.Name)
		}
		outboundName2Id[o.Name] = uint8(i)
		outboundId2Name[uint8(i)] = o.Name
	}
	// Apply rules optimizers.
	log.Infoln("Optimizing and loading routing rules (this may take a while for large rule sets)...")
	if err := checkCtx("optimize routing rules"); err != nil {
		return nil, err
	}
	routingProgram, err := routing.NewNormalizedProgram(routingA.Rules, routingA.Fallback,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: log, LocationFinder: locationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}
	routingA.Rules = nil // Release.
	// Device-scoped whitelists (selector && domain -> group followed by a
	// selector-only -> direct/block line) cannot match in kernel space when
	// the client's DNS bypasses dae: the domain half has no bitmap and every
	// connection of the device falls to the fallback. With sniffing
	// available, inject kernel-space-only sniff-punt lines so those
	// connections are re-routed userspace-side from the sniffed domain.
	// Runs before the policy identity is derived so the injected lines are
	// part of the policy hash.
	if sniffingTimeout > 0 && global.AutoSniffPunt {
		var injections []routing.SniffPuntInjection
		routingProgram.Rules, injections = routing.InferSniffPunt(routingProgram.Rules)
		for _, inj := range injections {
			log.Infof("Auto sniff-punt: injected %v -> %v before rule #%v; connections of this selector without kernel-space domain knowledge are sniffed and re-routed from the sniffed domain",
				inj.Selector, consts.OutboundControlPlaneRouting.String(), inj.FallbackRuleIndex)
		}
	}
	policyEpoch := routing.PolicyEpoch(policyEpochSequence.Add(1))
	policyIdentity, err := routing.NewPolicyIdentity(policyEpoch, routingProgram)
	if err != nil {
		return nil, fmt.Errorf("create routing policy identity: %w", err)
	}
	if _, err = core.PrepareRoutingEpoch(policyIdentity.Epoch(), sharedBpfReload); err != nil {
		return nil, fmt.Errorf("prepare routing epoch: %w", err)
	}
	if err = core.clearDomainRoutingSlot(core.RoutingEpochSlot()); err != nil {
		return nil, fmt.Errorf("clear inactive domain routing epoch: %w", err)
	}
	if log.IsLevelEnabled(logrus.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range routingProgram.Rules {
			debugBuilder.WriteString(rule.String(true, false, false) + "\n")
		}
		log.Debugf("RoutingA:\n%vfallback: %v\n", debugBuilder.String(), routingProgram.Fallback)
	}
	// Parse rules and build.
	log.Infoln("Building routing matcher...")
	builder, err := NewRoutingMatcherBuilderFromProgram(log, routingProgram, outboundName2Id, core.bpf.Load())
	if err != nil {
		return nil, fmt.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	kernspaceSnapshot := builder.KernspaceSnapshot()
	if !buildOpts.DelayDatapathCommit {
		log.Infoln("Loading routing rules into kernel space (BPF)...")
		if err = core.buildRoutingKernspaceForSlot(log, kernspaceSnapshot); err != nil {
			return nil, fmt.Errorf("routing kernspace snapshot: %w", err)
		}
		if err = core.StageRoutingEpoch(); err != nil {
			return nil, fmt.Errorf("stage routing epoch: %w", err)
		}
	} else {
		log.Infoln("Prepared routing matcher; kernel-space routing commit deferred until listener cutover")
	}
	log.Infoln("Building userspace routing matcher...")
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}

	// Get referenced outbounds to limit health checks.
	referencedOutbounds := builder.GetReferencedOutbounds()
	if len(referencedOutbounds) > 0 {
		var names []string
		for name := range referencedOutbounds {
			names = append(names, name)
		}
		log.Infof("Health check will only verify %d outbounds referenced by routing rules: %v",
			len(names), names)
	} else {
		log.Warnln("No outbounds referenced by routing rules; all outbounds will be health-checked")
		// If no outbounds are referenced (e.g., all rules use logical operators),
		// fall back to checking all outbounds to avoid breaking existing behavior.
		for _, o := range outbounds {
			referencedOutbounds[o.Name] = struct{}{}
		}
	}

	// Routing compilation allocates large temporary slices and trie builders.
	// Startup/reload is infrequent.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Infof("Memory usage after routing build: Alloc=%vMiB, Sys=%vMiB, HeapObjects=%v",
		m.Alloc/1024/1024, m.Sys/1024/1024, m.HeapObjects)

	// Transfer every dialer, group health registration and the shared transport
	// cache namespace into structured runtime ownership. The constructor's
	// defer stack remains responsible until this point.
	egressDialers := dialerSet.AllDialers()
	for _, group := range outbounds {
		if group != nil {
			egressDialers = append(egressDialers, group.Dialers...)
		}
	}
	egressRuntime := newEgressRuntime(log, []func() error{func() error {
		dialer.CleanupTransportCacheNamespace(option.TransportCacheNamespace)
		return nil
	}})
	egressRuntime.configureResources(outbounds, egressDialers, DefaultUdpEndpointPool.forgetDialerEpochs)
	var planeDeferFuncs []func() error
	if option.DaeDNS != nil {
		planeDeferFuncs = append(planeDeferFuncs, option.DaeDNS.Close)
	}
	deferFuncs = nil

	// New control plane.
	cctx, cancel := context.WithCancel(context.Background())
	plane = &ControlPlane{
		log:           log,
		directDialer:  directDialer,
		runtimeStats:  newRuntimeStats(),
		core:          core,
		deferFuncs:    planeDeferFuncs,
		listenIp:      "0.0.0.0",
		egressRuntime: egressRuntime,
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:           outbounds,
			referencedOutbounds: referencedOutbounds,
			dialMode:            dialMode,
			policyIdentity:      policyIdentity,
			routingMatcher:      routingMatcher,
			bootstrapResolvers:  bootstrapResolvers,
		},
		controlPlaneDNSRuntime: newControlPlaneDNSRuntime(buildOpts.DelayDNSListenerStart),
		controlPlaneDatapathJanitor: controlPlaneDatapathJanitor{
			stop: make(chan struct{}),
		},
		onceNetworkReady:              sync.Once{},
		drainTracker:                  newControlPlaneDrainTracker(),
		ctx:                           cctx,
		cancel:                        cancel,
		ready:                         make(chan struct{}),
		autoConfigKernelParameter:     global.AutoConfigKernelParameter,
		routingKernspaceSnapshot:      kernspaceSnapshot,
		preparedDatapathCommit:        buildOpts.DelayDatapathCommit,
		sharedBpfReload:               sharedBpfReload,
		pendingDnsReloadCache:         dnsCache,
		dnsRoutingUnchanged:           buildOpts.DNSRoutingUnchanged,
		controlPlaneRealDomainRuntime: newControlPlaneRealDomainRuntime(),
		lanInterface:                  global.LanInterface,
		wanInterface:                  global.WanInterface,
		sniffingTimeout:               sniffingTimeout,
		tproxyPortProtect:             global.TproxyPortProtect,
		soMarkFromDae:                 global.SoMarkFromDae,
		mptcp:                         global.Mptcp,
		udpRouteScopeSensitive:        builder.UsesPacketMetadataRouting(),
		controlPlaneUDPRuntime: controlPlaneUDPRuntime{
			failedQuicDcidCache:  newFailedQuicDcidCache(failedQuicDcidCacheMaxEntries),
			udpDirectDispatchSem: make(chan struct{}, udpDirectDispatchConcurrency),
		},
	}
	constructedPlane = plane
	SetFailedQuicDcidCache(plane.failedQuicDcidCache)
	SetAnyfromSoMark(global.SoMarkFromDae)
	plane.deferFuncs = append(plane.deferFuncs, plane.closePublishedListenerFiles)
	plane.startRealDomainNegJanitor()

	var upstreamHostResolver func(ctx context.Context, host string, network string) (*netutils.Ip46, error, error)
	if len(bootstrapResolvers) > 0 {
		upstreamHostResolver = plane.resolveBootstrapIp46
	}

	/// DNS upstream.
	dnsUpstream, err := dns.New(dnsConfig, &dns.NewOption{
		Logger:                  log,
		LocationFinder:          locationFinder,
		UpstreamReadyCallback:   plane.dnsUpstreamReadyCallback,
		UpstreamResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp),
		UpstreamHostResolver:    upstreamHostResolver,
	})
	if err != nil {
		return nil, err
	}
	/// Dns controller.
	fixedDomainTtl, err := ParseFixedDomainTtl(dnsConfig.FixedDomainTtl)
	if err != nil {
		return nil, err
	}
	plane.dnsRouting = dnsUpstream
	plane.dnsFixedDomainTtl = fixedDomainTtl
	plane.dnsOptimisticCache = dnsConfig.OptimisticCache
	plane.dnsOptimisticCacheTtl = dnsConfig.OptimisticCacheTtl
	plane.dnsOptimisticStaleReplyTtl = dnsConfig.OptimisticStaleReplyTtl
	plane.dnsMaxCacheSize = dnsConfig.MaxCacheSize
	plane.dnsIpVersionPrefer = dnsConfig.IpVersionPrefer
	plane.dnsController, err = NewDnsController(dnsUpstream, plane.dnsControllerOption())
	if err != nil {
		return nil, err
	}
	plane.deferFuncs = append(plane.deferFuncs, plane.closeOwnedDNSController)

	// Create and start DNS listener if configured
	if dnsConfig.Bind != "" {
		plane.dnsListener, err = NewDNSListener(log, dnsConfig.Bind, plane)
		if err != nil {
			return nil, err
		}
		if !buildOpts.DelayDNSListenerStart {
			if err = plane.dnsListener.Start(); err != nil {
				log.Errorf("Failed to start DNS listener: %v", err)
			} else {
				log.Infof("DNS listener started on %s", dnsConfig.Bind)
				plane.registerDNSListenerStop()
			}
		}
	}

	// Init immediately to avoid DNS leaking in the very beginning because param control_plane_dns_routing will
	// be set in callback.
	if err = dnsUpstream.CheckUpstreamsFormat(); err != nil {
		return nil, err
	}
	dnsUpstreamsReady := plane.dnsUpstreamsReady
	dnsUpstreamsCtx := plane.ctx
	go func() {
		defer close(dnsUpstreamsReady)
		dnsUpstream.InitUpstreams(dnsUpstreamsCtx)
	}()

	if buildOpts.DelayDatapathCommit {
		plane.bpfMaintenance = bindBpfMaintenanceRuntime(core.PeekBpf(), plane)
		plane.preparedDatapathCommit = true
	} else {
		if err = plane.commitInterfaceBindings(); err != nil {
			return nil, err
		}
		if err = plane.replayDnsReloadCache(); err != nil {
			return nil, fmt.Errorf("replay DNS reload cache: %w", err)
		}
		if err = core.PublishRoutingEpoch(); err != nil {
			return nil, fmt.Errorf("publish routing epoch: %w", err)
		}
		if err = core.commitBpfHookFlip(); err != nil {
			if rollbackErr := core.RollbackRoutingEpoch(); rollbackErr != nil {
				return nil, stderrors.Join(err, rollbackErr)
			}
			return nil, err
		}
		plane.bpfMaintenance = bindBpfMaintenanceRuntime(core.PeekBpf(), plane)
		plane.startConnStateJanitor()
		plane.releaseCommittedDNSReloadState()
		plane.markReady()
	}
	return plane, nil
}

// clearReloadDomainRoutingMapSlot clears one routing epoch slot of the domain
// routing map.
// IMPORTANT: Connection-state maps are preserved across in-process reload
// (Scheme3 Embedded Design). Do NOT clear them here.
func clearReloadDomainRoutingMapSlot(bpf *bpfObjects, slot uint32) error {
	if bpf == nil || bpf.DomainRoutingMap == nil {
		return nil
	}
	if !validRoutingEpochSlot(slot) {
		return fmt.Errorf("invalid domain routing epoch slot %d", slot)
	}

	var (
		key   bpfRoutingEpochIp
		value bpfDomainRouting
		keys  []bpfRoutingEpochIp
		iter  = bpf.DomainRoutingMap.Iterate()
	)
	for iter.Next(&key, &value) {
		if key.Slot == slot {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate domain routing slot %d: %w", slot, err)
	}
	if len(keys) == 0 {
		return nil
	}
	if _, err := BpfMapBatchDelete(bpf.DomainRoutingMap, keys); err != nil {
		return fmt.Errorf("clear domain routing slot %d: %w", slot, err)
	}
	return nil
}

// validateRequiredBpfMapsLoaded checks maps that are required by both DNS and
// non-DNS datapaths. DNS fast-path may skip per-flow entry updates, but these
// map objects must always exist.
func validateRequiredBpfMapsLoaded(bpf *bpfObjects) error {
	if bpf == nil {
		return fmt.Errorf("nil bpf objects")
	}
	required := []struct {
		name string
		m    *ebpf.Map
	}{
		{name: "domain_routing_map", m: bpf.DomainRoutingMap},
		{name: "conn_state_map", m: bpf.ConnStateMap},
		{name: "routing_handoff_map", m: bpf.RoutingHandoffMap},
		{name: "routing_map", m: bpf.RoutingMap},
		{name: "routing_meta_map", m: bpf.RoutingMetaMap},
		{name: "active_routing_epoch_map", m: bpf.ActiveRoutingEpochMap},
	}
	for _, r := range required {
		if r.m == nil {
			return fmt.Errorf("required map %q is nil", r.name)
		}
	}
	return nil
}

func (c *ControlPlane) EjectBpf() *bpfObjects {
	if c.core == nil {
		return nil
	}
	return c.core.EjectBpf()
}

func (c *ControlPlane) InjectBpf(bpf *bpfObjects) {
	c.core.InjectBpf(bpf)
}

func (c *ControlPlane) PeekBpf() *bpfObjects {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.PeekBpf()
}

func (c *ControlPlane) ActiveSessionCount() int {
	if c == nil || c.drainTracker == nil {
		return 0
	}
	return c.drainTracker.Count()
}

func (c *ControlPlane) DrainIdleCh() <-chan struct{} {
	if c == nil || c.drainTracker == nil {
		return closedDrainIdleCh
	}
	return c.drainTracker.IdleCh()
}

func (c *ControlPlane) ReplaceLpmIndices(indices []uint32) {
	if c == nil || c.core == nil {
		return
	}
	c.core.ReplaceLpmIndices(indices)
}

func (c *ControlPlane) currentBpf() *bpfObjects {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.PeekBpf()
}

func (c *ControlPlane) acquireDrainTicket() func() {
	if c == nil || c.drainTracker == nil {
		return func() {}
	}
	return c.drainTracker.Acquire()
}

// InheritDialerHealthFrom copies health snapshots from a previous control plane
// generation into the current one, so a reload does not reset health for
// dialers that both generations share.
func (c *ControlPlane) InheritDialerHealthFrom(previous *ControlPlane) {
	if c == nil || previous == nil {
		return
	}

	previousGroups := make(map[string]*outbound.DialerGroup, len(previous.outbounds))
	for _, group := range previous.outbounds {
		if group == nil {
			continue
		}
		previousGroups[group.Name] = group
	}

	for _, group := range c.outbounds {
		if group == nil {
			continue
		}
		oldGroup := previousGroups[group.Name]
		if oldGroup == nil {
			continue
		}
		fallback := group.CaptureReloadSelectionFallback()
		oldDialers := make(map[string]*dialer.Dialer, len(oldGroup.Dialers))
		for _, d := range oldGroup.Dialers {
			if d == nil || d.Property() == nil {
				continue
			}
			oldDialers[d.Property().Name] = d
		}
		for _, d := range group.Dialers {
			if d == nil || d.Property() == nil {
				continue
			}
			if oldDialer := oldDialers[d.Property().Name]; oldDialer != nil {
				if dialerHealthCheckConfigEqual(d, oldDialer) {
					d.RestoreHealthSnapshot(oldDialer.ReloadHealthSnapshot())
				}
			}
		}
		group.EnsureReloadSelectionFloor(fallback)
	}
}

func dialerHealthCheckConfigEqual(current, previous *dialer.Dialer) bool {
	if current == nil || previous == nil || current.GlobalOption == nil || previous.GlobalOption == nil {
		return false
	}
	return slices.Equal(current.TcpCheckOptionRaw.Raw, previous.TcpCheckOptionRaw.Raw) &&
		current.TcpCheckOptionRaw.Method == previous.TcpCheckOptionRaw.Method &&
		current.TcpCheckOptionRaw.ResolverNetwork == previous.TcpCheckOptionRaw.ResolverNetwork &&
		slices.Equal(current.CheckDnsOptionRaw.Raw, previous.CheckDnsOptionRaw.Raw) &&
		current.CheckDnsOptionRaw.ResolverNetwork == previous.CheckDnsOptionRaw.ResolverNetwork &&
		current.CheckDnsOptionRaw.Somark == previous.CheckDnsOptionRaw.Somark
}

func isIgnorableBatchLookupErr(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, ebpf.ErrKeyNotExist) ||
		stderrors.Is(err, os.ErrClosed) ||
		stderrors.Is(err, unix.EBADF) {
		return true
	}

	// Keep a compact string fallback for wrapped kernel/libbpf errors.
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "bad file descriptor") ||
		strings.Contains(errStr, "file descriptor") ||
		strings.Contains(errStr, "closed") ||
		strings.Contains(errStr, "key does not exist")
}

func (c *ControlPlane) markReady() {
	if c == nil {
		return
	}
	c.readyOnce.Do(func() {
		close(c.ready)
	})
}

func (c *ControlPlane) registerDNSListenerStop() {
	if c == nil {
		return
	}
	c.registerListenerStop(&c.deferFuncs, c.stopOwnedDNSListener)
}

func (c *ControlPlane) stopOwnedDNSListener() error {
	if c == nil {
		return nil
	}
	return c.controlPlaneDNSRuntime.stopOwnedDNSListener()
}

func (c *ControlPlane) closeOwnedDNSController() error {
	if c == nil {
		return nil
	}
	return c.controlPlaneDNSRuntime.closeOwnedDNSController()
}

var domainRoutingMapFullLastLog atomic.Int64

// logDomainRoutingMapFull reports a saturated domain_routing_map at most once a
// minute, so a sustained overflow cannot flood the log from the DNS hot path.
func (c *ControlPlane) logDomainRoutingMapFull(cache *DnsCache) {
	if c == nil || c.log == nil {
		return
	}
	now := time.Now().UnixNano()
	last := domainRoutingMapFullLastLog.Load()
	if now-last < int64(time.Minute) || !domainRoutingMapFullLastLog.CompareAndSwap(last, now) {
		return
	}
	var fqdn string
	if cache != nil {
		fqdn = cache.GetFqdn()
	}
	c.log.WithField("domain", fqdn).Warn(
		"domain_routing_map is full; newly resolved domains fall back to userspace routing until cached entries expire")
}

func (c *ControlPlane) dnsControllerOption() *DnsControllerOption {
	if c == nil {
		return nil
	}
	policyIdentity := c.PolicyIdentity()
	routeProjectionEpoch := uint64(policyIdentity.Epoch())
	return &DnsControllerOption{
		Log:              c.log,
		LifecycleContext: c.ctx,
		ConcurrencyLimit: 0,
		CacheAccessCallback: func(cache *DnsCache) (err error) {
			if err = c.core.BatchUpdateDomainRouting(cache); err != nil {
				if stderrors.Is(err, ErrBpfMapFull) {
					// The answer itself is valid; only the kernel-side domain
					// bitmap could not be projected. Failing the query would
					// take DNS down for every new domain until entries expire,
					// so degrade to routing this domain in userspace and let
					// the projection retry once the map drains.
					c.logDomainRoutingMapFull(cache)
					return nil
				}
				return fmt.Errorf("BatchUpdateDomainRouting: %w", err)
			}
			return nil
		},
		CacheDeleteCallback: func(cacheKey string, cache *DnsCache) (err error) {
			_ = cacheKey
			if err = c.core.BatchRemoveDomainRouting(cache); err != nil {
				return fmt.Errorf("BatchRemoveDomainRouting: %w", err)
			}
			return nil
		},
		RouteProjectionEpoch: routeProjectionEpoch,
		RouteProjectionHash:  policyIdentity.Hash(),
		ProjectCacheRoute: func(cache *DnsCache) []uint32 {
			if cache == nil {
				return nil
			}
			return c.routingMatcher.domainMatcher.MatchDomainBitmap(cache.GetFqdn())
		},
		NewCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error) {
			return &DnsCache{
				RouteProjectionEpoch: routeProjectionEpoch,
				DomainBitmap:         c.routingMatcher.domainMatcher.MatchDomainBitmap(fqdn),
				NS:                   ns,
				Extra:                extra,
				Answer:               answers,
				Deadline:             deadline,
				OriginalDeadline:     originalDeadline,
			}, nil
		},
		BestDialerChooser: c.chooseBestDnsDialerSnapshot,
		TimeoutExceedCallback: func(dialArgument *dialArgument, err error) {
			if commonerrors.IsIgnorableConnectionError(err) {
				return
			}
			c.penalizeDnsDialArg(dialArgument, time.Now())
			if dialArgument == nil || dialArgument.l4proto == consts.L4ProtoStr_UDP {
				return
			}
			dialArgument.bestDialer.ReportUnavailable(&dialer.NetworkType{
				L4Proto:         dialArgument.l4proto,
				IpVersion:       dialArgument.ipversion,
				IsDns:           true,
				UdpHealthDomain: dialer.UdpHealthDomainDns,
			}, err)
		},
		FixedDomainTtl:          c.dnsFixedDomainTtl,
		OptimisticCache:         c.dnsOptimisticCache,
		OptimisticCacheTtl:      c.dnsOptimisticCacheTtl,
		OptimisticStaleReplyTtl: c.dnsOptimisticStaleReplyTtl,
		MaxCacheSize:            c.dnsMaxCacheSize,
		IpVersionPrefer:         c.dnsIpVersionPrefer,
	}
}

func (c *ControlPlane) dnsUpstreamReadyCallback(dnsUpstream *dns.Upstream) (err error) {
	if c != nil {
		c.noteDNSUpstreamAvailable()
	}
	// Waiting for ready.
	select {
	case <-c.ctx.Done():
		return nil
	case <-c.ready:
	}

	///  Notify dialers to check.
	c.onceNetworkReady.Do(func() {
		for _, out := range c.outbounds {
			for _, d := range out.Dialers {
				d.NotifyCheck()
			}
		}
	})
	if dnsUpstream == nil {
		return nil
	}

	/// Updates dns cache to support domain routing for hostname of dns_upstream.
	// Ten years later.
	deadline := time.Now().Add(time.Hour * 24 * 365 * 10)
	fqdn := dnsmessage.CanonicalName(dnsUpstream.Hostname)

	if dnsUpstream.Ip4.IsValid() {
		typ := dnsmessage.TypeA
		answers := []dnsmessage.RR{&dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(fqdn),
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // Must be zero.
			},
			A: dnsUpstream.Ip4.AsSlice(),
		}}
		ttl := max(int(time.Until(deadline).Seconds()), 0)
		if err = c.dnsController.UpdateDnsCacheTtl(dnsUpstream.Hostname, typ, answers, nil, nil, ttl); err != nil {
			return err
		}
	}

	if dnsUpstream.Ip6.IsValid() {
		typ := dnsmessage.TypeAAAA
		answers := []dnsmessage.RR{&dnsmessage.AAAA{
			Hdr: dnsmessage.RR_Header{
				Name:   dnsmessage.CanonicalName(fqdn),
				Rrtype: typ,
				Class:  dnsmessage.ClassINET,
				Ttl:    0, // Must be zero.
			},
			AAAA: dnsUpstream.Ip6.AsSlice(),
		}}
		ttl := max(int(time.Until(deadline).Seconds()), 0)
		if err = c.dnsController.UpdateDnsCacheTtl(dnsUpstream.Hostname, typ, answers, nil, nil, ttl); err != nil {
			return err
		}
	}
	return nil
}

type dnsDialerSnapshotKey struct {
	realSrc      netip.AddrPort
	upstream     string
	upstreamIp4  netip.Addr
	upstreamIp6  netip.Addr
	routingPname [16]uint8
	routingMac   [6]uint8
	routingDscp  uint8
}

type dnsDialerSnapshotEntry struct {
	expiresAtUnixNano int64
	dialArg           dialArgument
}

type dnsDialerPenaltyKey struct {
	dialer    *dialer.Dialer
	target    netip.AddrPort
	l4proto   consts.L4ProtoStr
	ipversion consts.IpVersionStr
}

type dnsDialerPenaltyEntry struct {
	expiresAtUnixNano int64
}

type dnsDialerCandidate struct {
	dialArg *dialArgument
	latency time.Duration
}

func pickBetterDnsDialerCandidate(best, candidate *dnsDialerCandidate) *dnsDialerCandidate {
	if candidate == nil {
		return best
	}
	if best == nil || candidate.latency < best.latency {
		return candidate
	}
	return best
}

func chooseDnsDialerCandidate(preferred, penalized *dnsDialerCandidate) (*dnsDialerCandidate, bool) {
	if preferred != nil {
		return preferred, false
	}
	if penalized != nil {
		return penalized, true
	}
	return nil, false
}

func buildDnsDialerSnapshotKeyForSnapshot(snapshot DnsRequestSnapshot, upstream *dns.Upstream) (dnsDialerSnapshotKey, bool) {
	if upstream == nil {
		return dnsDialerSnapshotKey{}, false
	}

	realSrc := snapshot.RealSrc
	// DNS fast path: exempt source port from cache key to enable cache reuse.
	// DNS queries use random source ports; including the port would completely invalidate the cache.
	// Routing decisions do not depend on the DNS query's source port (port is only for transport layer multiplexing).
	if snapshot.RealDst.Port() == 53 {
		realSrc = netip.AddrPortFrom(snapshot.RealSrc.Addr(), 0)
	}

	key := dnsDialerSnapshotKey{
		realSrc:     realSrc,
		upstream:    upstream.String(),
		upstreamIp4: upstream.Ip4,
		upstreamIp6: upstream.Ip6,
	}

	if routingResult := snapshot.routingResultForRoute(); routingResult != nil {
		key.routingPname = routingResult.Pname
		key.routingMac = routingResult.Mac
		key.routingDscp = routingResult.Dscp
	}

	return key, true
}

func (c *ControlPlane) loadDnsDialerSnapshot(key dnsDialerSnapshotKey, now time.Time) (*dialArgument, bool) {
	if dnsDialerSnapshotTTL <= 0 {
		return nil, false
	}

	v, ok := c.dnsDialerSnapshot.Load(key)
	if !ok {
		return nil, false
	}

	entry, ok := v.(*dnsDialerSnapshotEntry)
	if !ok {
		c.dnsDialerSnapshot.Delete(key)
		return nil, false
	}

	if entry.expiresAtUnixNano <= now.UnixNano() {
		c.dnsDialerSnapshot.CompareAndDelete(key, entry)
		return nil, false
	}

	dialArg := entry.dialArg
	if c.isDnsDialArgPenalized(&dialArg, now) {
		c.dnsDialerSnapshot.CompareAndDelete(key, entry)
		return nil, false
	}
	return &dialArg, true
}

func (c *ControlPlane) storeDnsDialerSnapshot(key dnsDialerSnapshotKey, dialArg *dialArgument, now time.Time) {
	if dnsDialerSnapshotTTL <= 0 || dialArg == nil {
		return
	}
	entry := &dnsDialerSnapshotEntry{
		expiresAtUnixNano: now.Add(dnsDialerSnapshotTTL).UnixNano(),
		dialArg:           *dialArg,
	}
	c.dnsDialerSnapshot.Store(key, entry)
}

func (c *ControlPlane) cleanupDnsDialerSnapshot(now time.Time) {
	nowNano := now.UnixNano()
	c.dnsDialerSnapshot.Range(func(key, value any) bool {
		entry, ok := value.(*dnsDialerSnapshotEntry)
		if !ok {
			c.dnsDialerSnapshot.Delete(key)
			return true
		}
		if entry.expiresAtUnixNano <= nowNano {
			c.dnsDialerSnapshot.CompareAndDelete(key, entry)
		}
		return true
	})
}

func (c *ControlPlane) cleanupDnsDialerPenalty(now time.Time) {
	nowNano := now.UnixNano()
	c.dnsDialerPenalty.Range(func(key, value any) bool {
		entry, ok := value.(*dnsDialerPenaltyEntry)
		if !ok {
			c.dnsDialerPenalty.Delete(key)
			return true
		}
		if entry.expiresAtUnixNano <= nowNano {
			c.dnsDialerPenalty.CompareAndDelete(key, entry)
		}
		return true
	})
}

func buildDnsDialerPenaltyKey(dialArg *dialArgument) (dnsDialerPenaltyKey, bool) {
	if dialArg == nil || dialArg.bestDialer == nil || !dialArg.bestTarget.IsValid() {
		return dnsDialerPenaltyKey{}, false
	}
	return dnsDialerPenaltyKey{
		dialer:    dialArg.bestDialer,
		target:    dialArg.bestTarget,
		l4proto:   dialArg.l4proto,
		ipversion: dialArg.ipversion,
	}, true
}

func (c *ControlPlane) isDnsDialArgPenalized(dialArg *dialArgument, now time.Time) bool {
	key, ok := buildDnsDialerPenaltyKey(dialArg)
	if !ok {
		return false
	}
	value, ok := c.dnsDialerPenalty.Load(key)
	if !ok {
		return false
	}
	entry, ok := value.(*dnsDialerPenaltyEntry)
	if !ok {
		c.dnsDialerPenalty.Delete(key)
		return false
	}
	if entry.expiresAtUnixNano <= now.UnixNano() {
		c.dnsDialerPenalty.CompareAndDelete(key, entry)
		return false
	}
	return true
}

func (c *ControlPlane) penalizeDnsDialArg(dialArg *dialArgument, now time.Time) {
	if dnsDialerPenaltyTTL <= 0 {
		return
	}
	key, ok := buildDnsDialerPenaltyKey(dialArg)
	if !ok {
		return
	}
	c.dnsDialerPenalty.Store(key, &dnsDialerPenaltyEntry{
		expiresAtUnixNano: now.Add(dnsDialerPenaltyTTL).UnixNano(),
	})
}

func (c *ControlPlane) startRealDomainNegJanitor() {
	go func() {
		ticker := time.NewTicker(realDomainNegJanitorInterval)
		defer ticker.Stop()
		defer close(c.negJanitorDone)
		for {
			select {
			case <-c.negJanitorStop:
				return
			case <-c.ctx.Done():
				return
			case now := <-ticker.C:
				c.cleanupNegativeCaches(now)
				c.cleanupDnsDialerSnapshot(now)
				c.cleanupDnsDialerPenalty(now)
			}
		}
	}()
}

func (c *ControlPlane) stopRealDomainNegJanitor() {
	c.negJanitorOnce.Do(func() {
		if c.negJanitorStop != nil {
			close(c.negJanitorStop)
		}
		if c.negJanitorDone != nil {
			timer := time.NewTimer(gracefulShutdownWaitTimeout)
			defer timer.Stop()
			select {
			case <-c.negJanitorDone:
			case <-timer.C:
				c.log.Warn("stopRealDomainNegJanitor: timeout waiting for janitor to exit")
			}
		}
	})
}

// RunReloadRetirementCleanup purges old-generation datapath state after a
// reload retires the previous control plane. staleBeforeNs is the monotonic
// timestamp of the reload request: entries not refreshed since that point
// belonged to the retired generation and are deleted immediately instead of
// waiting for their TTL. Entries kept by active flows (last_seen refreshed
// per packet) and by session-manager pins (adopted-but-idle sessions) survive.
func (c *ControlPlane) RunReloadRetirementCleanup(staleBeforeNs uint64) {
	if c == nil {
		return
	}
	if c.bpfMaintenance == nil || c.bpfMaintenance.runtime == nil {
		c.runReloadRetirementCleanup(staleBeforeNs)
		return
	}
	c.bpfMaintenance.runtime.request(c, staleBeforeNs)
}

func (c *ControlPlane) runReloadRetirementCleanup(staleBeforeNs uint64) {
	if c == nil {
		return
	}
	if c.core != nil {
		err := retryPreviousRoutingEpochCleanup(c.ctx, c.core.finalizePreviousRoutingEpoch, nil)
		if err != nil && c.log != nil {
			c.log.WithError(err).Warnln("[Reload] Failed to release previous routing epoch projection")
		}
	}
	if staleBeforeNs == 0 {
		return
	}

	cleanupMu, _ := c.maintenanceState()
	cleanupMu.Lock()
	redirectDeleted := c.cleanupRedirectTrackMapBeforeLocked(staleBeforeNs)
	cookieDeleted := c.cleanupCookiePidMapBeforeLocked(staleBeforeNs)
	routingHandoffDeleted := c.cleanupRoutingHandoffMapBeforeLocked(staleBeforeNs)
	udpStats, tcpStats := c.cleanupConnStateMapBeforeLocked(true, staleBeforeNs)
	cleanupMu.Unlock()

	if c.log == nil {
		return
	}
	if redirectDeleted == 0 && cookieDeleted == 0 && routingHandoffDeleted == 0 &&
		udpStats.deleted == 0 && tcpStats.deleted == 0 {
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.Debugln("[Reload] No stale datapath state remained after generation retirement")
		}
		return
	}
	c.log.WithFields(logrus.Fields{
		"redirect_deleted":        redirectDeleted,
		"cookie_pid_deleted":      cookieDeleted,
		"routing_handoff_deleted": routingHandoffDeleted,
		"udp_conn_deleted":        udpStats.deleted,
		"tcp_conn_deleted":        tcpStats.deleted,
	}).Infoln("[Reload] Cleaned stale datapath state after generation retirement")
}

// redirectTrackTimeout is the TTL for redirect entries.
// Redirect entries track which interface and MAC addresses to use for reply traffic.
// The TTL only governs entries with no live owner: cleanupRedirectTrackMap
// consults the pin snapshot BEFORE the age test, so a process-owned
// connection's entry is never retired by age while its flow lives - the pin,
// not the TTL, is what keeps an active connection's MAC mapping in place. For
// the unpinned remainder a longer TTL is acceptable because these entries are
// small and the consequence of a stale one is bounded: it is refreshed by the
// next reply packet, and until then it can only misdirect that one reply.
const redirectTrackTimeout = 5 * time.Minute

// cleanupRedirectTrackMap iterates through the redirect track map and removes
// entries that haven't been accessed within redirectTrackTimeout. Pinned
// entries are skipped before the age test, so a pinned long-lived connection
// keeps its own entry for as long as its flow lives without ever blocking the
// cleanup of any other entry: redirect_track is a HASH map, so there is no LRU
// eviction order for it to occupy.
func (c *ControlPlane) cleanupRedirectTrackMap() int {
	cleanupMu, _ := c.maintenanceState()
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	return c.cleanupRedirectTrackMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupRedirectTrackMapBeforeLocked(staleBeforeNs uint64) int {
	// Check if we're shutting down - if stop signal is sent, skip cleanup
	select {
	case <-c.stop:
		return 0
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.RedirectTrack == nil {
		return 0
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupRedirectTrackMap: failed to get monotonic time: %v", err)
		return 0
	}
	nowNano := ts.Nano()

	timeoutNano := redirectTrackTimeout.Nanoseconds()

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.redirectDelete)
	totalEntries := 0
	maxAge := int64(0)
	totalAge := int64(0)

	keysOut := ensureJanitorLookupScratch(scratch.redirectKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.redirectValues)
	defer func() {
		scratch.redirectDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.redirectKeys = keysOut
		scratch.redirectValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	manager, _ := c.controlPlaneSessionManager()
	for {
		count, err := bpf.RedirectTrack.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				key := keysOut[i]
				value := valuesOut[i]
				totalEntries++
				age := nowNano - int64(value.LastSeenNs)
				totalAge += age
				if age > maxAge {
					maxAge = age
				}
				if manager != nil && manager.isRedirectTrackPinned(key) {
					continue
				}
				if age > timeoutNano ||
					(staleBeforeNs > 0 && (value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, key)
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				c.log.Errorf("cleanupRedirectTrackMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	if len(keysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.RedirectTrack, keysToDelete); err != nil {
			c.log.Debugf("cleanupRedirectTrackMap: batch delete error: %v", err)
		}
	}

	// Only log when there are actual changes
	if len(keysToDelete) > 0 {
		c.log.Debugf("cleanupRedirectTrackMap: removed %d entries", len(keysToDelete))
	}

	// Alert if map usage is high. The capacity is read from the loaded map
	// instead of a second hard-coded copy of MAX_REDIRECT_TRACK_NUM: the map
	// capacity is owned by tuneRedirectTrackMap, which cross-checks the
	// compiled value against the Go constant at load time.
	redirectTrackCapacity := bpf.RedirectTrack.MaxEntries()
	if totalEntries > 0 && redirectTrackCapacity > 0 {
		usagePercent := float64(totalEntries) / float64(redirectTrackCapacity) * 100
		if usagePercent > 90 {
			c.logMapCapacityAlert(&c.redirectTrackCapacityAlert, "cleanupRedirectTrackMap", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// cleanupCookiePidMap removes stale cookie->pid metadata that escaped the
// cgroup sock_release backstop. Active sockets refresh last_seen_ns in BPF.
func (c *ControlPlane) cleanupCookiePidMap() int {
	cleanupMu, _ := c.maintenanceState()
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	return c.cleanupCookiePidMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupCookiePidMapBeforeLocked(staleBeforeNs uint64) int {
	select {
	case <-c.stop:
		return 0
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.CookiePidMap == nil {
		return 0
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupCookiePidMap: failed to get monotonic time: %v", err)
		return 0
	}
	nowNano := ts.Nano()
	timeoutNano := cookiePidMapTimeout.Nanoseconds()

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.cookiePidDelete)
	keysOut := ensureJanitorLookupScratch(scratch.cookiePidKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.cookiePidValues)
	totalEntries := 0
	defer func() {
		scratch.cookiePidDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.cookiePidKeys = keysOut
		scratch.cookiePidValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	for {
		count, err := bpf.CookiePidMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				totalEntries++
				age := nowNano - int64(valuesOut[i].LastSeenNs)
				if age > timeoutNano ||
					(staleBeforeNs > 0 && (valuesOut[i].LastSeenNs == 0 || valuesOut[i].LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, keysOut[i])
				}
			}
		}
		if err != nil {
			if !isIgnorableBatchLookupErr(err) {
				c.log.Errorf("cleanupCookiePidMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	if len(keysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.CookiePidMap, keysToDelete); err != nil {
			c.log.Debugf("cleanupCookiePidMap: batch delete error: %v", err)
		}
		c.log.Debugf("cleanupCookiePidMap: removed %d entries", len(keysToDelete))
	}

	maxEntries := bpf.CookiePidMap.MaxEntries()
	if totalEntries > 0 && maxEntries > 0 {
		usagePercent := float64(totalEntries) / float64(maxEntries) * 100
		if usagePercent > 90 {
			c.logMapCapacityAlert(&c.cookiePidCapacityAlert, "cleanupCookiePidMap", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// cleanupRoutingHandoffMap removes expired tuple-miss routing metadata entries.
// The handoff map is a short-lived bridge for userspace consumers that miss the
// authoritative conn-state publication window.
func (c *ControlPlane) cleanupRoutingHandoffMap() int {
	cleanupMu, _ := c.maintenanceState()
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	return c.cleanupRoutingHandoffMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupRoutingHandoffMapBeforeLocked(staleBeforeNs uint64) int {
	select {
	case <-c.stop:
		return 0
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.RoutingHandoffMap == nil {
		return 0
	}

	nowNano, err := monotonicNowNano()
	if err != nil {
		c.log.Errorf("cleanupRoutingHandoffMap: failed to get monotonic time: %v", err)
		return 0
	}

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.routingHandoffDelete)
	keysOut := ensureJanitorLookupScratch(scratch.routingHandoffKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.routingHandoffValues)
	totalEntries := 0
	defer func() {
		scratch.routingHandoffDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.routingHandoffKeys = keysOut
		scratch.routingHandoffValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	for {
		count, batchErr := bpf.RoutingHandoffMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				totalEntries++
				if routingHandoffExpired(nowNano, valuesOut[i].LastSeenNs) ||
					(staleBeforeNs > 0 && (valuesOut[i].LastSeenNs == 0 || valuesOut[i].LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, keysOut[i])
				}
			}
		}
		if batchErr != nil {
			if !isIgnorableBatchLookupErr(batchErr) {
				c.log.Errorf("cleanupRoutingHandoffMap: BatchLookup error: %v", batchErr)
			}
			break
		}
	}

	if len(keysToDelete) > 0 {
		if _, deleteErr := BpfMapBatchDelete(bpf.RoutingHandoffMap, keysToDelete); deleteErr != nil {
			c.log.Debugf("cleanupRoutingHandoffMap: batch delete error: %v", deleteErr)
		}
		c.log.Debugf("cleanupRoutingHandoffMap: removed %d expired entries", len(keysToDelete))
	}

	maxEntries := bpf.RoutingHandoffMap.MaxEntries()
	if totalEntries > 0 && maxEntries > 0 {
		usagePercent := float64(totalEntries) / float64(maxEntries) * 100
		if usagePercent > 90 {
			c.logMapCapacityAlert(&c.routingHandoffCapacityAlert, "cleanupRoutingHandoffMap", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// datapathCounterReadFailureCooldown paces the datapath-counter read failure.
// The health check runs on every janitor tick (5s), so an unpaced report of a
// read that keeps failing writes ~720 lines/hour at the default log level. The
// condition is worth reporting (a failed read hides every datapath counter),
// so it is paced rather than demoted, and each emitted line carries the number
// of failed reads it folded in.
const datapathCounterReadFailureCooldown = 30 * time.Second

// logDatapathCounterReadFailure reports a failed datapath-counter snapshot
// read at most once per cooldown. The count in the line is the number of failed
// reads since the process started, so a condition that never clears stays
// visible as a magnitude instead of one line per tick, and the first failure is
// always reported (a single failure is never suppressed).
func (c *ControlPlane) logDatapathCounterReadFailure(now time.Time, err error) {
	if c == nil || c.log == nil || err == nil {
		return
	}
	failures, emit := c.checkBpfMapHealthWarnAlert.observe(now, datapathCounterReadFailureCooldown)
	if !emit {
		return
	}
	c.log.Warnf("checkBpfMapHealth: %v (failures=%d, reporting at most one line per %v)",
		err, failures, datapathCounterReadFailureCooldown)
}

// checkBpfMapHealth monitors map usage and overflow counters for robustness.
// Alerts when maps are approaching capacity or experiencing high overflow rates.
// Accepts pre-read overflow counters to avoid redundant BPF map lookups.
func (c *ControlPlane) checkBpfMapHealth(udpOverflow, tcpOverflow uint64) {
	bpf := c.currentBpf()
	if bpf == nil {
		return
	}

	// Read the counters added for the datapath visibility work (redirect
	// track, rebind rejections, stateless passthrough, ...). The two
	// conn-state overflow counters are passed in by the janitor because they
	// also drive its pressure mode. A read failure would silently hide every
	// counter, so it is reported instead of ignored.
	var (
		snap        bpfStatsSnapshot
		snapshotErr error
	)
	if bpf.BpfStatsMap != nil {
		snap, snapshotErr = c.readDatapathCounters(bpf.BpfStatsMap)
	}

	now := time.Now()

	if snapshotErr != nil {
		c.logDatapathCounterReadFailure(now, snapshotErr)
	}

	// The by-design passthrough counters are published from this same snapshot
	// on the same tick; see control/datapath_passthrough_report.go.
	c.reportDatapathPassthroughSummary(now, snap)

	// The conn-state capacity is the operator's lever on an overflowing
	// conn-state map, so it is carried into the report rather than read by it.
	connStateCapacity := uint64(0)
	if bpf.ConnStateMap != nil {
		connStateCapacity = uint64(bpf.ConnStateMap.MaxEntries())
	}

	// Publish the counters for the interval since the previous line. Comparing
	// them against their lifetime totals instead (the previous behaviour) meant
	// that a single overflow ever observed re-alerted on every cooldown expiry
	// for the life of the process, because these counters never return to zero,
	// and that "CRITICAL ... overflow=%d" presented a lifetime total as if it
	// were pressure happening now.
	c.reportDatapathOverflowInterval(now, snap, udpOverflow, tcpOverflow, connStateCapacity)
}

// readMapOverflowCounters reads the two conn-state overflow counters that
// drive the janitor's pressure mode. The remaining bpf_stats_map keys are read
// by readDatapathCounters on the health-check cadence.
func (c *ControlPlane) readMapOverflowCounters(m *ebpf.Map) (udpOverflow uint64, tcpOverflow uint64) {
	if m == nil {
		return 0, 0
	}
	if v, err := readBpfStatsCounter(m, bpfStatsUDPConnOverflow); err == nil {
		udpOverflow = v
	}
	if v, err := readBpfStatsCounter(m, bpfStatsTCPConnOverflow); err == nil {
		tcpOverflow = v
	}
	return udpOverflow, tcpOverflow
}

// readDatapathCounters reads the bpf_stats_map counters added for the
// datapath-visibility work (////// and the
// routing-epoch rebind reroute). Every key is read or the whole read fails: a
// partially reported snapshot would look like "no anomaly" for the missing
// keys.
func (c *ControlPlane) readDatapathCounters(m *ebpf.Map) (bpfStatsSnapshot, error) {
	var snap bpfStatsSnapshot

	if m == nil {
		return snap, fmt.Errorf("read datapath counters: bpf_stats_map is not loaded")
	}
	for _, field := range []struct {
		name string
		key  uint32
		dst  *uint64
	}{
		{"redirect overflow", bpfStatsRedirectOverflow, &snap.RedirectOverflow},
		{"redirect update failed", bpfStatsRedirectUpdateFailed, &snap.RedirectUpdateFailed},
		{"redirect rebind rejected", bpfStatsRedirectRebindRejected, &snap.RedirectRebindRejected},
		{"syn rebind rejected", bpfStatsSynRebindRejected, &snap.SynRebindRejected},
		{"stateless tcp passthrough", bpfStatsStatelessTCPPassthrough, &snap.StatelessTCPPassthrough},
		{"frag tail passed", bpfStatsFragTailPassed, &snap.FragTailPassed},
		{"parse unsupported l4", bpfStatsParseUnsupportedL4, &snap.ParseUnsupportedL4},
		{"unsolicited udp seen", bpfStatsUnsolicitedUDPSeen, &snap.UnsolicitedUDPSeen},
		{"sockmark fallback", bpfStatsSockmarkFallback, &snap.SockmarkFallback},
		{"event drop", bpfStatsEventDrop, &snap.EventDrop},
		{"rebind rerouted after epoch change", bpfStatsRebindReroutedAfterEpochChange, &snap.RebindReroutedAfterEpochChange},
	} {
		v, err := readBpfStatsCounter(m, field.key)
		if err != nil {
			return snap, fmt.Errorf("read bpf_stats_map counter %q (key %d): %w", field.name, field.key, err)
		}
		*field.dst = v
	}
	return snap, nil
}

func (c *ControlPlane) allowDnsFastPathErrorLog(now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		last := c.lastDnsFastPathErrorLogTime.Load()
		if nowNano-last < int64(dnsFastPathErrorLogInterval) {
			return false
		}
		if c.lastDnsFastPathErrorLogTime.CompareAndSwap(last, nowNano) {
			return true
		}
	}
}

// allowHandlePktEpochWarn rate-limits the expected reload-window warning for
// UDP packets whose stale routing-epoch attribution has no execution owner.
func (c *ControlPlane) allowHandlePktEpochWarn(now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		last := c.lastHandlePktEpochWarnTime.Load()
		if nowNano-last < int64(handlePktEpochWarnInterval) {
			return false
		}
		if c.lastHandlePktEpochWarnTime.CompareAndSwap(last, nowNano) {
			return true
		}
	}
}

func (c *ControlPlane) allowDnsFastPathServfailLog(now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		last := c.lastDnsFastPathServfailLogTime.Load()
		if nowNano-last < int64(dnsFastPathErrorLogInterval) {
			return false
		}
		if c.lastDnsFastPathServfailLogTime.CompareAndSwap(last, nowNano) {
			return true
		}
	}
}

// readBpfStatsCounter reads a counter from the BPF stats map by key index.
func readBpfStatsCounter(m *ebpf.Map, key uint32) (uint64, error) {
	var value uint64
	if err := m.Lookup(&key, &value); err != nil {
		return 0, err
	}
	return value, nil
}

type Listener struct {
	tcp4Listener net.Listener
	tcp6Listener net.Listener
	packetConn   net.PacketConn
	port         uint16
}

func currentNetnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
}

func socketNetnsCookie(conn any) (uint64, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("socket type %T does not expose SyscallConn", conn)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cookie    uint64
		cookieErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		cookie, cookieErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	}); err != nil {
		return 0, err
	}
	return cookie, cookieErr
}

// ValidateCurrentNetns verifies that every listener socket belongs to the
// caller's current network namespace. BPF socket assignment rejects sockets
// from another namespace, so publishing one would silently black-hole proxy
// traffic even though the listener itself was otherwise healthy.
func (l *Listener) ValidateCurrentNetns() error {
	if l == nil {
		return fmt.Errorf("validate listener netns: nil listener")
	}
	expected, err := currentNetnsCookie()
	if err != nil {
		return fmt.Errorf("read current network namespace cookie: %w", err)
	}
	sockets := []struct {
		name string
		conn any
	}{
		{name: "tcp4", conn: l.tcp4Listener},
		{name: "tcp6", conn: l.tcp6Listener},
		{name: "udp", conn: l.packetConn},
	}
	validated := 0
	for _, socket := range sockets {
		if socket.conn == nil {
			continue
		}
		cookie, err := socketNetnsCookie(socket.conn)
		if err != nil {
			return fmt.Errorf("read %s listener network namespace cookie: %w", socket.name, err)
		}
		if cookie != expected {
			return fmt.Errorf("%s listener belongs to network namespace cookie %d, want %d", socket.name, cookie, expected)
		}
		validated++
	}
	if validated == 0 {
		return fmt.Errorf("validate listener netns: listener has no sockets")
	}
	return nil
}

const udpDualStackListenIP = "::"

func udpDualStackListenAddr(port uint16) string {
	return net.JoinHostPort(udpDualStackListenIP, strconv.Itoa(int(port)))
}

func enableUDPDualStackSocket(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
			sockOptErr = fmt.Errorf("error setting IPV6_V6ONLY socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func udpDualStackListenControl(c syscall.RawConn) error {
	if err := dialer.TproxyControl(c); err != nil {
		return err
	}
	return enableUDPDualStackSocket(c)
}

func udpIngressSupportsBatch(conn *net.UDPConn) bool {
	if conn == nil {
		return false
	}
	_, ok := conn.LocalAddr().(*net.UDPAddr)
	return ok
}

func wakeTCPListener(listener net.Listener) {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok || tcpListener == nil {
		return
	}
	_ = tcpListener.SetDeadline(time.Now())
}

func wakePacketConn(packetConn net.PacketConn) {
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok || udpConn == nil {
		return
	}
	now := time.Now()
	_ = udpConn.SetReadDeadline(now)
	_ = udpConn.SetWriteDeadline(now)
}

func (l *Listener) Close() error {
	if l == nil {
		return nil
	}

	var err error

	if l.tcp4Listener != nil {
		wakeTCPListener(l.tcp4Listener)
		err = l.tcp4Listener.Close()
	}
	if l.tcp6Listener != nil {
		wakeTCPListener(l.tcp6Listener)
		if err2 := l.tcp6Listener.Close(); err2 != nil {
			if err == nil {
				err = err2
			} else {
				err = fmt.Errorf("%w: %v", err, err2)
			}
		}
	}
	if l.packetConn != nil {
		wakePacketConn(l.packetConn)
		if err2 := l.packetConn.Close(); err2 != nil {
			if err == nil {
				err = err2
			} else {
				err = fmt.Errorf("%w: %v", err, err2)
			}
		}
	}
	return err
}

// Clone duplicates the listener sockets so a new control plane generation can
// take over serving before the old generation closes its copies. This allows
// reload to wake the old Accept/Read goroutines without rebinding the port.
func (l *Listener) Clone() (*Listener, error) {
	if l == nil {
		return nil, fmt.Errorf("nil listener")
	}

	// Keep the partial clone in a plain local: the error returns below must
	// not overwrite the named result before the deferred cleanup inspects it.
	var err error
	partial := &Listener{port: l.port}
	defer func() {
		if err != nil {
			// Best-effort close of every socket duplicated before the failure
			// so a failed staged reload releases ports/fds deterministically
			// instead of leaving them to the garbage collector.
			_ = partial.Close()
		}
	}()

	if l.tcp4Listener != nil {
		partial.tcp4Listener, err = cloneTCPListener(l.tcp4Listener)
		if err != nil {
			return nil, fmt.Errorf("clone tcp4 listener: %w", err)
		}
	}
	if l.tcp6Listener != nil {
		partial.tcp6Listener, err = cloneTCPListener(l.tcp6Listener)
		if err != nil {
			return nil, fmt.Errorf("clone tcp6 listener: %w", err)
		}
	}
	if l.packetConn != nil {
		partial.packetConn, err = cloneUDPPacketConn(l.packetConn)
		if err != nil {
			return nil, fmt.Errorf("clone udp packet conn: %w", err)
		}
	}

	return partial, nil
}

func cloneTCPListener(listener net.Listener) (net.Listener, error) {
	file, err := dupTCPListenerFile(listener)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	cloned, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

func cloneUDPPacketConn(packetConn net.PacketConn) (net.PacketConn, error) {
	file, err := dupUDPPacketConnFile(packetConn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	cloned, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

func dupTCPListenerFile(listener net.Listener) (*os.File, error) {
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("unexpected tcp listener type %T", listener)
	}
	rawConn, err := tcpListener.SyscallConn()
	if err != nil {
		return nil, err
	}
	return dupRawConnFile(rawConn, "dae-tcp-listener")
}

func dupUDPPacketConnFile(packetConn net.PacketConn) (*os.File, error) {
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("unexpected udp packet conn type %T", packetConn)
	}
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return dupRawConnFile(rawConn, "dae-udp-packet-conn")
}

func dupRawConnFile(rawConn syscall.RawConn, name string) (*os.File, error) {
	var dupFD int
	var dupErr error
	if err := rawConn.Control(func(fd uintptr) {
		dupFD, dupErr = unix.Dup(int(fd))
		if dupErr == nil {
			unix.CloseOnExec(dupFD)
		}
	}); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, dupErr
	}
	return os.NewFile(uintptr(dupFD), name), nil
}

func (c *ControlPlane) activatePreparedRuntime() error {
	if c == nil {
		return nil
	}

	c.publishRuntimeStats()
	if err := c.StartPreparedDNSListener(); err != nil {
		c.unpublishRuntimeStats()
		return err
	}
	return nil
}

// shouldSkipDNSFastPathForLocalListenerTraffic returns true only for packets
// that are both addressed to the control plane's own DNS listener and likely
// sourced from the local host itself. External LAN clients querying a
// LAN-bound DNS listener are intercepted via the ingress/TProxy path and must
// continue into the DNS fast path instead of being dropped here.
func shouldSkipDNSFastPathForLocalListenerTraffic(listenAddr string, src, dst netip.AddrPort) bool {
	if listenAddr == "" || dst.Port() != 53 {
		return false
	}

	if dst.Addr().IsLoopback() || dst.Addr().IsUnspecified() {
		_, portStr, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return false
		}
		return uint16(port) == dst.Port()
	}

	if listenAddr == dst.String() {
		return src.Addr().IsLoopback() || src.Addr().IsUnspecified() || src.Addr() == dst.Addr()
	}

	return false
}

// ingressRetryBackoff is the pause between retries of transient ingress
// loop errors (fd/memory pressure) so resource exhaustion can clear without
// tearing the listener loop down.
const ingressRetryBackoff = 100 * time.Millisecond

// ingressResourceExhausted reports whether an ingress loop error is transient
// resource exhaustion worth retrying instead of exiting the loop. Exiting the
// accept/read loop on EMFILE/ENFILE/ENOMEM/ENOBUFS would silently blackhole
// the listener for that address family until the next reload.
func ingressResourceExhausted(err error) bool {
	return stderrors.Is(err, syscall.EMFILE) ||
		stderrors.Is(err, syscall.ENFILE) ||
		stderrors.Is(err, syscall.ENOMEM) ||
		stderrors.Is(err, syscall.ENOBUFS)
}

// ingressWakeTimeout reports whether err is the read-deadline expiry that
// Listener.Close installs through wakePacketConn to unblock a parked UDP
// ingress read. A timeout therefore means the listener is being closed, which
// is a clean stop; treating it as fatal let a reload's listener handoff abort
// the retiring generation with "ingress loop terminated". The TCP accept loop
// below already returns cleanly on the same signal.
func ingressWakeTimeout(err error) bool {
	netErr, ok := stderrors.AsType[net.Error](err)
	return ok && netErr.Timeout()
}

// retryIngressAfterBackoff logs (rate-limited) and sleeps briefly so the
// caller can retry a transient ingress error. It reports whether the caller
// should keep looping; false means the plane is shutting down.
func (c *ControlPlane) retryIngressAfterBackoff(op string, err error) bool {
	if c.allowConnectionErrorLog(time.Now()) {
		c.log.Errorf("%s: transient error, retrying: %v", op, err)
	}
	select {
	case <-c.ctx.Done():
		return false
	case <-time.After(ingressRetryBackoff):
		return true
	}
}

// fatalIngressLoopError records a terminal ingress loop failure and cancels
// the plane context so Serve stops blocking on ctx.Done and returns the
// error to its caller. Without this, a detached accept/read loop that dies
// on an unclassified error (EPERM, EINVAL, ...) leaves Serve returning nil
// and the hijacked traffic silently blackholes until the next reload.
func (c *ControlPlane) fatalIngressLoopError(op string, err error) {
	wrapped := fmt.Errorf("%s: %w", op, err)
	c.serveLoopErrMu.Lock()
	if c.serveLoopErr == nil {
		c.serveLoopErr = wrapped
	}
	c.serveLoopErrMu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	c.log.Errorf("[Critical] Ingress loop terminated: %v", wrapped)
}

func (c *ControlPlane) Serve(readyChan chan<- bool, listener *Listener) (err error) {
	sentReady := false
	defer func() {
		if !sentReady {
			select {
			case readyChan <- false:
			default:
			}
		}
	}()
	validateListener := func(listener *Listener) error {
		if listener == nil {
			return fmt.Errorf("nil listener")
		}
		if tcp4, ok := listener.tcp4Listener.(*net.TCPListener); !ok || tcp4 == nil {
			return fmt.Errorf("listener TCP IPv4 socket is not TCP")
		}
		if tcp6, ok := listener.tcp6Listener.(*net.TCPListener); !ok || tcp6 == nil {
			return fmt.Errorf("listener TCP IPv6 socket is not TCP")
		}
		udpConn, ok := listener.packetConn.(*net.UDPConn)
		if !ok || udpConn == nil {
			return fmt.Errorf("listener packet connection is not UDP")
		}
		return nil
	}
	if err := validateListener(listener); err != nil {
		return err
	}
	publishListenerSockets := c.publishListenerSockets
	publishBeforeCommit := c.preparedDatapathCommit && !c.sharedBpfReload && c.core != nil
	if publishBeforeCommit {
		if err := publishListenerSockets(listener); err != nil {
			return err
		}
	}
	if err := c.CommitPreparedDatapath(); err != nil {
		return err
	}
	if !publishBeforeCommit {
		if err := publishListenerSockets(listener); err != nil {
			return err
		}
	}
	if err := c.activatePreparedRuntime(); err != nil {
		return err
	}
	udpConn, _ := listener.packetConn.(*net.UDPConn)

	c.markReady()
	sentReady = true
	select {
	case readyChan <- true:
	default:
	}
	serveTCP := func(tcpListener net.Listener) {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			lconn, err := tcpListener.Accept()
			if err != nil {
				if netErr, ok := stderrors.AsType[net.Error](err); ok && netErr.Timeout() {
					return
				}
				if commonerrors.IsClosedConnection(err) || stderrors.Is(err, context.Canceled) {
					return
				}
				if ingressResourceExhausted(err) {
					// Transient fd/memory pressure: retry with a short
					// backoff instead of tearing the accept loop down.
					// Exiting here would silently blackhole this address
					// family until the next reload.
					if !c.retryIngressAfterBackoff("Accept", err) {
						return
					}
					continue
				}
				c.log.Errorf("Error when accept: %v", err)
				c.fatalIngressLoopError("accept", err)
				return
			}
			go func(lconn net.Conn) {
				// Direct-dispatch goroutines get the same panic isolation as
				// dispatcher tasks: one bad packet or connection must not take
				// down the whole dae process.
				defer func() {
					if recovered := recover(); recovered != nil {
						_ = lconn.Close()
						reportPacketPathPanic("tcp_conn", "serve", &c.tcpConnPanicCount, recovered)
					}
				}()
				ownership, ok := c.acquireIncomingConnectionLease(lconn)
				if !ok {
					return
				}
				defer ownership.release()
				// Keep the ControlPlane lifecycle context so shutdown/reload can cancel
				// in-flight connection handling. Dial timeout is applied independently
				// inside RouteDialTcp and is not reduced by sniffing time.
				if err := c.handleConn(c.ctx, lconn, ownership); err != nil {
					c.log.Warnln("handleConn:", err)
				}
			}(lconn)
		}
	}
	go serveTCP(listener.tcp4Listener)
	go serveTCP(listener.tcp6Listener)
	go func() {
		// Panic isolation for the ingress read loop: this goroutine runs
		// processPacket synchronously (ClassifyUdpFlow, admission, pooled task
		// checkout, batch read), so an unrecovered panic here would take down
		// the whole process. Recovery is not a silent drop: the plane context
		// is cancelled so Serve returns the first error and the run loop can
		// fail fast. This defer is registered first, so it runs after the
		// batch reader's own Close defer during the unwind.
		defer func() {
			if recovered := recover(); recovered != nil {
				reportPacketPathPanic("udp_ingress", "read_loop", &c.udpIngressLoopPanicCount, recovered)
				c.fatalIngressLoopError("udp-ingress-read-loop-panic", fmt.Errorf("recovered panic: %v", recovered))
			}
		}()
		processPacket := func(pktBuf pool.PB, src netip.AddrPort, oob []byte) {
			pktDst := RetrieveOriginalDest(oob)
			realDst := common.ConvergeAddrPort(pktDst)
			// IMPORTANT: keep original capacity for pool bucketing.
			// Do not use full-slice cap clipping ([:n:n]) here, otherwise Put
			// may return the buffer into a wrong size-class and poison the pool.
			convergeSrc := common.ConvergeAddrPort(src)
			flowDecision := ClassifyUdpFlow(convergeSrc, realDst, pktBuf)
			if flowDecision.IsQuicInitial {
				flowDecision = flowDecision.EnsureSnifferSession()
			}
			// Debug:
			// t := time.Now
			if !c.udpIngressAdmission.tryAcquire() {
				pktBuf.Put()
				return
			}
			// Pooled owned task: captures the per-packet locals by value (they
			// never change after submission) instead of allocating an escaping
			// closure per packet. Run releases the buffer, the admission
			// gate, and returns the task to the pool on every path.
			task := udpIngressTaskPool.Get().(*udpIngressTask)
			task.c = c
			task.lConn = udpConn
			task.pktBuf = pktBuf
			task.admission = &c.udpIngressAdmission
			task.realDst = realDst
			task.convergeSrc = convergeSrc
			task.flowDecision = flowDecision
			// Reset on every checkout: a stale slot pointer from a previous
			// use would make Run or Discard release a semaphore this packet
			// never acquired. The direct path reassigns it after acquiring.
			task.dispatchSem = nil

			// Session FIFO now takes precedence for generic UDP forwarding.
			// Ordered ingress keeps same-flow packets in the order they were read
			// from the client socket before they reach handlePkt/ue.WriteTo.
			// Direct goroutine dispatch remains only for narrow low-latency
			// exceptions where queue handoff is less valuable than minimal overhead
			// (DNS, SIP/RTP, STUN).
			if flowDecision.DispatchStrategy() == StrategyDirectGoroutine {
				// DNS, VoIP, and other low-latency exception traffic bypasses
				// the ordered per-flow queue and runs immediately, but under
				// a generous concurrency cap: an unbounded `go` here would
				// turn a UDP flood on any exception port into unbounded
				// goroutine and buffer growth. Saturation drops the packet
				// like ordinary UDP loss (clients retransmit) and recycles
				// the task inline.
				select {
				case c.udpDirectDispatchSem <- struct{}{}:
					task.dispatchSem = c.udpDirectDispatchSem
					// Panic isolation: task.Run releases the dispatch
					// slot, the admission ticket, the packet buffer, and
					// the pooled task through its own defers, which all
					// complete during the unwind. The wrapper must only
					// report the panic (see runDirectDispatchTask).
					go runDirectDispatchTask(task, &c.udpDirectDispatchPanicCount)
				default:
					task.Discard()
				}
			} else if !DefaultUdpTaskPool.EmitTask(flowDecision.Key, task) {
				// Rejected: the pool does not own the buffer or the admission,
				// so release both inline and return the task to the pool (it
				// was never queued, so Run will not run).
				c.udpIngressAdmission.release()
				pktBuf.Put()
				*task = udpIngressTask{}
				udpIngressTaskPool.Put(task)
			}
			// if d := time.Since(t); d > 100*time.Millisecond {
			// 	logrus.Println(d)
			// }
		}

		if udpIngressSupportsBatch(udpConn) {
			batchReader := newUDPIngressBatchReader(udpConn, 0)
			if batchReader == nil {
				goto singleRead
			}
			defer batchReader.Close()

			for {
				select {
				case <-c.ctx.Done():
					return
				default:
				}

				// IPv4 listener fast path: batch read reduces syscall overhead while
				// preserving one exclusive ingress buffer per packet.
				n, err := batchReader.ReadBatch()
				if err != nil {
					if !commonerrors.IsClosedConnection(err) && !ingressWakeTimeout(err) {
						if ingressResourceExhausted(err) && c.retryIngressAfterBackoff("ReadBatchUDP", err) {
							continue
						}
						c.log.Errorf("ReadBatchUDP: %v", err)
						c.fatalIngressLoopError("read-batch-udp", err)
					}
					break
				}
				for i := range n {
					pktBuf, src, oob, ok := batchReader.Take(i)
					if !ok {
						continue
					}
					processPacket(pktBuf, src, oob)
				}
			}
			return
		}

	singleRead:
		var oob [udpIngressOobSize]byte
		singleReader := udpIngressSingleReader{pc: udpConn}
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			pktBuf, src, oobn, err := singleReader.Read(oob[:])
			if err != nil {
				if !commonerrors.IsClosedConnection(err) && !ingressWakeTimeout(err) {
					if ingressResourceExhausted(err) && c.retryIngressAfterBackoff("ReadMsgUDPAddrPort", err) {
						continue
					}
					c.log.Errorf("ReadMsgUDPAddrPort: %v", err)
					c.fatalIngressLoopError("read-udp", err)
				}
				break
			}
			if pktBuf == nil {
				continue
			}

			// Dual-stack UDP listener path: prefer correctness and IPv6 coverage
			// over batch-read optimization. OOB is consumed synchronously in
			// processPacket, so reusing the stack buffer is safe here.
			processPacket(pktBuf, src, oob[:oobn])
		}
	}()
	c.ActivateCheck()
	<-c.ctx.Done()
	// Log the reason Serve is exiting to help distinguish intentional
	// shutdown/reload from unexpected context cancellation (e.g. a leaked
	// timeout inherited from the reload preparation context).
	ctxErr := c.ctx.Err()
	if ctxErr != nil {
		c.log.WithFields(logrus.Fields{
			"error": ctxErr.Error(),
		}).Info("[ControlPlane] Serve() exiting; context cancelled")
	}
	// A terminal ingress loop failure cancels the context and stashes its
	// error here; surface it so the caller can fail fast.
	c.serveLoopErrMu.Lock()
	serveErr := c.serveLoopErr
	c.serveLoopErrMu.Unlock()
	return serveErr
}

// Listen opens the ingress listeners without starting the serving loops.
func (c *ControlPlane) Listen(port uint16) (listener *Listener, err error) {
	// Listen.
	tcpListenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	udpListenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return udpDualStackListenControl(c)
		},
	}
	tcp4ListenAddr := net.JoinHostPort(c.listenIp, strconv.Itoa(int(port)))
	tcp4Listener, err := tcpListenConfig.Listen(context.Background(), "tcp4", tcp4ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listenTCP4: %w", err)
	}
	tcp6Listener, err := tcpListenConfig.Listen(context.Background(), "tcp6", net.JoinHostPort("::", strconv.Itoa(int(port))))
	if err != nil {
		_ = tcp4Listener.Close()
		return nil, fmt.Errorf("listenTCP6: %w", err)
	}
	packetConn, err := udpListenConfig.ListenPacket(context.Background(), "udp6", udpDualStackListenAddr(port))
	if err != nil {
		if c.log != nil {
			c.log.WithError(err).Warn("Failed to open dual-stack UDP listener; fallback to IPv4-only UDP listener")
		}
		packetConn, err = tcpListenConfig.ListenPacket(context.Background(), "udp", tcp4ListenAddr)
		if err != nil {
			_ = tcp4Listener.Close()
			_ = tcp6Listener.Close()
			return nil, fmt.Errorf("listenUDP: %w", err)
		}
	}
	listener = &Listener{
		tcp4Listener: tcp4Listener,
		tcp6Listener: tcp6Listener,
		packetConn:   packetConn,
		port:         port,
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	return listener, nil
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	listener, err = c.Listen(port)
	if err != nil {
		return nil, err
	}

	if err = c.Serve(readyChan, listener); err != nil {
		// This wrapper created the sockets, so it owns them: close on failure
		// so a retried startup cannot leave the previous attempt's listeners
		// bound until GC. The caller receives nil on error, matching the
		// historical contract.
		_ = listener.Close()
		return nil, fmt.Errorf("failed to serve: %w", err)
	}

	return listener, nil
}

func (c *ControlPlane) chooseBestDnsDialerSnapshot(
	ctx context.Context, snapshot DnsRequestSnapshot, dnsUpstream *dns.Upstream,
) (*dialArgument, error) {
	now := time.Now()
	snapshotKey, snapshotEnabled := buildDnsDialerSnapshotKeyForSnapshot(snapshot, dnsUpstream)
	if snapshotEnabled {
		if cachedDialArg, hit := c.loadDnsDialerSnapshot(snapshotKey, now); hit {
			return cachedDialArg, nil
		}
	}

	/// Choose the best l4proto+ipversion dialer, and change taregt DNS to the best ipversion DNS upstream for DNS request.
	// Get available ipversions and l4protos for DNS upstream.
	ipversions, l4protos := dnsUpstream.SupportedNetworks()
	var (
		bestCandidate          *dnsDialerCandidate
		bestPenalizedCandidate *dnsDialerCandidate
	)
	// Get the min latency path.
	networkType := dialer.NetworkType{
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}
	for _, ver := range ipversions {
		for _, proto := range l4protos {
			networkType.L4Proto = proto
			networkType.IpVersion = ver
			var dAddr netip.Addr
			switch ver {
			case consts.IpVersionStr_4:
				dAddr = dnsUpstream.Ip4
			case consts.IpVersionStr_6:
				dAddr = dnsUpstream.Ip6
			default:
				return nil, fmt.Errorf("unexpected ipversion: %v", ver)
			}
			outboundIndex, mark, _, err := c.Route(
				snapshot.RealSrc,
				netip.AddrPortFrom(dAddr, dnsUpstream.Port),
				dnsUpstream.Hostname,
				proto.ToL4ProtoType(),
				snapshot.routingResultForRoute(),
			)
			if err != nil {
				return nil, err
			}
			if mark == 0 {
				mark = c.soMarkFromDae
			}
			if int(outboundIndex) >= len(c.outbounds) {
				return nil, fmt.Errorf("bad outbound index: %v", outboundIndex)
			}
			dialerGroup := c.outbounds[outboundIndex]
			// DNS always dial IP.
			d, latency, err := dialerGroup.Select(&networkType, true)
			if err != nil {
				continue
			}
			candidate := &dnsDialerCandidate{
				dialArg: &dialArgument{
					l4proto:      proto,
					ipversion:    ver,
					bestDialer:   d,
					bestOutbound: dialerGroup,
					bestTarget:   netip.AddrPortFrom(dAddr, dnsUpstream.Port),
					mark:         mark,
					mptcp:        c.mptcp,
				},
				latency: latency,
			}
			if c.isDnsDialArgPenalized(candidate.dialArg, now) {
				bestPenalizedCandidate = pickBetterDnsDialerCandidate(bestPenalizedCandidate, candidate)
				continue
			}
			bestCandidate = pickBetterDnsDialerCandidate(bestCandidate, candidate)
			if bestCandidate.latency == 0 {
				break
			}
		}
	}
	selectedCandidate, selectedPenalized := chooseDnsDialerCandidate(bestCandidate, bestPenalizedCandidate)
	if selectedCandidate == nil || selectedCandidate.dialArg == nil {
		return nil, fmt.Errorf("no proper dialer for DNS upstream: %v", dnsUpstream.String())
	}
	selected := *selectedCandidate.dialArg
	switch selected.ipversion {
	case consts.IpVersionStr_4:
		selected.bestTarget = netip.AddrPortFrom(dnsUpstream.Ip4, dnsUpstream.Port)
	case consts.IpVersionStr_6:
		selected.bestTarget = netip.AddrPortFrom(dnsUpstream.Ip6, dnsUpstream.Port)
	}
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		fields := logrus.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
			"upstream":   dnsUpstream.String(),
			"choose":     string(selected.l4proto) + "+" + string(selected.ipversion),
			"use":        selected.bestTarget.String(),
		}
		if selected.bestOutbound != nil {
			fields["outbound"] = selected.bestOutbound.Name
		}
		if selected.bestDialer != nil {
			fields["dialer"] = selected.bestDialer.Property().Name
		}
		if selectedPenalized {
			fields["penalized_fallback"] = true
		}
		c.log.WithFields(fields).Traceln("Choose DNS path")
	}
	if snapshotEnabled && !selectedPenalized {
		c.storeDnsDialerSnapshot(snapshotKey, &selected, now)
	}
	return &selected, nil
}

func (c *ControlPlane) AbortConnections() (err error) {
	return c.abortConnections(true)
}

// AbortPendingConnections stops generation-owned admission and UDP work while
// preserving TCP flows already promoted into the process SessionManager.
func (c *ControlPlane) AbortPendingConnections() error {
	return c.abortConnections(false)
}

func (c *ControlPlane) abortConnections(abortManagedTCP bool) (err error) {
	if c == nil {
		return nil
	}
	connections, flows, errs := c.takeIncomingConnectionsForAbort()
	if abortManagedTCP {
		// Explicit abort: the operator asked for established connections to
		// be closed ("reload --abort"). Migration of surviving TCP flows to
		// the linked peer generation is a seamless-reload optimization and
		// must not apply on this path; matching flows would otherwise outlive
		// the explicit abort, retaining their previous routing decision
		// (seamless flow continuity on ordinary reloads is provided by the
		// per-packet epoch migration in the datapath/egress runtime, not by
		// this teardown). Abort every generation-owned flow instead.
		manager, _ := c.controlPlaneSessionManager()
		if manager != nil {
			if abortErr := manager.AbortGeneration(c.PolicyEpoch()); abortErr != nil {
				errs = append(errs, abortErr)
			}
		}
	}
	c.udpIngressAdmission.closeAndWait()
	// Wait for endpoint creation already admitted by this generation before
	// scanning the shared pool. New creation attempts are rejected once closed.
	c.udpEndpointAdmission.closeAndWait()

	for _, conn := range connections {
		if cerr := conn.Close(); cerr != nil {
			errs = append(errs, cerr)
		}
	}
	for _, egress := range flows {
		if egress == nil {
			continue
		}
		if cerr := egress.Close(); cerr != nil && !commonerrors.IsClosedConnection(cerr) {
			errs = append(errs, cerr)
		}
	}
	if c.core != nil {
		if udpErr := DefaultUdpEndpointPool.AbortEndpointsOwnedBy(c.core); udpErr != nil {
			errs = append(errs, udpErr)
		}
	}

	return stderrors.Join(errs...)
}

// DetachBpfHooks immediately detaches all BPF hooks from the system.
// This should be called first when receiving SIGTERM to ensure network is restored
// even if the rest of the shutdown process takes too long and gets SIGKILL'd.
// This is safe to call multiple times - subsequent calls will be no-ops.
func (c *ControlPlane) DetachBpfHooks() error {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.DetachBpfHooks()
}

// MarkRetired signals that this generation is no longer authoritative for
// outbound liveness. After this call, outboundAliveChangeCallback returns
// early and will not write to the shared OutboundConnectivityMap BPF map.
// This must be called before the drain period starts so that stale health
// check results from the retiring generation cannot clobber the successor's
// map entries.
func (c *ControlPlane) MarkRetired() {
	if c == nil || c.core == nil {
		return
	}
	c.core.markOutboundConnectivityRetired()
}

// ResetGlobalUdpState clears all global UDP-related pools.
// Called during process shutdown to stop background goroutines (janitors).
func ResetGlobalUdpState() {
	DefaultUdpEndpointPool.Reset()
	DefaultAnyfromPool.Reset()
	DefaultUdpTaskPool.Close()
	DefaultPacketSnifferSessionMgr.Close() // Close stops janitor goroutines; safe for shutdown path
}

func (c *ControlPlane) closeTail() error {
	var errs []error

	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			errs = append(errs, e)
		}
	}
	if c.egressRuntime != nil {
		if err := c.egressRuntime.releaseOwner(); err != nil {
			errs = append(errs, err)
		}
	}

	// Clear sync.Maps to prevent memory leak on reload.
	// These maps accumulate data over time and must be explicitly cleared.
	c.realDomainNegSet.Range(func(key, value any) bool {
		c.realDomainNegSet.Delete(key)
		return true
	})
	c.dnsDialerSnapshot.Range(func(key, value any) bool {
		c.dnsDialerSnapshot.Delete(key)
		return true
	})
	c.dnsDialerPenalty.Range(func(key, value any) bool {
		c.dnsDialerPenalty.Delete(key)
		return true
	})
	c.clearAllTcpSniffNegative()
	if c.failedQuicDcidCache != nil {
		c.failedQuicDcidCache.Clear()
		if getFailedQuicDcidCache() == c.failedQuicDcidCache {
			SetFailedQuicDcidCache(nil)
		}
	}

	// Note: inConnections is cleared by AbortConnections which should be called before Close
	// Note: core.Close is invoked synchronously by ControlPlane.Close BEFORE this
	// function runs, so that BPF hooks and maps are guaranteed to be released before
	// the retirement gate signals completion. Keeping it here would leave hook detach
	// subject to the deferred-cleanup timeout and risk racing with the next reload.

	// Note: ResetGlobalUdpState is intentionally NOT called here.
	// Global UDP pools (DefaultUdpEndpointPool, DefaultUdpTaskPool, etc.)
	// are shared across reload generations. Calling ResetGlobalUdpState
	// during closeTail would corrupt the new generation's live UDP state.
	// The caller (shutdownAfterSignalWithHandoff in cmd/run.go) calls
	// ResetGlobalUdpState after all control planes have been closed
	// during process termination.

	c.releaseRetainedState()

	return stderrors.Join(errs...)
}

// releaseRetainedState releases the resources this generation still owns after
// its datapath has been torn down.
//
// It deliberately does not nil out routingMatcher, outbounds, dnsController,
// core, egressRuntime, sessionManager or the UDP dispatchers. SessionManager
// lets established flows outlive the generation that created them, and those
// flow goroutines keep reading exactly those fields. Clearing them races with
// live readers and turns a reload into a nil dereference. Dropping the fields
// buys nothing either: once the generation itself is unreachable, everything it
// points at is collected with it.
func (c *ControlPlane) releaseRetainedState() {
	if c == nil {
		return
	}

	// Detach the handoff slot so the retired plane no longer references the
	// controller. It is not owned here, so it is deliberately left open.
	c.takeDNSHandoffController()
	c.bpfMaintenance = nil
	c.ClearReloadDnsCacheSource()
}

func (c *ControlPlane) Close() (err error) {
	if c == nil {
		return nil
	}
	c.closeRoutingEpochExecution()
	c.ClearReloadDnsCacheSource()

	c.closeOnce.Do(func() {
		c.unpublishActiveControlPlane()
		c.unpublishRuntimeStats()
		if c.cancel != nil {
			c.cancel()
		}
		if manager, owned := c.controlPlaneSessionManager(); owned && manager != nil {
			c.closeErr = stderrors.Join(c.closeErr, manager.Close())
		}
		c.udpIngressAdmission.closeAndWait()

		var stopWg sync.WaitGroup
		stopWg.Add(2)
		go func() {
			defer stopWg.Done()
			c.stopRealDomainNegJanitor()
		}()
		go func() {
			defer stopWg.Done()
			c.stopConnStateJanitor()
		}()
		stopWg.Wait()

		// Close the core (BPF hooks + maps) synchronously WITHOUT timeout.
		// core.Close detaches BPF hooks via netlink and must complete before
		// Close returns; the retirement gate uses Close completion as the
		// signal that the old generation's TC filters and maps are released.
		// If this were left inside the timed closeTail goroutine, a timeout
		// would let the retirement gate release while old-generation hook
		// detach is still running, racing with the next reload's datapath.
		// Netlink socket timeout (set at core init) bounds individual calls.
		var coreErr error
		if c.core != nil {
			coreErr = c.core.Close()
		}

		done := make(chan error, 1)
		go func() {
			done <- c.closeTail()
		}()

		timer := time.NewTimer(controlPlaneDeferredCleanupTimeout)
		defer timer.Stop()

		select {
		case tailErr := <-done:
			c.closeErr = stderrors.Join(c.closeErr, coreErr, tailErr)
		case <-timer.C:
			timeoutErr := fmt.Errorf("control plane close tail timed out after %v", controlPlaneDeferredCleanupTimeout)
			if c.log != nil {
				c.log.WithError(timeoutErr).Warn("ControlPlane.Close: continuing while tail cleanup finishes in background")
			}
			c.closeErr = stderrors.Join(c.closeErr, coreErr, timeoutErr)
		}
	})
	c.UnlinkRoutingEpochPeer(nil)

	return c.closeErr
}

func (c *ControlPlane) Outbounds() []*outbound.DialerGroup {
	return c.outbounds
}

// StopDNSListener stops the DNS listener if it's running
func (c *ControlPlane) StopDNSListener() error {
	if c == nil {
		return nil
	}
	return c.controlPlaneDNSRuntime.stopOwnedDNSListener()
}

// RestartDNSListener restarts the control plane's DNS listener after it was
// explicitly stopped during reload preparation.
func (c *ControlPlane) RestartDNSListener() error {
	if c == nil {
		return nil
	}
	return c.restartDNSListener(&c.deferFuncs, c.stopOwnedDNSListener)
}

func (c *ControlPlane) ReuseDNSListenerFrom(previous *ControlPlane) bool {
	if c == nil || previous == nil {
		return false
	}
	return c.reuseDNSListenerFrom(&previous.controlPlaneDNSRuntime, c, &c.deferFuncs, c.stopOwnedDNSListener)
}

func (c *ControlPlane) ReuseDNSControllerFrom(previous *ControlPlane) bool {
	if c == nil || previous == nil {
		return false
	}
	return c.reuseDNSControllerFrom(
		&previous.controlPlaneDNSRuntime,
		c.dnsControllerOption(),
		c.dnsRouting,
		c.log,
		previous.SetDNSHandoffController,
	)
}

func (c *ControlPlane) SetPreparedDNSStartHook(hook func() error) {
	if c == nil {
		return
	}
	c.setPreparedDNSStartHook(hook)
}

func (c *ControlPlane) SetPreparedDNSReuseHook(hook func() error) {
	if c == nil {
		return
	}
	c.setPreparedDNSReuseHook(hook)
}

func (c *ControlPlane) WaitDNSUpstreamsReady(timeout time.Duration) error {
	if c == nil {
		return nil
	}
	return c.waitDNSUpstreamsReady(c.ctx, timeout)
}

func (c *ControlPlane) WaitDNSUpstreamAvailable(timeout time.Duration) error {
	if c == nil {
		return nil
	}
	return c.waitDNSUpstreamAvailable(c.ctx, timeout)
}

func (c *ControlPlane) StartPreparedDNSListener() error {
	if c == nil {
		return nil
	}
	return c.startPreparedDNSListener(c.ctx, &c.deferFuncs, c.stopOwnedDNSListener)
}
