/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
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
	"github.com/daeuniverse/outbound/protocol/direct"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	"golang.org/x/sys/unix"
)

type ControlPlane struct {
	log *logrus.Logger

	runtimeStats *runtimeStats

	core       *controlPlaneCore
	deferFuncs []func() error
	listenIp   string

	controlPlaneGenerationState
	inConnections        sync.Map
	rejectNewConnections atomic.Bool
	drainTracker         *controlPlaneDrainTracker

	controlPlaneDNSRuntime
	dnsHandoffMu         sync.Mutex
	dnsHandoffController atomic.Pointer[DnsController]
	dnsHandoffOwned      bool
	onceNetworkReady     sync.Once

	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	readyOnce sync.Once

	muRealDomainSet   sync.RWMutex
	realDomainSet     *bloom.BloomFilter
	realDomainNegSet  sync.Map // map[string]int64 (expiresAt unix nano)
	dnsDialerSnapshot sync.Map // map[dnsDialerSnapshotKey]*dnsDialerSnapshotEntry
	dnsDialerPenalty  sync.Map // map[dnsDialerPenaltyKey]*dnsDialerPenaltyEntry
	tcpSniffNegMu     sync.RWMutex
	tcpSniffNegSet    map[tcpSniffNegKey]tcpSniffNegEntry
	realDomainProbeS  singleflight.Group
	negJanitorStop    chan struct{}
	negJanitorDone    chan struct{}
	negJanitorOnce    sync.Once

	controlPlaneDatapathJanitor

	// Track last alert time to avoid spamming logs
	lastBpfOverflowAlertTime atomic.Int64
	lastUdpPressureAlertTime atomic.Int64
	lastTcpPressureAlertTime atomic.Int64

	wanInterface []string
	lanInterface []string

	sniffingTimeout                time.Duration
	tproxyPortProtect              bool
	soMarkFromDae                  uint32
	mptcp                          bool
	udpRouteScopeSensitive         bool
	udpUnorderedRunner             *udpUnorderedTaskRunner
	failedQuicDcidCache            *failedQuicDcidCache
	lastConnectionErrorLogTime     atomic.Int64
	lastDnsFastPathErrorLogTime    atomic.Int64
	lastDnsFastPathServfailLogTime atomic.Int64
	listenerPublishMu              sync.Mutex
	listenerFiles                  []*os.File
	preparedDatapathCommit         bool
	autoConfigKernelParameter      bool
	routingKernspaceSnapshot       *routingKernspaceSnapshot
	pendingDnsReloadCache          map[string]*DnsCache
	sharedBpfReload                bool
	closeOnce                      sync.Once
	closeErr                       error
}

type controlPlaneBuildOptions struct {
	delayDatapathCommit   bool
	delayDNSListenerStart bool
}

const (
	janitorBatchLookupSize = 1024
	janitorDeleteInitCap   = 256
	janitorDeleteRetainMax = 8192
)

func ensureJanitorLookupScratch[T any](buf []T) []T {
	if cap(buf) < janitorBatchLookupSize {
		return make([]T, janitorBatchLookupSize)
	}
	return buf[:janitorBatchLookupSize]
}

func takeJanitorDeleteScratch[T any](buf []T) []T {
	if cap(buf) < janitorDeleteInitCap {
		return make([]T, 0, janitorDeleteInitCap)
	}
	return buf[:0]
}

func keepJanitorDeleteScratch[T any](buf []T) []T {
	if cap(buf) > janitorDeleteRetainMax {
		return make([]T, 0, janitorDeleteInitCap)
	}
	return buf[:0]
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

	// UDP connection state timeout constants (matching former bpf_timer values).
	// DNS connections are shorter-lived since they're typically query/response.
	udpConnStateTimeoutDNS = 17 * time.Second

	// DNS port in network byte order for connection state cleanup.
	// Precomputed to avoid repeated Htons() calls during janitor iterations.
	dnsPortNetworkOrder = common.Htons(53)
	// connStateJanitorPressureInterval is the fast-path scan interval used
	// when connection-state maps are under pressure.
	connStateJanitorPressureInterval = 1 * time.Second
	// connStateJanitorSteadyInterval is the default scan interval for steady
	// state. This keeps cleanup prompt without paying a full-table cost every
	// second when map pressure is low.
	connStateJanitorSteadyInterval = 5 * time.Second
	// redirectTrackJanitorPressureInterval is used when maps are under pressure.
	redirectTrackJanitorPressureInterval = 5 * time.Second
	// redirectTrackJanitorSteadyInterval is sufficient for the redirect cache
	// because stale entries have a limited blast radius.
	redirectTrackJanitorSteadyInterval = 30 * time.Second
	// cookiePidMapTimeout bounds stale cookie metadata when sock_release backstop
	// is missed for any reason. Active sockets refresh this timestamp from BPF.
	cookiePidMapTimeout = 5 * time.Minute
	// connStateJanitorPressureEnterUsage is the usage percentage that activates
	// pressure mode for connection-state cleanup.
	connStateJanitorPressureEnterUsage = 70
	// connStateJanitorPressureExitUsage is the usage percentage below which the
	// janitor starts counting down to leave pressure mode.
	connStateJanitorPressureExitUsage = 50
	// connStateJanitorPressureExitRounds is the number of consecutive low-usage
	// cleanup rounds required before leaving pressure mode.
	connStateJanitorPressureExitRounds = 3
	// routingHandoffTimeout bounds the tuple-miss metadata bridge between eBPF
	// and userspace. Keep it short so the handoff map does not become a second
	// long-lived conn-state cache.
	routingHandoffTimeout = 10 * time.Second
	// egressReturnHandoffTimeout bounds how long WAN egress reply-route metadata
	// waits for userspace to publish redirect_track before aging out.
	egressReturnHandoffTimeout = 30 * time.Second
	// routingHandoffPressureInterval lets the janitor react quickly when the
	// handoff map is churning under repeated tuple misses.
	routingHandoffPressureInterval = 1 * time.Second
	// routingHandoffSteadyInterval is sufficient because RetrieveRoutingResult
	// also rejects expired handoff entries on read.
	routingHandoffSteadyInterval = 5 * time.Second
	dnsFastPathErrorLogInterval  = 5 * time.Second

	// TCP connection state timeout constants.
	// TCP connections are longer-lived but we still need to clean up closed connections.
	// Established connections: 2 minutes timeout (conservative, most connections close sooner)
	// Closing connections (FIN/RST seen): 10 seconds timeout (quick cleanup)
	tcpConnStateTimeoutEstablished = 120 * time.Second
	tcpConnStateTimeoutClosing     = 10 * time.Second

	// Test seams: injected in tests to avoid external DNS dependency.
	resolveIp46ForBootstrap       = netutils.ResolveIp46
	resolveIp46ForRealDomainProbe = netutils.ResolveIp46
)

type mapCleanupStats struct {
	entries      int
	deleted      int
	usagePercent int
}

type connStateJanitorPressureState struct {
	active               bool
	belowThresholdRounds int
	lastUdpOverflow      uint64
	lastTcpOverflow      uint64
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

func NewControlPlane(
	log *logrus.Logger,
	_bpf any,
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		context.Background(),
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{},
	)
}

func NewControlPlaneWithContext(
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
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{},
	)
}

// NewPreparedControlPlaneWithContext builds a new generation without mutating
// the shared datapath. Call CommitPreparedDatapath before switching traffic.
func NewPreparedControlPlaneWithContext(
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
) (plane *ControlPlane, err error) {
	return newControlPlaneWithContextOptions(
		ctx,
		log,
		_bpf,
		dnsCache,
		tagToNodeList,
		groups,
		routingA,
		global,
		dnsConfig,
		externGeoDataDirs,
		controlPlaneBuildOptions{
			delayDatapathCommit:   true,
			delayDNSListenerStart: true,
		},
	)
}

func newControlPlaneWithContextOptions(
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
	buildOpts controlPlaneBuildOptions,
) (plane *ControlPlane, err error) {
	// The ctx parameter may carry a preparation timeout from the caller (e.g.
	// context.WithTimeout in cmd/run.go).  All long-lived objects owned by the
	// ControlPlane — its lifecycle context, dialer contexts, goroutines — MUST
	// derive from a background context so they are not cancelled when the
	// preparation deadline expires.  The caller's ctx is NOT used as a parent
	// for any perennnial context below.
	_ = ctx

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
	if err := features.HaveProgramHelper(ebpf.SchedCLS, asm.FnLoop); err != nil {
		return nil, fmt.Errorf("%w: your kernel version %v does not support bpf_loop (needed by routing); expect >=%v; upgrade your kernel and try again",
			err,
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
		return nil, fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}

	InitDaeNetns(log)
	if err = InitSysctlManager(log); err != nil {
		return nil, err
	}

	if err = GetDaeNetns().Setup(); err != nil {
		return nil, fmt.Errorf("failed to setup dae netns: %w", err)
	}
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		if os.IsNotExist(err) {
			log.Warnln("Perhaps you are in a container environment (such as lxc). If so, please use higher virtualization (kvm/qemu).")
		}
		return nil, err
	}

	/// Load pre-compiled programs and maps into the kernel.
	if _bpf == nil {
		// Conn-state maps are preserved across in-process reload via object handoff,
		// so fresh loads should not inherit stale bpffs pins from previous processes.
		cleanupPinnedConnStateMapFiles(log, pinPath)
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

	var bpf *bpfObjects
	if _bpf != nil {
		if obj, ok := _bpf.(*bpfObjects); ok {
			bpf = obj
		} else {
			return nil, fmt.Errorf("unexpected bpf type: %T", _bpf)
		}
	} else {
		bpf = new(bpfObjects)
		if err = fullLoadBpfObjects(log, bpf, &loadBpfOptions{
			PinPath:           pinPath,
			CollectionOptions: collectionOpts,
		}, global.SoMarkFromDae); err != nil {
			if log.Level == logrus.PanicLevel {
				log.Panicln(err)
			}
			return nil, fmt.Errorf("load eBPF objects: %w", err)
		}
	}
	// Ensure critical maps are always present. DNS fast-path optimizations only
	// skip per-flow map updates, never map object creation.
	if err = validateRequiredBpfMapsLoaded(bpf); err != nil {
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
		_bpf != nil,
	)
	defer func() {
		if err != nil {
			if plane != nil {
				_ = plane.Close()
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
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	option := dialer.NewGlobalOption(global, log)
	option.DaeDNS, err = daedns.NewWithOption(log, global, dnsConfig, &daedns.NewOption{LocationFinder: locationFinder})
	if err != nil {
		return nil, err
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
		groupOption, err := ParseGroupOverrideOption(group, *global, log)
		finalOption := option
		if err == nil && groupOption != nil {
			groupOption.TransportCacheNamespace = option.TransportCacheNamespace
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
	if log.IsLevelEnabled(logrus.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range routingProgram.Rules {
			debugBuilder.WriteString(rule.String(true, false, false) + "\n")
		}
		log.Debugf("RoutingA:\n%vfallback: %v\n", debugBuilder.String(), routingProgram.Fallback)
	}
	// Parse rules and build.
	log.Infoln("Building routing matcher...")
	builder, err := NewRoutingMatcherBuilderFromProgram(log, routingProgram, outboundName2Id, core.bpf)
	if err != nil {
		return nil, fmt.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	kernspaceSnapshot := builder.KernspaceSnapshot()
	if !buildOpts.delayDatapathCommit {
		log.Infoln("Loading routing rules into kernel space (BPF)...")
		var lpmIndices []uint32
		if lpmIndices, err = kernspaceSnapshot.BuildKernspace(log, core.bpf); err != nil {
			return nil, fmt.Errorf("routing kernspace snapshot: %w", err)
		}
		core.lpmTrieIndices = lpmIndices
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

	// New control plane.
	cctx, cancel := context.WithCancel(context.Background())
	plane = &ControlPlane{
		log:          log,
		runtimeStats: newRuntimeStats(),
		core:         core,
		deferFuncs:   deferFuncs,
		listenIp:     "0.0.0.0",
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:           outbounds,
			referencedOutbounds: referencedOutbounds,
			dialMode:            dialMode,
			routingMatcher:      routingMatcher,
			bootstrapResolvers:  bootstrapResolvers,
		},
		controlPlaneDNSRuntime:      newControlPlaneDNSRuntime(buildOpts.delayDNSListenerStart),
		controlPlaneDatapathJanitor: newControlPlaneDatapathJanitor(),
		onceNetworkReady:            sync.Once{},
		drainTracker:                newControlPlaneDrainTracker(),
		ctx:                         cctx,
		cancel:                      cancel,
		ready:                       make(chan struct{}),
		autoConfigKernelParameter:   global.AutoConfigKernelParameter,
		routingKernspaceSnapshot:    kernspaceSnapshot,
		preparedDatapathCommit:      buildOpts.delayDatapathCommit,
		sharedBpfReload:             _bpf != nil,
		pendingDnsReloadCache:       dnsCache,
		muRealDomainSet:             sync.RWMutex{},
		realDomainSet:               bloom.NewWithEstimates(2048, 0.001),
		tcpSniffNegSet:              make(map[tcpSniffNegKey]tcpSniffNegEntry),
		negJanitorStop:              make(chan struct{}),
		negJanitorDone:              make(chan struct{}),
		lanInterface:                global.LanInterface,
		wanInterface:                global.WanInterface,
		sniffingTimeout:             sniffingTimeout,
		tproxyPortProtect:           global.TproxyPortProtect,
		soMarkFromDae:               global.SoMarkFromDae,
		mptcp:                       global.Mptcp,
		udpRouteScopeSensitive:      builder.UsesPacketMetadataRouting(),
		udpUnorderedRunner:          newDefaultUdpUnorderedTaskRunner(cctx),
		failedQuicDcidCache:         newFailedQuicDcidCache(failedQuicDcidCacheMaxEntries),
	}
	SetFailedQuicDcidCache(plane.failedQuicDcidCache)
	SetAnyfromSoMark(global.SoMarkFromDae)
	plane.runtimeStats.startRoller(cctx)
	plane.deferFuncs = append(plane.deferFuncs, plane.closePublishedListenerFiles)
	plane.startRealDomainNegJanitor()
	if !buildOpts.delayDatapathCommit {
		plane.startConnStateJanitor()
	}

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
	dnsControllerOption := plane.dnsControllerOption()
	dnsControllerOption.OptimisticCache = dnsConfig.OptimisticCache
	dnsControllerOption.OptimisticCacheTtl = dnsConfig.OptimisticCacheTtl
	dnsControllerOption.MaxCacheSize = dnsConfig.MaxCacheSize
	dnsControllerOption.IpVersionPrefer = dnsConfig.IpVersionPrefer
	plane.dnsController, err = NewDnsController(dnsUpstream, dnsControllerOption)
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
		if !buildOpts.delayDNSListenerStart {
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
	go func() {
		defer close(plane.dnsUpstreamsReady)
		dnsUpstream.InitUpstreams(plane.ctx)
	}()

	if buildOpts.delayDatapathCommit {
		plane.preparedDatapathCommit = true
	} else {
		if err = plane.commitInterfaceBindings(); err != nil {
			return nil, err
		}
		if plane.sharedBpfReload {
			if err = clearReloadDomainRoutingMap(core.bpf); err != nil {
				return nil, fmt.Errorf("clearReloadDomainRoutingMap: %w", err)
			}
		}
		plane.replayDnsReloadCache()
		plane.markReady()
	}
	return plane, nil
}

func ParseFixedDomainTtl(ks []config.KeyableString) (map[string]int, error) {
	m := make(map[string]int)
	for _, k := range ks {
		key, value, _ := strings.Cut(string(k), ":")
		ttl, err := strconv.ParseInt(strings.TrimSpace(value), 0, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ttl: %v", err)
		}
		m[strings.TrimSpace(key)] = int(ttl)
	}
	return m, nil
}

func ParseGroupOverrideOption(group config.Group, global config.Global, log *logrus.Logger) (*dialer.GlobalOption, error) {
	result := global
	changed := false
	if group.TcpCheckUrl != nil {
		result.TcpCheckUrl = group.TcpCheckUrl
		changed = true
	}
	if group.TcpCheckHttpMethod != "" {
		result.TcpCheckHttpMethod = group.TcpCheckHttpMethod
		changed = true
	}
	if group.UdpCheckDns != nil {
		result.UdpCheckDns = group.UdpCheckDns
		changed = true
	}
	if group.CheckInterval != 0 {
		result.CheckInterval = group.CheckInterval
		changed = true
	}
	if group.CheckTolerance != 0 {
		result.CheckTolerance = group.CheckTolerance
		changed = true
	}
	if changed {
		option := dialer.NewGlobalOption(&result, log)
		return option, nil
	}
	return nil, nil
}

// clearReloadDomainRoutingMap keeps reload behavior aligned with main:
// only clear domain_routing_map on reload.
//
// IMPORTANT:
// Scheme3 (Embedded Design): Connection-state maps are preserved across in-process
// reload by handing the live BPF objects to the new control plane. Do NOT clear
// them here, otherwise established flows may lose cached state and get rerouted.
func clearReloadDomainRoutingMap(bpf *bpfObjects) error {
	return BpfMapDeleteAll[[4]uint32, bpfDomainRouting](bpf.DomainRoutingMap)
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
		{name: "egress_return_handoff_map", m: bpf.EgressReturnHandoffMap},
		{name: "udp_conn_state_map", m: bpf.UdpConnStateMap},
		{name: "routing_handoff_map", m: bpf.RoutingHandoffMap},
		{name: "routing_map", m: bpf.RoutingMap},
		{name: "routing_meta_map", m: bpf.RoutingMetaMap},
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

func (c *ControlPlane) EjectLpmIndices() []uint32 {
	if c == nil || c.core == nil {
		return nil
	}
	return c.core.EjectLpmIndices()
}

func (c *ControlPlane) InheritLpmIndices(indices []uint32) {
	if c == nil || c.core == nil {
		return
	}
	c.core.InheritLpmIndices(indices)
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

func (c *ControlPlane) CloneDnsCache() map[string]*DnsCache {
	if c == nil {
		return nil
	}
	return c.cloneDnsCache()
}

func (c *ControlPlane) ActiveDnsController() *DnsController {
	if c == nil {
		return nil
	}
	return c.activeController(&c.dnsHandoffController)
}

func (c *ControlPlane) dnsRequestContext(ctx context.Context, controller *DnsController) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || controller == nil || controller == c.dnsController {
		return ctx
	}
	if c.dnsHandoffController.Load() == controller {
		return controller.baseContext()
	}
	return ctx
}

// SharesActiveDnsControllerWith reports whether both control planes currently
// resolve DNS through the same active controller instance.
func (c *ControlPlane) SharesActiveDnsControllerWith(other *ControlPlane) bool {
	if c == nil || other == nil {
		return false
	}
	controller := c.ActiveDnsController()
	return controller != nil && controller == other.ActiveDnsController()
}

func (c *ControlPlane) DetachDnsController() *DnsController {
	if c == nil {
		return nil
	}
	return c.detachController()
}

func (c *ControlPlane) replaceDNSHandoffController(controller *DnsController, owned bool) (*DnsController, bool) {
	if c == nil {
		return nil, false
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	previous := c.dnsHandoffController.Load()
	previousOwned := c.dnsHandoffOwned
	c.dnsHandoffOwned = owned && controller != nil
	c.dnsHandoffController.Store(controller)
	return previous, previousOwned
}

func (c *ControlPlane) clearDNSHandoffControllerIfMatch(controller *DnsController) (*DnsController, bool, bool) {
	if c == nil {
		return nil, false, false
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	current := c.dnsHandoffController.Load()
	if current != controller {
		return current, false, false
	}
	owned := c.dnsHandoffOwned
	c.dnsHandoffOwned = false
	c.dnsHandoffController.Store(nil)
	return current, owned, true
}

func (c *ControlPlane) takeDNSHandoffController() (*DnsController, bool) {
	if c == nil {
		return nil, false
	}
	c.dnsHandoffMu.Lock()
	defer c.dnsHandoffMu.Unlock()

	controller := c.dnsHandoffController.Load()
	owned := c.dnsHandoffOwned
	c.dnsHandoffOwned = false
	c.dnsHandoffController.Store(nil)
	return controller, owned
}

func (c *ControlPlane) EnableDNSHandoff(controller *DnsController, duration time.Duration) {
	if c == nil || controller == nil {
		return
	}
	if c.log != nil {
		c.log.WithField("duration", duration).Warnln("[Reload] Enabled DNS handoff controller")
	}
	if previous, previousOwned := c.replaceDNSHandoffController(controller, true); previous != nil && previousOwned && previous != controller {
		_ = previous.Close()
	}
	go func(ctrl *DnsController) {
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-timer.C:
			if _, owned, cleared := c.clearDNSHandoffControllerIfMatch(ctrl); cleared {
				if c.log != nil {
					c.log.Warnln("[Reload] DNS handoff controller expired")
				}
				if owned {
					_ = ctrl.Close()
				}
			}
		case <-c.ctx.Done():
			if _, owned, cleared := c.clearDNSHandoffControllerIfMatch(ctrl); cleared && owned {
				_ = ctrl.Close()
			}
		}
	}(controller)
}

func (c *ControlPlane) SetDNSHandoffController(controller *DnsController) {
	if c == nil {
		return
	}
	if previous, previousOwned := c.replaceDNSHandoffController(controller, false); previous != nil && previousOwned && previous != controller {
		_ = previous.Close()
	}
}

// InheritDialerHealthFrom copies health snapshots from a previous control plane
// generation into the current one. It returns true when at least one dialer
// matched by group+name between the old and new generation, indicating that
// active connections on those dialers may survive the reload.
func (c *ControlPlane) InheritDialerHealthFrom(previous *ControlPlane) bool {
	if c == nil || previous == nil {
		return false
	}

	var hasOverlap bool

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
				d.RestoreHealthSnapshot(oldDialer.ReloadHealthSnapshot())
				hasOverlap = true
			}
		}
		group.EnsureReloadSelectionFloor(fallback)
	}
	return hasOverlap
}

func updateConnStateJanitorPressure(
	state connStateJanitorPressureState,
	overflowDelta bool,
	maxUsagePercent int,
) connStateJanitorPressureState {
	if overflowDelta || maxUsagePercent >= connStateJanitorPressureEnterUsage {
		state.active = true
		state.belowThresholdRounds = 0
		return state
	}
	if !state.active {
		return state
	}
	if maxUsagePercent < connStateJanitorPressureExitUsage {
		state.belowThresholdRounds++
		if state.belowThresholdRounds >= connStateJanitorPressureExitRounds {
			state.active = false
			state.belowThresholdRounds = 0
		}
		return state
	}
	state.belowThresholdRounds = 0
	return state
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

func (c *ControlPlane) dnsControllerOption() *DnsControllerOption {
	if c == nil {
		return nil
	}
	return &DnsControllerOption{
		Log:              c.log,
		LifecycleContext: c.ctx,
		ConcurrencyLimit: 0,
		CacheAccessCallback: func(cache *DnsCache) (err error) {
			if err = c.core.BatchUpdateDomainRouting(cache); err != nil {
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
		NewCache: func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error) {
			return &DnsCache{
				DomainBitmap:     c.routingMatcher.domainMatcher.MatchDomainBitmap(fqdn),
				NS:               ns,
				Extra:            extra,
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: c.chooseBestDnsDialer,
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
		FixedDomainTtl: c.dnsFixedDomainTtl,
	}
}

func (c *ControlPlane) closePublishedListenerFiles() error {
	if c == nil {
		return nil
	}

	c.listenerPublishMu.Lock()
	files := c.listenerFiles
	c.listenerFiles = nil
	c.listenerPublishMu.Unlock()

	var errs []error
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

func (c *ControlPlane) publishListenerSockets(listener *Listener) error {
	if c == nil || c.core == nil || listener == nil {
		return fmt.Errorf("publishListenerSockets: nil control plane or listener")
	}

	var (
		newFiles []*os.File
		err      error
	)
	closeNewFiles := func() {
		for _, f := range newFiles {
			if f != nil {
				_ = f.Close()
			}
		}
	}

	if listener.tcp4Listener != nil {
		tcp4File, e := dupTCPListenerFile(listener.tcp4Listener)
		if e != nil {
			return fmt.Errorf("failed to retrieve copy of the underlying TCP IPv4 listener file")
		}
		newFiles = append(newFiles, tcp4File)
		if err = c.core.bpf.ListenSocketMap.Update(consts.ZeroKey, uint64(tcp4File.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}
	if listener.tcp6Listener != nil {
		tcp6File, e := dupTCPListenerFile(listener.tcp6Listener)
		if e != nil {
			closeNewFiles()
			return fmt.Errorf("failed to retrieve copy of the underlying TCP IPv6 listener file")
		}
		newFiles = append(newFiles, tcp6File)
		if err = c.core.bpf.ListenSocketMap.Update(consts.TwoKey, uint64(tcp6File.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}
	if listener.packetConn != nil {
		udpFile, e := dupUDPPacketConnFile(listener.packetConn)
		if e != nil {
			closeNewFiles()
			return fmt.Errorf("failed to retrieve copy of the underlying UDP connection file")
		}
		newFiles = append(newFiles, udpFile)
		if err = c.core.bpf.ListenSocketMap.Update(consts.OneKey, uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
			closeNewFiles()
			return err
		}
	}

	c.listenerPublishMu.Lock()
	oldFiles := c.listenerFiles
	c.listenerFiles = newFiles
	c.listenerPublishMu.Unlock()
	for _, f := range oldFiles {
		if f != nil {
			_ = f.Close()
		}
	}
	return nil
}

func (c *ControlPlane) PublishListenerSockets(listener *Listener) error {
	return c.publishListenerSockets(listener)
}

func (c *ControlPlane) commitInterfaceBindings() error {
	if c == nil || c.core == nil {
		return nil
	}

	if len(c.lanInterface) > 0 {
		if c.autoConfigKernelParameter {
			if err := SetIpv4forward("1"); err != nil {
				c.log.WithError(err).Warnln("Failed to enable IPv4 forwarding; proxy functionality may be limited")
			}
			if err := setForwarding("all", consts.IpVersionStr_6, "1"); err != nil {
				c.log.WithError(err).Warnln("Failed to enable IPv6 forwarding; proxy functionality may be limited")
			}
		}
		c.lanInterface = common.Deduplicate(c.lanInterface)
		for _, ifname := range c.lanInterface {
			c.core.bindLan(ifname, c.autoConfigKernelParameter)
		}
	}

	if len(c.wanInterface) > 0 {
		if err := c.core.setupSkPidMonitor(); err != nil {
			c.log.WithError(err).Warnln("cgroup2 is not enabled; pname routing cannot be used")
		}
		if err := c.core.setupTCPRelayOffload(); err != nil {
			c.log.WithError(err).Debugln("TCP relay eBPF offload disabled")
		}
		for _, ifname := range c.wanInterface {
			if len(c.lanInterface) > 0 && c.autoConfigKernelParameter {
				acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
				val, err := acceptRa.Get()
				if err == nil && val == "1" {
					if err := acceptRa.Set("2", false); err != nil {
						c.log.WithError(err).Warnf("Failed to set accept_ra=2 for %v; IPv6 autoconfig may not work as expected", ifname)
					}
				}
			}
			c.core.bindWan(ifname)
		}
	}

	if err := c.core.bindDaens(); err != nil {
		return fmt.Errorf("bindDaens: %w", err)
	}
	return nil
}

func (c *ControlPlane) replayDnsReloadCache() {
	if c == nil || c.dnsController == nil || c.pendingDnsReloadCache == nil {
		return
	}
	count := c.dnsController.RestoreReloadCache(c.pendingDnsReloadCache, c.routingMatcher.domainMatcher.MatchDomainBitmap, time.Now())
	if count > 0 {
		c.log.Infof("Restored %d DNS cache entries from previous control plane", count)
	}
	c.pendingDnsReloadCache = nil
}

func (c *ControlPlane) registerIncomingConnection(conn net.Conn) bool {
	if c == nil || conn == nil {
		return false
	}
	if c.rejectNewConnections.Load() {
		_ = conn.Close()
		return false
	}
	c.inConnections.Store(conn, struct{}{})
	if c.rejectNewConnections.Load() {
		c.inConnections.Delete(conn)
		_ = conn.Close()
		return false
	}
	return true
}

func (c *ControlPlane) unregisterIncomingConnection(conn net.Conn) {
	if c == nil || conn == nil {
		return
	}
	c.inConnections.Delete(conn)
}

// CommitPreparedDatapath applies deferred kernel/BPF mutations for a prepared
// control plane. It is safe to call once; subsequent calls are no-ops.
func (c *ControlPlane) CommitPreparedDatapath() error {
	if c == nil || !c.preparedDatapathCommit {
		return nil
	}
	if err := c.commitInterfaceBindings(); err != nil {
		return err
	}
	if c.routingKernspaceSnapshot != nil {
		c.log.Infoln("Loading routing rules into kernel space (BPF)...")
		lpmIndices, err := c.routingKernspaceSnapshot.BuildKernspace(c.log, c.core.bpf)
		if err != nil {
			return fmt.Errorf("routing kernspace snapshot: %w", err)
		}
		c.core.lpmTrieIndices = lpmIndices
	}
	if c.sharedBpfReload {
		if err := clearReloadDomainRoutingMap(c.core.bpf); err != nil {
			return fmt.Errorf("clearReloadDomainRoutingMap: %w", err)
		}
	}
	c.replayDnsReloadCache()
	c.startConnStateJanitor()
	c.preparedDatapathCommit = false
	return nil
}

// RebuildReloadDatapath restores this generation's datapath after a staged
// reload attempt modified shared BPF state but failed before cutover completed.
func (c *ControlPlane) RebuildReloadDatapath() error {
	if c == nil || c.routingKernspaceSnapshot == nil || c.core == nil || c.core.PeekBpf() == nil {
		return nil
	}
	c.log.Warnln("[Reload] Rebuilding previous generation datapath after staged handoff failure")
	lpmIndices, err := c.routingKernspaceSnapshot.BuildKernspace(c.log, c.core.bpf)
	if err != nil {
		return fmt.Errorf("rebuild routing kernspace: %w", err)
	}
	c.ReplaceLpmIndices(lpmIndices)
	if err := clearReloadDomainRoutingMap(c.core.bpf); err != nil {
		return fmt.Errorf("rebuild clearReloadDomainRoutingMap: %w", err)
	}
	cache := c.CloneDnsCache()
	c.pendingDnsReloadCache = cache
	c.replayDnsReloadCache()
	return nil
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

func (c *ControlPlane) ActivateCheck() {
	for _, g := range c.outbounds {
		// Only activate health checks for outbounds referenced by routing rules.
		// This significantly reduces startup time when subscription has many nodes
		// but only a few groups are actually used in routing.
		if _, referenced := c.referencedOutbounds[g.Name]; !referenced {
			c.log.Debugf("Skip health check for unreferenced outbound: %v", g.Name)
			continue
		}
		for _, d := range g.Dialers {
			// We only activate check of nodes that have a group.
			d.ActivateCheck()
		}
	}
}

// OnHealthCheckSuccess is called when a dialer passes health check.
// This clears the failed QUIC DCID cache since network conditions may have improved.
func (c *ControlPlane) OnHealthCheckSuccess() {
	ClearFailedQuicDcids()
}

func (c *ControlPlane) ChooseDialTarget(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) (dialTarget string, shouldReroute bool, dialIp bool) {
	dialMode := consts.DialMode_Ip

	if !outbound.IsReserved() && domain != "" {
		switch c.dialMode {
		case consts.DialMode_Domain:
			// Avoid blocking probe for literal IP / host:port values.
			if isIPLikeDomain(domain) {
				break
			}
			if c.dnsController.HasDnsKnowledge(c.dnsController.cacheKey(domain, common.AddrToDnsType(dst.Addr()))) {
				// Has A/AAAA records. It is a real domain.
				dialMode = consts.DialMode_Domain
				shouldReroute = true
			} else {
				if known, real := c.lookupRealDomainCache(domain); known {
					if real {
						dialMode = consts.DialMode_Domain
						shouldReroute = true
					}
				} else {
					// Unknown domain on first hit: warm it asynchronously to avoid
					// blocking connection setup on webpage first paint path.
					c.triggerRealDomainProbe(domain)
				}
			}
		case consts.DialMode_DomainCao:
			shouldReroute = true
			fallthrough
		case consts.DialMode_DomainPlus:
			dialMode = consts.DialMode_Domain
		}
	}

	switch dialMode {
	case consts.DialMode_Ip:
		dialTarget = dst.String()
		dialIp = true
	case consts.DialMode_Domain:
		if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
			// Sniffed domain may be like `[2606:4700:20::681a:d1f]`. We should remove the brackets.
			domain = domain[1 : len(domain)-1]
		}
		if _, err := netip.ParseAddr(domain); err == nil {
			// domain is IPv4 or IPv6 (has colon)
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
			dialIp = true

		} else if _, _, err := net.SplitHostPort(domain); err == nil {
			// domain is already domain:port
			dialTarget = domain
		} else {
			dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(logrus.Fields{
				"from": dst.String(),
				"to":   dialTarget,
			}).Debugln("Rewrite dial target to domain")
		}
	}
	return dialTarget, shouldReroute, dialIp
}

func (c *ControlPlane) lookupRealDomainCache(domain string) (known bool, real bool) {
	// Read-mostly fast path.
	c.muRealDomainSet.RLock()
	hit := c.realDomainSet.TestString(domain)
	c.muRealDomainSet.RUnlock()
	if hit {
		return true, true
	}

	// Negative-cache fast path.
	now := time.Now()
	if v, ok := c.realDomainNegSet.Load(domain); ok {
		expiresAt, _ := v.(int64)
		if now.UnixNano() < expiresAt {
			return true, false
		}
		c.realDomainNegSet.Delete(domain)
	}
	return false, false
}

func (c *ControlPlane) resolveBootstrapIp46(ctx context.Context, host string, network string) (*netutils.Ip46, error, error) {
	if len(c.bootstrapResolvers) == 0 {
		err := fmt.Errorf("bootstrap resolver is not configured")
		return &netutils.Ip46{}, err, err
	}
	return c.resolveIp46WithBootstrapResolvers(ctx, host, network, false, resolveIp46ForBootstrap)
}

func (c *ControlPlane) triggerRealDomainProbe(domain string) {
	if domain == "" || isIPLikeDomain(domain) {
		return
	}
	if known, _ := c.lookupRealDomainCache(domain); known {
		return
	}
	go func() {
		_, _, _ = c.realDomainProbeS.Do(domain, func() (any, error) {
			return c.probeAndUpdateRealDomain(domain), nil
		})
	}()
}

func (c *ControlPlane) probeAndUpdateRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	now := time.Now()
	// Use ControlPlane's context for real domain probe to enable proper cancel propagation
	ctx, cancel := context.WithTimeout(c.ctx, realDomainProbeTimeout)
	defer cancel()

	if len(c.bootstrapResolvers) == 0 {
		// Fail closed when no bootstrap resolver is configured.
		return false
	}

	ip46, err4, err6 := c.resolveIp46WithBootstrapResolvers(
		ctx,
		domain,
		common.MagicNetwork("udp", c.soMarkFromDae, c.mptcp),
		true,
		resolveIp46ForRealDomainProbe,
	)
	if err4 != nil && err6 != nil {
		// Probe failed for both families; avoid sticky false negatives.
		return false
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		c.realDomainNegSet.Store(domain, now.Add(realDomainNegativeCacheTTL).UnixNano())
		return false
	}

	c.muRealDomainSet.Lock()
	c.realDomainSet.AddString(domain)
	c.muRealDomainSet.Unlock()
	c.realDomainNegSet.Delete(domain)
	return true
}

func (c *ControlPlane) resolveIp46WithBootstrapResolvers(
	ctx context.Context,
	host string,
	network string,
	race bool,
	resolve func(context.Context, netproxy.Dialer, netip.AddrPort, string, string, bool) (*netutils.Ip46, error, error),
) (*netutils.Ip46, error, error) {
	if len(c.bootstrapResolvers) == 0 {
		err := fmt.Errorf("bootstrap resolver is not configured")
		return &netutils.Ip46{}, err, err
	}

	var firstErr4 error
	var firstErr6 error
	var lastNoRecord *netutils.Ip46
	var lastNoRecordErr4 error
	var lastNoRecordErr6 error
	for _, resolver := range c.bootstrapResolvers {
		ip46, err4, err6 := resolve(ctx, direct.SymmetricDirect, resolver, host, network, race)
		if ip46 == nil {
			ip46 = &netutils.Ip46{}
		}
		if ip46.Ip4.IsValid() || ip46.Ip6.IsValid() {
			return ip46, err4, err6
		}
		if err4 == nil || err6 == nil {
			lastNoRecord = ip46
			lastNoRecordErr4 = err4
			lastNoRecordErr6 = err6
			continue
		}
		if firstErr4 == nil {
			firstErr4 = err4
		}
		if firstErr6 == nil {
			firstErr6 = err6
		}
	}
	if lastNoRecord != nil {
		return lastNoRecord, lastNoRecordErr4, lastNoRecordErr6
	}
	if firstErr4 == nil {
		firstErr4 = fmt.Errorf("bootstrap resolver failed")
	}
	if firstErr6 == nil {
		firstErr6 = firstErr4
	}
	return &netutils.Ip46{}, firstErr4, firstErr6
}

func (c *ControlPlane) cleanupNegativeCaches(now time.Time) {
	nowNano := now.UnixNano()

	// 1. Cleanup real domain negative cache
	c.realDomainNegSet.Range(func(key, value interface{}) bool {
		expiresAt, ok := value.(int64)
		if !ok || nowNano >= expiresAt {
			c.realDomainNegSet.Delete(key)
		}
		return true
	})

	// 2. Cleanup QUIC DCID negative cache
	c.failedQuicDcidCache.CleanupExpired(now)

	// 3. Cleanup TCP sniff negative cache
	c.cleanupTcpSniffNegative(now)
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

func buildDnsDialerSnapshotKey(req *udpRequest, upstream *dns.Upstream) (dnsDialerSnapshotKey, bool) {
	if req == nil || upstream == nil {
		return dnsDialerSnapshotKey{}, false
	}

	realSrc := req.realSrc
	// DNS fast path: exempt source port from cache key to enable cache reuse.
	// DNS queries use random source ports; including the port would completely invalidate the cache.
	// Routing decisions do not depend on the DNS query's source port (port is only for transport layer multiplexing).
	if req.realDst.Port() == 53 {
		realSrc = netip.AddrPortFrom(req.realSrc.Addr(), 0)
	}

	key := dnsDialerSnapshotKey{
		realSrc:     realSrc,
		upstream:    upstream.String(),
		upstreamIp4: upstream.Ip4,
		upstreamIp6: upstream.Ip6,
	}

	if req.routingResult != nil {
		key.routingPname = req.routingResult.Pname
		key.routingMac = req.routingResult.Mac
		key.routingDscp = req.routingResult.Dscp
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

// startConnStateJanitor runs a periodic goroutine that cleans up expired
// UDP and TCP connection state entries from the eBPF maps. This replaces the
// former bpf_timer-based automatic cleanup, providing better hot path performance
// and avoiding CVE-2024-41045.
func (c *ControlPlane) startConnStateJanitor() {
	if c == nil || !c.connStateJanitorStarted.CompareAndSwap(false, true) {
		return
	}
	go func() {
		ticker := time.NewTicker(connStateJanitorPressureInterval)
		defer ticker.Stop()
		defer close(c.connStateJanitorDone)

		var (
			lastConnCleanup      time.Time
			lastRedirectCleanup  time.Time
			lastCookiePidCleanup time.Time
			lastRoutingHandoff   time.Time
			lastHealthCheck      time.Time
			pressureState        connStateJanitorPressureState
		)

		for {
			select {
			case <-c.connStateJanitorStop:
				return
			case <-c.ctx.Done():
				return
			case now := <-ticker.C:
				bpf := c.currentBpf()

				overflowDelta := false
				if bpf != nil && bpf.BpfStatsMap != nil {
					udpOverflow, tcpOverflow := c.readMapOverflowCounters(bpf.BpfStatsMap)
					overflowDelta = udpOverflow > pressureState.lastUdpOverflow ||
						tcpOverflow > pressureState.lastTcpOverflow
					pressureState.lastUdpOverflow = udpOverflow
					pressureState.lastTcpOverflow = tcpOverflow
				}
				if overflowDelta {
					pressureState.active = true
					pressureState.belowThresholdRounds = 0
				}

				connCleanupInterval := connStateJanitorSteadyInterval
				redirectCleanupInterval := redirectTrackJanitorSteadyInterval
				if pressureState.active {
					connCleanupInterval = connStateJanitorPressureInterval
					redirectCleanupInterval = redirectTrackJanitorPressureInterval
				}

				if lastRedirectCleanup.IsZero() || now.Sub(lastRedirectCleanup) >= redirectCleanupInterval {
					c.cleanupRedirectTrackMap()
					lastRedirectCleanup = now
				}
				if lastCookiePidCleanup.IsZero() || now.Sub(lastCookiePidCleanup) >= redirectCleanupInterval {
					c.cleanupCookiePidMap()
					lastCookiePidCleanup = now
				}
				routingHandoffInterval := routingHandoffSteadyInterval
				if pressureState.active {
					routingHandoffInterval = routingHandoffPressureInterval
				}
				if lastRoutingHandoff.IsZero() || now.Sub(lastRoutingHandoff) >= routingHandoffInterval {
					c.cleanupRoutingHandoffMap()
					c.cleanupEgressReturnHandoffMap()
					lastRoutingHandoff = now
				}

				if lastConnCleanup.IsZero() || now.Sub(lastConnCleanup) >= connCleanupInterval {
					udpStats := c.cleanupUdpConnStateMap(pressureState.active)
					tcpStats := c.cleanupTcpConnStateMap(pressureState.active)

					maxUsagePercent := udpStats.usagePercent
					if tcpStats.usagePercent > maxUsagePercent {
						maxUsagePercent = tcpStats.usagePercent
					}
					pressureState = updateConnStateJanitorPressure(pressureState, overflowDelta, maxUsagePercent)
					lastConnCleanup = now
				}

				if lastHealthCheck.IsZero() || now.Sub(lastHealthCheck) >= 5*time.Second {
					c.checkBpfMapHealth()
					lastHealthCheck = now
				}
			}
		}
	}()
}

func (c *ControlPlane) RunReloadRetirementCleanup(staleBeforeNs uint64) {
	if c == nil || staleBeforeNs == 0 {
		return
	}

	c.connStateCleanupMu.Lock()
	redirectDeleted := c.cleanupRedirectTrackMapBeforeLocked(staleBeforeNs)
	cookieDeleted := c.cleanupCookiePidMapBeforeLocked(staleBeforeNs)
	routingHandoffDeleted := c.cleanupRoutingHandoffMapBeforeLocked(staleBeforeNs)
	egressReturnHandoffDeleted := c.cleanupEgressReturnHandoffMapBeforeLocked(staleBeforeNs)
	udpStats := c.cleanupUdpConnStateMapBeforeLocked(true, staleBeforeNs)
	tcpStats := c.cleanupTcpConnStateMapBeforeLocked(true, staleBeforeNs)
	c.connStateCleanupMu.Unlock()

	if c.log == nil {
		return
	}
	if redirectDeleted == 0 && cookieDeleted == 0 && routingHandoffDeleted == 0 &&
		egressReturnHandoffDeleted == 0 &&
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
		"egress_return_deleted":   egressReturnHandoffDeleted,
		"udp_conn_deleted":        udpStats.deleted,
		"tcp_conn_deleted":        tcpStats.deleted,
	}).Infoln("[Reload] Cleaned stale datapath state after generation retirement")
}

// stopConnStateJanitor signals the conn state janitor to stop and waits
// for it to exit gracefully.
func (c *ControlPlane) stopConnStateJanitor() {
	if c == nil || !c.connStateJanitorStarted.Load() {
		return
	}
	c.connStateJanitorOnce.Do(func() {
		if c.connStateJanitorStop != nil {
			close(c.connStateJanitorStop)
		}
		if c.connStateJanitorDone != nil {
			timer := time.NewTimer(gracefulShutdownWaitTimeout)
			defer timer.Stop()
			select {
			case <-c.connStateJanitorDone:
			case <-timer.C:
				c.log.Warn("stopConnStateJanitor: timeout waiting for janitor to exit")
			}
		}
	})
}

// redirectTrackTimeout is the TTL for redirect entries.
// Redirect entries track which interface and MAC addresses to use for reply traffic.
// A longer timeout is acceptable because these entries are small and the consequence
// of stale entries is minimal (wrong MAC address causes one packet to be misdirected).
const redirectTrackTimeout = 5 * time.Minute

// cleanupRedirectTrackMap iterates through the redirect track map and removes
// entries that haven't been accessed within redirectTrackTimeout.
// This is necessary because redirect_track uses HASH (not LRU) to avoid
// the problem where long-lived connections prevent cleanup of other entries.
func (c *ControlPlane) cleanupRedirectTrackMap() int {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupRedirectTrackMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupRedirectTrackMapBeforeLocked(staleBeforeNs uint64) int {
	// Check if we're shutting down - if stop signal is sent, skip cleanup
	select {
	case <-c.connStateJanitorStop:
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
				if age > timeoutNano ||
					(staleBeforeNs > 0 && (value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, key)
				}
			}
		}
		if err != nil {
			if !strings.Contains(err.Error(), "bad file descriptor") &&
				!strings.Contains(err.Error(), "file descriptor") &&
				!strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "key does not exist") {
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

	// Alert if map usage is high
	const redirectTrackCapacity = 65536
	if totalEntries > 0 {
		usagePercent := float64(totalEntries) / float64(redirectTrackCapacity) * 100
		if usagePercent > 90 {
			c.log.Warnf("cleanupRedirectTrackMap: map at %.1f%% capacity (%d entries)",
				usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// cleanupCookiePidMap removes stale cookie->pid metadata that escaped the
// cgroup sock_release backstop. Active sockets refresh last_seen_ns in BPF.
func (c *ControlPlane) cleanupCookiePidMap() int {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupCookiePidMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupCookiePidMapBeforeLocked(staleBeforeNs uint64) int {
	select {
	case <-c.connStateJanitorStop:
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
			if !strings.Contains(err.Error(), "bad file descriptor") &&
				!strings.Contains(err.Error(), "file descriptor") &&
				!strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "key does not exist") {
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
			c.log.Warnf("cleanupCookiePidMap: map at %.1f%% capacity (%d entries)", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// cleanupRoutingHandoffMap removes expired tuple-miss routing metadata entries.
// The handoff map is a short-lived bridge for userspace consumers that miss the
// authoritative conn-state publication window.
func (c *ControlPlane) cleanupRoutingHandoffMap() int {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupRoutingHandoffMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupRoutingHandoffMapBeforeLocked(staleBeforeNs uint64) int {
	select {
	case <-c.connStateJanitorStop:
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
			if !strings.Contains(batchErr.Error(), "bad file descriptor") &&
				!strings.Contains(batchErr.Error(), "file descriptor") &&
				!strings.Contains(batchErr.Error(), "closed") &&
				!strings.Contains(batchErr.Error(), "key does not exist") {
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
			c.log.Warnf("cleanupRoutingHandoffMap: map at %.1f%% capacity (%d entries)", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

func (c *ControlPlane) cleanupEgressReturnHandoffMap() int {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupEgressReturnHandoffMapBeforeLocked(0)
}

func (c *ControlPlane) cleanupEgressReturnHandoffMapBeforeLocked(staleBeforeNs uint64) int {
	select {
	case <-c.connStateJanitorStop:
		return 0
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.EgressReturnHandoffMap == nil {
		return 0
	}

	nowNano, err := monotonicNowNano()
	if err != nil {
		c.log.Errorf("cleanupEgressReturnHandoffMap: failed to get monotonic time: %v", err)
		return 0
	}

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.egressReturnHandoffDelete)
	keysOut := ensureJanitorLookupScratch(scratch.egressReturnHandoffKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.egressReturnHandoffValues)
	totalEntries := 0
	defer func() {
		scratch.egressReturnHandoffDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.egressReturnHandoffKeys = keysOut
		scratch.egressReturnHandoffValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	for {
		count, batchErr := bpf.EgressReturnHandoffMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				totalEntries++
				if egressReturnHandoffExpired(nowNano, valuesOut[i].LastSeenNs) ||
					(staleBeforeNs > 0 && (valuesOut[i].LastSeenNs == 0 || valuesOut[i].LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, keysOut[i])
				}
			}
		}
		if batchErr != nil {
			if !strings.Contains(batchErr.Error(), "bad file descriptor") &&
				!strings.Contains(batchErr.Error(), "file descriptor") &&
				!strings.Contains(batchErr.Error(), "closed") &&
				!strings.Contains(batchErr.Error(), "key does not exist") {
				c.log.Errorf("cleanupEgressReturnHandoffMap: BatchLookup error: %v", batchErr)
			}
			break
		}
	}

	if len(keysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.EgressReturnHandoffMap, keysToDelete); err != nil {
			c.log.Debugf("cleanupEgressReturnHandoffMap: batch delete error: %v", err)
		}
		c.log.Debugf("cleanupEgressReturnHandoffMap: removed %d entries", len(keysToDelete))
	}

	maxEntries := bpf.EgressReturnHandoffMap.MaxEntries()
	if totalEntries > 0 && maxEntries > 0 {
		usagePercent := float64(totalEntries) / float64(maxEntries) * 100
		if usagePercent > 90 {
			c.log.Warnf("cleanupEgressReturnHandoffMap: map at %.1f%% capacity (%d entries)", usagePercent, totalEntries)
		}
	}
	return len(keysToDelete)
}

// cleanupUdpConnStateMap iterates through the UDP conn state map and removes
// cold entries that escaped endpoint-owned teardown.
// DNS entries use a shorter timeout (17s) while non-DNS UDP keeps a longer
// backstop timeout so datapath-only tuples still age out after crashes/reload races.
// When map is under pressure (high usage), timeouts are dynamically reduced
// to free up space more aggressively in a single pass.
func (c *ControlPlane) cleanupUdpConnStateMap(aggressiveCleanup bool) mapCleanupStats {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupUdpConnStateMapBeforeLocked(aggressiveCleanup, 0)
}

func (c *ControlPlane) cleanupUdpConnStateMapBeforeLocked(aggressiveCleanup bool, staleBeforeNs uint64) mapCleanupStats {
	stats := mapCleanupStats{}

	// Check if we're shutting down - if stop signal is sent, skip cleanup
	select {
	case <-c.connStateJanitorStop:
		return stats
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.UdpConnStateMap == nil {
		return stats
	}

	// Use CLOCK_MONOTONIC to match bpf_ktime_get_ns() time base.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupUdpConnStateMap: failed to get monotonic time: %v", err)
		return stats
	}
	nowNano := ts.Nano()

	// Default timeouts
	dnsTimeoutNano := udpConnStateTimeoutDNS.Nanoseconds()
	normalTimeoutNano := QuicNatTimeout.Nanoseconds() // Align eBPF state with Userspace proxy QuicNatTimeout

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.udpDelete)
	keysOut := ensureJanitorLookupScratch(scratch.udpKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.udpValues)
	defer func() {
		scratch.udpDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.udpKeys = keysOut
		scratch.udpValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	aggressiveTimeout := normalTimeoutNano / 2
	aggressiveDnsTimeout := dnsTimeoutNano / 2

	for {
		count, err := bpf.UdpConnStateMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				stats.entries++
				key := keysOut[i]
				value := valuesOut[i]
				// Check if this entry is a DNS connection (port 53)
				isDNS := key.Sport == dnsPortNetworkOrder || key.Dport == dnsPortNetworkOrder

				// Apply dynamic timeout based on map pressure
				timeout := normalTimeoutNano
				if isDNS {
					timeout = dnsTimeoutNano
				}
				if aggressiveCleanup {
					if isDNS {
						timeout = aggressiveDnsTimeout
					} else {
						timeout = aggressiveTimeout
					}
				}

				age := nowNano - int64(value.LastSeenNs)
				if age > timeout ||
					(staleBeforeNs > 0 && (value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs)) {
					keysToDelete = append(keysToDelete, key)
				}
			}
		}
		if err != nil {
			if !strings.Contains(err.Error(), "bad file descriptor") &&
				!strings.Contains(err.Error(), "file descriptor") &&
				!strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "key does not exist") {
				c.log.Errorf("cleanupUdpConnStateMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	maxEntries := bpf.UdpConnStateMap.MaxEntries()
	if maxEntries > 0 {
		stats.usagePercent = stats.entries * 100 / int(maxEntries)
	}

	// Batch delete from UDP conn state map
	if len(keysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.UdpConnStateMap, keysToDelete); err != nil {
			c.log.Debugf("cleanupUdpConnStateMap: batch delete error: %v", err)
		}
	}
	stats.deleted = len(keysToDelete)

	// Log cleanup stats
	if len(keysToDelete) > 0 {
		if aggressiveCleanup {
			c.log.Debugf("cleanupUdpConnStateMap: aggressive cleanup removed %d entries (%d%% usage)",
				len(keysToDelete), stats.usagePercent)
		} else {
			c.log.Debugf("cleanupUdpConnStateMap: removed %d expired entries", len(keysToDelete))
		}
	}

	return stats
}

// cleanupTcpConnStateMap iterates through the TCP conn state map and removes
// entries that haven't been seen within their timeout period or are in CLOSING state.
// When map is under pressure, aggressive cleanup applies with shorter timeouts.
func (c *ControlPlane) cleanupTcpConnStateMap(aggressiveCleanup bool) mapCleanupStats {
	c.connStateCleanupMu.Lock()
	defer c.connStateCleanupMu.Unlock()
	return c.cleanupTcpConnStateMapBeforeLocked(aggressiveCleanup, 0)
}

func (c *ControlPlane) cleanupTcpConnStateMapBeforeLocked(aggressiveCleanup bool, staleBeforeNs uint64) mapCleanupStats {
	stats := mapCleanupStats{}

	// Check if we're shutting down - if stop signal is sent, skip cleanup
	select {
	case <-c.connStateJanitorStop:
		return stats
	default:
	}

	bpf := c.currentBpf()
	if bpf == nil || bpf.TcpConnStateMap == nil {
		return stats
	}

	// Use CLOCK_MONOTONIC to match bpf_ktime_get_ns() time base.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupTcpConnStateMap: failed to get monotonic time: %v", err)
		return stats
	}
	nowNano := ts.Nano()

	establishedTimeoutNano := tcpConnStateTimeoutEstablished.Nanoseconds()
	closingTimeoutNano := tcpConnStateTimeoutClosing.Nanoseconds()

	scratch := c.connStateJanitorScratch()
	keysToDelete := takeJanitorDeleteScratch(scratch.tcpDelete)
	keysOut := ensureJanitorLookupScratch(scratch.tcpKeys)
	valuesOut := ensureJanitorLookupScratch(scratch.tcpValues)
	defer func() {
		scratch.tcpDelete = keepJanitorDeleteScratch(keysToDelete)
		scratch.tcpKeys = keysOut
		scratch.tcpValues = valuesOut
	}()

	var cursor ebpf.MapBatchCursor
	aggressiveEstablishedTimeout := establishedTimeoutNano / 2
	aggressiveClosingTimeout := closingTimeoutNano / 2

	for {
		count, err := bpf.TcpConnStateMap.BatchLookup(&cursor, keysOut, valuesOut, nil)
		if count > 0 {
			for i := range count {
				stats.entries++
				key := keysOut[i]
				value := valuesOut[i]
				// Apply dynamic timeout based on map pressure
				establishedTimeout := establishedTimeoutNano
				closingTimeout := closingTimeoutNano
				if aggressiveCleanup {
					establishedTimeout = aggressiveEstablishedTimeout
					closingTimeout = aggressiveClosingTimeout
				}

				// Check if entry should be cleaned up
				shouldDelete := false
				if value.State == 1 { // TCP_STATE_CLOSING
					// CLOSING state: quick cleanup (FIN/RST seen)
					age := nowNano - int64(value.LastSeenNs)
					if age > closingTimeout {
						shouldDelete = true
					}
				} else {
					// ACTIVE state: normal timeout for established connections
					age := nowNano - int64(value.LastSeenNs)
					if age > establishedTimeout {
						shouldDelete = true
					}
				}
				if !shouldDelete && staleBeforeNs > 0 &&
					(value.LastSeenNs == 0 || value.LastSeenNs < staleBeforeNs) {
					shouldDelete = true
				}

				if shouldDelete {
					keysToDelete = append(keysToDelete, key)
				}
			}
		}
		if err != nil {
			if !strings.Contains(err.Error(), "bad file descriptor") &&
				!strings.Contains(err.Error(), "file descriptor") &&
				!strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "key does not exist") {
				c.log.Errorf("cleanupTcpConnStateMap: BatchLookup error: %v", err)
			}
			break
		}
	}

	maxEntries := bpf.TcpConnStateMap.MaxEntries()
	if maxEntries > 0 {
		stats.usagePercent = stats.entries * 100 / int(maxEntries)
	}

	// Batch delete expired TCP conn state entries
	if len(keysToDelete) > 0 {
		if _, err := BpfMapBatchDelete(bpf.TcpConnStateMap, keysToDelete); err != nil {
			c.log.Debugf("cleanupTcpConnStateMap: batch delete error: %v", err)
		}
	}
	stats.deleted = len(keysToDelete)

	// Log cleanup stats
	if len(keysToDelete) > 0 {
		if aggressiveCleanup {
			c.log.Debugf("cleanupTcpConnStateMap: aggressive cleanup removed %d TCP entries (%d%% usage)",
				len(keysToDelete), stats.usagePercent)
		} else {
			c.log.Debugf("cleanupTcpConnStateMap: removed %d expired TCP entries", len(keysToDelete))
		}
	}

	return stats
}

func (c *ControlPlane) connStateJanitorScratch() *connStateJanitorScratch {
	if c == nil {
		return nil
	}
	return c.scratch()
}

// checkBpfMapHealth monitors map usage and overflow counters for robustness.
// Alerts when maps are approaching capacity or experiencing high overflow rates.
func (c *ControlPlane) checkBpfMapHealth() {
	bpf := c.currentBpf()
	if bpf == nil || bpf.BpfStatsMap == nil {
		return
	}

	// Define alert thresholds
	const (
		warnThreshold = 70               // Alert at 70% capacity
		critThreshold = 85               // Critical alert at 85% capacity
		alertCooldown = 30 * time.Second // Minimum time between alerts
	)

	now := time.Now()

	// Read and log overflow counters from BPF stats map
	var (
		udpOverflow uint64
		tcpOverflow uint64
	)

	udpOverflow, tcpOverflow = c.readMapOverflowCounters(bpf.BpfStatsMap)

	// Alert on significant overflow counts
	if udpOverflow > 0 || tcpOverflow > 0 {
		// Use atomic Int64 to store the last alert time in Unix nanoseconds.
		// Cooldown prevents alert spam.
		nowNano := now.UnixNano()
		last := c.lastBpfOverflowAlertTime.Load()
		if last == 0 || last+int64(alertCooldown) < nowNano {
			if c.lastBpfOverflowAlertTime.CompareAndSwap(last, nowNano) {
				c.log.Warnf("BPF map overflow detected: UDP conn state=%d, TCP conn state=%d. "+
					"Some packets are falling back to slower paths. Check if map capacity is adequate.",
					udpOverflow, tcpOverflow)
			}
		}
	}

	// Estimate map usage by sampling (full iteration is expensive)
	if bpf.UdpConnStateMap != nil {
		maxEntries := bpf.UdpConnStateMap.MaxEntries()
		// If overflow is happening, map is under pressure.
		if udpOverflow > 100 && maxEntries > 0 {
			nowNano := now.UnixNano()
			last := c.lastUdpPressureAlertTime.Load()
			if last == 0 || last+int64(alertCooldown) < nowNano {
				if c.lastUdpPressureAlertTime.CompareAndSwap(last, nowNano) {
					c.log.Errorf("CRITICAL: UDP conn state map is under heavy pressure (overflow=%d). "+
						"Configured capacity=%d. Consider increasing udp_conn_state_map capacity or reducing UDP connection timeout.",
						udpOverflow, maxEntries)
				}
			}
		}
	}
	if bpf.TcpConnStateMap != nil {
		maxEntries := bpf.TcpConnStateMap.MaxEntries()
		if tcpOverflow > 100 && maxEntries > 0 {
			nowNano := now.UnixNano()
			last := c.lastTcpPressureAlertTime.Load()
			if last == 0 || last+int64(alertCooldown) < nowNano {
				if c.lastTcpPressureAlertTime.CompareAndSwap(last, nowNano) {
					c.log.Errorf("CRITICAL: TCP conn state map is under heavy pressure (overflow=%d). "+
						"Configured capacity=%d. Consider increasing tcp_conn_state_map capacity or reducing TCP connection timeout.",
						tcpOverflow, maxEntries)
				}
			}
		}
	}
}

func (c *ControlPlane) readMapOverflowCounters(m *ebpf.Map) (udpOverflow uint64, tcpOverflow uint64) {
	if m == nil {
		return 0, 0
	}
	if v, err := readBpfStatsCounter(m, 0); err == nil {
		udpOverflow = v
	}
	if v, err := readBpfStatsCounter(m, 1); err == nil {
		tcpOverflow = v
	}
	return udpOverflow, tcpOverflow
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
func (l *Listener) Clone() (cloned *Listener, err error) {
	if l == nil {
		return nil, fmt.Errorf("nil listener")
	}

	cloned = &Listener{port: l.port}
	defer func() {
		if err != nil && cloned != nil {
			_ = cloned.Close()
		}
	}()

	if l.tcp4Listener != nil {
		cloned.tcp4Listener, err = cloneTCPListener(l.tcp4Listener)
		if err != nil {
			return nil, fmt.Errorf("clone tcp4 listener: %w", err)
		}
	}
	if l.tcp6Listener != nil {
		cloned.tcp6Listener, err = cloneTCPListener(l.tcp6Listener)
		if err != nil {
			return nil, fmt.Errorf("clone tcp6 listener: %w", err)
		}
	}
	if l.packetConn != nil {
		cloned.packetConn, err = cloneUDPPacketConn(l.packetConn)
		if err != nil {
			return nil, fmt.Errorf("clone udp packet conn: %w", err)
		}
	}

	return cloned, nil
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
	udpConn := listener.packetConn.(*net.UDPConn)
	if err := c.CommitPreparedDatapath(); err != nil {
		return err
	}
	if err := c.publishListenerSockets(listener); err != nil {
		return err
	}
	if err := c.activatePreparedRuntime(); err != nil {
		return err
	}

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
				var netErr net.Error
				if stderrors.As(err, &netErr) && netErr.Timeout() {
					return
				}
				if !commonerrors.IsClosedConnection(err) && !stderrors.Is(err, context.Canceled) {
					c.log.Errorf("Error when accept: %v", err)
				}
				return
			}
			drainRelease := c.acquireDrainTicket()
			go func(lconn net.Conn, release func()) {
				defer release()
				if !c.registerIncomingConnection(lconn) {
					return
				}
				defer c.unregisterIncomingConnection(lconn)
				// Keep the ControlPlane lifecycle context so shutdown/reload can cancel
				// in-flight connection handling. Dial timeout is applied independently
				// inside RouteDialTcp and is not reduced by sniffing time.
				if err := c.handleConn(c.ctx, lconn); err != nil {
					c.log.Warnln("handleConn:", err)
				}
			}(lconn, drainRelease)
		}
	}
	go serveTCP(listener.tcp4Listener)
	go serveTCP(listener.tcp6Listener)
	go func() {
		processPacket := func(pktBuf pool.PB, src netip.AddrPort, oob []byte) {
			pktDst := RetrieveOriginalDest(oob)
			realDst := common.ConvergeAddrPort(pktDst)
			// IMPORTANT: keep original capacity for pool bucketing.
			// Do not use full-slice cap clipping ([:n:n]) here, otherwise Put()
			// may return the buffer into a wrong size-class and poison the pool.
			convergeSrc := common.ConvergeAddrPort(src)
			flowDecision := ClassifyUdpFlow(convergeSrc, realDst, pktBuf)
			if flowDecision.IsQuicInitial {
				flowDecision = flowDecision.EnsureSnifferSession()
			}
			// Debug:
			// t := time.Now()
			task := func() {
				data := pktBuf

				defer data.Put()
				var routingResult *bpfRoutingResult
				var freshRoutingResult *bpfRoutingResult

				// DNS ingress fast path: valid DNS packets to port 53 do not need
				// UdpEndpoint state tracking on ingress. Keep userspace handling to
				// reduce hot-path overhead, but best-effort preserve tuple metadata
				// for rules matching (pname/mac/dscp).
				if realDst.Port() == 53 {
					// IMPORTANT: Check if this is destined for our own DNS listener.
					// If so, skip fast path processing to avoid double-handling.
					// Traffic to 127.0.0.1:53 (or our configured listen address) should be
					// handled only by the DNS listener, not by UDP ingress fast path.
					if c.dnsListener != nil {
						listenAddr := c.dnsListener.Addr()
						// Match both exact address and wildcard port 53 to our listener
						if listenAddr != "" && listenAddr == realDst.String() {
							// This is destined for our own DNS listener - let it handle normally
							if c.log.IsLevelEnabled(logrus.TraceLevel) {
								c.log.WithFields(logrus.Fields{
									"src":        convergeSrc.String(),
									"dst":        realDst.String(),
									"listenAddr": listenAddr,
								}).Trace("Skipping DNS fast path for traffic to our own DNS listener")
							}
							// Fall through to normal UDP processing (will be dropped/ignored)
							return
						}
						// Also check for common local addresses
						if realDst.Addr().IsLoopback() || realDst.Addr().IsUnspecified() {
							// For local addresses, verify we have a DNS listener on port 53
							if _, portStr, err := net.SplitHostPort(listenAddr); err == nil {
								if port, err := strconv.Atoi(portStr); err == nil && port == 53 {
									// We have a DNS listener on port 53, skip fast path
									if c.log.IsLevelEnabled(logrus.TraceLevel) {
										c.log.WithFields(logrus.Fields{
											"src":        convergeSrc.String(),
											"dst":        realDst.String(),
											"listenAddr": listenAddr,
										}).Trace("Skipping DNS fast path for local loopback DNS listener traffic")
									}
									return
								}
							}
						}
					}

					if dnsMessage, _ := ChooseNatTimeout(data, true); dnsMessage != nil {
						dnsRoutingResult := &bpfRoutingResult{
							Outbound: uint8(consts.OutboundControlPlaneRouting),
							Mark:     c.soMarkFromDae,
						}
						if rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP); retrieveErr == nil {
							dnsRoutingResult = rr
							if dnsRoutingResult.Mark == 0 {
								dnsRoutingResult.Mark = c.soMarkFromDae
							}
						} else if !stderrors.Is(retrieveErr, ebpf.ErrKeyNotExist) && c.log.IsLevelEnabled(logrus.DebugLevel) {
							c.log.WithFields(logrus.Fields{
								"src": convergeSrc.String(),
								"dst": realDst.String(),
							}).WithError(retrieveErr).Debug("UDP routing tuple lookup failed for DNS ingress fast path; fallback to minimal routing metadata")
						}
						req := &udpRequest{
							realSrc:       convergeSrc,
							realDst:       realDst,
							src:           convergeSrc,
							lConn:         udpConn,
							routingResult: dnsRoutingResult,
						}

						dnsController := c.ActiveDnsController()
						if dnsController == nil {
							return
						}
						if e := dnsController.Handle_(c.dnsRequestContext(c.ctx, dnsController), dnsMessage, req); e != nil {
							if stderrors.Is(e, ErrDNSQueryConcurrencyLimitExceeded) {
								if c.log.IsLevelEnabled(logrus.DebugLevel) {
									c.log.WithFields(logrus.Fields{
										"src": convergeSrc.String(),
										"dst": realDst.String(),
									}).Debug("DNS query concurrency limit exceeded in fast path")
								}
								return
							}
							if stderrors.Is(e, ErrDNSTruncated) {
								if c.log.IsLevelEnabled(logrus.DebugLevel) {
									c.log.WithFields(logrus.Fields{
										"src":      convergeSrc.String(),
										"dst":      realDst.String(),
										"question": dnsMessage.Question,
									}).Debug("DNS ingress fast path got truncated UDP response; returning TC=1 to client")
								}
								if sendErr := dnsController.sendDnsTruncatedResponse_(dnsMessage, req, nil); sendErr != nil {
									if c.log.IsLevelEnabled(logrus.WarnLevel) && c.allowDnsFastPathServfailLog(time.Now()) {
										c.log.WithError(stderrors.Join(e, sendErr)).WithFields(logrus.Fields{
											"src": convergeSrc.String(),
											"dst": realDst.String(),
										}).Warn("Failed to send truncated DNS response in DNS fast path")
									}
								}
								return
							}
							if c.log.IsLevelEnabled(logrus.WarnLevel) && c.allowDnsFastPathErrorLog(time.Now()) {
								c.log.WithFields(logrus.Fields{
									"src":      convergeSrc.String(),
									"dst":      realDst.String(),
									"question": dnsMessage.Question,
									"error":    e.Error(),
								}).Warn("DNS ingress fast path failed; sending SERVFAIL response")
							}
							if sendErr := dnsController.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeServerFailure, "ServeFail (dns ingress fast path)", req, nil); sendErr != nil {
								if c.log.IsLevelEnabled(logrus.WarnLevel) && c.allowDnsFastPathServfailLog(time.Now()) {
									c.log.WithError(stderrors.Join(e, sendErr)).WithFields(logrus.Fields{
										"src": convergeSrc.String(),
										"dst": realDst.String(),
									}).Warn("Failed to send SERVFAIL response in DNS fast path")
								}
								return
							}
						} else if c.log.IsLevelEnabled(logrus.TraceLevel) {
							// Success logging for DNS fast path (trace level only)
							c.log.WithFields(logrus.Fields{
								"src":      convergeSrc.String(),
								"dst":      realDst.String(),
								"question": dnsMessage.Question,
							}).Trace("DNS ingress fast path handled successfully")
						}
						return
					}
				}

				if !c.udpRouteScopeSensitive {
					if ue, ok := DefaultUdpEndpointPool.Get(flowDecision.CachedRoutingEndpointKey()); ok {
						if cached, cacheHit := ue.GetCachedRoutingResult(realDst, unix.IPPROTO_UDP); cacheHit {
							routingResult = cached
						}
					}
					if routingResult == nil {
						if fallbackKey, ok := flowDecision.CachedRoutingFallbackKey(); ok {
							if ue, ok := DefaultUdpEndpointPool.Get(fallbackKey); ok {
								if cached, cacheHit := ue.GetCachedRoutingResult(realDst, unix.IPPROTO_UDP); cacheHit {
									routingResult = cached
								}
							}
						}
					}
				}

				if routingResult == nil {
					rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP)
					if retrieveErr != nil {
						switch {
						case stderrors.Is(retrieveErr, ebpf.ErrKeyNotExist):
							// Keep behavior consistent with TCP path: missing tuple can happen
							// in short race windows; fallback to userspace routing instead of
							// dropping the packet.
							routingResult = &bpfRoutingResult{
								Outbound: uint8(consts.OutboundControlPlaneRouting),
							}
							if c.log.IsLevelEnabled(logrus.DebugLevel) {
								c.log.WithFields(logrus.Fields{
									"src": convergeSrc.String(),
									"dst": realDst.String(),
								}).WithError(retrieveErr).Debug("UDP routing tuple missing; fallback to userspace routing")
							}
						case realDst.Port() == 53:
							// DNS should never be silently dropped due to transient eBPF lookup
							// failures. Fall back to userspace routing to preserve availability.
							routingResult = &bpfRoutingResult{
								Outbound: uint8(consts.OutboundControlPlaneRouting),
							}
							c.log.WithFields(logrus.Fields{
								"src": convergeSrc.String(),
								"dst": realDst.String(),
							}).WithError(retrieveErr).Warn("UDP routing tuple lookup failed for DNS; fallback to userspace routing")
						default:
							c.log.Warnf("No AddrPort presented: %v", retrieveErr)
							return
						}
					} else {
						routingResult = rr
						rrCopy := *routingResult
						freshRoutingResult = &rrCopy
					}
				}

				if e := c.handlePkt(udpConn, data, convergeSrc, realDst, routingResult, flowDecision, false); e != nil {
					c.log.Warnln("handlePkt:", e)
					return
				}

				if !c.udpRouteScopeSensitive && freshRoutingResult != nil {
					updatedCache := false
					if ue, ok := DefaultUdpEndpointPool.Get(flowDecision.CachedRoutingEndpointKey()); ok {
						ue.UpdateCachedRoutingResult(realDst, unix.IPPROTO_UDP, freshRoutingResult)
						updatedCache = true
					}
					if !updatedCache {
						if fallbackKey, ok := flowDecision.CachedRoutingFallbackKey(); ok {
							if ue, ok := DefaultUdpEndpointPool.Get(fallbackKey); ok {
								ue.UpdateCachedRoutingResult(realDst, unix.IPPROTO_UDP, freshRoutingResult)
							}
						}
					}
				}
			}

			// Session FIFO now takes precedence for generic UDP forwarding.
			// Ordered ingress keeps same-flow packets in the order they were read
			// from the client socket before they reach handlePkt/ue.WriteTo.
			// Direct goroutine dispatch remains only for narrow low-latency
			// exceptions where queue handoff is less valuable than minimal overhead
			// (DNS, SIP/RTP, STUN).
			switch flowDecision.DispatchStrategy() {
			case StrategyOrderedIngress:
				DefaultUdpTaskPool.EmitTask(flowDecision.Key, task)
			case StrategyDirectGoroutine:
				// DNS, VoIP, and other low-latency exception traffic bypasses the
				// ordered per-flow queue and runs immediately.
				go task()
			default:
				// Defensive fallback for unknown future strategy values.
				if !c.udpUnorderedRunner.Submit(flowDecision.Key, task) {
					pktBuf.Put()
				}
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
					if !commonerrors.IsClosedConnection(err) {
						c.log.Errorf("ReadBatchUDP: %v", err)
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
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			pktBuf := pool.GetFullCap(consts.EthernetMtu)
			n, oobn, _, src, err := udpConn.ReadMsgUDPAddrPort(pktBuf, oob[:])
			if err != nil {
				pktBuf.Put()
				if !commonerrors.IsClosedConnection(err) {
					c.log.Errorf("ReadMsgUDPAddrPort: %v", err)
				}
				break
			}

			// Dual-stack UDP listener path: prefer correctness and IPv6 coverage
			// over batch-read optimization. OOB is consumed synchronously in
			// processPacket, so reusing the stack buffer is safe here.
			processPacket(pktBuf[:n], src, oob[:oobn])
		}
	}()
	c.ActivateCheck()
	<-c.ctx.Done()
	// Log the reason Serve() is exiting to help distinguish intentional
	// shutdown/reload from unexpected context cancellation (e.g. a leaked
	// timeout inherited from the reload preparation context).
	ctxErr := c.ctx.Err()
	if ctxErr != nil {
		c.log.WithFields(logrus.Fields{
			"error": ctxErr.Error(),
		}).Info("[ControlPlane] Serve() exiting; context cancelled")
	}
	return nil
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
		return nil, fmt.Errorf("failed to serve: %w", err)
	}

	return listener, nil
}

func (c *ControlPlane) chooseBestDnsDialer(
	ctx context.Context, req *udpRequest, dnsUpstream *dns.Upstream,
) (*dialArgument, error) {
	now := time.Now()
	snapshotKey, snapshotEnabled := buildDnsDialerSnapshotKey(req, dnsUpstream)
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
			outboundIndex, mark, _, err := c.Route(req.realSrc, netip.AddrPortFrom(dAddr, dnsUpstream.Port), dnsUpstream.Hostname, proto.ToL4ProtoType(), req.routingResult)
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
	if c == nil {
		return nil
	}
	c.rejectNewConnections.Store(true)

	var errs []error
	c.inConnections.Range(func(key, value any) bool {
		// Use comma-ok pattern for type safety to prevent panic if key is not net.Conn
		conn, ok := key.(net.Conn)
		if !ok {
			// Unexpected type in inConnections - this should never happen
			errs = append(errs, fmt.Errorf("unexpected type %T in inConnections", key))
			return true
		}
		if cerr := conn.Close(); cerr != nil {
			errs = append(errs, cerr)
		}
		c.inConnections.Delete(key)
		return true
	})

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
	c.core.retired.Store(true)
}

// ResetGlobalUdpState clears all global UDP-related pools (endpoints and sniffers).
// This is used during reload to ensure no stale connections from the previous
// generation leak into the new one.
func ResetGlobalUdpState() {
	DefaultUdpEndpointPool.Reset()
	DefaultAnyfromPool.Reset()
	DefaultUdpTaskPool.Reset()
	DefaultPacketSnifferSessionMgr.Reset()
	ResetUdpLogLimiters()
}

func (c *ControlPlane) closeTail() error {
	var errs []error

	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			errs = append(errs, e)
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

	// Note: inConnections is cleared by AbortConnections() which should be called before Close()

	// Combine defer errors with core.Close error
	if c.core != nil {
		if coreErr := c.core.Close(); coreErr != nil {
			errs = append(errs, coreErr)
		}
	}

	c.releaseRetainedState()

	return stderrors.Join(errs...)
}

func (c *ControlPlane) releaseRetainedState() {
	if c == nil {
		return
	}

	c.deferFuncs = nil
	c.controlPlaneGenerationState.releaseRetainedState()
	c.controlPlaneDNSRuntime.releaseRetainedState()
	if handoff, owned := c.takeDNSHandoffController(); owned && handoff != nil {
		_ = handoff.Close()
	}
	c.muRealDomainSet.Lock()
	c.realDomainSet = nil
	c.muRealDomainSet.Unlock()
	c.controlPlaneDatapathJanitor.releaseRetainedState()
	c.wanInterface = nil
	c.lanInterface = nil
	c.udpUnorderedRunner = nil
	c.failedQuicDcidCache = nil
	c.listenerPublishMu.Lock()
	c.listenerFiles = nil
	c.listenerPublishMu.Unlock()
	c.routingKernspaceSnapshot = nil
	c.pendingDnsReloadCache = nil
	c.core = nil
}

func (c *ControlPlane) Close() (err error) {
	if c == nil {
		return nil
	}

	c.closeOnce.Do(func() {
		c.unpublishRuntimeStats()
		if c.cancel != nil {
			c.cancel()
		}

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

		done := make(chan error, 1)
		go func() {
			done <- c.closeTail()
		}()

		timer := time.NewTimer(controlPlaneDeferredCleanupTimeout)
		defer timer.Stop()

		select {
		case err := <-done:
			c.closeErr = err
		case <-timer.C:
			timeoutErr := fmt.Errorf("control plane close tail timed out after %v", controlPlaneDeferredCleanupTimeout)
			if c.log != nil {
				c.log.WithError(timeoutErr).Warn("ControlPlane.Close: continuing while tail cleanup finishes in background")
			}
			c.closeErr = timeoutErr
		}
	})

	return c.closeErr
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
	return c.startPreparedDNSListener(c.ctx, c.log, &c.deferFuncs, c.stopOwnedDNSListener)
}
