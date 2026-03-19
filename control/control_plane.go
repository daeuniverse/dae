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
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/daeuniverse/outbound/transport/meek"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	"golang.org/x/sys/unix"
)

type ControlPlane struct {
	log *logrus.Logger

	core       *controlPlaneCore
	deferFuncs []func() error
	listenIp   string

	// outbounds is an immutable slice set during NewControlPlane initialization.
	// It is safe for concurrent reads without synchronization because:
	// 1. The slice is never modified after initialization
	// 2. The ready channel is closed only after outbounds is fully populated
	// 3. All reads happen-after the ready channel is closed
	outbounds     []*outbound.DialerGroup
	inConnections sync.Map

	dnsController    *DnsController
	dnsListener      *DNSListener
	onceNetworkReady sync.Once

	dialMode consts.DialMode

	routingMatcher *RoutingMatcher

	ctx    context.Context
	cancel context.CancelFunc
	ready  chan struct{}

	muRealDomainSet   sync.RWMutex
	realDomainSet     *bloom.BloomFilter
	realDomainNegSet  sync.Map // map[string]int64 (expiresAt unix nano)
	dnsDialerSnapshot sync.Map // map[dnsDialerSnapshotKey]*dnsDialerSnapshotEntry
	tcpSniffNegMu     sync.RWMutex
	tcpSniffNegSet    map[tcpSniffNegKey]tcpSniffNegEntry
	realDomainProbeS  singleflight.Group
	negJanitorStop    chan struct{}
	negJanitorDone    chan struct{}
	negJanitorOnce    sync.Once

	connStateJanitorStop chan struct{}
	connStateJanitorDone chan struct{}
	connStateJanitorOnce sync.Once

	// Track last alert time to avoid spamming logs
	lastMapOverflowAlertTime sync.Map // map[string]time.Time

	wanInterface []string
	lanInterface []string

	sniffingTimeout    time.Duration
	tproxyPortProtect  bool
	soMarkFromDae      uint32
	mptcp              bool
	udpUnorderedRunner *udpUnorderedTaskRunner
	udpBoundedPool     *udpBoundedPoolManager
}

var (
	// realDomainNegativeCacheTTL controls how long failed real-domain probes are cached.
	// Keep it short to avoid stale negatives while still damping bursty probe storms.
	realDomainNegativeCacheTTL = 10 * time.Second
	// realDomainProbeTimeout bounds synchronous probe latency on connection setup path.
	// Keep it sub-second to avoid hurting first-paint responsiveness under DNS jitter.
	// Reduced from 800ms to 500ms for faster fallback under poor network conditions.
	realDomainProbeTimeout = 500 * time.Millisecond
	// dnsDialerSnapshotTTL caches dialer selection results to reduce selection overhead.
	// Set to 2s since dialer health status only updates every 30s (default CheckInterval).
	// This provides good cache hit rate without missing dialer state changes.
	dnsDialerSnapshotTTL         = 2 * time.Second
	realDomainNegJanitorInterval = 30 * time.Second

	// UDP connection state timeout constants (matching former bpf_timer values).
	// DNS connections are shorter-lived since they're typically query/response.
	udpConnStateTimeoutDNS    = 17 * time.Second
	udpConnStateTimeoutNormal = 60 * time.Second

	// DNS port in network byte order for connection state cleanup.
	// Precomputed to avoid repeated Htons() calls during janitor iterations.
	dnsPortNetworkOrder = common.Htons(53)
	// connStateJanitorInterval controls how often we scan for expired entries.
	// A shorter interval means faster cleanup but more CPU overhead.
	// 1s provides good balance between prompt cleanup and low overhead.
	connStateJanitorInterval = 1 * time.Second

	// TCP connection state timeout constants.
	// TCP connections are longer-lived but we still need to clean up closed connections.
	// Established connections: 2 minutes timeout (conservative, most connections close sooner)
	// Closing connections (FIN/RST seen): 10 seconds timeout (quick cleanup)
	tcpConnStateTimeoutEstablished = 120 * time.Second
	tcpConnStateTimeoutClosing     = 10 * time.Second

	// Test seam: injected in tests to avoid external DNS dependency.
	systemDnsForRealDomainProbe   = netutils.SystemDns
	resolveIp46ForRealDomainProbe = netutils.ResolveIp46
)

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
	return NewControlPlaneWithContext(
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
	// Clear failed QUIC DCID cache on reload/startup.
	// Network conditions may have changed, so we should allow retrying sniffing
	// for DCIDs that previously failed.
	ClearFailedQuicDcids()

	// Register the cache clear function with dialer package so health checks
	// can clear the failed DCID cache when network conditions improve.
	dialer.SetQuicDcidCacheClearFunc(ClearFailedQuicDcids)

	if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
		os.Setenv("QUIC_GO_DISABLE_GSO", "1")
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
		if _bpf, ok := _bpf.(*bpfObjects); ok {
			bpf = _bpf
		} else {
			return nil, fmt.Errorf("unexpected bpf type: %T", _bpf)
		}
	} else {
		bpf = new(bpfObjects)
		if err = fullLoadBpfObjects(log, bpf, &loadBpfOptions{
			PinPath:           pinPath,
			CollectionOptions: collectionOpts,
		}); err != nil {
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

	// Bind to links.
	// Bind to LAN
	if len(global.LanInterface) > 0 {
		if global.AutoConfigKernelParameter {
			// Enable IP forwarding for LAN interfaces
			if err := SetIpv4forward("1"); err != nil {
				// Log warning but don't fail - may be running in restricted environment (e.g., container)
				log.WithError(err).Warnln("Failed to enable IPv4 forwarding; proxy functionality may be limited")
			}
			if err := setForwarding("all", consts.IpVersionStr_6, "1"); err != nil {
				log.WithError(err).Warnln("Failed to enable IPv6 forwarding; proxy functionality may be limited")
			}
		}
		global.LanInterface = common.Deduplicate(global.LanInterface)
		for _, ifname := range global.LanInterface {
			core.bindLan(ifname, global.AutoConfigKernelParameter)
		}
	}
	// Bind to WAN
	if len(global.WanInterface) > 0 {
		if err = core.setupSkPidMonitor(); err != nil {
			log.WithError(err).Warnln("cgroup2 is not enabled; pname routing cannot be used")
		}
		if err = core.setupTCPRelayOffload(); err != nil {
			log.WithError(err).Debugln("TCP relay eBPF offload disabled")
		}
		for _, ifname := range global.WanInterface {
			if len(global.LanInterface) > 0 {
				// NOTE: Linux kernel behavior: ipv6.forwarding=1 suppresses accept_ra=1.
				// We set accept_ra=2 to enable RA reception without auto-configuring
				// default routes. This allows LAN+WAN coexistence with IPv6 SLAAC.
				// Ref: https://sysctl-explorer.net/net/ipv6/accept_ra/
				if global.AutoConfigKernelParameter {
					acceptRa := sysctl.Keyf("net.ipv6.conf.%v.accept_ra", ifname)
					val, err := acceptRa.Get()
					if err == nil && val == "1" {
						if err := acceptRa.Set("2", false); err != nil {
							log.WithError(err).Warnf("Failed to set accept_ra=2 for %v; IPv6 autoconfig may not work as expected", ifname)
						}
					}
				}
			}
			core.bindWan(ifname, global.AutoConfigKernelParameter)
		}
	}
	// Bind to dae0 and dae0peer
	if err = core.bindDaens(); err != nil {
		return nil, fmt.Errorf("bindDaens: %w", err)
	}

	/// DialerGroups (outbounds).
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	option := dialer.NewGlobalOption(global, log)

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
	direct := dialer.NewDialer(_direct, option, dialer.InstanceOption{DisableCheck: true}, directProperty)
	_block, blockProperty := dialer.NewBlockDialer(option, func() { /*Dialer Outbound*/ })
	block := dialer.NewDialer(_block, option, dialer.InstanceOption{DisableCheck: true}, blockProperty)
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
	grpc.CleanGlobalClientConnectionCache()
	meek.CleanGlobalRoundTripperCache()
	dialerSet := outbound.NewDialerSetFromLinks(option, tagToNodeList)
	deferFuncs = append(deferFuncs, dialerSet.Close)
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
			newDialers := make([]*dialer.Dialer, 0)
			for _, d := range dialers {
				newDialer := d.Clone()
				deferFuncs = append(deferFuncs, newDialer.Close)
				newDialer.GlobalOption = groupOption
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
	locationFinder := assets.NewLocationFinder(externGeoDataDirs)
	var rules []*config_parser.RoutingRule
	if rules, err = routing.ApplyRulesOptimizers(routingA.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: log, LocationFinder: locationFinder},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}
	routingA.Rules = nil // Release.
	if log.IsLevelEnabled(logrus.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range rules {
			debugBuilder.WriteString(rule.String(true, false, false) + "\n")
		}
		log.Debugf("RoutingA:\n%vfallback: %v\n", debugBuilder.String(), routingA.Fallback)
	}
	// Parse rules and build.
	log.Infoln("Building routing matcher...")
	builder, err := NewRoutingMatcherBuilder(log, rules, outboundName2Id, core.bpf, routingA.Fallback)
	if err != nil {
		return nil, fmt.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	log.Infoln("Loading routing rules into kernel space (BPF)...")
	if err = builder.BuildKernspace(log); err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildKernspace: %w", err)
	}
	log.Infoln("Building userspace routing matcher...")
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}

	// Memory optimization: Force GC after building routing matcher
	// to release temporary allocations from rule processing.
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Infof("Memory usage after routing build: Alloc=%vMiB, Sys=%vMiB, HeapObjects=%v",
		m.Alloc/1024/1024, m.Sys/1024/1024, m.HeapObjects)

	// New control plane.
	ctx, cancel := context.WithCancel(context.Background())
	plane = &ControlPlane{
		log:                  log,
		core:                 core,
		deferFuncs:           deferFuncs,
		listenIp:             "0.0.0.0",
		outbounds:            outbounds,
		dnsController:        nil,
		onceNetworkReady:     sync.Once{},
		dialMode:             dialMode,
		routingMatcher:       routingMatcher,
		ctx:                  ctx,
		cancel:               cancel,
		ready:                make(chan struct{}),
		muRealDomainSet:      sync.RWMutex{},
		realDomainSet:        bloom.NewWithEstimates(2048, 0.001),
		tcpSniffNegSet:       make(map[tcpSniffNegKey]tcpSniffNegEntry),
		negJanitorStop:       make(chan struct{}),
		negJanitorDone:       make(chan struct{}),
		connStateJanitorStop: make(chan struct{}),
		connStateJanitorDone: make(chan struct{}),
		lanInterface:         global.LanInterface,
		wanInterface:         global.WanInterface,
		sniffingTimeout:      sniffingTimeout,
		tproxyPortProtect:    global.TproxyPortProtect,
		soMarkFromDae:        global.SoMarkFromDae,
		mptcp:                global.Mptcp,
		udpUnorderedRunner:   newDefaultUdpUnorderedTaskRunner(ctx),
		udpBoundedPool:       newUdpBoundedPoolManager(ctx),
	}
	plane.startRealDomainNegJanitor()
	plane.startConnStateJanitor()

	/// DNS upstream.
	dnsUpstream, err := dns.New(dnsConfig, &dns.NewOption{
		Logger:                  log,
		LocationFinder:          locationFinder,
		UpstreamReadyCallback:   plane.dnsUpstreamReadyCallback,
		UpstreamResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae, global.Mptcp),
	})
	if err != nil {
		return nil, err
	}
	/// Dns controller.
	fixedDomainTtl, err := ParseFixedDomainTtl(dnsConfig.FixedDomainTtl)
	if err != nil {
		return nil, err
	}
	plane.dnsController, err = NewDnsController(dnsUpstream, &DnsControllerOption{
		Log: log,
		// ConcurrencyLimit: use default (16384)
		// Suitable for proxy scenarios with higher latency
		// Each concurrent query uses ~4KB, so 16384 = ~64MB memory
		ConcurrencyLimit:   0, // 0 means use default (16384)
		OptimisticCache:    dnsConfig.OptimisticCache,
		OptimisticCacheTtl: dnsConfig.OptimisticCacheTtl,
		MaxCacheSize:       dnsConfig.MaxCacheSize,
		CacheAccessCallback: func(cache *DnsCache) (err error) {
			// Write mappings into eBPF map:
			// IP record (from dns lookup) -> domain routing
			if err = core.BatchUpdateDomainRouting(cache); err != nil {
				return fmt.Errorf("BatchUpdateDomainRouting: %w", err)
			}
			return nil
		},
		CacheRemoveCallback: func(cache *DnsCache) (err error) {
			// Write mappings into eBPF map:
			// IP record (from dns lookup) -> domain routing
			if err = core.BatchRemoveDomainRouting(cache); err != nil {
				return fmt.Errorf("BatchRemoveDomainRouting: %w", err)
			}
			return nil
		},
		NewCache: func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error) {
			return &DnsCache{
				DomainBitmap:     plane.routingMatcher.domainMatcher.MatchDomainBitmap(fqdn),
				Answer:           answers,
				Deadline:         deadline,
				OriginalDeadline: originalDeadline,
			}, nil
		},
		BestDialerChooser: plane.chooseBestDnsDialer,
		TimeoutExceedCallback: func(dialArgument *dialArgument, err error) {
			if commonerrors.IsIgnorableConnectionError(err) {
				return
			}
			dialArgument.bestDialer.ReportUnavailable(&dialer.NetworkType{
				L4Proto:   dialArgument.l4proto,
				IpVersion: dialArgument.ipversion,
				IsDns:     true,
			}, err)
		},
		IpVersionPrefer: dnsConfig.IpVersionPrefer,
		FixedDomainTtl:  fixedDomainTtl,
	})
	if err != nil {
		return nil, err
	}
	plane.deferFuncs = append(plane.deferFuncs, plane.dnsController.Close)
	plane.deferFuncs = append(plane.deferFuncs, func() error {
		plane.udpBoundedPool.Close()
		return nil
	})

	// On reload, clear the BPF domain routing map to ensure DNS configuration
	// changes take effect immediately. The dnsCache parameter is preserved for
	// dae-wing compatibility but not used for cache refresh.
	// TODO: Implement selective cache refresh based on what changed in DNS config.
	if _bpf != nil {
		// Keep reload behavior aligned with main: clear domain_routing_map only.
		// Connection-state maps are intentionally preserved to avoid affecting
		// established flows during reload.
		if err = clearReloadDomainRoutingMap(core.bpf); err != nil {
			return nil, fmt.Errorf("clearReloadDomainRoutingMap: %w", err)
		}
	}

	// Restore DNS cache from last control plane if available.
	if dnsCache != nil {
		// Clear all global pools and reset log limiters on reload.
		// This prevents stale connections/endpoints from using pre-reload routing state,
		// which could cause UDP routing failures after configuration changes.
		DefaultUdpEndpointPool.Reset()
		DefaultAnyfromPool.Reset()
		DefaultUdpTaskPool.Reset()
		DefaultPacketSnifferSessionMgr.Reset()
		ResetUdpLogLimiters()

		count := 0
		now := time.Now()
		for k, v := range dnsCache {
			if v != nil {
				// Re-patch domain bitmap for new routing rules.
				v.DomainBitmap = plane.routingMatcher.domainMatcher.MatchDomainBitmap(v.GetFqdn())
				plane.dnsController.dnsCache.Store(k, v)
				// Trigger async BPF update to populate the cleared domain_routing_map.
				plane.dnsController.triggerBpfUpdateIfNeeded(v, now)
				count++
			}
		}
		if count > 0 {
			log.Infof("Restored %d DNS cache entries from previous control plane", count)
		}
	}

	// Create and start DNS listener if configured
	if dnsConfig.Bind != "" {
		plane.dnsListener, err = NewDNSListener(log, dnsConfig.Bind, plane)
		if err != nil {
			return nil, err
		}
		if err = plane.dnsListener.Start(); err != nil {
			log.Errorf("Failed to start DNS listener: %v", err)
		} else {
			log.Infof("DNS listener started on %s", dnsConfig.Bind)
			// Add DNS listener stop to defer functions
			plane.deferFuncs = append(plane.deferFuncs, plane.dnsListener.Stop)
		}
	}

	// Init immediately to avoid DNS leaking in the very beginning because param control_plane_dns_routing will
	// be set in callback.
	if err = dnsUpstream.CheckUpstreamsFormat(); err != nil {
		return nil, err
	}
	go dnsUpstream.InitUpstreams()

	close(plane.ready)
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
// Do NOT clear connection-state maps (routing_tuples_map/udp_conn_state_map)
// here, otherwise established flows may lose cached state and get rerouted.
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
		{name: "routing_tuples_map", m: bpf.RoutingTuplesMap},
		{name: "udp_conn_state_map", m: bpf.UdpConnStateMap},
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

func (c *ControlPlane) CloneDnsCache() map[string]*DnsCache {
	result := make(map[string]*DnsCache)
	c.dnsController.dnsCache.Range(func(key, value any) bool {
		k, ok1 := key.(string)
		v, ok2 := value.(*DnsCache)
		if ok1 && ok2 {
			// Deep copy to prevent data race on the returned map values
			// Use manual Clone instead of reflection-based deepcopy for performance
			result[k] = v.Clone()
		} else {
			c.log.Errorf("CloneDnsCache: invalid type found in sync.Map: key=%T, value=%T", key, value)
		}
		return true
	})
	return result
}

func (c *ControlPlane) dnsUpstreamReadyCallback(dnsUpstream *dns.Upstream) (err error) {
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
		ttl := int(deadline.Sub(time.Now()).Seconds())
		if ttl < 0 {
			ttl = 0
		}
		if err = c.dnsController.UpdateDnsCacheTtl(dnsUpstream.Hostname, typ, answers, ttl); err != nil {
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
		ttl := int(deadline.Sub(time.Now()).Seconds())
		if ttl < 0 {
			ttl = 0
		}
		if err = c.dnsController.UpdateDnsCacheTtl(dnsUpstream.Hostname, typ, answers, ttl); err != nil {
			return err
		}
	}
	return nil
}

func (c *ControlPlane) ActivateCheck() {
	for _, g := range c.outbounds {
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
			if cache := c.dnsController.LookupDnsRespCache(c.dnsController.cacheKey(domain, common.AddrToDnsType(dst.Addr())), true); cache != nil {
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

func (c *ControlPlane) isRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	// Deduplicate concurrent probes for same domain to avoid stampede under bursty connection setup.
	v, _, _ := c.realDomainProbeS.Do(domain, func() (any, error) {
		return c.probeAndUpdateRealDomain(domain), nil
	})
	isReal, _ := v.(bool)
	return isReal
}

func (c *ControlPlane) probeAndUpdateRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	now := time.Now()
	// Use ControlPlane's context for real domain probe to enable proper cancel propagation
	ctx, cancel := context.WithTimeout(c.ctx, realDomainProbeTimeout)
	defer cancel()

	systemDns, err := systemDnsForRealDomainProbe()
	if err != nil {
		// Do not negative-cache probe infra errors.
		return false
	}

	// TODO: use DNS controller and re-route by control plane.
	ip46, err4, err6 := resolveIp46ForRealDomainProbe(ctx, direct.SymmetricDirect, systemDns, domain, common.MagicNetwork("udp", c.soMarkFromDae, c.mptcp), true)
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

func (c *ControlPlane) cleanupRealDomainNegSet(now time.Time) {
	nowNano := now.UnixNano()
	c.realDomainNegSet.Range(func(key, value any) bool {
		domain, ok := key.(string)
		if !ok {
			c.realDomainNegSet.Delete(key)
			return true
		}
		expiresAt, ok := value.(int64)
		if !ok || expiresAt <= nowNano {
			c.realDomainNegSet.Delete(domain)
		}
		return true
	})
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

func (c *ControlPlane) startRealDomainNegJanitor() {
	go func() {
		ticker := time.NewTicker(realDomainNegJanitorInterval)
		defer ticker.Stop()
		defer close(c.negJanitorDone)
		for {
			select {
			case <-c.negJanitorStop:
				return
			case now := <-ticker.C:
				c.cleanupRealDomainNegSet(now)
				c.cleanupDnsDialerSnapshot(now)
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
			timer := time.NewTimer(5 * time.Second)
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
	go func() {
		ticker := time.NewTicker(connStateJanitorInterval)
		healthCheckTicker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		defer healthCheckTicker.Stop()
		defer close(c.connStateJanitorDone)
		for {
			select {
			case <-c.connStateJanitorStop:
				return
			case <-ticker.C:
				c.cleanupRedirectTrackMap()
				c.cleanupUdpConnStateMap()
				c.cleanupTcpConnStateMap()
			case <-healthCheckTicker.C:
				c.checkBpfMapHealth()
			}
		}
	}()
}

// stopConnStateJanitor signals the conn state janitor to stop and waits
// for it to exit gracefully.
func (c *ControlPlane) stopConnStateJanitor() {
	c.connStateJanitorOnce.Do(func() {
		if c.connStateJanitorStop != nil {
			close(c.connStateJanitorStop)
		}
		if c.connStateJanitorDone != nil {
			timer := time.NewTimer(5 * time.Second)
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
func (c *ControlPlane) cleanupRedirectTrackMap() {
	bpf := c.core.EjectBpf()
	if bpf == nil || bpf.RedirectTrack == nil {
		return
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupRedirectTrackMap: failed to get monotonic time: %v", err)
		return
	}
	nowNano := ts.Nano()

	timeoutNano := redirectTrackTimeout.Nanoseconds()

	var keysToDelete []bpfRedirectTuple
	totalEntries := 0
	maxAge := int64(0)
	totalAge := int64(0)

	iter := bpf.RedirectTrack.Iterate()
	var key bpfRedirectTuple
	var value bpfRedirectEntry
	for iter.Next(&key, &value) {
		totalEntries++
		age := nowNano - int64(value.LastSeenNs)
		totalAge += age
		if age > maxAge {
			maxAge = age
		}
		if age > timeoutNano {
			keysToDelete = append(keysToDelete, key)
		}
	}

	if err := iter.Err(); err != nil {
		c.log.Errorf("cleanupRedirectTrackMap: iteration error: %v", err)
		return
	}

	for _, k := range keysToDelete {
		if err := bpf.RedirectTrack.Delete(&k); err != nil {
			c.log.Debugf("cleanupRedirectTrackMap: failed to delete entry: %v", err)
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
}

// cleanupUdpConnStateMap iterates through the UDP conn state map and removes
// entries that haven't been seen within their timeout period.
// DNS entries use a shorter timeout (17s) while normal UDP uses 60s.
// When map is under pressure (high usage), timeouts are dynamically reduced
// to free up space more aggressively.
func (c *ControlPlane) cleanupUdpConnStateMap() {
	bpf := c.core.EjectBpf()
	if bpf == nil || bpf.UdpConnStateMap == nil {
		return
	}

	// Use CLOCK_MONOTONIC to match bpf_ktime_get_ns() time base.
	// bpf_ktime_get_ns() returns monotonic time since boot, not wall clock time.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupUdpConnStateMap: failed to get monotonic time: %v", err)
		return
	}
	nowNano := ts.Nano()

	// Default timeouts
	dnsTimeoutNano := udpConnStateTimeoutDNS.Nanoseconds()
	normalTimeoutNano := udpConnStateTimeoutNormal.Nanoseconds()

	// Pre-allocate slice for better performance
	keysToDelete := make([]bpfTuplesKey, 0, 256)
	estimatedCount := 0

	iter := bpf.UdpConnStateMap.Iterate()
	var key bpfTuplesKey
	var value bpfUdpConnState
	for iter.Next(&key, &value) {
		estimatedCount++
		// Check if this entry is a DNS connection (port 53).
		// Use precomputed network byte order constant for efficiency.
		isDNS := key.Sport == dnsPortNetworkOrder || key.Dport == dnsPortNetworkOrder
		timeout := normalTimeoutNano
		if isDNS {
			timeout = dnsTimeoutNano
		}

		// Check if entry has expired
		if nowNano-int64(value.LastSeenNs) > timeout {
			keysToDelete = append(keysToDelete, key)
		}
	}

	// Apply dynamic timeout adjustment based on estimated usage.
	// Check map usage percentage to determine if aggressive cleanup is needed.
	maxEntries := bpf.UdpConnStateMap.MaxEntries()
	if maxEntries > 0 {
		usagePercent := int(estimatedCount * 100 / int(maxEntries))

		// If map is getting full (>70%), do a second pass with shorter timeout.
		// We run aggressive cleanup regardless of whether first pass found expired entries,
		// because we want to free up space when the map is under pressure.
		if usagePercent > 70 {
			// Use halved timeout for aggressive cleanup
			aggressiveTimeout := normalTimeoutNano / 2
			aggressiveDnsTimeout := dnsTimeoutNano / 2

			iter2 := bpf.UdpConnStateMap.Iterate()
			var key2 bpfTuplesKey
			var value2 bpfUdpConnState
			initialCount := len(keysToDelete)
			for iter2.Next(&key2, &value2) {
				isDNS := key2.Sport == dnsPortNetworkOrder || key2.Dport == dnsPortNetworkOrder
				timeout := aggressiveTimeout
				if isDNS {
					timeout = aggressiveDnsTimeout
				}

				age := nowNano - int64(value2.LastSeenNs)
				if age > timeout {
					keysToDelete = append(keysToDelete, key2)
				}
			}
			if err := iter2.Err(); err != nil {
				c.log.Errorf("cleanupUdpConnStateMap: aggressive cleanup iteration error: %v", err)
			}
			additionalCount := len(keysToDelete) - initialCount
			if additionalCount > 0 {
				c.log.Debugf("cleanupUdpConnStateMap: aggressive cleanup removed %d additional entries (map was %d%% full)",
					additionalCount, usagePercent)
			}
		}
	}

	if err := iter.Err(); err != nil {
		c.log.Errorf("cleanupUdpConnStateMap: iteration error: %v", err)
	}

	// Batch delete expired entries from both udp_conn_state_map and routing_tuples_map.
	// This implements cascade cleanup: when a UDP connection expires, we also remove
	// its routing cache entry. This keeps routing_tuples_map clean without needing
	// its own timestamp-based cleanup.
	for _, k := range keysToDelete {
		// Delete from UDP conn state map
		if err := bpf.UdpConnStateMap.Delete(&k); err != nil {
			// Entry might have been deleted concurrently, log and continue
			c.log.Debugf("cleanupUdpConnStateMap: failed to delete entry: %v", err)
		}
		// Cascade delete: also remove routing cache for this flow
		// This handles both forward (key.five) and reverse (from conn state) directions
		if err := bpf.RoutingTuplesMap.Delete(&k); err != nil {
			// Routing cache might not exist or already deleted, ignore
		}
		// Also delete the reverse direction routing entry
		var reverseKey bpfTuplesKey
		reverseKey.Sip = k.Dip
		reverseKey.Dip = k.Sip
		reverseKey.Sport = k.Dport
		reverseKey.Dport = k.Sport
		reverseKey.L4proto = k.L4proto
		if err := bpf.RoutingTuplesMap.Delete(&reverseKey); err != nil {
			// Ignore if not found
		}
	}

	// Log cleanup stats if significant
	if len(keysToDelete) > 0 {
		c.log.Debugf("cleanupUdpConnStateMap: removed %d expired entries", len(keysToDelete))
	}
}

// cleanupTcpConnStateMap iterates through the TCP conn state map and removes
// entries that haven't been seen within their timeout period or are in CLOSING state.
// This implements cascade cleanup: when a TCP connection expires or closes,
// we also remove its routing cache entries from routing_tuples_map.
func (c *ControlPlane) cleanupTcpConnStateMap() {
	bpf := c.core.EjectBpf()
	if bpf == nil || bpf.TcpConnStateMap == nil {
		return
	}

	// Use CLOCK_MONOTONIC to match bpf_ktime_get_ns() time base.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		c.log.Errorf("cleanupTcpConnStateMap: failed to get monotonic time: %v", err)
		return
	}
	nowNano := ts.Nano()

	establishedTimeoutNano := tcpConnStateTimeoutEstablished.Nanoseconds()
	closingTimeoutNano := tcpConnStateTimeoutClosing.Nanoseconds()

	// We'll collect keys to delete and batch delete them
	var keysToDelete []bpfTuplesKey
	var routingKeysToDelete []bpfTuplesKey
	estimatedCount := 0

	iter := bpf.TcpConnStateMap.Iterate()
	var key bpfTuplesKey
	var value bpfTcpConnState
	for iter.Next(&key, &value) {
		estimatedCount++

		// Check if entry should be cleaned up
		shouldDelete := false
		if value.State == 1 { // TCP_STATE_CLOSING
			// CLOSING state: quick cleanup (FIN/RST seen)
			age := nowNano - int64(value.LastSeenNs)
			if age > closingTimeoutNano {
				shouldDelete = true
			}
		} else {
			// ACTIVE state: normal timeout for established connections
			age := nowNano - int64(value.LastSeenNs)
			if age > establishedTimeoutNano {
				shouldDelete = true
			}
		}

		if shouldDelete {
			keysToDelete = append(keysToDelete, key)
			// Also collect routing keys for cascade deletion
			routingKeysToDelete = append(routingKeysToDelete, key)
		}
	}

	// Batch delete expired TCP conn state entries
	for _, k := range keysToDelete {
		if err := bpf.TcpConnStateMap.Delete(&k); err != nil {
			// Entry might have been deleted concurrently, log and continue
			c.log.Debugf("cleanupTcpConnStateMap: failed to delete entry: %v", err)
		}
	}

	// Cascade delete: remove routing cache entries for expired TCP connections
	// We delete both forward and reverse routing entries
	for _, k := range routingKeysToDelete {
		if err := bpf.RoutingTuplesMap.Delete(&k); err != nil {
			// Routing cache might not exist or already deleted, ignore
		}
		// Also delete the reverse direction routing entry
		var reverseKey bpfTuplesKey
		reverseKey.Sip = k.Dip
		reverseKey.Dip = k.Sip
		reverseKey.Sport = k.Dport
		reverseKey.Dport = k.Sport
		reverseKey.L4proto = k.L4proto
		if err := bpf.RoutingTuplesMap.Delete(&reverseKey); err != nil {
			// Ignore if not found
		}
	}

	// Log cleanup stats if significant
	if len(keysToDelete) > 0 {
		c.log.Debugf("cleanupTcpConnStateMap: removed %d expired TCP entries", len(keysToDelete))
	}
}

// checkBpfMapHealth monitors map usage and overflow counters for robustness.
// Alerts when maps are approaching capacity or experiencing high overflow rates.
func (c *ControlPlane) checkBpfMapHealth() {
	bpf := c.core.EjectBpf()
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
		udpOverflow     uint64
		routingOverflow uint64
		udpUpdates      uint64
		udpLookupHits   uint64
	)

	// Read stats (key 0 = UDP overflow, key 1 = routing overflow, etc.)
	if v, err := readBpfStatsCounter(bpf.BpfStatsMap, 0); err == nil {
		udpOverflow = v
	}
	if v, err := readBpfStatsCounter(bpf.BpfStatsMap, 1); err == nil {
		routingOverflow = v
	}
	if v, err := readBpfStatsCounter(bpf.BpfStatsMap, 2); err == nil {
		udpUpdates = v
	}
	if v, err := readBpfStatsCounter(bpf.BpfStatsMap, 3); err == nil {
		udpLookupHits = v
	}

	// Alert on significant overflow counts
	if udpOverflow > 0 || routingOverflow > 0 {
		// Use a fixed key to avoid unbounded growth in lastMapOverflowAlertTime.
		// The cooldown period prevents alert spam.
		const alertKeyBpfOverflow = "bpf_overflow"
		lastAlertTime, _ := c.lastMapOverflowAlertTime.LoadOrStore(alertKeyBpfOverflow, time.Time{})

		// Type assertion is safe here since we only ever store time.Time values.
		lastTime, ok := lastAlertTime.(time.Time)
		if !ok || lastTime.Add(alertCooldown).Before(now) {
			c.log.Warnf("BPF map overflow detected: UDP conn state=%d, routing cache=%d. "+
				"Some packets are falling back to slower paths. Check if map capacity is adequate.",
				udpOverflow, routingOverflow)

			// Calculate hit rate if we have data
			totalLookups := udpLookupHits + udpUpdates
			if totalLookups > 0 {
				hitRate := float64(udpLookupHits) / float64(totalLookups) * 100
				c.log.Debugf("UDP conn track hit rate: %.1f%% (%d hits / %d total)",
					hitRate, udpLookupHits, totalLookups)
			}

			c.lastMapOverflowAlertTime.Store(alertKeyBpfOverflow, now)
		}
	}

	// Estimate map usage by sampling (full iteration is expensive)
	// We use the count from the last cleanup cycle as an estimate
	if bpf.UdpConnStateMap != nil {
		maxEntries := bpf.UdpConnStateMap.MaxEntries()
		// Since we don't have a cheap way to get exact count without iterating,
		// we rely on the overflow counters as the primary health indicator.
		// If overflow is happening, map is under pressure.
		if udpOverflow > 100 && maxEntries > 0 {
			alertKey := "udp_conn_state_map_pressure"
			lastAlertTime, _ := c.lastMapOverflowAlertTime.LoadOrStore(alertKey, time.Time{})

			if lastAlertTime.(time.Time).Add(alertCooldown).Before(now) {
				c.log.Errorf("CRITICAL: UDP conn state map is under heavy pressure (overflow=%d). "+
					"Consider increasing MAX_DST_MAPPING_NUM or reducing connection timeout.",
					udpOverflow)
				c.lastMapOverflowAlertTime.Store(alertKey, now)
			}
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

// cleanupBpfStatsMap resets overflow counters periodically to avoid overflow.
// This should be called much less frequently than checkBpfMapHealth.
func (c *ControlPlane) cleanupBpfStatsMap() {
	bpf := c.core.EjectBpf()
	if bpf == nil || bpf.BpfStatsMap == nil {
		return
	}

	// Reset overflow counters to zero
	resetKeys := []uint32{0, 1} // UDP overflow, routing overflow
	zero := uint64(0)

	for _, key := range resetKeys {
		if err := bpf.BpfStatsMap.Put(&key, &zero); err != nil {
			c.log.Debugf("cleanupBpfStatsMap: failed to reset key %d: %v", key, err)
		}
	}
}

type Listener struct {
	tcpListener net.Listener
	packetConn  net.PacketConn
	port        uint16
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
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return false
	}
	return common.ConvergeAddrPort(addr.AddrPort()).Addr().Is4()
}

func (l *Listener) Close() error {
	var (
		err  error
		err2 error
	)
	if err, err2 = l.tcpListener.Close(), l.packetConn.Close(); err2 != nil {
		if err == nil {
			err = err2
		} else {
			err = fmt.Errorf("%w: %v", err, err2)
		}
	}
	return err
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
	/// Serve.
	// TCP socket.
	tcpFile, err := listener.tcpListener.(*net.TCPListener).File()
	if err != nil {
		return fmt.Errorf("failed to retrieve copy of the underlying TCP connection file")
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		return tcpFile.Close()
	})
	if err := c.core.bpf.ListenSocketMap.Update(consts.ZeroKey, uint64(tcpFile.Fd()), ebpf.UpdateAny); err != nil {
		return err
	}
	// UDP socket.
	udpFile, err := udpConn.File()
	if err != nil {
		return fmt.Errorf("failed to retrieve copy of the underlying UDP connection file")
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		return udpFile.Close()
	})
	if err := c.core.bpf.ListenSocketMap.Update(consts.OneKey, uint64(udpFile.Fd()), ebpf.UpdateAny); err != nil {
		return err
	}

	sentReady = true
	select {
	case readyChan <- true:
	default:
	}
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			lconn, err := listener.tcpListener.Accept()
			if err != nil {
				if !commonerrors.IsClosedConnection(err) && !stderrors.Is(err, context.Canceled) {
					c.log.Errorf("Error when accept: %v", err)
				}
				break
			}
			go func(lconn net.Conn) {
				c.inConnections.Store(lconn, struct{}{})
				defer c.inConnections.Delete(lconn)
				// Keep the ControlPlane lifecycle context so shutdown/reload can cancel
				// in-flight connection handling. Dial timeout is applied independently
				// inside RouteDialTcp and is not reduced by sniffing time.
				if err := c.handleConn(c.ctx, lconn); err != nil {
					c.log.Warnln("handleConn:", err)
				}
			}(lconn)
		}
	}()
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

						if e := c.dnsController.Handle_(c.ctx, dnsMessage, req); e != nil {
							if stderrors.Is(e, ErrDNSQueryConcurrencyLimitExceeded) {
								return
							}
							if sendErr := c.dnsController.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeServerFailure, "ServeFail (dns ingress fast path)", req, nil); sendErr != nil {
								c.log.WithError(stderrors.Join(e, sendErr)).Warnln("handlePkt(dns ingress):")
								return
							}
							if c.log.IsLevelEnabled(logrus.DebugLevel) {
								c.log.WithError(e).Debug("DNS ingress fast path failed; SERVFAIL sent")
							}
						}
						return
					}
				}

				if ue, ok := DefaultUdpEndpointPool.Get(flowDecision.CachedRoutingEndpointKey()); ok {
					if cached, cacheHit := ue.GetCachedRoutingResult(realDst, unix.IPPROTO_UDP); cacheHit {
						routingResult = cached
					}
				}

				if routingResult == nil {
					rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP)
					if retrieveErr != nil {
						if stderrors.Is(retrieveErr, ebpf.ErrKeyNotExist) {
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
						} else if realDst.Port() == 53 {
							// DNS should never be silently dropped due to transient eBPF lookup
							// failures. Fall back to userspace routing to preserve availability.
							routingResult = &bpfRoutingResult{
								Outbound: uint8(consts.OutboundControlPlaneRouting),
							}
							c.log.WithFields(logrus.Fields{
								"src": convergeSrc.String(),
								"dst": realDst.String(),
							}).WithError(retrieveErr).Warn("UDP routing tuple lookup failed for DNS; fallback to userspace routing")
						} else {
							c.log.Warnf("No AddrPort presented: %v", retrieveErr)
							return
						}
					} else {
						routingResult = rr
						rrCopy := *routingResult
						freshRoutingResult = &rrCopy
					}
				}

				if e := c.handlePkt(udpConn, data, convergeSrc, realDst, realDst, routingResult, flowDecision, false); e != nil {
					c.log.Warnln("handlePkt:", e)
					return
				}

				if freshRoutingResult != nil {
					if ue, ok := DefaultUdpEndpointPool.Get(flowDecision.CachedRoutingEndpointKey()); ok {
						ue.UpdateCachedRoutingResult(realDst, unix.IPPROTO_UDP, freshRoutingResult)
					}
				}
			}

			// Keep ordered ingress scoped to QUIC Initial flows and flows with an
			// active sniff session so multi-packet ClientHello reassembly stays
			// deterministic; other UDP traffic stays on the direct path.
			//
			// Layered dispatch strategy for optimal throughput, latency, and reliability:
			// 1. Ordered Ingress: For QUIC Initial and sniffing sessions (preserves order)
			// 2. Direct Goroutine: For DNS/VoIP (lowest latency, zero drops)
			// 3. Bounded Pool: For WireGuard/VPN (backpressure without drops)
			// 4. Task Runner: Fallback for other traffic (may drop under load)
			switch flowDecision.DispatchStrategy() {
			case StrategyOrderedIngress:
				DefaultUdpTaskPool.EmitTask(flowDecision.Key, task)
			case StrategyDirectGoroutine:
				// DNS, VoIP, and other drop-sensitive traffic use direct goroutine spawn.
				// This provides the lowest latency and guarantees no drops.
				go task()
			case StrategyBoundedPool:
				// WireGuard, VPN, and long-lived UDP connections use bounded pool.
				// This provides concurrency control with backpressure (no drops).
				if !c.udpBoundedPool.Submit(task) {
					// Pool closed (shutdown), fall back to direct goroutine
					go task()
				}
			default:
				// For any other traffic, use task runner (may drop under load)
				if !c.udpUnorderedRunner.Submit(flowDecision.Key, task) {
					pktBuf.Put()
				}
			}
			// if d := time.Since(t); d > 100*time.Millisecond {
			// 	logrus.Println(d)
			// }
		}

		if udpIngressSupportsBatch(udpConn) {
			batchReader := newUdpIngressBatchReader(udpConn, 0)
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
				for i := 0; i < n; i++ {
					pktBuf, src, oob, ok := batchReader.Take(i)
					if !ok {
						continue
					}
					processPacket(pktBuf, src, oob)
				}
			}
			return
		}

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
	return nil
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
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
	tcpListenAddr := net.JoinHostPort(c.listenIp, strconv.Itoa(int(port)))
	tcpListener, err := tcpListenConfig.Listen(context.Background(), "tcp", tcpListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listenTCP: %w", err)
	}
	packetConn, err := udpListenConfig.ListenPacket(context.Background(), "udp6", udpDualStackListenAddr(port))
	if err != nil {
		if c.log != nil {
			c.log.WithError(err).Warn("Failed to open dual-stack UDP listener; fallback to IPv4-only UDP listener")
		}
		packetConn, err = tcpListenConfig.ListenPacket(context.Background(), "udp", tcpListenAddr)
		if err != nil {
			_ = tcpListener.Close()
			return nil, fmt.Errorf("listenUDP: %w", err)
		}
	}
	listener = &Listener{
		tcpListener: tcpListener,
		packetConn:  packetConn,
		port:        port,
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()

	// Serve
	if err = c.Serve(readyChan, listener); err != nil {
		return nil, fmt.Errorf("failed to serve: %w", err)
	}

	return listener, nil
}

func (c *ControlPlane) chooseBestDnsDialer(
	req *udpRequest,
	dnsUpstream *dns.Upstream,
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
		bestLatency  time.Duration
		l4proto      consts.L4ProtoStr
		ipversion    consts.IpVersionStr
		bestDialer   *dialer.Dialer
		bestOutbound *outbound.DialerGroup
		bestTarget   netip.AddrPort
		dialMark     uint32
	)
	// Get the min latency path.
	networkType := dialer.NetworkType{
		IsDns: true,
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
			//if c.log.IsLevelEnabled(logrus.TraceLevel) {
			//	c.log.WithFields(logrus.Fields{
			//		"name":     d.Name(),
			//		"latency":  latency,
			//		"network":  networkType.String(),
			//		"outbound": dialerGroup.Name,
			//	}).Traceln("Choice")
			//}
			if bestDialer == nil || latency < bestLatency {
				bestDialer = d
				bestOutbound = dialerGroup
				bestLatency = latency
				l4proto = proto
				ipversion = ver
				dialMark = mark

				if bestLatency == 0 {
					break
				}
			}
		}
	}
	if bestDialer == nil {
		return nil, fmt.Errorf("no proper dialer for DNS upstream: %v", dnsUpstream.String())
	}
	switch ipversion {
	case consts.IpVersionStr_4:
		bestTarget = netip.AddrPortFrom(dnsUpstream.Ip4, dnsUpstream.Port)
	case consts.IpVersionStr_6:
		bestTarget = netip.AddrPortFrom(dnsUpstream.Ip6, dnsUpstream.Port)
	}
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
			"upstream":   dnsUpstream.String(),
			"choose":     string(l4proto) + "+" + string(ipversion),
			"use":        bestTarget.String(),
			"outbound":   bestOutbound.Name,
			"dialer":     bestDialer.Property().Name,
		}).Traceln("Choose DNS path")
	}
	selected := &dialArgument{
		l4proto:      l4proto,
		ipversion:    ipversion,
		bestDialer:   bestDialer,
		bestOutbound: bestOutbound,
		bestTarget:   bestTarget,
		mark:         dialMark,
		mptcp:        c.mptcp,
	}
	if snapshotEnabled {
		c.storeDnsDialerSnapshot(snapshotKey, selected, now)
	}
	return selected, nil
}

func (c *ControlPlane) AbortConnections() (err error) {
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
		return true
	})
	return stderrors.Join(errs...)
}

// DetachBpfHooks immediately detaches all BPF hooks from the system.
// This should be called first when receiving SIGTERM to ensure network is restored
// even if the rest of the shutdown process takes too long and gets SIGKILL'd.
// This is safe to call multiple times - subsequent calls will be no-ops.
func (c *ControlPlane) DetachBpfHooks() error {
	return c.core.DetachBpfHooks()
}

func (c *ControlPlane) Close() (err error) {
	c.stopRealDomainNegJanitor()
	c.stopConnStateJanitor()

	// Collect errors from defer funcs using errors.Join (Go 1.26 best practice)
	var errs []error
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			errs = append(errs, e)
		}
	}
	c.cancel()

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
	c.clearAllTcpSniffNegative()
	// Note: inConnections is cleared by AbortConnections() which should be called before Close()

	// Combine defer errors with core.Close error
	if coreErr := c.core.Close(); coreErr != nil {
		errs = append(errs, coreErr)
	}
	return stderrors.Join(errs...)
}

// StopDNSListener stops the DNS listener if it's running
func (c *ControlPlane) StopDNSListener() error {
	if c.dnsListener != nil {
		return c.dnsListener.Stop()
	}
	return nil
}
