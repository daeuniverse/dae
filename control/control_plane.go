/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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
	realDomainProbeS  singleflight.Group
	negJanitorStop    chan struct{}
	negJanitorDone    chan struct{}
	negJanitorOnce    sync.Once

	wanInterface []string
	lanInterface []string

	sniffingTimeout   time.Duration
	tproxyPortProtect bool
	soMarkFromDae     uint32
	mptcp             bool
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
	_bpf interface{},
	dnsCache map[string]*DnsCache,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
	externGeoDataDirs []string,
) (*ControlPlane, error) {
	// TODO: Some users reported that enabling GSO on the client would affect the performance of watching YouTube, so we disabled it by default.
	if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
		os.Setenv("QUIC_GO_DISABLE_GSO", "1")
	}

	var err error

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
		LogSize:     ebpf.DefaultVerifierLogSize * 10,
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
			PinPath:             pinPath,
			BigEndianTproxyPort: uint32(common.Htons(global.TproxyPort)),
			CollectionOptions:   collectionOpts,
		}); err != nil {
			if log.Level == logrus.PanicLevel {
				log.Panicln(err)
			}
			return nil, fmt.Errorf("load eBPF objects: %w", err)
		}
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
			// Flip back.
			core.Flip()
			_ = core.Close()
		}
	}()

	/// Bind to links. Binding should be advance of dialerGroups to avoid un-routable old connection.
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
		for _, ifname := range global.WanInterface {
			if len(global.LanInterface) > 0 {
				// FIXME: Code is not elegant here.
				// bindLan setting conf.ipv6.all.forwarding=1 suppresses accept_ra=1,
				// thus we set it 2 as a workaround.
				// See https://sysctl-explorer.net/net/ipv6/accept_ra/ for more information.
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
	// FIXME: Ugly code here: reset grpc and meek clients manually.
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
		log.Infof(`Group "%v" node list:`, group.Name)
		for _, d := range dialers {
			log.Infoln("\t" + d.Property().Name)
		}
		if len(dialers) == 0 {
			log.Infoln("\t<Empty>")
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
	builder, err := NewRoutingMatcherBuilder(log, rules, outboundName2Id, core.bpf, routingA.Fallback)
	if err != nil {
		return nil, fmt.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	if err = builder.BuildKernspace(log); err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildKernspace: %w", err)
	}
	routingMatcher, err := builder.BuildUserspace()
	if err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildUserspace: %w", err)
	}

	// New control plane.
	ctx, cancel := context.WithCancel(context.Background())
	plane := &ControlPlane{
		log:               log,
		core:              core,
		deferFuncs:        deferFuncs,
		listenIp:          "0.0.0.0",
		outbounds:         outbounds,
		dnsController:     nil,
		onceNetworkReady:  sync.Once{},
		dialMode:          dialMode,
		routingMatcher:    routingMatcher,
		ctx:               ctx,
		cancel:            cancel,
		ready:             make(chan struct{}),
		muRealDomainSet:   sync.RWMutex{},
		realDomainSet:     bloom.NewWithEstimates(2048, 0.001),
		negJanitorStop:    make(chan struct{}),
		negJanitorDone:    make(chan struct{}),
		lanInterface:      global.LanInterface,
		wanInterface:      global.WanInterface,
		sniffingTimeout:   sniffingTimeout,
		tproxyPortProtect: global.TproxyPortProtect,
		soMarkFromDae:     global.SoMarkFromDae,
		mptcp:             global.Mptcp,
	}
	plane.startRealDomainNegJanitor()
	defer func() {
		if err != nil {
			cancel()
		}
	}()

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
	if plane.dnsController, err = NewDnsController(dnsUpstream, &DnsControllerOption{
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
				return fmt.Errorf("BatchUpdateDomainRouting: %w", err)
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
			dialArgument.bestDialer.ReportUnavailable(&dialer.NetworkType{
				L4Proto:   dialArgument.l4proto,
				IpVersion: dialArgument.ipversion,
				IsDns:     true,
			}, err)
		},
		IpVersionPrefer: dnsConfig.IpVersionPrefer,
		FixedDomainTtl:  fixedDomainTtl,
	}); err != nil {
		return nil, err
	}
	plane.deferFuncs = append(plane.deferFuncs, plane.dnsController.Close)

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
	// Refresh domain routing cache with new routing.
	// FIXME: We temperarily disable it because we want to make change of DNS section take effects immediately.
	// TODO: Add change detection.
	if false && len(dnsCache) > 0 {
		for cacheKey, cache := range dnsCache {
			// Also refresh out-dated routing because kernel map items have no expiration.
			lastDot := strings.LastIndex(cacheKey, ".")
			if lastDot == -1 || lastDot == len(cacheKey)-1 {
				// Not a valid key.
				log.Warnln("Invalid cache key:", cacheKey)
				continue
			}
			host := cacheKey[:lastDot]
			_typ := cacheKey[lastDot+1:]
			typ, err := strconv.ParseUint(_typ, 10, 16)
			if err != nil {
				// Unexpected.
				return nil, err
			}
			_ = plane.dnsController.UpdateDnsCacheDeadline(host, uint16(typ), cache.Answer, cache.Deadline)
		}
	} else if _bpf != nil {
		// Is reloading, and dnsCache == nil.
		// Remove all map items.
		// Normally, it is due to the change of ip version preference.
		var key [4]uint32
		var val bpfDomainRouting
		iter := core.bpf.DomainRoutingMap.Iterate()
		for iter.Next(&key, &val) {
			_ = core.bpf.DomainRoutingMap.Delete(&key)
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

// EjectBpf will resect bpf from destroying life-cycle of control plane.
func (c *ControlPlane) EjectBpf() *bpfObjects {
	return c.core.EjectBpf()
}

func (c *ControlPlane) InjectBpf(bpf *bpfObjects) {
	c.core.InjectBpf(bpf)
}

func (c *ControlPlane) CloneDnsCache() map[string]*DnsCache {
	result := make(map[string]*DnsCache)
	c.dnsController.dnsCache.Range(func(key, value interface{}) bool {
		k, ok1 := key.(string)
		v, ok2 := value.(*DnsCache)
		if ok1 && ok2 {
			// Deep copy to prevent data race on the returned map values
			// Use manual Clone instead of reflection-based deepcopy for performance
			result[k] = v.Clone()
		} else {
			logrus.Errorf("CloneDnsCache: invalid type found in sync.Map: key=%T, value=%T", key, value)
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
		if err = c.dnsController.UpdateDnsCacheDeadline(dnsUpstream.Hostname, typ, answers, deadline); err != nil {
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
		if err = c.dnsController.UpdateDnsCacheDeadline(dnsUpstream.Hostname, typ, answers, deadline); err != nil {
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
						// Should use this domain to reroute
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
		c.log.WithFields(logrus.Fields{
			"from": dst.String(),
			"to":   dialTarget,
		}).Debugln("Rewrite dial target to domain")
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
		_, _, _ = c.realDomainProbeS.Do(domain, func() (interface{}, error) {
			return c.probeAndUpdateRealDomain(domain), nil
		})
	}()
}

func (c *ControlPlane) isRealDomain(domain string) bool {
	if known, real := c.lookupRealDomainCache(domain); known {
		return real
	}

	// Deduplicate concurrent probes for same domain to avoid stampede under bursty connection setup.
	v, _, _ := c.realDomainProbeS.Do(domain, func() (interface{}, error) {
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

	key := dnsDialerSnapshotKey{
		realSrc:     req.realSrc,
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
			<-c.negJanitorDone
		}
	})
}

type Listener struct {
	tcpListener net.Listener
	packetConn  net.PacketConn
	port        uint16
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
			readyChan <- false
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
	readyChan <- true
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			lconn, err := listener.tcpListener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					c.log.Errorf("Error when accept: %v", err)
				}
				break
			}
			go func(lconn net.Conn) {
				c.inConnections.Store(lconn, struct{}{})
				defer c.inConnections.Delete(lconn)
				// Create a new context for each connection that is independent
				// of the ControlPlane's lifecycle. This ensures each connection
				// has its own timeout and won't be canceled when the plane shuts down.
				// The connection will be closed when the listener is closed.
				ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
				defer cancel()
				if err := c.handleConn(ctx, lconn); err != nil {
					c.log.Warnln("handleConn:", err)
				}
			}(lconn)
		}
	}()
	go func() {
		buf := pool.GetFullCap(consts.EthernetMtu)
		var oob [120]byte // Size for original dest
		defer buf.Put()
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			n, oobn, _, src, err := udpConn.ReadMsgUDPAddrPort(buf, oob[:])
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					c.log.Errorf("ReadFromUDPAddrPort: %v, %v", src.String(), err)
				}
				break
			}
			pktDst := RetrieveOriginalDest(oob[:oobn])
			realDst := common.ConvergeAddrPort(pktDst)
			newBuf := pool.Get(n)
			copy(newBuf, buf[:n])
			convergeSrc := common.ConvergeAddrPort(src)
			// Debug:
			// t := time.Now()
			task := func() {
				data := newBuf

				defer data.Put()
				var routingResult *bpfRoutingResult
				var freshRoutingResult *bpfRoutingResult

				if ue, ok := DefaultUdpEndpointPool.Get(convergeSrc); ok {
					if cached, cacheHit := ue.GetCachedRoutingResult(realDst, unix.IPPROTO_UDP); cacheHit {
						routingResult = cached
					}
				}

				if routingResult == nil {
					rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP)
					if retrieveErr != nil {
						if errors.Is(retrieveErr, ebpf.ErrKeyNotExist) {
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

				if e := c.handlePkt(udpConn, data, convergeSrc, realDst, realDst, routingResult, false); e != nil {
					c.log.Warnln("handlePkt:", e)
					return
				}

				if freshRoutingResult != nil {
					if ue, ok := DefaultUdpEndpointPool.Get(convergeSrc); ok {
						ue.UpdateCachedRoutingResult(realDst, unix.IPPROTO_UDP, freshRoutingResult)
					}
				}
			}

			DefaultUdpTaskPool.EmitTask(convergeSrc, task)
			// if d := time.Since(t); d > 100*time.Millisecond {
			// 	logrus.Println(d)
			// }
		}
	}()
	c.ActivateCheck()
	<-c.ctx.Done()
	return nil
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	// Listen.
	listenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	listenAddr := net.JoinHostPort(c.listenIp, strconv.Itoa(int(port)))
	tcpListener, err := listenConfig.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listenTCP: %w", err)
	}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", listenAddr)
	if err != nil {
		_ = tcpListener.Close()
		return nil, fmt.Errorf("listenUDP: %w", err)
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
	return errors.Join(errs...)
}

func (c *ControlPlane) Close() (err error) {
	c.stopRealDomainNegJanitor()

	// Invoke defer funcs in reverse order.
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			// Combine errors.
			if err != nil {
				err = fmt.Errorf("%w; %v", err, e)
			} else {
				err = e
			}
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
	// Note: inConnections is cleared by AbortConnections() which should be called before Close()

	return c.core.Close()
}

// StopDNSListener stops the DNS listener if it's running
func (c *ControlPlane) StopDNSListener() error {
	if c.dnsListener != nil {
		return c.dnsListener.Stop()
	}
	return nil
}
