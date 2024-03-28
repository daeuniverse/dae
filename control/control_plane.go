/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
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
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/softwind/pool"
	"github.com/daeuniverse/softwind/protocol/direct"
	"github.com/daeuniverse/softwind/transport/grpc"
	"github.com/daeuniverse/softwind/transport/meek"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type ControlPlane struct {
	log *logrus.Logger

	core       *controlPlaneCore
	deferFuncs []func() error
	listenIp   string

	// TODO: add mutex?
	outbounds     []*outbound.DialerGroup
	inConnections sync.Map

	dnsController    *DnsController
	onceNetworkReady sync.Once

	dialMode consts.DialMode

	routingMatcher *RoutingMatcher

	ctx    context.Context
	cancel context.CancelFunc
	ready  chan struct{}

	muRealDomainSet sync.Mutex
	realDomainSet   *bloom.BloomFilter

	wanInterface []string
	lanInterface []string

	sniffingTimeout   time.Duration
	tproxyPortProtect bool
	soMarkFromDae     uint32
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
	if requirement := consts.ChecksumFeatureVersion; kernelVersion.Less(requirement) {
		return nil, fmt.Errorf("your kernel version %v does not support checksum related features; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			requirement.String())
	}
	if requirement := consts.SockmapFeatureVersion; len(global.WanInterface) > 0 && kernelVersion.Less(requirement) {
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
	//var bpf bpfObjects
	var ProgramOptions = ebpf.ProgramOptions{
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
			_ = SetIpv4forward("1")
		}
		global.LanInterface = common.Deduplicate(global.LanInterface)
		for _, ifname := range global.LanInterface {
			if err = core.bindLan(ifname, global.AutoConfigKernelParameter); err != nil {
				return nil, fmt.Errorf("bindLan: %v: %w", ifname, err)
			}
		}
	}
	// Bind to WAN
	if len(global.WanInterface) > 0 {
		if err = core.setupSkPidMonitor(); err != nil {
			log.WithError(err).Warnln("cgroup2 is not enabled; pname routing cannot be used")
		}
		if err = core.setupLocalTcpFastRedirect(); err != nil {
			log.WithError(err).Warnln("failed to setup local tcp fast redirect")
		}
		for _, ifname := range global.WanInterface {
			if err = core.bindWan(ifname, global.AutoConfigKernelParameter); err != nil {
				return nil, fmt.Errorf("bindWan: %v: %w", ifname, err)
			}
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
	option := &dialer.GlobalOption{
		ExtraOption: D.ExtraOption{
			AllowInsecure:     global.AllowInsecure,
			TlsImplementation: global.TlsImplementation,
			UtlsImitate:       global.UtlsImitate},
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: global.TcpCheckUrl, Log: log, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae), Method: global.TcpCheckHttpMethod},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: global.UdpCheckDns, ResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae), Somark: global.SoMarkFromDae},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
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
		// Create dialer group and append it to outbounds.
		dialerGroup := outbound.NewDialerGroup(option, group.Name, dialers, annos, *policy,
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
		muRealDomainSet:   sync.Mutex{},
		realDomainSet:     bloom.NewWithEstimates(2048, 0.001),
		lanInterface:      global.LanInterface,
		wanInterface:      global.WanInterface,
		sniffingTimeout:   sniffingTimeout,
		tproxyPortProtect: global.TproxyPortProtect,
		soMarkFromDae:     global.SoMarkFromDae,
	}
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
		UpstreamResolverNetwork: common.MagicNetwork("udp", global.SoMarkFromDae),
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
		IpVersionPrefer:   dnsConfig.IpVersionPrefer,
		FixedDomainTtl:    fixedDomainTtl,
	}); err != nil {
		return nil, err
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

// EjectBpf will resect bpf from destroying life-cycle of control plane.
func (c *ControlPlane) EjectBpf() *bpfObjects {
	return c.core.EjectBpf()
}
func (c *ControlPlane) InjectBpf(bpf *bpfObjects) {
	c.core.InjectBpf(bpf)
}

func (c *ControlPlane) CloneDnsCache() map[string]*DnsCache {
	c.dnsController.dnsCacheMu.Lock()
	defer c.dnsController.dnsCacheMu.Unlock()
	return deepcopy.Copy(c.dnsController.dnsCache).(map[string]*DnsCache)
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
			if cache := c.dnsController.LookupDnsRespCache(c.dnsController.cacheKey(domain, common.AddrToDnsType(dst.Addr())), true); cache != nil {
				// Has A/AAAA records. It is a real domain.
				dialMode = consts.DialMode_Domain
			} else {
				// Check if the domain is in real-domain set (bloom filter).
				c.muRealDomainSet.Lock()
				if c.realDomainSet.TestString(domain) {
					c.muRealDomainSet.Unlock()
					dialMode = consts.DialMode_Domain

					// Should use this domain to reroute
					shouldReroute = true
				} else {
					c.muRealDomainSet.Unlock()
					// Lookup A/AAAA to make sure it is a real domain.
					ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
					defer cancel()
					// TODO: use DNS controller and re-route by control plane.
					systemDns, err := netutils.SystemDns()
					if err == nil {
						if ip46, err := netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, domain, common.MagicNetwork("udp", c.soMarkFromDae), true); err == nil && (ip46.Ip4.IsValid() || ip46.Ip6.IsValid()) {
							// Has A/AAAA records. It is a real domain.
							dialMode = consts.DialMode_Domain
							// Add it to real-domain set.
							c.muRealDomainSet.Lock()
							c.realDomainSet.AddString(domain)
							c.muRealDomainSet.Unlock()

							// Should use this domain to reroute
							shouldReroute = true
						}
					}
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
				if err := c.handleConn(lconn); err != nil {
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
			newBuf := pool.Get(n)
			copy(newBuf, buf[:n])
			newOob := pool.Get(oobn)
			copy(newOob, oob[:oobn])
			go func(data pool.PB, oob pool.PB, src netip.AddrPort) {
				defer data.Put()
				defer oob.Put()
				var realDst netip.AddrPort
				var routingResult *bpfRoutingResult
				pktDst := RetrieveOriginalDest(oob)
				routingResult, err := c.core.RetrieveRoutingResult(src, pktDst, unix.IPPROTO_UDP)
				if err != nil {
					c.log.Warnf("No AddrPort presented: %v", err)
					return
				} else {
					realDst = pktDst
				}
				if e := c.handlePkt(udpConn, data, common.ConvergeAddrPort(src), common.ConvergeAddrPort(pktDst), common.ConvergeAddrPort(realDst), routingResult, false); e != nil {
					c.log.Warnln("handlePkt:", e)
				}
			}(newBuf, newOob, src)
		}
	}()
	c.ActivateCheck()
	<-c.ctx.Done()
	return nil
}

func (c *ControlPlane) ListenAndServe(readyChan chan<- bool, port uint16) (listener *Listener, err error) {
	// Listen.
	var listenConfig = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	listenAddr := net.JoinHostPort(c.listenIp, strconv.Itoa(int(port)))
	tcpListener, err := listenConfig.Listen(context.TODO(), "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listenTCP: %w", err)
	}
	packetConn, err := listenConfig.ListenPacket(context.TODO(), "udp", listenAddr)
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
		}).Traceln("Choose DNS path")
	}
	return &dialArgument{
		l4proto:      l4proto,
		ipversion:    ipversion,
		bestDialer:   bestDialer,
		bestOutbound: bestOutbound,
		bestTarget:   bestTarget,
		mark:         dialMark,
	}, nil
}

func (c *ControlPlane) AbortConnections() (err error) {
	var errs []error
	c.inConnections.Range(func(key, value any) bool {
		if err = key.(net.Conn).Close(); err != nil {
			errs = append(errs, err)
		}
		return true
	})
	return errors.Join(errs...)
}
func (c *ControlPlane) Close() (err error) {
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
	return c.core.Close()
}
