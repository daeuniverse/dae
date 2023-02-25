/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mzz2017/softwind/pool"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/dns"
	"github.com/v2rayA/dae/component/outbound"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/component/routing"
	"github.com/v2rayA/dae/config"
	"github.com/v2rayA/dae/pkg/config_parser"
	internal "github.com/v2rayA/dae/pkg/ebpf_internal"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ControlPlane struct {
	log *logrus.Logger

	core       *ControlPlaneCore
	deferFuncs []func() error
	listenIp   string

	// TODO: add mutex?
	outbounds []*outbound.DialerGroup

	dnsController    *DnsController
	onceNetworkReady sync.Once

	dialMode consts.DialMode

	routingMatcher *RoutingMatcher
}

func NewControlPlane(
	log *logrus.Logger,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
	dnsConfig *config.Dns,
) (c *ControlPlane, err error) {
	kernelVersion, e := internal.KernelVersion()
	if e != nil {
		return nil, fmt.Errorf("failed to get kernel version: %w", e)
	}
	/// Check linux kernel requirements.
	// Check version from high to low to reduce the number of user upgrading kernel.
	if kernelVersion.Less(consts.ChecksumFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support checksum related features; expect >=%v; upgrade your kernel and try again",
			kernelVersion.String(),
			consts.ChecksumFeatureVersion.String())
	}
	if len(global.WanInterface) > 0 && kernelVersion.Less(consts.CgSocketCookieFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to WAN; expect >=%v; remove wan_interface in config file and try again",
			kernelVersion.String(),
			consts.CgSocketCookieFeatureVersion.String())
	}
	if len(global.LanInterface) > 0 && kernelVersion.Less(consts.SkAssignFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not support bind to LAN; expect >=%v; remove lan_interface in config file and try again",
			kernelVersion.String(),
			consts.SkAssignFeatureVersion.String())
	}
	if kernelVersion.Less(consts.BasicFeatureVersion) {
		return nil, fmt.Errorf("your kernel version %v does not satisfy basic requirement; expect >=%v",
			kernelVersion.String(),
			consts.BasicFeatureVersion.String())
	}

	/// Allow the current process to lock memory for eBPF resources.
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	if err = os.MkdirAll(pinPath, 0755); err != nil && !os.IsExist(err) {
		if os.IsNotExist(err) {
			c.log.Warnln("Perhaps you are in a container environment (docker/lxc). If so, please use higher virtualization (kvm/qemu). Or you could just try to mount /sys and give privilege and try again.")
		}
		return nil, err
	}

	/// Load pre-compiled programs and maps into the kernel.
	log.Infof("Loading eBPF programs and maps into the kernel")
	var bpf bpfObjects
	var ProgramOptions = ebpf.ProgramOptions{
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
	if err = selectivelyLoadBpfObjects(log, &bpf, &loadBpfOptions{
		PinPath:           pinPath,
		CollectionOptions: collectionOpts,
		BindLan:           len(global.LanInterface) > 0,
		BindWan:           len(global.WanInterface) > 0,
	}); err != nil {
		if log.Level == logrus.PanicLevel {
			log.Panicln(err)
		}
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	core := &ControlPlaneCore{
		log:           log,
		deferFuncs:    []func() error{bpf.Close},
		bpf:           &bpf,
		kernelVersion: &kernelVersion,
	}
	defer func() {
		if err != nil {
			_ = core.Close()
		}
	}()

	// Write params.
	var lanNatDirect uint32
	if global.LanNatDirect {
		lanNatDirect = 1
	} else {
		lanNatDirect = 0
	}
	if err = bpf.ParamMap.Update(consts.ControlPlaneNatDirectKey, lanNatDirect, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.ParamMap.Update(consts.ControlPlanePidKey, uint32(os.Getpid()), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	// Write ip_proto to hdr_size mapping for IPv6 extension extraction (it is just for eBPF code insns optimization).
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_HOPOPTS), int32(-1), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_ROUTING), int32(-1), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_FRAGMENT), int32(4), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_TCP), int32(-2), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_UDP), int32(-2), ebpf.UpdateAny); err != nil {
		return nil, err
	}

	/// Bind to links. Binding should be advance of dialerGroups to avoid un-routable old connection.
	// Add clsact qdisc
	for _, ifname := range common.Deduplicate(append(append([]string{}, global.LanInterface...), global.WanInterface...)) {
		_ = core.addQdisc(ifname)
	}
	// Bind to LAN
	if len(global.LanInterface) > 0 {
		if err = core.setupRoutingPolicy(); err != nil {
			return nil, err
		}
		for _, ifname := range global.LanInterface {
			if err = core.bindLan(ifname); err != nil {
				return nil, fmt.Errorf("bindLan: %v: %w", ifname, err)
			}
		}
	}
	// Bind to WAN
	if len(global.WanInterface) > 0 {
		if err = core.setupSkPidMonitor(); err != nil {
			return nil, err
		}
		for _, ifname := range global.WanInterface {
			if err = core.bindWan(ifname); err != nil {
				return nil, fmt.Errorf("bindWan: %v: %w", ifname, err)
			}
		}
	}

	/// DialerGroups (outbounds).
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: global.TcpCheckUrl},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       true,
		AllowInsecure:     global.AllowInsecure,
	}
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(),
			[]*dialer.Dialer{dialer.NewDirectDialer(option, true)},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, core.OutboundAliveChangeCallback(0)),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(),
			[]*dialer.Dialer{dialer.NewBlockDialer(option, func() { /*Dialer Outbound*/ })},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}, core.OutboundAliveChangeCallback(1)),
	}

	// Filter out groups.
	dialerSet := outbound.NewDialerSetFromLinks(option, tagToNodeList)
	for _, group := range groups {
		// Parse policy.
		policy, err := outbound.NewDialerSelectionPolicyFromGroupParam(&group)
		if err != nil {
			return nil, fmt.Errorf("failed to create group %v: %w", group.Name, err)
		}
		// Filter nodes with user given filters.
		dialers, err := dialerSet.Filter(group.Filter)
		if err != nil {
			return nil, fmt.Errorf(`failed to create group "%v": %w`, group.Name, err)
		}
		// Convert node links to dialers.
		log.Infof(`Group "%v" node list:`, group.Name)
		for _, d := range dialers {
			log.Infoln("\t" + d.Name())
			// We only activate check of nodes that have a group.
			d.ActivateCheck()
		}
		if len(dialers) == 0 {
			log.Infoln("\t<Empty>")
		}
		// Create dialer group and append it to outbounds.
		dialerGroup := outbound.NewDialerGroup(option, group.Name, dialers, *policy, core.OutboundAliveChangeCallback(uint8(len(outbounds))))
		outbounds = append(outbounds, dialerGroup)
	}

	/// Routing.
	// Generate outboundName2Id from outbounds.
	if len(outbounds) > int(consts.OutboundUserDefinedMax) {
		return nil, fmt.Errorf("too many outbounds")
	}
	outboundName2Id := make(map[string]uint8)
	outboundId2Name := make(map[uint8]string)
	for i, o := range outbounds {
		if _, exist := outboundName2Id[o.Name]; exist {
			return nil, fmt.Errorf("duplicated outbound name: %v", o.Name)
		}
		outboundName2Id[o.Name] = uint8(i)
		outboundId2Name[uint8(i)] = o.Name
	}
	core.outboundId2Name = outboundId2Name
	// Apply rules optimizers.
	var rules []*config_parser.RoutingRule
	if rules, err = routing.ApplyRulesOptimizers(routingA.Rules,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: log},
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
	builder, err := NewRoutingMatcherBuilder(log, rules, outboundName2Id, &bpf, routingA.Fallback)
	if err != nil {
		return nil, fmt.Errorf("NewRoutingMatcherBuilder: %w", err)
	}
	if err = builder.BuildKernspace(); err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildKernspace: %w", err)
	}
	routingMatcher, err := builder.BuildUserspace(core.bpf.LpmArrayMap)
	if err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.BuildKernspace: %w", err)
	}

	/// Dial mode.
	dialMode, err := consts.ParseDialMode(global.DialMode)
	if err != nil {
		return nil, err
	}

	c = &ControlPlane{
		log:            log,
		core:           core,
		deferFuncs:     nil,
		listenIp:       "0.0.0.0",
		outbounds:      outbounds,
		dialMode:       dialMode,
		routingMatcher: routingMatcher,
	}

	/// DNS upstream.
	dnsUpstream, err := dns.New(log, dnsConfig, &dns.NewOption{
		UpstreamReadyCallback: c.dnsUpstreamReadyCallback,
	})
	if err != nil {
		return nil, err
	}

	/// Dns controller.
	c.dnsController, err = NewDnsController(dnsUpstream, &DnsControllerOption{
		Log: log,
		CacheAccessCallback: func(cache *DnsCache) (err error) {
			// Write mappings into eBPF map:
			// IP record (from dns lookup) -> domain routing
			if err = core.BatchUpdateDomainRouting(cache); err != nil {
				return fmt.Errorf("BatchUpdateDomainRouting: %w", err)
			}
			return nil
		},
		NewCache: func(fqdn string, answers []dnsmessage.Resource, deadline time.Time) (cache *DnsCache, err error) {
			return &DnsCache{
				DomainBitmap: c.routingMatcher.domainMatcher.MatchDomainBitmap(fqdn),
				Answers:      answers,
				Deadline:     deadline,
			}, nil
		},
		BestDialerChooser: c.chooseBestDnsDialer,
	})

	return c, nil
}

func (c *ControlPlane) dnsUpstreamReadyCallback(raw *url.URL, dnsUpstream *dns.Upstream) (err error) {
	///  Notify dialers to check.
	c.onceNetworkReady.Do(func() {
		for _, out := range c.outbounds {
			for _, d := range out.Dialers {
				d.NotifyCheck()
			}
		}
		if dnsUpstream != nil {
			// Control plane DNS routing.
			if err = c.core.bpf.ParamMap.Update(consts.ControlPlaneDnsRoutingKey, uint32(1), ebpf.UpdateAny); err != nil {
				return
			}
		} else {
			// As-is.
			if err = c.core.bpf.ParamMap.Update(consts.ControlPlaneDnsRoutingKey, uint32(0), ebpf.UpdateAny); err != nil {
				return
			}
		}
	})
	if err != nil {
		return err
	}
	if dnsUpstream == nil {
		return nil
	}

	/// Updates dns cache to support domain routing for hostname of dns_upstream.
	// Ten years later.
	deadline := time.Now().Add(time.Hour * 24 * 365 * 10)
	fqdn := dnsUpstream.Hostname
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	if dnsUpstream.Ip4.IsValid() {
		typ := dnsmessage.TypeA
		answers := []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(fqdn),
				Type:  typ,
				Class: dnsmessage.ClassINET,
				TTL:   0, // Must be zero.
			},
			Body: &dnsmessage.AResource{
				A: dnsUpstream.Ip4.As4(),
			},
		}}
		if err = c.dnsController.UpdateDnsCache(dnsUpstream.Hostname, typ, answers, deadline); err != nil {
			return err
		}
	}

	if dnsUpstream.Ip6.IsValid() {
		typ := dnsmessage.TypeAAAA
		answers := []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(fqdn),
				Type:  typ,
				Class: dnsmessage.ClassINET,
				TTL:   0, // Must be zero.
			},
			Body: &dnsmessage.AAAAResource{
				AAAA: dnsUpstream.Ip6.As16(),
			},
		}}
		if err = c.dnsController.UpdateDnsCache(dnsUpstream.Hostname, typ, answers, deadline); err != nil {
			return err
		}
	}
	return nil
}

func (c *ControlPlane) ChooseDialTarget(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) (dialTarget string) {
	mode := consts.DialMode_Ip

	if !outbound.IsReserved() && domain != "" {
		switch c.dialMode {
		case consts.DialMode_Domain:
			cache := c.dnsController.LookupDnsRespCache(domain, common.AddrToDnsType(dst.Addr()))
			if cache != nil && cache.IncludeIp(dst.Addr()) {
				mode = consts.DialMode_Domain
			}
		case consts.DialMode_DomainPlus:
			mode = consts.DialMode_Domain
		}
	}

	switch mode {
	case consts.DialMode_Ip:
		dialTarget = dst.String()
	case consts.DialMode_Domain:
		dialTarget = net.JoinHostPort(domain, strconv.Itoa(int(dst.Port())))
		c.log.WithFields(logrus.Fields{
			"from": dst.String(),
			"to":   dialTarget,
		}).Debugln("Rewrite dial target to domain")
	}
	return dialTarget
}

func (c *ControlPlane) ListenAndServe(port uint16) (err error) {
	// Listen.
	var listenConfig = net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return dialer.TproxyControl(c)
		},
	}
	listenAddr := net.JoinHostPort(c.listenIp, strconv.Itoa(int(port)))
	tcpListener, err := listenConfig.Listen(context.TODO(), "tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listenTCP: %w", err)
	}
	defer tcpListener.Close()
	packetConn, err := listenConfig.ListenPacket(context.TODO(), "udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listenUDP: %w", err)
	}
	defer packetConn.Close()
	udpConn := packetConn.(*net.UDPConn)

	/// Serve.
	// TCP socket.
	tcpFile, err := tcpListener.(*net.TCPListener).File()
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
	// Port.
	if err := c.core.bpf.ParamMap.Update(consts.BigEndianTproxyPortKey, uint32(common.Htons(port)), ebpf.UpdateAny); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.deferFuncs = append(c.deferFuncs, func() error {
		cancel()
		return nil
	})
	go func() {
		defer cancel()
		for {
			lconn, err := tcpListener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					c.log.Errorf("Error when accept: %v", err)
				}
				break
			}
			go func() {
				if err := c.handleConn(lconn); err != nil {
					c.log.Warnln("handleConn:", err)
				}
			}()
		}
	}()
	go func() {
		defer cancel()
		for {
			var buf [65535]byte
			var oob [120]byte // Size for original dest
			n, oobn, _, src, err := udpConn.ReadMsgUDPAddrPort(buf[:], oob[:])
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					c.log.Errorf("ReadFromUDPAddrPort: %v, %v", src.String(), err)
				}
				break
			}
			newBuf := pool.Get(n)
			copy(newBuf, buf[:n])
			go func(data []byte, src netip.AddrPort) {
				defer pool.Put(data)
				var realDst netip.AddrPort
				var routingResult *bpfRoutingResult
				pktDst := RetrieveOriginalDest(oob[:oobn])
				routingResult, err := c.core.RetrieveRoutingResult(src, pktDst, unix.IPPROTO_UDP)
				if err != nil {
					// WAN. Old method.
					lastErr := err
					addrHdr, dataOffset, err := ParseAddrHdr(data)
					if err != nil {
						c.log.Warnf("No AddrPort presented: %v, %v", lastErr, err)
						return
					}
					copy(data, data[dataOffset:])
					routingResult = &addrHdr.RoutingResult
					__ip := common.Ipv6Uint32ArrayToByteSlice(addrHdr.Ip)
					_ip, _ := netip.AddrFromSlice(__ip)
					// Comment it because them SHOULD equal.
					//src = netip.AddrPortFrom(_ip, src.Port())
					realDst = netip.AddrPortFrom(_ip, addrHdr.Port)
				} else {
					realDst = pktDst
				}
				if e := c.handlePkt(udpConn, data, common.ConvergeAddrPort(src), common.ConvergeAddrPort(pktDst), common.ConvergeAddrPort(realDst), routingResult); e != nil {
					c.log.Warnln("handlePkt:", e)
				}
			}(newBuf, src)
		}
	}()
	<-ctx.Done()
	return nil
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
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"ipversions": ipversions,
			"l4protos":   l4protos,
			"upstream":   dnsUpstream.String(),
		}).Traceln("Choose DNS path")
	}
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
			outboundIndex, mark, err := c.Route(req.realSrc, netip.AddrPortFrom(dAddr, dnsUpstream.Port), "", proto.ToL4ProtoType(), req.routingResult)
			if err != nil {
				return nil, err
			}
			// Already "must direct".
			if outboundIndex == consts.OutboundMustDirect {
				outboundIndex = consts.OutboundDirect
			}
			if int(outboundIndex) >= len(c.outbounds) {
				return nil, fmt.Errorf("bad outbound index: %v", outboundIndex)
			}
			dialerGroup := c.outbounds[outboundIndex]
			d, latency, err := dialerGroup.Select(&networkType)
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
	return &dialArgument{
		l4proto:      l4proto,
		ipversion:    ipversion,
		bestDialer:   bestDialer,
		bestOutbound: bestOutbound,
		bestTarget:   bestTarget,
		mark:         dialMark,
	}, nil
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
	return c.core.Close()
}
