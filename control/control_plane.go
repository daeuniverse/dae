/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
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
	outbounds       []*outbound.DialerGroup
	outboundName2Id map[string]uint8

	SimulatedLpmTries  [][]netip.Prefix
	SimulatedDomainSet []DomainSet
	Final              string

	// mutex protects the dnsCache.
	dnsCacheMu  sync.Mutex
	dnsCache    map[string]*dnsCache
	dnsUpstream DnsUpstreamRaw

	dialMode consts.DialMode
}

func NewControlPlane(
	log *logrus.Logger,
	tagToNodeList map[string][]string,
	groups []config.Group,
	routingA *config.Routing,
	global *config.Global,
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
	checkDnsTcp := false
	if !global.DnsUpstream.Empty {
		if scheme, _, _, err := ParseDnsUpstream(global.DnsUpstream.Url); err == nil &&
			scheme.ContainsTcp() {
			checkDnsTcp = true
		}
	}
	if global.AllowInsecure {
		log.Warnln("AllowInsecure is enabled, but it is not recommended. Please make sure you have to turn it on.")
	}
	option := &dialer.GlobalOption{
		Log:               log,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: global.TcpCheckUrl},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: global.UdpCheckDns},
		CheckInterval:     global.CheckInterval,
		CheckTolerance:    global.CheckTolerance,
		CheckDnsTcp:       checkDnsTcp,
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
		policy, err := outbound.NewDialerSelectionPolicyFromGroupParam(&group.Param)
		if err != nil {
			return nil, fmt.Errorf("failed to create group %v: %w", group.Name, err)
		}
		// Filter nodes with user given filters.
		dialers, err := dialerSet.Filter(group.Param.Filter)
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
	for i, o := range outbounds {
		if _, exist := outboundName2Id[o.Name]; exist {
			return nil, fmt.Errorf("duplicated outbound name: %v", o.Name)
		}
		outboundName2Id[o.Name] = uint8(i)
	}
	builder := NewRoutingMatcherBuilder(outboundName2Id, &bpf)
	var rules []*config_parser.RoutingRule
	if rules, err = routing.ApplyRulesOptimizers(routingA.Rules,
		&routing.RefineFunctionParamKeyOptimizer{},
		&routing.DatReaderOptimizer{Logger: log},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error:\n%w", err)
	}
	if log.IsLevelEnabled(logrus.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range rules {
			debugBuilder.WriteString(rule.String(true) + "\n")
		}
		log.Debugf("RoutingA:\n%vfinal: %v\n", debugBuilder.String(), routingA.Final)
	}
	if err = routing.ApplyMatcherBuilder(log, builder, rules, routingA.Final); err != nil {
		return nil, fmt.Errorf("ApplyMatcherBuilder: %w", err)
	}
	if err = builder.Build(); err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.Build: %w", err)
	}

	dialMode, err := consts.ParseDialMode(global.DialMode)

	c = &ControlPlane{
		log:                log,
		core:               core,
		deferFuncs:         nil,
		listenIp:           "0.0.0.0",
		outbounds:          outbounds,
		outboundName2Id:    outboundName2Id,
		SimulatedLpmTries:  builder.SimulatedLpmTries,
		SimulatedDomainSet: builder.SimulatedDomainSet,
		Final:              routingA.Final,
		dnsCacheMu:         sync.Mutex{},
		dnsCache:           make(map[string]*dnsCache),
		dnsUpstream: DnsUpstreamRaw{
			Raw:                global.DnsUpstream,
			FinishInitCallback: nil,
		},
		dialMode: dialMode,
	}

	/// DNS upstream
	c.dnsUpstream.FinishInitCallback = c.finishInitDnsUpstreamResolve
	// Try to invoke once to avoid dns leaking at the very beginning.
	_, _ = c.dnsUpstream.GetUpstream()
	return c, nil
}

func (c *ControlPlane) finishInitDnsUpstreamResolve(raw common.UrlOrEmpty, dnsUpstream *DnsUpstream) (err error) {
	///  Notify dialers to check.
	for _, out := range c.outbounds {
		for _, d := range out.Dialers {
			d.NotifyCheck()
		}
	}

	/// Updates dns cache to support domain routing for hostname of dns_upstream.
	if !raw.Empty {
		ip4in6 := dnsUpstream.Ip4.As16()
		ip6 := dnsUpstream.Ip6.As16()
		if err = c.core.bpf.DnsUpstreamMap.Update(consts.ZeroKey, bpfDnsUpstream{
			Ip4:    common.Ipv6ByteSliceToUint32Array(ip4in6[:]),
			Ip6:    common.Ipv6ByteSliceToUint32Array(ip6[:]),
			HasIp4: dnsUpstream.Ip4.IsValid(),
			HasIp6: dnsUpstream.Ip6.IsValid(),
			Port:   internal.Htons(dnsUpstream.Port),
		}, ebpf.UpdateAny); err != nil {
			return err
		}
		/// Update dns cache to support domain routing for hostname of dns_upstream.
		// Ten years later.
		deadline := time.Now().Add(24 * time.Hour * 365 * 10)
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
			if err = c.UpdateDnsCache(fqdn, typ, answers, deadline); err != nil {
				c = nil
				return
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
			if err = c.UpdateDnsCache(fqdn, typ, answers, deadline); err != nil {
				c = nil
				return
			}
		}
	} else {
		// Empty string. As-is.
		if err = c.core.bpf.DnsUpstreamMap.Update(consts.ZeroKey, bpfDnsUpstream{
			Ip4:    [4]uint32{},
			Ip6:    [4]uint32{},
			HasIp4: false,
			HasIp6: false,
			// Zero port indicates no element, because bpf_map_lookup_elem cannot return 0 for map_type_array.
			Port: 0,
		}, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func (c *ControlPlane) ChooseDialTarget(outbound consts.OutboundIndex, dst netip.AddrPort, domain string) (dialTarget string) {
	mode := consts.DialMode_Ip
	if c.dialMode == consts.DialMode_Domain &&
		!outbound.IsReserved() && // Direct, block, etc. should be skipped.
		domain != "" {
		dstIp := common.ConvergeIp(dst.Addr())
		cache := c.lookupDnsRespCache(domain, common.AddrToDnsType(dstIp))
		if cache != nil && cache.IncludeIp(dstIp) {
			mode = consts.DialMode_Domain
		}
		if cache == nil {
			c.log.WithFields(logrus.Fields{
				"domain": domain,
			}).Debugln("cache miss")
		} else if !cache.IncludeIp(dstIp) {
			c.log.WithFields(logrus.Fields{
				"domain":  domain,
				"addr":    dstIp,
				"records": FormatDnsRsc(cache.Answers),
			}).Debugln("record miss")
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
		}).Debugln("Reset dial target to domain")
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
	if err := c.core.bpf.ParamMap.Update(consts.BigEndianTproxyPortKey, uint32(internal.Htons(port)), ebpf.UpdateAny); err != nil {
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
			pktDst := RetrieveOriginalDest(oob[:oobn])
			var newBuf []byte
			var realDst netip.AddrPort
			outboundIndex, err := c.core.RetrieveOutboundIndex(src, pktDst, unix.IPPROTO_UDP)
			if err != nil {
				// WAN. Old method.
				addrHdr, dataOffset, err := ParseAddrHdr(buf[:n])
				if err != nil {
					c.log.Warnf("No AddrPort presented")
					continue
				}
				newBuf = pool.Get(n - dataOffset)
				copy(newBuf, buf[dataOffset:n])
				outboundIndex = consts.OutboundIndex(addrHdr.Outbound)
				src = netip.AddrPortFrom(addrHdr.Dest.Addr(), src.Port())
				realDst = addrHdr.Dest
			} else {
				newBuf = pool.Get(n)
				copy(newBuf, buf[:n])
				realDst = pktDst
			}
			go func(data []byte, src, pktDst, realDst netip.AddrPort, outboundIndex consts.OutboundIndex) {
				if e := c.handlePkt(udpConn, newBuf, src, pktDst, realDst, outboundIndex); e != nil {
					c.log.Warnln("handlePkt:", e)
				}
				pool.Put(newBuf)
			}(newBuf, src, pktDst, realDst, outboundIndex)
		}
	}()
	<-ctx.Done()
	return nil
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
