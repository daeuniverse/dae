/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/component/routing"
	"github.com/v2rayA/dae/config"
	"github.com/v2rayA/dae/pkg/config_parser"
	"github.com/v2rayA/dae/pkg/pool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ControlPlane struct {
	log *logrus.Logger

	// TODO: add mutex?
	outbounds       []*outbound.DialerGroup
	outboundName2Id map[string]uint8
	bpf             *bpfObjects

	SimulatedLpmTries  [][]netip.Prefix
	SimulatedDomainSet []DomainSet
	Final              string

	// mutex protects the dnsCache.
	mutex       sync.Mutex
	dnsCache    map[string]*dnsCache
	dnsUpstream netip.AddrPort

	deferFuncs []func() error
}

func NewControlPlane(
	log *logrus.Logger,
	nodes []string,
	groups []config.Group,
	routingA *config.Routing,
	dnsUpstream string,
	checkUrl string,
	checkInterval time.Duration,
) (c *ControlPlane, err error) {
	// Allow the current process to lock memory for eBPF resources.
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	os.MkdirAll(pinPath, 0755)

	// Load pre-compiled programs and maps into the kernel.
	var bpf bpfObjects
	var ProgramOptions ebpf.ProgramOptions
	if log.IsLevelEnabled(logrus.TraceLevel) {
		ProgramOptions = ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelStats,
		}
	}
retryLoadBpf:
	if err = loadBpfObjects(&bpf, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
		Programs: ProgramOptions,
	}); err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			// Map property is incompatible. Remove the old map and try again.
			prefix := "use pinned map "
			_, after, ok := strings.Cut(err.Error(), prefix)
			if !ok {
				return nil, fmt.Errorf("loading objects: bad format: %w", err)
			}
			mapName, _, _ := strings.Cut(after, ":")
			_ = os.Remove(filepath.Join(pinPath, mapName))
			log.Infof("Incompatible new map format with existing map %v detected; removed the old one.", mapName)
			goto retryLoadBpf
		}
		// Get detailed log from ebpf.internal.(*VerifierError)
		if log.IsLevelEnabled(logrus.TraceLevel) {
			if v := reflect.Indirect(reflect.ValueOf(errors.Unwrap(errors.Unwrap(err)))); v.Kind() == reflect.Struct {
				if log := v.FieldByName("Log"); log.IsValid() {
					if strSlice, ok := log.Interface().([]string); ok {
						err = fmt.Errorf("%v", strings.Join(strSlice, "\n"))
					}
				}
			}
		}
		return nil, fmt.Errorf("loading objects: %v", err)
	}
	// Write params.
	if err = bpf.ParamMap.Update(consts.DisableL4TxChecksumKey, consts.DisableL4ChecksumPolicy_SetZero, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.ParamMap.Update(consts.DisableL4RxChecksumKey, consts.DisableL4ChecksumPolicy_SetZero, ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_HOPOPTS), int32(-1), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_ROUTING), int32(-1), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_FRAGMENT), int32(4), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_TCP), int32(0), ebpf.UpdateAny); err != nil {
		return nil, err
	}
	if err = bpf.IpprotoHdrsizeMap.Update(uint32(unix.IPPROTO_UDP), int32(0), ebpf.UpdateAny); err != nil {
		return nil, err
	}

	// DialerGroups (outbounds).
	option := &dialer.GlobalOption{
		Log:           log,
		CheckUrl:      checkUrl,
		CheckInterval: checkInterval,
	}
	outbounds := []*outbound.DialerGroup{
		outbound.NewDialerGroup(option, consts.OutboundDirect.String(),
			[]*dialer.Dialer{dialer.NewDirectDialer(option, true)},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}),
		outbound.NewDialerGroup(option, consts.OutboundBlock.String(),
			[]*dialer.Dialer{dialer.NewBlockDialer(option)},
			outbound.DialerSelectionPolicy{
				Policy:     consts.DialerSelectionPolicy_Fixed,
				FixedIndex: 0,
			}),
	}

	// Filter out groups.
	dialerSet := outbound.NewDialerSetFromLinks(option, nodes)
	for _, group := range groups {
		// Parse policy.
		policy, err := outbound.NewDialerSelectionPolicyFromGroupParam(&group.Param)
		if err != nil {
			return nil, fmt.Errorf("failed to create group %v: %w", group.Name, err)
		}
		// Filter nodes.
		dialers, err := dialerSet.Filter(group.Param.Filter)
		if err != nil {
			return nil, fmt.Errorf(`failed to create group "%v": %w`, group.Name, err)
		}
		// Convert node links to dialers.
		log.Infof(`Group "%v" node list:`, group.Name)
		for _, d := range dialers {
			log.Infoln("\t" + d.Name())
			d.ActiveCheck()
		}
		if len(dialers) == 0 {
			log.Infoln("\t<Empty>")
		}
		// Create dialer group and append it to outbounds.
		dialerGroup := outbound.NewDialerGroup(option, group.Name, dialers, *policy)
		outbounds = append(outbounds, dialerGroup)
	}

	// Generate outboundName2Id from outbounds.
	if len(outbounds) > 0xff {
		return nil, fmt.Errorf("too many outbounds")
	}
	outboundName2Id := make(map[string]uint8)
	for i, o := range outbounds {
		outboundName2Id[o.Name] = uint8(i)
	}
	builder := NewRoutingMatcherBuilder(outboundName2Id, &bpf)

	// Routing.
	var rules []*config_parser.RoutingRule
	if rules, err = routing.ApplyRulesOptimizers(routingA.Rules,
		&routing.RefineFunctionParamKeyOptimizer{},
		&routing.DatReaderOptimizer{Logger: log},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	); err != nil {
		return nil, fmt.Errorf("ApplyRulesOptimizers error: \n %w", err)
	}
	if log.IsLevelEnabled(logrus.DebugLevel) {
		var debugBuilder strings.Builder
		for _, rule := range rules {
			debugBuilder.WriteString(rule.String(true) + "\n")
		}
		log.Debugf("RoutingA:\n%vfinal: %v\n", debugBuilder.String(), routingA.Final)
	}
	if err = routing.ApplyMatcherBuilder(builder, rules, routingA.Final); err != nil {
		return nil, fmt.Errorf("ApplyMatcherBuilder: %w", err)
	}
	if err = builder.Build(); err != nil {
		return nil, fmt.Errorf("RoutingMatcherBuilder.Build: %w", err)
	}

	// DNS upstream.
	dnsAddrPort, err := netip.ParseAddrPort(dnsUpstream)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS upstream: %v: %w", dnsUpstream, err)
	}
	dnsAddr16 := dnsAddrPort.Addr().As16()
	if err = bpf.DnsUpstreamMap.Update(consts.ZeroKey, bpfIpPort{
		Ip:   common.Ipv6ByteSliceToUint32Array(dnsAddr16[:]),
		Port: swap16(dnsAddrPort.Port()),
	}, ebpf.UpdateAny); err != nil {
		return nil, err
	}

	return &ControlPlane{
		log:                log,
		outbounds:          outbounds,
		outboundName2Id:    outboundName2Id,
		bpf:                &bpf,
		SimulatedLpmTries:  builder.SimulatedLpmTries,
		SimulatedDomainSet: builder.SimulatedDomainSet,
		Final:              routingA.Final,
		mutex:              sync.Mutex{},
		dnsCache:           make(map[string]*dnsCache),
		dnsUpstream:        dnsAddrPort,
		deferFuncs:         []func() error{bpf.Close},
	}, nil
}

func (c *ControlPlane) BindLink(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	// Insert an elem into IfindexIpsMap.
	// TODO: We should monitor IP change of the link.
	ipnets, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	// TODO: If we monitor IP change of the link, we should remove code below.
	if len(ipnets) == 0 {
		return fmt.Errorf("interface %v has no ip", ifname)
	}
	var linkIp bpfIfIp
	for _, ipnet := range ipnets {
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if (ip.Is6() && linkIp.HasIp6) ||
			(ip.Is4() && linkIp.HasIp4) {
			continue
		}
		ip6format := ip.As16()
		if ip.Is4() {
			linkIp.HasIp4 = true
			linkIp.Ip4 = common.Ipv6ByteSliceToUint32Array(ip6format[:])
		} else {
			linkIp.HasIp6 = true
			linkIp.Ip6 = common.Ipv6ByteSliceToUint32Array(ip6format[:])
		}
		if linkIp.HasIp4 && linkIp.HasIp6 {
			break
		}
	}
	if err := c.bpf.IfindexTproxyIpMap.Update(uint32(link.Attrs().Index), linkIp, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update IfindexIpsMap: %w", err)
	}
	// FIXME: not only this link ip.
	if linkIp.HasIp4 {
		if err := c.bpf.HostIpLpm.Update(_bpfLpmKey{
			PrefixLen: 128,
			Data:      linkIp.Ip4,
		}, uint32(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update IfindexIpsMap: %w", err)
		}
	}
	if linkIp.HasIp6 {
		if err := c.bpf.HostIpLpm.Update(_bpfLpmKey{
			PrefixLen: 128,
			Data:      linkIp.Ip6,
		}, uint32(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update IfindexIpsMap: %w", err)
		}
	}

	// Insert qdisc and filters.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if os.IsExist(err) {
			_ = netlink.QdiscDel(qdisc)
			err = netlink.QdiscAdd(qdisc)
		}

		if err != nil {
			return fmt.Errorf("cannot add clsact qdisc: %w", err)
		}
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.QdiscDel(qdisc); err != nil {
			return fmt.Errorf("QdiscDel: %w", err)
		}
		return nil
	})

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyIngress.FD(),
		Name:         consts.AppName + "_ingress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyEgress.FD(),
		Name:         consts.AppName + "_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	return nil
}

func (c *ControlPlane) ListenAndServe(port uint16) (err error) {
	// Listen.
	listener, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(int(port)))
	if err != nil {
		return fmt.Errorf("listenTCP: %w", err)
	}
	defer listener.Close()
	lConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: int(port),
	})
	if err != nil {
		return fmt.Errorf("listenUDP: %w", err)
	}
	defer lConn.Close()

	// Serve.
	if err := c.bpf.ParamMap.Update(consts.BigEndianTproxyPortKey, uint32(swap16(port)), ebpf.UpdateAny); err != nil {
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
			lconn, err := listener.Accept()
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
			var buf [65536]byte
			n, lAddrPort, err := lConn.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					c.log.Errorf("ReadFromUDPAddrPort: %v, %v", lAddrPort.String(), err)
				}
				break
			}
			addrHdr, dataOffset, err := ParseAddrHdr(buf[:n])
			if err != nil {
				c.log.Warnf("No AddrPort presented")
				continue
			}
			newBuf := pool.Get(n - dataOffset)
			copy(newBuf, buf[dataOffset:n])
			go func(data []byte, lConn *net.UDPConn, lAddrPort netip.AddrPort, addrHdr *AddrHdr) {
				if e := c.handlePkt(newBuf, lConn, lAddrPort, addrHdr); e != nil {
					c.log.Warnln("handlePkt:", e)
				}
				pool.Put(newBuf)
			}(newBuf, lConn, lAddrPort, addrHdr)
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
	return err
}
