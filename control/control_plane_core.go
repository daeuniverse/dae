/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sync"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/safchain/ethtool"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// coreFlip should be 0 or 1
var coreFlip = 0

type controlPlaneCore struct {
	mu sync.Mutex

	log             *logrus.Logger
	deferFuncs      []func() error
	bpf             *bpfObjects
	outboundId2Name map[uint8]string

	kernelVersion *internal.Version

	flip       int
	isReload   bool
	bpfEjected bool

	closed context.Context
	close  context.CancelFunc
}

func newControlPlaneCore(log *logrus.Logger,
	bpf *bpfObjects,
	outboundId2Name map[uint8]string,
	kernelVersion *internal.Version,
	isReload bool,
) *controlPlaneCore {
	if isReload {
		coreFlip = coreFlip&1 ^ 1
	}
	var deferFuncs []func() error
	if !isReload {
		deferFuncs = append(deferFuncs, bpf.Close)
	}
	closed, toClose := context.WithCancel(context.Background())
	return &controlPlaneCore{
		log:             log,
		deferFuncs:      deferFuncs,
		bpf:             bpf,
		outboundId2Name: outboundId2Name,
		kernelVersion:   kernelVersion,
		flip:            coreFlip,
		isReload:        isReload,
		bpfEjected:      false,
		closed:          closed,
		close:           toClose,
	}
}

func (c *controlPlaneCore) Flip() {
	coreFlip = coreFlip&1 ^ 1
}
func (c *controlPlaneCore) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
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
	c.close()
	return err
}

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		return bpfIfParams{}, err
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		return bpfIfParams{}, err
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

func (c *controlPlaneCore) addQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("cannot add clsact qdisc: %w", err)
		}
	}
	return nil
}

func (c *controlPlaneCore) setupRoutingPolicy() (err error) {
	/// Insert ip rule / ip route.
	var table = 2023 + c.flip

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
	var routeBadIpv6 bool
	cleanRoutes := func() error {
		var errs error
		for _, route := range routes {
			if e := netlink.RouteDel(&route); e != nil {
				if len(route.Dst.IP) == net.IPv6len && routeBadIpv6 {
					// Not clean for bad ipv6.
					continue
				}
				if errs != nil {
					errs = fmt.Errorf("%w; %v", errs, e)
				} else {
					errs = e
				}
			}
		}
		if errs != nil {
			return fmt.Errorf("IpRouteDel(lo): %w", errs)
		}
		return nil
	}
tryRouteAddAgain:
	for _, route := range routes {
		if err = netlink.RouteAdd(&route); err != nil {
			if os.IsExist(err) {
				_ = cleanRoutes()
				goto tryRouteAddAgain
			}
			if len(route.Dst.IP) == net.IPv6len {
				// ipv6
				c.log.Warnln("IpRouteAdd: Bad IPv6 support. Perhaps your machine disabled IPv6.")
				routeBadIpv6 = true
				continue
			}
			return fmt.Errorf("IpRouteAdd: %w", err)
		}
	}
	c.deferFuncs = append(c.deferFuncs, cleanRoutes)

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
		Mark:              int(consts.TproxyMark),
		Mask:              int(consts.TproxyMark),
	}, {
		SuppressIfgroup:   -1,
		SuppressPrefixlen: -1,
		Priority:          -1,
		Goto:              -1,
		Flow:              -1,
		Family:            unix.AF_INET6,
		Table:             table,
		Mark:              int(consts.TproxyMark),
		Mask:              int(consts.TproxyMark),
	}}
	var ruleBadIpv6 bool
	cleanRules := func() error {
		var errs error
		for _, rule := range rules {
			if rule.Family == unix.AF_INET6 && ruleBadIpv6 {
				// Not clean for bad ipv6.
				continue
			}
			if e := netlink.RuleDel(&rule); e != nil {
				if errs != nil {
					errs = fmt.Errorf("%w; %v", errs, e)
				} else {
					errs = e
				}
			}
		}
		if errs != nil {
			return fmt.Errorf("IpRuleDel: %w", errs)
		}
		return nil
	}
tryRuleAddAgain:
	for _, rule := range rules {
		if err = netlink.RuleAdd(&rule); err != nil {
			if os.IsExist(err) {
				_ = cleanRules()
				goto tryRuleAddAgain
			}
			if rule.Family == unix.AF_INET6 {
				// ipv6
				c.log.Warnln("IpRuleAdd: Bad IPv6 support. Perhaps your machine disabled IPv6 (need CONFIG_IPV6_MULTIPLE_TABLES).")
				ruleBadIpv6 = true
				continue
			}
			return fmt.Errorf("IpRuleAdd: %w", err)
		}
	}
	c.deferFuncs = append(c.deferFuncs, cleanRules)
	return nil
}

func (c *controlPlaneCore) addLinkCb(_ifname string, rtmType uint16, cb func()) error {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if e := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			c.log.Debug("LinkSubscribe:", err)
		},
		ListExisting: true,
	}); e != nil {
		return e
	}
	go func(ctx context.Context, ch <-chan netlink.LinkUpdate, done chan struct{}) {
		for {
			select {
			case <-ctx.Done():
				close(done)
				return
			case <-done:
				return
			case update := <-ch:
				if update.Header.Type == rtmType {
					ifname := update.Link.Attrs().Name
					if ifname == _ifname {
						cb()
						close(done)
						return
					}
				}
			}
		}
	}(c.closed, ch, done)
	return nil
}

// addNewLinkBindLanCb waits for NEWLINK msg of given `ifname` and invokes `bindLan`.
func (c *controlPlaneCore) addNewLinkBindLanCb(ifname string, autoConfigKernelParameter bool) error {
	return c.addLinkCb(ifname, unix.RTM_NEWLINK, func() {
		c.log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", ifname)
		if err := c.addQdisc(ifname); err != nil {
			c.log.Errorf("addQdisc: %v", err)
			return
		}
		if err := c.bindLan(ifname, autoConfigKernelParameter); err != nil {
			c.log.Errorf("bindLan: %v", err)
		}
	})
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is deleted in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) error {
	if autoConfigKernelParameter {
		SetSendRedirects(ifname, "0")
		SetForwarding(ifname, "1")
	}
	if err := c._bindLan(ifname); err != nil {
		var notFoundErr netlink.LinkNotFoundError
		if !errors.As(err, &notFoundErr) {
			return err
		}
		// Not found error.

		// Listen for `NEWLINK` to bind.
		c.log.Warnf("Link '%v' is not found. Bind LAN program to it once it is created.", ifname)
		if e := c.addNewLinkBindLanCb(ifname, autoConfigKernelParameter); e != nil {
			return fmt.Errorf("%w: %v", err, e)
		}
		return nil
	}
	// Listen for `DELLINK` and add `NEWLINK` callback to re-bind.
	if err := c.addLinkCb(ifname, unix.RTM_DELLINK, func() {
		c.log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", ifname)
		if e := c.addNewLinkBindLanCb(ifname, autoConfigKernelParameter); e != nil {
			c.log.Errorf("Failed to add callback for re-bind LAN program to '%v': %v", ifname, e)
		}
	}); err != nil {
		return fmt.Errorf("failed to add re-bind callback: %w", err)
	}
	return nil
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
	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}
	if err := c.bpf.IfindexParamsMap.Update(uint32(link.Attrs().Index), ifParams, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update IfindexIpsMap: %w", err)
	}

	// Insert filters.
	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be behind of WAN's
			Priority: 2,
		},
		Fd:           c.bpf.bpfPrograms.TproxyLanIngress.FD(),
		Name:         consts.AppName + "_lan_ingress",
		DirectAction: true,
	}
	// Remove and add.
	_ = netlink.FilterDel(filterIngress)
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	// Insert filters.
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be front of WAN's
			Priority: 1,
		},
		Fd:           c.bpf.bpfPrograms.TproxyLanEgress.FD(),
		Name:         consts.AppName + "_lan_egress",
		DirectAction: true,
	}
	// Remove and add.
	_ = netlink.FilterDel(filterEgress)
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})
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
		c.deferFuncs = append(c.deferFuncs, func() error {
			if err := attached.Close(); err != nil {
				return fmt.Errorf("inet6Bind.Close(): %w", err)
			}
			return nil
		})
	}
	return nil
}

func (c *controlPlaneCore) bindWan(ifname string) error {
	return c._bindWan(ifname)
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
	/// Insert an elem into IfindexParamsMap.
	ifParams, err := getIfParamsFromLink(link)
	if err != nil {
		return err
	}
	if err = ifParams.CheckVersionRequirement(c.kernelVersion); err != nil {
		return err
	}
	if err := c.bpf.IfindexParamsMap.Update(uint32(link.Attrs().Index), ifParams, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update IfindexIpsMap: %w", err)
	}

	/// Set-up WAN ingress/egress TC programs.
	// Insert TC filters
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b100+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  2,
		},
		Fd:           c.bpf.bpfPrograms.TproxyWanEgress.FD(),
		Name:         consts.AppName + "_wan_egress",
		DirectAction: true,
	}
	_ = netlink.FilterDel(filterEgress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterEgressFlipped := deepcopy.Copy(filterEgress).(*netlink.BpfFilter)
		filterEgressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterEgressFlipped)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	})

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           c.bpf.bpfPrograms.TproxyWanIngress.FD(),
		Name:         consts.AppName + "_wan_ingress",
		DirectAction: true,
	}
	_ = netlink.FilterDel(filterIngress)
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly.
		filterIngressFlipped := deepcopy.Copy(filterIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		_ = netlink.FilterDel(filterIngressFlipped)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})
	return nil
}

// BatchUpdateDomainRouting update bpf map domain_routing. Since one IP may have multiple domains, this function should
// be invoked every A/AAAA-record lookup.
func (c *controlPlaneCore) BatchUpdateDomainRouting(cache *DnsCache) error {
	// Parse ips from DNS resp answers.
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
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
	var keys [][4]uint32
	var vals []bpfDomainRouting
	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
		r := bpfDomainRouting{}
		if len(cache.DomainBitmap) != len(r.Bitmap) {
			return fmt.Errorf("domain bitmap length not sync with kern program")
		}
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
	// Parse ips from DNS resp answers.
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
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
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
	if !c.bpfEjected && !c.isReload {
		c.deferFuncs = c.deferFuncs[1:]
	}
	c.bpfEjected = true
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
