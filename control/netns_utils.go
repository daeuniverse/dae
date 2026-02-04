/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	NsName       = "daens"
	HostVethName = "dae0"
	NsVethName   = "dae0peer"
)

var (
	daeNetns *DaeNetns
	once     sync.Once
)

type DaeNetns struct {
	log *logrus.Logger

	setupDone atomic.Bool
	mu        sync.Mutex

	dae0, dae0peer netlink.Link
	hostNs, daeNs  netns.NsHandle
}

func InitDaeNetns(log *logrus.Logger) {
	once.Do(func() {
		daeNetns = &DaeNetns{}
	})
	daeNetns.log = log
}

func GetDaeNetns() *DaeNetns {
	return daeNetns
}

func (ns *DaeNetns) NetnsID() (int, error) {
	return netlink.GetNetNsIdByFd(int(ns.daeNs))
}

func (ns *DaeNetns) Dae0() netlink.Link {
	return ns.dae0
}

func (ns *DaeNetns) Dae0Peer() netlink.Link {
	return ns.dae0peer
}

func (ns *DaeNetns) Setup() (err error) {
	if ns.setupDone.Load() {
		return
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.setupDone.Load() {
		return
	}
	if err = ns.setup(); err != nil {
		return
	}
	ns.setupDone.Store(true)
	return nil
}

func (ns *DaeNetns) Close() (err error) {
	DeleteNamedNetns(NsName)
	DeleteLink(HostVethName)
	return
}

func (ns *DaeNetns) With(f func() error) (err error) {
	if err = daeNetns.Setup(); err != nil {
		return fmt.Errorf("failed to setup dae netns: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	if err = f(); err != nil {
		return fmt.Errorf("failed to run func in dae netns: %v", err)
	}
	return
}

func (ns *DaeNetns) setup() (err error) {
	ns.log.Trace("setting up dae netns")

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if ns.hostNs, err = netns.Get(); err != nil {
		return fmt.Errorf("failed to get host netns: %v", err)
	}
	defer netns.Set(ns.hostNs)

	if err = ns.setupVeth(); err != nil {
		return
	}
	if err = ns.setupNetns(); err != nil {
		return
	}
	if err = ns.setupSysctl(); err != nil {
		return
	}
	if err = ns.setupIPv4Datapath(); err != nil {
		return
	}
	if err = ns.setupIPv6Datapath(); err != nil {
		return
	}
	if err = ns.setupRoutingPolicy(); err != nil {
		return
	}
	return
}

func (ns *DaeNetns) setupRoutingPolicy() (err error) {
	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	/// Insert ip rule / ip route.
	var table = 2023

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
	for _, route := range routes {
		if err = netlink.RouteAdd(&route); err != nil {
			if len(route.Dst.IP) == net.IPv6len {
				// ipv6
				ns.log.Warnln("IpRouteAdd: Bad IPv6 support. Perhaps your machine disabled IPv6.")
				continue
			}
			return fmt.Errorf("IpRouteAdd: %w", err)
		}
	}

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

	for _, rule := range rules {
		if err = netlink.RuleAdd(&rule); err != nil {
			if rule.Family == unix.AF_INET6 {
				// ipv6
				ns.log.Warnln("IpRuleAdd: Bad IPv6 support. Perhaps your machine disabled IPv6 (need CONFIG_IPV6_MULTIPLE_TABLES).")
				continue
			}
			return fmt.Errorf("IpRuleAdd: %w", err)
		}
	}
	return nil
}
func (ns *DaeNetns) setupVeth() (err error) {
	// ip l a dae0 type veth peer name dae0peer
	DeleteLink(HostVethName)
	if err = netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   HostVethName,
			TxQLen: 1000,
		},
		PeerName: NsVethName,
	}); err != nil {
		return fmt.Errorf("failed to add veth pair: %v", err)
	}
	if ns.dae0, err = netlink.LinkByName(HostVethName); err != nil {
		return fmt.Errorf("failed to get link dae0: %v", err)
	}
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("failed to get link dae0peer: %v", err)
	}
	// ip l s dae0 up
	if err = netlink.LinkSetUp(ns.dae0); err != nil {
		return fmt.Errorf("failed to set link dae0 up: %v", err)
	}

	if err = netlink.LinkSetMTU(ns.dae0, netutils.GetEthernetMtu()); err != nil {
		return fmt.Errorf("failed to set mtu %d for dae0: %v", netutils.GetEthernetMtu(), err)
	}
	return
}

func (ns *DaeNetns) setupNetns() (err error) {
	// ip netns a daens
	DeleteNamedNetns(NsName)
	ns.daeNs, err = netns.NewNamed(NsName)
	if err != nil {
		return fmt.Errorf("failed to create netns: %v", err)
	}
	// NewNamed() will switch to the new netns, switch back to host netns
	if err = netns.Set(ns.hostNs); err != nil {
		return fmt.Errorf("failed to switch to host netns: %v", err)
	}
	// ip l s dae0peer netns daens
	if err = netlink.LinkSetNsFd(ns.dae0peer, int(ns.daeNs)); err != nil {
		return fmt.Errorf("failed to move dae0peer to daens: %v", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)
	// (ip net e daens) ip l s dae0peer up
	if err = netlink.LinkSetUp(ns.dae0peer); err != nil {
		return fmt.Errorf("failed to set link dae0peer up: %v", err)
	}
	if err = netlink.LinkSetMTU(ns.dae0peer, netutils.GetEthernetMtu()); err != nil {
		return fmt.Errorf("failed to set mtu %d for dae0peer: %v", netutils.GetEthernetMtu(), err)
	}
	// re-fetch dae0peer to make sure we have the latest mac address
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("failed to get link dae0peer: %v", err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get link lo: %v", err)
	}
	// (ip net e daens) ip l s lo up
	if err = netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("failed to set link lo up: %v", err)
	}
	return
}

func (ns *DaeNetns) setupSysctl() (err error) {
	// sysctl net.ipv6.conf.dae0.disable_ipv6=0
	if err = sysctl.Keyf("net.ipv6.conf.%s.disable_ipv6", HostVethName).Set("0", true); err != nil {
		return fmt.Errorf("failed to set disable_ipv6 for dae0: %v", err)
	}
	// sysctl net.ipv6.conf.dae0.forwarding=1
	if err = sysctl.Keyf("net.ipv6.conf.%s.forwarding", HostVethName).Set("1", true); err != nil {
		return fmt.Errorf("failed to set forwarding for dae0: %v", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// *_early_demux is not mandatory, but it's recommended to enable it for better performance
	sysctl.Keyf("net.ipv4.tcp_early_demux").Set("1", false)
	sysctl.Keyf("net.ipv4.ip_early_demux").Set("1", false)

	// (ip net e daens) sysctl net.ipv4.conf.dae0peer.accept_local=1
	// This is to prevent kernel from dropping skb due to "martian source" check: https://elixir.bootlin.com/linux/v6.6/source/net/ipv4/fib_frontend.c#L381
	if err = sysctl.Keyf("net.ipv4.conf.%s.accept_local", NsVethName).Set("1", false); err != nil {
		return fmt.Errorf("failed to set accept_local for dae0peer: %v", err)
	}
	return
}

func (ns *DaeNetns) setupIPv4Datapath() (err error) {
	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// (ip net e daens) ip a a 169.254.0.11 dev dae0peer
	// Although transparent UDP socket doesn't use this IP, it's still needed to make proper L3 header
	ip, ipNet, err := net.ParseCIDR("169.254.0.11/32")
	ipNet.IP = ip
	if err != nil {
		return fmt.Errorf("failed to parse ip 169.254.0.11: %v", err)
	}
	if err = netlink.AddrAdd(ns.dae0peer, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("failed to add v4 addr to dae0peer: %v", err)
	}
	// (ip net e daens) ip r a 169.254.0.1 dev dae0peer
	// 169.254.0.1 is the link-local address used for ARP caching
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("169.254.0.1"), Mask: net.CIDRMask(32, 32)},
		Gw:        nil,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("failed to add v4 route1 to dae0peer: %v", err)
	}
	// (ip net e daens) ip r a default via 169.254.0.1 dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		Gw:        net.ParseIP("169.254.0.1"),
	}); err != nil {
		return fmt.Errorf("failed to add v4 route2 to dae0peer: %v", err)
	}
	// (ip net e daens) ip n r 169.254.0.1 dev dae0peer lladdr $mac_dae0 nud permanent
	if err = netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("169.254.0.1"),
		HardwareAddr: ns.dae0.Attrs().HardwareAddr,
		LinkIndex:    ns.dae0peer.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("failed to add neigh to dae0peer: %v", err)
	}
	return
}

func (ns *DaeNetns) setupIPv6Datapath() (err error) {
	// ip -6 a a fe80::ecee:eeff:feee:eeee/128 dev dae0 scope link
	// fe80::ecee:eeff:feee:eeee/128 is the link-local address used for L2 NDP addressing
	if err = netlink.AddrAdd(ns.dae0, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP("fe80::ecee:eeff:feee:eeee"),
			Mask: net.CIDRMask(128, 128),
		},
	}); err != nil {
		return fmt.Errorf("failed to add v6 addr to dae0: %v", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// (ip net e daens) ip -6 r a default via fe80::ecee:eeff:feee:eeee dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:        net.ParseIP("fe80::ecee:eeff:feee:eeee"),
	}); err != nil {
		return fmt.Errorf("failed to add v6 route to dae0peer: %v", err)
	}
	// (ip net e daens) ip n r fe80::ecee:eeff:feee:eeee dev dae0peer lladdr $mac_dae0 nud permanent
	if err = netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("fe80::ecee:eeff:feee:eeee"),
		HardwareAddr: ns.dae0.Attrs().HardwareAddr,
		LinkIndex:    ns.dae0peer.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("failed to add neigh to dae0peer: %v", err)
	}
	return
}

func DeleteNamedNetns(name string) error {
	namedPath := path.Join("/run/netns", name)
	unix.Unmount(namedPath, unix.MNT_DETACH|unix.MNT_FORCE)
	return os.Remove(namedPath)
}

func DeleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err == nil {
		return netlink.LinkDel(link)
	}
	return err
}
