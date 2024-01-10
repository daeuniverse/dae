package control

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"sync"
	"sync/atomic"

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
)

type DaeNetns struct {
	setupDone atomic.Bool
	mu        sync.Mutex

	dae0, dae0peer netlink.Link
	hostNs, daeNs  netns.NsHandle
}

func init() {
	daeNetns = &DaeNetns{}
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

func (ns *DaeNetns) With(f func() error) (err error) {
	if err = daeNetns.Setup(); err != nil {
		return fmt.Errorf("Failed to setup dae netns: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("Failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	if err = f(); err != nil {
		return fmt.Errorf("Failed to run func in dae netns: %v", err)
	}
	return
}

func (ns *DaeNetns) setup() (err error) {
	logrus.Trace("Setting up dae netns")

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if ns.hostNs, err = netns.Get(); err != nil {
		return fmt.Errorf("Failed to get host netns: %v", err)
	}
	defer netns.Set(ns.hostNs)

	if err = ns.setupVeth(); err != nil {
		return
	}
	if err = ns.setupSysctl(); err != nil {
		return
	}
	if err = ns.setupNetns(); err != nil {
		return
	}
	if err = ns.setupIPv4Datapath(); err != nil {
		return
	}
	if err = ns.setupIPv6Datapath(); err != nil {
		return
	}
	go ns.monitorDae0LinkAddr()
	return
}

func (ns *DaeNetns) setupVeth() (err error) {
	// ip l a dae0 type veth peer name dae0peer
	DeleteLink(HostVethName)
	if err = netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: HostVethName,
		},
		PeerName: NsVethName,
	}); err != nil {
		return fmt.Errorf("Failed to add veth pair: %v", err)
	}
	if ns.dae0, err = netlink.LinkByName(HostVethName); err != nil {
		return fmt.Errorf("Failed to get link dae0: %v", err)
	}
	if ns.dae0peer, err = netlink.LinkByName(NsVethName); err != nil {
		return fmt.Errorf("Failed to get link dae0peer: %v", err)
	}
	// ip l s dae0 up
	if err = netlink.LinkSetUp(ns.dae0); err != nil {
		return fmt.Errorf("Failed to set link dae0 up: %v", err)
	}
	return
}

func (ns *DaeNetns) setupSysctl() (err error) {
	// sysctl net.ipv4.conf.dae0.rp_filter=0
	if err = SetRpFilter(HostVethName, "0"); err != nil {
		return fmt.Errorf("Failed to set rp_filter for dae0: %v", err)
	}
	// sysctl net.ipv4.conf.all.rp_filter=0
	if err = SetRpFilter("all", "0"); err != nil {
		return fmt.Errorf("Failed to set rp_filter for all: %v", err)
	}
	// sysctl net.ipv4.conf.dae0.arp_filter=0
	if err = SetArpFilter(HostVethName, "0"); err != nil {
		return fmt.Errorf("Failed to set arp_filter for dae0: %v", err)
	}
	// sysctl net.ipv4.conf.all.arp_filter=0
	if err = SetArpFilter("all", "0"); err != nil {
		return fmt.Errorf("Failed to set arp_filter for all: %v", err)
	}
	// sysctl net.ipv4.conf.dae0.accept_local=1
	if err = SetAcceptLocal(HostVethName, "1"); err != nil {
		return fmt.Errorf("Failed to set accept_local for dae0: %v", err)
	}
	// sysctl net.ipv6.conf.dae0.disable_ipv6=0
	if err = SetDisableIpv6(HostVethName, "0"); err != nil {
		return fmt.Errorf("Failed to set disable_ipv6 for dae0: %v", err)
	}
	// sysctl net.ipv6.conf.dae0.forwarding=1
	SetForwarding(HostVethName, "1")
	// sysctl net.ipv6.conf.all.forwarding=1
	SetForwarding("all", "1")
	return
}

func (ns *DaeNetns) setupNetns() (err error) {
	// ip netns a daens
	DeleteNamedNetns(NsName)
	ns.daeNs, err = netns.NewNamed(NsName)
	if err != nil {
		return fmt.Errorf("Failed to create netns: %v", err)
	}
	// NewNamed() will switch to the new netns, switch back to host netns
	if err = netns.Set(ns.hostNs); err != nil {
		return fmt.Errorf("Failed to switch to host netns: %v", err)
	}
	// ip l s dae0peer netns daens
	if err = netlink.LinkSetNsFd(ns.dae0peer, int(ns.daeNs)); err != nil {
		return fmt.Errorf("Failed to move dae0peer to daens: %v", err)
	}
	return
}

func (ns *DaeNetns) setupIPv4Datapath() (err error) {
	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("Failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// (ip net e daens) ip l s dae0peer up
	if err = netlink.LinkSetUp(ns.dae0peer); err != nil {
		return fmt.Errorf("Failed to set link dae0peer up: %v", err)
	}
	// (ip net e daens) ip a a 169.254.0.11 dev dae0peer
	// Although transparent UDP socket doesn't use this IP, it's still needed to make proper L3 header
	ip, ipNet, err := net.ParseCIDR("169.254.0.11/32")
	ipNet.IP = ip
	if err != nil {
		return fmt.Errorf("Failed to parse ip 169.254.0.11: %v", err)
	}
	if err = netlink.AddrAdd(ns.dae0peer, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("Failed to add v4 addr to dae0peer: %v", err)
	}
	// (ip net e daens) ip r a 169.254.0.1 dev dae0peer
	// 169.254.0.1 is the link-local address used for ARP caching
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("169.254.0.1"), Mask: net.CIDRMask(32, 32)},
		Gw:        nil,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("Failed to add v4 route1 to dae0peer: %v", err)
	}
	// (ip net e daens) ip r a default via 169.254.0.1 dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		Gw:        net.ParseIP("169.254.0.1"),
	}); err != nil {
		return fmt.Errorf("Failed to add v4 route2 to dae0peer: %v", err)
	}
	// (ip net e daens) ip n r 169.254.0.1 dev dae0peer lladdr $mac_dae0 nud permanent
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
		return fmt.Errorf("Failed to add v6 addr to dae0: %v", err)
	}

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("Failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	// (ip net e daens) ip -6 r a default via fe80::ecee:eeff:feee:eeee dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: ns.dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:        net.ParseIP("fe80::ecee:eeff:feee:eeee"),
	}); err != nil {
		return fmt.Errorf("Failed to add v6 route to dae0peer: %v", err)
	}
	return
}

// updateNeigh() isn't named as setupNeigh() because it requires runtime.LockOSThread()
func (ns *DaeNetns) updateNeigh() (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = netns.Set(ns.daeNs); err != nil {
		return fmt.Errorf("Failed to switch to daens: %v", err)
	}
	defer netns.Set(ns.hostNs)

	if err = netlink.NeighSet(&netlink.Neigh{
		IP:           net.ParseIP("169.254.0.1"),
		HardwareAddr: ns.dae0.Attrs().HardwareAddr,
		LinkIndex:    ns.dae0peer.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
	}); err != nil {
		return fmt.Errorf("Failed to add neigh to dae0peer: %v", err)
	}
	return
}

func (ns *DaeNetns) monitorDae0LinkAddr() {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)

	err := netlink.LinkSubscribe(ch, done)
	if err != nil {
		logrus.Errorf("Failed to subscribe link updates: %v", err)
	}
	if err = ns.updateNeigh(); err != nil {
		logrus.Errorf("Failed to update neigh: %v", err)
	}
	for msg := range ch {
		if msg.Link.Attrs().Name == HostVethName && !bytes.Equal(msg.Link.Attrs().HardwareAddr, ns.dae0.Attrs().HardwareAddr) {
			logrus.WithField("old addr", ns.dae0.Attrs().HardwareAddr).WithField("new addr", msg.Link.Attrs().HardwareAddr).Info("dae0 link addr changed")
			ns.dae0 = msg.Link
			ns.updateNeigh()
		}
	}
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
