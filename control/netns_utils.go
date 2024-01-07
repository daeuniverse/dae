package control

import (
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var (
	indieNetns netns.NsHandle
	once       sync.Once
)

func WithIndieNetns(f func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNetns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("Failed to get host netns: %v", err)
	}
	defer netns.Set(hostNetns)

	ns, err := GetIndieNetns()
	if err != nil {
		return
	}
	if err = netns.Set(ns); err != nil {
		return fmt.Errorf("Failed to switch to daens: %v", err)
	}

	return f()
}

func GetIndieNetns() (_ netns.NsHandle, err error) {
	if indieNetns != 0 {
		return indieNetns, nil
	}

	once.Do(func() {
		err = setupIndieNetns()
	})
	return indieNetns, err
}

func setupIndieNetns() (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNetns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("Failed to get host netns: %v", err)
	}
	defer netns.Set(hostNetns)

	// ip netns a daens
	DeleteNamedNetns("daens")
	indieNetns, err = netns.NewNamed("daens")
	if err != nil {
		return fmt.Errorf("Failed to create netns: %v", err)
	}
	if err = netns.Set(hostNetns); err != nil {
		return fmt.Errorf("Failed to switch to host netns: %v", err)
	}
	// ip l a dae0 type veth peer name dae0peer
	DeleteLink("dae0")
	if err = netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "dae0",
		},
		PeerName: "dae0peer",
	}); err != nil {
		return fmt.Errorf("Failed to add veth pair: %v", err)
	}
	dae0, err := netlink.LinkByName("dae0")
	if err != nil {
		return fmt.Errorf("Failed to get link dae0: %v", err)
	}
	dae0peer, err := netlink.LinkByName("dae0peer")
	if err != nil {
		return fmt.Errorf("Failed to get link dae0peer: %v", err)
	}
	// ip l s dae0 up
	if err = netlink.LinkSetUp(dae0); err != nil {
		return fmt.Errorf("Failed to set link dae0 up: %v", err)
	}
	// sysctl net.ipv4.conf.dae0.rp_filter=0
	if err = SetRpFilter("dae0", "0"); err != nil {
		return fmt.Errorf("Failed to set rp_filter for dae0: %v", err)
	}
	// sysctl net.ipv4.conf.all.rp_filter=0
	if err = SetRpFilter("all", "0"); err != nil {
		return fmt.Errorf("Failed to set rp_filter for all: %v", err)
	}
	// sysctl net.ipv4.conf.dae0.arp_filter=0
	if err = SetArpFilter("dae0", "0"); err != nil {
		return fmt.Errorf("Failed to set arp_filter for dae0: %v", err)
	}
	// sysctl net.ipv4.conf.all.arp_filter=0
	if err = SetArpFilter("all", "0"); err != nil {
		return fmt.Errorf("Failed to set arp_filter for all: %v", err)
	}
	// sysctl net.ipv4.conf.dae0.accept_local=1
	if err = SetAcceptLocal("dae0", "1"); err != nil {
		return fmt.Errorf("Failed to set accept_local for dae0: %v", err)
	}
	// sysctl net.ipv6.conf.dae0.disable_ipv6=0
	if err = SetDisableIpv6("dae0", "0"); err != nil {
		return fmt.Errorf("Failed to set disable_ipv6 for dae0: %v", err)
	}
	// sysctl net.ipv6.conf.dae0.forwarding=1
	SetForwarding("dae0", "1")
	// sysctl net.ipv6.conf.all.forwarding=1
	SetForwarding("all", "1")
	// ip -6 a a fe80::ecee:eeff:feee:eeee dev dae0 scope link
	if err = netlink.AddrAdd(dae0, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP("fe80::ecee:eeff:feee:eeee"),
			Mask: net.CIDRMask(128, 128),
		},
	}); err != nil {
		return fmt.Errorf("Failed to add v6 addr to dae0: %v", err)
	}
	// ip l s dae0peer netns daens
	if err = netlink.LinkSetNsFd(dae0peer, int(indieNetns)); err != nil {
		return fmt.Errorf("Failed to move dae0peer to daens: %v", err)
	}
	// ip net e daens
	if err = netns.Set(indieNetns); err != nil {
		return fmt.Errorf("Failed to switch to daens: %v", err)
	}
	// (ip net e daens) ip l s dae0peer up
	if err = netlink.LinkSetUp(dae0peer); err != nil {
		return fmt.Errorf("Failed to set link dae0peer up: %v", err)
	}
	// (ip net e daens) ip a a 169.254.0.1 dev dae0peer
	ip, ipNet, err := net.ParseCIDR("169.254.0.1/24")
	ipNet.IP = ip
	if err != nil {
		return fmt.Errorf("Failed to parse ip: %v", err)
	}
	if err = netlink.AddrAdd(dae0peer, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("Failed to add v4 addr to dae0peer: %v", err)
	}
	// (ip net e daens) ip r a default dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		Gw:        nil,
	}); err != nil {
		return fmt.Errorf("Failed to add v4 route to dae0peer: %v", err)
	}
	// (ip net e daens) ip -6 r a default via fe80::ecee:eeff:feee:eeee dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		Gw:        net.ParseIP("fe80::ecee:eeff:feee:eeee"),
	}); err != nil {
		return fmt.Errorf("Failed to add v6 route to dae0peer: %v", err)
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
