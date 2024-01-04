package control

import (
	"net"
	"os"
	"path"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var indieNetns netns.NsHandle

func WithIndieNetns(f func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNetns, err := netns.Get()
	if err != nil {
		return
	}
	defer netns.Set(hostNetns)

	ns, err := GetIndieNetns()
	if err != nil {
		return
	}
	if err = netns.Set(ns); err != nil {
		return
	}

	return f()
}

func GetIndieNetns() (_ netns.NsHandle, err error) {
	if indieNetns != 0 {
		return indieNetns, nil
	}

	// Setup a new netns
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNetns, err := netns.Get()
	if err != nil {
		return
	}
	defer netns.Set(hostNetns)

	// ip netns a daens
	DeleteNamedNetns("daens")
	indieNetns, err = netns.NewNamed("daens")
	if err != nil {
		return
	}
	if err = netns.Set(hostNetns); err != nil {
		return
	}
	// ip l a dae0 type veth peer name dae0peer
	DeleteLink("dae0")
	if err = netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "dae0",
		},
		PeerName: "dae0peer",
	}); err != nil {
		return
	}
	dae0, err := netlink.LinkByName("dae0")
	if err != nil {
		return
	}
	dae0peer, err := netlink.LinkByName("dae0peer")
	if err != nil {
		return
	}
	// ip l s dae0 up
	if err = netlink.LinkSetUp(dae0); err != nil {
		return
	}
	// sysctl net.ipv4.conf.{dae0,all}.rp_filter=0
	if err = SetRpFilter("dae0", "0"); err != nil {
		return
	}
	if err = SetRpFilter("all", "0"); err != nil {
		return
	}
	// ip l s dae0peer netns daens
	if err = netlink.LinkSetNsFd(dae0peer, int(indieNetns)); err != nil {
		return
	}
	// ip net e daens
	if err = netns.Set(indieNetns); err != nil {
		return
	}
	// (ip net e daens) ip l s dae0peer up
	if err = netlink.LinkSetUp(dae0peer); err != nil {
		return
	}
	// (ip net e daens) ip a a 169.254.0.1 dev dae0peer
	ip, ipNet, err := net.ParseCIDR("169.254.0.1/24")
	ipNet.IP = ip
	if err != nil {
		return
	}
	if err = netlink.AddrAdd(dae0peer, &netlink.Addr{IPNet: ipNet}); err != nil {
		return
	}
	// (ip net e daens) ip r a default dev dae0peer
	if err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: dae0peer.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(0, 32)},
		Gw:        nil,
	}); err != nil {
		return
	}
	return indieNetns, err
}

func DeleteNamedNetns(name string) error {
	namedPath := path.Join("/run/netns", name)
	unix.Unmount(namedPath, unix.MNT_DETACH)
	return os.Remove(namedPath)
}

func DeleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err == nil {
		return netlink.LinkDel(link)
	}
	return err
}
