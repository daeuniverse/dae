/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package control

import (
	"fmt"
	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	internal "github.com/v2rayA/dae/pkg/ebpf_internal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net/netip"
	"os"
)

type ControlPlaneCore struct {
	log        *logrus.Logger
	deferFuncs []func() error
	bpf        *bpfObjects

	kernelVersion *internal.Version
}

func (c *ControlPlaneCore) Close() (err error) {
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

func (c *ControlPlaneCore) BindLan(ifname string) error {
	c.log.Infof("Bind to LAN: %v", ifname)
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
		Fd:           c.bpf.bpfPrograms.TproxyLanIngress.FD(),
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
		Fd:           c.bpf.bpfPrograms.TproxyLanEgress.FD(),
		Name:         consts.AppName + "_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	return nil
}

func (c *ControlPlaneCore) BindWan(ifname string) error {
	c.log.Infof("Bind to WAN: %v", ifname)
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

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
		//{Prog: c.bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		//{Prog: c.bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		//{Prog: c.bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		//{Prog: c.bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, prog := range cgProgs {
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			return fmt.Errorf("AttachTracing: %v: %w", prog.Prog.String(), err)
		}
		c.deferFuncs = append(c.deferFuncs, func() error {
			if err := attached.Close(); err != nil {
				return fmt.Errorf("inet6Bind.Close(): %w", err)
			}
			return nil
		})
	}

	/// Set-up WAN ingress/egress TC programs.
	// Insert qdisc.
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

	// Insert TC filters
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyWanEgress.FD(),
		Name:         consts.AppName + "_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filterEgress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyWanIngress.FD(),
		Name:         consts.AppName + "_ingress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filterIngress); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	return nil
}
