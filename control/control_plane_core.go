/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	dnsmessage "github.com/miekg/dns"
	"github.com/mohae/deepcopy"
	"github.com/safchain/ethtool"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// coreFlip should be 0 or 1; accessed atomically.
var coreFlip int32

type controlPlaneCore struct {
	mu sync.Mutex

	log             *logrus.Logger
	deferFuncs      []func() error
	bpf             *bpfObjects
	outboundId2Name map[uint8]string
	tcpRelayOffload bool

	kernelVersion *internal.Version

	flip       int
	isReload   bool
	bpfEjected bool

	closed context.Context
	close  context.CancelFunc
	ifmgr  *component.InterfaceManager
}

func newControlPlaneCore(log *logrus.Logger,
	bpf *bpfObjects,
	outboundId2Name map[uint8]string,
	kernelVersion *internal.Version,
	isReload bool,
) *controlPlaneCore {
	var flip int
	if isReload {
		flip = int(atomic.LoadInt32(&coreFlip)&1 ^ 1)
		atomic.StoreInt32(&coreFlip, int32(flip))
	} else {
		flip = int(atomic.LoadInt32(&coreFlip))
	}
	var deferFuncs []func() error
	if !isReload {
		deferFuncs = append(deferFuncs, bpf.Close)
	}
	closed, toClose := context.WithCancel(context.Background())
	ifmgr := component.NewInterfaceManager(log)
	deferFuncs = append(deferFuncs, ifmgr.Close)
	return &controlPlaneCore{
		log:             log,
		deferFuncs:      deferFuncs,
		bpf:             bpf,
		outboundId2Name: outboundId2Name,
		kernelVersion:   kernelVersion,
		flip:            flip,
		isReload:        isReload,
		bpfEjected:      false,
		ifmgr:           ifmgr,
		closed:          closed,
		close:           toClose,
	}
}

func (c *controlPlaneCore) Flip() {
	// Use CAS loop to avoid race condition between Load and Store.
	for {
		old := atomic.LoadInt32(&coreFlip)
		newVal := old&1 ^ 1
		if atomic.CompareAndSwapInt32(&coreFlip, old, newVal) {
			break
		}
	}
}
func (c *controlPlaneCore) Close() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	// Invoke defer funcs in reverse order and collect errors.
	// Use errors.Join (Go 1.20+) for clean multi-error handling.
	var errs []error
	for i := len(c.deferFuncs) - 1; i >= 0; i-- {
		if e := c.deferFuncs[i](); e != nil {
			errs = append(errs, e)
		}
	}
	c.close()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		return bpfIfParams{}, nil
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		return bpfIfParams{}, nil
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

func (c *controlPlaneCore) linkHdrLen(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, err
	}
	var linkHdrLen uint32
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		linkHdrLen = consts.LinkHdrLen_None
	case "ether":
		linkHdrLen = consts.LinkHdrLen_Ethernet
	default:
		c.log.Warnf("Maybe unsupported link type %v, using default link header length", link.Attrs().EncapType)
		linkHdrLen = consts.LinkHdrLen_Ethernet
	}
	return linkHdrLen, nil
}

// buildClsactQdisc constructs the clsact GenericQdisc descriptor for ifname.
// Shared by addQdisc and delQdisc to avoid duplicating the netlink.LinkByName
// + GenericQdisc construction.
func buildClsactQdisc(ifname string) (netlink.Link, *netlink.GenericQdisc, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil, nil, err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	return link, qdisc, nil
}

func (c *controlPlaneCore) addQdisc(ifname string) error {
	_, qdisc, err := buildClsactQdisc(ifname)
	if err != nil {
		return err
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(ifname string) error {
	_, qdisc, err := buildClsactQdisc(ifname)
	if err != nil {
		return err
	}
	if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("cannot delete clsact qdisc: %w", err)
	} else if errors.Is(err, unix.ENOENT) {
		c.log.Debugf("delQdisc: clsact qdisc not found for %v (already gone)", ifname)
	}
	return nil
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		if err := c._bindLan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindLan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
		if err := c.delQdisc(link.Attrs().Name); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
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
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
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
		Name:         consts.AppName + "_lan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyLanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyLanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	// Remove and add.
	// Best effort to remove old filter; it may not exist.
	_ = netlink.FilterDel(filterIngress)
	if !c.isReload {
		tryDeleteFlippedFilter(filterIngress)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0x2023, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			// Priority should be front of WAN's
			Priority: 1,
		},
		Name:         consts.AppName + "_lan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyLanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyLanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	// Remove and add.
	// Best effort to remove old filter; it may not exist.
	_ = netlink.FilterDel(filterEgress)
	if !c.isReload {
		tryDeleteFlippedFilter(filterEgress)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
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

func (c *controlPlaneCore) setupTCPRelayOffload() error {
	if os.Getenv("DAE_DISABLE_TCP_RELAY_OFFLOAD") == "1" {
		c.log.Debug("TCP relay eBPF offload disabled by DAE_DISABLE_TCP_RELAY_OFFLOAD=1")
		return nil
	}
	if c.bpf.FastSock == nil ||
		c.bpf.TproxyFastRedirectParser == nil ||
		c.bpf.TproxyFastRedirectVerdict == nil {
		return nil
	}

	attachments := []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{
		{prog: c.bpf.TproxyFastRedirectParser, attach: ebpf.AttachSkSKBStreamParser},
		{prog: c.bpf.TproxyFastRedirectVerdict, attach: ebpf.AttachSkSKBStreamVerdict},
	}

	var attached []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}
	for _, item := range attachments {
		if err := ciliumLink.RawAttachProgram(ciliumLink.RawAttachProgramOptions{
			Target:  c.bpf.FastSock.FD(),
			Program: item.prog,
			Attach:  item.attach,
		}); err != nil {
			for i := len(attached) - 1; i >= 0; i-- {
				_ = ciliumLink.RawDetachProgram(ciliumLink.RawDetachProgramOptions{
					Target:  c.bpf.FastSock.FD(),
					Program: attached[i].prog,
					Attach:  attached[i].attach,
				})
			}
			return fmt.Errorf("attach %s: %w", item.prog.String(), err)
		}
		attached = append(attached, item)
	}

	c.tcpRelayOffload = true
	c.deferFuncs = append(c.deferFuncs, func() error {
		var errs []error
		for i := len(attached) - 1; i >= 0; i-- {
			if err := ciliumLink.RawDetachProgram(ciliumLink.RawDetachProgramOptions{
				Target:  c.bpf.FastSock.FD(),
				Program: attached[i].prog,
				Attach:  attached[i].attach,
			}); err != nil {
				errs = append(errs, fmt.Errorf("detach %s: %w", attached[i].prog.String(), err))
			}
		}
		return errors.Join(errs...)
	})
	return nil
}

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string, autoConfigKernelParameter bool) {
	initlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		if err := c._bindWan(link.Attrs().Name); err != nil {
			c.log.Errorf("bindWan: %v", err)
		}
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		initlinkCallback(link)
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Warnf("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
		if err := c.delQdisc(link.Attrs().Name); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	c.ifmgr.RegisterWithPattern(ifname, initlinkCallback, newlinkCallback, dellinkCallback)
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
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(ifname)
	linkHdrLen, err := c.linkHdrLen(ifname)
	if err != nil {
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
		Name:         consts.AppName + "_wan_egress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.bpfPrograms.TproxyWanEgressL3.FD()
		filterEgress.Name = filterEgress.Name + "_l3"
	}
	// Best effort to remove old filter; it may not exist.
	_ = netlink.FilterDel(filterEgress)
	if !c.isReload {
		tryDeleteFlippedFilter(filterEgress)
	}
	if err := netlink.FilterAdd(filterEgress); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
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
		Name:         consts.AppName + "_wan_ingress",
		DirectAction: true,
	}
	if linkHdrLen > 0 {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.bpfPrograms.TproxyWanIngressL3.FD()
		filterIngress.Name = filterIngress.Name + "_l3"
	}
	// Best effort to remove old filter; it may not exist.
	_ = netlink.FilterDel(filterIngress)
	if !c.isReload {
		tryDeleteFlippedFilter(filterIngress)
	}
	if err := netlink.FilterAdd(filterIngress); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	})

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := GetDaeNetns()

	// tproxy_dae0peer_ingress@eth0 at dae netns
	// Best effort: qdisc may already exist and tx queue tuning is non-critical.
	daens.WithBestEffort("set dae0peer tx queue and add clsact qdisc", func() error {
		err := netlink.LinkSetTxQLen(daens.Dae0Peer(), DaeVethTxQLen)
		if err == nil {
			err = c.addQdisc(daens.Dae0Peer().Attrs().Name)
		}
		return err
	})
	filterDae0peerIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0Peer().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0peerIngress.FD(),
		Name:         consts.AppName + "_dae0peer_ingress",
		DirectAction: true,
	}
	// Best effort to remove old filter; it may not exist.
	daens.WithBestEffort("delete old dae0peer ingress filter", func() error {
		return netlink.FilterDel(filterDae0peerIngress)
	})
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly: delete the filter with the flipped handle.
		filterIngressFlipped := deepcopy.Copy(filterDae0peerIngress).(*netlink.BpfFilter)
		filterIngressFlipped.FilterAttrs.Handle ^= 1
		daens.WithBestEffort("delete flipped dae0peer ingress filter", func() error {
			return netlink.FilterDel(filterIngressFlipped) // R-07 fixed: was filterDae0peerIngress
		})
	}
	if err = daens.WithRequired("add dae0peer ingress filter", func() error {
		if err := netlink.FilterAdd(filterDae0peerIngress); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		return daens.WithRequired("delete dae0peer ingress filter", func() error {
			if err := netlink.FilterDel(filterDae0peerIngress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("FilterDel(%v:%v): %w", daens.Dae0Peer().Attrs().Name, filterDae0peerIngress.Name, err)
			}
			return nil
		})
	})

	// tproxy_dae0_ingress@dae0 at host netns
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(daens.Dae0().Attrs().Name)
	filterDae0Ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.bpfPrograms.TproxyDae0Ingress.FD(),
		Name:         consts.AppName + "_dae0_ingress",
		DirectAction: true,
	}
	// Best effort to remove old filter; it may not exist.
	_ = netlink.FilterDel(filterDae0Ingress)
	// Remove and add.
	if !c.isReload {
		tryDeleteFlippedFilter(filterDae0Ingress)
	}
	if err := netlink.FilterAdd(filterDae0Ingress); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}
	c.deferFuncs = append(c.deferFuncs, func() error {
		if err := netlink.FilterDel(filterDae0Ingress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", daens.Dae0().Attrs().Name, filterDae0Ingress.Name, err)
		}
		return nil
	})
	return
}

// tryDeleteFlippedFilter deletes the TC filter obtained by flipping the
// low bit of the handle. Used during non-reload startup to remove any
// stale filter from a previous run that used the opposite flip value.
func tryDeleteFlippedFilter(f *netlink.BpfFilter) {
	flipped := deepcopy.Copy(f).(*netlink.BpfFilter)
	flipped.FilterAttrs.Handle ^= 1
	_ = netlink.FilterDel(flipped)
}

// extractIpsFromDnsCache returns the unique, valid non-unspecified IP addresses
// contained in the A/AAAA records of a DNS cache entry.
func extractIpsFromDnsCache(cache *DnsCache) []netip.Addr {
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
	return ips
}

// BatchUpdateDomainRouting update bpf map domain_routing. Since one IP may have multiple domains, this function should
// be invoked every A/AAAA-record lookup.
func (c *controlPlaneCore) BatchUpdateDomainRouting(cache *DnsCache) error {
	ips := extractIpsFromDnsCache(cache)
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and vals, and BpfMapBatchUpdate.
	// OPTIMIZATION: Pre-allocate capacity to avoid multiple allocations.
	numIps := len(ips)
	keys := make([][4]uint32, 0, numIps)
	vals := make([]bpfDomainRouting, 0, numIps)

	// Pre-check bitmap length compatibility once
	if len(cache.DomainBitmap) != len(bpfDomainRouting{}.Bitmap) {
		return fmt.Errorf("domain bitmap length not sync with kern program")
	}

	for _, ip := range ips {
		ip6 := ip.As16()
		keys = append(keys, common.Ipv6ByteSliceToUint32Array(ip6[:]))
		r := bpfDomainRouting{}
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
	ips := extractIpsFromDnsCache(cache)
	if len(ips) == 0 {
		return nil
	}

	// Update bpf map.
	// Construct keys and BpfMapBatchDelete.
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

	// Stop link watcher immediately during交接 period to avoid race condition
	// between old and new control planes reacting to link events (e.g. PPPoE flapping).
	_ = c.ifmgr.Close()

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
