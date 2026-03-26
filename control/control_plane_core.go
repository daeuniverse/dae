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

	log        *logrus.Logger
	deferFuncs []func() error
	// bpfHookDetachFuncs contains only BPF hook detachment functions (FilterDel, tc detach)
	// These are tracked separately so they can be detached immediately on SIGTERM
	// before other cleanup that might take longer (like dialer shutdown).
	// Protected by bpfHookMu to avoid deadlock with c.mu in _bindLan/_bindWan.
	bpfHookDetachFuncs []func() error
	bpfHookMu          sync.Mutex
	bpf                *bpfObjects
	outboundId2Name    map[uint8]string
	// tcpRelayOffload is permanently disabled due to kernel panic issues.
	// See: https://github.com/daeuniverse/dae/pull/912
	// Field preserved for ABI compatibility; always remains false.

	kernelVersion *internal.Version

	flip             int
	isReload         bool
	bpfEjected       bool
	bpfHooksDetached bool // Track if BPF hooks were already detached

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
		log:                log,
		deferFuncs:         deferFuncs,
		bpfHookDetachFuncs: make([]func() error, 0),
		bpf:                bpf,
		outboundId2Name:    outboundId2Name,
		kernelVersion:      kernelVersion,
		flip:               flip,
		isReload:           isReload,
		bpfEjected:         false,
		bpfHooksDetached:   false,
		ifmgr:              ifmgr,
		closed:             closed,
		close:              toClose,
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

// addBpfHookDetach adds a BPF hook detachment function to the dedicated list.
// These functions will be executed immediately on SIGTERM before other cleanup.
// Uses bpfHookMu to avoid deadlock with c.mu held by callers like _bindLan/_bindWan.
func (c *controlPlaneCore) addBpfHookDetach(detachFunc func() error) {
	c.bpfHookMu.Lock()
	defer c.bpfHookMu.Unlock()
	c.bpfHookDetachFuncs = append(c.bpfHookDetachFuncs, detachFunc)
}

// DetachBpfHooks immediately detaches all BPF hooks from the system.
// This should be called first when receiving SIGTERM to ensure network is restored
// even if the rest of the shutdown process takes too long and gets SIGKILL'd.
// This is safe to call multiple times - subsequent calls will be no-ops.
func (c *controlPlaneCore) DetachBpfHooks() error {
	c.bpfHookMu.Lock()
	defer c.bpfHookMu.Unlock()

	// Already detached, skip
	if c.bpfHooksDetached {
		return nil
	}

	c.log.Infoln("[Shutdown] Detaching BPF hooks immediately to restore network")

	var errs []error
	// Execute in reverse order (last attached, first detached)
	for i := len(c.bpfHookDetachFuncs) - 1; i >= 0; i-- {
		if e := c.bpfHookDetachFuncs[i](); e != nil {
			// Log but continue detaching other hooks
			c.log.WithError(e).Warnln("[Shutdown] Failed to detach BPF hook")
			errs = append(errs, e)
		}
	}

	c.bpfHooksDetached = true
	c.log.Infoln("[Shutdown] BPF hooks detached, network should be restored")

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
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

func buildClsactQdisc(link netlink.Link) *netlink.GenericQdisc {
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
}

func (c *controlPlaneCore) addQdisc(link netlink.Link) error {
	qdisc := buildClsactQdisc(link)
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("cannot add clsact qdisc: %w", err)
	}
	return nil
}

func (c *controlPlaneCore) delQdisc(link netlink.Link) error {
	qdisc := buildClsactQdisc(link)
	if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("cannot delete clsact qdisc: %w", err)
	} else if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		c.log.Debugf("delQdisc: clsact qdisc or link not found for %v (already gone)", link.Attrs().Name)
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
		if err := c.delQdisc(link); err != nil {
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
	_ = c.addQdisc(link)
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
		filterIngress.Fd = c.bpf.TproxyLanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.TproxyLanIngressL3.FD()
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
	detachFunc := func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	}
	c.deferFuncs = append(c.deferFuncs, detachFunc)
	c.addBpfHookDetach(detachFunc)

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
		filterEgress.Fd = c.bpf.TproxyLanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.TproxyLanEgressL3.FD()
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
	egressDetachFunc := func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	}
	c.deferFuncs = append(c.deferFuncs, egressDetachFunc)
	c.addBpfHookDetach(egressDetachFunc)

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
		detachFunc := func() error {
			if err := attached.Close(); err != nil {
				return fmt.Errorf("inet6Bind.Close(): %w", err)
			}
			return nil
		}
		c.deferFuncs = append(c.deferFuncs, detachFunc)
		c.addBpfHookDetach(detachFunc)
	}
	return nil
}

func (c *controlPlaneCore) setupTCPRelayOffload() error {
	if os.Getenv("DAE_DISABLE_TCP_RELAY_OFFLOAD") == "1" {
		c.log.Debug("TCP relay eBPF offload disabled by DAE_DISABLE_TCP_RELAY_OFFLOAD=1")
		return nil
	}
	// TCP relay eBPF offload is disabled due to kernel panic issues with bpf_msg_redirect_hash().
	// See: https://github.com/daeuniverse/dae/pull/912
	// The sk_msg program now returns SK_PASS, so we must not enable offload or connections will hang.
	// The function body below is preserved for potential future re-enabling.
	c.log.Info("TCP relay eBPF offload is disabled due to kernel panic issues; falling back to userspace relay")
	return nil
}

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string) {
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
		if err := c.delQdisc(link); err != nil {
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
	_ = c.addQdisc(link)
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
		filterEgress.Fd = c.bpf.TproxyWanEgressL2.FD()
		filterEgress.Name = filterEgress.Name + "_l2"
	} else {
		filterEgress.Fd = c.bpf.TproxyWanEgressL3.FD()
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
	egressDetachFunc := func() error {
		if err := netlink.FilterDel(filterEgress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterEgress.Name, err)
		}
		return nil
	}
	c.deferFuncs = append(c.deferFuncs, egressDetachFunc)
	c.addBpfHookDetach(egressDetachFunc)

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
		filterIngress.Fd = c.bpf.TproxyWanIngressL2.FD()
		filterIngress.Name = filterIngress.Name + "_l2"
	} else {
		filterIngress.Fd = c.bpf.TproxyWanIngressL3.FD()
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
	detachFunc := func() error {
		if err := netlink.FilterDel(filterIngress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", ifname, filterIngress.Name, err)
		}
		return nil
	}
	c.deferFuncs = append(c.deferFuncs, detachFunc)
	c.addBpfHookDetach(detachFunc)

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	daens := GetDaeNetns()

	// tproxy_dae0peer_ingress@eth0 at dae netns
	// Best effort: qdisc may already exist and tx queue tuning is non-critical.
	daens.WithBestEffort("set dae0peer tx queue and add clsact qdisc", func() error {
		err := netlink.LinkSetTxQLen(daens.Dae0Peer(), DaeVethTxQLen)
		if err == nil {
			err = c.addQdisc(daens.Dae0Peer())
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
		Fd:           c.bpf.TproxyDae0peerIngress.FD(),
		Name:         consts.AppName + "_dae0peer_ingress",
		DirectAction: true,
	}
	// Best effort to remove old filter; it may not exist.
	daens.WithBestEffort("delete old dae0peer ingress filter", func() error {
		err := netlink.FilterDel(filterDae0peerIngress)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return nil
		}
		return err
	})
	// Remove and add.
	if !c.isReload {
		// Clean up thoroughly: delete the filter with the flipped handle.
		filterIngressFlipped := deepcopy.Copy(filterDae0peerIngress).(*netlink.BpfFilter)
		filterIngressFlipped.Handle ^= 1
		daens.WithBestEffort("delete flipped dae0peer ingress filter", func() error {
			err := netlink.FilterDel(filterIngressFlipped)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
				return nil
			}
			return err
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
	detachFunc := func() error {
		return daens.WithRequired("delete dae0peer ingress filter", func() error {
			if err := netlink.FilterDel(filterDae0peerIngress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("FilterDel(%v:%v): %w", daens.Dae0Peer().Attrs().Name, filterDae0peerIngress.Name, err)
			}
			return nil
		})
	}
	c.deferFuncs = append(c.deferFuncs, detachFunc)
	c.addBpfHookDetach(detachFunc)

	// tproxy_dae0_ingress@dae0 at host netns
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(daens.Dae0())
	filterDae0Ingress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: daens.Dae0().Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0x2022, 0b010+uint16(c.flip)),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
		Fd:           c.bpf.TproxyDae0Ingress.FD(),
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
	dae0DetachFunc := func() error {
		if err := netlink.FilterDel(filterDae0Ingress); err != nil && !os.IsNotExist(err) && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("FilterDel(%v:%v): %w", daens.Dae0().Attrs().Name, filterDae0Ingress.Name, err)
		}
		return nil
	}
	c.deferFuncs = append(c.deferFuncs, dae0DetachFunc)
	c.addBpfHookDetach(dae0DetachFunc)
	return
}

// tryDeleteFlippedFilter deletes the TC filter obtained by flipping the
// low bit of the handle. Used during non-reload startup to remove any
// stale filter from a previous run that used the opposite flip value.
func tryDeleteFlippedFilter(f *netlink.BpfFilter) {
	flipped := deepcopy.Copy(f).(*netlink.BpfFilter)
	flipped.Handle ^= 1
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
	if c.bpfEjected {
		return c.bpf
	}
	if !c.isReload {
		c.deferFuncs = c.deferFuncs[1:]
	}
	c.bpfEjected = true

	// Stop link watcher immediately during handover period to avoid race condition
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
}

// PeekBpf returns the current BPF objects without transferring ownership.
// Background maintenance paths such as janitors and health checks should use
// this accessor instead of EjectBpf to avoid disturbing reload lifecycle.
func (c *controlPlaneCore) PeekBpf() *bpfObjects {
	return c.bpf
}
