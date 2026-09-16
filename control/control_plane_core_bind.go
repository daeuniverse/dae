/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func getIfParamsFromLink(link netlink.Link) (ifParams bpfIfParams, err error) {
	// Get link offload features.
	et, err := ethtool.NewEthtool()
	if err != nil {
		// ethtool may be unavailable in restricted environments (e.g. containers
		// without CAP_NET_ADMIN). Silently degrade to defaults.
		return bpfIfParams{}, nil
	}
	defer et.Close()
	features, err := et.Features(link.Attrs().Name)
	if err != nil {
		// Virtual interfaces (TUN/TAP, WireGuard, etc.) or older kernels
		// may not support ETHTOOL_GFEATURES.  Silently degrade to defaults
		// (all offload flags = false) rather than blocking interface binding.
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

func makeTCHookSpec(scope tcHookScope, link netlink.Link, direction tcHookDirection, priority uint16, major uint16, program *ebpf.Program, name string, run func(func() error) error) tcHookSpec {
	return tcHookSpec{
		Scope:     scope,
		Ifindex:   link.Attrs().Index,
		Ifname:    link.Attrs().Name,
		Direction: direction,
		Priority:  priority,
		Handle:    netlink.MakeHandle(major, priority*2),
		Name:      name,
		Program:   program,
		Run:       run,
	}
}

func (c *controlPlaneCore) configureTCHookPatterns(lanPatterns, wanPatterns []string) {
	c.interfacePatternMu.Lock()
	c.tcHookLanPatterns = append(c.tcHookLanPatterns[:0], lanPatterns...)
	c.tcHookWanPatterns = append(c.tcHookWanPatterns[:0], wanPatterns...)
	c.interfacePatternMu.Unlock()
}

func (c *controlPlaneCore) isDualRoleTCInterface(ifname string) bool {
	c.interfacePatternMu.Lock()
	defer c.interfacePatternMu.Unlock()
	return matchesAnyInterfacePattern(c.tcHookLanPatterns, ifname) &&
		matchesAnyInterfacePattern(c.tcHookWanPatterns, ifname)
}

func matchesAnyInterfacePattern(patterns []string, ifname string) bool {
	for _, pattern := range patterns {
		if matched, err := path.Match(pattern, ifname); err == nil && matched {
			return true
		}
	}
	return false
}

type dualRoleTCHookPrograms struct {
	ingress     *ebpf.Program
	ingressName string
	egress      *ebpf.Program
	egressName  string
}

func selectDualRoleTCHookPrograms(bpf *bpfObjects, layer2 bool) dualRoleTCHookPrograms {
	if layer2 {
		return dualRoleTCHookPrograms{
			ingress:     bpf.TproxyWanLanIngressL2,
			ingressName: consts.AppName + "_wan_lan_ingress_l2",
			egress:      bpf.TproxyLanWanEgressL2,
			egressName:  consts.AppName + "_lan_wan_egress_l2",
		}
	}
	return dualRoleTCHookPrograms{
		ingress:     bpf.TproxyWanLanIngressL3,
		ingressName: consts.AppName + "_wan_lan_ingress_l3",
		egress:      bpf.TproxyLanWanEgressL3,
		egressName:  consts.AppName + "_lan_wan_egress_l3",
	}
}

// bindLan automatically configures kernel parameters and bind to lan interface `ifname`.
// bindLan supports lazy-bind if interface `ifname` is not found.
// bindLan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindLan(ifname string, autoConfigKernelParameter bool) error {
	attach := func(link netlink.Link) error {
		if link.Attrs().Name == HostVethName {
			return nil
		}
		if !c.beginBpfHookAttach() {
			return nil
		}
		defer c.endBpfHookAttach()
		if autoConfigKernelParameter {
			SetSendRedirects(link.Attrs().Name, "0")
			SetForwarding(link.Attrs().Name, "1")
		}
		return c._bindLan(link.Attrs().Name)
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		// A link that appears late (veth created after dae started) is the
		// lazy-bind milestone this callback exists for, so it is info, not a
		// warning: it is expected operation, and the bind outcome below carries
		// the anomaly when there is one.
		c.log.Infof("New link creation of '%v' is detected. Bind LAN program to it.", link.Attrs().Name)
		c.logBindOutcome(link.Attrs().Name, true, attach(link))
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Infof("Link deletion of '%v' is detected. Bind LAN program to it once it is re-created.", link.Attrs().Name)
		c.forgetBindState(link.Attrs().Name)
		if err := c.removeTCHooksForInterface(tcHookScopeHost, link.Attrs().Index); err != nil {
			c.log.Errorf("remove TC hooks: %v", err)
		}
		if err := c.delQdisc(link); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	if err := c.registerInterfacePattern(ifname, true, newlinkCallback, dellinkCallback); err != nil {
		return err
	}
	return c.attachMatchingInterfaces(ifname, attach)
}

func (c *controlPlaneCore) _bindLan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	bpf := c.bpf.Load()
	if bpf == nil {
		return nil
	}
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

	ingressProgram := bpf.TproxyLanIngressL3
	ingressName := consts.AppName + "_lan_ingress_l3"
	ingressPriority := uint16(2)
	egressProgram := bpf.TproxyLanEgressL3
	egressName := consts.AppName + "_lan_egress_l3"
	if c.isDualRoleTCInterface(ifname) {
		programs := selectDualRoleTCHookPrograms(bpf, linkHdrLen > 0)
		ingressProgram = programs.ingress
		ingressName = programs.ingressName
		ingressPriority = 1
		egressProgram = programs.egress
		egressName = programs.egressName
	} else if linkHdrLen > 0 {
		ingressProgram = bpf.TproxyLanIngressL2
		ingressName = consts.AppName + "_lan_ingress_l2"
		egressProgram = bpf.TproxyLanEgressL2
		egressName = consts.AppName + "_lan_egress_l2"
	}
	if err := c.stageTCHook(makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, ingressPriority, 0x2023, ingressProgram, ingressName, nil)); err != nil {
		return fmt.Errorf("install LAN ingress hook: %w", err)
	}
	if err := c.stageTCHook(makeTCHookSpec(tcHookScopeHost, link, tcHookEgress, 1, 0x2023, egressProgram, egressName, nil)); err != nil {
		return fmt.Errorf("install LAN egress hook: %w", err)
	}

	return nil
}

func (c *controlPlaneCore) setupSkPidMonitor() error {
	select {
	case <-c.closed.Done():
		return nil
	default:
	}
	/// Set-up SrcPidMapper.
	/// Attach programs to support pname routing.
	// Get the first-mounted cgroupv2 path.
	cgroupPath, err := detectCgroupPathFunc()
	if err != nil {
		return err
	}
	// Bind cg programs
	type cgProg struct {
		Name   string
		Prog   *ebpf.Program
		Attach ebpf.AttachType
	}
	bpf := c.bpf.Load()
	cgProgs := []cgProg{
		{Name: "sock_create", Prog: bpf.TproxyWanCgSockCreate, Attach: ebpf.AttachCGroupInetSockCreate},
		{Name: "sock_release", Prog: bpf.TproxyWanCgSockRelease, Attach: ebpf.AttachCgroupInetSockRelease},
		{Name: "connect4", Prog: bpf.TproxyWanCgConnect4, Attach: ebpf.AttachCGroupInet4Connect},
		{Name: "connect6", Prog: bpf.TproxyWanCgConnect6, Attach: ebpf.AttachCGroupInet6Connect},
		{Name: "sendmsg4", Prog: bpf.TproxyWanCgSendmsg4, Attach: ebpf.AttachCGroupUDP4Sendmsg},
		{Name: "sendmsg6", Prog: bpf.TproxyWanCgSendmsg6, Attach: ebpf.AttachCGroupUDP6Sendmsg},
	}
	attachedLinks := make([]cgroupAttachment, 0, len(cgProgs))
	detachFuncs := make([]func() error, 0, len(cgProgs))
	for _, prog := range cgProgs {
		attached, err := attachCgroupFunc(ciliumLink.CgroupOptions{
			Path:    cgroupPath,
			Attach:  prog.Attach,
			Program: prog.Prog,
		})
		if err != nil {
			for i := len(attachedLinks) - 1; i >= 0; i-- {
				_ = attachedLinks[i].Close()
			}
			return fmt.Errorf("AttachCgroup: %v: %w", prog.Prog.String(), err)
		}
		attachedLinks = append(attachedLinks, attached)
		attachedLink := attached
		progName := prog.Name
		detachFunc := func() error {
			if err := attachedLink.Close(); err != nil {
				return fmt.Errorf("cgroup %s detach: %w", progName, err)
			}
			return nil
		}
		detachFuncs = append(detachFuncs, detachFunc)
	}
	for _, detachFunc := range detachFuncs {
		c.addManagedBpfHookCleanup(detachFunc)
	}
	return nil
}

func (c *controlPlaneCore) setupTCPRelayOffload() error {
	// Idempotent: reload/rollback paths re-enter commitInterfaceBindings with
	// the same loaded program objects, and resetBpfHookDetachForReattach does
	// not close the links attached by a previous pass. Re-attaching the fentry
	// link while the first one is alive is rejected by the kernel with EBUSY
	// ("prog already linked", kernel/bpf/trampoline.c
	// __bpf_trampoline_link_prog), which surfaced as a spurious
	// "TCP relay eBPF offload disabled" on rollback.
	if c.tcpSockmapOffloadReady.Load() {
		return nil
	}
	if os.Getenv("DAE_DISABLE_TCP_RELAY_OFFLOAD") == "1" {
		c.log.Debug("TCP relay eBPF offload disabled by DAE_DISABLE_TCP_RELAY_OFFLOAD=1")
		return nil
	}

	// Opt-in only. The sockmap redirect was removed upstream (dae#912) after
	// CVE-2025-38165 ("bpf, sockmap: Fix panic when calling skb_linearize")
	// and because the psock ingress_skb queue is still not charged to socket
	// buffers/memcg (bpf-next 2025-04 series issue #4, unfixed), so a
	// slow-reading peer can grow kernel memory without bound. The user-space
	// session enforces tcpOffloadMaxPeerBacklog as a mitigation, but the
	// feature stays off unless explicitly enabled.
	if os.Getenv("DAE_ALLOW_TCP_SOCKMAP") != "1" {
		c.log.Debug("TCP relay eBPF offload disabled (opt-in via DAE_ALLOW_TCP_SOCKMAP=1)")
		return nil
	}

	bpf := c.bpf.Load()
	if bpf == nil || bpf.FastSock == nil || bpf.TcpOffloadRedirect == nil || bpf.TcpOffloadSent == nil || bpf.TcpOffloadPause == nil || bpf.TcpOffloadSentAccount == nil {
		return fmt.Errorf("fast_sock, tcp_offload_redirect, tcp_offload_pause, tcp_offload_sent or tcp_offload_sent_account unavailable")
	}

	switch {
	case c.kernelVersion == nil:
		return fmt.Errorf("kernel version unavailable")
	case consts.IsTcpSockmapPanicSafeKernel(*c.kernelVersion):
		c.log.Infof("Enabling TCP relay eBPF offload (kernel %v has the CVE-2025-38165 fix)", *c.kernelVersion)
	default:
		c.log.Warnf("Enabling TCP relay eBPF offload via DAE_ALLOW_TCP_SOCKMAP on kernel %v without a known CVE-2025-38165 fix; a message larger than ~100KB redirected between relay sockets can panic this kernel", *c.kernelVersion)
	}

	// The links target maps/programs inside the shared bpfObjects, which are
	// handed over to the next generation on reload while this core's cleanup
	// list is not run until the old generation finalizes. attachTCPOffloadLinks
	// therefore keys the links (and their reference count) by the bpfObjects
	// themselves: a reload reuses the still-attached links instead of
	// re-attaching and hitting EBUSY on fast_sock.
	reused, err := attachTCPOffloadLinks(bpf, func() (tcpOffloadLinks, error) {
		rawLink, err := ciliumLink.AttachRawLink(ciliumLink.RawLinkOptions{
			Target:  bpf.FastSock.FD(),
			Program: bpf.TcpOffloadRedirect,
			Attach:  ebpf.AttachSkSKBStreamVerdict,
		})
		if err != nil {
			return tcpOffloadLinks{}, fmt.Errorf("attach tcp_offload_redirect to fast_sock: %w", err)
		}
		var account io.Closer
		// Backlog-fuse accounting: count bytes entering each relay socket's
		// send path, keyed by reversed four-tuple. The selector prefers an
		// addressable inner implementation over a potentially bypassed wrapper.
		// DAE_FUSE_ACCOUNT=0 skips the attach (diagnostics only: the backlog
		// fuse cannot engage without the accounting).
		if os.Getenv("DAE_FUSE_ACCOUNT") != "0" {
			sentLink, hook, err := attachTCPOffloadAccount(bpf.TcpOffloadSentAccount, bpf.TcpOffloadSentAccountKprobe)
			if err != nil {
				// Without the accounting the backlog fuse cannot engage, so the
				// verdict program is useless; drop it so a retry starts clean.
				_ = rawLink.Close()
				return tcpOffloadLinks{}, fmt.Errorf("attach tcp_offload_sent_account: %w", err)
			}
			c.log.Debugf("TCP relay eBPF offload accounting attached to %s", hook)
			account = sentLink
		}
		return tcpOffloadLinks{verdict: rawLink, account: account}, nil
	})
	if err != nil {
		return err
	}
	c.addManagedBpfHookCleanup(func() error {
		releaseTCPOffloadLinks(bpf)
		return nil
	})

	c.tcpSockmapOffloadReady.Store(true)
	if reused {
		c.log.Debug("TCP relay eBPF offload links reused from the previous datapath generation")
	} else {
		c.log.Info("TCP relay eBPF offload enabled (sk_skb stream verdict on fast_sock)")
	}
	return nil
}

// tcpRelayOffloadAccountTarget matches the embedded fentry program's target.
// Use this wrapper only when no addressable inner implementation is present;
// LTO can bypass it on the sk_psock_handle_skb send path. skb_send_sock_locked
// is not an alternative: it serves espintcp, not sockmap verdict egress.
const tcpRelayOffloadAccountTarget = "skb_send_sock"

func tcpOffloadKprobeFallbackSupported(goarch string) bool {
	return goarch == "amd64"
}

// bindWan supports lazy-bind if interface `ifname` is not found.
// bindWan supports rebinding when the interface `ifname` is detected in the future.
func (c *controlPlaneCore) bindWan(ifname string) error {
	attach := func(link netlink.Link) error {
		if link.Attrs().Name == HostVethName {
			return nil
		}
		if !c.beginBpfHookAttach() {
			return nil
		}
		defer c.endBpfHookAttach()
		return c._bindWan(link.Attrs().Name)
	}
	newlinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		// See bindLan: a late link is the lazy-bind milestone, the bind
		// outcome below carries the anomaly.
		c.log.Infof("New link creation of '%v' is detected. Bind WAN program to it.", link.Attrs().Name)
		c.logBindOutcome(link.Attrs().Name, false, attach(link))
	}
	dellinkCallback := func(link netlink.Link) {
		if link.Attrs().Name == HostVethName {
			return
		}
		c.log.Infof("Link deletion of '%v' is detected. Bind WAN program to it once it is re-created.", link.Attrs().Name)
		c.forgetBindState(link.Attrs().Name)
		if err := c.removeTCHooksForInterface(tcHookScopeHost, link.Attrs().Index); err != nil {
			c.log.Errorf("remove TC hooks: %v", err)
		}
		if err := c.delQdisc(link); err != nil {
			c.log.Errorf("delQdisc: %v", err)
		}
	}
	if err := c.registerInterfacePattern(ifname, false, newlinkCallback, dellinkCallback); err != nil {
		return err
	}
	return c.attachMatchingInterfaces(ifname, attach)
}

func (c *controlPlaneCore) registerInterfacePattern(
	pattern string,
	lan bool,
	newCallback func(netlink.Link),
	delCallback func(netlink.Link),
) error {
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid interface pattern %q: %w", pattern, err)
	}

	c.interfacePatternMu.Lock()
	defer c.interfacePatternMu.Unlock()
	registered := c.registeredWanPatterns
	if lan {
		registered = c.registeredLanPatterns
	}
	if registered == nil {
		registered = make(map[string]struct{})
		if lan {
			c.registeredLanPatterns = registered
		} else {
			c.registeredWanPatterns = registered
		}
	}
	if _, ok := registered[pattern]; ok {
		return nil
	}
	c.ifmgr.RegisterWithPattern(pattern, nil, newCallback, delCallback)
	registered[pattern] = struct{}{}
	return nil
}

func (c *controlPlaneCore) attachMatchingInterfaces(pattern string, attach func(netlink.Link) error) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list interfaces for pattern %q: %w", pattern, err)
	}
	for _, link := range links {
		matched, matchErr := path.Match(pattern, link.Attrs().Name)
		if matchErr != nil {
			return fmt.Errorf("match interface pattern %q: %w", pattern, matchErr)
		}
		if !matched {
			continue
		}
		if err := attach(link); err != nil {
			return fmt.Errorf("attach interface %s: %w", link.Attrs().Name, err)
		}
	}
	return nil
}

func (c *controlPlaneCore) _bindWan(ifname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	bpf := c.bpf.Load()
	if bpf == nil {
		return nil
	}
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

	egressProgram := bpf.TproxyWanEgressL3
	egressName := consts.AppName + "_wan_egress_l3"
	egressPriority := uint16(2)
	ingressProgram := bpf.TproxyWanIngressL3
	ingressName := consts.AppName + "_wan_ingress_l3"
	if c.isDualRoleTCInterface(ifname) {
		programs := selectDualRoleTCHookPrograms(bpf, linkHdrLen > 0)
		egressProgram = programs.egress
		egressName = programs.egressName
		egressPriority = 1
		ingressProgram = programs.ingress
		ingressName = programs.ingressName
	} else if linkHdrLen > 0 {
		egressProgram = bpf.TproxyWanEgressL2
		egressName = consts.AppName + "_wan_egress_l2"
		ingressProgram = bpf.TproxyWanIngressL2
		ingressName = consts.AppName + "_wan_ingress_l2"
	}
	if err := c.stageTCHook(makeTCHookSpec(tcHookScopeHost, link, tcHookEgress, egressPriority, 0x2023, egressProgram, egressName, nil)); err != nil {
		return fmt.Errorf("install WAN egress hook: %w", err)
	}
	if err := c.stageTCHook(makeTCHookSpec(tcHookScopeHost, link, tcHookIngress, 1, 0x2023, ingressProgram, ingressName, nil)); err != nil {
		return fmt.Errorf("install WAN ingress hook: %w", err)
	}

	return nil
}

func (c *controlPlaneCore) bindDaens() (err error) {
	bpf := c.bpf.Load()
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
	runInDaeNetns := func(operation func() error) error {
		return daens.WithRequired("manage dae0peer TC hook", operation)
	}
	if err = c.stageTCHook(makeTCHookSpec(
		tcHookScopeDae,
		daens.Dae0Peer(),
		tcHookIngress,
		1,
		0x2022,
		bpf.TproxyDae0peerIngress,
		consts.AppName+"_dae0peer_ingress",
		runInDaeNetns,
	)); err != nil {
		return fmt.Errorf("install dae0peer ingress hook: %w", err)
	}

	// tproxy_dae0_ingress@dae0 at host netns
	// Best effort to add qdisc; it may already exist.
	_ = c.addQdisc(daens.Dae0())
	if err = c.stageTCHook(makeTCHookSpec(
		tcHookScopeHost,
		daens.Dae0(),
		tcHookIngress,
		1,
		0x2022,
		bpf.TproxyDae0Ingress,
		consts.AppName+"_dae0_ingress",
		nil,
	)); err != nil {
		return fmt.Errorf("install dae0 ingress hook: %w", err)
	}
	return
}
