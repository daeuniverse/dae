//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NetkitConfig holds configuration options for Netkit device creation.
type NetkitConfig struct {
	Name     string
	PeerName string
	TxQLen   int
	// ScrubNone controls whether to disable skb->mark scrubbing.
	// When true, skb->mark is preserved across netkit boundaries, which is
	// required for bpf_redirect_peer(). The loader only enables
	// bpf_redirect_peer() on kernels containing the CVE-2025-37959 fix.
	// This requires kernel support (Linux 6.13+ with CONFIG_NETKIT).
	ScrubNone bool
}

// createNetkitDeviceViaNetlink creates a Netkit device pair using the netlink library.
// This method is preferred over using the ip command because:
// 1. It doesn't require iproute2 6.7.0+
// 2. It's more efficient (no fork/exec)
// 3. It provides better error handling
// 4. It works on systems where ip command doesn't support netkit
//
// It supports configuring scrub behavior when the kernel supports it
// (scrub=NONE is required for bpf_redirect_peer()).
func createNetkitDeviceViaNetlink(log *logrus.Logger, cfg *NetkitConfig) error {
	log.Debug("Attempting to create Netkit device via netlink API")

	attrs := netlink.LinkAttrs{
		Name:   cfg.Name,
		TxQLen: cfg.TxQLen,
	}

	// Create Netkit device configuration.
	// Mode: L2 keeps Ethernet header/MAC semantics aligned with dae's
	// existing veth datapath and IPv6 neighbor setup.
	// Policy: FORWARD (pass traffic normally)
	// PeerPolicy: FORWARD (pass traffic on peer side)
	netkit := &netlink.Netkit{
		LinkAttrs:  attrs,
		Mode:       netlink.NETKIT_MODE_L2,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
	}

	// Configure scrub behavior (scrub=NONE is required for bpf_redirect_peer(),
	// which the loader only enables on CVE-2025-37959-fixed kernels).
	if cfg.ScrubNone {
		netkit.Scrub = netlink.NETKIT_SCRUB_NONE
		netkit.PeerScrub = netlink.NETKIT_SCRUB_NONE
		log.Debug("Configuring netkit with scrub=NONE to preserve skb->mark")
	} else {
		netkit.Scrub = netlink.NETKIT_SCRUB_DEFAULT
		netkit.PeerScrub = netlink.NETKIT_SCRUB_DEFAULT
		log.Debug("Using default netkit scrub behavior (skb->mark will be cleared)")
	}

	// Set peer attributes
	peerAttrs := netlink.NewLinkAttrs()
	peerAttrs.Name = cfg.PeerName
	netkit.SetPeerAttrs(&peerAttrs)

	// Attempt to create the Netkit device
	if err := netlink.LinkAdd(netkit); err != nil {
		log.Debugf("Netlink API failed to create Netkit device: %v", err)
		return fmt.Errorf("netlink.LinkAdd failed: %w", err)
	}

	log.Infof("Successfully created Netkit device pair %s <-> %s via netlink API (scrub=%v)",
		cfg.Name, cfg.PeerName, !cfg.ScrubNone)
	return nil
}

func isZeroMAC(addr net.HardwareAddr) bool {
	if len(addr) == 0 {
		return true
	}
	for _, b := range addr {
		if b != 0 {
			return false
		}
	}
	return true
}

// requireNetkitL2WithMAC rejects a netkit pair that landed in L3 (kernel
// default) or without Ethernet addresses. dae's IPv6 datapath installs a
// permanent NDP neighbor using dae0's MAC; L3 netkit sets IFF_NOARP and
// leaves HardwareAddr empty, which makes that neighbor unusable.
func requireNetkitL2WithMAC(primary, peer netlink.Link) error {
	nk, ok := primary.(*netlink.Netkit)
	if !ok {
		return fmt.Errorf("link %s is %T, want netkit", primary.Attrs().Name, primary)
	}
	if nk.Mode != netlink.NETKIT_MODE_L2 {
		return fmt.Errorf("netkit %s mode is %v, want L2", nk.Attrs().Name, nk.Mode)
	}
	if primary.Attrs().RawFlags&unix.IFF_NOARP != 0 {
		return fmt.Errorf("netkit %s still has IFF_NOARP; L2 mode did not take effect", primary.Attrs().Name)
	}
	if isZeroMAC(primary.Attrs().HardwareAddr) {
		return fmt.Errorf("netkit %s has empty MAC; L2 Ethernet datapath is unusable", primary.Attrs().Name)
	}
	if isZeroMAC(peer.Attrs().HardwareAddr) {
		return fmt.Errorf("netkit %s has empty MAC; L2 Ethernet datapath is unusable", peer.Attrs().Name)
	}
	return nil
}

// checkNetkitScrubSupport checks if the kernel supports netkit scrub attributes.
// The attributes landed in Linux 6.13, after the initial netkit release.
func checkNetkitScrubSupport(log *logrus.Logger) bool {
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		log.Debugf("Failed to get kernel version: %v", err)
		return false
	}

	scrubSupportThreshold := internal.Version{6, 13, 0}
	supportsScrub := !kernelVersion.Less(scrubSupportThreshold)

	if supportsScrub {
		log.Debugf("Kernel %s supports netkit scrub (6.13+)", kernelVersion.String())
	} else {
		log.Debugf("Kernel %s may not support netkit scrub (< 6.13)", kernelVersion.String())
	}

	return supportsScrub
}

func netkitScrubNone(supports bool, primary, peer netlink.NetkitScrub) bool {
	return supports && primary == netlink.NETKIT_SCRUB_NONE && peer == netlink.NETKIT_SCRUB_NONE
}

// checkExistingNetkitScrubConfig checks if an existing netkit device
// has scrub=NONE configured by reading the link attributes.
func checkExistingNetkitScrubConfig(log *logrus.Logger, ifname string) (bool, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return false, err
	}

	netkit, ok := link.(*netlink.Netkit)
	if !ok {
		return false, fmt.Errorf("link %s is not a netkit device", ifname)
	}

	// Attribute absence decodes to zero as well, so presence and both ends
	// must be checked before treating scrub as NONE.
	scrubNone := netkitScrubNone(netkit.SupportsScrub(), netkit.Scrub, netkit.PeerScrub)
	log.Debugf("Netkit device %s: scrub=%v, peer_scrub=%v, supportsScrub=%v",
		ifname, netkit.Scrub, netkit.PeerScrub, netkit.SupportsScrub())

	return scrubNone, nil
}
