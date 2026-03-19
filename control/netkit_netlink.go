//go:build linux
// +build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"

	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// NetkitConfig holds configuration options for Netkit device creation.
type NetkitConfig struct {
	Name     string
	PeerName string
	TxQLen   int
	// ScrubNone controls whether to disable skb->mark scrubbing.
	// When true, skb->mark is preserved across netkit boundaries, allowing
	// bpf_redirect_peer() to work correctly with routing metadata.
	// This requires kernel support (Linux 6.6+ with CONFIG_NETKIT).
	ScrubNone bool
}

// createNetkitDeviceViaNetlink creates a Netkit device pair using the netlink library.
// This method is preferred over using the ip command because:
// 1. It doesn't require iproute2 6.7.0+
// 2. It's more efficient (no fork/exec)
// 3. It provides better error handling
// 4. It works on systems where ip command doesn't support netkit
//
// It supports configuring scrub behavior when the kernel supports it.
func createNetkitDeviceViaNetlink(log *logrus.Logger, cfg *NetkitConfig) error {
	log.Debug("Attempting to create Netkit device via netlink API")

	attrs := netlink.LinkAttrs{
		Name:   cfg.Name,
		TxQLen: cfg.TxQLen,
	}

	// Create Netkit device configuration
	// Mode: L3 (layer 3) - required for dae's use case
	// Policy: FORWARD (pass traffic normally)
	// PeerPolicy: FORWARD (pass traffic on peer side)
	netkit := &netlink.Netkit{
		LinkAttrs:  attrs,
		Mode:       netlink.NETKIT_MODE_L3,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
	}

	// Configure scrub behavior
	// When ScrubNone=true, we set scrub=NETKIT_SCRUB_NONE to preserve skb->mark
	// This enables bpf_redirect_peer() to work correctly with routing metadata
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

// checkNetkitScrubSupport checks if the kernel supports the scrub configuration option.
// Linux 6.6+ has scrub support in the kernel.
func checkNetkitScrubSupport(log *logrus.Logger) bool {
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		log.Debugf("Failed to get kernel version: %v", err)
		return false
	}

	// Linux 6.6+ has scrub support
	scrubSupportThreshold := internal.Version{6, 6, 0}
	supportsScrub := !kernelVersion.Less(scrubSupportThreshold)

	if supportsScrub {
		log.Debugf("Kernel %s supports netkit scrub (6.6+)", kernelVersion.String())
	} else {
		log.Debugf("Kernel %s may not support netkit scrub (< 6.6)", kernelVersion.String())
	}

	return supportsScrub
}

// checkNetkitSupportViaNetlink checks if the kernel supports Netkit devices
// by attempting to query the netlink interface types.
func checkNetkitSupportViaNetlink(log *logrus.Logger) bool {
	log.Debug("Checking Netkit support via netlink API")

	// Try to get list of supported device types
	// If the kernel supports netkit, we should be able to query it
	links, err := netlink.LinkList()
	if err != nil {
		log.Debugf("Failed to list links: %v", err)
		return false
	}

	// Check if any netkit devices exist (indicates kernel support)
	for _, link := range links {
		if link.Type() == "netkit" {
			log.Debugf("Found existing netkit device: %s", link.Attrs().Name)
			return true
		}
	}

	// No netkit devices found, but that doesn't mean it's not supported
	// The only way to know for sure is to try creating one
	log.Debug("No existing netkit devices found, will attempt creation")
	return true // Optimistic - try creation and handle failure
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

	// Check if scrub is set to NONE (0)
	scrubNone := netkit.Scrub == netlink.NETKIT_SCRUB_NONE
	log.Debugf("Netkit device %s: scrub=%v, peer_scrub=%v, supportsScrub=%v",
		ifname, netkit.Scrub, netkit.PeerScrub, netkit.SupportsScrub())

	return scrubNone, nil
}
