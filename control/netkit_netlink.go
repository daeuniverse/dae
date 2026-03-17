//go:build linux
// +build linux

/*
* SPDX-License-Identifier: AGPL-3.0-only
* Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// createNetkitDeviceViaNetlink creates a Netkit device pair using the netlink library.
// This method is preferred over using the ip command because:
// 1. It doesn't require iproute2 6.7.0+
// 2. It's more efficient (no fork/exec)
// 3. It provides better error handling
// 4. It works on systems where ip command doesn't support netkit
//
// However, it still requires:
// - Linux kernel ≥ 6.7 with CONFIG_NETKIT enabled
func createNetkitDeviceViaNetlink(log *logrus.Logger, name, peerName string, txQLen int) error {
	log.Debug("Attempting to create Netkit device via netlink API")

	// Check if netlink library supports Netkit
	// This is a compile-time check - the library must support Netkit types
	// The current version (v1.3.1) does support it

	attrs := netlink.LinkAttrs{
		Name:   name,
		TxQLen: txQLen,
	}

	// Create Netkit device configuration
	// Mode: L2 (layer 2) - works like veth
	// Policy: FORWARD (pass traffic normally)
	// PeerPolicy: FORWARD (pass traffic on peer side)
	netkit := &netlink.Netkit{
		LinkAttrs:  attrs,
		Mode:       netlink.NETKIT_MODE_L2,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_FORWARD,
	}

	// Set peer attributes
	peerAttrs := netlink.NewLinkAttrs()
	peerAttrs.Name = peerName
	netkit.SetPeerAttrs(&peerAttrs)

	// Attempt to create the Netkit device
	if err := netlink.LinkAdd(netkit); err != nil {
		log.Debugf("Netlink API failed to create Netkit device: %v", err)
		return fmt.Errorf("netlink.LinkAdd failed: %w", err)
	}

	log.Infof("Successfully created Netkit device pair %s <-> %s via netlink API",
		name, peerName)
	return nil
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
