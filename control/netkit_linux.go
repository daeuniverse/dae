//go:build linux
// +build linux

/*
* SPDX-License-Identifier: AGPL-3.0-only
* Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// Netkit device attributes from linux/if_link.h
const (
	IFLA_NETKIT_PEER_INFO   = 1
	IFLA_NETKIT_PRIMARY     = 2
	IFLA_NETKIT_POLICY      = 3
	IFLA_NETKIT_PEER_POLICY = 4
	IFLA_NETKIT_MODE        = 5
	IFLA_NETKIT_SCRUB       = 6
	IFLA_NETKIT_PEER_SCRUB  = 7
)

// Netkit modes
const (
	NETKIT_L2 = 0
	NETKIT_L3 = 1
)

// createNetkitDeviceViaIpCmd creates a Netkit device pair using the ip command.
// This is the most reliable method as it uses iproute2 which has Netkit support.
func createNetkitDeviceViaIpCmd(name, peerName string, txQLen int) error {
	// Try multiple syntax variations for Netkit device creation

	// Syntax 1: ip link add <name> type netkit peer <peer-name> mode L2
	// This is the most common syntax
	cmd := exec.Command("ip", "link", "add", name, "type", "netkit", "peer", peerName, "mode", "L2")
	output, err := cmd.CombinedOutput()
	if err == nil {
		// Success, set TX queue length
		if txQLen > 0 {
			cmd = exec.Command("ip", "link", "set", name, "txqlen", fmt.Sprintf("%d", txQLen))
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to set txqlen: %w: %s", err, string(output))
			}
		}
		return nil
	}

	// Syntax 2: ip link add name <name> type netkit peer <peer-name> mode L2
	// Alternative syntax
	cmd = exec.Command("ip", "link", "add", "name", name, "type", "netkit", "peer", peerName, "mode", "L2")
	output, err = cmd.CombinedOutput()
	if err == nil {
		// Success, set TX queue length
		if txQLen > 0 {
			cmd = exec.Command("ip", "link", "set", name, "txqlen", fmt.Sprintf("%d", txQLen))
			if output, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to set txqlen: %w: %s", err, string(output))
			}
		}
		return nil
	}

	// Both syntaxes failed, return error
	return fmt.Errorf("failed to create Netkit device (tried multiple syntaxes): %w: %s", err, string(output))
}

// checkIpNetkitSupport checks if the ip command supports Netkit devices.
// It also checks the iproute2 version to provide helpful error messages.
func checkIpNetkitSupport() bool {
	// Try to get iproute2 version first
	cmd := exec.Command("ip", "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Parse version to check if it's >= 6.7.0
	versionStr := string(output)
	// Simple version check for iproute2-6.7.0 and later
	if strings.Contains(versionStr, "iproute2-") {
		// Extract major.minor version
		parts := strings.Split(versionStr, ".")
		if len(parts) >= 2 {
			majorStr := strings.TrimPrefix(parts[0], "iproute2-")
			major := 0
			minor := 0
			fmt.Sscanf(majorStr, "%d", &major)
			fmt.Sscanf(parts[1], "%d", &minor)

			// Check if version is < 6.7
			if major < 6 || (major == 6 && minor < 7) {
				// iproute2 is too old, don't even try to check help text
				return false
			}
		}
	}

	// If version is OK, also check help text for netkit keyword
	cmd = exec.Command("ip", "link", "help")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return false
	}

	// Check if "netkit" is mentioned in the help text
	return strings.Contains(string(output), "netkit")
}

// createNetkitDevice tries multiple methods to create a Netkit device.
// It prefers the netlink API method (doesn't require iproute2 6.7.0+),
// and falls back to the ip command method if needed.
func createNetkitDevice(log *logrus.Logger, name, peerName string, txQLen int) error {
	log.Debug("Attempting to create Netkit device")

	// Method 1: Try using netlink API (preferred)
	// This works even with older iproute2 versions
	log.Debug("Trying netlink API method (doesn't require iproute2 6.7.0+)")
	if err := createNetkitDeviceViaNetlink(log, name, peerName, txQLen); err == nil {
		log.Infof("Successfully created Netkit device pair %s <-> %s using netlink API", name, peerName)
		return nil
	} else {
		log.Debugf("Netlink API method failed: %v (this is expected if kernel < 6.7 or CONFIG_NETKIT not enabled)", err)
	}

	// Method 2: Fall back to ip command (requires iproute2 6.7.0+)
	log.Debug("Trying ip command method (requires iproute2 6.7.0+)")
	if !checkIpNetkitSupport() {
		// Get iproute2 version for better error message
		cmd := exec.Command("ip", "-V")
		output, err := cmd.CombinedOutput()
		versionMsg := "iproute2 version 6.7.0+ required"
		if err == nil {
			versionMsg = fmt.Sprintf("%s (current: %s)", versionMsg, strings.TrimSpace(string(output)))
		}
		log.Infof("ip command does not support Netkit; %s", versionMsg)
		return fmt.Errorf("neither netlink API nor ip command support Netkit (kernel may be < 6.7 or CONFIG_NETKIT not enabled); %s", versionMsg)
	}
	log.Debug("ip command supports Netkit, proceeding with device creation")

	// Create Netkit device using ip command
	if err := createNetkitDeviceViaIpCmd(name, peerName, txQLen); err != nil {
		log.Infof("Failed to create Netkit device via ip command: %v", err)
		return fmt.Errorf("failed to create Netkit device via ip command: %w", err)
	}

	log.Infof("Successfully created Netkit device pair %s <-> %s using ip command", name, peerName)
	return nil
}
