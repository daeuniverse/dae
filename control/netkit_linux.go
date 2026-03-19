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
// When scrubNone is true, it attempts to set scrub=0 to preserve skb->mark.
func createNetkitDeviceViaIpCmd(name, peerName string, txQLen int, scrubNone bool) error {
	// Try multiple syntax variations for Netkit device creation

	// Build base command arguments
	args := []string{"link", "add", name, "type", "netkit", "peer", peerName}

	// Add mode
	args = append(args, "mode", "L3")

	// Add scrub configuration if requested
	// scrub=0 means NETKIT_SCRUB_NONE (don't clear skb->mark)
	// This requires iproute2 that supports the scrub parameter (kernel 6.6+)
	if scrubNone {
		args = append(args, "scrub", "0", "peer_scrub", "0")
	}

	cmd := exec.Command("ip", args...)
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

	// If scrub configuration was requested and failed, try without it
	if scrubNone && strings.Contains(string(output), "Unknown parameter") {
		// ip command doesn't support scrub parameter, retry without it
		return createNetkitDeviceViaIpCmd(name, peerName, txQLen, false)
	}

	return fmt.Errorf("failed to create Netkit device: %w: %s", err, string(output))
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
//
// When enableRedirectPeer is true, it attempts to configure scrub=NONE
// to enable bpf_redirect_peer() with preserved skb->mark.
func createNetkitDevice(log *logrus.Logger, name, peerName string, txQLen int, enableRedirectPeer bool) error {
	log.Debug("Attempting to create Netkit device")

	// Determine if we should try to use scrub=NONE
	scrubNone := enableRedirectPeer && checkNetkitScrubSupport(log)
	if scrubNone {
		log.Info("Enabling netkit scrub=NONE for bpf_redirect_peer support")
	} else if enableRedirectPeer {
		log.Debug("bpf_redirect_peer requested but kernel doesn't support scrub; will use bpf_redirect instead")
	}

	cfg := &NetkitConfig{
		Name:     name,
		PeerName: peerName,
		TxQLen:   txQLen,
		ScrubNone: scrubNone,
	}

	// Method 1: Try using netlink API (preferred)
	// This works even with older iproute2 versions
	log.Debug("Trying netlink API method")
	if err := createNetkitDeviceViaNetlink(log, cfg); err == nil {
		log.Infof("Successfully created Netkit device pair %s <-> %s using netlink API", name, peerName)
		return nil
	} else {
		log.Debugf("Netlink API method failed: %v", err)
	}

	// Method 2: Fall back to ip command (requires iproute2 6.7.0+)
	log.Debug("Trying ip command method")
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
	if err := createNetkitDeviceViaIpCmd(name, peerName, txQLen, scrubNone); err != nil {
		log.Infof("Failed to create Netkit device via ip command: %v", err)
		return fmt.Errorf("failed to create Netkit device via ip command: %w", err)
	}

	log.Infof("Successfully created Netkit device pair %s <-> %s using ip command", name, peerName)
	return nil
}

// checkNetkitDeviceCanUseRedirectPeer checks if an existing netkit device
// is configured with scrub=NONE, which is required for bpf_redirect_peer.
func checkNetkitDeviceCanUseRedirectPeer(log *logrus.Logger, ifname string) bool {
	scrubNone, err := checkExistingNetkitScrubConfig(log, ifname)
	if err != nil {
		log.Debugf("Failed to check netkit scrub config for %s: %v", ifname, err)
		return false
	}
	return scrubNone
}
