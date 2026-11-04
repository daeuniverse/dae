/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sort"

	"github.com/vishvananda/netlink"
)

// bridgeLinkInfo is the part of a link the port selection needs. Keeping it
// separate from netlink.Link lets the selection be tested without a kernel.
type bridgeLinkInfo struct {
	name   string
	index  int
	master int
}

// selectBridgePorts returns the devices bridged under bridgeIndex.
//
// A bridge forwards frames without passing its own ingress hook: the frame is
// received on the member device, and the bridge device only sees traffic
// addressed to itself. Hooks installed on the master therefore never observe
// forwarded traffic, which is why direct-traffic accounting stayed at zero on a
// bridged LAN while proxied flows (which are delivered locally) were seen.
func selectBridgePorts(bridgeIndex int, links []bridgeLinkInfo) []bridgeLinkInfo {
	ports := make([]bridgeLinkInfo, 0, len(links))
	for _, link := range links {
		if link.master != bridgeIndex || link.index == bridgeIndex {
			continue
		}
		ports = append(ports, link)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].name < ports[j].name })
	return ports
}

// bridgePorts lists the member devices of a bridge link. It returns nothing for
// a link that is not a bridge.
func bridgePorts(bridge netlink.Link) ([]netlink.Link, error) {
	if bridge == nil || bridge.Attrs() == nil || bridge.Type() != "bridge" {
		return nil, nil
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	infos := make([]bridgeLinkInfo, 0, len(links))
	byIndex := make(map[int]netlink.Link, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			continue
		}
		infos = append(infos, bridgeLinkInfo{name: attrs.Name, index: attrs.Index, master: attrs.MasterIndex})
		byIndex[attrs.Index] = link
	}
	selected := selectBridgePorts(bridge.Attrs().Index, infos)
	ports := make([]netlink.Link, 0, len(selected))
	for _, info := range selected {
		if link, ok := byIndex[info.index]; ok && link.Attrs() != nil {
			ports = append(ports, link)
		}
	}
	return ports, nil
}
