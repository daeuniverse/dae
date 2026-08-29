/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"fmt"
	"strings"
)

// GroupChain describes the supported group-based chain form. Proxy chains
// retain dae's endpoint -> relay order, so the entry group is on the right.
type GroupChain struct {
	Name         string
	EntryGroup   string
	EndpointLink string
	Link         string
}

// ParseGroupChain recognizes group-based node chains without changing the
// parsing behavior of ordinary nodes and node-to-node chains.
func ParseGroupChain(link string) (*GroupChain, bool, error) {
	name, linklike := GetTagFromLinkLikePlaintext(link)
	parts := strings.Split(linklike, "->")
	groupAt := -1
	groupName := ""
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "group(") {
			continue
		}
		if !strings.HasSuffix(part, ")") {
			return nil, true, fmt.Errorf("invalid group chain entry syntax")
		}
		groupAt = i
		groupName = strings.TrimSpace(part[len("group(") : len(part)-1])
		break
	}
	if groupAt < 0 {
		return nil, false, nil
	}
	if len(parts) != 2 || groupAt != 1 {
		return nil, true, fmt.Errorf("group chain must have the form endpoint -> group(NAME)")
	}
	if groupName == "" {
		return nil, true, fmt.Errorf("group chain entry name is empty")
	}
	endpointLink := strings.TrimSpace(parts[0])
	if endpointLink == "" {
		return nil, true, fmt.Errorf("group chain endpoint is empty")
	}
	return &GroupChain{
		Name:         strings.TrimSpace(name),
		EntryGroup:   groupName,
		EndpointLink: endpointLink,
		Link:         strings.TrimSpace(linklike),
	}, true, nil
}
