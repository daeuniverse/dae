/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"fmt"
	"strings"
)

// ProxyChain is a strictly two-node proxy chain in traffic order.
type ProxyChain struct {
	Name      string
	EntryLink string
	ExitLink  string
	Link      string
}

// ParseProxyChain recognizes ordinary and group-entry chains. A chain always
// contains exactly one entry and one exit; single nodes are not matched.
func ParseProxyChain(link string) (*ProxyChain, bool, error) {
	name, linklike := GetTagFromLinkLikePlaintext(link)
	parts := strings.Split(linklike, "->")
	if len(parts) == 1 {
		return nil, false, nil
	}
	if len(parts) != 2 {
		return nil, true, fmt.Errorf("proxy chain must contain exactly two nodes")
	}
	entryLink := strings.TrimSpace(parts[0])
	exitLink := strings.TrimSpace(parts[1])
	if entryLink == "" {
		return nil, true, fmt.Errorf("proxy chain entry node is empty")
	}
	if exitLink == "" {
		return nil, true, fmt.Errorf("proxy chain exit node is empty")
	}
	return &ProxyChain{
		Name:      strings.TrimSpace(name),
		EntryLink: entryLink,
		ExitLink:  exitLink,
		Link:      strings.TrimSpace(linklike),
	}, true, nil
}
