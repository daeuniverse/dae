/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// PurgeStaleTCFilters removes dae classic-TC filters left by an older process.
// Unpinned TCX links detach automatically when their owner exits, while classic
// filters persist and therefore require this startup sweep before HookSet load.
func PurgeStaleTCFilters(log *logrus.Logger) {
	log.Infof("purging stale TC filters before startup")
	links, err := netlink.LinkList()
	if err != nil {
		log.Errorf("failed to list links for TC filter purge: %v", err)
		return
	}

	for _, link := range links {
		purgeFiltersOnParent(log, link, netlink.HANDLE_MIN_INGRESS)
		purgeFiltersOnParent(log, link, netlink.HANDLE_MIN_EGRESS)
	}
}

func purgeFiltersOnParent(log *logrus.Logger, link netlink.Link, parent uint32) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		// Interfaces without a clsact qdisc return an error here; skip silently.
		return
	}

	for _, f := range filters {
		// dae uses major handles 0x2022 and 0x2023 for its TC filters.
		major := f.Attrs().Handle >> 16
		if major == 0x2022 || major == 0x2023 {
			log.Infof("purging stale TC filter from %s (handle: %#x)", link.Attrs().Name, f.Attrs().Handle)
			if err := netlink.FilterDel(f); err != nil {
				log.Warnf("failed to delete stale TC filter from %s: %v", link.Attrs().Name, err)
			}
		}
	}
}
