/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// PurgeStaleTCFilters removes all dae-related TC (Traffic Control) filters from
// every network interface. Called at initial startup to ensure no filters from a
// previous process remain active before the new BPF programs are loaded.
func PurgeStaleTCFilters(log *logrus.Logger) {
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

// PurgeAllDaeTCFilters removes dae-related TC filters from both the host netns
// and dae's private netns. Used on process exit as a fast, deterministic cleanup.
func PurgeAllDaeTCFilters(log *logrus.Logger) {
	hostLinks, err := collectDaeFilterLinks()
	if err != nil {
		log.Errorf("failed to collect host TC qdisc targets for purge: %v", err)
	} else {
		purgeClsactQdiscs(log, hostLinks, nil)
	}

	if ns := GetDaeNetns(); ns != nil {
		var nsLinks []string
		if err := ns.WithRequired("collect stale TC qdisc targets in daens", func() error {
			var collectErr error
			nsLinks, collectErr = collectDaeFilterLinks()
			return collectErr
		}); err != nil {
			log.WithError(err).Debug("best-effort dae netns operation failed: purge stale TC qdiscs in daens")
		} else {
			purgeClsactQdiscs(log, nsLinks, ns)
		}
	}
}

// RemovePinnedBpfObjects removes dae's pinned BPF objects from bpffs.
// This complements fast shutdown where we don't wait for full object teardown.
func RemovePinnedBpfObjects(log *logrus.Logger) {
	pinPath := filepath.Join(consts.BpfPinRoot, consts.AppName)
	if err := os.RemoveAll(pinPath); err != nil && !os.IsNotExist(err) {
		log.WithError(err).Warnf("failed to remove pinned BPF path %s", pinPath)
	}
}

func collectDaeFilterLinks() ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var targets []string
	for _, link := range links {
		if hasDaeFilterOnParent(link, netlink.HANDLE_MIN_INGRESS) || hasDaeFilterOnParent(link, netlink.HANDLE_MIN_EGRESS) {
			if _, ok := seen[link.Attrs().Name]; ok {
				continue
			}
			seen[link.Attrs().Name] = struct{}{}
			targets = append(targets, link.Attrs().Name)
		}
	}
	return targets, nil
}

func hasDaeFilterOnParent(link netlink.Link, parent uint32) bool {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return false
	}

	for _, f := range filters {
		major := f.Attrs().Handle >> 16
		if major == 0x2022 || major == 0x2023 {
			return true
		}
	}
	return false
}

func purgeClsactQdiscs(log *logrus.Logger, links []string, ns *DaeNetns) {
	for _, ifname := range links {
		if ns != nil {
			if err := ns.WithRequired("purge stale TC qdisc", func() error {
				return deleteClsactQdisc(log, ifname)
			}); err != nil && log != nil {
				log.WithError(err).Warnf("failed to purge stale clsact qdisc from %s", ifname)
			}
			continue
		}
		if err := deleteClsactQdisc(log, ifname); err != nil && log != nil {
			log.WithError(err).Warnf("failed to purge stale clsact qdisc from %s", ifname)
		}
	}
}

func deleteClsactQdisc(log *logrus.Logger, ifname string) error {
	link, qdisc, err := buildClsactQdiscForPurge(ifname)
	if err != nil {
		return nil
	}
	if log != nil {
		log.Infof("purging stale clsact qdisc from %s", link.Attrs().Name)
	}
	if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ENODEV) {
		return err
	}
	return nil
}

func buildClsactQdiscForPurge(ifname string) (netlink.Link, *netlink.GenericQdisc, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil, nil, err
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	return link, qdisc, nil
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
