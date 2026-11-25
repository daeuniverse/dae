/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	// Package-level seams keep stale-state cleanup tests hermetic on hosts
	// where real netlink or bpffs mutations would affect live interfaces.
	tcLinkListFunc      = netlink.LinkList
	tcFilterListFunc    = netlink.FilterList
	tcFilterDelFunc     = netlink.FilterDel
	bpfPinRoot          = consts.BpfPinRoot
	removeBpfPinDirFunc = os.RemoveAll
)

// StaleStateCleanupResult records which leftover kernel artifacts
// CleanupStaleState removed.
type StaleStateCleanupResult struct {
	TCFiltersRemoved int
	HostLinkRemoved  bool
	NetnsRemoved     bool
	BpfPinRemoved    bool
}

// AnyRemoved reports whether at least one leftover artifact was removed.
func (r StaleStateCleanupResult) AnyRemoved() bool {
	return r.TCFiltersRemoved > 0 || r.HostLinkRemoved || r.NetnsRemoved || r.BpfPinRemoved
}

// PurgeStaleTCFilters removes dae classic-TC filters left by an older process.
// Unpinned TCX links detach automatically when their owner exits, while classic
// filters persist and therefore require this startup sweep before HookSet load.
func PurgeStaleTCFilters(log *logrus.Logger) {
	if log != nil {
		log.Infof("purging stale TC filters before startup")
	}
	_, _ = purgeStaleTCFilters(log)
}

func purgeStaleTCFilters(log *logrus.Logger) (int, error) {
	links, err := tcLinkListFunc()
	if err != nil {
		if log != nil {
			log.Errorf("failed to list links for TC filter purge: %v", err)
		}
		return 0, fmt.Errorf("list links for TC filter purge: %w", err)
	}

	var (
		removed int
		errs    []error
	)
	for _, link := range links {
		n, err := purgeFiltersOnParent(log, link, netlink.HANDLE_MIN_INGRESS)
		removed += n
		if err != nil {
			errs = append(errs, err)
		}
		n, err = purgeFiltersOnParent(log, link, netlink.HANDLE_MIN_EGRESS)
		removed += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return removed, errors.Join(errs...)
}

func purgeFiltersOnParent(log *logrus.Logger, link netlink.Link, parent uint32) (int, error) {
	filters, err := tcFilterListFunc(link, parent)
	if err != nil {
		// Interfaces without a clsact qdisc return an error here; skip silently.
		return 0, nil
	}

	var (
		removed int
		errs    []error
	)
	ifname := link.Attrs().Name
	for _, f := range filters {
		// dae uses major handles 0x2022 and 0x2023 for its TC filters.
		major := f.Attrs().Handle >> 16
		if major == 0x2022 || major == 0x2023 {
			if log != nil {
				log.Infof("purging stale TC filter from %s (handle: %#x)", ifname, f.Attrs().Handle)
			}
			if err := tcFilterDelFunc(f); err != nil {
				if log != nil {
					log.Warnf("failed to delete stale TC filter from %s: %v", ifname, err)
				}
				errs = append(errs, fmt.Errorf("delete stale TC filter from %s (handle %#x): %w", ifname, f.Attrs().Handle, err))
				continue
			}
			removed++
		}
	}
	return removed, errors.Join(errs...)
}

func isLinkNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	var linkNotFound netlink.LinkNotFoundError
	return errors.As(err, &linkNotFound) || errors.Is(err, unix.ENODEV)
}

func cleanupStaleBpfPinDir(log *logrus.Logger) (bool, error) {
	if consts.AppName == "" || consts.AppName != filepath.Base(consts.AppName) || consts.AppName == "." || consts.AppName == ".." {
		return false, fmt.Errorf("invalid BPF pin app name %q", consts.AppName)
	}
	pinDir := filepath.Join(bpfPinRoot, consts.AppName)
	if filepath.Clean(pinDir) == filepath.Clean(bpfPinRoot) {
		return false, fmt.Errorf("refusing to remove BPF pin root %q", pinDir)
	}
	if _, err := os.Lstat(pinDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat BPF pin directory %s: %w", pinDir, err)
	}
	if err := removeBpfPinDirFunc(pinDir); err != nil {
		return false, fmt.Errorf("remove BPF pin directory %s: %w", pinDir, err)
	}
	if log != nil {
		log.Infof("removed stale BPF pin directory %s", pinDir)
	}
	return true, nil
}

// CleanupStaleState removes kernel state that survives an abnormal dae exit
// (SIGKILL, OOM kill, or aborted shutdown): classic-TC filters with dae major
// handles (0x2022/0x2023), the dae0 host device, the /run/netns/daens named
// network namespace, and the /sys/fs/bpf/<AppName> pin directory.
//
// Each stage runs independently so a failure in one stage (such as a locked
// /run/netns/daens mount) does not prevent purging blackholing TC filters.
// Callers must verify that no live dae instance is running before invoking
// this function.
func CleanupStaleState(log *logrus.Logger) (StaleStateCleanupResult, error) {
	var (
		res  StaleStateCleanupResult
		errs []error
	)

	// 1. Purge classic-TC filters first so host WAN/LAN interfaces stop
	// redirecting packets into a dead datapath immediately.
	removedFilters, err := purgeStaleTCFilters(log)
	res.TCFiltersRemoved = removedFilters
	if err != nil {
		errs = append(errs, err)
	}

	// 2. Delete the leftover dae0 host netkit/veth link if present.
	if err := deleteLinkFunc(HostVethName); err != nil {
		if !isLinkNotFoundError(err) {
			errs = append(errs, fmt.Errorf("delete host link %s: %w", HostVethName, err))
		}
	} else {
		res.HostLinkRemoved = true
		if log != nil {
			log.Infof("removed stale host link %s", HostVethName)
		}
	}

	// 3. Delete the leftover named netns mount /run/netns/daens if present.
	namedPath := filepath.Join(netnsNamedDir, NsName)
	_, statErr := os.Lstat(namedPath)
	netnsExisted := statErr == nil
	if netnsExisted || !errors.Is(statErr, os.ErrNotExist) {
		if err := deleteNamedNetnsFunc(NsName); err != nil {
			errs = append(errs, fmt.Errorf("delete named netns %s: %w", NsName, err))
		} else if netnsExisted {
			res.NetnsRemoved = true
			if log != nil {
				log.Infof("removed stale named netns %s", namedPath)
			}
		}
	}

	// 4. Remove the leftover /sys/fs/bpf/<AppName> pin directory if present.
	bpfPinRemoved, err := cleanupStaleBpfPinDir(log)
	res.BpfPinRemoved = bpfPinRemoved
	if err != nil {
		errs = append(errs, err)
	}

	return res, errors.Join(errs...)
}
