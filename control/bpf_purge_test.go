/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func newQuietPurgeLogger() *logrus.Logger {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

func makeFakeLink(index int, name string) netlink.Link {
	return &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Index: index,
			Name:  name,
		},
	}
}

func makeFakeFilter(linkIndex int, parent uint32, major, minor uint16) netlink.Filter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIndex,
			Parent:    parent,
			Handle:    netlink.MakeHandle(major, minor),
		},
	}
}

func stubCleanupSeams(t *testing.T) (netnsDir, pinRoot string) {
	t.Helper()
	prevLinkList := tcLinkListFunc
	prevFilterList := tcFilterListFunc
	prevFilterDel := tcFilterDelFunc
	prevDeleteLink := deleteLinkFunc
	prevDeleteNamedNetns := deleteNamedNetnsFunc
	prevNetnsDir := netnsNamedDir
	prevPinRoot := bpfPinRoot
	prevRemovePinDir := removeBpfPinDirFunc
	t.Cleanup(func() {
		tcLinkListFunc = prevLinkList
		tcFilterListFunc = prevFilterList
		tcFilterDelFunc = prevFilterDel
		deleteLinkFunc = prevDeleteLink
		deleteNamedNetnsFunc = prevDeleteNamedNetns
		netnsNamedDir = prevNetnsDir
		bpfPinRoot = prevPinRoot
		removeBpfPinDirFunc = prevRemovePinDir
	})

	netnsDir = t.TempDir()
	pinRoot = t.TempDir()
	netnsNamedDir = netnsDir
	bpfPinRoot = pinRoot
	return netnsDir, pinRoot
}

func TestPurgeStaleTCFiltersRemovesOnlyDaeHandles(t *testing.T) {
	stubCleanupSeams(t)

	wan := makeFakeLink(2, "wlp0s20f3")
	lan := makeFakeLink(3, "eth0")

	tcLinkListFunc = func() ([]netlink.Link, error) {
		return []netlink.Link{wan, lan}, nil
	}
	tcFilterListFunc = func(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
		if link.Attrs().Name == "eth0" {
			return nil, unix.ENOENT
		}
		if parent == netlink.HANDLE_MIN_INGRESS {
			return []netlink.Filter{
				makeFakeFilter(2, parent, 0x2023, 3),
				makeFakeFilter(2, parent, 0x1000, 1),
			}, nil
		}
		return []netlink.Filter{
			makeFakeFilter(2, parent, 0x2022, 2),
			makeFakeFilter(2, parent, 0x2023, 5),
			makeFakeFilter(2, parent, 0x0001, 1),
		}, nil
	}

	var deleted []uint32
	tcFilterDelFunc = func(f netlink.Filter) error {
		deleted = append(deleted, f.Attrs().Handle)
		return nil
	}

	PurgeStaleTCFilters(newQuietPurgeLogger())

	want := []uint32{
		netlink.MakeHandle(0x2023, 3),
		netlink.MakeHandle(0x2022, 2),
		netlink.MakeHandle(0x2023, 5),
	}
	if len(deleted) != len(want) {
		t.Fatalf("deleted %d filters (%#x), want %d (%#x)", len(deleted), deleted, len(want), want)
	}
	for i := range want {
		if deleted[i] != want[i] {
			t.Fatalf("deleted[%d] = %#x, want %#x", i, deleted[i], want[i])
		}
	}
}

func TestCleanupStaleStateRemovesAllLeftoverArtifacts(t *testing.T) {
	netnsDir, pinRoot := stubCleanupSeams(t)

	// Seed a leftover /run/netns/daens file and /sys/fs/bpf/dae directory.
	namedPath := filepath.Join(netnsDir, NsName)
	if err := os.WriteFile(namedPath, nil, 0o600); err != nil {
		t.Fatalf("seed netns file: %v", err)
	}
	pinDir := filepath.Join(pinRoot, consts.AppName)
	if err := os.MkdirAll(filepath.Join(pinDir, "reload-123-1"), 0o755); err != nil {
		t.Fatalf("seed pin dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pinDir, "conn_state_map"), nil, 0o600); err != nil {
		t.Fatalf("seed pin file: %v", err)
	}

	wan := makeFakeLink(2, "eth0")
	tcLinkListFunc = func() ([]netlink.Link, error) {
		return []netlink.Link{wan}, nil
	}
	tcFilterListFunc = func(_ netlink.Link, parent uint32) ([]netlink.Filter, error) {
		if parent == netlink.HANDLE_MIN_EGRESS {
			return []netlink.Filter{
				makeFakeFilter(2, parent, 0x2023, 5),
				makeFakeFilter(2, parent, 0x0042, 1),
			}, nil
		}
		return nil, nil
	}
	tcFilterDelFunc = func(netlink.Filter) error { return nil }

	var deletedLinkName string
	deleteLinkFunc = func(name string) error {
		deletedLinkName = name
		return nil
	}
	var deletedNetnsName string
	deleteNamedNetnsFunc = func(name string) error {
		deletedNetnsName = name
		return os.Remove(filepath.Join(netnsDir, name))
	}

	res, err := CleanupStaleState(newQuietPurgeLogger())
	if err != nil {
		t.Fatalf("CleanupStaleState() error = %v, want nil", err)
	}
	if !res.AnyRemoved() {
		t.Fatalf("AnyRemoved() = false, want true (res=%+v)", res)
	}
	if res.TCFiltersRemoved != 1 {
		t.Fatalf("TCFiltersRemoved = %d, want 1", res.TCFiltersRemoved)
	}
	if !res.HostLinkRemoved || deletedLinkName != HostVethName {
		t.Fatalf("HostLinkRemoved = %v (deleted=%q), want true (%q)", res.HostLinkRemoved, deletedLinkName, HostVethName)
	}
	if !res.NetnsRemoved || deletedNetnsName != NsName {
		t.Fatalf("NetnsRemoved = %v (deleted=%q), want true (%q)", res.NetnsRemoved, deletedNetnsName, NsName)
	}
	if !res.BpfPinRemoved {
		t.Fatal("BpfPinRemoved = false, want true")
	}
	if _, statErr := os.Lstat(pinDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("pinDir %s still exists after cleanup: %v", pinDir, statErr)
	}

	// Second call on a clean host is a benign no-op.
	tcFilterListFunc = func(netlink.Link, uint32) ([]netlink.Filter, error) { return nil, nil }
	deleteLinkFunc = func(string) error { return netlink.LinkNotFoundError{} }

	res2, err2 := CleanupStaleState(newQuietPurgeLogger())
	if err2 != nil {
		t.Fatalf("second CleanupStaleState() error = %v, want nil", err2)
	}
	if res2.AnyRemoved() {
		t.Fatalf("second CleanupStaleState() removed state on clean host: %+v", res2)
	}
}

func TestCleanupStaleStateContinuesAcrossStageFailures(t *testing.T) {
	netnsDir, pinRoot := stubCleanupSeams(t)

	namedPath := filepath.Join(netnsDir, NsName)
	if err := os.WriteFile(namedPath, nil, 0o600); err != nil {
		t.Fatalf("seed netns file: %v", err)
	}
	pinDir := filepath.Join(pinRoot, consts.AppName)
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		t.Fatalf("seed pin dir: %v", err)
	}

	wan := makeFakeLink(2, "eth0")
	tcLinkListFunc = func() ([]netlink.Link, error) {
		return []netlink.Link{wan}, nil
	}
	tcFilterListFunc = func(_ netlink.Link, parent uint32) ([]netlink.Filter, error) {
		if parent == netlink.HANDLE_MIN_EGRESS {
			return []netlink.Filter{makeFakeFilter(2, parent, 0x2023, 5)}, nil
		}
		return nil, nil
	}
	tcFilterDelFunc = func(netlink.Filter) error { return nil }
	deleteLinkFunc = func(string) error { return unix.ENODEV }

	netnsErr := errors.New("device or resource busy")
	deleteNamedNetnsFunc = func(string) error { return netnsErr }

	res, err := CleanupStaleState(nil)
	if !errors.Is(err, netnsErr) {
		t.Fatalf("CleanupStaleState() error = %v, want wrapped %v", err, netnsErr)
	}
	if res.TCFiltersRemoved != 1 {
		t.Fatalf("TCFiltersRemoved = %d, want 1", res.TCFiltersRemoved)
	}
	if res.HostLinkRemoved {
		t.Fatal("HostLinkRemoved = true for ENODEV, want false")
	}
	if res.NetnsRemoved {
		t.Fatal("NetnsRemoved = true when delete failed, want false")
	}
	if !res.BpfPinRemoved {
		t.Fatal("BpfPinRemoved = false, want true even when netns deletion failed")
	}
}
