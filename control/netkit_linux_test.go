//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"os/exec"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNetkitIpLinkAddArgsUsesLowercaseL2BeforePeer(t *testing.T) {
	args := netkitIpLinkAddArgs("dae0", "dae0peer", false)
	want := []string{"link", "add", "dae0", "type", "netkit", "mode", "l2", "peer", "dae0peer"}
	if !slices.Equal(args, want) {
		t.Fatalf("netkitIpLinkAddArgs() = %v, want %v", args, want)
	}
	if slices.Contains(args, "L2") {
		t.Fatal("iproute2 rejects uppercase L2; argv must use lowercase l2")
	}

	modeIdx := slices.Index(args, "mode")
	peerIdx := slices.Index(args, "peer")
	if modeIdx < 0 || peerIdx < 0 || modeIdx > peerIdx {
		t.Fatalf("mode must appear before peer so iproute2 does not treat it as a peer attribute: %v", args)
	}
}

func TestNetkitIpLinkAddArgsScrubNoneUsesNamedValues(t *testing.T) {
	args := netkitIpLinkAddArgs("dae0", "dae0peer", true)
	want := []string{
		"link", "add", "dae0", "type", "netkit", "mode", "l2",
		"scrub", "none", "peer", "scrub", "none", "dae0peer",
	}
	if !slices.Equal(args, want) {
		t.Fatalf("netkitIpLinkAddArgs(scrubNone)= %v, want %v", args, want)
	}
	if slices.Contains(args, "0") {
		t.Fatal("iproute2 expects scrub none/default, not numeric 0")
	}
	if slices.Contains(args, "peer_scrub") {
		t.Fatal("iproute2 has no peer_scrub keyword; peer scrub is `peer scrub none NAME`")
	}

	peerIdx := slices.Index(args, "peer")
	if peerIdx < 0 || peerIdx+1 >= len(args) || args[peerIdx+1] != "scrub" {
		t.Fatalf("peer scrub must follow the peer keyword: %v", args)
	}
}

func TestNetkitScrubNoneRequiresAttributesOnBothEnds(t *testing.T) {
	tests := []struct {
		name     string
		supports bool
		primary  netlink.NetkitScrub
		peer     netlink.NetkitScrub
		want     bool
	}{
		{name: "attributes absent", primary: netlink.NETKIT_SCRUB_NONE, peer: netlink.NETKIT_SCRUB_NONE},
		{name: "both none", supports: true, primary: netlink.NETKIT_SCRUB_NONE, peer: netlink.NETKIT_SCRUB_NONE, want: true},
		{name: "primary default", supports: true, primary: netlink.NETKIT_SCRUB_DEFAULT, peer: netlink.NETKIT_SCRUB_NONE},
		{name: "peer default", supports: true, primary: netlink.NETKIT_SCRUB_NONE, peer: netlink.NETKIT_SCRUB_DEFAULT},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := netkitScrubNone(test.supports, test.primary, test.peer); got != test.want {
				t.Fatalf("netkitScrubNone() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRequireNetkitL2WithMAC(t *testing.T) {
	macA := net.HardwareAddr{0x0e, 0xee, 0xee, 0xee, 0xee, 0xee}
	macB := net.HardwareAddr{0x0e, 0xee, 0xee, 0xee, 0xee, 0xef}

	l2 := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "dae0",
			HardwareAddr: macA,
		},
		Mode: netlink.NETKIT_MODE_L2,
	}
	peer := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "dae0peer",
			HardwareAddr: macB,
		},
		Mode: netlink.NETKIT_MODE_L2,
	}
	if err := requireNetkitL2WithMAC(l2, peer); err != nil {
		t.Fatalf("L2 pair with MACs should be accepted: %v", err)
	}

	l3 := *l2
	l3.Mode = netlink.NETKIT_MODE_L3
	if err := requireNetkitL2WithMAC(&l3, peer); err == nil {
		t.Fatal("L3 netkit must be rejected; kernel default L3 breaks IPv6 NDP")
	}

	noarp := *l2
	noarp.RawFlags = unix.IFF_NOARP
	if err := requireNetkitL2WithMAC(&noarp, peer); err == nil {
		t.Fatal("IFF_NOARP netkit must be rejected")
	}

	emptyMAC := *l2
	emptyMAC.HardwareAddr = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	if err := requireNetkitL2WithMAC(&emptyMAC, peer); err == nil {
		t.Fatal("zero MAC on primary must be rejected")
	}

	emptyPeer := *peer
	emptyPeer.HardwareAddr = nil
	if err := requireNetkitL2WithMAC(l2, &emptyPeer); err == nil {
		t.Fatal("empty MAC on peer must be rejected")
	}

	if err := requireNetkitL2WithMAC(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "dae0"}}, peer); err == nil {
		t.Fatal("non-netkit primary must be rejected")
	}
}

func TestIsZeroMAC(t *testing.T) {
	if !isZeroMAC(nil) {
		t.Fatal("nil MAC is empty")
	}
	if !isZeroMAC(net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		t.Fatal("all-zero MAC is empty")
	}
	if isZeroMAC(net.HardwareAddr{0, 0, 0, 0, 0, 1}) {
		t.Fatal("non-zero MAC should not be treated as empty")
	}
}

func TestDae0IPv6LinkLocalSkipsDAD(t *testing.T) {
	addr := dae0IPv6LinkLocal()
	if addr.Flags&unix.IFA_F_NODAD == 0 {
		t.Fatal("dae0 IPv6 link-local must set IFA_F_NODAD so netkit DAD cannot leave it tentative")
	}
	if got, want := addr.IP.String(), "fe80::ecee:eeff:feee:eeee"; got != want {
		t.Fatalf("link-local IP = %s, want %s", got, want)
	}
	ones, bits := addr.Mask.Size()
	if ones != 128 || bits != 128 {
		t.Fatalf("link-local prefix = %d/%d, want 128/128", ones, bits)
	}
}

func TestParseIproute2Version(t *testing.T) {
	cases := []struct {
		name      string
		output    string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{"standard", "ip utility, iproute2-6.10.0, libbpf 1.4.0", 6, 10, true},
		{"standard-lower", "ip utility, iproute2-6.1.0, libbpf 1.3.0", 6, 1, true},
		{"bare", "iproute2-6.7.0", 6, 7, true},
		{"trailing-garbage", "iproute2-6.7.0-dev", 6, 7, true},
		{"three-part", "iproute2-6.10.0.1", 6, 10, true},
		{"no-marker", "ip utility, libbpf 1.4.0", 0, 0, false},
		{"no-minor", "iproute2-6", 0, 0, false},
		{"empty", "", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			major, minor, ok := parseIproute2Version(tc.output)
			if ok != tc.wantOK || major != tc.wantMajor || minor != tc.wantMinor {
				t.Fatalf("parseIproute2Version(%q) = (%d, %d, %v), want (%d, %d, %v)",
					tc.output, major, minor, ok, tc.wantMajor, tc.wantMinor, tc.wantOK)
			}
		})
	}
}

// TestCheckIpNetkitSupportLive validates the detector against the real
// iproute2 on the test host: modern output formats and the exit-255 help
// convention must not break detection when netkit is absent.
func TestCheckIpNetkitSupportLive(t *testing.T) {
	// Exercising the real binary is only meaningful when ip is present.
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip command not found")
	}
	// The function must not panic and must return a definitive bool on the
	// host's actual iproute2; correctness of the version gate is covered by
	// TestParseIproute2Version above.
	_ = checkIpNetkitSupport()
}
