//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func writeHostsFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write hosts fixture: %v", err)
	}
	return path
}

func TestHostsResolveIp46(t *testing.T) {
	orig := hostsFilePath
	t.Cleanup(func() { hostsFilePath = orig })
	hostsFilePath = writeHostsFixture(t, `# comment line
127.0.0.1   localhost
103.190.178.214 vpn.yllty.de
2407:d840:20:0:be24:11ff:fe68:23dd vpn.yllty.de
10.0.0.1 Example.COM alias
192.168.0.9 onlyv6.example
`)

	ip46, ok := HostsResolveIp46("vpn.yllty.de")
	if !ok {
		t.Fatal("expected vpn.yllty.de to be found")
	}
	if want := netip.MustParseAddr("103.190.178.214"); ip46.Ip4 != want {
		t.Errorf("Ip4 = %v, want %v", ip46.Ip4, want)
	}
	if want := netip.MustParseAddr("2407:d840:20:0:be24:11ff:fe68:23dd"); ip46.Ip6 != want {
		t.Errorf("Ip6 = %v, want %v", ip46.Ip6, want)
	}

	// Case-insensitive match and trailing-dot normalisation.
	if _, ok := HostsResolveIp46("EXAMPLE.com."); !ok {
		t.Error("expected case-insensitive, trailing-dot match")
	}

	if _, ok := HostsResolveIp46("absent.example"); ok {
		t.Error("expected absent.example to be not found")
	}
	if _, ok := HostsResolveIp46(""); ok {
		t.Error("expected empty host to be not found")
	}
}

func TestHostsLookupMissingFile(t *testing.T) {
	orig := hostsFilePath
	t.Cleanup(func() { hostsFilePath = orig })
	hostsFilePath = filepath.Join(t.TempDir(), "does-not-exist")
	if addrs := HostsLookup("localhost"); len(addrs) != 0 {
		t.Fatalf("expected no addresses for missing hosts file, got %v", addrs)
	}
}
