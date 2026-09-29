/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package daedns

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/netproxy"
)

// recordingDialer records the network of every dial attempt and fails right
// away, so bootstrap resolution can be driven end to end without a network
// and without root (the CI unit-test job runs as an unprivileged user).
type recordingDialer struct {
	mu       sync.Mutex
	networks []string
}

var errRecordingDialerStop = errors.New("recording dialer: stop")

func (d *recordingDialer) DialContext(_ context.Context, network, _ string) (netproxy.Conn, error) {
	d.mu.Lock()
	d.networks = append(d.networks, network)
	d.mu.Unlock()
	return nil, errRecordingDialerStop
}

func (d *recordingDialer) recorded() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.networks...)
}

// TestLookupBootstrapIPAddrDoesNotInheritRequestedFamily pins the fix for
// "no suitable address found" during bootstrap resolution.
//
// The bootstrap resolver is reached at a fixed address (119.29.29.29:53 and
// 223.5.5.5:53 by default), so the family used to dial it follows from that
// address. Inheriting the family requested by the caller made both the A and
// the AAAA query dial the v4 bootstrap literal over "udp6" whenever a
// v6-origin flow needed bootstrap resolution, which Go rejects with
//
//	dial udp6: address 119.29.29.29: no suitable address found
//
// and which disabled node/subscription hostname resolution entirely instead
// of merely returning no v6 answer. Every dial attempt must therefore stay
// family-agnostic; the requested family only filters the answers.
func TestLookupBootstrapIPAddrDoesNotInheritRequestedFamily(t *testing.T) {
	cases := []struct {
		label   string
		network string
	}{
		{"udp6", "udp6"},
		{"tcp6", "tcp6"},
		{"magic-udp-ipv6", common.MagicNetworkWithIPVersion("udp", 0, false, "6")},
		{"udp4", "udp4"},
		{"udp", "udp"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			d := &recordingDialer{}
			r := &Router{
				directDialer: d,
				bootstrapDns: []netip.AddrPort{netip.MustParseAddrPort("119.29.29.29:53")},
				log:          quietLogger(),
			}

			_, _ = r.lookupBootstrapIPAddr(context.Background(), tc.network, "node.example.test")

			attempts := d.recorded()
			if len(attempts) == 0 {
				t.Fatal("bootstrap resolution dialed nothing")
			}
			for _, attempt := range attempts {
				mn, err := netproxy.ParseMagicNetwork(attempt)
				if err != nil {
					t.Fatalf("dial attempt %q: %v", attempt, err)
				}
				if mn.IPVersion != "" {
					t.Errorf("dial %q carried IPVersion %q, want family-agnostic dialing",
						attempt, mn.IPVersion)
				}
			}
		})
	}
}
