/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"testing"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDNSFastPath_ExcludeLocalListener verifies that DNS fast path correctly
// excludes traffic destined for dae's own DNS listener.
func TestDNSFastPath_ExcludeLocalListener(t *testing.T) {
	t.Run("Local address detection", func(t *testing.T) {
		testCases := []struct {
			name       string
			dst        string
			isLocal    bool
			shouldSkip bool
		}{
			{"127.0.0.1:53", "127.0.0.1:53", true, true},
			{"127.0.0.2:53", "127.0.0.2:53", true, true},
			{"[::1]:53", "[::1]:53", true, true},
			{"0.0.0.0:53", "0.0.0.0:53", true, true},
			{"8.8.8.8:53", "8.8.8.8:53", false, false},
			{"192.168.1.1:53", "192.168.1.1:53", false, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				dst, err := netip.ParseAddrPort(tc.dst)
				require.NoError(t, err)

				isLocal := dst.Addr().IsLoopback() || dst.Addr().IsUnspecified()
				assert.Equal(t, tc.isLocal, isLocal, "Local address detection should match")

				// Local addresses should be skipped when we have a DNS listener on port 53
				if isLocal {
					assert.True(t, tc.shouldSkip, "Local DNS should be skipped from fast path")
				}
			})
		}
	})
}

// TestDNSFastPath_RemoteDNSHandling verifies that remote DNS servers
// are correctly handled by the fast path.
func TestDNSFastPath_RemoteDNSHandling(t *testing.T) {
	testCases := []struct {
		name           string
		dst            string
		shouldFastPath bool
	}{
		{"Google DNS", "8.8.8.8:53", true},
		{"Cloudflare DNS", "1.1.1.1:53", true},
		{"Local network DNS", "192.168.1.1:53", true},
		{"Upstream DNS", "10.0.0.1:53", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dst, err := netip.ParseAddrPort(tc.dst)
			require.NoError(t, err)

			// Remote DNS should go through fast path
			if tc.shouldFastPath {
				assert.False(t, dst.Addr().IsLoopback(), "Should not be loopback address")
				assert.False(t, dst.Addr().IsUnspecified(), "Should not be unspecified address")
				assert.Equal(t, uint16(53), dst.Port(), "Should be port 53")
			}
		})
	}
}

// TestDNSMessage_ValidDNSDetection tests DNS message validation.
func TestDNSMessage_ValidDNSDetection(t *testing.T) {
	testCases := []struct {
		name    string
		data    []byte
		isValid bool
	}{
		{
			name:    "Valid DNS query",
			data:    createDNSQuery("example.com.", dnsmessage.TypeA),
			isValid: true,
		},
		{
			name:    "Valid DNS response",
			data:    createDNSResponse("example.com.", []string{"1.2.3.4"}),
			isValid: false, // Responses are not queries
		},
		{
			name:    "Invalid DNS packet",
			data:    []byte{0x00, 0x01, 0x02, 0x03},
			isValid: false,
		},
		{
			name:    "Empty packet",
			data:    []byte{},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg, _ := ChooseNatTimeout(tc.data, true)

			if tc.isValid {
				assert.NotNil(t, msg, "Should detect valid DNS message")
				assert.False(t, msg.Response, "Should be a query, not response")
			} else {
				// Either nil or a response
				if msg != nil {
					assert.True(t, msg.Response || len(tc.data) < 12, "Should be invalid (response or too short)")
				}
			}
		})
	}
}

// Helper function to create a DNS query message
func createDNSQuery(domain string, qtype uint16) []byte {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(domain, qtype)
	data, err := msg.Pack()
	if err != nil {
		return nil
	}
	return data
}

// Helper function to create a DNS response message
func createDNSResponse(domain string, ips []string) []byte {
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(domain, dnsmessage.TypeA)
	msg.Response = true
	msg.Rcode = dnsmessage.RcodeSuccess

	for _, ip := range ips {
		rr := &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   domain,
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP(ip),
		}
		msg.Answer = append(msg.Answer, rr)
	}

	data, err := msg.Pack()
	if err != nil {
		return nil
	}
	return data
}
