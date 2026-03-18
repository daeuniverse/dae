/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org
 */

package control

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

// TestTcpSniffingExcludedPorts verifies that ports in the exclusion list
// correctly skip sniffing.
func TestTcpSniffingExcludedPorts(t *testing.T) {
	c := &ControlPlane{
		sniffingTimeout: 100 * time.Millisecond,
		dialMode:        consts.DialMode_Domain,
	}

	// Create a basic routing result
	routingResult := &bpfRoutingResult{
		Outbound: uint8(consts.OutboundControlPlaneRouting),
	}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		// Known non-HTTP/TLS ports - should skip sniffing
		{"FTP Data", 20, false},
		{"FTP Control", 21, false},
		{"SSH", 22, false},
		{"SMTP", 25, false},
		{"DNS", 53, false},
		{"MySQL", 3306, false},
		{"PostgreSQL", 5432, false},
		{"Redis", 6379, false},
		{"MongoDB", 27017, false},
		{"Memcached", 11211, false},

		// Common HTTP/TLS ports - should allow sniffing
		{"HTTP", 80, true},
		{"HTTPS", 443, true},
		{"HTTP Alt", 8080, true},
		{"Custom Port", 9999, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst, _ := netip.ParseAddrPort("127.0.0.1:" + itoa(tt.port))
			result := c.shouldTryTcpSniff(dst, routingResult)
			if result != tt.expected {
				t.Errorf("shouldTryTcpSniff(port %d) = %v, want %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestTcpSniffFailureThreshold verifies the behavior of the sniffing
// failure threshold optimization.
func TestTcpSniffFailureThreshold(t *testing.T) {
	if tcpSniffFailureThreshold != 1 {
		t.Errorf("tcpSniffFailureThreshold = %d, want 1 for optimization", tcpSniffFailureThreshold)
	}

	// Verify that negative cache TTL is reasonable
	if tcpSniffNegativeCacheTTL < 5*time.Minute {
		t.Errorf("tcpSniffNegativeCacheTTL = %v, want >= 5 minutes", tcpSniffNegativeCacheTTL)
	}
}

// TestTcpSniffNegativeCache verifies that the negative cache correctly
// suppresses sniffing after the threshold is reached.
func TestTcpSniffNegativeCache(t *testing.T) {
	c := &ControlPlane{
		tcpSniffNegSet: make(map[tcpSniffNegKey]tcpSniffNegEntry),
	}

	dst, _ := netip.ParseAddrPort("192.168.1.1:9999")
	routingResult := &bpfRoutingResult{
		Pname: [16]uint8{},
		Mac:   [6]uint8{},
		Dscp:  0,
	}
	key := newTcpSniffNegKey(dst, routingResult)
	now := time.Now()

	// Initially, no entry exists - should not skip
	if c.shouldSkipTcpSniffByNegativeCache(key, now) {
		t.Error("shouldSkipTcpSniffByNegativeCache = true on first call, want false")
	}

	// Mark one failure (threshold is 1)
	c.noteTcpSniffFailure(key, now)

	// After threshold reached, should skip sniffing
	if !c.shouldSkipTcpSniffByNegativeCache(key, now) {
		t.Error("shouldSkipTcpSniffByNegativeCache = false after threshold, want true")
	}

	// After TTL expires, should not skip
	expiredTime := now.Add(tcpSniffNegativeCacheTTL + time.Second)
	if c.shouldSkipTcpSniffByNegativeCache(key, expiredTime) {
		t.Error("shouldSkipTcpSniffByNegativeCache = true after TTL expired, want false")
	}
}

func itoa(i uint16) string {
	if i == 0 {
		return "0"
	}
	var buf [5]byte
	n := 5
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}
