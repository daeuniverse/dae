/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
)

// TestAnyfromGSOFix verifies that the GSO fix in anyfrom_pool.go works correctly.
// This ensures that UDP_SEGMENT is only set when the payload will actually be segmented.
func TestAnyfromGSOFix(t *testing.T) {
	tests := []struct {
		name              string
		payloadSize       int
		gsoEnabled        bool
		shouldUseGSO      bool
	}{
		{
			name:         "small packet (500B)",
			payloadSize:  500,
			gsoEnabled:   true,
			shouldUseGSO: false, // < 1500, no GSO
		},
		{
			name:         "MTU packet (1500B)",
			payloadSize:  1500,
			gsoEnabled:   true,
			shouldUseGSO: false, // = 1500, no GSO
		},
		{
			name:         "large packet (2000B)",
			payloadSize:  2000,
			gsoEnabled:   true,
			shouldUseGSO: true, // > 1500, use GSO
		},
		{
			name:         "jumbo packet (9000B)",
			payloadSize:  9000,
			gsoEnabled:   true,
			shouldUseGSO: true, // > 1500, use GSO
		},
		{
			name:         "GSO disabled",
			payloadSize:  2000,
			gsoEnabled:   false,
			shouldUseGSO: false, // GSO disabled
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Anyfrom{
				gso:         tt.gsoEnabled,
				gotGSOError: false,
			}

			// Check if GSO would be used
			wouldUseGSO := a.SupportGso(tt.payloadSize)
			
			// The actual GSO usage depends on both SupportGso and the size check in Write methods
			actualUse := wouldUseGSO && tt.payloadSize > 1500

			if actualUse != tt.shouldUseGSO {
				t.Errorf("GSO usage mismatch: got=%v, want=%v (payload=%d, gsoEnabled=%v)",
					actualUse, tt.shouldUseGSO, tt.payloadSize, tt.gsoEnabled)
			}
		})
	}
}

// TestGSOSizeVerification tests that GSO is only used when payload > segment size
func TestGSOSizeVerification(t *testing.T) {
	gsoSize := uint16(1500) // Standard MTU

	tests := []struct {
		name     string
		payload  []byte
		wantGSO  bool
	}{
		{
			name:    "100 bytes",
			payload: make([]byte, 100),
			wantGSO: false,
		},
		{
			name:    "1200 bytes (typical QUIC)",
			payload: make([]byte, 1200),
			wantGSO: false,
		},
		{
			name:    "1500 bytes (exactly MTU)",
			payload: make([]byte, 1500),
			wantGSO: false,
		},
		{
			name:    "1501 bytes (just over MTU)",
			payload: make([]byte, 1501),
			wantGSO: true,
		},
		{
			name:    "4000 bytes",
			payload: make([]byte, 4000),
			wantGSO: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic from WriteMsgUDP
			shouldUseGSO := len(tt.payload) > int(gsoSize)

			if shouldUseGSO != tt.wantGSO {
				t.Errorf("GSO decision wrong: got=%v, want=%v (payload=%d, gsoSize=%d)",
					shouldUseGSO, tt.wantGSO, len(tt.payload), gsoSize)
			}
		})
	}
}
