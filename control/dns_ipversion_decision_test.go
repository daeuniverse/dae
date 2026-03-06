/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package control

import (
	"fmt"
	"testing"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDecideIPVersionResponse_PreferredQueryKeepsEarlyReturnSemantics(t *testing.T) {
	tests := []struct {
		name                 string
		requestedRespPresent bool
		preferRes            ipVersionLookupResult
		wantReject           bool
		wantErr              string
	}{
		{
			name:                 "writes preferred response when cache is present",
			requestedRespPresent: true,
			preferRes:            ipVersionLookupResult{},
		},
		{
			name:                 "rejects preferred response when cache is absent",
			requestedRespPresent: false,
			preferRes:            ipVersionLookupResult{},
			wantReject:           true,
		},
		{
			name:                 "returns preferred lookup error before responding",
			requestedRespPresent: true,
			preferRes:            ipVersionLookupResult{err: fmt.Errorf("prefer failed")},
			wantErr:              "prefer failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := decideIPVersionResponse(
				dnsmessage.TypeAAAA,
				dnsmessage.TypeAAAA,
				tt.requestedRespPresent,
				tt.preferRes,
				ipVersionLookupResult{hasIP: true},
			)

			require.True(t, decision.cleanupSecondary)
			require.Equal(t, tt.wantReject, decision.reject)
			if tt.wantErr == "" {
				require.NoError(t, decision.err)
			} else {
				require.EqualError(t, decision.err, tt.wantErr)
			}
		})
	}
}

func TestDecideIPVersionResponse_NonPreferredQueryUsesPreferredAvailability(t *testing.T) {
	tests := []struct {
		name                 string
		preferRes            ipVersionLookupResult
		secondaryRes         ipVersionLookupResult
		requestedRespPresent bool
		wantReject           bool
		wantCleanupSecondary bool
		wantErr              string
	}{
		{
			name:                 "rejects IPv4 when preferred IPv6 has an IP",
			preferRes:            ipVersionLookupResult{hasIP: true},
			secondaryRes:         ipVersionLookupResult{hasIP: true},
			requestedRespPresent: true,
			wantReject:           true,
			wantCleanupSecondary: true,
		},
		{
			name:                 "writes requested qtype when preferred misses and requested qtype has IP",
			preferRes:            ipVersionLookupResult{},
			secondaryRes:         ipVersionLookupResult{hasIP: true},
			requestedRespPresent: true,
			wantCleanupSecondary: false,
		},
		{
			name:                 "rejects when requested qtype has IP result but cache is absent",
			preferRes:            ipVersionLookupResult{},
			secondaryRes:         ipVersionLookupResult{hasIP: true},
			requestedRespPresent: false,
			wantReject:           true,
			wantCleanupSecondary: false,
		},
		{
			name:                 "returns preferred error when neither qtype yields IP",
			preferRes:            ipVersionLookupResult{err: fmt.Errorf("prefer failed")},
			secondaryRes:         ipVersionLookupResult{},
			requestedRespPresent: false,
			wantCleanupSecondary: false,
			wantErr:              "prefer failed",
		},
		{
			name:                 "returns secondary error after preferred miss",
			preferRes:            ipVersionLookupResult{},
			secondaryRes:         ipVersionLookupResult{err: fmt.Errorf("secondary failed")},
			requestedRespPresent: false,
			wantCleanupSecondary: false,
			wantErr:              "secondary failed",
		},
		{
			name:                 "rejects when both qtypes miss without errors",
			preferRes:            ipVersionLookupResult{},
			secondaryRes:         ipVersionLookupResult{},
			requestedRespPresent: false,
			wantReject:           true,
			wantCleanupSecondary: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := decideIPVersionResponse(
				dnsmessage.TypeA,
				dnsmessage.TypeAAAA,
				tt.requestedRespPresent,
				tt.preferRes,
				tt.secondaryRes,
			)

			require.Equal(t, dnsmessage.TypeA, decision.responseQtype)
			require.Equal(t, tt.wantReject, decision.reject)
			require.Equal(t, tt.wantCleanupSecondary, decision.cleanupSecondary)
			if tt.wantErr == "" {
				require.NoError(t, decision.err)
			} else {
				require.EqualError(t, decision.err, tt.wantErr)
			}
		})
	}
}
