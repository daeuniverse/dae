/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2024, daeuniverse Organization <dae@v2raya.org>
 */

package bandwidth

import "testing"

func TestParse(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    uint64
		wantErr bool
	}{
		{"bytes", args{"25000000"}, 25000000, false}, // 200mb
		{"bps", args{"800 bps"}, 100, false},
		{"kbps", args{"800 kbps"}, 100_000, false},
		{"mbps", args{"800 mbps"}, 100_000_000, false},
		{"gbps", args{"800 gbps"}, 100_000_000_000, false},
		{"tbps", args{"800 tbps"}, 100_000_000_000_000, false},
		{"mbps simp", args{"100m"}, 12_500_000, false},
		{"gbps simp upper", args{"2G"}, 250_000_000, false},
		{"invalid 1", args{"damn"}, 0, true},
		{"invalid 2", args{"5.4 mbps"}, 0, true},
		{"invalid 3", args{"kbps"}, 0, true},
		{"invalid 4", args{"1234 5678 gbps"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
