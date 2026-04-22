/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"
	"strings"
	"testing"
)

func TestIsDigitPrefixDomainPattern(t *testing.T) {
	listener := NewConsoleErrorListener()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "digit prefix domain with port",
			input: "123.com:60",
			want:  true,
		},
		{
			name:  "digit prefix domain with different port",
			input: "123dns.com:53",
			want:  true,
		},
		{
			name:  "letter prefix domain with port",
			input: "example.com:60",
			want:  false,
		},
		{
			name:  "digit prefix without dot",
			input: "123:60",
			want:  false,
		},
		{
			name:  "digit prefix without colon",
			input: "123.com",
			want:  false,
		},
		{
			name:  "dot prefix with colon",
			input: ".com:60",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "just colon",
			input: ":",
			want:  false,
		},
		{
			name:  "just dot",
			input: ".",
			want:  false,
		},
		{
			name:  "multi-digit prefix",
			input: "12345.domain.com:8080",
			want:  true,
		},
		{
			name:  "single digit prefix",
			input: "1.com:53",
			want:  true,
		},
		{
			name:  "special characters",
			input: "123_domain.com:60",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := listener.isDigitPrefixDomainPattern(tt.input)
			if got != tt.want {
				t.Errorf("isDigitPrefixDomainPattern(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectDigitPrefixDomainError(t *testing.T) {
	listener := NewConsoleErrorListener()

	tests := []struct {
		name     string
		msg      string
		strLine  string
		wantHint bool
	}{
		{
			name:     "digit prefix domain error",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "        123.com:60",
			wantHint: true,
		},
		{
			name:     "digit prefix domain with different error",
			msg:      "mismatched input ':' expecting something",
			strLine:  "        123dns.com:53",
			wantHint: true,
		},
		{
			name:     "already has single quotes",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "        '123.com:60'",
			wantHint: false,
		},
		{
			name:     "already has double quotes",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  `        "123.com:60"`,
			wantHint: false,
		},
		{
			name:     "letter prefix domain",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "        example.com:60",
			wantHint: false,
		},
		{
			name:     "no colon in line",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "        123.com",
			wantHint: false,
		},
		{
			name:     "different error type",
			msg:      "some other error message",
			strLine:  "        123.com:60",
			wantHint: false,
		},
		{
			name:     "empty line",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "",
			wantHint: false,
		},
		{
			name:     "whitespace only",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "        ",
			wantHint: false,
		},
		{
			name:     "complex line with multiple words",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "fixed_domain_ttl { 123.com:60 abc.com:30 }",
			wantHint: true,
		},
		{
			name:     "upstream style",
			msg:      "mismatched input ':' expecting '}'",
			strLine:  "        123dns.com:53",
			wantHint: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := listener.detectDigitPrefixDomainError(tt.msg, tt.strLine)
			hasHint := got != ""
			if hasHint != tt.wantHint {
				t.Errorf("detectDigitPrefixDomainError() hint = %v, wantHint %v\nmsg: %q\nstrLine: %q",
					hasHint, tt.wantHint, tt.msg, tt.strLine)
			}
			if tt.wantHint && !strings.Contains(got, "Hint:") {
				t.Errorf("detectDigitPrefixDomainError() hint should contain 'Hint:', got: %q", got)
			}
		})
	}
}

func TestHintDigitPrefixDomainFormat(t *testing.T) {
	// Verify the hint format is as expected
	hint := fmt.Sprintf(hintDigitPrefixDomain, "123.com:60", "123.com:60")
	if !strings.Contains(hint, "Hint:") {
		t.Errorf("hint should contain 'Hint:', got: %q", hint)
	}
	if !strings.Contains(hint, "123.com:60") {
		t.Errorf("hint should contain the input, got: %q", hint)
	}
	if !strings.Contains(hint, "'123.com:60'") {
		t.Errorf("hint should contain the quoted input, got: %q", hint)
	}
}
