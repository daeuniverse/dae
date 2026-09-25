/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"strings"
	"testing"
)

// fixedDomainTtlValues returns the value-only entries of the
// dns.fixed_domain_ttl block, i.e. what control.ParseFixedDomainTtl receives
// after the walker has folded each entry into a single value.
func fixedDomainTtlValues(t *testing.T, in string) []string {
	t.Helper()
	sections, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse(%q) = %v, want no error", in, err)
	}
	var got []string
	for _, section := range sections {
		if section.Name != "dns" {
			continue
		}
		for _, item := range section.Items {
			sub, ok := item.Value.(*Section)
			if !ok || sub.Name != "fixed_domain_ttl" {
				continue
			}
			for _, subItem := range sub.Items {
				param, ok := subItem.Value.(*Param)
				if !ok {
					continue
				}
				if param.Key != "" {
					t.Fatalf("fixed_domain_ttl entry %q kept a key; the whole entry is expected as a value", param.Key)
				}
				got = append(got, param.Val)
			}
		}
	}
	return got
}

// TestDigitPrefixHintQuotesWholeEntry is a regression guard for the hint shown
// when a name starting with a digit is used as a bare key. The hint used to
// say the *name* must be quoted and rendered it as `'123.example.com:'` - the
// colon swallowed and the TTL dropped. A quoted name is still not a valid
// declaration key in any block, and the rendered form passed `dae validate`
// while control.ParseFixedDomainTtl rejected it at daemon startup.
func TestDigitPrefixHintQuotesWholeEntry(t *testing.T) {
	_, err := Parse("global {}\ndns {\n  fixed_domain_ttl {\n    123.example.com: 10\n  }\n}\n")
	if err == nil {
		t.Fatal("Parse() = nil error, want a syntax error for a bare digit-leading key")
	}
	msg := err.Error()
	if !strings.Contains(msg, "'123.example.com: 10'") {
		t.Errorf("hint must quote the whole entry so the suggestion parses, got:\n%s", msg)
	}
	if strings.Contains(msg, "'123.example.com:'") {
		t.Errorf("hint must not quote the name with the colon swallowed, got:\n%s", msg)
	}

	// The recommended spelling has to survive the walker as one value-only
	// entry; ParseFixedDomainTtl splits it again at the ':'.
	got := fixedDomainTtlValues(t, "dns {\n  fixed_domain_ttl {\n    '123.example.com: 10'\n  }\n}\n")
	if len(got) != 1 || got[0] != "123.example.com: 10" {
		t.Fatalf("quoted whole entry = %q, want [\"123.example.com: 10\"]", got)
	}
}

// TestDigitPrefixHintDropsTrailingComment pins that the entry shown by the
// hint excludes a trailing '#' comment: quoting the comment as part of the
// entry would produce a config that still does not work.
func TestDigitPrefixHintDropsTrailingComment(t *testing.T) {
	_, err := Parse("global {}\ndns {\n  fixed_domain_ttl {\n    123.example.com: 10 # my ddns\n  }\n}\n")
	if err == nil {
		t.Fatal("Parse() = nil error, want a syntax error for a bare digit-leading key")
	}
	msg := err.Error()
	// The offending line is echoed verbatim above the hint, so assert on the
	// rendered suggestion rather than on the raw line.
	if !strings.Contains(msg, "To:    '123.example.com: 10'\n") {
		t.Errorf("hint must quote the entry without the comment, got:\n%s", msg)
	}
}
