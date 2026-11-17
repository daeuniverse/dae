/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"strings"
	"testing"
)

func TestRedactURLHidesUserinfoAndQueryValues(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "userinfo and token",
			in:   "https://alice:s3cret@subs.example.com/api?token=abc123&flag&size=10",
			want: "https://[redacted]@subs.example.com/api?token=[redacted]&flag&size=[redacted]",
		},
		{
			name: "no credentials",
			in:   "https://subs.example.com/api",
			want: "https://subs.example.com/api",
		},
		{
			name: "query only",
			in:   "https://subs.example.com/api?token=abc",
			want: "https://subs.example.com/api?token=[redacted]",
		},
		{
			name: "share link userinfo",
			in:   "socks5://u:pw'x@127.0.0.1:1080#tag",
			want: "socks5://[redacted]@127.0.0.1:1080#tag",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := RedactURL(test.in); got != test.want {
				t.Fatalf("RedactURL(%q) = %q, want %q", test.in, got, test.want)
			}
			if strings.Contains(RedactURL(test.in), "s3cret") && test.in != "" {
				t.Fatalf("RedactURL(%q) still contains the password", test.in)
			}
		})
	}
}

func TestRedactInlineURLsRewritesFreeText(t *testing.T) {
	in := `Get "https://alice:s3cret@subs.example.com/sub?token=abc": dial tcp 1.2.3.4:443: connect: connection refused`
	got := RedactInlineURLs(in)
	if strings.Contains(got, "s3cret") || strings.Contains(got, "token=abc") {
		t.Fatalf("RedactInlineURLs leaked a credential: %q", got)
	}
	if !strings.Contains(got, "subs.example.com") {
		t.Fatalf("RedactInlineURLs dropped the host, which the log line needs: %q", got)
	}
}

func TestRedactInlineURLsKeepsPlainText(t *testing.T) {
	in := "the subscription answered HTTP 500"
	if got := RedactInlineURLs(in); got != in {
		t.Fatalf("RedactInlineURLs(%q) = %q, want it unchanged", in, got)
	}
}

func TestRedactInlineURLsHandlesQuotedAuthorities(t *testing.T) {
	cases := []string{
		`socks5://u:pa'ss@127.0.0.1:1080`,
		`socks5://u:pa\"ss@127.0.0.1:1080`,
		`parse "socks5://u:pa'ss@127.0.0.1:1080": invalid port`,
		`socks5://u:pa\'ss@127.0.0.1:1080`,
	}
	for _, in := range cases {
		out := RedactInlineURLs(in)
		for _, secret := range []string{"pa'ss", `pa\"ss`, `pa\'ss`} {
			if strings.Contains(out, secret) {
				t.Fatalf("RedactInlineURLs(%q) leaked %q: %q", in, secret, out)
			}
		}
		if !strings.Contains(out, redactedPlaceholder) {
			t.Fatalf("RedactInlineURLs(%q) did not redact the userinfo: %q", in, out)
		}
	}
}

// A standard-base64 credential contains '/', which is illegal in a conformant
// userinfo. Stopping the authority at the first '/' left the whole credential in
// the log, so both helpers have to keep looking for the '@'.
func TestRedactHandlesSeparatorsInsideCredentials(t *testing.T) {
	if got, want := RedactURL("ss://YWJjL2RlZg==@203.0.113.9:8388"), "ss://[redacted]@203.0.113.9:8388"; got != want {
		t.Fatalf("RedactURL with a '/' in the userinfo = %q, want %q", got, want)
	}
	if got, want := RedactURL("ss://abc?def@203.0.113.9:8388"), "ss://[redacted]@203.0.113.9:8388"; got != want {
		t.Fatalf("RedactURL with a '?' in the userinfo = %q, want %q", got, want)
	}

	in := `Get "ss://YWJjL2RlZg==@203.0.113.9:8388": i/o timeout`
	got := RedactInlineURLs(in)
	if strings.Contains(got, "YWJjL2RlZg==") {
		t.Fatalf("RedactInlineURLs leaked the credential: %q", got)
	}
	if !strings.Contains(got, "203.0.113.9") {
		t.Fatalf("RedactInlineURLs dropped the host, which the log line needs: %q", got)
	}
}
