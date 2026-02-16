/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package outbound

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func newSS2022TestGlobalOption() *dialer.GlobalOption {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &dialer.GlobalOption{
		Log:               logger,
		TcpCheckOptionRaw: dialer.TcpCheckOptionRaw{Raw: []string{testTcpCheckUrl}},
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{testUdpCheckDns}},
		CheckInterval:     15 * time.Second,
		CheckTolerance:    0,
		CheckDnsTcp:       false,
	}
}

func makeBase64Key(length int, fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, length))
}

func buildSSLinkUserInfo(cipher, password, name string) string {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + password))
	return fmt.Sprintf("ss://%s@127.0.0.1:443#%s", userinfo, name)
}

func buildSSLinkWholeBase64(cipher, password, name string) string {
	raw := fmt.Sprintf("%s:%s@127.0.0.1:443", cipher, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	return fmt.Sprintf("ss://%s#%s", encoded, name)
}

func TestSS2022_NewFromLink_Matrix(t *testing.T) {
	option := newSS2022TestGlobalOption()
	iOption := dialer.InstanceOption{DisableCheck: true}
	psk16A := makeBase64Key(16, 0x11)
	psk16B := makeBase64Key(16, 0x22)
	psk16BadLen := makeBase64Key(15, 0x33)
	psk32A := makeBase64Key(32, 0x44)
	psk32B := makeBase64Key(32, 0x55)
	psk32BadLen := makeBase64Key(31, 0x66)

	type testCase struct {
		name         string
		buildLink    func() string
		wantErrMatch string
	}

	cases := []testCase{
		{
			name: "aes_128_single_psk_valid_userinfo",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-128-gcm", psk16A, "n1")
			},
		},
		{
			name: "aes_128_multi_psk_valid_userinfo",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-128-gcm", strings.Join([]string{psk16A, psk16B}, ":"), "n2")
			},
		},
		{
			name: "aes_256_single_psk_valid_userinfo",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-256-gcm", psk32A, "n3")
			},
		},
		{
			name: "aes_256_multi_psk_valid_userinfo",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-256-gcm", strings.Join([]string{psk32A, psk32B}, ":"), "n4")
			},
		},
		{
			name: "aes_256_single_psk_valid_whole_link_base64",
			buildLink: func() string {
				return buildSSLinkWholeBase64("2022-blake3-aes-256-gcm", psk32A, "n5")
			},
		},
		{
			name: "aes_256_invalid_base64_psk",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-256-gcm", "not_base64!!!", "bad1")
			},
			wantErrMatch: "PSK must be valid base64",
		},
		{
			name: "aes_256_invalid_psk_length",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-256-gcm", psk32BadLen, "bad2")
			},
			wantErrMatch: "PSK length must be 32 bytes",
		},
		{
			name: "aes_128_invalid_psk_length",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-128-gcm", psk16BadLen, "bad3")
			},
			wantErrMatch: "PSK length must be 16 bytes",
		},
		{
			name: "aes_256_empty_psk",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-aes-256-gcm", "", "bad4")
			},
			wantErrMatch: "PSK cannot be empty",
		},
		{
			name: "unsupported_ss2022_cipher",
			buildLink: func() string {
				return buildSSLinkUserInfo("2022-blake3-chacha20-poly1305", psk32A, "bad5")
			},
			wantErrMatch: "unsupported shadowsocks encryption method",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			link := tc.buildLink()
			d, err := dialer.NewFromLink(option, iOption, link, "matrix-sub")
			if tc.wantErrMatch != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrMatch)
				}
				if !strings.Contains(err.Error(), tc.wantErrMatch) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErrMatch, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d == nil {
				t.Fatal("dialer is nil")
			}

			prop := d.Property()
			if prop == nil {
				t.Fatal("property is nil")
			}
			if prop.Protocol != "shadowsocks" {
				t.Fatalf("unexpected protocol: %q", prop.Protocol)
			}
			if prop.SubscriptionTag != "matrix-sub" {
				t.Fatalf("unexpected subscription tag: %q", prop.SubscriptionTag)
			}
			if prop.Address != "127.0.0.1:443" {
				t.Fatalf("unexpected address: %q", prop.Address)
			}
		})
	}
}
