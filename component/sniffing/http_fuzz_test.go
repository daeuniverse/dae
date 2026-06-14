/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"testing"
)

func FuzzSniffHTTPHostHeader(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHOST: Example.com:443\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("GET"))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte("Host: "))
	f.Add([]byte("POST /api HTTP/1.1\r\nContent-Length: 0\r\nHost: test.example.org\r\n\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		host, err := sniffHTTPHostHeader(data)
		if err != nil {
			if host != "" {
				t.Errorf("non-empty host %q with error %v", host, err)
			}
			return
		}
		if host == "" {
			t.Error("empty host without error")
		}
	})
}
