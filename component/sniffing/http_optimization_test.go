package sniffing

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func sniffHTTPHostHeaderLegacy(data []byte) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, []byte("\r\n")); i >= 0 {
			return i + 2, data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for scanner.Scan() && len(scanner.Bytes()) > 0 {
		key, value, found := bytes.Cut(scanner.Bytes(), []byte{':'})
		if !found {
			continue
		}
		if strings.EqualFold(string(key), "host") {
			return string(value), nil
		}
	}
	return "", ErrNotFound
}

func TestSniffHTTPHostHeader_Compatibility(t *testing.T) {
	testCases := []struct {
		name string
		data string
	}{
		{
			name: "standard_with_space",
			data: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "uppercase_header",
			data: "GET / HTTP/1.1\r\nHOST:Example.com:443\r\n\r\n",
		},
		{
			name: "trailing_line_without_crlf",
			data: "GET / HTTP/1.1\r\nUser-Agent: dae\r\nHost: final.example.com",
		},
		{
			name: "no_host_header",
			data: "GET / HTTP/1.1\r\nUser-Agent: dae\r\n\r\n",
		},
		{
			name: "blank_line_ends_headers",
			data: "GET / HTTP/1.1\r\nHost: first.example.com\r\n\r\nHost: second.example.com\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want, wantErr := sniffHTTPHostHeaderLegacy([]byte(tc.data))
			got, gotErr := sniffHTTPHostHeader([]byte(tc.data))

			if !errors.Is(gotErr, wantErr) {
				t.Fatalf("error mismatch: got=%v want=%v", gotErr, wantErr)
			}
			if got != want {
				t.Fatalf("value mismatch: got=%q want=%q", got, want)
			}
		})
	}
}

func BenchmarkSniffHTTPHostHeader(b *testing.B) {
	payload := []byte(
		"GET /path HTTP/1.1\r\n" +
			"User-Agent: dae\r\n" +
			"Accept: */*\r\n" +
			"X-Forwarded-For: 1.2.3.4\r\n" +
			"Host: benchmark.example.com:443\r\n" +
			"Connection: keep-alive\r\n\r\n",
	)

	b.Run("legacy_scanner", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			host, err := sniffHTTPHostHeaderLegacy(payload)
			if err != nil {
				b.Fatalf("sniff failed: %v", err)
			}
			if host == "" {
				b.Fatal("empty host")
			}
		}
	})

	b.Run("optimized_bytes_scan", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			host, err := sniffHTTPHostHeader(payload)
			if err != nil {
				b.Fatalf("sniff failed: %v", err)
			}
			if host == "" {
				b.Fatal("empty host")
			}
		}
	})
}
