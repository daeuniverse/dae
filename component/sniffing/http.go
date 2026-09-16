/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"unicode"
)

var (
	httpHeaderHost = []byte("host")
	httpHeaderSep  = []byte{':'}
)

// httpMethods lists valid HTTP request methods as []byte so the method check
// in SniffHttp is allocation-free (string(method) would heap-allocate per call
// on a hot path).
var httpMethods = [][]byte{
	[]byte("GET"), []byte("POST"), []byte("PUT"), []byte("PATCH"),
	[]byte("DELETE"), []byte("COPY"), []byte("HEAD"), []byte("OPTIONS"),
	[]byte("LINK"), []byte("UNLINK"), []byte("PURGE"), []byte("LOCK"),
	[]byte("UNLOCK"), []byte("PROPFIND"), []byte("CONNECT"), []byte("TRACE"),
}

// isValidHttpMethod reports whether method is a recognized HTTP method,
// comparing bytes directly to avoid a string conversion.
func isValidHttpMethod(method []byte) bool {
	for _, m := range httpMethods {
		if bytes.Equal(method, m) {
			return true
		}
	}
	return false
}

func sniffHTTPHostHeader(data []byte) (string, error) {
	// The first line is the request line ("METHOD SP target SP version"); it is
	// never a Host header, so jump past it to avoid a wasted scan per request.
	start := 0
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		start = i + 1
	} else {
		return "", ErrNotFound
	}
	for start < len(data) {
		// Split on LF. HTTP lines end with CRLF, and a single-byte search for
		// '\n' is markedly cheaper than a two-byte search for "\r\n"; the
		// preceding CR (if present) is stripped from the header content.
		nl := bytes.IndexByte(data[start:], '\n')
		var line []byte
		if nl >= 0 {
			lineEnd := start + nl
			if lineEnd > start && data[lineEnd-1] == '\r' {
				line = data[start : lineEnd-1]
			} else {
				line = data[start:lineEnd]
			}
			start = lineEnd + 1
		} else {
			line = data[start:]
			start = len(data)
		}

		// Empty line marks end-of-headers.
		if len(line) == 0 {
			break
		}
		key, value, found := bytes.Cut(line, httpHeaderSep)
		if !found {
			// Bad key value.
			continue
		}
		if bytes.EqualFold(bytes.TrimSpace(key), httpHeaderHost) {
			host := string(bytes.TrimSpace(value))
			if host == "" {
				return "", ErrNotFound
			}
			return host, nil
		}
	}
	return "", ErrNotFound
}

func (s *Sniffer) SniffHttp() (d string, err error) {
	// First byte should be printable.
	if s.buf.Len() == 0 || !unicode.IsPrint(rune(s.buf.Bytes()[0])) {
		return "", ErrNotApplicable
	}

	// Search method.
	search := s.buf.Bytes()
	if len(search) > 12 {
		search = search[:12]
	}
	method, _, found := bytes.Cut(search, []byte(" "))
	if !found {
		return "", ErrNotApplicable
	}
	if !isValidHttpMethod(method) {
		return "", ErrNotApplicable
	}

	// Now we assume it is an HTTP packet. We should not return NotApplicableError after here.

	return sniffHTTPHostHeader(s.buf.Bytes())
}
