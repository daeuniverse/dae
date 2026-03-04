/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"unicode"

	"github.com/daeuniverse/dae/common"
)

var (
	httpHeaderHost = []byte("host")
	httpHeaderSep  = []byte{':'}
	httpLineSep    = []byte("\r\n")
)

func sniffHTTPHostHeader(data []byte) (string, error) {
	for lineStart := 0; lineStart <= len(data); {
		lineEnd := bytes.Index(data[lineStart:], httpLineSep)
		var line []byte
		if lineEnd >= 0 {
			line = data[lineStart : lineStart+lineEnd]
			lineStart += lineEnd + len(httpLineSep)
		} else {
			line = data[lineStart:]
			lineStart = len(data) + 1
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
			return string(value), nil
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
	if !common.IsValidHttpMethod(string(method)) {
		return "", ErrNotApplicable
	}

	// Now we assume it is an HTTP packet. We should not return NotApplicableError after here.

	return sniffHTTPHostHeader(s.buf.Bytes())
}
