/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import (
	"bufio"
	"bytes"
	"strings"
	"unicode"
)

func (s *Sniffer) SniffHttp() (d string, err error) {
	// First byte should be printable.
	if len(s.buf) == 0 || !unicode.IsPrint(rune(s.buf[0])) {
		return "", NotApplicableError
	}

	// Search method.
	search := s.buf
	if len(search) > 12 {
		search = search[:12]
	}
	method, _, found := bytes.Cut(search, []byte(" "))
	if !found {
		return "", NotApplicableError
	}
	switch string(method) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "COPY", "HEAD", "OPTIONS", "LINK", "UNLINK", "PURGE", "LOCK", "UNLOCK", "PROPFIND":
	default:
		return "", NotApplicableError
	}

	// Now we assume it is an HTTP packet. We should not return NotApplicableError after here.

	// Search Host.
	scanner := bufio.NewScanner(bytes.NewReader(s.buf))
	// \r\n
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, []byte("\r\n")); i >= 0 {
			// We have a full newline-terminated line.
			return i + 2, data[0:i], nil
		}
		// If we're at EOF, we have a final, non-terminated line. Return it.
		if atEOF {
			return len(data), data, nil
		}
		// Request more data.
		return 0, nil, nil
	})
	for scanner.Scan() && len(scanner.Bytes()) > 0 {
		key, value, found := bytes.Cut(scanner.Bytes(), []byte{':'})
		if !found {
			// Bad key value.
			continue
		}
		if strings.EqualFold(string(key), "host") {
			return strings.TrimSpace(string(value)), nil
		}
	}
	return "", NotFoundError
}
