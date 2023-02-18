/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import (
	"bytes"
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
	search = s.buf
	prefix := []byte("Host: ")
	_, afterHostKey, found := bytes.Cut(search, prefix)
	if !found {
		return "", NotFoundError
	}
	host, _, found := bytes.Cut(afterHostKey, []byte("\r\n"))
	if !found {
		return "", NotFoundError
	}
	return string(host), nil
}
