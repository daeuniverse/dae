/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package sniffing

import "bytes"

func (s *Sniffer) SniffHttp() (d string, err error) {
	search := s.buf
	if len(search) > 20 {
		search = search[:20]
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
