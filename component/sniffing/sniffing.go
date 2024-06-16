/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	Error            = fmt.Errorf("sniffing error")
	ErrNotApplicable = fmt.Errorf("%w: not applicable", Error)
	ErrNotFound      = fmt.Errorf("%w: not found", Error)
)

func IsSniffingError(err error) bool {
	return errors.Is(err, Error)
}

func NormalizeDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.HasSuffix(host, "]") {
		// Sniffed domain may be like `[2606:4700:20::681a:d1f]`. We should remove the brackets.
		return strings.Trim(host, "[]")
	}
	if domain, _, err := net.SplitHostPort(host); err == nil {
		return domain
	}
	return strings.TrimSuffix(host, ".")
}
