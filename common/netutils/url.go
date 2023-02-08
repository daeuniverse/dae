/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package netutils

import "net/url"

type URL struct {
	*url.URL
}

func (u *URL) Port() string {
	if port := u.URL.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}
