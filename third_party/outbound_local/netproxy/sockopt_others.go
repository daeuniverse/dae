//go:build !(linux || android || freebsd || openbsd)

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netproxy

import (
	"syscall"
)

// SoMarkControl is replacable.
var SoMarkControl = func(c syscall.RawConn, mark int) error {
	return nil
}

// SoMark is replacable.
var SoMark = func(fd int, mark int) error {
	return nil
}
