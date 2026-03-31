//go:build linux || android || freebsd || openbsd

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netproxy

import (
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

// SoMarkControl is replacable. Replacibility is useful for Android.
var SoMarkControl = func(c syscall.RawConn, mark int) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, mark)
		if err != nil {
			sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

// SoMark is replacable. Replacibility is useful for Android.
var SoMark = func(fd int, mark int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, fwmarkIoctl, mark); err != nil {
		return err
	}
	return nil
}
