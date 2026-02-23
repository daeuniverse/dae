/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

func ValidateFilePermissionNotTooOpen(path string, fi os.FileInfo) error {
	if fi.IsDir() {
		return fmt.Errorf("cannot read a directory: %v", path)
	}
	if fi.Mode()&0o037 > 0 {
		return fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", fi.Mode()&0o777, path)
	}
	return nil
}

func ValidateFilePermissionAllowed(path string, fi os.FileInfo, allowedModes ...os.FileMode) error {
	if fi.IsDir() {
		return fmt.Errorf("cannot read a directory: %v", path)
	}
	perm := fi.Mode().Perm()
	for _, mode := range allowedModes {
		if perm == mode.Perm() {
			return nil
		}
	}
	if len(allowedModes) == 0 {
		return fmt.Errorf("permissions %04o for '%v' are invalid", perm, path)
	}
	allowed := make([]string, 0, len(allowedModes))
	for _, mode := range allowedModes {
		allowed = append(allowed, fmt.Sprintf("%04o", mode.Perm()))
	}
	sort.Strings(allowed)
	return fmt.Errorf("permissions %04o for '%v' are invalid; allowed: %s", perm, path, strings.Join(allowed, ", "))
}
