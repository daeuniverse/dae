/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"fmt"
	"os"
)

// ValidateFilePermissionForbidden rejects a directory, or a file whose
// permission bits include any of forbidden.
func ValidateFilePermissionForbidden(path string, fi os.FileInfo, forbidden os.FileMode) error {
	if fi.IsDir() {
		return fmt.Errorf("cannot read a directory: %v", path)
	}
	if perm := fi.Mode().Perm(); perm&forbidden != 0 {
		return fmt.Errorf("permissions %04o for '%v' are too open; bits %04o must not be set", perm, path, forbidden.Perm())
	}
	return nil
}
