/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package config

import (
	"testing"
)

func TestExportOutline(t *testing.T) {
	t.Log(ExportOutlineJson("test"))
}
