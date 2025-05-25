/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

func ReportMemory(tag string) {
	if !logrus.IsLevelEnabled(logrus.DebugLevel) {
		return
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "status"))
	if err != nil {
		panic(err)
	}
	str := strings.TrimSpace(string(b))
	_, after, _ := strings.Cut(str, "VmHWM:")
	usage, _, _ := strings.Cut(after, "\n")
	logrus.Debugln(tag+": memory usage:", strings.TrimSpace(usage))
}
