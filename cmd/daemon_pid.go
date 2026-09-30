/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	stderrors "errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/daeuniverse/dae/common/consts"
)

// processAlive reports whether pid names a live process. EPERM means the
// process exists but is owned by another user, which still counts as alive.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || stderrors.Is(err, syscall.EPERM)
}

// processComm returns the short command name of pid, or "" when unavailable.
func processComm(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readDaemonPID reads the daemon pid from PidFilePath.
func readDaemonPID() (int, error) {
	return readDaemonPIDFile(PidFilePath)
}

func readDaemonPIDFile(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("dae is not running (%s not found)", path)
		}
		return 0, fmt.Errorf("failed to read pid file: %w", err)
	}
	value := strings.TrimSpace(string(raw))
	pid, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid pid %q in %s: %w", value, path, err)
	}
	return pid, nil
}

// resolveReloadPID returns the pid from args, or from PidFilePath when args is
// empty.
func resolveReloadPID(args []string) (int, error) {
	if len(args) == 0 {
		return readDaemonPID()
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return 0, fmt.Errorf("invalid pid %q: %w", args[0], err)
	}
	return pid, nil
}

// cleanupStaleDaemonFiles removes a pid file left behind by a daemon that is
// gone and resets the reload progress so a later reload is not blocked.
func cleanupStaleDaemonFiles() {
	_ = os.Remove(PidFilePath)
	_ = setRunSignalProgress(consts.ReloadDone, "")
}

// ensureDaemonAlive verifies pid is a live dae. When it is not, it cleans up the
// stale pid/progress files and returns a user-facing error.
func ensureDaemonAlive(pid int) error {
	return ensureDaemonAliveAt(PidFilePath, pid)
}

func ensureDaemonAliveAt(path string, pid int) error {
	if processAlive(pid) {
		if comm := processComm(pid); comm == "" || comm == "dae" {
			return nil
		}
	}
	_ = os.Remove(path)
	_ = setRunSignalProgress(consts.ReloadDone, "")
	return fmt.Errorf("dae is not running (stale pid file %s, pid %d)", path, pid)
}
