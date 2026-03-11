/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const daeSystemdUnit = "dae.service"
const stopEscalationDelay = 2 * time.Second

func resolveTargetPID(args []string) (int, error) {
	if len(args) > 0 {
		pid, err := strconv.Atoi(args[0])
		if err != nil {
			return 0, fmt.Errorf("invalid pid %q: %w", args[0], err)
		}
		return pid, nil
	}

	b, err := os.ReadFile(PidFilePath)
	if err != nil {
		return 0, fmt.Errorf("read pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("parse pid file: %w", err)
	}
	return pid, nil
}

func splitProcCmdline(b []byte) []string {
	parts := bytes.Split(b, []byte{0})
	args := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		args = append(args, string(part))
	}
	return args
}

func readProcessCommand(pid int) (exe string, args []string, err error) {
	exe, err = os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return "", nil, fmt.Errorf("read process executable: %w", err)
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return "", nil, fmt.Errorf("read process cmdline: %w", err)
	}
	args = splitProcCmdline(cmdline)
	if len(args) == 0 {
		return "", nil, fmt.Errorf("process %d has empty cmdline", pid)
	}
	return exe, args[1:], nil
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func waitForProcessExit(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if !processExists(pid) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for process %d to exit", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func signalProcess(pid int, sig syscall.Signal) error {
	if err := syscall.Kill(pid, sig); err != nil {
		return fmt.Errorf("signal pid %d with %s: %w", pid, sig, err)
	}
	return nil
}

func stopProcess(pid int, immediate bool, timeout time.Duration) error {
	if immediate {
		if err := signalProcess(pid, syscall.SIGQUIT); err != nil {
			return err
		}
		return waitForProcessExit(pid, timeout)
	}

	if err := signalProcess(pid, syscall.SIGINT); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	escalateAt := time.Now().Add(stopEscalationDelay)
	escalated := false

	for {
		if !processExists(pid) {
			return nil
		}
		now := time.Now()
		if !escalated && now.After(escalateAt) {
			if err := signalProcess(pid, syscall.SIGQUIT); err != nil && processExists(pid) {
				return err
			}
			escalated = true
		}
		if now.After(deadline) {
			return fmt.Errorf("timeout waiting for process %d to exit", pid)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func systemdMainPID(unit string) (int, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return 0, err
	}
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unit).Output()
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func maybeRunSystemctlForPID(pid int, action string) (bool, error) {
	mainPID, err := systemdMainPID(daeSystemdUnit)
	if err != nil || mainPID <= 0 || mainPID != pid {
		return false, nil
	}
	cmd := exec.Command("systemctl", action, daeSystemdUnit)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return true, err
	}
	return true, nil
}

func isSystemdMainPID(pid int) bool {
	mainPID, err := systemdMainPID(daeSystemdUnit)
	return err == nil && mainPID > 0 && mainPID == pid
}

func startDetachedProcess(exe string, args []string) (int, error) {
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}
