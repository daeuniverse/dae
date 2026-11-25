/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	cleanupForce         bool
	cleanupDisableAutoSu bool

	// Package-level seams keep cleanup command unit tests hermetic without
	// touching host PID files, /proc, netlink, or bpffs.
	cleanupPidFilePath            = PidFilePath
	cleanupSignalProgressFilePath = SignalProgressFilePath
	cleanupAbortFilePath          = AbortFile
	cleanupProcRoot               = "/proc"
	cleanupSelfPID                = os.Getpid
	cleanupProcessAliveFunc       = isProcessAlive
	cleanupStaleKernelStateFunc   = control.CleanupStaleState
	cleanupAutoSuFunc             = internal.AutoSu
	cleanupGeteuidFunc            = os.Geteuid

	cleanupCmd = &cobra.Command{
		Use:   "cleanup",
		Short: "Remove stale eBPF, TC filter, netns, and runtime state left by an exited dae process.",
		Long: `Remove stale classic-TC filters (handles 0x2022/0x2023), the dae0 host device,
/run/netns/daens, /sys/fs/bpf/dae, and runtime state files left behind when dae
exited abnormally (for example, SIGKILL or OOM kill).

Refuses to run while a live dae instance is detected unless --force is specified.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCleanupCommand(cmd, cleanupForce, cleanupDisableAutoSu)
		},
	}
)

func init() {
	cleanupCmd.Flags().BoolVar(&cleanupForce, "force", false, "Run cleanup even if a running dae process is detected.")
	cleanupCmd.Flags().BoolVar(&cleanupDisableAutoSu, "disable-sudo", false, "Disable sudo prompt, may cause cleanup failure due to insufficient permissions.")
	rootCmd.AddCommand(cleanupCmd)
}

func runCleanupCommand(cmd *cobra.Command, force, disableAutoSu bool) error {
	if disableAutoSu && cleanupGeteuidFunc() != 0 {
		return fmt.Errorf("auto-sudo is disabled and current user is not root")
	}
	if !disableAutoSu {
		cleanupAutoSuFunc()
	}

	if !force {
		if pid, source, running := detectRunningDaePID(); running {
			return fmt.Errorf("refusing to clean up while dae appears to be running (pid %d from %s); stop dae first or pass --force", pid, source)
		}
	}

	log := logrus.New()
	log.SetOutput(cmd.ErrOrStderr())

	res, kernelErr := cleanupStaleKernelStateFunc(log)
	removedFiles, fileErr := cleanupStaleRuntimeFiles(
		cleanupPidFilePath,
		cleanupSignalProgressFilePath,
		cleanupAbortFilePath,
	)

	summary := formatCleanupSummary(res, removedFiles)
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), summary); err != nil {
		return errors.Join(kernelErr, fileErr, fmt.Errorf("write cleanup summary: %w", err))
	}
	return errors.Join(kernelErr, fileErr)
}

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func detectRunningDaePID() (pid int, source string, running bool) {
	selfPID := cleanupSelfPID()

	// 1. Check the PID file first so renamed binaries (e.g. dae-linux-amd64)
	// started with a PID file are reliably detected.
	if b, err := os.ReadFile(cleanupPidFilePath); err == nil {
		if filePID, parseErr := strconv.Atoi(strings.TrimSpace(string(b))); parseErr == nil && filePID > 0 && filePID != selfPID {
			if cleanupProcessAliveFunc(filePID) && !isProcZombie(cleanupProcRoot, filePID) && looksLikeDaeProcess(cleanupProcRoot, filePID, true) {
				return filePID, cleanupPidFilePath, true
			}
		}
	}

	// 2. Fall back to scanning /proc for live `dae run` instances started with
	// --disable-pidfile or after a missing PID file.
	entries, err := os.ReadDir(cleanupProcRoot)
	if err != nil {
		return 0, "", false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		procPID, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || procPID <= 0 || procPID == selfPID {
			continue
		}
		if isProcZombie(cleanupProcRoot, procPID) {
			continue
		}
		if looksLikeRunningDaeRunCommand(cleanupProcRoot, procPID) {
			return procPID, filepath.Join(cleanupProcRoot, entry.Name()), true
		}
	}
	return 0, "", false
}

func readProcCmdline(procRoot string, pid int) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 {
		return nil, nil
	}
	parts := bytes.Split(raw, []byte{0})
	args := make([]string, 0, len(parts))
	for _, p := range parts {
		args = append(args, string(p))
	}
	return args, nil
}

// isProcZombie parses /proc/<pid>/stat and reports whether the process is in
// zombie ('Z') or dead ('X'/'x') state. In proc(5), field 2 is "(comm)" which
// may contain spaces or parentheses, so scanning from the last ')' locates the
// single-character state field unambiguously.
func isProcZombie(procRoot string, pid int) bool {
	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	idx := bytes.LastIndexByte(raw, ')')
	if idx < 0 || idx+2 >= len(raw) {
		return false
	}
	rest := strings.TrimSpace(string(raw[idx+1:]))
	if rest == "" {
		return false
	}
	state := rest[0]
	return state == 'Z' || state == 'X' || state == 'x'
}

func firstNonFlagArg(args []string) string {
	for _, arg := range args {
		if arg == "--" {
			return ""
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func looksLikeDaeProcess(procRoot string, pid int, fromPidFile bool) bool {
	args, err := readProcCmdline(procRoot, pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		// If /proc/<pid>/cmdline cannot be inspected (e.g., hidepid mount),
		// stay conservative for a PID taken directly from dae.pid.
		return fromPidFile
	}
	if len(args) == 0 {
		// Kernel threads have an empty cmdline; a recycled PID matching one is
		// never dae.
		return false
	}
	base := strings.ToLower(filepath.Base(args[0]))
	appName := strings.ToLower(consts.AppName)
	if !strings.Contains(base, appName) {
		return false
	}
	sub := firstNonFlagArg(args[1:])
	return sub == "" || sub == "run"
}

func looksLikeRunningDaeRunCommand(procRoot string, pid int) bool {
	args, err := readProcCmdline(procRoot, pid)
	if err != nil || len(args) < 2 {
		return false
	}
	if filepath.Base(args[0]) != consts.AppName {
		return false
	}
	return firstNonFlagArg(args[1:]) == "run"
}

func cleanupStaleRuntimeFiles(paths ...string) (int, error) {
	var (
		removed int
		errs    []error
	)
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, fmt.Errorf("remove runtime file %s: %w", path, err))
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

func formatCleanupSummary(res control.StaleStateCleanupResult, removedFiles int) string {
	if !res.AnyRemoved() && removedFiles == 0 {
		return "No stale dae state found."
	}
	var parts []string
	if res.TCFiltersRemoved > 0 {
		parts = append(parts, fmt.Sprintf("%d TC filter(s)", res.TCFiltersRemoved))
	}
	if res.HostLinkRemoved {
		parts = append(parts, control.HostVethName)
	}
	if res.NetnsRemoved {
		parts = append(parts, control.NsName)
	}
	if res.BpfPinRemoved {
		parts = append(parts, filepath.Join(consts.BpfPinRoot, consts.AppName))
	}
	if removedFiles > 0 {
		parts = append(parts, fmt.Sprintf("%d runtime file(s)", removedFiles))
	}
	return "Cleaned up stale dae state: " + strings.Join(parts, ", ")
}
