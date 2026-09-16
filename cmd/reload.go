/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/spf13/cobra"
)

const reloadProgressWaitTimeout = 60 * time.Second

func encodeSignalProgress(code byte, content string) []byte {
	payload := []byte{code}
	if content == "" {
		return payload
	}
	payload = append(payload, '\n')
	payload = append(payload, content...)
	return payload
}

func writeSignalProgressBytesFile(path string, payload []byte) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err = tmpFile.Write(payload); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err = tmpFile.Chmod(0644); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err = tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func writeSignalProgressFile(path string, code byte, content string) error {
	return writeSignalProgressBytesFile(path, encodeSignalProgress(code, content))
}

func readSignalProgressFile(path string) (code byte, content string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	var firstLine string
	firstLine, content, _ = strings.Cut(string(b), "\n")
	if len(firstLine) != 1 {
		return 0, "", fmt.Errorf("unexpected format: %v", string(b))
	}
	code = firstLine[0]
	return code, content, nil
}

type signalProgressSnapshot struct {
	exists  bool
	content []byte
}

func snapshotSignalProgressFile(path string) (signalProgressSnapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return signalProgressSnapshot{}, nil
		}
		return signalProgressSnapshot{}, err
	}
	return signalProgressSnapshot{exists: true, content: append([]byte(nil), b...)}, nil
}

func restoreSignalProgressFile(path string, snapshot signalProgressSnapshot) error {
	if !snapshot.exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeSignalProgressBytesFile(path, snapshot.content)
}

func writeReloadSendAndSignal(path string, pid int, kill func(int, syscall.Signal) error) error {
	snapshot, err := snapshotSignalProgressFile(path)
	if err != nil {
		return err
	}
	if err := writeSignalProgressFile(path, consts.ReloadSend, ""); err != nil {
		return err
	}
	if err := kill(pid, syscall.SIGUSR1); err != nil {
		if restoreErr := restoreSignalProgressFile(path, snapshot); restoreErr != nil {
			return fmt.Errorf("send reload signal: %w (restore progress file: %v)", err, restoreErr)
		}
		return err
	}
	return nil
}

func waitReloadCompletion(path string, initialDelay, pollInterval, timeout time.Duration) (code byte, content string, err error) {
	if initialDelay > 0 {
		time.Sleep(initialDelay)
	}

	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	for {
		code, content, err = readSignalProgressFile(path)
		if err != nil {
			return 0, "", err
		}
		if code == consts.ReloadDone || code == consts.ReloadError || code == consts.ReloadBusy {
			return code, content, nil
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return 0, "", fmt.Errorf("reload timed out after %v", timeout)
		}
		time.Sleep(pollInterval)
	}
}

var (
	abort     bool
	reloadCmd = &cobra.Command{
		Use:   "reload [pid]",
		Short: "To reload config file without interrupt connections.",
		RunE: func(cmd *cobra.Command, args []string) error {
			internal.AutoSu()
			if len(args) == 0 {
				_pid, err := os.ReadFile(PidFilePath)
				if err != nil {
					return fmt.Errorf("failed to read pid file: %w", err)
				}
				args = []string{strings.TrimSpace(string(_pid))}
			}
			pid, err := strconv.Atoi(args[0])
			if err != nil {
				_ = cmd.Help()
				return fmt.Errorf("invalid pid %q: %w", args[0], err)
			}
			// Read the first line of SignalProgressFilePath.
			code, content, err := readSignalProgressFile(SignalProgressFilePath)
			if err == nil && code != consts.ReloadDone && code != consts.ReloadError {
				if content != "" {
					return fmt.Errorf("reload not started: %s", content)
				}
				return fmt.Errorf("reload not started: %v shows another reload operation is in progress", SignalProgressFilePath)
			}
			abortMarkerCreated := false
			if abort {
				if err := createReloadAbortMarker(AbortFile); err != nil {
					return err
				}
				abortMarkerCreated = true
			}
			// Set the progress as ReloadSend and roll it back if signaling fails.
			if err = writeReloadSendAndSignal(SignalProgressFilePath, pid, syscall.Kill); err != nil {
				requestErr := fmt.Errorf("failed to request reload: %w", err)
				return cleanupReloadAbortMarker(AbortFile, abortMarkerCreated, requestErr)
			}
			code, content, err = waitReloadCompletion(
				SignalProgressFilePath,
				500*time.Millisecond,
				200*time.Millisecond,
				reloadProgressWaitTimeout,
			)
			if err != nil {
				return fmt.Errorf("failed to wait reload result: %w", err)
			}
			result, err := reloadCommandResult(code, content)
			if err != nil {
				if code == consts.ReloadBusy {
					return cleanupReloadAbortMarker(AbortFile, abortMarkerCreated, err)
				}
				return err
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), result); err != nil {
				return fmt.Errorf("write reload result: %w", err)
			}
			return nil
		},
	}
)

func createReloadAbortMarker(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create reload abort marker: %w", err)
	}
	if err := f.Close(); err != nil {
		removeErr := os.Remove(path)
		if os.IsNotExist(removeErr) {
			removeErr = nil
		}
		return stderrors.Join(
			fmt.Errorf("close reload abort marker: %w", err),
			removeErr,
		)
	}
	return nil
}

func cleanupReloadAbortMarker(path string, created bool, cause error) error {
	if !created {
		return cause
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return stderrors.Join(cause, fmt.Errorf("remove reload abort marker: %w", err))
	}
	return cause
}

func reloadCommandResult(code byte, content string) (string, error) {
	switch code {
	case consts.ReloadDone:
		if content == "" {
			content = "OK"
		}
		return content, nil
	case consts.ReloadError:
		if content == "" {
			content = "reload failed"
		}
		return "", fmt.Errorf("reload failed: %s", content)
	case consts.ReloadBusy:
		if content == "" {
			content = "another reload is in progress"
		}
		return "", fmt.Errorf("reload not started: %s", content)
	default:
		return "", fmt.Errorf("unexpected reload result code %d", code)
	}
}

func init() {
	rootCmd.AddCommand(reloadCmd)
	reloadCmd.PersistentFlags().BoolVarP(&abort, "abort", "a", false, "Abort established connections.")
}
