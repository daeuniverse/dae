/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type cleanupTestEnv struct {
	procDir      string
	pidFile      string
	progressFile string
	abortFile    string
}

func setupCleanupTestEnv(t *testing.T) cleanupTestEnv {
	t.Helper()
	dir := t.TempDir()
	env := cleanupTestEnv{
		procDir:      filepath.Join(dir, "proc"),
		pidFile:      filepath.Join(dir, "dae.pid"),
		progressFile: filepath.Join(dir, "dae.progress"),
		abortFile:    filepath.Join(dir, "dae.abort"),
	}
	if err := os.MkdirAll(env.procDir, 0o755); err != nil {
		t.Fatalf("create fake proc dir: %v", err)
	}

	prevPid := cleanupPidFilePath
	prevProgress := cleanupSignalProgressFilePath
	prevAbort := cleanupAbortFilePath
	prevProc := cleanupProcRoot
	prevSelf := cleanupSelfPID
	prevAlive := cleanupProcessAliveFunc
	prevKernel := cleanupStaleKernelStateFunc
	prevAutoSu := cleanupAutoSuFunc
	prevGeteuid := cleanupGeteuidFunc

	t.Cleanup(func() {
		cleanupPidFilePath = prevPid
		cleanupSignalProgressFilePath = prevProgress
		cleanupAbortFilePath = prevAbort
		cleanupProcRoot = prevProc
		cleanupSelfPID = prevSelf
		cleanupProcessAliveFunc = prevAlive
		cleanupStaleKernelStateFunc = prevKernel
		cleanupAutoSuFunc = prevAutoSu
		cleanupGeteuidFunc = prevGeteuid
	})

	cleanupPidFilePath = env.pidFile
	cleanupSignalProgressFilePath = env.progressFile
	cleanupAbortFilePath = env.abortFile
	cleanupProcRoot = env.procDir
	cleanupSelfPID = func() int { return 9999 }
	cleanupProcessAliveFunc = func(int) bool { return false }
	cleanupStaleKernelStateFunc = func(*logrus.Logger) (control.StaleStateCleanupResult, error) {
		return control.StaleStateCleanupResult{}, nil
	}
	cleanupAutoSuFunc = func() {}
	cleanupGeteuidFunc = func() int { return 0 }

	return env
}

func seedFakeProcEntry(t *testing.T, procRoot string, pid int, state byte, cmdline ...string) {
	t.Helper()
	pidDir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", pidDir, err)
	}
	statLine := strconv.Itoa(pid) + " (dae) " + string(state) + " 1 1 1 0 -1 0\n"
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(statLine), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	rawCmdline := strings.Join(cmdline, "\x00")
	if len(cmdline) > 0 {
		rawCmdline += "\x00"
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(rawCmdline), 0o600); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
}

func newTestCleanupCobraCmd() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	c := &cobra.Command{}
	c.SetOut(out)
	c.SetErr(errOut)
	return c, out, errOut
}

func TestRunCleanupRefusesLiveDaemonFromPidFile(t *testing.T) {
	env := setupCleanupTestEnv(t)

	const livePID = 4242
	if err := os.WriteFile(env.pidFile, []byte(strconv.Itoa(livePID)), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	seedFakeProcEntry(t, env.procDir, livePID, 'S', "/usr/bin/dae", "run", "-c", "/etc/dae/config.dae")
	cleanupProcessAliveFunc = func(pid int) bool { return pid == livePID }

	kernelCalled := false
	cleanupStaleKernelStateFunc = func(*logrus.Logger) (control.StaleStateCleanupResult, error) {
		kernelCalled = true
		return control.StaleStateCleanupResult{}, nil
	}

	c, _, _ := newTestCleanupCobraCmd()
	err := runCleanupCommand(c, false, true)
	if err == nil || !strings.Contains(err.Error(), "appears to be running") {
		t.Fatalf("runCleanupCommand() error = %v, want running-daemon refusal", err)
	}
	if kernelCalled {
		t.Fatal("kernel cleanup ran while live dae process was detected")
	}
}

func TestRunCleanupForceBypassesLiveDaemonGuard(t *testing.T) {
	env := setupCleanupTestEnv(t)

	const livePID = 4242
	if err := os.WriteFile(env.pidFile, []byte(strconv.Itoa(livePID)), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	seedFakeProcEntry(t, env.procDir, livePID, 'S', "/usr/bin/dae", "run", "-c", "/etc/dae/config.dae")
	cleanupProcessAliveFunc = func(pid int) bool { return pid == livePID }

	kernelCalled := false
	cleanupStaleKernelStateFunc = func(*logrus.Logger) (control.StaleStateCleanupResult, error) {
		kernelCalled = true
		return control.StaleStateCleanupResult{TCFiltersRemoved: 2, HostLinkRemoved: true}, nil
	}

	c, out, _ := newTestCleanupCobraCmd()
	if err := runCleanupCommand(c, true, true); err != nil {
		t.Fatalf("runCleanupCommand(--force) error = %v, want nil", err)
	}
	if !kernelCalled {
		t.Fatal("expected kernel cleanup to run with --force")
	}
	if !strings.Contains(out.String(), "2 TC filter(s)") {
		t.Fatalf("output %q does not mention removed TC filters", out.String())
	}
}

func TestRunCleanupProceedsOnStaleRecycledOrZombiePidFile(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, env cleanupTestEnv)
	}{
		{
			name: "dead pid",
			setup: func(t *testing.T, env cleanupTestEnv) {
				if err := os.WriteFile(env.pidFile, []byte("5001\n"), 0o644); err != nil {
					t.Fatalf("write pid file: %v", err)
				}
				cleanupProcessAliveFunc = func(int) bool { return false }
			},
		},
		{
			name: "recycled pid owned by sshd",
			setup: func(t *testing.T, env cleanupTestEnv) {
				if err := os.WriteFile(env.pidFile, []byte("5002\n"), 0o644); err != nil {
					t.Fatalf("write pid file: %v", err)
				}
				seedFakeProcEntry(t, env.procDir, 5002, 'S', "/usr/sbin/sshd", "-D")
				cleanupProcessAliveFunc = func(pid int) bool { return pid == 5002 }
			},
		},
		{
			name: "recycled pid owned by docker run",
			setup: func(t *testing.T, env cleanupTestEnv) {
				if err := os.WriteFile(env.pidFile, []byte("5004\n"), 0o644); err != nil {
					t.Fatalf("write pid file: %v", err)
				}
				seedFakeProcEntry(t, env.procDir, 5004, 'S', "/usr/bin/docker", "run", "alpine")
				cleanupProcessAliveFunc = func(pid int) bool { return pid == 5004 }
			},
		},
		{
			name: "zombie dae pid",
			setup: func(t *testing.T, env cleanupTestEnv) {
				if err := os.WriteFile(env.pidFile, []byte("5003\n"), 0o644); err != nil {
					t.Fatalf("write pid file: %v", err)
				}
				seedFakeProcEntry(t, env.procDir, 5003, 'Z', "/usr/bin/dae", "run", "-c", "/etc/dae/config.dae")
				cleanupProcessAliveFunc = func(pid int) bool { return pid == 5003 }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupCleanupTestEnv(t)
			tc.setup(t, env)
			if err := os.WriteFile(env.progressFile, []byte("0\nOK"), 0o644); err != nil {
				t.Fatalf("write progress file: %v", err)
			}
			if err := os.WriteFile(env.abortFile, nil, 0o600); err != nil {
				t.Fatalf("write abort file: %v", err)
			}

			cleanupStaleKernelStateFunc = func(*logrus.Logger) (control.StaleStateCleanupResult, error) {
				return control.StaleStateCleanupResult{
					TCFiltersRemoved: 2,
					HostLinkRemoved:  true,
					NetnsRemoved:     true,
					BpfPinRemoved:    true,
				}, nil
			}

			c, out, _ := newTestCleanupCobraCmd()
			if err := runCleanupCommand(c, false, true); err != nil {
				t.Fatalf("runCleanupCommand() error = %v, want nil", err)
			}
			for _, f := range []string{env.pidFile, env.progressFile, env.abortFile} {
				if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("runtime file %s still exists after cleanup: %v", f, err)
				}
			}
			got := out.String()
			for _, want := range []string{"2 TC filter(s)", "dae0", "daens", "3 runtime file(s)"} {
				if !strings.Contains(got, want) {
					t.Fatalf("summary %q missing %q", got, want)
				}
			}
		})
	}
}

func TestRunCleanupDetectsPidfilelessDaeRunInProcAndIgnoresOtherSubcommands(t *testing.T) {
	env := setupCleanupTestEnv(t)

	// Non-run subcommands and self PID must not block cleanup.
	seedFakeProcEntry(t, env.procDir, 9999, 'R', "/usr/bin/dae", "cleanup")
	seedFakeProcEntry(t, env.procDir, 6001, 'S', "/usr/bin/dae", "validate", "-c", "/etc/dae/config.dae")
	seedFakeProcEntry(t, env.procDir, 6002, 'S', "/usr/bin/grep", "dae", "run")

	c, out, _ := newTestCleanupCobraCmd()
	if err := runCleanupCommand(c, false, true); err != nil {
		t.Fatalf("runCleanupCommand() with only non-run dae procs error = %v, want nil", err)
	}
	if !strings.Contains(out.String(), "No stale dae state found.") {
		t.Fatalf("unexpected clean summary: %q", out.String())
	}

	// Now add a live pidfile-less `dae run` process; cleanup must refuse.
	seedFakeProcEntry(t, env.procDir, 6003, 'S', "/usr/bin/dae", "run", "--disable-pidfile", "-c", "/etc/dae/config.dae")
	c2, _, _ := newTestCleanupCobraCmd()
	err := runCleanupCommand(c2, false, true)
	if err == nil || !strings.Contains(err.Error(), "6003") {
		t.Fatalf("runCleanupCommand() error = %v, want refusal citing pid 6003", err)
	}
}

func TestRunCleanupRejectsNonRootWhenAutoSuDisabled(t *testing.T) {
	setupCleanupTestEnv(t)
	cleanupGeteuidFunc = func() int { return 1000 }

	c, _, _ := newTestCleanupCobraCmd()
	err := runCleanupCommand(c, false, true)
	if err == nil || !strings.Contains(err.Error(), "not root") {
		t.Fatalf("runCleanupCommand() error = %v, want non-root refusal", err)
	}
}

func TestRunCleanupPropagatesKernelError(t *testing.T) {
	setupCleanupTestEnv(t)
	wantErr := errors.New("tc filter del failed")
	cleanupStaleKernelStateFunc = func(*logrus.Logger) (control.StaleStateCleanupResult, error) {
		return control.StaleStateCleanupResult{}, wantErr
	}

	c, _, _ := newTestCleanupCobraCmd()
	if err := runCleanupCommand(c, false, true); !errors.Is(err, wantErr) {
		t.Fatalf("runCleanupCommand() error = %v, want %v", err, wantErr)
	}
}

func TestSystemdServiceRunsCleanupOnStopPost(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "install", "dae.service"))
	if err != nil {
		t.Fatalf("read install/dae.service: %v", err)
	}
	if !strings.Contains(string(data), "ExecStopPost=-/usr/bin/dae cleanup --disable-sudo") {
		t.Fatal("install/dae.service does not configure ExecStopPost cleanup hook")
	}
}
