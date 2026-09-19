/*
 *  SPDX-License-Identifier: AGPL-3.0-only
 *  Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	stderrors "errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// redirectNetnsNamedDir points the named-netns probes at a scratch directory
// so the unit tests never touch the real /run/netns.
func redirectNetnsNamedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	previous := netnsNamedDir
	netnsNamedDir = dir
	t.Cleanup(func() { netnsNamedDir = previous })
	return dir
}

// A missing /run/netns entry is the normal no-stale-state case both callers
// hit on a clean host; the speculative deletion must not report it.
func TestDeleteNamedNetnsMissingEntryIsSuccess(t *testing.T) {
	redirectNetnsNamedDir(t)
	if err := DeleteNamedNetns("dae-test-missing"); err != nil {
		t.Fatalf("DeleteNamedNetns(missing) = %v, want nil", err)
	}
}

// A plain (non-mount) entry must be cleaned silently: the two umount(2)
// attempts fail harmlessly (EINVAL as root, EPERM unprivileged — both are
// normal for a non-mount path), and the successful removal makes that noise
// irrelevant.
func TestDeleteNamedNetnsPlainEntryIsCleanedWithoutUnmountNoise(t *testing.T) {
	dir := redirectNetnsNamedDir(t)
	if err := os.WriteFile(filepath.Join(dir, "dae-test-plain"), nil, 0o644); err != nil {
		t.Fatalf("prepare plain entry: %v", err)
	}
	if err := DeleteNamedNetns("dae-test-plain"); err != nil {
		t.Fatalf("DeleteNamedNetns(plain file) = %v, want nil", err)
	}
}

// The entry survives the deletion: both umount attempts fail and os.Remove
// fails too. The returned error must carry the unmount context next to the
// removal failure instead of the bare removal errno — that context is what
// tells a kernel-locked mount apart from a healthy cleanup (issue #1109). A
// non-empty directory is the unprivileged stand-in for the unremovable mount
// point, and the umount errno is stubbed because the real one depends on
// privilege: EINVAL for root, EPERM for an unprivileged CI runner.
func TestDeleteNamedNetnsReportsUnmountAndRemoveFailures(t *testing.T) {
	dir := redirectNetnsNamedDir(t)
	blocked := filepath.Join(dir, "dae-test-blocked")
	if err := os.MkdirAll(filepath.Join(blocked, "child"), 0o755); err != nil {
		t.Fatalf("prepare blocked entry: %v", err)
	}
	previous := unmountFunc
	unmountFunc = func(string, int) error { return unix.EINVAL }
	t.Cleanup(func() { unmountFunc = previous })

	err := DeleteNamedNetns("dae-test-blocked")
	if err == nil {
		t.Fatal("DeleteNamedNetns(blocked) = nil, want the removal failure")
	}
	if !strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("error lacks the unmount EINVAL context: %v", err)
	}
	if !strings.Contains(err.Error(), "directory not empty") {
		t.Fatalf("error lacks the removal failure: %v", err)
	}
	if !strings.Contains(err.Error(), blocked) {
		t.Fatalf("error lacks the entry path %s: %v", blocked, err)
	}
	if !stderrors.Is(err, unix.EINVAL) {
		t.Fatalf("errors.Is(err, EINVAL) = false, want the unmount errno to stay matchable: %v", err)
	}
}

// lockedMountErr is the issue #1109 incident signature: every umount(2) flag
// combination rejected with EINVAL and the removal refused with EBUSY.
func lockedMountErr() error {
	return &staleNetnsError{
		path:      "/run/netns/daens",
		syncErr:   unix.EINVAL,
		lazyErr:   unix.EINVAL,
		removeErr: &os.PathError{Op: "remove", Path: "/run/netns/daens", Err: unix.EBUSY},
	}
}

// The recovery cover must fire on the exact locked signature only. The errno
// pair alone (an EINVAL anywhere plus an EBUSY anywhere in the chain) would
// also match mixed shapes — e.g. a synchronous EINVAL with a busy lazy
// unmount — that no real kernel produces for one mount point; the predicate
// checks each stage's own errno instead (review feedback on #1111).
func TestIsKernelLockedMountRequiresExactSourceSignature(t *testing.T) {
	removeBusy := &os.PathError{Op: "remove", Path: "/run/netns/daens", Err: unix.EBUSY}
	if !isKernelLockedMount(lockedMountErr()) {
		t.Fatal("the locked signature must match")
	}
	cross := &staleNetnsError{path: "/run/netns/daens", syncErr: unix.EINVAL, lazyErr: unix.EBUSY, removeErr: removeBusy}
	if isKernelLockedMount(cross) {
		t.Fatal("sync EINVAL + lazy EBUSY + remove EBUSY must not fire the cover")
	}
	lazyDetached := &staleNetnsError{path: "/run/netns/daens", syncErr: unix.EBUSY, removeErr: removeBusy}
	if isKernelLockedMount(lazyDetached) {
		t.Fatal("a lazy unmount that succeeded (nil) must not fire the cover")
	}
	notMount := &staleNetnsError{path: "/run/netns/daens", syncErr: unix.EINVAL, lazyErr: unix.EINVAL,
		removeErr: &os.PathError{Op: "remove", Path: "/run/netns/daens", Err: unix.ENOTEMPTY}}
	if isKernelLockedMount(notMount) {
		t.Fatal("a non-EBUSY removal must not fire the cover")
	}
	if isKernelLockedMount(fmt.Errorf("unmount: %w; %w", unix.EINVAL, unix.EBUSY)) {
		t.Fatal("an untyped errno pair must not fire the cover")
	}
}

// When the locked signature is present but the environment denies the
// recovery mount, setupNetns must fail fast with the real errnos plus the
// manual command, and must not walk into NewNamed — with the entry still
// present its O_CREATE|O_EXCL can only report the misleading "file exists"
// (issue #1109).
func TestSetupNetnsFailsFastWhenRecoveryCoverIsDenied(t *testing.T) {
	dir := redirectNetnsNamedDir(t)
	previousDelete := deleteNamedNetnsFunc
	previousNewNamed := newNamedNetnsFunc
	previousMount := mountFunc
	t.Cleanup(func() {
		deleteNamedNetnsFunc = previousDelete
		newNamedNetnsFunc = previousNewNamed
		mountFunc = previousMount
	})
	staleErr := lockedMountErr()
	deleteNamedNetnsFunc = func(string) error { return staleErr }
	newNamedCalls := 0
	newNamedNetnsFunc = func(string) (netns.NsHandle, error) {
		newNamedCalls++
		return netns.None(), nil
	}
	mountCalls := 0
	mountFunc = func(source, target, fstype string, flags uintptr, data string) error {
		mountCalls++
		if source != "tmpfs" || target != dir || fstype != "tmpfs" || flags != 0 || data != "mode=755" {
			t.Errorf("cover mount args = (%q, %q, %q, %d, %q), want (tmpfs, %s, tmpfs, 0, mode=755)", source, target, fstype, flags, data, dir)
		}
		return unix.EPERM
	}

	err := (&DaeNetns{log: logrus.New()}).setupNetns()
	if !stderrors.Is(err, staleErr) || !stderrors.Is(err, unix.EPERM) {
		t.Fatalf("setupNetns() = %v, want it to wrap the stale cleanup failure and the denied cover", err)
	}
	for _, want := range []string{
		"failed to clean up the stale named netns",
		"mount -t tmpfs -o mode=755 tmpfs " + dir,
		"or reboot",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("setupNetns() error lacks %q: %v", want, err)
		}
	}
	if newNamedCalls != 0 {
		t.Fatalf("NewNamed was reached %d times despite the failed recovery", newNamedCalls)
	}
	if mountCalls != 1 {
		t.Fatalf("cover mount calls = %d, want exactly 1", mountCalls)
	}
}

// The locked signature is the one state no retry can clear, so setupNetns
// recovers by covering the directory with a fresh tmpfs and retrying the
// deletion once; NewNamed then runs against a clean directory, and the
// recovery is logged for the operator.
func TestSetupNetnsRecoversFromKernelLockedMount(t *testing.T) {
	redirectNetnsNamedDir(t)
	previousDelete := deleteNamedNetnsFunc
	previousNewNamed := newNamedNetnsFunc
	previousMount := mountFunc
	t.Cleanup(func() {
		deleteNamedNetnsFunc = previousDelete
		newNamedNetnsFunc = previousNewNamed
		mountFunc = previousMount
	})
	staleErr := lockedMountErr()
	deleteCalls := 0
	deleteNamedNetnsFunc = func(string) error {
		deleteCalls++
		if deleteCalls == 1 {
			return staleErr
		}
		return nil
	}
	mountCalls := 0
	mountFunc = func(string, string, string, uintptr, string) error {
		mountCalls++
		return nil
	}
	newNamedErr := stderrors.New("injected NewNamed failure")
	newNamedCalls := 0
	newNamedNetnsFunc = func(string) (netns.NsHandle, error) {
		newNamedCalls++
		return netns.None(), newNamedErr
	}

	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	err := (&DaeNetns{log: log}).setupNetns()
	if !stderrors.Is(err, newNamedErr) {
		t.Fatalf("setupNetns() = %v, want the injected NewNamed failure reached after the recovery", err)
	}
	if newNamedCalls != 1 || deleteCalls != 2 || mountCalls != 1 {
		t.Fatalf("newNamed=%d delete=%d mount=%d, want 1/2/1", newNamedCalls, deleteCalls, mountCalls)
	}
	if !strings.Contains(buf.String(), "Covered") {
		t.Fatalf("the recovery was not logged: %q", buf.String())
	}
}

// A cover that succeeds but still cannot clear the name must not walk into
// NewNamed either: the surviving entry makes its O_CREATE|O_EXCL report the
// misleading "file exists" (issue #1109).
func TestSetupNetnsFailsWhenNameSurvivesTheCover(t *testing.T) {
	redirectNetnsNamedDir(t)
	previousDelete := deleteNamedNetnsFunc
	previousNewNamed := newNamedNetnsFunc
	previousMount := mountFunc
	t.Cleanup(func() {
		deleteNamedNetnsFunc = previousDelete
		newNamedNetnsFunc = previousNewNamed
		mountFunc = previousMount
	})
	staleErr := lockedMountErr()
	deleteNamedNetnsFunc = func(string) error { return staleErr }
	mountFunc = func(string, string, string, uintptr, string) error { return nil }
	newNamedNetnsFunc = func(string) (netns.NsHandle, error) {
		t.Fatal("NewNamed must not be reached")
		return netns.None(), nil
	}

	err := (&DaeNetns{log: logrus.New()}).setupNetns()
	if !stderrors.Is(err, staleErr) {
		t.Fatalf("setupNetns() = %v, want it to wrap the surviving-entry failure", err)
	}
	if !strings.Contains(err.Error(), "after covering") {
		t.Fatalf("setupNetns() error does not mention the attempted cover: %v", err)
	}
}

// The cover hides every named netns in the directory, not only the stale one,
// until the next reboot; the recovery log must name them so the operator can
// tell dae's recovery apart from a side effect on other tooling.
func TestCoverLogsHiddenNamedNetnsBeforeMounting(t *testing.T) {
	dir := redirectNetnsNamedDir(t)
	for _, name := range []string{NsName, "other-ns", "third-ns"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	previousMount := mountFunc
	t.Cleanup(func() { mountFunc = previousMount })
	mountCalls := 0
	mountFunc = func(string, string, string, uintptr, string) error {
		mountCalls++
		return nil
	}

	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	if err := (&DaeNetns{log: log}).coverNamedNetnsDir(); err != nil {
		t.Fatalf("coverNamedNetnsDir() = %v", err)
	}
	if mountCalls != 1 {
		t.Fatalf("cover mount calls = %d, want 1", mountCalls)
	}
	out := buf.String()
	for _, want := range []string{"other-ns", "third-ns", "hiding named netns"} {
		if !strings.Contains(out, want) {
			t.Fatalf("cover log lacks %q: %q", want, out)
		}
	}
	if strings.Contains(out, NsName) {
		t.Fatalf("cover log lists the stale entry itself as hidden: %q", out)
	}
}

// The tmpfs recovery belongs to the locked-mount signature only. A transient
// EBUSY (another instance still shutting down) and a stray non-mount entry
// (EINVAL from umount, but the removal fails with ENOTEMPTY instead of EBUSY)
// must both keep the plain wrap — and no cover attempt — or the daemon answers
// conditions a retry or a manual cleanup fixes with an action that hides
// /run/netns.
func TestSetupNetnsKeepsPlainWrapOutsideTheLockedSignature(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			name: "transient EBUSY",
			err: &staleNetnsError{path: "/run/netns/daens", syncErr: unix.EBUSY,
				removeErr: &os.PathError{Op: "remove", Path: "/run/netns/daens", Err: unix.EBUSY}},
		},
		{
			name: "non-mount entry",
			err: &staleNetnsError{path: "/run/netns/daens", syncErr: unix.EINVAL, lazyErr: unix.EINVAL,
				removeErr: &os.PathError{Op: "remove", Path: "/run/netns/daens", Err: unix.ENOTEMPTY}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			redirectNetnsNamedDir(t)
			previousDelete := deleteNamedNetnsFunc
			previousNewNamed := newNamedNetnsFunc
			previousMount := mountFunc
			t.Cleanup(func() {
				deleteNamedNetnsFunc = previousDelete
				newNamedNetnsFunc = previousNewNamed
				mountFunc = previousMount
			})
			deleteNamedNetnsFunc = func(string) error { return tc.err }
			newNamedNetnsFunc = func(string) (netns.NsHandle, error) {
				t.Fatal("NewNamed must not be reached")
				return netns.None(), nil
			}
			mountCalls := 0
			mountFunc = func(string, string, string, uintptr, string) error {
				mountCalls++
				return nil
			}

			err := (&DaeNetns{log: logrus.New()}).setupNetns()
			if !stderrors.Is(err, tc.err) {
				t.Fatalf("setupNetns() = %v, want it to wrap the cleanup failure", err)
			}
			if strings.Contains(err.Error(), "tmpfs") {
				t.Fatalf("cause outside the locked signature got the locked-mount advice: %v", err)
			}
			if mountCalls != 0 {
				t.Fatalf("recovery cover was attempted %d times outside the locked signature", mountCalls)
			}
		})
	}
}

// With a clean deletion the flow must still reach NewNamed; the injected
// NewNamed error stops the test before any netlink work.
func TestSetupNetnsReachesNewNamedAfterCleanDeletion(t *testing.T) {
	redirectNetnsNamedDir(t)
	previousDelete := deleteNamedNetnsFunc
	previousNewNamed := newNamedNetnsFunc
	t.Cleanup(func() {
		deleteNamedNetnsFunc = previousDelete
		newNamedNetnsFunc = previousNewNamed
	})
	deleteNamedNetnsFunc = func(string) error { return nil }
	newNamedErr := stderrors.New("injected NewNamed failure")
	newNamedCalls := 0
	newNamedNetnsFunc = func(string) (netns.NsHandle, error) {
		newNamedCalls++
		return netns.None(), newNamedErr
	}

	err := (&DaeNetns{log: logrus.New()}).setupNetns()
	if newNamedCalls != 1 {
		t.Fatalf("NewNamed calls = %d, want 1", newNamedCalls)
	}
	if !stderrors.Is(err, newNamedErr) || !strings.Contains(err.Error(), "failed to create netns") {
		t.Fatalf("setupNetns() = %v, want the wrapped NewNamed failure", err)
	}
}

// A minimal container may boot without /run/netns at all; the setup must
// create the directory instead of surfacing NewNamed's
// "no such file or directory".
func TestPrepareNamedNetnsCreatesMissingDir(t *testing.T) {
	root := redirectNetnsNamedDir(t)
	target := filepath.Join(root, "nested", "netns")
	previousDir := netnsNamedDir
	netnsNamedDir = target
	previousDelete := deleteNamedNetnsFunc
	previousNewNamed := newNamedNetnsFunc
	t.Cleanup(func() {
		netnsNamedDir = previousDir
		deleteNamedNetnsFunc = previousDelete
		newNamedNetnsFunc = previousNewNamed
	})
	deleteNamedNetnsFunc = func(string) error { return nil }
	newNamedErr := stderrors.New("injected NewNamed failure")
	newNamedNetnsFunc = func(string) (netns.NsHandle, error) {
		return netns.None(), newNamedErr
	}

	err := (&DaeNetns{log: logrus.New()}).setupNetns()
	if !stderrors.Is(err, newNamedErr) {
		t.Fatalf("setupNetns() = %v, want the injected NewNamed failure", err)
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		t.Fatalf("prepareNamedNetns did not create %s (err=%v)", target, statErr)
	}
}

// The shutdown that leaves the mount point behind is the first occurrence of
// the stuck state; Close must log it but not report it as a shutdown failure —
// the setup-failure and reload-handoff callers must not treat a leftover mount
// as a lifecycle failure.
func TestCloseLogsStaleNetnsMountWithoutFailingShutdown(t *testing.T) {
	previousDelete := deleteNamedNetnsFunc
	previousLink := deleteLinkFunc
	t.Cleanup(func() {
		deleteNamedNetnsFunc = previousDelete
		deleteLinkFunc = previousLink
	})
	staleErr := stderrors.New("remove /run/netns/daens: device or resource busy")
	deleteNamedNetnsFunc = func(string) error { return staleErr }
	deleteLinkFunc = func(string) error { return nil }

	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	ns := newDaeNetnsWithCurrentHandles(t)
	ns.mu.Lock()
	ns.log = log
	ns.mu.Unlock()
	if err := ns.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil for a leftover mount", err)
	}
	if !strings.Contains(buf.String(), "Failed to clean up named netns") ||
		!strings.Contains(buf.String(), "device or resource busy") {
		t.Fatalf("Close() did not log the stale mount: %q", buf.String())
	}
}

// A successful cleanup must stay silent: healthy hosts would otherwise warn on
// every shutdown.
func TestCloseIsSilentWhenNamedNetnsCleanupSucceeds(t *testing.T) {
	previousDelete := deleteNamedNetnsFunc
	previousLink := deleteLinkFunc
	t.Cleanup(func() {
		deleteNamedNetnsFunc = previousDelete
		deleteLinkFunc = previousLink
	})
	deleteNamedNetnsFunc = func(string) error { return nil }
	deleteLinkFunc = func(string) error { return nil }

	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	ns := newDaeNetnsWithCurrentHandles(t)
	ns.mu.Lock()
	ns.log = log
	ns.mu.Unlock()
	if err := ns.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	if buf.String() != "" {
		t.Fatalf("Close() logged on a healthy cleanup: %q", buf.String())
	}
}

// The #1086 contract that every following startup depends on: try a
// synchronous unmount, fall back to the lazy MNT_DETACH one only when it
// fails. The fallback covers a mount point that is genuinely busy — another
// process holding a reference through the /run/netns path. dae itself does not
// hold one: its handles come from /proc/<pid>/task/<tid>/ns/net rather than
// from the bind mount, so a clean shutdown takes the synchronous path. A
// regression here would leak the mount point whenever the synchronous unmount
// is the one that cannot complete, while the suite stayed green.
func TestDeleteNamedNetnsFallsBackToLazyUnmount(t *testing.T) {
	dir := redirectNetnsNamedDir(t)
	if err := os.WriteFile(filepath.Join(dir, "dae-test-busy"), nil, 0o644); err != nil {
		t.Fatalf("prepare entry: %v", err)
	}
	previous := unmountFunc
	var flags []int
	unmountFunc = func(_ string, flag int) error {
		flags = append(flags, flag)
		if flag == 0 {
			return unix.EBUSY
		}
		return nil
	}
	t.Cleanup(func() { unmountFunc = previous })

	if err := DeleteNamedNetns("dae-test-busy"); err != nil {
		t.Fatalf("DeleteNamedNetns(busy entry) = %v, want nil after the lazy fallback", err)
	}
	if len(flags) != 2 || flags[0] != 0 || flags[1] != unix.MNT_DETACH {
		t.Fatalf("unmount flags = %v, want a synchronous attempt then MNT_DETACH", flags)
	}
}

// The name reaches unmount(2) and unlink(2) as a path component: a traversal
// name must be rejected before either call, not resolved.
func TestDeleteNamedNetnsRejectsTraversalName(t *testing.T) {
	dir := redirectNetnsNamedDir(t)
	victim := filepath.Join(filepath.Dir(dir), "netns1109-victim")
	if err := os.WriteFile(victim, nil, 0o644); err != nil {
		t.Fatalf("prepare victim outside the netns dir: %v", err)
	}

	if err := DeleteNamedNetns("../netns1109-victim"); err == nil {
		t.Fatal("DeleteNamedNetns accepted a traversal name")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("entry outside the netns directory was touched: %v", err)
	}
}

const (
	netns1109ChildEnv = "DAE_TEST_NETNS1109_CHILD"
	netns1109OK       = "NETNS1109-OK"
	netns1109Fail     = "NETNS1109-FAIL"
	netns1109Skip     = "NETNS1109-SKIP"
)

// TestDeleteNamedNetnsKernelLockedMount exercises the issue #1109 incident
// shape end to end: /run/netns/daens is an nsfs mount point inherited across a
// user namespace boundary, so the kernel marks the copy MNT_LOCKED and rejects
// every umount(2) flag combination with EINVAL — the state reported on
// ImmortalWrt and on Debian LXC guests. Needs nested user namespaces and the
// unshare(1) helper; it skips wherever the environment cannot build that
// shape.
func TestDeleteNamedNetnsKernelLockedMount(t *testing.T) {
	if os.Getenv(netns1109ChildEnv) != "" {
		testNetns1109Child(t)
		return
	}
	unsharePath, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare(1) is not available")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Skipf("cannot resolve the test binary: %v", err)
	}

	// Inner role: re-exec this binary inside a further userns+mountns clone.
	// The second user namespace is the privilege boundary that locks the
	// inherited mounts (MNT_LOCKED), which the first namespace alone does not
	// produce.
	childCmd := fmt.Sprintf("exec %s --user --map-root-user --mount %s -test.run '^%s$'",
		unsharePath, testBinary, "TestDeleteNamedNetnsKernelLockedMount")
	outerScript := fmt.Sprintf(`
set -e
mount --make-rprivate /
# /run is shared with the host and may not be writable for an unprivileged
# runner, and writing there would leave /run/netns behind on the host. Overlay
# it inside this private mount namespace instead: no host privilege, no host
# side effect.
mount -t tmpfs -o mode=755 tmpfs /run
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
touch /run/netns/%[1]s
mount --bind /proc/self/ns/net /run/netns/%[1]s
exec %[2]s --user --map-root-user --mount bash -c %[3]q
`, NsName, unsharePath, childCmd)

	cmd := exec.CommandContext(t.Context(), unsharePath,
		"--user", "--map-root-user", "--mount", "--net", "bash", "-c", outerScript)
	// LC_ALL=C keeps the harness-failure text of unshare(1)/mount(8) in the
	// language the restriction probe below matches; the child's own assertions
	// compare Go errno values and are locale-independent.
	cmd.Env = append(os.Environ(), netns1109ChildEnv+"=1", "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	msg := string(out)
	switch {
	case strings.Contains(msg, netns1109OK) && err == nil:
		// Both conditions matter: a child that printed the marker and then
		// died non-zero (a fence or an exit-path failure) must not pass.
		return
	case strings.Contains(msg, netns1109Fail):
		// The shape reproduced and the behavior was wrong. This branch must
		// stay ahead of the restriction heuristic below: whatever errno text
		// a real regression carries, it must never be downgraded to a skip.
		t.Fatalf("behavior regression in the kernel-locked netns shape (err=%v):\n%s", err, msg)
	case strings.Contains(msg, netns1109Skip):
		// A kernel that does not lock the inherited mount cannot reproduce
		// the incident: absence of the shape, not a wrong behavior.
		t.Skipf("kernel-locked netns shape not reproducible here: %s", tailLines(msg))
	case err != nil && isNamespaceRestriction(msg):
		t.Skipf("environment cannot nest user namespaces: %s", tailLines(msg))
	default:
		t.Fatalf("kernel-locked netns harness did not pass (err=%v):\n%s", err, msg)
	}
}

func isNamespaceRestriction(msg string) bool {
	for _, marker := range []string{
		"operation not permitted",
		"Operation not permitted",
		"permission denied",
		"Permission denied",
		"unshare: invalid option",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func tailLines(msg string) string {
	lines := strings.Split(strings.TrimRight(msg, "\n"), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return strings.Join(lines, "; ")
}

// testNetns1109Child runs inside the prepared nested namespace, where
// /run/netns/daens is the kernel-locked mount point, and pins the fixed
// behavior: the deletion reports the kernel's refusal, and setupNetns either
// auto-recovers via the tmpfs cover (locked signature) or fails on the
// cleanup with the real errnos (any other refusal) — never NewNamed's
// misleading "file exists".
func testNetns1109Child(t *testing.T) {
	namedPath := filepath.Join(netnsNamedDir, NsName)
	delErr := DeleteNamedNetns(NsName)

	// Confirm the incident shape from the filesystem, not from the returned
	// error: the shape is a surviving nsfs mount point. A kernel that refuses
	// with another errno (EPERM) still has it; a leftover that is not a mount
	// does not. Reading the shape first is what keeps a swallowed cleanup
	// failure (the secondary defect of issue #1109) from being reported as a
	// kernel that does not lock the inherited mount.
	var st unix.Statfs_t
	statErr := unix.Statfs(namedPath, &st)
	survivor := statErr == nil && st.Type == unix.NSFS_MAGIC
	if delErr == nil {
		if survivor {
			// Only a successful removal clears the entry, so a mount point
			// that is still there means the deletion lost its own failure.
			fmt.Printf("%s: DeleteNamedNetns reported success but %s is still an nsfs mount point\n", netns1109Fail, namedPath)
			return
		}
		fmt.Printf("%s: the inherited mount was not locked by this kernel\n", netns1109Skip)
		return
	}
	if !survivor {
		fmt.Printf("%s: the surviving entry is not an nsfs mount point (err=%v type=%#x)\n", netns1109Skip, statErr, st.Type)
		return
	}

	// The kernel just produced the incident shape, so this is the one place
	// where the shipped gate meets a real refusal instead of a hand-built
	// error: read the documented signature from the raw per-stage errnos and
	// require isKernelLockedMount to agree with it. Without that equivalence
	// check, a tightened gate would silently degrade auto-recovery to
	// fail-fast and the branch below would keep passing, while a loosened one
	// would hide /run/netns for a condition a retry or a manual cleanup
	// fixes. Kernels that refuse with another errno (EPERM) leave both sides
	// false and still exercise the fail-fast branch.
	rawLocked := false
	var stale *staleNetnsError
	if stderrors.As(delErr, &stale) {
		rawLocked = stderrors.Is(stale.syncErr, unix.EINVAL) &&
			stderrors.Is(stale.lazyErr, unix.EINVAL) &&
			stderrors.Is(stale.removeErr, unix.EBUSY)
	}
	lockedGate := isKernelLockedMount(delErr)
	if lockedGate != rawLocked {
		t.Fatalf("%s: the kernel's refusal (locked signature=%v) and the shipped recovery gate (gated=%v) disagree: %v", netns1109Fail, rawLocked, lockedGate, delErr)
	}

	setupErr := (&DaeNetns{log: logrus.New()}).setupNetns()
	if lockedGate {
		// The locked signature engages the automatic recovery: the tmpfs
		// cover hides the locked entry, so setupNetns must get past the
		// cleanup and past NewNamed, and stop only on this bare harness's
		// zero host handle — the proof a real start would have proceeded on
		// a clean directory.
		if setupErr == nil || !strings.Contains(setupErr.Error(), "host netns") {
			t.Fatalf("%s: the locked signature was not auto-recovered (err=%v): the setup did not get past the cleanup", netns1109Fail, setupErr)
		}
		// The fresh entry NewNamed created on the cover is the state the
		// next start builds on.
		var st unix.Statfs_t
		if err := unix.Statfs(namedPath, &st); err != nil || st.Type != unix.NSFS_MAGIC {
			t.Fatalf("%s: no fresh nsfs entry at %s after the recovery (err=%v type=%#x)", netns1109Fail, namedPath, err, st.Type)
		}
	} else {
		// A kernel refusing with a different errno does not match the
		// recovery gate; it still has to fail fast instead of walking into
		// NewNamed's "file exists".
		if setupErr == nil {
			t.Fatalf("%s: setupNetns succeeded against a stale nsfs mount", netns1109Fail)
		}
		if strings.Contains(setupErr.Error(), "file exists") {
			t.Fatalf("%s: setupNetns still reports NewNamed's misleading error: %v", netns1109Fail, setupErr)
		}
		if !strings.Contains(setupErr.Error(), "failed to clean up the stale named netns") {
			t.Fatalf("%s: setupNetns did not fail on the cleanup: %v", netns1109Fail, setupErr)
		}
		// Fidelity of the wrap is kernel-independent: every errno the
		// deletion reported must stay matchable through setupNetns.
		for _, errno := range []error{unix.EINVAL, unix.EBUSY, unix.EPERM} {
			if stderrors.Is(delErr, errno) && !stderrors.Is(setupErr, errno) {
				t.Fatalf("%s: setupNetns dropped the %v reported by the deletion: %v", netns1109Fail, errno, setupErr)
			}
		}
		// Documented manual fallback for environments that deny the
		// automatic cover: pin that it still unblocks a start.
		if err := unix.Mount("tmpfs", netnsNamedDir, "tmpfs", 0, "mode=755"); err != nil {
			t.Fatalf("%s: manual tmpfs cover failed: %v", netns1109Fail, err)
		}
		if err := DeleteNamedNetns(NsName); err != nil {
			t.Fatalf("%s: leftover still blocks deletion after tmpfs cover: %v", netns1109Fail, err)
		}
		if fd, err := os.OpenFile(namedPath, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o444); err != nil {
			t.Fatalf("%s: NewNamed's O_CREATE|O_EXCL still fails after tmpfs cover: %v", netns1109Fail, err)
		} else {
			_ = fd.Close()
		}
	}
	fmt.Println(netns1109OK)
}
