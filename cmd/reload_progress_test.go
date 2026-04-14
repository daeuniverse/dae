package cmd

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func TestWriteReloadSendAndSignalRestoresProgressOnSignalFailure(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	want := []byte{consts.ReloadProcessing, '\n', 'b', 'u', 's', 'y'}
	if err := os.WriteFile(progressPath, want, 0644); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	killErr := stderrors.New("boom")
	err := writeReloadSendAndSignal(progressPath, 1234, func(pid int, sig syscall.Signal) error {
		if pid != 1234 {
			t.Fatalf("pid = %d, want 1234", pid)
		}
		if sig != syscall.SIGUSR1 {
			t.Fatalf("sig = %v, want SIGUSR1", sig)
		}
		return killErr
	})
	if !stderrors.Is(err, killErr) {
		t.Fatalf("writeReloadSendAndSignal() error = %v, want %v", err, killErr)
	}

	got, readErr := os.ReadFile(progressPath)
	if readErr != nil {
		t.Fatalf("ReadFile(): %v", readErr)
	}
	if string(got) != string(want) {
		t.Fatalf("progress content = %q, want %q", string(got), string(want))
	}
}

func TestWriteReloadSendAndSignalRemovesCreatedProgressOnSignalFailure(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	killErr := stderrors.New("boom")

	err := writeReloadSendAndSignal(progressPath, 4321, func(pid int, sig syscall.Signal) error {
		if pid != 4321 {
			t.Fatalf("pid = %d, want 4321", pid)
		}
		if sig != syscall.SIGUSR1 {
			t.Fatalf("sig = %v, want SIGUSR1", sig)
		}
		return killErr
	})
	if !stderrors.Is(err, killErr) {
		t.Fatalf("writeReloadSendAndSignal() error = %v, want %v", err, killErr)
	}
	if _, statErr := os.Stat(progressPath); !os.IsNotExist(statErr) {
		t.Fatalf("Stat() error = %v, want not-exist", statErr)
	}
}

func TestWriteReloadSendAndSignalWritesReloadSendOnSuccess(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")

	if err := writeReloadSendAndSignal(progressPath, 5678, func(pid int, sig syscall.Signal) error {
		if pid != 5678 {
			t.Fatalf("pid = %d, want 5678", pid)
		}
		if sig != syscall.SIGUSR1 {
			t.Fatalf("sig = %v, want SIGUSR1", sig)
		}
		return nil
	}); err != nil {
		t.Fatalf("writeReloadSendAndSignal() error = %v", err)
	}

	got, readErr := os.ReadFile(progressPath)
	if readErr != nil {
		t.Fatalf("ReadFile(): %v", readErr)
	}
	want := []byte{consts.ReloadSend}
	if string(got) != string(want) {
		t.Fatalf("progress content = %q, want %q", string(got), string(want))
	}
}

func TestWaitReloadCompletionReturnsDoneContent(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	if err := writeSignalProgressFile(progressPath, consts.ReloadProcessing, ""); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = writeSignalProgressFile(progressPath, consts.ReloadDone, "OK")
	}()

	code, content, err := waitReloadCompletion(progressPath, 0, 5*time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("waitReloadCompletion() error = %v", err)
	}
	if code != consts.ReloadDone {
		t.Fatalf("code = %v, want ReloadDone", code)
	}
	if content != "OK" {
		t.Fatalf("content = %q, want %q", content, "OK")
	}
}

func TestWaitReloadCompletionWaitsPastReloadSend(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	if err := writeSignalProgressFile(progressPath, consts.ReloadSend, ""); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = writeSignalProgressFile(progressPath, consts.ReloadDone, "OK")
	}()

	code, content, err := waitReloadCompletion(progressPath, 0, 5*time.Millisecond, time.Second)
	if err != nil {
		t.Fatalf("waitReloadCompletion() error = %v", err)
	}
	if code != consts.ReloadDone {
		t.Fatalf("code = %v, want ReloadDone", code)
	}
	if content != "OK" {
		t.Fatalf("content = %q, want %q", content, "OK")
	}
}

func TestWaitReloadCompletionTimesOut(t *testing.T) {
	progressPath := filepath.Join(t.TempDir(), "dae.progress")
	if err := writeSignalProgressFile(progressPath, consts.ReloadProcessing, ""); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	if _, _, err := waitReloadCompletion(progressPath, 0, 5*time.Millisecond, 20*time.Millisecond); err == nil {
		t.Fatal("waitReloadCompletion() error = nil, want timeout")
	}
}
