package cmd

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

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
