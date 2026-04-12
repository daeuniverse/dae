package control

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestControlPlaneCore_Flip_Race(t *testing.T) {
	// coreFlip is global in package control.
	// Reset it to 0 for deterministic test.
	atomic.StoreInt32(&coreFlip, 0)

	// Since Flip() doesn't access any struct fields, we can use an empty struct.
	c := &controlPlaneCore{}

	var wg sync.WaitGroup
	iterations := 1000 // Must be even

	for range iterations {
		wg.Go(func() {
			c.Flip()
		})
	}

	wg.Wait()

	val := atomic.LoadInt32(&coreFlip)
	// If atomic operations are correct, flipping 0 an even number of times should result in 0.
	// If a race occurred (e.g. lost update), the result might be 1.
	if val != 0 {
		t.Errorf("Expected coreFlip to be 0 after %d flips, got %d. Race condition detected.", iterations, val)
	}
}

func TestControlPlaneCore_EjectBpfKeepsHookCleanupForClose(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	core := newControlPlaneCore(logger, nil, nil, nil, false)
	calls := 0
	core.addManagedBpfHookCleanup(func() error {
		calls++
		return nil
	})

	core.EjectBpf()
	if core.bpfOwned {
		t.Fatal("expected EjectBpf to transfer BPF ownership")
	}

	if err := core.Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("expected hook cleanup to run once after EjectBpf, got %d", calls)
	}
}
