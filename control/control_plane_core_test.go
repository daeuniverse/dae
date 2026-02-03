package control

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestControlPlaneCore_Flip_Race(t *testing.T) {
	// coreFlip is global in package control.
	// Reset it to 0 for deterministic test.
	atomic.StoreInt32(&coreFlip, 0)

	// Since Flip() doesn't access any struct fields, we can use an empty struct.
	c := &controlPlaneCore{}

	var wg sync.WaitGroup
	iterations := 1000 // Must be even

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Flip()
		}()
	}

	wg.Wait()

	val := atomic.LoadInt32(&coreFlip)
	// If atomic operations are correct, flipping 0 an even number of times should result in 0.
	// If a race occurred (e.g. lost update), the result might be 1.
	if val != 0 {
		t.Errorf("Expected coreFlip to be 0 after %d flips, got %d. Race condition detected.", iterations, val)
	}
}
