package dialer

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

func newRecoveryTestDialer() *Dialer {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	d := NewDialer(
		direct.SymmetricDirect,
		&GlobalOption{
			Log:           logger,
			CheckInterval: 30 * time.Second,
		},
		InstanceOption{},
		&Property{
			Property: D.Property{
				Name: "test",
			},
		},
	)
	return d
}

func TestIssue1_DeadlockFixed(t *testing.T) {
	d := newRecoveryTestDialer()
	d.GlobalOption.CheckInterval = 30 * time.Second

	d.initRecoveryDetection(30 * time.Second)

	// Verify that calculateBackoffDurationLocked doesn't acquire the lock
	d.recoveryState[idxTcp].Lock()
	d.recoveryState[idxTcp].backoffLevel = 2

	done := make(chan bool, 1)
	go func() {
		duration := d.calculateBackoffDurationLocked(2, d.recoveryState[idxTcp].maxBackoff)
		if duration <= 0 {
			t.Errorf("Invalid duration: %v", duration)
		}
		done <- true
	}()

	select {
	case <-done:
		d.recoveryState[idxTcp].Unlock()
	case <-time.After(2 * time.Second):
		d.recoveryState[idxTcp].Unlock()
		t.Fatal("Deadlock detected in calculateBackoffDurationLocked")
	}
}

func TestIssue2_MaxBackoffNowUsed(t *testing.T) {
	checkInterval := 90 * time.Second
	expectedMaxBackoff := time.Duration(float64(checkInterval) * 2.0 / 3.0)

	d := newRecoveryTestDialer()
	d.GlobalOption.CheckInterval = checkInterval

	d.initRecoveryDetection(checkInterval)

	d.recoveryState[idxTcp].Lock()
	actualMaxBackoff := d.recoveryState[idxTcp].maxBackoff
	d.recoveryState[idxTcp].Unlock()

	if actualMaxBackoff != expectedMaxBackoff {
		t.Errorf("Expected maxBackoff=%v, got %v", expectedMaxBackoff, actualMaxBackoff)
	}
}

func TestRevivalTrigger(t *testing.T) {
	d := newRecoveryTestDialer()
	d.GlobalOption.CheckInterval = 30 * time.Second
	d.initRecoveryDetection(30 * time.Second)

	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. Success with isRevival=false should NOT start timer
	d.NotifyHealthCheckResult(typ, true, false)
	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer != nil {
		d.recoveryState[idxTcp].Unlock()
		t.Error("Timer started on non-revival success")
	}
	d.recoveryState[idxTcp].Unlock()

	// 2. Success with isRevival=true SHOULD start timer
	d.NotifyHealthCheckResult(typ, true, true)
	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer == nil {
		d.recoveryState[idxTcp].Unlock()
		t.Error("Timer NOT started on revival success")
	} else {
		d.recoveryState[idxTcp].confirmTimer.Stop()
		d.recoveryState[idxTcp].confirmTimer = nil
	}
	d.recoveryState[idxTcp].Unlock()
}

func TestConcurrentBackoffAccess(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(nil)

	d := &Dialer{
		GlobalOption: &GlobalOption{
			Log:           logger,
			CheckInterval: 30 * time.Second,
		},
		property: &Property{
			Property: D.Property{
				Name: "test",
			},
		},
	}

	d.initRecoveryDetection(30 * time.Second)

	var wg sync.WaitGroup
	iterations := 100

	for i := 0; i < iterations; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			d.getRecoveryBackoffDuration(consts.L4ProtoStr_UDP)
		}()

		go func() {
			defer wg.Done()
			d.resetStabilityCount(consts.L4ProtoStr_UDP)
		}()
	}

	wg.Wait()
}
