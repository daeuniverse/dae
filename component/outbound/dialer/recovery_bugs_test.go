package dialer

import (
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func TestRecoveryTimerCancellation(t *testing.T) {
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. Trigger revival -> Timer starts
	d.NotifyHealthCheckResult(typ, true, true)
	
	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer == nil {
		d.recoveryState[idxTcp].Unlock()
		t.Fatal("Expected timer to be started")
	}
	d.recoveryState[idxTcp].Unlock()

	// 2. Trigger failure -> Timer should be cancelled
	d.NotifyHealthCheckResult(typ, false, false)

	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer != nil {
		d.recoveryState[idxTcp].Unlock()
		t.Error("Expected timer to be cancelled after failure")
	}
	d.recoveryState[idxTcp].Unlock()
}

func TestBackoffOverflowProtection(t *testing.T) {
	d := newRecoveryTestDialer()
	// Set a reasonable max backoff
	maxBackoff := 30 * time.Second
	d.recoveryState[idxTcp].maxBackoff = maxBackoff

	// 1. Test with a very high level that would normally overflow int64
	// 2^60 * 10s will definitely overflow
	d.recoveryState[idxTcp].backoffLevel = 60
	
	duration := d.getRecoveryBackoffDuration(consts.L4ProtoStr_TCP)
	
	if duration != maxBackoff {
		t.Errorf("Expected duration to be capped at %v, got %v", maxBackoff, duration)
	}

	// 2. Test with a level that is large but doesn't overflow yet but exceeds maxBackoff
	d.recoveryState[idxTcp].backoffLevel = 10 // 2^10 * 10s = 10240s
	duration = d.getRecoveryBackoffDuration(consts.L4ProtoStr_TCP)
	if duration != maxBackoff {
		t.Errorf("Expected duration to be capped at %v, got %v", maxBackoff, duration)
	}
}

func TestRecoveryAbortOnShutdown(t *testing.T) {
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// Trigger revival
	d.NotifyHealthCheckResult(typ, true, true)
	
	// Close dialer
	d.Close()

	// The confirmRecovery function should abort if called
	// We can't easily test the internal select but we can verify no panic/leak
	d.confirmRecovery(typ)
}
