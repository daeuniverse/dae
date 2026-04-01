package dialer

import (
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
)

func TestRecoveryTimerCancellation(t *testing.T) {
	globalRecoveryBackoffLevelStore.Reset()
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. Trigger failure -> Level increases to 1
	d.NotifyHealthCheckResult(typ, false, false)
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 1 {
		t.Errorf("Expected level 1 after failure, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}

	// 2. Trigger revival -> Timer starts
	d.NotifyHealthCheckResult(typ, true, true)

	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer == nil {
		d.recoveryState[idxTcp].Unlock()
		t.Fatal("Expected timer to be started after revival")
	}
	d.recoveryState[idxTcp].Unlock()

	// 3. Trigger another failure -> Timer should be cancelled, level increases to 2
	d.lastPunish[idxTcp].Store(0)
	d.NotifyHealthCheckResult(typ, false, false)

	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer != nil {
		d.recoveryState[idxTcp].Unlock()
		t.Error("Expected timer to be cancelled after failure")
	}
	if d.recoveryState[idxTcp].backoffLevel != 2 {
		t.Errorf("Expected level 2 after second failure, got %d", d.recoveryState[idxTcp].backoffLevel)
	}
	d.recoveryState[idxTcp].Unlock()
}

func TestEmergencyProbeNonPunishment(t *testing.T) {
	globalRecoveryBackoffLevelStore.Reset()
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. Node is healthy (level 0)
	// 2. Trigger emergency probe (isRevival=false in new connectivity_check.go logic)
	d.NotifyHealthCheckResult(typ, true, false)

	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 0 {
		t.Errorf("Expected level 0 to remain 0 after emergency probe, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}

	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer != nil {
		d.recoveryState[idxTcp].Unlock()
		t.Error("Expected no timer for emergency probe on healthy node")
	}
	d.recoveryState[idxTcp].Unlock()
}

func TestBackoffOverflowProtection(t *testing.T) {
	globalRecoveryBackoffLevelStore.Reset()
	d := newRecoveryTestDialer()
	maxBackoff := 30 * time.Second
	d.recoveryState[idxTcp].maxBackoff = maxBackoff

	// Test level capping (maxBackoffLevel = 6)
	for i := 0; i < 10; i++ {
		d.lastPunish[idxTcp].Store(0)
		d.incrementBackoffLevel(consts.L4ProtoStr_TCP)
	}

	level := d.GetBackoffLevel(consts.L4ProtoStr_TCP)
	if level != 6 {
		t.Errorf("Expected level capped at 6, got %d", level)
	}

	duration := d.getRecoveryBackoffDuration(consts.L4ProtoStr_TCP)
	// 10s * 2^6 = 640s -> capped at 30s
	if duration != maxBackoff {
		t.Errorf("Expected duration to be capped at %v, got %v", maxBackoff, duration)
	}
}

func TestRecoveryConfirmationDecrementsLevel(t *testing.T) {
	globalRecoveryBackoffLevelStore.Reset()
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. Fail -> level 1
	d.NotifyHealthCheckResult(typ, false, false)

	// 2. Revive -> starts timer
	d.NotifyHealthCheckResult(typ, true, true)

	// 3. Confirm -> level becomes 0
	d.confirmRecovery(typ, nil)

	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 0 {
		t.Errorf("Expected level 0 after successful confirmation, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}
}

func TestDualStackRecoveryInterference(t *testing.T) {
	globalRecoveryBackoffLevelStore.Reset()
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)

	tcp4 := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	tcp6 := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6}

	// 1. Initial State: Both dead, Level 2
	d.lastPunish[idxTcp].Store(0)
	d.incrementBackoffLevel(consts.L4ProtoStr_TCP)
	d.lastPunish[idxTcp].Store(0)
	d.incrementBackoffLevel(consts.L4ProtoStr_TCP)
	d.collections[IdxTcp4].Alive.Store(false)
	d.collections[IdxTcp6].Alive.Store(false)

	// 2. Both revive. TCP4 sets the timer.
	d.NotifyHealthCheckResult(tcp4, true, true)
	d.collections[IdxTcp4].Alive.Store(true)

	d.NotifyHealthCheckResult(tcp6, true, true)
	d.collections[IdxTcp6].Alive.Store(true)

	// Verify timer is running for TCP4
	d.recoveryState[idxTcp].Lock()
	if d.recoveryState[idxTcp].confirmTimer == nil {
		d.recoveryState[idxTcp].Unlock()
		t.Fatal("Expected timer to be running")
	}
	d.recoveryState[idxTcp].Unlock()

	// 3. TCP4 fails again. In the old logic, this would abort recovery even if TCP6 is alive.
	// We manually simulate TCP4 failure WITHOUT calling NotifyHealthCheckResult(success=false)
	// because that would cancel the timer (correctly).
	// We want to test the case where the timer EXPIRES and confirmRecovery is called,
	// but the original pendingNetworkType (TCP4) is now dead, while TCP6 is still alive.
	d.collections[IdxTcp4].Alive.Store(false)

	// 4. Confirm recovery (Simulate timer firing)
	d.confirmRecovery(tcp4, nil)

	// 5. Check results: Level should decrease to 1 because TCP6 was alive.
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 1 {
		t.Errorf("Expected level 1 after recovery (one stack alive), got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}
}

func TestDeduplicatedPunishment(t *testing.T) {
	globalRecoveryBackoffLevelStore.Reset()
	d := newRecoveryTestDialer()
	typ4 := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	typ6 := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_6}

	// 1. Trigger dual failures rapidly (simulating parallel health check cycle)
	d.NotifyHealthCheckResult(typ4, false, false)
	d.NotifyHealthCheckResult(typ6, false, false)

	// 2. Expected level 1 (deduplicated), not level 2
	level := d.GetBackoffLevel(consts.L4ProtoStr_TCP)
	if level != 1 {
		t.Errorf("Expected deduplicated punishment level 1, got %d", level)
	}

	// 3. Reset cooldown and trigger again
	d.lastPunish[idxTcp].Store(0)
	d.NotifyHealthCheckResult(typ4, false, false)

	level = d.GetBackoffLevel(consts.L4ProtoStr_TCP)
	if level != 2 {
		t.Errorf("Expected incremented level 2 after cooldown reset, got %d", level)
	}
}

func TestAliveTransitionCallbackOnlyFiresOnStateChanges(t *testing.T) {
	d := newRecoveryTestDialer()
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, UdpHealthDomain: UdpHealthDomainData}

	var transitions []bool
	d.RegisterAliveTransitionCallback(func(networkType *NetworkType, alive bool) {
		if networkType.L4Proto == typ.L4Proto && networkType.IpVersion == typ.IpVersion {
			transitions = append(transitions, alive)
		}
	})

	d.ReportUnavailableForced(typ, io.EOF)
	d.ReportUnavailableForced(typ, io.EOF)
	d.markAvailable(typ, time.Millisecond)
	d.markAvailable(typ, time.Millisecond)

	if len(transitions) != 2 {
		t.Fatalf("transition count = %d, want 2", len(transitions))
	}
	if transitions[0] {
		t.Fatal("expected first transition to be not alive")
	}
	if !transitions[1] {
		t.Fatal("expected second transition to be alive")
	}
}

func TestRecoveryBackoffStoreReleasedAfterLastCloneCloses(t *testing.T) {
	globalRecoveryBackoffLevelStore.Reset()

	d := newNamedRecoveryTestDialer("clone-test")
	d.lastPunish[idxTcp].Store(0)
	d.incrementBackoffLevel(consts.L4ProtoStr_TCP)

	clone := d.Clone()
	if got := clone.GetBackoffLevel(consts.L4ProtoStr_TCP); got != 1 {
		t.Fatalf("clone backoff level = %d, want 1", got)
	}

	if err := d.Close(); err != nil {
		t.Fatalf("close original dialer: %v", err)
	}

	globalRecoveryBackoffLevelStore.RLock()
	entry, ok := globalRecoveryBackoffLevelStore.levels["clone-test"]
	globalRecoveryBackoffLevelStore.RUnlock()
	if !ok {
		t.Fatal("expected recovery entry to remain while clone is alive")
	}
	if entry.refs != 1 {
		t.Fatalf("recovery entry refs = %d, want 1", entry.refs)
	}
	if entry.levels[idxTcp] != 1 {
		t.Fatalf("recovery entry tcp level = %d, want 1", entry.levels[idxTcp])
	}

	if err := clone.Close(); err != nil {
		t.Fatalf("close cloned dialer: %v", err)
	}

	globalRecoveryBackoffLevelStore.RLock()
	_, ok = globalRecoveryBackoffLevelStore.levels["clone-test"]
	globalRecoveryBackoffLevelStore.RUnlock()
	if ok {
		t.Fatal("expected recovery entry to be removed after last dialer closed")
	}
}
