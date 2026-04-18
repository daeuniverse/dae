package dialer

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	D "github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/sirupsen/logrus"
)

func TestRecoveryTimerCancellation(t *testing.T) {
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
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	// 1. Fail -> level 1
	d.NotifyHealthCheckResult(typ, false, false)

	// 2. Revive -> starts timer
	d.NotifyHealthCheckResult(typ, true, true)
	confirmSequence := d.recoveryState[idxTcp].confirmSequence

	// 3. Confirm -> level becomes 0
	d.confirmRecovery(typ, confirmSequence)

	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 0 {
		t.Errorf("Expected level 0 after successful confirmation, got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}
}

func TestDualStackRecoveryInterference(t *testing.T) {
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
	confirmSequence := d.recoveryState[idxTcp].confirmSequence

	// 4. Confirm recovery (Simulate timer firing)
	d.confirmRecovery(tcp4, confirmSequence)

	// 5. Check results: Level should decrease to 1 because TCP6 was alive.
	if d.GetBackoffLevel(consts.L4ProtoStr_TCP) != 1 {
		t.Errorf("Expected level 1 after recovery (one stack alive), got %d", d.GetBackoffLevel(consts.L4ProtoStr_TCP))
	}
}

func TestRecoveryConfirmationIgnoresStaleCallback(t *testing.T) {
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	state := &d.recoveryState[idxTcp]
	state.Lock()
	state.backoffLevel = 1
	state.pendingNetworkType = cloneNetworkType(typ)
	staleSequence := state.nextConfirmSequenceLocked()
	currentTimer := time.NewTimer(time.Hour)
	state.confirmTimer = currentTimer
	state.confirmDeadlineUnixNano = time.Now().Add(time.Minute).UnixNano()
	currentSequence := state.nextConfirmSequenceLocked()
	state.Unlock()
	defer currentTimer.Stop()

	d.collections[IdxTcp4].Alive.Store(true)
	d.confirmRecovery(typ, staleSequence)

	state.Lock()
	timer := state.confirmTimer
	sequence := state.confirmSequence
	backoffLevel := state.backoffLevel
	state.Unlock()

	if timer != currentTimer {
		t.Fatal("stale callback should not clear the current confirmation timer")
	}
	if sequence != currentSequence {
		t.Fatalf("confirmSequence = %d, want %d", sequence, currentSequence)
	}
	if backoffLevel != 1 {
		t.Fatalf("backoffLevel = %d, want 1", backoffLevel)
	}
}

func TestRecoveryConfirmationSequenceRemainsMonotonicAcrossCancelAndRearm(t *testing.T) {
	d := newRecoveryTestDialer()
	d.initRecoveryDetection(60 * time.Second)
	typ := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}

	d.NotifyHealthCheckResult(typ, false, false)
	d.NotifyHealthCheckResult(typ, true, true)

	state := &d.recoveryState[idxTcp]
	state.Lock()
	firstSequence := state.confirmSequence
	firstTimer := state.confirmTimer
	state.Unlock()
	if firstTimer == nil {
		t.Fatal("expected first recovery confirmation timer to be armed")
	}

	d.lastPunish[idxTcp].Store(0)
	d.NotifyHealthCheckResult(typ, false, false)
	d.collections[IdxTcp4].Alive.Store(true)
	d.NotifyHealthCheckResult(typ, true, true)

	state.Lock()
	secondSequence := state.confirmSequence
	secondTimer := state.confirmTimer
	backoffLevel := state.backoffLevel
	state.Unlock()
	if secondTimer == nil {
		t.Fatal("expected re-armed recovery confirmation timer")
	}
	if secondSequence <= firstSequence {
		t.Fatalf("confirmSequence did not advance after re-arm: first=%d second=%d", firstSequence, secondSequence)
	}

	d.confirmRecovery(typ, firstSequence)

	state.Lock()
	currentTimer := state.confirmTimer
	currentSequence := state.confirmSequence
	currentBackoffLevel := state.backoffLevel
	state.Unlock()

	if currentTimer != secondTimer {
		t.Fatal("stale callback should not clear the re-armed confirmation timer")
	}
	if currentSequence != secondSequence {
		t.Fatalf("confirmSequence = %d, want %d", currentSequence, secondSequence)
	}
	if currentBackoffLevel != backoffLevel {
		t.Fatalf("backoffLevel = %d, want %d", currentBackoffLevel, backoffLevel)
	}
}

func TestDeduplicatedPunishment(t *testing.T) {
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

func TestCloneStartsWithCleanBackoffState(t *testing.T) {
	d := newNamedRecoveryTestDialer("clone-test")
	defer func() { _ = d.Close() }()
	d.lastPunish[idxTcp].Store(0)
	d.incrementBackoffLevel(consts.L4ProtoStr_TCP)

	clone := d.Clone()
	defer func() { _ = clone.Close() }()

	if got := clone.GetBackoffLevel(consts.L4ProtoStr_TCP); got != 0 {
		t.Fatalf("clone backoff level = %d, want 0", got)
	}
}

func TestCloneWithGlobalOptionUsesOverrideCheckInterval(t *testing.T) {
	d := newNamedRecoveryTestDialer("clone-option-test")
	defer func() { _ = d.Close() }()

	override := &GlobalOption{
		ExtraOption: d.ExtraOption,
		Log:         d.Log,
		TcpCheckOptionRaw: TcpCheckOptionRaw{
			Log:             d.TcpCheckOptionRaw.Log,
			Raw:             slices.Clone(d.TcpCheckOptionRaw.Raw),
			ResolverNetwork: d.TcpCheckOptionRaw.ResolverNetwork,
			Method:          d.TcpCheckOptionRaw.Method,
		},
		CheckDnsOptionRaw: CheckDnsOptionRaw{
			Raw:             slices.Clone(d.CheckDnsOptionRaw.Raw),
			ResolverNetwork: d.CheckDnsOptionRaw.ResolverNetwork,
			Somark:          d.CheckDnsOptionRaw.Somark,
		},
		CheckInterval:  90 * time.Second,
		CheckTolerance: d.CheckTolerance,
		CheckDnsTcp:    d.CheckDnsTcp,
		SoMarkFromDae:  d.SoMarkFromDae,
		Mptcp:          d.Mptcp,
	}

	clone := d.CloneWithGlobalOption(override)
	defer func() { _ = clone.Close() }()

	clone.recoveryState[idxTcp].Lock()
	got := clone.recoveryState[idxTcp].maxBackoff
	clone.recoveryState[idxTcp].Unlock()

	want := 60 * time.Second
	if got != want {
		t.Fatalf("clone maxBackoff = %v, want %v", got, want)
	}
}

func TestRestoreHealthSnapshotRestoresCollectionState(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	opt := &GlobalOption{
		Log:            log,
		CheckInterval:  30 * time.Second,
		CheckTolerance: time.Second,
	}
	src := NewDialer(nil, opt, InstanceOption{}, &Property{Property: D.Property{Name: "src"}})
	dst := NewDialer(nil, opt, InstanceOption{}, &Property{Property: D.Property{Name: "dst"}})

	tcp4 := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	update, _ := src.markAvailable(tcp4, 120*time.Millisecond)
	src.informDialerGroupUpdate(update)
	src.informDialerGroupUpdate(src.markUnavailableInternal(&NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		IsDns:           true,
		UdpHealthDomain: UdpHealthDomainDns,
	}, true, false))

	dst.RestoreHealthSnapshot(src.HealthSnapshot())

	if !dst.MustGetAlive(tcp4) {
		t.Fatal("expected restored TCP dialer health to be alive")
	}
	last, ok := dst.MustGetLatencies10(tcp4).LastLatency()
	if !ok || last != 120*time.Millisecond {
		t.Fatalf("restored TCP last latency = %v, %v, want 120ms, true", last, ok)
	}

	udpDns4 := &NetworkType{L4Proto: consts.L4ProtoStr_UDP, IpVersion: consts.IpVersionStr_4, IsDns: true, UdpHealthDomain: UdpHealthDomainDns}
	if dst.MustGetAlive(udpDns4) {
		t.Fatal("expected restored DNS-UDP dialer health to be unavailable")
	}
}

func TestRestoreHealthSnapshotRestoresRecoveryState(t *testing.T) {
	src := newNamedRecoveryTestDialer("src-recovery")
	defer func() { _ = src.Close() }()
	dst := newNamedRecoveryTestDialer("dst-recovery")
	defer func() { _ = dst.Close() }()

	src.lastPunish[idxTcp].Store(0)
	src.incrementBackoffLevel(consts.L4ProtoStr_TCP)
	src.recoveryState[idxTcp].Lock()
	src.recoveryState[idxTcp].stableSuccessCount = 1
	src.recoveryState[idxTcp].Unlock()
	src.lastPunish[idxTcp].Store(1234)

	dst.RestoreHealthSnapshot(src.HealthSnapshot())

	if got := dst.GetBackoffLevel(consts.L4ProtoStr_TCP); got != 1 {
		t.Fatalf("restored TCP backoff level = %d, want 1", got)
	}
	dst.recoveryState[idxTcp].Lock()
	stableSuccessCount := dst.recoveryState[idxTcp].stableSuccessCount
	dst.recoveryState[idxTcp].Unlock()
	if stableSuccessCount != 1 {
		t.Fatalf("restored stableSuccessCount = %d, want 1", stableSuccessCount)
	}
	if got := dst.lastPunish[idxTcp].Load(); got != 1234 {
		t.Fatalf("restored lastPunish = %d, want 1234", got)
	}
}

func TestReloadHealthSnapshotPreservesAvailabilityAndClearsPunishment(t *testing.T) {
	src := newNamedRecoveryTestDialer("src-reload")
	defer func() { _ = src.Close() }()
	dst := newNamedRecoveryTestDialer("dst-reload")
	defer func() { _ = dst.Close() }()

	tcp4 := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	src.ReportUnavailableForced(tcp4, nil)
	if src.MustGetAlive(tcp4) {
		t.Fatal("expected source dialer to be unavailable before reload snapshot")
	}

	src.NotifyHealthCheckResult(tcp4, false, false)
	src.lastPunish[idxTcp].Store(1234)
	src.recoveryState[idxTcp].Lock()
	src.recoveryState[idxTcp].stableSuccessCount = 1
	src.recoveryState[idxTcp].Unlock()

	snapshot := src.ReloadHealthSnapshot()
	if snapshot.Collections[tcp4.Index()].Alive {
		t.Fatal("expected reload snapshot to preserve unavailable state")
	}
	if snapshot.Collections[tcp4.Index()].FailCount != 0 {
		t.Fatalf("reload snapshot failCount = %d, want 0", snapshot.Collections[tcp4.Index()].FailCount)
	}
	if snapshot.Collections[tcp4.Index()].TrafficFailCount != 0 {
		t.Fatalf("reload snapshot trafficFailCount = %d, want 0", snapshot.Collections[tcp4.Index()].TrafficFailCount)
	}
	if len(snapshot.Collections[tcp4.Index()].Latencies.Latencies) == 0 {
		t.Fatal("expected reload snapshot to preserve latency history")
	}
	if snapshot.Recovery[idxTcp].BackoffLevel != 0 {
		t.Fatalf("reload snapshot backoff level = %d, want 0", snapshot.Recovery[idxTcp].BackoffLevel)
	}
	if snapshot.Recovery[idxTcp].StableSuccessCount != 0 {
		t.Fatalf("reload snapshot stableSuccessCount = %d, want 0", snapshot.Recovery[idxTcp].StableSuccessCount)
	}
	if snapshot.Recovery[idxTcp].LastPunishUnixNano != 0 {
		t.Fatalf("reload snapshot lastPunish = %d, want 0", snapshot.Recovery[idxTcp].LastPunishUnixNano)
	}

	dst.RestoreHealthSnapshot(snapshot)

	if dst.reloadInheritedHealth.Load() {
		t.Fatal("expected reload restore NOT to defer health check when some collections are NOT ALIVE")
	}
	if dst.MustGetAlive(tcp4) {
		t.Fatal("expected destination dialer to preserve unavailable state after reload restore")
	}
	if got := dst.GetBackoffLevel(consts.L4ProtoStr_TCP); got != 0 {
		t.Fatalf("restored backoff level = %d, want 0", got)
	}
	last, ok := dst.MustGetLatencies10(tcp4).LastLatency()
	if !ok || last != Timeout {
		t.Fatalf("restored last latency = %v, %v, want %v, true", last, ok, Timeout)
	}
}

func TestRestoreHealthSnapshotRearmsPendingRecoveryConfirmation(t *testing.T) {
	dst := newNamedRecoveryTestDialer("dst-pending-recovery")
	defer func() { _ = dst.Close() }()

	tcp4 := &NetworkType{L4Proto: consts.L4ProtoStr_TCP, IpVersion: consts.IpVersionStr_4}
	snapshot := DialerHealthSnapshot{
		Recovery: [3]DialerRecoveryHealthSnapshot{
			idxTcp: {
				BackoffLevel:        1,
				PendingNetworkType:  tcp4,
				PendingConfirmDelay: 5 * time.Millisecond,
			},
		},
	}

	dst.RestoreHealthSnapshot(snapshot)

	dst.recoveryState[idxTcp].Lock()
	pending := cloneNetworkType(dst.recoveryState[idxTcp].pendingNetworkType)
	timer := dst.recoveryState[idxTcp].confirmTimer
	dst.recoveryState[idxTcp].Unlock()
	if timer == nil {
		t.Fatal("expected pending recovery timer to be re-armed")
	}
	if pending == nil || *pending != *tcp4 {
		t.Fatalf("pending network type = %#v, want %#v", pending, tcp4)
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		dst.recoveryState[idxTcp].Lock()
		timer = dst.recoveryState[idxTcp].confirmTimer
		dst.recoveryState[idxTcp].Unlock()
		if timer == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected pending recovery timer to complete")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRecreatedDialerStartsWithCleanBackoffState(t *testing.T) {
	d := newNamedRecoveryTestDialer("recreate-test")
	d.lastPunish[idxTcp].Store(0)
	d.incrementBackoffLevel(consts.L4ProtoStr_TCP)

	if err := d.Close(); err != nil {
		t.Fatalf("close original dialer: %v", err)
	}

	recreated := newNamedRecoveryTestDialer("recreate-test")
	defer func() { _ = recreated.Close() }()

	if got := recreated.GetBackoffLevel(consts.L4ProtoStr_TCP); got != 0 {
		t.Fatalf("recreated dialer backoff level = %d, want 0", got)
	}
}

func TestReportUnavailableIgnoresTeardownCancellation(t *testing.T) {
	d := newNamedRecoveryTestDialer("teardown-traffic")
	typ := &NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}

	for range 64 {
		d.ReportUnavailable(typ, context.Canceled)
	}

	if !d.MustGetAlive(typ) {
		t.Fatal("teardown cancellation must not mark traffic dialer unavailable")
	}
	if got := d.trafficFailCount[typ.Index()].Load(); got != 0 {
		t.Fatalf("traffic fail counter = %d, want 0", got)
	}
}

func TestReportUnavailableTransactionalIgnoresOperationCanceled(t *testing.T) {
	d := newNamedRecoveryTestDialer("teardown-transactional")
	typ := &NetworkType{
		L4Proto:         consts.L4ProtoStr_UDP,
		IpVersion:       consts.IpVersionStr_4,
		UdpHealthDomain: UdpHealthDomainDns,
		IsDns:           true,
	}

	d.ReportUnavailableTransactional(typ, errors.New("dial udp 1.2.3.4:53: operation was canceled"))

	if !d.MustGetAlive(typ) {
		t.Fatal("teardown cancellation must not mark transactional dialer unavailable")
	}
	if got := d.failCount[typ.Index()]; got != 0 {
		t.Fatalf("transactional fail counter = %d, want 0", got)
	}
}

func TestCloneWithGlobalOptionUsesIndependentStickyIpCycle(t *testing.T) {
	oldGlobalProxyIpCache := globalProxyIpCache
	globalProxyIpCache = NewProxyIpCache()
	defer func() {
		globalProxyIpCache = oldGlobalProxyIpCache
	}()

	log := logrus.New()
	log.SetOutput(io.Discard)
	option := &GlobalOption{
		Log:           log,
		CheckInterval: 30 * time.Second,
	}

	original, err := NewFromLink(option, InstanceOption{}, "custom:ss://YWVzLTEyOC1nY206cGFzcw@proxy.example.com:443#node", "sub")
	if err != nil {
		t.Fatalf("NewFromLink error = %v", err)
	}
	defer func() { _ = original.Close() }()

	clone := original.CloneWithGlobalOption(option)
	defer func() { _ = clone.Close() }()

	if original.stickyIpDialer == nil {
		t.Fatal("expected original stickyIpDialer to be initialized")
	}
	if clone.stickyIpDialer == nil {
		t.Fatal("expected clone stickyIpDialer to be initialized")
	}
	if original.stickyIpDialer == clone.stickyIpDialer {
		t.Fatal("expected clone to have an independent stickyIpDialer")
	}
	if clone.Property().Name != original.Property().Name {
		t.Fatalf("clone name = %q, want %q", clone.Property().Name, original.Property().Name)
	}

	const cachedAddr = "203.0.113.10:443"
	globalProxyIpCache.Set(original.Property().Address, cachedAddr, "tcp", "4", 0)

	if got := original.stickyIpDialer.GetCachedProxyAddrWithIpVersion("tcp", "4"); got != cachedAddr {
		t.Fatalf("original cached addr before clone cycle increment = %q, want %q", got, cachedAddr)
	}

	clone.IncrementCheckCycle()

	if got := original.stickyIpDialer.GetCachedProxyAddrWithIpVersion("tcp", "4"); got != cachedAddr {
		t.Fatalf("original cached addr after clone cycle increment = %q, want %q", got, cachedAddr)
	}
}
