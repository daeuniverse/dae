package dialer

import (
	"errors"
	"testing"
	"time"
)

func resetReloadFailureSuppressionForTest() {
	reloadProxyFailureSuppression.Store(0)
	reloadProxyFailureSuppressUntil.Store(0)
}

func TestProxyFailureTrackerCleansStaleEntries(t *testing.T) {
	resetGlobalProxyState()

	globalProxyIpHealthTracker.Lock()
	globalProxyIpHealthTracker.failures["stale.example:443"] = proxyIpFailureEntry{
		count:       2,
		lastUpdated: time.Now().Add(-proxyFailureTTL - time.Minute),
	}
	globalProxyIpHealthTracker.nextCleanupAt = time.Time{}
	globalProxyIpHealthTracker.Unlock()

	if recordProxyFailure("fresh.example:443") {
		t.Fatal("unexpected threshold hit for fresh entry")
	}

	globalProxyIpHealthTracker.Lock()
	defer globalProxyIpHealthTracker.Unlock()

	if _, ok := globalProxyIpHealthTracker.failures["stale.example:443"]; ok {
		t.Fatal("stale failure entry was not cleaned up")
	}
	entry, ok := globalProxyIpHealthTracker.failures["fresh.example:443"]
	if !ok {
		t.Fatal("fresh failure entry missing after record")
	}
	if entry.count != 1 {
		t.Fatalf("fresh entry count = %d, want 1", entry.count)
	}
}

func TestResetGlobalProxyStateForReloadClearsGlobalState(t *testing.T) {
	resetGlobalProxyState()

	proxyAddr := "reload.example:443"
	previousCache := globalProxyIpCache

	if recordProxyFailure(proxyAddr) {
		t.Fatal("unexpected threshold hit for first failure before reload reset")
	}

	ResetGlobalProxyStateForReload()

	if globalProxyIpCache == previousCache {
		t.Fatal("expected reload reset to rotate the global proxy cache")
	}

	globalProxyIpHealthTracker.Lock()
	defer globalProxyIpHealthTracker.Unlock()
	if len(globalProxyIpHealthTracker.failures) != 0 {
		t.Fatalf("failure tracker len = %d, want 0 after reload reset", len(globalProxyIpHealthTracker.failures))
	}
	if !globalProxyIpHealthTracker.nextCleanupAt.IsZero() {
		t.Fatal("expected cleanup schedule to be cleared after reload reset")
	}
}

func TestReloadProxyFailureSuppressionSkipsForcedDialerDeath(t *testing.T) {
	resetGlobalProxyState()
	resetReloadFailureSuppressionForTest()
	t.Cleanup(resetReloadFailureSuppressionForTest)

	tcp4 := &NetworkType{L4Proto: "tcp", IpVersion: "4"}

	unsuppressed := newNamedRecoveryTestDialer("unsuppressed")
	defer func() { _ = unsuppressed.Close() }()
	unsuppressed.property.Address = "proxy.example:443"
	for range 3 {
		unsuppressed.NotifyHealthCheckResult(tcp4, false, false)
	}
	if unsuppressed.MustGetAlive(tcp4) {
		t.Fatal("expected repeated proxy failures without suppression to kill the dialer")
	}

	resetGlobalProxyState()

	suppressed := newNamedRecoveryTestDialer("suppressed")
	defer func() { _ = suppressed.Close() }()
	suppressed.property.Address = "proxy.example:443"
	BeginReloadProxyFailureSuppression()
	for range 3 {
		suppressed.NotifyHealthCheckResult(tcp4, false, false)
	}
	EndReloadProxyFailureSuppression()

	if !suppressed.MustGetAlive(tcp4) {
		t.Fatal("expected reload-time suppression to keep the dialer alive")
	}

	globalProxyIpHealthTracker.Lock()
	defer globalProxyIpHealthTracker.Unlock()
	if len(globalProxyIpHealthTracker.failures) != 0 {
		t.Fatalf("failure tracker len = %d, want 0 while suppression is active", len(globalProxyIpHealthTracker.failures))
	}
}

func TestReloadFailureSuppressionSkipsAvailabilityChanges(t *testing.T) {
	resetGlobalProxyState()
	resetReloadFailureSuppressionForTest()
	t.Cleanup(resetReloadFailureSuppressionForTest)

	tcp4 := &NetworkType{L4Proto: "tcp", IpVersion: "4"}
	d := newNamedRecoveryTestDialer("reload-suppressed-availability")
	defer func() { _ = d.Close() }()

	BeginReloadProxyFailureSuppression()
	d.ReportUnavailableTransactional(tcp4, errors.New("simulated reload-time timeout"))
	if !d.MustGetAlive(tcp4) {
		t.Fatal("expected active reload suppression to keep the dialer alive")
	}
	if got := d.failCount[tcp4.Index()]; got != 0 {
		t.Fatalf("fail counter during active suppression = %d, want 0", got)
	}

	EndReloadProxyFailureSuppression()
	d.ReportUnavailableTransactional(tcp4, errors.New("simulated delayed reload-time timeout"))
	if !d.MustGetAlive(tcp4) {
		t.Fatal("expected reload quiesce suppression to keep the dialer alive")
	}
	if got := d.failCount[tcp4.Index()]; got != 0 {
		t.Fatalf("fail counter during quiesce suppression = %d, want 0", got)
	}
}
