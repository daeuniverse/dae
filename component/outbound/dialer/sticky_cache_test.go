package dialer

import (
	"testing"
	"time"
)

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
