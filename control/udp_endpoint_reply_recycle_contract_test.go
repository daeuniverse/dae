/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/pool"
)

// TestSenderStopRecycleDoesNotDoubleRelease locks the invariant that was
// at risk of being "fixed" into a double free: in the senderStop branch the read
// loop hands the reply back with releaseDataWhenNoOwner=false because its own
// defer still owns the very same backing array. Releasing there as well would
// Put one array into the pool twice, and pool.Put buckets by cap without being
// idempotent, so two consumers would later receive the same array.
func TestSenderStopRecycleDoesNotDoubleRelease(t *testing.T) {
	const size = 1 << 14
	buf := pool.GetFullCap(size)

	var mu sync.Mutex
	releases := make(map[*byte]int)
	oldPut := putUdpEndpointReplyData
	putUdpEndpointReplyData = func(data pool.PB) {
		if len(data) > 0 {
			mu.Lock()
			releases[&data[0]]++
			mu.Unlock()
		}
		oldPut(data)
	}
	t.Cleanup(func() { putUdpEndpointReplyData = oldPut })

	releaseCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return releases[&buf[0]]
	}

	// The senderStop branch: no owner release callback, and the caller must not
	// release the payload either.
	queued := takeUdpEndpointReply(buf, netip.AddrPort{})
	recycleUdpEndpointReply(queued, false)
	if got := releaseCount(); got != 0 {
		t.Fatalf("recycle with releaseDataWhenNoOwner=false released the payload %d time(s), want 0", got)
	}

	// The read loop's own defer is the single owner of that array.
	putUdpEndpointReplyData(buf)
	if got := releaseCount(); got != 1 {
		t.Fatalf("payload release count after the read-loop defer = %d, want exactly 1", got)
	}

	// Call sites that really own the payload still release it. A different size
	// class keeps the identity key distinct from the array released above
	// (pool.Get may otherwise hand back the very same slice).
	owned := pool.GetFullCap(size * 2)
	recycleUdpEndpointReply(takeUdpEndpointReply(owned, netip.AddrPort{}), true)
	mu.Lock()
	ownedReleases := releases[&owned[0]]
	mu.Unlock()
	if ownedReleases != 1 {
		t.Fatalf("owning recycle released the payload %d time(s), want exactly 1", ownedReleases)
	}
}

// TestSenderStopRecycleCallSiteContract is the source contract for: the
// parameter name must say what it means, and the senderStop branch must keep
// passing false while the read loop's defer keeps releasing the buffer.
func TestSenderStopRecycleCallSiteContract(t *testing.T) {
	replySrc, err := os.ReadFile("udp_endpoint_reply.go")
	if err != nil {
		t.Fatalf("read udp_endpoint_reply.go: %v", err)
	}
	if !strings.Contains(string(replySrc), "func recycleUdpEndpointReply(reply *udpEndpointReply, releaseDataWhenNoOwner bool)") {
		t.Fatal("recycleUdpEndpointReply's second parameter must be named releaseDataWhenNoOwner")
	}

	watcherSrc, err := os.ReadFile("udp_endpoint_watcher.go")
	if err != nil {
		t.Fatalf("read udp_endpoint_watcher.go: %v", err)
	}
	watcher := string(watcherSrc)
	stopIdx := strings.Index(watcher, "case <-senderStop:")
	if stopIdx < 0 {
		t.Fatal("senderStop branch not found in udp_endpoint_watcher.go")
	}
	branch := watcher[stopIdx:]
	if end := strings.Index(branch, "}\n"); end > 0 {
		branch = branch[:end]
	}
	if !strings.Contains(branch, "recycleUdpEndpointReply(queued, false)") {
		t.Fatalf("senderStop branch must not release the payload it does not own:\n%s", branch)
	}
	if !strings.Contains(watcher, "putUdpEndpointReplyData(buf)") {
		t.Fatal("the read loop's deferred buffer release is gone; the senderStop branch would now leak")
	}
}
