/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"sync"

	"github.com/daeuniverse/outbound/pool"
)

type udpEndpointResponseCacheEntry struct {
	bindAddr netip.AddrPort
	conn     *Anyfrom
}

type udpConnStateTuplePairSnapshot struct {
	src netip.AddrPort
	dst netip.AddrPort
}

func (p *udpConnStateTuplePairSnapshot) matches(src, dst netip.AddrPort) bool {
	if p == nil {
		return false
	}
	return p.src == src && p.dst == dst || p.src == dst && p.dst == src
}

type udpEndpointResponseConnSlot interface {
	Load() *Anyfrom
	Swap(next *Anyfrom)
	CompareAndSwap(old, next *Anyfrom) bool
}

type udpEndpointSymmetricResponseConnSlot struct {
	endpoint *UdpEndpoint
}

func (s udpEndpointSymmetricResponseConnSlot) Load() *Anyfrom {
	if s.endpoint == nil {
		return nil
	}
	return s.endpoint.loadResponseConn()
}

func (s udpEndpointSymmetricResponseConnSlot) Swap(next *Anyfrom) {
	if s.endpoint == nil {
		return
	}
	s.endpoint.swapResponseConn(next)
}

func (s udpEndpointSymmetricResponseConnSlot) CompareAndSwap(old, next *Anyfrom) bool {
	if s.endpoint == nil {
		return false
	}
	return s.endpoint.compareAndSwapResponseConn(old, next)
}

func (ue *UdpEndpoint) responseConnSlot() udpEndpointResponseConnSlot {
	if ue == nil {
		return nil
	}
	// Only fixed-destination sessions (Symmetric NAT) may reuse a cached
	// Anyfrom response socket. Full-Cone sessions must re-resolve on every
	// packet because the remote source can legitimately change.
	if ue.poolKey.Dst.Port() == 0 {
		return nil
	}
	return udpEndpointSymmetricResponseConnSlot{endpoint: ue}
}

func (ue *UdpEndpoint) cachedResponseConn(bindAddr netip.AddrPort) *Anyfrom {
	if ue == nil || !bindAddr.IsValid() || ue.poolKey.Dst.Port() != 0 {
		return nil
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		entry := ue.fullConeRespCache[i]
		if entry.bindAddr == bindAddr {
			return entry.conn
		}
	}
	return nil
}

func (ue *UdpEndpoint) storeCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	if ue == nil || !bindAddr.IsValid() || conn == nil || ue.poolKey.Dst.Port() != 0 {
		return
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		if ue.fullConeRespCache[i].bindAddr == bindAddr {
			if ue.fullConeRespCache[i].conn == conn {
				return
			}
			conn.Pin()
			if old := ue.fullConeRespCache[i].conn; old != nil {
				old.Unpin()
			}
			ue.fullConeRespCache[i].conn = conn
			return
		}
	}
	conn.Pin()
	if old := ue.fullConeRespCache[ue.fullConeRespCacheNext].conn; old != nil {
		old.Unpin()
	}
	ue.fullConeRespCache[ue.fullConeRespCacheNext] = udpEndpointResponseCacheEntry{
		bindAddr: bindAddr,
		conn:     conn,
	}
	ue.fullConeRespCacheNext = (ue.fullConeRespCacheNext + 1) % len(ue.fullConeRespCache)
}

func (ue *UdpEndpoint) clearCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	if ue == nil || !bindAddr.IsValid() || ue.poolKey.Dst.Port() != 0 {
		return
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		entry := &ue.fullConeRespCache[i]
		if entry.bindAddr == bindAddr && (conn == nil || entry.conn == conn) {
			if entry.conn != nil {
				entry.conn.Unpin()
			}
			entry.bindAddr = netip.AddrPort{}
			entry.conn = nil
		}
	}
}

func (ue *UdpEndpoint) prewarmResponseConn(target string) {
	if ue == nil || !ue.lAddr.IsValid() {
		return
	}

	replyPeer := ue.poolKey.Dst
	if !replyPeer.IsValid() || replyPeer.Port() == 0 {
		parsedTarget, err := netip.ParseAddrPort(target)
		if err != nil || !parsedTarget.IsValid() || parsedTarget.Port() == 0 {
			return
		}
		replyPeer = parsedTarget
	}

	bindAddr, _ := normalizeSendPktAddrFamily(replyPeer, ue.lAddr)
	replySoMark := ue.replySoMark()
	// The anyfrom cache path is only reachable inside the dae netns: outside
	// it no cached anyfrom socket can exist and none may be created.
	if GetDaeNetns() == nil || DefaultAnyfromPool == nil {
		return
	}
	af, _, err := DefaultAnyfromPool.getOrCreateWithMark(bindAddr, replySoMark)
	if err != nil {
		return
	}

	if ue.poolKey.Dst.Port() != 0 {
		ue.swapResponseConn(af)
		return
	}
	ue.storeCachedResponseConn(bindAddr, af)
}

type udpEndpointResponseConnCache interface {
	CachedResponseConn(bindAddr netip.AddrPort) *Anyfrom
	StoreCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom)
	ClearCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom)
}

func (ue *UdpEndpoint) CachedResponseConn(bindAddr netip.AddrPort) *Anyfrom {
	return ue.cachedResponseConn(bindAddr)
}

func (ue *UdpEndpoint) StoreCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	ue.storeCachedResponseConn(bindAddr, conn)
}

func (ue *UdpEndpoint) ClearCachedResponseConn(bindAddr netip.AddrPort, conn *Anyfrom) {
	ue.clearCachedResponseConn(bindAddr, conn)
}

func (ue *UdpEndpoint) loadResponseConn() *Anyfrom {
	if ue == nil {
		return nil
	}
	ue.respConnMu.Lock()
	defer ue.respConnMu.Unlock()
	return ue.respConn
}

func (ue *UdpEndpoint) swapResponseConn(next *Anyfrom) {
	if ue == nil {
		return
	}
	ue.respConnMu.Lock()
	defer ue.respConnMu.Unlock()
	swapPinnedAnyfrom(&ue.respConn, next)
}

func (ue *UdpEndpoint) compareAndSwapResponseConn(old, next *Anyfrom) bool {
	if ue == nil {
		return false
	}
	ue.respConnMu.Lock()
	defer ue.respConnMu.Unlock()
	if ue.respConn != old {
		return false
	}
	swapPinnedAnyfrom(&ue.respConn, next)
	return true
}

func (ue *UdpEndpoint) refreshCachedResponseConnsWithTime(deadlineNano int64) {
	if ue == nil {
		return
	}
	if conn := ue.loadResponseConn(); conn != nil {
		conn.ExtendExpiryTo(deadlineNano)
	}
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		if conn := ue.fullConeRespCache[i].conn; conn != nil {
			conn.ExtendExpiryTo(deadlineNano)
		}
	}
}

func (ue *UdpEndpoint) releaseCachedResponseConns() {
	if ue == nil {
		return
	}
	ue.swapResponseConn(nil)
	ue.fullConeRespCacheMu.Lock()
	defer ue.fullConeRespCacheMu.Unlock()
	for i := range ue.fullConeRespCache {
		if ue.fullConeRespCache[i].conn != nil {
			ue.fullConeRespCache[i].conn.Unpin()
			ue.fullConeRespCache[i].conn = nil
		}
		ue.fullConeRespCache[i].bindAddr = netip.AddrPort{}
	}
}

// udpEndpointReplyQueueSize is the buffer depth for the async reply dispatch
// channel in UdpEndpoint.start(). This decouples the protocol-layer read loop
// (which must drain the upstream ReceiveCh as fast as possible) from the
// potentially slower sendPkt path (Anyfrom bind, tproxy write). The value is
// generous enough to absorb burst game server ticks without dropping, while
// still bounded to avoid unbounded memory under pathological conditions.
const udpEndpointReplyQueueSize = 256

type udpEndpointReply struct {
	data pool.PB
	from netip.AddrPort
	// release, when set, owns the reply payload instead of the package pool:
	// transport-owned packet receivers hand their buffers in with a release
	// callback (ReceivedPacket.Release).
	release func()
}

var udpEndpointReplyObjects = sync.Pool{
	New: func() any { return new(udpEndpointReply) },
}

// putUdpEndpointReplyData is a package-local seam for tests that need to observe
// reply-buffer release without changing the production hot path.
var putUdpEndpointReplyData = func(data pool.PB) {
	data.Put()
}

func takeUdpEndpointReply(data pool.PB, from netip.AddrPort) *udpEndpointReply {
	reply := udpEndpointReplyObjects.Get().(*udpEndpointReply)
	reply.data = data
	reply.from = from
	// Clear any stale release callback explicitly instead of relying solely
	// on recycleUdpEndpointReply's whole-struct zeroing: recycled objects must
	// never inherit transport-owned buffer ownership from a previous use.
	reply.release = nil
	return reply
}

// recycleUdpEndpointReply returns a reply object to its pool.
//
// releaseDataWhenNoOwner decides what happens to the payload when the reply
// carries no transport-owned release callback:
//   - true: this call owns the buffer and returns it to the pool.
//   - false: somebody else still owns it, so nothing is released here.
//
// The false case is NOT a leak and must not be "fixed" to true: the senderStop
// branch of startReadLoop hands the reply back while the read loop's own defer
// (putUdpEndpointReplyData(buf)) is still the single owner of that same
// underlying array - buf is not replaced before the early return. Releasing
// here as well would Put the same array twice, and pool.Put buckets by cap
// without being idempotent, so the array would then be handed out to two
// consumers at once (silent aliasing/corruption). The exactly-once accounting
// is locked by TestSenderStopRecycleDoesNotDoubleRelease and by
// udp_endpoint_receiver_lifecycle_test.go.
func recycleUdpEndpointReply(reply *udpEndpointReply, releaseDataWhenNoOwner bool) {
	if reply == nil {
		return
	}
	if reply.release != nil {
		reply.release()
	} else if releaseDataWhenNoOwner {
		putUdpEndpointReplyData(reply.data)
	}
	*reply = udpEndpointReply{}
	udpEndpointReplyObjects.Put(reply)
}

func releaseUdpEndpointReplies(replies []*udpEndpointReply) {
	for i := range replies {
		recycleUdpEndpointReply(replies[i], true)
	}
}

// replySender is the dedicated goroutine that drains the reply channel and
// calls the handler (which invokes sendPkt). Running this off the read loop
// avoids blocking the upstream protocol layer's ReceiveCh. The creator binds
// retire to this sender's lifecycle: a push sender must not synchronously call
// Close, which waits for its done channel even after the shared queue closes.
// A ReadFrom sender must close the conn to wake its read loop, including after
// failed push registration has left behind a closed shared queue.
func (ue *UdpEndpoint) replySender(replyCh <-chan *udpEndpointReply, stop chan<- struct{}, done chan<- struct{}, retire func()) {
	defer close(done)
	batch := make([]*udpEndpointReply, 0, 8)
	for reply := range replyCh {
		batch = append(batch[:0], reply)
		for len(batch) < cap(batch) {
			select {
			case next, ok := <-replyCh:
				if !ok {
					replyCh = nil
					goto drainBatch
				}
				batch = append(batch, next)
			default:
				goto drainBatch
			}
		}

	drainBatch:
		for i := range batch {
			queued := batch[i]
			// Do NOT skip queued replies when dead: these were already received
			// from the upstream before the read loop exited, and must be forwarded
			// to the client. The handler (forwardUdpEndpointReplyToClient) only
			// writes to the local tproxy socket, which is independent of the
			// upstream endpoint's liveness.
			if err := ue.handler(ue, queued.data, queued.from); err != nil {
				releaseUdpEndpointReplies(batch[i:])
				retire()
				close(stop)
				ue.logEndpointExit(err, "reply sender")
				// Drain remaining queued replies to release pool buffers.
				if replyCh != nil {
					for r := range replyCh {
						recycleUdpEndpointReply(r, true)
					}
				}
				return
			}
			recycleUdpEndpointReply(queued, true)
		}
		if replyCh == nil {
			return
		}
	}
}
