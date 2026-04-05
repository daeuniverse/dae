/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/sirupsen/logrus"
)

var UdpRoutingResultCacheTtl = 300 * time.Millisecond
var ErrEndpointFailed = fmt.Errorf("endpoint creation recently failed (negative cache)")

// udpEndpointCreateShardCount is the number of sharded mutexes that guard
// concurrent endpoint creation. 64 shards provide near-zero contention even
// under high concurrent-create rates.
const udpEndpointCreateShardCount = 64
const udpEndpointJanitorInterval = 250 * time.Millisecond
const udpEndpointPendingReplyPeerLimit = 8
const udpEndpointReplyCacheSlots = 4

type UdpHandler func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error

type udpConnStateOwner interface {
	RetainUdpConnStateTuples(keys []bpfTuplesKey)
	ReleaseUdpConnStateTuples(keys []bpfTuplesKey) error
}

type UdpEndpoint struct {
	conn          netproxy.PacketConn
	expiresAtNano atomic.Int64
	handler       UdpHandler
	// NatTimeout is guarded by natTimeoutMu after endpoint creation.
	NatTimeout   time.Duration
	natTimeoutMu sync.RWMutex
	closeOnce    sync.Once
	closeErr     error

	// lastRefreshNano tracks the last TTL refresh time for throttling.
	// Reduces atomic store + time.Now() frequency under high QPS from every packet to ~5/sec max.
	lastRefreshNano atomic.Int64

	// hasReply indicates the upstream side has replied at least once.
	// Before this flips true, the endpoint is still probing and must not
	// use the normal sliding NAT lifetime.
	hasReply atomic.Bool
	// hasSent indicates the endpoint has already forwarded at least one client
	// packet successfully. Once a flow reaches this point, control-plane health
	// probes should not tear it down proactively; only data-plane errors,
	// transport lifecycle end, or NAT timeout should retire it.
	hasSent atomic.Bool

	// pendingReplyPeers keeps a small ring of recently written upstream peers
	// while the endpoint is still probing. The first reply must match one of
	// these peers before the endpoint is promoted to established state.
	pendingReplyMu        sync.Mutex
	pendingReplyPeers     [udpEndpointPendingReplyPeerLimit]netip.AddrPort
	pendingReplyPeerCount int
	pendingReplyPeerNext  int

	Dialer   *dialer.Dialer
	Outbound *outbound.DialerGroup

	// Non-empty indicates this UDP Endpoint is related with a sniffed domain.
	SniffedDomain string
	DialTarget    string

	routingMu         sync.RWMutex
	routingCacheDst   netip.AddrPort
	routingCacheProto uint8
	routingCacheAt    time.Time
	routingCache      bpfRoutingResult
	hasRoutingCache   bool

	lAddr netip.AddrPort
	// respConn is a cached Anyfrom socket used to send responses back to the client.
	// This avoids repeated pool lookups and bind syscalls in the hot path.
	respConn *Anyfrom
	// fullConeRespCache keeps a tiny bindAddr-keyed Anyfrom cache for full-cone
	// reply reinjection. This preserves safety for multi-peer sessions while
	// still skipping repeated pool lookups on hot reply paths.
	fullConeRespCacheMu   sync.Mutex
	fullConeRespCache     [udpEndpointReplyCacheSlots]udpEndpointResponseCacheEntry
	fullConeRespCacheNext int
	udpConnStateMu        sync.Mutex
	udpConnStateTuples    map[bpfTuplesKey]struct{}
	udpConnStateClosed    bool
	udpConnStateOwner     udpConnStateOwner

	log *logrus.Logger

	dead   atomic.Bool
	failed atomic.Bool

	softErrorCount int

	// poolRef and poolKey allow hard-failure paths to self-remove from the pool
	// immediately. Soft read-loop exits intentionally keep the endpoint cached so
	// active flows continue to follow the old timer-based reuse model.
	poolRef *UdpEndpointPool
	poolKey UdpEndpointKey

	dialerGeneration    uint64
	endpointNetworkType dialer.NetworkType
	lifecycleProfile    UdpLifecycleProfile
	transportDone       <-chan struct{}
}

type udpEndpointResponseCacheEntry struct {
	bindAddr netip.AddrPort
	conn     *Anyfrom
}

func (ue *UdpEndpoint) responseConnCacheSlot() **Anyfrom {
	if ue == nil {
		return nil
	}
	// Only fixed-destination sessions (Symmetric NAT) may reuse a cached
	// Anyfrom response socket. Full-Cone sessions must re-resolve on every
	// packet because the remote source can legitimately change.
	if ue.poolKey.Dst.Port() == 0 {
		return nil
	}
	return &ue.respConn
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
	var af *Anyfrom
	if DefaultAnyfromPool != nil {
		shard := DefaultAnyfromPool.shardFor(bindAddr)
		nowNano := time.Now().UnixNano()
		shard.mu.RLock()
		if cached, ok := shard.pool[bindAddr]; ok && cached != nil && !cached.failed.Load() && !cached.IsExpired(nowNano) {
			af = cached
		}
		shard.mu.RUnlock()
		if af != nil {
			af.RefreshTtlWithTime(nowNano)
		}
	}

	if af == nil {
		if GetDaeNetns() == nil || DefaultAnyfromPool == nil {
			return
		}
		var err error
		af, _, err = DefaultAnyfromPool.GetOrCreate(bindAddr, AnyfromTimeout)
		if err != nil {
			return
		}
	}

	if ue.poolKey.Dst.Port() != 0 {
		swapPinnedAnyfrom(&ue.respConn, af)
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

func (ue *UdpEndpoint) refreshCachedResponseConnsWithTime(deadlineNano int64) {
	if ue == nil {
		return
	}
	if ue.respConn != nil {
		ue.respConn.ExtendExpiryTo(deadlineNano)
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
	if ue.respConn != nil {
		ue.respConn.Unpin()
		ue.respConn = nil
	}
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

func (ue *UdpEndpoint) TrackUdpConnStateTuplePair(src, dst netip.AddrPort) {
	if ue == nil || ue.udpConnStateOwner == nil || !src.IsValid() || !dst.IsValid() {
		return
	}

	forward := bpfTuplesKeyFromAddrPorts(src, dst, uint8(syscall.IPPROTO_UDP))
	reverse := bpfTuplesKeyFromAddrPorts(dst, src, uint8(syscall.IPPROTO_UDP))

	ue.udpConnStateMu.Lock()
	defer ue.udpConnStateMu.Unlock()

	if ue.udpConnStateClosed {
		return
	}
	if ue.udpConnStateTuples == nil {
		ue.udpConnStateTuples = make(map[bpfTuplesKey]struct{}, 4)
	}
	newKeys := make([]bpfTuplesKey, 0, 2)
	if _, ok := ue.udpConnStateTuples[forward]; !ok {
		ue.udpConnStateTuples[forward] = struct{}{}
		newKeys = append(newKeys, forward)
	}
	if _, ok := ue.udpConnStateTuples[reverse]; !ok {
		ue.udpConnStateTuples[reverse] = struct{}{}
		newKeys = append(newKeys, reverse)
	}
	if len(newKeys) > 0 {
		ue.udpConnStateOwner.RetainUdpConnStateTuples(newKeys)
	}
}

func (ue *UdpEndpoint) releaseTrackedUdpConnState() {
	if ue == nil || ue.udpConnStateOwner == nil {
		return
	}

	ue.udpConnStateMu.Lock()
	if ue.udpConnStateClosed {
		ue.udpConnStateMu.Unlock()
		return
	}
	ue.udpConnStateClosed = true
	if len(ue.udpConnStateTuples) == 0 {
		ue.udpConnStateMu.Unlock()
		return
	}
	keys := make([]bpfTuplesKey, 0, len(ue.udpConnStateTuples))
	for key := range ue.udpConnStateTuples {
		keys = append(keys, key)
	}
	ue.udpConnStateTuples = nil
	ue.udpConnStateMu.Unlock()

	if err := ue.udpConnStateOwner.ReleaseUdpConnStateTuples(keys); err != nil &&
		ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithError(err).Debug("[UdpEndpoint] Failed to release tracked UDP conn-state tuples")
	}
}

func isProxyBackedDialer(d *dialer.Dialer) bool {
	if d == nil {
		return false
	}
	property := d.Property()
	return property != nil && property.Address != ""
}

func isStatelessProxyBackedUdpProtocol(d *dialer.Dialer) bool {
	if !isProxyBackedDialer(d) {
		return false
	}
	property := d.Property()
	if property == nil {
		return false
	}
	switch strings.ToLower(property.Protocol) {
	case "shadowsocks", "shadowsocksr", "socks4", "socks5":
		return true
	default:
		return false
	}
}

func proxyBackedUdpNatTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		return requested
	}
	// Proxy-backed UDP sessions are multiplexed over a longer-lived transport.
	// Recreating them too aggressively causes avoidable session churn and log
	// spam for interactive traffic such as games.
	if requested < QuicNatTimeout {
		return QuicNatTimeout
	}
	return requested
}

func effectiveUdpEndpointNatTimeout(d *dialer.Dialer, requested time.Duration) time.Duration {
	if !isProxyBackedDialer(d) || isStatelessProxyBackedUdpProtocol(d) {
		return requested
	}
	return proxyBackedUdpNatTimeout(requested)
}

func isTransientLocalUdpDialCreateError(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, syscall.EADDRINUSE) ||
		stderrors.Is(err, syscall.EADDRNOTAVAIL) ||
		stderrors.Is(err, syscall.EAGAIN) ||
		stderrors.Is(err, syscall.ENOBUFS) ||
		stderrors.Is(err, syscall.EMFILE) ||
		stderrors.Is(err, syscall.ENFILE) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "bind: address already in use") ||
		strings.Contains(errStr, "cannot assign requested address")
}

func udpEndpointIgnoresDialerHealth(ue *UdpEndpoint) bool {
	return ue != nil &&
		ue.Outbound != nil &&
		ue.Outbound.GetSelectionPolicy() == consts.DialerSelectionPolicy_Fixed
}

func (ue *UdpEndpoint) logEndpointExit(err error, msg string) {
	if ue.log == nil {
		return
	}
	natTimeout := ue.natTimeout()
	fields := logrus.Fields{
		"lAddr":       ue.lAddr.String(),
		"dialer":      ue.Dialer.Property().Name,
		"proxy_addr":  ue.DialTarget,
		"sniffed":     ue.SniffedDomain,
		"nat_timeout": natTimeout.String(),
	}
	entry := ue.log.WithFields(fields).WithError(err)
	if errors.IsUDPEndpointNormalClose(err) {
		entry.Debugln("UdpEndpoint " + msg + " closed normally")
	} else {
		// Add error details for connection refused
		if opErr, ok := err.(*net.OpError); ok {
			fields["op"] = opErr.Op
			fields["err_type"] = fmt.Sprintf("%T", err)
		}
		entry.WithFields(fields).Warnln("UdpEndpoint " + msg + " exited with error")
	}
}

func (ue *UdpEndpoint) shouldRetireOnReadError(err error) bool {
	if err == nil {
		return false
	}
	// Connection-refused class errors must still retire the endpoint so proxy IP
	// failure handling can evict the bad upstream target immediately.
	if ue.isConnectionRefused(err) {
		return true
	}
	if !errors.IsUDPEndpointNormalClose(err) {
		return true
	}
	// Delegate the "normal close" policy to the lifecycle model so all UDP
	// session managers use the same rule.
	if lifecycle, ok := newUdpSessionLifecycleContext(ue, ""); ok {
		return lifecycle.shouldRetireOnNormalClose(err)
	}
	return false
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
}

func (ue *UdpEndpoint) start() {
	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithFields(logrus.Fields{
			"lAddr":      ue.lAddr.String(),
			"dialer":     ue.Dialer.Property().Name,
			"proxy_addr": ue.DialTarget,
		}).Debug("[UdpEndpoint] Read loop started")
	}

	// Async reply dispatch: the read loop pushes replies into this channel
	// and a dedicated sender goroutine drains it. This prevents slow sendPkt
	// operations (Anyfrom cache miss → bind syscall) from stalling the read
	// loop during short bursts. Once the burst buffer fills, we intentionally
	// backpressure the read loop instead of introducing a second lossy queue in
	// dae itself. Generic UDP traffic cannot assume that older packets are safe
	// to discard.
	replyCh := make(chan udpEndpointReply, udpEndpointReplyQueueSize)
	senderStop := make(chan struct{})
	senderDone := make(chan struct{})
	go ue.replySender(replyCh, senderStop, senderDone)

	buf := pool.GetFullCap(consts.EthernetMtu)
	defer func() {
		pool.Put(buf)
		close(replyCh)
		<-senderDone
	}()
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			// Fast path for soft errors (authentication failures/replay attacks from network noise)
			if errors.IsReplayAttackError(err) || errors.IsAuthError(err) {
				// Dynamic threshold:
				// If we haven't received any valid packet yet, keep threshold low (3) to fail fast on wrong passwords/nodes.
				// If we have successfully received packets, the proxy works. Subsequent errors are likely network noise, so use high threshold (100).
				threshold := 3
				if ue.hasReply.Load() {
					threshold = 100
				}

				if ue.softErrorCount < threshold {
					ue.softErrorCount++
					// Optimize logging condition to avoid unnecessary log object allocation when debug is off
					if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) && ue.softErrorCount%10 == 1 {
						ue.log.WithFields(logrus.Fields{
							"lAddr":      ue.lAddr.String(),
							"dialer":     ue.Dialer.Property().Name,
							"proxy_addr": ue.DialTarget,
							"sniffed":    ue.SniffedDomain,
						}).WithError(err).Debugf("UdpEndpoint read loop soft error (hit %d/%d, ignored)", ue.softErrorCount, threshold)
					}
					continue
				}
			}

			if ue.shouldRetireOnReadError(err) {
				ue.retire()

				// Check if this is a connection refused error from proxy server
				// If so, invalidate the cached proxy IP so we can try a different one
				if ue.isConnectionRefused(err) {
					ue.handleProxyServerFailure()
				}
			}

			ue.logEndpointExit(err, "read loop")
			break
		}
		ue.softErrorCount = 0
		if !ue.hasReply.Load() && !ue.acceptsInitialReplyFrom(from) {
			if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
				ue.log.WithFields(logrus.Fields{
					"lAddr":      ue.lAddr.String(),
					"dialer":     ue.Dialer.Property().Name,
					"proxy_addr": ue.DialTarget,
					"from":       from.String(),
				}).Debug("[UdpEndpoint] Dropped unmatched initial UDP reply during probing")
			}
			continue
		}
		if lifecycle, ok := newUdpSessionLifecycleContext(ue, consts.IpVersionFromAddr(from.Addr())); ok {
			lifecycle.handleReply(ue, time.Now().UnixNano())
		} else {
			ue.markReplied(time.Now().UnixNano())
		}
		// Dispatch reply asynchronously: copy data into a pool buffer and
		// push it to the sender goroutine. Short bursts are absorbed by replyCh.
		// If the sender falls behind, block here and apply backpressure instead
		// of dropping queued packets inside dae.
		pktCopy := pool.Get(n)
		copy(pktCopy, buf[:n])
		select {
		case replyCh <- udpEndpointReply{data: pktCopy, from: from}:
		case <-senderStop:
			pktCopy.Put()
			return
		}
	}
}

// replySender is the dedicated goroutine that drains the reply channel and
// calls the handler (which invokes sendPkt). Running this off the read loop
// avoids blocking the upstream protocol layer's ReceiveCh.
func (ue *UdpEndpoint) replySender(replyCh <-chan udpEndpointReply, stop chan<- struct{}, done chan<- struct{}) {
	defer close(done)
	batch := make([]udpEndpointReply, 0, 8)
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
		for _, queued := range batch {
			// Do NOT skip queued replies when dead: these were already received
			// from the upstream before the read loop exited, and must be forwarded
			// to the client. The handler (forwardUdpEndpointReplyToClient) only
			// writes to the local tproxy socket, which is independent of the
			// upstream endpoint's liveness.
			if err := ue.handler(ue, queued.data, queued.from); err != nil {
				queued.data.Put()
				ue.retire()
				close(stop)
				ue.logEndpointExit(err, "reply sender")
				// Drain remaining queued replies to release pool buffers.
				if replyCh != nil {
					for r := range replyCh {
						r.data.Put()
					}
				}
				return
			}
			queued.data.Put()
		}
		if replyCh == nil {
			return
		}
	}
}

// isConnectionRefused checks if the error indicates connection was refused.
// Uses typed syscall matching first (handles kernel ICMP errors), then falls
// back to string matching for wrapped errors from SOCKS5 and other proxy protocols.
func (ue *UdpEndpoint) isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	// Fast path: typed syscall errors from kernel ICMP responses.
	if stderrors.Is(err, syscall.ECONNREFUSED) || stderrors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var sysErr *os.SyscallError
	if stderrors.As(err, &sysErr) {
		if stderrors.Is(sysErr.Err, syscall.ECONNREFUSED) || stderrors.Is(sysErr.Err, syscall.EHOSTUNREACH) {
			return true
		}
	}
	// Slow path: string matching for proxy-protocol wrapped errors (e.g. SOCKS5 replies).
	errStr := errStrLower(err)
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "port unreachable") ||
		strings.Contains(errStr, "host unreachable")
}

// handleProxyServerFailure is called when the proxy server refuses the connection.
// It invalidates the cached proxy IP so that subsequent connections can try a different IP.
func (ue *UdpEndpoint) handleProxyServerFailure() {
	if ue.Dialer == nil {
		return
	}

	// Get the proxy address from the dialer property
	proxyAddr := ue.Dialer.Property().Address
	if proxyAddr == "" {
		return
	}

	// Notify the dialer about the proxy server failure.
	// This invalidates the failed UDP family cache so retries can pivot immediately.
	networkType := udpEndpointNetworkType(ue)
	ue.Dialer.NotifyProxyFailure(proxyAddr, &networkType)

	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"dialer":     ue.Dialer.Property().Name,
		}).Debug("[UdpEndpoint] Proxy server UDP connection refused - invalidated cached IP")
	}
}

// errStrLower returns the lowercased error message. Used as a helper for
// case-insensitive string matching in fallback error detection.
func errStrLower(err error) string {
	return strings.ToLower(err.Error())
}

// selfRemoveFromPool performs a best-effort CAS delete of this endpoint from
// its owning pool. It is called by the read loop on exit so that the dead entry
// is evicted immediately — before any writer goroutine has a chance to observe
// it and be forced through the slower dead-check recovery path.
func (ue *UdpEndpoint) selfRemoveFromPool() {
	if ue.poolRef == nil {
		return
	}
	shard := ue.poolRef.shardFor(ue.poolKey)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if v, ok := shard.pool[ue.poolKey]; ok && v == ue {
		delete(shard.pool, ue.poolKey)
	}
}

func (ue *UdpEndpoint) retire() {
	ue.dead.Store(true)
	ue.expiresAtNano.Store(1)
	ue.selfRemoveFromPool()
	_ = ue.Close()
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	// Fast dead check: avoid work on an already-dead endpoint.
	if ue.dead.Load() {
		return 0, net.ErrClosed
	}

	if !ue.hasReply.Load() {
		ue.rememberPendingReplyPeer(addr)
	}

	// Refresh TTL on write to keep endpoint alive for active connections
	ue.RefreshTtl()

	// Check again - endpoint may have died.
	// The underlying conn.WriteTo is thread-safe; we accept a small race window
	// for performance. Write errors will mark the endpoint dead for cleanup.
	n, err := ue.conn.WriteTo(b, addr)
	if err != nil {
		ue.retire()
		if ue.isConnectionRefused(err) {
			ue.handleProxyServerFailure()
		}
		return n, err
	}
	ue.hasSent.Store(true)
	if n != len(b) {
		ue.retire()
		return n, fmt.Errorf("%w: udp endpoint wrote %d/%d bytes to %s", io.ErrShortWrite, n, len(b), addr)
	}
	return n, nil
}

func (ue *UdpEndpoint) Close() error {
	ue.closeOnce.Do(func() {
		ue.expiresAtNano.Store(0)
		ue.releaseCachedResponseConns()
		if ue.poolRef != nil {
			ue.poolRef.unregisterEndpoint(ue)
		}

		ue.routingMu.Lock()
		ue.hasRoutingCache = false
		ue.routingMu.Unlock()
		ue.releaseTrackedUdpConnState()

		// conn is nil for negatively-cached failure entries; guard against panic.
		if ue.conn != nil {
			ue.closeErr = ue.conn.Close()
		}
	})
	return ue.closeErr
}

// RefreshTtl updates the expiration time. Uses throttling to reduce atomic
// store overhead.
func (ue *UdpEndpoint) RefreshTtl() {
	ue.RefreshTtlWithTime(0)
}

func (ue *UdpEndpoint) natTimeout() time.Duration {
	ue.natTimeoutMu.RLock()
	defer ue.natTimeoutMu.RUnlock()
	return ue.NatTimeout
}

func (ue *UdpEndpoint) setNatTimeout(timeout time.Duration) {
	ue.natTimeoutMu.Lock()
	ue.NatTimeout = timeout
	ue.natTimeoutMu.Unlock()
}

// requiresInitialReplyGuard reports whether dae needs to verify the first
// upstream reply itself before promoting the endpoint to established state.
// Proxy-backed PacketConn implementations already demultiplex packets by
// protocol session, so an extra address-based guard here is redundant and can
// incorrectly strand valid flows whose first reply address is rewritten by the
// proxy layer.
func (ue *UdpEndpoint) requiresInitialReplyGuard() bool {
	return ue == nil || !isProxyBackedDialer(ue.Dialer)
}

// markReplied promotes the endpoint from probing to established state.
// Once a reply has been observed, the normal sliding NAT timeout applies.
func (ue *UdpEndpoint) markReplied(nowNano int64) {
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}
	if !ue.hasReply.Swap(true) {
		ue.clearPendingReplyPeers()
		ue.lastRefreshNano.Store(nowNano)
		ue.expiresAtNano.Store(nowNano + int64(ue.natTimeout()))
		return
	}
	ue.RefreshTtlWithTime(nowNano)
}

func (ue *UdpEndpoint) rememberPendingReplyPeer(addr string) {
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil || !addrPort.IsValid() {
		return
	}

	ue.pendingReplyMu.Lock()
	defer ue.pendingReplyMu.Unlock()

	for i := 0; i < ue.pendingReplyPeerCount; i++ {
		if ue.pendingReplyPeers[i] == addrPort {
			return
		}
	}

	if ue.pendingReplyPeerCount < len(ue.pendingReplyPeers) {
		ue.pendingReplyPeers[ue.pendingReplyPeerCount] = addrPort
		ue.pendingReplyPeerCount++
		return
	}

	ue.pendingReplyPeers[ue.pendingReplyPeerNext] = addrPort
	ue.pendingReplyPeerNext = (ue.pendingReplyPeerNext + 1) % len(ue.pendingReplyPeers)
}

func (ue *UdpEndpoint) clearPendingReplyPeers() {
	ue.pendingReplyMu.Lock()
	defer ue.pendingReplyMu.Unlock()

	ue.pendingReplyPeerCount = 0
	ue.pendingReplyPeerNext = 0
	for i := range ue.pendingReplyPeers {
		ue.pendingReplyPeers[i] = netip.AddrPort{}
	}
}

func (ue *UdpEndpoint) acceptsInitialReplyFrom(from netip.AddrPort) bool {
	if !from.IsValid() {
		return false
	}
	if !ue.requiresInitialReplyGuard() {
		return true
	}

	ue.pendingReplyMu.Lock()
	defer ue.pendingReplyMu.Unlock()

	if ue.pendingReplyPeerCount == 0 {
		return ue.poolKey.Dst.IsValid() && from == ue.poolKey.Dst
	}

	allowSameIPFallback := ue.poolKey.Dst.Port() == 0
	for i := 0; i < ue.pendingReplyPeerCount; i++ {
		expected := ue.pendingReplyPeers[i]
		if from == expected {
			return true
		}
		if allowSameIPFallback && from.Addr() == expected.Addr() {
			return true
		}
	}

	if ue.poolKey.Dst.IsValid() && from == ue.poolKey.Dst {
		return true
	}
	return false
}

// RefreshTtlWithTime updates the expiration time using a pre-calculated
// timestamp (Unix nanoseconds). If nowNano is 0, time.Now() is used.
func (ue *UdpEndpoint) RefreshTtlWithTime(nowNano int64) {
	timeout := ue.natTimeout()
	if timeout <= 0 {
		return
	}
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}
	last := ue.lastRefreshNano.Load()
	// Throttle: skip if refreshed recently.
	// For long TTLs, use TTL/50 as interval; for short TTLs, use minimum.
	minInterval := ttlRefreshMinInterval
	if ttlNano := int64(timeout); ttlNano > 10*ttlRefreshMinInterval {
		minInterval = ttlNano / 50
	}
	if nowNano-last < minInterval {
		return
	}
	// CAS to avoid thundering herd on the same connection.
	if ue.lastRefreshNano.CompareAndSwap(last, nowNano) {
		deadlineNano := nowNano + int64(timeout)
		ue.expiresAtNano.Store(deadlineNano)
		// Keep cached reply sockets alive as long as the endpoint is alive.
		// Without this, Anyfrom entries can expire before the owning UDP
		// endpoint does, forcing a bind syscall on a later reply and causing
		// a latency spike for active proxy-backed sessions whose
		// server->client traffic is sparse on a given source address.
		ue.refreshCachedResponseConnsWithTime(deadlineNano)
	}
}

// UpdateNatTimeout updates the NAT timeout and refreshes TTL with the new timeout.
// This allows the timeout to adapt to changing forwarding state (e.g., QUIC upgrade, fixed policy).
func (ue *UdpEndpoint) UpdateNatTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	ue.setNatTimeout(timeout)
	now := time.Now().UnixNano()
	// Force immediate refresh on timeout change (bypass throttling).
	ue.lastRefreshNano.Store(now)
	ue.expiresAtNano.Store(now + int64(timeout))
}

func (ue *UdpEndpoint) IsExpired(nowNano int64) bool {
	expiresAt := ue.expiresAtNano.Load()
	return expiresAt > 0 && nowNano >= expiresAt
}

// IsDead returns true if the endpoint's read loop has exited and should not be reused.
func (ue *UdpEndpoint) IsDead() bool {
	return ue.dead.Load()
}

func (ue *UdpEndpoint) GetCachedRoutingResult(dst netip.AddrPort, l4proto uint8) (*bpfRoutingResult, bool) {
	ttl := UdpRoutingResultCacheTtl
	if ttl <= 0 {
		return nil, false
	}

	ue.routingMu.RLock()
	defer ue.routingMu.RUnlock()

	if !ue.hasRoutingCache {
		return nil, false
	}
	if ue.routingCacheProto != l4proto || ue.routingCacheDst != dst {
		return nil, false
	}
	if time.Since(ue.routingCacheAt) > ttl {
		return nil, false
	}

	result := ue.routingCache
	return &result, true
}

func (ue *UdpEndpoint) UpdateCachedRoutingResult(dst netip.AddrPort, l4proto uint8, result *bpfRoutingResult) {
	if result == nil {
		return
	}
	if UdpRoutingResultCacheTtl <= 0 {
		return
	}

	ue.routingMu.Lock()
	ue.routingCacheDst = dst
	ue.routingCacheProto = l4proto
	ue.routingCacheAt = time.Now()
	ue.routingCache = *result
	ue.hasRoutingCache = true
	ue.routingMu.Unlock()
}

// UdpEndpointKey is the pool key. Dst=0 for Full-Cone NAT, non-zero for
// destination-affine flows such as QUIC or userspace-routed UDP. RouteScope is
// only populated when UDP routing depends on packet metadata that userspace
// cannot safely infer from payload reuse alone.

type UdpEndpointKey struct {
	Src        netip.AddrPort
	Dst        netip.AddrPort
	RouteScope udpEndpointRouteScope
}

type udpEndpointPoolShard struct {
	mu       sync.RWMutex
	createMu sync.Mutex
	pool     map[UdpEndpointKey]*UdpEndpoint
}

type udpEndpointDialerBucket struct {
	mu        sync.RWMutex
	endpoints map[*UdpEndpoint]struct{}
}

type udpEndpointTransportBucket struct {
	mu        sync.RWMutex
	endpoints map[*UdpEndpoint]struct{}
	watchOnce sync.Once
}

type udpEndpointDialerNetworkKey struct {
	dialer      *dialer.Dialer
	networkType dialer.NetworkType
}

// UdpEndpointPool is a UDP connection pool.
type UdpEndpointPool struct {
	shards         [udpEndpointCreateShardCount]udpEndpointPoolShard
	janitorOnce    sync.Once
	janitorStop    chan struct{}
	janitorDone    chan struct{}
	dialerIndex    sync.Map // map[udpEndpointDialerNetworkKey]*udpEndpointDialerBucket
	dialerEpoch    sync.Map // map[udpEndpointDialerNetworkKey]*atomic.Uint64
	transportIndex sync.Map // map[<-chan struct{}]*udpEndpointTransportBucket
}

type UdpEndpointOptions struct {
	Ctx        context.Context
	Handler    UdpHandler
	NatTimeout time.Duration
	// ConnStateOwner releases eBPF UDP conn-state tuples when the endpoint exits.
	ConnStateOwner udpConnStateOwner
	// GetTarget is useful only if the underlay does not support Full-cone.
	GetDialOption func(ctx context.Context) (option *DialOption, err error)
	// Log is the logger to use for endpoint lifecycle events.
	// If nil, logs are discarded.
	Log *logrus.Logger
	// NowNano is an optional pre-calculated timestamp to avoid calling time.Now()
	// in the hot path. If 0, time.Now() will be used.
	NowNano int64
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	p := &UdpEndpointPool{
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
	}
	for i := range udpEndpointCreateShardCount {
		p.shards[i].pool = make(map[UdpEndpointKey]*UdpEndpoint, 16)
	}
	p.startJanitor()
	return p
}

func normalizeUdpEndpointPoolNetworkType(networkType dialer.NetworkType) dialer.NetworkType {
	if networkType.L4Proto == "" {
		networkType.L4Proto = consts.L4ProtoStr_UDP
	}
	networkType.IsDns = false
	if networkType.L4Proto == consts.L4ProtoStr_UDP {
		networkType.UdpHealthDomain = dialer.UdpHealthDomainData
	}
	return networkType
}

func (p *UdpEndpointPool) dialerNetworkKey(d *dialer.Dialer, networkType dialer.NetworkType) udpEndpointDialerNetworkKey {
	return udpEndpointDialerNetworkKey{
		dialer:      d,
		networkType: normalizeUdpEndpointPoolNetworkType(networkType),
	}
}

func (p *UdpEndpointPool) endpointDialerNetworkKey(ue *UdpEndpoint) (udpEndpointDialerNetworkKey, bool) {
	if ue == nil || ue.Dialer == nil {
		return udpEndpointDialerNetworkKey{}, false
	}
	return p.dialerNetworkKey(ue.Dialer, udpEndpointNetworkType(ue)), true
}

func (p *UdpEndpointPool) dialerEpochCounter(d *dialer.Dialer, networkType dialer.NetworkType) *atomic.Uint64 {
	if d == nil {
		return nil
	}
	key := p.dialerNetworkKey(d, networkType)
	if counter, ok := p.dialerEpoch.Load(key); ok {
		return counter.(*atomic.Uint64)
	}
	actual, _ := p.dialerEpoch.LoadOrStore(key, &atomic.Uint64{})
	return actual.(*atomic.Uint64)
}

func (p *UdpEndpointPool) currentDialerGeneration(d *dialer.Dialer, networkType dialer.NetworkType) uint64 {
	counter := p.dialerEpochCounter(d, networkType)
	if counter == nil {
		return 0
	}
	return counter.Load()
}

func (p *UdpEndpointPool) endpointGenerationCurrent(ue *UdpEndpoint) bool {
	if ue == nil || ue.Dialer == nil {
		return true
	}
	if udpEndpointIgnoresDialerHealth(ue) {
		return true
	}
	return ue.dialerGeneration == p.currentDialerGeneration(ue.Dialer, udpEndpointNetworkType(ue))
}

// endpointSurvivesDialerInvalidation reports whether an endpoint should remain
// reusable after its dialer transitions to not alive.
//
// Control-plane health is an admission signal for new selections, not a hard
// kill switch for live sessions. Once an endpoint has successfully forwarded at
// least one packet, proactively retiring it based only on health probes causes
// avoidable redials and session churn. Real failures are still surfaced by
// WriteTo/ReadFrom errors, transport lifecycle end, or NAT timeout expiry.
func (p *UdpEndpointPool) endpointSurvivesDialerInvalidation(ue *UdpEndpoint) bool {
	if ue == nil {
		return false
	}
	return ue.hasSent.Load() || ue.hasReply.Load()
}

func endpointTransportDoneChannel(ue *UdpEndpoint) <-chan struct{} {
	if ue == nil {
		return nil
	}
	if ue.transportDone != nil {
		return ue.transportDone
	}
	if ue.conn == nil {
		return nil
	}
	lifecycle, ok := ue.conn.(netproxy.TransportLifecycle)
	if !ok {
		return nil
	}
	return lifecycle.TransportDone()
}

func (p *UdpEndpointPool) registerTransportEndpoint(ue *UdpEndpoint) {
	transportDone := endpointTransportDoneChannel(ue)
	if transportDone == nil {
		return
	}
	ue.transportDone = transportDone

	actual, _ := p.transportIndex.LoadOrStore(transportDone, &udpEndpointTransportBucket{
		endpoints: make(map[*UdpEndpoint]struct{}),
	})
	bucket := actual.(*udpEndpointTransportBucket)
	bucket.mu.Lock()
	bucket.endpoints[ue] = struct{}{}
	bucket.mu.Unlock()

	bucket.watchOnce.Do(func() {
		go p.watchTransportLifecycle(transportDone, bucket)
	})
}

func (p *UdpEndpointPool) watchTransportLifecycle(transportDone <-chan struct{}, bucket *udpEndpointTransportBucket) {
	<-transportDone
	p.transportIndex.CompareAndDelete(transportDone, bucket)

	bucket.mu.RLock()
	endpoints := make([]*UdpEndpoint, 0, len(bucket.endpoints))
	for ue := range bucket.endpoints {
		endpoints = append(endpoints, ue)
	}
	bucket.mu.RUnlock()

	for _, ue := range endpoints {
		if ue != nil && ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
			ue.log.WithFields(logrus.Fields{
				"lAddr": ue.lAddr.String(),
			}).Debug("[UdpEndpoint] Retiring endpoint after transport lifecycle ended")
		}
		if ue != nil {
			ue.retire()
		}
	}
}

func (p *UdpEndpointPool) registerEndpoint(ue *UdpEndpoint) {
	if udpEndpointIgnoresDialerHealth(ue) {
		p.registerTransportEndpoint(ue)
		return
	}
	key, ok := p.endpointDialerNetworkKey(ue)
	if ok {
		actual, _ := p.dialerIndex.LoadOrStore(key, &udpEndpointDialerBucket{
			endpoints: make(map[*UdpEndpoint]struct{}),
		})
		bucket := actual.(*udpEndpointDialerBucket)
		bucket.mu.Lock()
		bucket.endpoints[ue] = struct{}{}
		bucket.mu.Unlock()
	}
	p.registerTransportEndpoint(ue)
}

func (p *UdpEndpointPool) unregisterEndpoint(ue *UdpEndpoint) {
	key, ok := p.endpointDialerNetworkKey(ue)
	if ok {
		actual, ok := p.dialerIndex.Load(key)
		if ok {
			bucket := actual.(*udpEndpointDialerBucket)
			bucket.mu.Lock()
			delete(bucket.endpoints, ue)
			// Keep empty buckets for the lifetime of the pool. The key space is tiny
			// (dialer x UDP family), and never deleting avoids a register/unregister
			// race where a newly re-added endpoint could lose its reverse index.
			bucket.mu.Unlock()
		}
	}

	transportDone := endpointTransportDoneChannel(ue)
	if transportDone == nil {
		return
	}
	actual, ok := p.transportIndex.Load(transportDone)
	if !ok {
		return
	}
	bucket := actual.(*udpEndpointTransportBucket)
	bucket.mu.Lock()
	delete(bucket.endpoints, ue)
	bucket.mu.Unlock()
}

func (p *UdpEndpointPool) InvalidateDialerNetworkType(d *dialer.Dialer, networkType *dialer.NetworkType) int {
	if d == nil || networkType == nil {
		return 0
	}
	key := p.dialerNetworkKey(d, *networkType)
	if counter := p.dialerEpochCounter(d, *networkType); counter != nil {
		counter.Add(1)
	}

	actual, ok := p.dialerIndex.Load(key)
	if !ok {
		return 0
	}
	bucket := actual.(*udpEndpointDialerBucket)
	bucket.mu.RLock()
	endpoints := make([]*UdpEndpoint, 0, len(bucket.endpoints))
	for ue := range bucket.endpoints {
		endpoints = append(endpoints, ue)
	}
	bucket.mu.RUnlock()

	removed := 0
	for _, ue := range endpoints {
		if p.endpointSurvivesDialerInvalidation(ue) {
			continue
		}
		ue.retire()
		removed++
	}
	return removed
}

// Reset clears all cached UDP endpoints.
// Called on reload to prevent stale endpoints from using pre-reload routing state.
// Uses LoadAndDelete for atomic removal that races safely with concurrent GetOrCreate.
func (p *UdpEndpointPool) Reset() {
	for i := range udpEndpointCreateShardCount {
		shard := &p.shards[i]
		shard.mu.Lock()
		// Phase 1: Collect keys to avoid modifying map during iteration
		var keys []UdpEndpointKey
		for key := range shard.pool {
			keys = append(keys, key)
		}
		// Phase 2: Delete and close each entry
		for _, key := range keys {
			if ue, ok := shard.pool[key]; ok {
				delete(shard.pool, key)
				_ = ue.Close()
			}
		}
		shard.mu.Unlock()
	}
	// Clear index maps by deleting entries rather than reassigning a new
	// sync.Map struct. Struct assignment races with background goroutines
	// (e.g. endpoint retire → unregisterEndpoint) that concurrently Load
	// from the same map.
	p.dialerIndex.Range(func(key, _ any) bool {
		p.dialerIndex.Delete(key)
		return true
	})
	p.dialerEpoch.Range(func(key, _ any) bool {
		p.dialerEpoch.Delete(key)
		return true
	})
	p.transportIndex.Range(func(key, _ any) bool {
		p.transportIndex.Delete(key)
		return true
	})
}

// Close stops the janitor goroutine and clears all pooled endpoints.
// Non-singleton pools must be closed when no longer needed.
func (p *UdpEndpointPool) Close() {
	if p == nil {
		return
	}
	if p.janitorStop != nil {
		select {
		case <-p.janitorStop:
		default:
			close(p.janitorStop)
		}
	}
	if p.janitorDone != nil {
		<-p.janitorDone
	}
	p.Reset()
}

func (p *UdpEndpointPool) Remove(key UdpEndpointKey, udpEndpoint *UdpEndpoint) (err error) {
	shard := p.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if ue, ok := shard.pool[key]; !ok || ue != udpEndpoint {
		_ = udpEndpoint.Close()
		return fmt.Errorf("target udp endpoint is not in the pool")
	}
	delete(shard.pool, key)
	_ = udpEndpoint.Close()
	return nil
}

func (p *UdpEndpointPool) Get(key UdpEndpointKey) (udpEndpoint *UdpEndpoint, ok bool) {
	shard := p.shardFor(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	ue, ok := shard.pool[key]
	if !ok {
		return nil, ok
	}
	if ue.failed.Load() || ue.IsDead() || (!p.endpointGenerationCurrent(ue) && !p.endpointSurvivesDialerInvalidation(ue)) {
		return nil, false
	}
	return ue, ok
}

// createEndpointLocked dials and registers a new UdpEndpoint under the caller's shard lock.
// The caller MUST hold the shard mutex for key before calling this function.
func (p *UdpEndpointPool) createEndpointLocked(key UdpEndpointKey, createOption *UdpEndpointOptions) (*UdpEndpoint, error) {
	if createOption == nil {
		createOption = &UdpEndpointOptions{}
	}
	if createOption.NatTimeout == 0 {
		createOption.NatTimeout = DefaultNatTimeout
	}
	if createOption.Handler == nil {
		return nil, fmt.Errorf("createOption.Handler cannot be nil")
	}

	baseCtx := createOption.Ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}

	// Tie endpoint creation to the caller lifecycle so reload/shutdown cancels
	// in-flight UDP dials instead of waiting for the full dial timeout.
	ctx, cancel := context.WithTimeout(baseCtx, consts.DefaultDialTimeout)
	defer cancel()

	dialOption, err := createOption.GetDialOption(ctx)
	if err != nil {
		if shouldCacheUdpEndpointCreateFailure(err) {
			p.cacheFailureLocked(key, createOption.Log)
		}
		return nil, err
	}
	udpConn, err := dialOption.Dialer.DialContext(ctx, dialOption.Network, dialOption.Target)
	if err != nil {
		reportUdpEndpointDialCreateFailure(key, dialOption, err)
		if shouldForceMarkUnavailableOnProxyDialError(err) {
			// Use a fresh timeout context for the retry to avoid inheriting a
			// nearly-expired deadline from the first dial attempt. When the first
			// dial consumes most of DefaultDialTimeout (e.g. network unreachable
			// after a long timeout), the second dial would otherwise immediately
			// fail with context.DeadlineExceeded and incorrectly penalize the new
			// dialer selected by GetDialOption.
			retryCtx, retryCancel := context.WithTimeout(baseCtx, consts.DefaultDialTimeout)
			retryOption, retryErr := createOption.GetDialOption(retryCtx)
			if retryErr == nil {
				dialOption = retryOption
				udpConn, err = dialOption.Dialer.DialContext(retryCtx, dialOption.Network, dialOption.Target)
				retryCancel()
				if err == nil {
					goto dialSuccess
				}
				reportUdpEndpointDialCreateFailure(key, dialOption, err)
			} else {
				retryCancel()
				err = retryErr
			}
		}
		if shouldCacheUdpEndpointCreateFailure(err) {
			p.cacheFailureLocked(key, createOption.Log)
		}
		return nil, err
	}
dialSuccess:
	packetConn, ok := udpConn.(netproxy.PacketConn)
	if !ok {
		_ = udpConn.Close()
		return nil, fmt.Errorf("protocol does not support udp")
	}
	ue := &UdpEndpoint{
		conn:              packetConn,
		handler:           createOption.Handler,
		NatTimeout:        effectiveUdpEndpointNatTimeout(dialOption.Dialer, createOption.NatTimeout),
		Dialer:            dialOption.Dialer,
		Outbound:          dialOption.Outbound,
		SniffedDomain:     dialOption.SniffedDomain,
		DialTarget:        dialOption.Target,
		lAddr:             key.Src,
		log:               createOption.Log,
		poolRef:           p,
		poolKey:           key,
		udpConnStateOwner: createOption.ConnStateOwner,
		lifecycleProfile:  newDataSessionLifecycleProfile(dialOption.Dialer),
		endpointNetworkType: normalizeUdpEndpointPoolNetworkType(func() dialer.NetworkType {
			if dialOption.NetworkType != nil {
				return *dialOption.NetworkType
			}
			return dialer.NetworkType{
				L4Proto:         consts.L4ProtoStr_UDP,
				IpVersion:       consts.IpVersionFromAddr(key.Src.Addr()),
				IsDns:           false,
				UdpHealthDomain: dialer.UdpHealthDomainData,
			}
		}()),
	}
	ue.dialerGeneration = p.currentDialerGeneration(dialOption.Dialer, ue.endpointNetworkType)

	// Prewarm the initial Anyfrom socket used to reinject replies back to the
	// client. Symmetric endpoints can pin a single fixed socket. Full-cone
	// endpoints still keep their bind-address cache keyed by remote peer, but
	// priming the first dial target removes the cold bind syscall from the
	// earliest reply path that games are sensitive to.
	ue.prewarmResponseConn(dialOption.Target)

	ue.RefreshTtlWithTime(createOption.NowNano)

	shard := p.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()
	p.registerEndpoint(ue)

	// Receive UDP messages.
	go ue.start()
	return ue, nil
}

func reportUdpEndpointDialCreateFailure(key UdpEndpointKey, dialOption *DialOption, err error) {
	if err == nil || dialOption == nil || dialOption.Dialer == nil {
		return
	}
	if stderrors.Is(err, context.Canceled) {
		return
	}
	if isTransientLocalUdpDialCreateError(err) {
		return
	}

	lifecycle, ok := newUdpDialOptionLifecycleContext(dialOption, key.Src)
	if !ok {
		return
	}

	wrappedErr := fmt.Errorf("udp endpoint dial failed: %w", err)
	if shouldForceMarkUnavailableOnProxyDialError(err) {
		lifecycle.reportUnavailableForced(wrappedErr)
		return
	}
	lifecycle.reportUnavailable(wrappedErr)
}

func shouldCacheUdpEndpointCreateFailure(err error) bool {
	if err == nil {
		return false
	}
	// "No alive dialer" is group-level admission state rather than flow-local
	// endpoint creation failure. Caching it per flow key can explode memory
	// under unhealthy-node bursts without preventing any extra dial attempts.
	if stderrors.Is(err, outbound.ErrNoAliveDialer) {
		return false
	}
	if isTransientLocalUdpDialCreateError(err) {
		return false
	}
	if shouldForceMarkUnavailableOnProxyDialError(err) {
		return false
	}
	return true
}

func (p *UdpEndpointPool) cacheFailureLocked(key UdpEndpointKey, log *logrus.Logger) {
	failedUe := &UdpEndpoint{
		log:     log,
		poolRef: p,
		poolKey: key,
	}
	failedUe.failed.Store(true)
	failedUe.expiresAtNano.Store(time.Now().Add(2 * time.Second).UnixNano())

	shard := p.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = failedUe
	shard.mu.Unlock()
}

func (p *UdpEndpointPool) GetOrCreate(key UdpEndpointKey, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, isNew bool, err error) {
	shard := p.shardFor(key)

	// Fast path: existing socket
	shard.mu.RLock()
	ue, ok := shard.pool[key]
	if ok {
		switch {
		case ue.failed.Load():
			if !ue.IsExpired(time.Now().UnixNano()) {
				shard.mu.RUnlock()
				return nil, false, ErrEndpointFailed
			}
			// Expired failure entry — fall through to lock and replace.
		case ue.IsDead() || (!p.endpointGenerationCurrent(ue) && !p.endpointSurvivesDialerInvalidation(ue)):
			// Expired dead entry — fall through to lock and replace.
		default:
			// Update NAT timeout based on current forwarding state
			if createOption != nil && createOption.NatTimeout > 0 {
				ue.UpdateNatTimeout(effectiveUdpEndpointNatTimeout(ue.Dialer, createOption.NatTimeout))
			} else {
				var nowNano int64
				if createOption != nil {
					nowNano = createOption.NowNano
				}
				ue.RefreshTtlWithTime(nowNano)
			}
			shard.mu.RUnlock()
			return ue, false, nil
		}
	}
	shard.mu.RUnlock()

	// Slow path: serialize creation for the same key using a creation shard lock.
	shard.createMu.Lock()
	defer shard.createMu.Unlock()

	var staleToClose *UdpEndpoint
	shard.mu.Lock()
	ue, ok = shard.pool[key]
	if ok {
		switch {
		case ue.failed.Load():
			if !ue.IsExpired(time.Now().UnixNano()) {
				shard.mu.Unlock()
				return nil, false, ErrEndpointFailed
			}
			delete(shard.pool, key)
			staleToClose = ue
		case ue.IsDead() || (!p.endpointGenerationCurrent(ue) && !p.endpointSurvivesDialerInvalidation(ue)):
			delete(shard.pool, key)
			staleToClose = ue
		default:
			if createOption != nil && createOption.NatTimeout > 0 {
				ue.UpdateNatTimeout(effectiveUdpEndpointNatTimeout(ue.Dialer, createOption.NatTimeout))
			} else {
				var nowNano int64
				if createOption != nil {
					nowNano = createOption.NowNano
				}
				ue.RefreshTtlWithTime(nowNano)
			}
			shard.mu.Unlock()
			return ue, false, nil
		}
	}
	shard.mu.Unlock()
	if staleToClose != nil {
		_ = staleToClose.Close()
	}

	// Create a new endpoint under the creation lock.
	newUe, createErr := p.createEndpointLocked(key, createOption)
	if createErr != nil {
		return nil, true, createErr
	}
	return newUe, true, nil
}

func (p *UdpEndpointPool) shardFor(key UdpEndpointKey) *udpEndpointPoolShard {
	idx := int(hashUdpEndpointKey(key) & uint64(udpEndpointCreateShardCount-1))
	return &p.shards[idx]
}

func (p *UdpEndpointPool) startJanitor() {
	p.janitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(udpEndpointJanitorInterval)
			defer ticker.Stop()
			defer close(p.janitorDone)

			var toClose []*UdpEndpoint

			for {
				select {
				case <-p.janitorStop:
					return
				case now := <-ticker.C:
					nowNano := now.UnixNano()
					for i := range udpEndpointCreateShardCount {
						shard := &p.shards[i]
						shard.mu.Lock()
						toClose = toClose[:0]
						for key, ue := range shard.pool {
							if ue.IsExpired(nowNano) || (!p.endpointGenerationCurrent(ue) && !p.endpointSurvivesDialerInvalidation(ue)) {
								delete(shard.pool, key)
								toClose = append(toClose, ue)
							}
						}
						shard.mu.Unlock()
						for _, ue := range toClose {
							_ = ue.Close()
						}
					}
				}
			}
		}()
	})
}
