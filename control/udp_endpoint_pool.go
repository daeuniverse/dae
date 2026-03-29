/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

type UdpHandler func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn          netproxy.PacketConn
	expiresAtNano atomic.Int64
	handler       UdpHandler
	NatTimeout    time.Duration

	// lastRefreshNano tracks the last TTL refresh time for throttling.
	// Reduces atomic store + time.Now() frequency under high QPS from every packet to ~5/sec max.
	lastRefreshNano atomic.Int64

	// hasReceived indicates if this endpoint has EVER received a packet.
	hasReceived atomic.Bool

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

	log *logrus.Logger

	dead   atomic.Bool
	failed atomic.Bool

	softErrorCount int

	// poolRef and poolKey allow the read loop to self-remove from the pool the
	// instant it detects death. This minimises the window during which a stale
	// dead entry lurks in the pool and forces callers through the slower
	// dead-check recovery branch in GetOrCreate.
	poolRef *UdpEndpointPool
	poolKey UdpEndpointKey
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

func (ue *UdpEndpoint) logEndpointExit(err error, msg string) {
	if ue.log == nil {
		return
	}
	fields := logrus.Fields{
		"lAddr":       ue.lAddr.String(),
		"dialer":      ue.Dialer.Property().Name,
		"proxy_addr":  ue.DialTarget,
		"sniffed":     ue.SniffedDomain,
		"nat_timeout": ue.NatTimeout.String(),
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

func (ue *UdpEndpoint) start() {
	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithFields(logrus.Fields{
			"lAddr":      ue.lAddr.String(),
			"dialer":     ue.Dialer.Property().Name,
			"proxy_addr": ue.DialTarget,
		}).Debug("[UdpEndpoint] Read loop started")
	}
	buf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(buf)
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			// Fast path for soft errors (authentication failures/replay attacks from network noise)
			if errors.IsReplayAttackError(err) || errors.IsAuthError(err) {
				// Dynamic threshold:
				// If we haven't received any valid packet yet, keep threshold low (3) to fail fast on wrong passwords/nodes.
				// If we have successfully received packets, the proxy works. Subsequent errors are likely network noise, so use high threshold (100).
				threshold := 3
				if ue.hasReceived.Load() {
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

			ue.dead.Store(true)
			ue.expiresAtNano.Store(1)
			ue.selfRemoveFromPool()

			// Check if this is a connection refused error from proxy server
			// If so, invalidate the cached proxy IP so we can try a different one
			if ue.isConnectionRefused(err) {
				ue.handleProxyServerFailure()
			}

			ue.logEndpointExit(err, "read loop")
			break
		}
		ue.softErrorCount = 0
		if !ue.hasReceived.Load() {
			ue.hasReceived.Store(true)
		}
		ue.RefreshTtl()
		if err = ue.handler(ue, buf[:n], from); err != nil {
			ue.dead.Store(true)
			ue.expiresAtNano.Store(1)
			ue.selfRemoveFromPool()
			ue.logEndpointExit(err, "handler")
			break
		}
	}
}

// isConnectionRefused checks if the error indicates connection was refused.
func (ue *UdpEndpoint) isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "connection refused") ||
		contains(errStr, "port unreachable") ||
		contains(errStr, "host unreachable")
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

	// Notify the dialer about the proxy server failure
	// This will invalidate the UDP cache for this proxy address
	ue.Dialer.NotifyProxyFailure(proxyAddr, "udp")

	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"dialer":     ue.Dialer.Property().Name,
		}).Debug("[UdpEndpoint] Proxy server UDP connection refused - invalidated cached IP")
	}
}

// contains checks if a string contains a substring (case-insensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && containsIgnoreCase(s, substr)))
}

// containsIgnoreCase is a helper for case-insensitive substring search.
func containsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1 := s[i+j]
			c2 := substr[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
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

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	// Fast dead check: avoid work on an already-dead endpoint.
	if ue.dead.Load() {
		return 0, net.ErrClosed
	}

	// Refresh TTL on write to keep endpoint alive for active connections
	ue.RefreshTtl()

	// Check again - endpoint may have died.
	// The underlying conn.WriteTo is thread-safe; we accept a small race window
	// for performance. Write errors will mark the endpoint dead for cleanup.
	n, err := ue.conn.WriteTo(b, addr)
	if err != nil {
		ue.dead.Store(true)
		if !errors.IsUDPEndpointNormalClose(err) && ue.Dialer != nil {
			networkType := &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionFromAddr(ue.lAddr.Addr()),
				IsDns:     false,
			}
			ue.Dialer.ReportUnavailable(networkType, fmt.Errorf("udp endpoint write failed: %w", err))
		}
		return n, err
	}
	if n != len(b) {
		ue.dead.Store(true)
		return n, fmt.Errorf("%w: udp endpoint wrote %d/%d bytes to %s", io.ErrShortWrite, n, len(b), addr)
	}
	return n, nil
}

func (ue *UdpEndpoint) Close() error {
	ue.expiresAtNano.Store(0)

	ue.routingMu.Lock()
	ue.hasRoutingCache = false
	ue.routingMu.Unlock()

	// conn is nil for negatively-cached failure entries; guard against panic.
	if ue.conn != nil {
		return ue.conn.Close()
	}
	return nil
}

// ttlRefreshMinInterval is the minimum time between TTL refreshes.
// This throttles atomic stores on hot paths to reduce overhead under high QPS.
func (ue *UdpEndpoint) RefreshTtl() {
	if ue.NatTimeout <= 0 {
		return
	}
	now := time.Now().UnixNano()
	last := ue.lastRefreshNano.Load()
	// Throttle: skip if refreshed recently.
	// For long TTLs, use TTL/50 as interval; for short TTLs, use minimum.
	minInterval := ttlRefreshMinInterval
	if ttlNano := int64(ue.NatTimeout); ttlNano > 10*ttlRefreshMinInterval {
		minInterval = ttlNano / 50
	}
	if now-last < minInterval {
		return
	}
	// CAS to avoid thundering herd on the same connection.
	if ue.lastRefreshNano.CompareAndSwap(last, now) {
		ue.expiresAtNano.Store(now + int64(ue.NatTimeout))
	}
}

// UpdateNatTimeout updates the NAT timeout and refreshes TTL with the new timeout.
// This allows the timeout to adapt to changing forwarding state (e.g., QUIC upgrade, fixed policy).
func (ue *UdpEndpoint) UpdateNatTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	ue.NatTimeout = timeout
	// Force immediate refresh on timeout change (bypass throttling).
	now := time.Now().UnixNano()
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

// UdpEndpointKey is the pool key. Dst=0 for Full-Cone NAT, non-zero for QUIC.

type UdpEndpointKey struct {
	Src netip.AddrPort
	Dst netip.AddrPort
}

type udpEndpointPoolShard struct {
	mu       sync.RWMutex
	createMu sync.Mutex
	pool     map[UdpEndpointKey]*UdpEndpoint
}

// UdpEndpointPool is a UDP connection pool.
type UdpEndpointPool struct {
	shards      [udpEndpointCreateShardCount]udpEndpointPoolShard
	janitorOnce sync.Once
}

type UdpEndpointOptions struct {
	Handler    UdpHandler
	NatTimeout time.Duration
	// GetTarget is useful only if the underlay does not support Full-cone.
	GetDialOption func(ctx context.Context) (option *DialOption, err error)
	// Log is the logger to use for endpoint lifecycle events.
	// If nil, logs are discarded.
	Log *logrus.Logger
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	p := &UdpEndpointPool{}
	for i := range udpEndpointCreateShardCount {
		p.shards[i].pool = make(map[UdpEndpointKey]*UdpEndpoint, 16)
	}
	p.startJanitor()
	return p
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
	if ue.failed.Load() || ue.IsDead() {
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

	// Use context.Background() as base for UDP endpoint creation.
	// The timeout context ensures the dial operation doesn't hang indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), consts.DefaultDialTimeout)
	defer cancel()

	dialOption, err := createOption.GetDialOption(ctx)
	if err != nil {
		p.cacheFailureLocked(key, createOption.Log)
		return nil, err
	}
	udpConn, err := dialOption.Dialer.DialContext(ctx, dialOption.Network, dialOption.Target)
	if err != nil {
		p.cacheFailureLocked(key, createOption.Log)
		return nil, err
	}
	packetConn, ok := udpConn.(netproxy.PacketConn)
	if !ok {
		_ = udpConn.Close()
		return nil, fmt.Errorf("protocol does not support udp")
	}
	ue := &UdpEndpoint{
		conn:          packetConn,
		handler:       createOption.Handler,
		NatTimeout:    createOption.NatTimeout,
		Dialer:        dialOption.Dialer,
		Outbound:      dialOption.Outbound,
		SniffedDomain: dialOption.SniffedDomain,
		DialTarget:    dialOption.Target,
		lAddr:         key.Src,
		log:           createOption.Log,
		poolRef:       p,
		poolKey:       key,
	}

	// Pre-cache the Anyfrom socket for responses. Caching is only safe for
	// fixed-destination sessions (Symmetric NAT) where the response bind address
	// remains constant. Full-Cone sessions must lookup on every packet as the
	// server source can change.
	if key.Dst.Port() != 0 {
		bindAddr, _ := normalizeSendPktAddrFamily(key.Dst, key.Src)
		if af, _, err := DefaultAnyfromPool.GetOrCreate(bindAddr, AnyfromTimeout); err == nil {
			ue.respConn = af
		}
	}

	ue.RefreshTtl()

	shard := p.shardFor(key)
	shard.mu.Lock()
	shard.pool[key] = ue
	shard.mu.Unlock()

	// Receive UDP messages.
	go ue.start()
	return ue, nil
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
		if ue.failed.Load() {
			if !ue.IsExpired(time.Now().UnixNano()) {
				shard.mu.RUnlock()
				return nil, false, ErrEndpointFailed
			}
			// Expired failure entry — fall through to lock and replace.
		} else if ue.IsDead() {
			// Expired dead entry — fall through to lock and replace.
		} else {
			// Update NAT timeout based on current forwarding state
			if createOption != nil && createOption.NatTimeout > 0 {
				ue.UpdateNatTimeout(createOption.NatTimeout)
			} else {
				ue.RefreshTtl()
			}
			shard.mu.RUnlock()
			return ue, false, nil
		}
	}
	shard.mu.RUnlock()

	// Slow path: serialize creation for the same key using a creation shard lock.
	shard.createMu.Lock()
	defer shard.createMu.Unlock()

	// Double-check under creation lock: another goroutine may have created it.
	shard.mu.RLock()
	ue, ok = shard.pool[key]
	if ok {
		if ue.failed.Load() {
			if !ue.IsExpired(time.Now().UnixNano()) {
				shard.mu.RUnlock()
				return nil, false, ErrEndpointFailed
			}
			// Expired failure entry — fall through to recreate.
		} else if !ue.IsDead() {
			if createOption != nil && createOption.NatTimeout > 0 {
				ue.UpdateNatTimeout(createOption.NatTimeout)
			} else {
				ue.RefreshTtl()
			}
			shard.mu.RUnlock()
			return ue, false, nil
		}
	}
	shard.mu.RUnlock()

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

			var toClose []*UdpEndpoint

			for now := range ticker.C {
				nowNano := now.UnixNano()
				for i := range udpEndpointCreateShardCount {
					shard := &p.shards[i]
					shard.mu.Lock()
					toClose = toClose[:0]
					for key, ue := range shard.pool {
						if ue.IsExpired(nowNano) {
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
		}()
	})
}
