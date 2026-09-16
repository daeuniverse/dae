/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

var (
	ErrEndpointFailed             = fmt.Errorf("endpoint creation recently failed (negative cache)")
	errUdpEndpointAdmissionClosed = stderrors.New("udp endpoint admission closed")
)

// udpEndpointCreateShardCount is the number of sharded mutexes that guard
// concurrent endpoint creation. Because a creation lock is held across the
// dial (up to DefaultDialTimeout), unrelated keys hashing to the same shard
// queue behind it; a larger shard count keeps
// that head-of-line blocking negligible under high concurrent-create rates.
const (
	udpEndpointCreateShardCount      = 1024
	udpEndpointJanitorInterval       = 250 * time.Millisecond
	udpEndpointJanitorMaxInterval    = 30 * time.Second
	udpEndpointPendingReplyPeerLimit = 8
	udpEndpointReplyCacheSlots       = 4
)

type UdpHandler func(ue *UdpEndpoint, data []byte, from netip.AddrPort) error

type udpConnStateOwner interface {
	RetainUdpConnStateTuples(keys []bpfTuplesKey)
	ReleaseUdpConnStateTuples(keys []bpfTuplesKey) error
}

type UdpEndpoint struct {
	conn netproxy.PacketConn
	// writeBatch, when non-nil, aggregates outgoing datagrams and flushes
	// them through the transport's batched writer (netproxy.PacketBatchWriter,
	// e.g. sendmmsg on direct UDP). See udp_write_batch.go.
	writeBatch    *udpWriteBatchAggregator
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

	// writeDeadlineArmedAtNano tracks when the proxy-side write deadline was
	// last armed, so the hot path pays one SetWriteDeadline per half-interval
	// window instead of one syscall per packet.
	writeDeadlineArmedAtNano atomic.Int64

	// hasReply indicates the upstream side has replied at least once.
	// Before this flips true, the endpoint is still probing and must not
	// use the normal sliding NAT lifetime.
	hasReply atomic.Bool
	// lastSendNano records the last time the client successfully sent a
	// packet through this endpoint, and lastReplyNano the last time the
	// upstream replied. A session that was established (hasReply) but whose
	// BOTH directions went silent for sendStaleTimeout() is presumed to be
	// starting a new round after an inter-round pause: the remote (e.g. a
	// game server) may have reaped the old session, so the old hy2
	// forwarding source port is no longer recognized. Rebuilding the endpoint
	// allocates a fresh hy2 session with a new forwarding port the peer treats
	// as a new client. The check uses the newer of the two timestamps, so
	// active gameplay — where the server keeps replying even if the client
	// briefly pauses — never rebuilds mid-round. Sniffed QUIC/H3 flows use
	// a longer window (udpEndpointQuicSendStaleTimeout) so video segment
	// gaps do not look like a new round.
	lastSendNano  atomic.Int64
	lastReplyNano atomic.Int64
	// hasSent indicates the endpoint has already forwarded at least one client
	// packet successfully. Once a flow reaches this point, control-plane health
	// probes should not tear it down proactively; only data-plane errors,
	// transport lifecycle end, or NAT timeout should retire it.
	hasSent atomic.Bool
	// initialWriteMu serializes the transition from a probing endpoint to one
	// that has forwarded traffic. Health invalidation must not retire an
	// endpoint between a successful first socket write and hasSent becoming true.
	initialWriteMu       sync.Mutex
	initialWritesPending atomic.Int32
	respConnMu           sync.Mutex

	// pendingReplyPeers keeps a small ring of recently written upstream peers
	// while the endpoint is still probing. The first reply must match one of
	// these peers before the endpoint is promoted to established state.
	pendingReplyMu        sync.Mutex
	pendingReplyPeers     [udpEndpointPendingReplyPeerLimit]netip.AddrPort
	pendingReplyPeerCount int
	pendingReplyPeerNext  int

	Dialer            *dialer.Dialer
	Outbound          *outbound.DialerGroup
	flowRouteBinding  UdpRouteBinding
	flowNetwork       string
	flowBindingSet    bool
	flowBindingDialIP bool

	// Non-empty indicates this UDP Endpoint is related with a sniffed domain.
	SniffedDomain string
	DialTarget    string

	routingMu         sync.RWMutex
	routingCacheDst   netip.AddrPort
	routingCacheProto uint8
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
	udpConnStateLastPair  atomic.Pointer[udpConnStateTuplePairSnapshot]
	udpConnStateClosed    bool
	udpConnStateOwner     udpConnStateOwner
	drainTracker          *controlPlaneDrainTracker
	drainRelease          func()

	log *logrus.Logger

	// sentReporter, when non-nil, owns the upload accounting and traffic health
	// reporting for datagrams this endpoint hands to the batch aggregator:
	// WriteTo only queues them, so the caller cannot report them at submission
	// time. It is invoked with the endpoint, the number of datagrams actually
	// handed to the transport, and their payload bytes, and only when that
	// count is > 0. Nil for non-batched endpoints (the caller reports inline)
	// and for endpoints built without a control plane (tests, pool-only use).
	sentReporter func(sent *UdpEndpoint, datagrams int, bytes int)

	// batchFlushFailureCount counts failed asynchronous flushes. The flush runs
	// off the caller's stack, so without this counter (and its rate-limited
	// warn) a failing batched transport was completely invisible.
	batchFlushFailureCount atomic.Uint64

	dead   atomic.Bool
	failed atomic.Bool

	softErrorCount int

	// Transport-owned packet receiver ("push mode"): when the conn supports
	// netproxy.PacketReceiver it delivers packets through handleReceivedPacket
	// instead of a blocking ReadFrom loop, and the bounded reply queue below
	// feeds the shared replySender goroutine. ReadFrom-loop endpoints keep
	// their queue as read-loop locals and never touch these fields.
	receiverMu   sync.Mutex // guards receiverStop
	receiverStop func()
	receiveMu    sync.Mutex // serializes concurrent receiver deliveries

	replyQueueMu     sync.Mutex // guards replyQueueCh vs teardown
	replyQueueCh     chan *udpEndpointReply
	replyQueueDone   chan struct{}
	replyQueueStop   chan struct{} // sender error signal; nobody listens in this mode
	replyQueueClosed bool

	// poolRef and poolKey allow hard-failure paths to self-remove from the pool
	// immediately. Soft read-loop exits intentionally keep the endpoint cached so
	// active flows continue to follow the old timer-based reuse model.
	poolRef *UdpEndpointPool
	poolKey UdpEndpointKey

	dialerGeneration    uint64
	dialerGenerationRef *atomic.Uint64
	endpointNetworkType dialer.NetworkType
	lifecycleProfile    UdpLifecycleProfile
	// transportDone stores a <-chan struct{} once the transport lifecycle is
	// indexed. atomic.Value avoids carrying a mutex in every endpoint.
	transportDone  atomic.Value
	sessionRuntime *UDPFlowRuntime
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
	stop      chan struct{}
	stopOnce  sync.Once
	done      chan struct{}
	closed    bool
}

type udpEndpointDialerNetworkKey struct {
	dialer      *dialer.Dialer
	networkType dialer.NetworkType
}

// UdpEndpointPool is a UDP connection pool.
type UdpEndpointPool struct {
	shards           [udpEndpointCreateShardCount]udpEndpointPoolShard
	janitorOnce      sync.Once
	janitorStop      chan struct{}
	janitorDone      chan struct{}
	dialerIndex      sync.Map // map[udpEndpointDialerNetworkKey]*udpEndpointDialerBucket
	dialerEpoch      sync.Map // map[udpEndpointDialerNetworkKey]*atomic.Uint64
	transportIndex   sync.Map // map[<-chan struct{}]*udpEndpointTransportBucket
	transportWatchMu sync.RWMutex
}

// udpEndpointAdmissionGate keeps endpoint publication ordered with forced
// control-plane retirement. GetOrCreate holds a read lease for its full
// operation, while CloseAndWait prevents later leases and drains earlier ones.
type udpEndpointAdmissionGate struct {
	mu     sync.RWMutex
	closed atomic.Bool
}

func (g *udpEndpointAdmissionGate) tryAcquire() bool {
	if g == nil {
		return true
	}
	if g.closed.Load() {
		return false
	}
	g.mu.RLock()
	if g.closed.Load() {
		g.mu.RUnlock()
		return false
	}
	return true
}

func (g *udpEndpointAdmissionGate) release() {
	if g != nil {
		g.mu.RUnlock()
	}
}

func (g *udpEndpointAdmissionGate) closeAndWait() {
	if g == nil {
		return
	}
	g.closed.Store(true)
	g.mu.Lock()
	// This lock/unlock pair waits for in-flight admission checks to finish.
	//nolint:staticcheck // The empty critical section is an intentional synchronization barrier.
	g.mu.Unlock()
}

type UdpEndpointOptions struct {
	Ctx        context.Context
	Handler    UdpHandler
	NatTimeout time.Duration
	// ConnStateOwner releases eBPF UDP conn-state tuples when the endpoint exits.
	ConnStateOwner udpConnStateOwner
	// DrainTracker keeps the creating generation alive while the endpoint remains
	// active. Reusing an endpoint never transfers this ownership.
	DrainTracker *controlPlaneDrainTracker
	// admissionGate prevents endpoint creation after its control plane begins
	// forced retirement and keeps in-flight creation visible to retirement.
	admissionGate *udpEndpointAdmissionGate
	// GetTarget is useful only if the underlay does not support Full-cone.
	GetDialOption func(ctx context.Context) (option *DialOption, err error)
	// Log is the logger to use for endpoint lifecycle events.
	// If nil, logs are discarded.
	Log *logrus.Logger
	// NowNano is an optional pre-calculated timestamp to avoid calling time.Now()
	// in the hot path. If 0, time.Now() will be used.
	NowNano int64
	// sessionManager promotes a successfully dialed endpoint into the
	// process-owned session lifecycle before it is published in the pool.
	sessionManager *SessionManager
	egressRuntime  *egressRuntime
	// SentReporter reports datagrams actually sent by the batch aggregator,
	// which is the only place that knows the real sent count. Nil keeps the
	// caller-side inline accounting (non-batched endpoints).
	SentReporter func(sent *UdpEndpoint, datagrams int, bytes int)
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

func (p *UdpEndpointPool) Len() int {
	if p == nil {
		return 0
	}
	total := 0
	for i := range p.shards {
		shard := &p.shards[i]
		shard.mu.RLock()
		total += len(shard.pool)
		shard.mu.RUnlock()
	}
	return total
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

func (p *UdpEndpointPool) forgetDialerEpochs(dialers []*dialer.Dialer) {
	if p == nil || len(dialers) == 0 {
		return
	}
	retired := make(map[*dialer.Dialer]struct{}, len(dialers))
	for _, d := range dialers {
		if d != nil {
			retired[d] = struct{}{}
		}
	}
	p.dialerEpoch.Range(func(rawKey, _ any) bool {
		key, ok := rawKey.(udpEndpointDialerNetworkKey)
		if !ok {
			return true
		}
		if _, exists := retired[key.dialer]; exists {
			p.dialerEpoch.Delete(rawKey)
		}
		return true
	})
}

func (p *UdpEndpointPool) endpointGenerationCurrent(ue *UdpEndpoint) bool {
	if ue == nil || ue.Dialer == nil {
		return true
	}
	if udpEndpointIgnoresDialerHealth(ue) {
		return true
	}
	if ue.dialerGenerationRef == nil {
		return ue.dialerGeneration == p.currentDialerGeneration(ue.Dialer, udpEndpointNetworkType(ue))
	}
	return ue.dialerGeneration == ue.dialerGenerationRef.Load()
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
	if bucket.closed {
		bucket.mu.Unlock()
		return
	}
	delete(bucket.endpoints, ue)
	empty := len(bucket.endpoints) == 0
	if empty {
		bucket.closed = true
	}
	bucket.mu.Unlock()
	if empty {
		bucket.stopWatching()
		p.transportIndex.CompareAndDelete(transportDone, bucket)
		<-bucket.done
	}
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
		if ue.retireIfUnforwardedForDialerHealth() {
			removed++
		}
	}
	return removed
}

// AbortEndpointsOwnedBy closes endpoints whose BPF conn-state tuples belong to
// owner. It is used only after a generation has been forced to retire; normal
// reload draining intentionally leaves existing endpoints owned by their
// creating generation.
func (p *UdpEndpointPool) AbortEndpointsOwnedBy(owner udpConnStateOwner) error {
	if p == nil || owner == nil {
		return nil
	}

	var endpoints []*UdpEndpoint
	for i := range p.shards {
		shard := &p.shards[i]
		shard.mu.Lock()
		for key, ue := range shard.pool {
			if ue == nil || !ue.markDeadIfOwnedBy(owner) {
				continue
			}
			delete(shard.pool, key)
			endpoints = append(endpoints, ue)
		}
		shard.mu.Unlock()
	}

	var errs []error
	for _, ue := range endpoints {
		if err := ue.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

// Reset clears all cached UDP endpoints.
// Called on reload to prevent stale endpoints from using pre-reload routing state.
// Uses LoadAndDelete for atomic removal that races safely with concurrent GetOrCreate.
func (p *UdpEndpointPool) Reset() {
	for i := range udpEndpointCreateShardCount {
		shard := &p.shards[i]
		shard.mu.Lock()
		toClose := make([]*UdpEndpoint, 0, len(shard.pool))
		for key, ue := range shard.pool {
			delete(shard.pool, key)
			if ue != nil {
				toClose = append(toClose, ue)
			}
		}
		shard.mu.Unlock()
		for _, ue := range toClose {
			_ = ue.Close()
		}
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
	p.stopTransportWatchers()
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
	if ue, ok := shard.pool[key]; !ok || ue != udpEndpoint {
		shard.mu.Unlock()
		_ = udpEndpoint.Close()
		return fmt.Errorf("target udp endpoint is not in the pool")
	}
	delete(shard.pool, key)
	shard.mu.Unlock()
	// Close waits for the reply sender; never hold shard.mu across it.
	return udpEndpoint.Close()
}

// udpEndpointPoolGetObserver, when non-nil, is invoked on every Get. Tests
// use it to count per-packet pool lookups; production leaves it nil.
var udpEndpointPoolGetObserver func(UdpEndpointKey)

func (p *UdpEndpointPool) Get(key UdpEndpointKey) (udpEndpoint *UdpEndpoint, ok bool) {
	if observe := udpEndpointPoolGetObserver; observe != nil {
		observe(key)
	}
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
		drainTracker:      createOption.DrainTracker,
		lifecycleProfile:  newDataSessionLifecycleProfile(dialOption.Dialer),
		endpointNetworkType: func() dialer.NetworkType {
			if dialOption.NetworkType != nil {
				return *dialOption.NetworkType
			}
			return dialer.NetworkType{
				L4Proto:         consts.L4ProtoStr_UDP,
				IpVersion:       consts.IpVersionFromAddr(key.Src.Addr()),
				IsDns:           false,
				UdpHealthDomain: dialer.UdpHealthDomainData,
			}
		}(),
	}
	if udpWriteBatchOptedIn() {
		if _, ok := packetConn.(netproxy.PacketBatchWriter); ok {
			ue.writeBatch = newUDPWriteBatchAggregator(ue)
			ue.sentReporter = createOption.SentReporter
		}
	}
	if createOption.sessionManager != nil {
		if _, err := createOption.sessionManager.adoptUDP(ue, dialOption.Binding, createOption.egressRuntime); err != nil {
			_ = packetConn.Close()
			return nil, err
		}
	} else {
		ue.setFlowBinding(dialOption.Binding)
	}
	if createOption.DrainTracker != nil {
		ue.drainRelease = createOption.DrainTracker.Acquire()
	}
	ue.dialerGenerationRef = p.dialerEpochCounter(dialOption.Dialer, ue.endpointNetworkType)
	if ue.dialerGenerationRef != nil {
		ue.dialerGeneration = ue.dialerGenerationRef.Load()
	}

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

	// Receive UDP messages. Transports that own a packet receiver register
	// synchronously and reuse the protocol's existing reader; everything else
	// gets a dedicated blocking ReadFrom loop.
	if !ue.startTransportReceiver() {
		go ue.startReadLoop()
	}
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

// udpEndpointHitClass classifies an endpoint found by GetOrCreate.
type udpEndpointHitClass int

const (
	udpEndpointHitUsable udpEndpointHitClass = iota
	udpEndpointHitFailed
	udpEndpointHitStale
)

// classifyUdpEndpointHit applies the shared existing-endpoint policy: usable
// entries get their TTL/NAT timeout refreshed in place; fresh failures are
// hard errors; expired failures, dead and generation-stale entries are stale
// and eligible for replacement. Callers hold the shard lock appropriate to
// their path.
func (p *UdpEndpointPool) classifyUdpEndpointHit(ue *UdpEndpoint, createOption *UdpEndpointOptions) udpEndpointHitClass {
	switch {
	case ue.failed.Load():
		if !ue.IsExpired(time.Now().UnixNano()) {
			return udpEndpointHitFailed
		}
		return udpEndpointHitStale
	case ue.IsDead() || (!p.endpointGenerationCurrent(ue) && !p.endpointSurvivesDialerInvalidation(ue)):
		return udpEndpointHitStale
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
		return udpEndpointHitUsable
	}
}

func (p *UdpEndpointPool) GetOrCreate(key UdpEndpointKey, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, isNew bool, err error) {
	var admissionGate *udpEndpointAdmissionGate
	if createOption != nil {
		admissionGate = createOption.admissionGate
	}
	if !admissionGate.tryAcquire() {
		return nil, false, errUdpEndpointAdmissionClosed
	}
	defer admissionGate.release()

	shard := p.shardFor(key)

	// Fast path: existing socket
	shard.mu.RLock()
	ue, ok := shard.pool[key]
	if ok {
		switch p.classifyUdpEndpointHit(ue, createOption) {
		case udpEndpointHitFailed:
			shard.mu.RUnlock()
			return nil, false, ErrEndpointFailed
		case udpEndpointHitUsable:
			shard.mu.RUnlock()
			return ue, false, nil
		}
		// Stale entry — fall through to the write-locked path for replacement.
	}
	shard.mu.RUnlock()

	// Slow path: serialize creation for the same key using a creation shard lock.
	var staleToClose *UdpEndpoint
	shard.createMu.Lock()
	createMuLocked := true
	defer func() {
		// GetOrCreate is called from panic-recovering packet workers. Preserve
		// unlock and stale cleanup on unwind so one panic cannot strand this shard.
		if createMuLocked {
			shard.createMu.Unlock()
		}
		if staleToClose != nil {
			_ = staleToClose.Close()
		}
	}()
	shard.mu.Lock()
	ue, ok = shard.pool[key]
	if ok {
		switch p.classifyUdpEndpointHit(ue, createOption) {
		case udpEndpointHitFailed:
			shard.mu.Unlock()
			return nil, false, ErrEndpointFailed
		case udpEndpointHitUsable:
			shard.mu.Unlock()
			return ue, false, nil
		default:
			delete(shard.pool, key)
			staleToClose = ue
		}
	}
	shard.mu.Unlock()

	// Create a new endpoint under the creation lock.
	newUe, createErr := p.createEndpointLocked(key, createOption)
	shard.createMu.Unlock()
	createMuLocked = false

	// Close the stale endpoint outside createMu: Close waits on the
	// transport receiver and must not extend the shard-wide creation hold.
	if staleToClose != nil {
		_ = staleToClose.Close()
		staleToClose = nil
	}
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
			interval := udpEndpointJanitorInterval
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			defer close(p.janitorDone)

			var toClose []*UdpEndpoint

			for {
				select {
				case <-p.janitorStop:
					return
				case now := <-ticker.C:
					nowNano := now.UnixNano()
					cleaned := 0
					entriesSeen := 0
					for i := range udpEndpointCreateShardCount {
						shard := &p.shards[i]
						shard.mu.Lock()
						entriesSeen += len(shard.pool)
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
						cleaned += len(toClose)
					}
					// Back off only while the pool is completely empty, so an
					// idle dae does not wake up to no-op scans. Any entries at
					// all keep the base cadence so their expiry is reaped
					// promptly.
					if cleaned > 0 || entriesSeen > 0 {
						interval = udpEndpointJanitorInterval
					} else if interval < udpEndpointJanitorMaxInterval {
						interval *= 2
						if interval > udpEndpointJanitorMaxInterval {
							interval = udpEndpointJanitorMaxInterval
						}
					}
					ticker.Reset(interval)
				}
			}
		}()
	})
}
