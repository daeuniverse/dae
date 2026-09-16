/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	// ErrSessionManagerClosed is returned when a flow is registered after the
	// process-level session manager has begun shutdown.
	ErrSessionManagerClosed = stderrors.New("session manager is closed")
	// ErrFlowAlreadyRegistered is returned when an ingress connection already
	// belongs to a live flow runtime.
	ErrFlowAlreadyRegistered = stderrors.New("flow is already registered")
)

type sessionGenerationState struct {
	active int
}

type controlPlaneSessionManagerBinding struct {
	manager *SessionManager
	owned   bool
}

type udpFlowSourceSnapshot struct {
	flows []*UDPFlowRuntime
	// epochCounts tallies held flows per policy epoch. It is rebuilt
	// together with flows (writers already reserialize under mu) so
	// retainedUDPEndpoint can skip its whole O(flows) scan when the
	// current epoch already owns every flow — the steady state between
	// reloads.
	epochCounts map[routing.PolicyEpoch]int
}

// sessionPinnedShardCount sizes the per-key refcount shards. Each key maps to
// one authoritative shard. Adoption and release still serialize generation
// bookkeeping with generationsMu, so sharding must not be treated as an
// end-to-end connection setup concurrency claim.
const sessionPinnedShardCount = 16

type pinnedKeyShard struct {
	mu   sync.Mutex
	keys map[bpfTuplesKey]int
}

type redirectKeyShard struct {
	mu   sync.Mutex
	keys map[bpfRedirectTuple]int
}

// tuplesShardIndex is an allocation-free FNV-1a over the fixed-width tuple.
func tuplesShardIndex(key *bpfTuplesKey) int {
	const (
		fnvOffset uint32 = 2166136261
		fnvPrime  uint32 = 16777619
	)
	h := fnvOffset
	for i := range key.Sip.U6Addr8 {
		h ^= uint32(key.Sip.U6Addr8[i])
		h *= fnvPrime
	}
	for i := range key.Dip.U6Addr8 {
		h ^= uint32(key.Dip.U6Addr8[i])
		h *= fnvPrime
	}
	h ^= uint32(key.Sport)
	h *= fnvPrime
	h ^= uint32(key.Dport)
	h *= fnvPrime
	h ^= uint32(key.L4proto)
	h *= fnvPrime
	return int(h % sessionPinnedShardCount)
}

func redirectShardIndex(key *bpfRedirectTuple) int {
	const (
		fnvOffset uint32 = 2166136261
		fnvPrime  uint32 = 16777619
	)
	h := fnvOffset
	for i := range key.Sip.U6Addr8 {
		h ^= uint32(key.Sip.U6Addr8[i])
		h *= fnvPrime
	}
	for i := range key.Dip.U6Addr8 {
		h ^= uint32(key.Dip.U6Addr8[i])
		h *= fnvPrime
	}
	return int(h % sessionPinnedShardCount)
}

func (s *pinnedKeyShard) pin(key bpfTuplesKey) {
	s.mu.Lock()
	s.keys[key]++
	s.mu.Unlock()
}

func (s *pinnedKeyShard) unpin(key bpfTuplesKey) (dropped bool) {
	s.mu.Lock()
	if refs := s.keys[key]; refs <= 1 {
		delete(s.keys, key)
		dropped = true
	} else {
		s.keys[key] = refs - 1
	}
	s.mu.Unlock()
	return dropped
}

func (s *redirectKeyShard) pin(key bpfRedirectTuple) {
	s.mu.Lock()
	s.keys[key]++
	s.mu.Unlock()
}

func (s *redirectKeyShard) unpin(key bpfRedirectTuple) {
	s.mu.Lock()
	if refs := s.keys[key]; refs <= 1 {
		delete(s.keys, key)
	} else {
		s.keys[key] = refs - 1
	}
	s.mu.Unlock()
}

// SessionManager owns established flow lifecycles independently of any
// ControlPlane generation. Reload swaps the policy used for new flows while
// existing runtimes retain their original sockets and immutable bindings.
//
// Locking: per-flow registration lives in sync.Maps, while generation
// bookkeeping and lifecycle snapshots serialize setup and teardown with
// generationsMu. Refcount maps are sharded by tuple hash. Established packet
// forwarding does not take these lifecycle locks.
type SessionManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	closed atomic.Bool

	// flows holds adopted-but-unfinished TCP flows keyed by ingress conn;
	// udpFlows holds UDP endpoint runtimes keyed by their pool endpoint.
	// Insert uses LoadOrStore so duplicate adoption fails atomically; release
	// removes an entry only when it still points at the same runtime.
	flows    sync.Map // map[net.Conn]*FlowRuntime
	udpFlows sync.Map // map[*UdpEndpoint]*UDPFlowRuntime

	tcpCount atomic.Int64
	udpCount atomic.Int64

	// generationsMu only guards the small epoch-count table plus flows whose
	// PolicyEpoch migrates mid-reload. The per-packet data plane never takes it.
	generationsMu sync.Mutex
	generations   map[routing.PolicyEpoch]*sessionGenerationState

	// pinnedShards/refShards hold process-level eBPF conn_state_map /
	// redirect-map refcounts. The shards isolate map ownership, while
	// generationsMu still serializes lifecycle transactions.
	pinnedShards [sessionPinnedShardCount]pinnedKeyShard
	refShards    [sessionPinnedShardCount]redirectKeyShard

	udpBySource sync.Map // map[netip.AddrPort]*udpFlowSourceSnapshot; writers serialize under generationsMu

	udpStateMu sync.RWMutex
	udpBPF     atomic.Pointer[bpfObjects]
	pinnedUDP  map[bpfTuplesKey]int

	closeOnce sync.Once
	closeErr  error
}

// FlowRuntime is the process-owned lifecycle capsule for one established TCP
// flow. Its context is independent from the ControlPlane that selected the
// immutable route and egress binding.
type FlowRuntime struct {
	manager *SessionManager

	ingress net.Conn
	egress  netproxy.Conn
	binding TcpFlowBinding

	ctx    context.Context
	cancel context.CancelFunc

	egressLease    *egressRuntimeLease
	pinKeys        [2]bpfTuplesKey
	pinKeyCount    uint8
	redirectKey    bpfRedirectTuple
	hasRedirectKey bool

	finishOnce sync.Once
	abortOnce  sync.Once
}

// UDPFlowRuntime keeps an established UDP endpoint and its immutable route
// binding alive independently of the ControlPlane that selected it.
type UDPFlowRuntime struct {
	manager  *SessionManager
	endpoint *UdpEndpoint
	binding  UdpFlowBinding

	ctx    context.Context
	cancel context.CancelFunc

	egressLease *egressRuntimeLease

	finishOnce sync.Once
	abortOnce  sync.Once
}

// NewSessionManager constructs a process-level flow owner. A nil parent uses
// context.Background.
func NewSessionManager(parent context.Context) *SessionManager {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	m := &SessionManager{
		ctx:         ctx,
		cancel:      cancel,
		generations: make(map[routing.PolicyEpoch]*sessionGenerationState),
		pinnedUDP:   make(map[bpfTuplesKey]int),
	}
	for i := range m.pinnedShards {
		m.pinnedShards[i].keys = make(map[bpfTuplesKey]int)
	}
	for i := range m.refShards {
		m.refShards[i].keys = make(map[bpfRedirectTuple]int)
	}
	return m
}

// AttachSessionManager installs the process-level session owner used by this
// control plane. It must be called before Serve starts accepting connections.
// Existing constructors remain compatible by creating a private manager lazily
// when no process owner is attached.
func (c *ControlPlane) AttachSessionManager(manager *SessionManager) error {
	if c == nil || manager == nil {
		return fmt.Errorf("attach session manager: manager is required")
	}
	incomingConnectionOwnershipMu.Lock()
	defer incomingConnectionOwnershipMu.Unlock()
	if c.drainTracker != nil && c.drainTracker.Count() != 0 {
		return fmt.Errorf("attach session manager after connection admission")
	}
	if c.udpIngressAdmission.state.Load() != 0 {
		return fmt.Errorf("attach session manager after UDP ingress admission")
	}
	activeIngress := false
	c.inConnections.Range(func(_, _ any) bool {
		activeIngress = true
		return false
	})
	if activeIngress {
		return fmt.Errorf("attach session manager with active ingress")
	}

	c.sessionManagerMu.Lock()
	previous := c.sessionManager
	previousOwned := c.ownsSessionManager
	if previous != nil && previous != manager && previous.ActiveConnections() != 0 {
		c.sessionManagerMu.Unlock()
		return fmt.Errorf("attach session manager with active private flows")
	}
	if err := manager.prepareControlPlane(c); err != nil {
		c.sessionManagerMu.Unlock()
		return err
	}
	c.sessionManager = manager
	c.ownsSessionManager = false
	c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{manager: manager})
	c.sessionManagerMu.Unlock()
	if previousOwned && previous != nil && previous != manager {
		return previous.Close()
	}
	return nil
}

func (m *SessionManager) prepareControlPlane(c *ControlPlane) error {
	if m == nil || c == nil {
		return ErrSessionManagerClosed
	}
	if m.closed.Load() {
		return ErrSessionManagerClosed
	}

	if bpf := c.PeekBpf(); bpf != nil {
		m.udpBPF.CompareAndSwap(nil, bpf)
	}
	return nil
}

func (c *ControlPlane) sessionManagerForFlow(parent context.Context) *SessionManager {
	if c == nil {
		return nil
	}
	if binding := c.sessionManagerBinding.Load(); binding != nil {
		return binding.manager
	}
	c.sessionManagerMu.Lock()
	defer c.sessionManagerMu.Unlock()
	if c.sessionManager == nil {
		c.sessionManager = NewSessionManager(parent)
		c.ownsSessionManager = true
	}
	c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{
		manager: c.sessionManager,
		owned:   c.ownsSessionManager,
	})
	return c.sessionManager
}

func (c *ControlPlane) controlPlaneSessionManager() (*SessionManager, bool) {
	if c == nil {
		return nil, false
	}
	if binding := c.sessionManagerBinding.Load(); binding != nil {
		return binding.manager, binding.owned
	}
	c.sessionManagerMu.Lock()
	manager := c.sessionManager
	owned := c.ownsSessionManager
	if manager != nil {
		c.sessionManagerBinding.Store(&controlPlaneSessionManagerBinding{
			manager: manager,
			owned:   owned,
		})
	}
	c.sessionManagerMu.Unlock()
	return manager, owned
}

func (c *ControlPlane) adoptTCPFlow(
	parent context.Context,
	ownership *incomingConnectionLease,
	ingress net.Conn,
	egress netproxy.Conn,
	binding TcpFlowBinding,
	src netip.AddrPort,
	dst netip.AddrPort,
) (*FlowRuntime, error) {
	takeFailedEgress := func() netproxy.Conn {
		if ownership != nil {
			return ownership.takePendingEgress()
		}
		return egress
	}
	manager := c.sessionManagerForFlow(parent)
	if manager == nil {
		if failedEgress := takeFailedEgress(); failedEgress != nil {
			_ = failedEgress.Close()
		}
		return nil, ErrSessionManagerClosed
	}
	keys := []bpfTuplesKey{
		bpfTuplesKeyFromAddrPorts(src, dst, uint8(unix.IPPROTO_TCP)),
		bpfTuplesKeyFromAddrPorts(dst, src, uint8(unix.IPPROTO_TCP)),
	}
	// Writer-side adoption: the ownership mutex only serializes writers now
	// (adoption, attach, close, abort snapshots); steady-state readers run
	// lock-free with their own gate rechecks. A transfer migrating this lease
	// out concurrently is self-guarding (it revalidates both gates after its
	// swap), while a straggler adopted moments after an abort snapshot ran
	// exits through normal relay error paths bounded by the relay watchdogs.
	incomingConnectionOwnershipMu.Lock()
	if !c.acceptsRoutingEpochExecution() || (ownership != nil && ownership.owner != c) {
		failedEgress := takeFailedEgress()
		incomingConnectionOwnershipMu.Unlock()
		if failedEgress != nil {
			_ = failedEgress.Close()
		}
		return nil, errRoutingEpochOwnerUnavailable
	}
	var runtime *egressRuntime
	if egress != nil {
		runtime = c.egressRuntime
	}
	flow, err := manager.adoptTCP(ingress, egress, binding, runtime, keys)
	var drainRelease func()
	var failedEgress netproxy.Conn
	if err == nil && ownership != nil {
		_ = ownership.takePendingEgress()
		drainRelease = ownership.releaseLocked()
	} else if err != nil {
		failedEgress = takeFailedEgress()
	}
	incomingConnectionOwnershipMu.Unlock()
	if drainRelease != nil {
		drainRelease()
	}
	if failedEgress != nil {
		_ = failedEgress.Close()
	}
	return flow, err
}

// Context returns the flow-specific lifetime context.
func (f *FlowRuntime) Context() context.Context {
	if f == nil || f.ctx == nil {
		return context.Background()
	}
	return f.ctx
}

// Ingress returns the accepted transparent connection.
func (f *FlowRuntime) Ingress() net.Conn {
	if f == nil {
		return nil
	}
	return f.ingress
}

// Egress returns the concrete outbound connection selected at establishment.
// It is nil for locally terminated flows such as transparent DNS-over-TCP.
func (f *FlowRuntime) Egress() netproxy.Conn {
	if f == nil {
		return nil
	}
	return f.egress
}

// Binding returns the immutable route and concrete egress decision.
func (f *FlowRuntime) Binding() TcpFlowBinding {
	if f == nil {
		return TcpFlowBinding{}
	}
	return f.binding
}

func (m *SessionManager) adoptTCP(
	ingress net.Conn,
	egress netproxy.Conn,
	binding TcpFlowBinding,
	runtime *egressRuntime,
	pinKeys []bpfTuplesKey,
) (*FlowRuntime, error) {
	if m == nil {
		return nil, ErrSessionManagerClosed
	}
	if ingress == nil {
		return nil, fmt.Errorf("adopt TCP flow: ingress is required")
	}
	lease, retainedOutbound, ok := runtime.acquireEgress(binding.Egress.Dialer, binding.Egress.Outbound)
	if !ok {
		return nil, fmt.Errorf("adopt TCP flow: egress runtime is retiring")
	}
	binding.Egress.Outbound = retainedOutbound
	ctx, cancel := context.WithCancel(m.ctx)
	flow := &FlowRuntime{
		manager:     m,
		ingress:     ingress,
		egress:      egress,
		binding:     binding,
		ctx:         ctx,
		cancel:      cancel,
		egressLease: lease,
	}
	if len(pinKeys) > len(flow.pinKeys) {
		pinKeys = pinKeys[:len(flow.pinKeys)]
	}
	flow.pinKeyCount = uint8(copy(flow.pinKeys[:], pinKeys))

	if m.closed.Load() {
		cancel()
		_ = lease.release()
		return nil, ErrSessionManagerClosed
	}
	// Registering the flow and bookkeeping its pins/generation must be
	// mutually exclusive with releaseFlow and reload-time snapshots (the
	// old single mutex covered all three; this small critical section keeps
	// the identical happens-before over a much narrower surface).
	m.generationsMu.Lock()
	if _, loaded := m.flows.LoadOrStore(ingress, flow); loaded {
		m.generationsMu.Unlock()
		cancel()
		_ = lease.release()
		return nil, ErrFlowAlreadyRegistered
	}
	m.tcpCount.Add(1)
	m.retainGenerationLocked(binding.Route.PolicyEpoch)
	for i := range int(flow.pinKeyCount) {
		shard := &m.pinnedShards[tuplesShardIndex(&flow.pinKeys[i])]
		shard.pin(flow.pinKeys[i])
	}
	if flow.pinKeyCount > 0 {
		flow.redirectKey = redirectTupleForFlow(flow.pinKeys[0])
		flow.hasRedirectKey = true
		refShard := &m.refShards[redirectShardIndex(&flow.redirectKey)]
		refShard.pin(flow.redirectKey)
	}
	m.generationsMu.Unlock()
	return flow, nil
}

func (f *FlowRuntime) finish() {
	if f == nil {
		return
	}
	f.finishOnce.Do(func() {
		if f.manager != nil {
			f.manager.releaseFlow(f)
			return
		}
		if f.cancel != nil {
			f.cancel()
		}
		_ = f.egressLease.release()
	})
}

func (m *SessionManager) releaseFlow(flow *FlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	deleteKeys := make([]bpfTuplesKey, 0, flow.pinKeyCount)

	m.generationsMu.Lock()
	current, loaded := m.flows.LoadAndDelete(flow.ingress)
	if loaded && current == flow {
		m.tcpCount.Add(-1)
		m.releaseGenerationLocked(flow.binding.Route.PolicyEpoch)

		for i := range int(flow.pinKeyCount) {
			key := flow.pinKeys[i]
			shard := &m.pinnedShards[tuplesShardIndex(&key)]
			if shard.unpin(key) {
				deleteKeys = append(deleteKeys, key)
			}
		}
		if flow.hasRedirectKey {
			refShard := &m.refShards[redirectShardIndex(&flow.redirectKey)]
			refShard.unpin(flow.redirectKey)
		}

		// The physical delete shares this generationsMu critical section with
		// the unpin above and with adoptTCP's pin: a same-tuple reconnect
		// must not slip a fresh pin between the refcount dropping to zero
		// and the delete, or the new flow would lose its live entry. This
		// mirrors the invariant ReleaseUdpConnStateTuples documents and
		// enforces for UDP under udpStateMu. Lock order generationsMu ->
		// udpStateMu matches the janitor's scan-to-delete recheck.
		//
		// deleteKeys is the set of keys whose refcount reached zero in the
		// loop above. The refcount is manager-global (pinnedShards), so a key
		// in deleteKeys is held by no flow in any table: the scrub must run
		// with exactly the same gate, inside this same critical section. Deleting the whole pinKeys set unconditionally
		// (the previous behavior, outside generationsMu) removed entries that
		// a still-live same-tuple flow pins.
		if len(deleteKeys) > 0 {
			m.udpStateMu.RLock()
			if bpf := m.udpBPF.Load(); bpf != nil && bpf.ConnStateMap != nil {
				if _, err := connStateScrubDelete(bpf.ConnStateMap, deleteKeys); err != nil {
					countConnStateScrubError("primary", err)
				}
			}
			m.udpStateMu.RUnlock()
		}
	}
	m.generationsMu.Unlock()

	if flow.cancel != nil {
		flow.cancel()
	}
	_ = flow.egressLease.release()
}

// connStateScrubErrorCount counts failed physical conn_state deletions issued
// from releaseFlow after the last in-process pin for a tuple disappeared.
//
// The deletion is best-effort by design (the janitor retires leftovers), but
// a silent failure would hide a broken map for a whole generation, so every
// failure is counted and the first / 2^n-th occurrence is logged.
var connStateScrubErrorCount atomic.Uint64

// connStateScrubDelete is the package-local seam for the physical conn_state
// deletion performed by releaseFlow. Production wiring is BpfMapBatchDelete;
// tests substitute it to observe exactly which keys the refcount gate released
// (and that a still-pinned tuple releases none) without a real BPF map.
var connStateScrubDelete = BpfMapBatchDelete

func countConnStateScrubError(stage string, err error) {
	if err == nil {
		return
	}
	count := connStateScrubErrorCount.Add(1)
	if !shouldReportEveryPow2(count) {
		return
	}
	logrus.WithFields(logrus.Fields{
		"stage": stage,
		"error": err.Error(),
		"count": count,
	}).Error("failed to scrub conn_state entry after the last flow pin dropped")
}

func (m *SessionManager) retainGenerationLocked(epoch routing.PolicyEpoch) {
	state := m.generations[epoch]
	if state == nil {
		state = &sessionGenerationState{}
		m.generations[epoch] = state
	}
	state.active++
}

func (m *SessionManager) releaseGenerationLocked(epoch routing.PolicyEpoch) {
	state := m.generations[epoch]
	if state == nil || state.active == 0 {
		return
	}
	state.active--
	if state.active == 0 {
		delete(m.generations, epoch)
	}
}

func (m *SessionManager) adoptUDP(endpoint *UdpEndpoint, binding UdpFlowBinding, runtime *egressRuntime) (*UDPFlowRuntime, error) {
	if m == nil {
		return nil, ErrSessionManagerClosed
	}
	if endpoint == nil {
		return nil, fmt.Errorf("adopt UDP flow: endpoint is required")
	}
	if binding.Egress.Dialer == nil {
		binding.Egress.Dialer = endpoint.Dialer
	}
	if binding.Egress.Outbound == nil {
		binding.Egress.Outbound = endpoint.Outbound
	}
	lease, retainedOutbound, ok := runtime.acquireEgress(binding.Egress.Dialer, binding.Egress.Outbound)
	if !ok {
		return nil, fmt.Errorf("adopt UDP flow: egress runtime is retiring")
	}
	binding.Egress.Outbound = retainedOutbound
	endpoint.Outbound = retainedOutbound
	endpoint.setFlowBinding(binding)
	ctx, cancel := context.WithCancel(m.ctx)
	flow := &UDPFlowRuntime{
		manager:     m,
		endpoint:    endpoint,
		binding:     binding,
		ctx:         ctx,
		cancel:      cancel,
		egressLease: lease,
	}

	if m.closed.Load() {
		cancel()
		_ = lease.release()
		return nil, ErrSessionManagerClosed
	}
	m.generationsMu.Lock()
	if _, loaded := m.udpFlows.LoadOrStore(endpoint, flow); loaded {
		m.generationsMu.Unlock()
		cancel()
		_ = lease.release()
		return nil, ErrFlowAlreadyRegistered
	}
	m.udpCount.Add(1)
	m.appendUDPFlowSourceLocked(endpoint.poolKey.Src, flow)
	m.retainGenerationLocked(binding.Route.PolicyEpoch)
	m.generationsMu.Unlock()
	endpoint.sessionRuntime = flow
	return flow, nil
}

func (f *UDPFlowRuntime) finish() {
	if f == nil {
		return
	}
	f.finishOnce.Do(func() {
		if f.manager != nil {
			f.manager.releaseUDPFlow(f)
			return
		}
		if f.cancel != nil {
			f.cancel()
		}
		_ = f.egressLease.release()
	})
}

func (m *SessionManager) releaseUDPFlow(flow *UDPFlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	m.generationsMu.Lock()
	current, loaded := m.udpFlows.LoadAndDelete(flow.endpoint)
	if loaded && current == flow {
		m.udpCount.Add(-1)
		m.removeUDPFlowSourceLocked(flow.endpoint.poolKey.Src, flow)
		m.releaseGenerationLocked(flow.binding.Route.PolicyEpoch)
	}
	m.generationsMu.Unlock()
	if flow.cancel != nil {
		flow.cancel()
	}
	_ = flow.egressLease.release()
}

func (f *UDPFlowRuntime) abort() error {
	if f == nil {
		return nil
	}
	var err error
	f.abortOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		if f.endpoint != nil {
			f.endpoint.dead.Store(true)
			f.endpoint.selfRemoveFromPool()
			err = f.endpoint.Close()
		}
		f.finish()
	})
	return err
}

func (m *SessionManager) retainedUDPEndpoint(src, dst netip.AddrPort, result *bpfRoutingResult, currentEpoch routing.PolicyEpoch) (*UdpEndpoint, bool) {
	if m == nil {
		return nil, false
	}
	desiredScope := newUdpEndpointRouteScope(result)
	value, ok := m.udpBySource.Load(src)
	if !ok {
		return nil, false
	}
	snapshot, ok := value.(*udpFlowSourceSnapshot)
	if !ok || snapshot == nil {
		return nil, false
	}
	if snapshot.epochCounts[currentEpoch] == len(snapshot.flows) {
		// Every flow for this source already routes under the current
		// epoch: no retained (stale-epoch) endpoint can exist. This keeps
		// the per-packet probe off the O(flows) scan for high-fan-out
		// sources outside reload windows.
		return nil, false
	}
	var selected *UDPFlowRuntime
	selectedScore := -1
	for _, flow := range snapshot.flows {
		if flow == nil || flow.endpoint == nil || flow.binding.Route.PolicyEpoch == currentEpoch {
			continue
		}
		key := flow.endpoint.poolKey
		if key.Dst.IsValid() && key.Dst != dst {
			continue
		}
		if key.RouteScope != (udpEndpointRouteScope{}) && key.RouteScope != desiredScope {
			continue
		}
		score := 0
		if key.Dst.IsValid() {
			score += 2
		}
		if key.RouteScope == desiredScope {
			score++
		}
		if score > selectedScore {
			selected = flow
			selectedScore = score
		}
	}
	if selected == nil || selected.endpoint.IsDead() {
		return nil, false
	}
	return selected.endpoint, true
}

// appendUDPFlowSourceLocked publishes a new immutable per-source index. The
// caller serializes writers with SessionManager.generationsMu (the same mutex
// that used to guard the old global mu) so same-source snapshots never lose an
// append or removal.
func (m *SessionManager) appendUDPFlowSourceLocked(src netip.AddrPort, flow *UDPFlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	var current []*UDPFlowRuntime
	if value, ok := m.udpBySource.Load(src); ok {
		if snapshot, snapshotOK := value.(*udpFlowSourceSnapshot); snapshotOK && snapshot != nil {
			current = snapshot.flows
		}
	}
	next := make([]*UDPFlowRuntime, len(current)+1)
	copy(next, current)
	next[len(current)] = flow
	m.udpBySource.Store(src, &udpFlowSourceSnapshot{
		flows:       next,
		epochCounts: udpFlowEpochCounts(next),
	})
}

// removeUDPFlowSourceLocked replaces one immutable per-source index. The
// caller serializes writers with SessionManager.generationsMu.
func (m *SessionManager) removeUDPFlowSourceLocked(src netip.AddrPort, flow *UDPFlowRuntime) {
	if m == nil || flow == nil {
		return
	}
	value, ok := m.udpBySource.Load(src)
	if !ok {
		return
	}
	snapshot, ok := value.(*udpFlowSourceSnapshot)
	if !ok || snapshot == nil {
		return
	}
	index := -1
	for i, candidate := range snapshot.flows {
		if candidate == flow {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	if len(snapshot.flows) == 1 {
		m.udpBySource.Delete(src)
		return
	}
	next := make([]*UDPFlowRuntime, len(snapshot.flows)-1)
	copy(next, snapshot.flows[:index])
	copy(next[index:], snapshot.flows[index+1:])
	m.udpBySource.Store(src, &udpFlowSourceSnapshot{
		flows:       next,
		epochCounts: udpFlowEpochCounts(next),
	})
}

// udpFlowEpochCounts tallies the routing epoch of every held flow. The
// snapshot rebuild paths are already O(flows); folding the tally in keeps the
// per-packet retained-endpoint probe O(1) in the steady state.
func udpFlowEpochCounts(flows []*UDPFlowRuntime) map[routing.PolicyEpoch]int {
	counts := make(map[routing.PolicyEpoch]int, 1)
	for _, flow := range flows {
		if flow != nil {
			counts[flow.binding.Route.PolicyEpoch]++
		}
	}
	return counts
}

// ActiveConnections returns all process-owned TCP and UDP flows. The counts
// are lock-free atomics, so the answer is a close-enough eventual snapshot
// under concurrent adoption — matching its status-reporting use.
func (m *SessionManager) ActiveConnections() int {
	if m == nil {
		return 0
	}
	return int(m.tcpCount.Load() + m.udpCount.Load())
}

func (f *FlowRuntime) abort() error {
	if f == nil {
		return nil
	}
	var err error
	f.abortOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		var errs []error
		if f.ingress != nil {
			if closeErr := f.ingress.Close(); closeErr != nil && !commonerrors.IsClosedConnection(closeErr) {
				errs = append(errs, closeErr)
			}
		}
		if f.egress != nil {
			if closeErr := f.egress.Close(); closeErr != nil && !commonerrors.IsClosedConnection(closeErr) {
				errs = append(errs, closeErr)
			}
		}
		err = stderrors.Join(errs...)
		f.finish()
	})
	return err
}

// ActiveTCPConnections returns the number of process-owned TCP flows.
func (m *SessionManager) ActiveTCPConnections() int {
	if m == nil {
		return 0
	}
	return int(m.tcpCount.Load())
}

// AbortGeneration closes every flow established under one policy epoch.
// The manager remains open for flows created by other or future generations.
func (m *SessionManager) AbortGeneration(epoch routing.PolicyEpoch) error {
	if m == nil {
		return nil
	}
	// generationsMu keeps epoch reads mutually exclusive with the generation
	// accounting that releaseFlow performs, exactly like the old global mu.
	flows := make([]*FlowRuntime, 0)
	udpFlows := make([]*UDPFlowRuntime, 0)
	m.generationsMu.Lock()
	m.flows.Range(func(_, v any) bool {
		flow := v.(*FlowRuntime)
		if flow.binding.Route.PolicyEpoch == epoch {
			flows = append(flows, flow)
		}
		return true
	})
	m.udpFlows.Range(func(_, v any) bool {
		flow := v.(*UDPFlowRuntime)
		if flow.binding.Route.PolicyEpoch == epoch {
			udpFlows = append(udpFlows, flow)
		}
		return true
	})
	m.generationsMu.Unlock()
	var errs []error
	for _, flow := range flows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, flow := range udpFlows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

// AbortAll closes every established flow without closing the manager.
func (m *SessionManager) AbortAll() error {
	if m == nil {
		return nil
	}
	flows := make([]*FlowRuntime, 0, 16)
	udpFlows := make([]*UDPFlowRuntime, 0, 16)
	m.flows.Range(func(_, v any) bool {
		flows = append(flows, v.(*FlowRuntime))
		return true
	})
	m.udpFlows.Range(func(_, v any) bool {
		udpFlows = append(udpFlows, v.(*UDPFlowRuntime))
		return true
	})
	var errs []error
	for _, flow := range flows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, flow := range udpFlows {
		if err := flow.abort(); err != nil {
			errs = append(errs, err)
		}
	}
	return stderrors.Join(errs...)
}

// Close prevents new adoption and aborts all process-owned flows.
func (m *SessionManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		m.cancel()
		m.closeErr = m.AbortAll()
	})
	return m.closeErr
}
