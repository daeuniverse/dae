/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	errRoutingEpochOwnerUnavailable = stderrors.New("routing epoch execution owner is unavailable")
	routingEpochPeerLinkMu          sync.Mutex
	// incomingConnectionOwnershipMu serializes lifecycle writers only:
	// AttachSessionManager, flow adoption, and the close/abort transitions.
	//
	// The ownership gate uses a double-checked atomic protocol. Admission also
	// acquires the generation drain tracker, whose coarse mutex accounts one
	// ticket per live flow; this path is therefore not fully lock-free. Every
	// admission follows
	//
	//	check(gates) -> drainTracker.Add -> recheck(gates) -> commit map state
	//
	// and every close first stores its flag. Under Go's sequentially
	// consistent atomics these operations share one total order, so for any
	// racing pair exactly one of the following holds:
	//
	//	ticket < closer.store(flag): the closer's count observation sees the
	//	                             ticket and waits for its release;
	//	closer.store(flag) < ticket: the recheck load follows the store,
	//	                             sees the gate closed, releases the
	//	                             ticket, and rejects.
	//
	// Admit-after-idle is therefore impossible without any shared reader
	// synchronization. Failed validations are backed out by releasing the
	// just-added ticket (or rolling a cross-generation move back); because
	// both gates are monotone (once closed they never reopen before the next
	// generation takes over fresh flags), retry converges to rejection
	// instead of livelocking.
	//
	// Residual nuance kept deliberately: an abort that snapshots conns can
	// miss a lease whose map entry lands moments later — such a straggler is
	// unknown to the wipe but exits through normal relay error paths and the
	// idle watchdogs, which bound its lifetime.
	incomingConnectionOwnershipMu sync.Mutex
)

// incomingConnectionLease keeps an accepted TCP connection attached to the
// control plane currently responsible for executing its policy. During a
// staged reload it can move to the peer before either generation retires.
type incomingConnectionLease struct {
	conn         net.Conn
	owner        *ControlPlane
	drainRelease func()
	once         sync.Once
	egress       atomic.Pointer[netproxy.Conn]
}

const routingEpochIngressClosed uint64 = 1 << 63

// routingEpochIngressGate accounts for packets that have already been read
// from a listener but have not reached their asynchronous UDP task yet. Its
// atomic fast path keeps ordinary packet ingress independent of the control
// plane drain mutex while allowing retirement to close admission exactly once.
type routingEpochIngressGate struct {
	state   atomic.Uint64
	waitMu  sync.Mutex
	drained chan struct{}
}

func (g *routingEpochIngressGate) tryAcquire() bool {
	if g == nil {
		return true
	}
	for {
		state := g.state.Load()
		if state&routingEpochIngressClosed != 0 {
			return false
		}
		if g.state.CompareAndSwap(state, state+1) {
			return true
		}
	}
}

func (g *routingEpochIngressGate) release() {
	if g == nil {
		return
	}
	if g.state.Add(^uint64(0)) != routingEpochIngressClosed {
		return
	}
	g.waitMu.Lock()
	if g.drained != nil {
		close(g.drained)
	}
	g.waitMu.Unlock()
}

func (g *routingEpochIngressGate) closeAndWait() {
	if g == nil {
		return
	}
	for {
		state := g.state.Load()
		if state&routingEpochIngressClosed != 0 {
			break
		}
		if g.state.CompareAndSwap(state, state|routingEpochIngressClosed) {
			break
		}
	}
	if g.state.Load() == routingEpochIngressClosed {
		return
	}
	g.waitMu.Lock()
	if g.state.Load() == routingEpochIngressClosed {
		g.waitMu.Unlock()
		return
	}
	if g.drained == nil {
		g.drained = make(chan struct{})
	}
	drained := g.drained
	g.waitMu.Unlock()
	<-drained
}

// LinkRoutingEpochPeer links two generations that share one BPF object during
// a staged reload. The association is intentionally pairwise and temporary:
// routing slots are reused by later reloads, so slot ownership remains local
// to the linked pair even though published execution owners are process-wide.
func (c *ControlPlane) LinkRoutingEpochPeer(peer *ControlPlane) error {
	if c == nil || peer == nil || c == peer {
		return fmt.Errorf("routing epoch peer must be a distinct control plane")
	}
	if c.core == nil || peer.core == nil {
		return fmt.Errorf("routing epoch peer requires initialized control planes")
	}
	cSlot := c.core.RoutingEpochSlot()
	peerSlot := peer.core.RoutingEpochSlot()
	if cSlot == peerSlot {
		return fmt.Errorf("routing epoch peers use the same slot %d", cSlot)
	}
	cBpf, peerBpf := c.core.PeekBpf(), peer.core.PeekBpf()
	if cBpf != nil && peerBpf != nil && cBpf != peerBpf {
		return fmt.Errorf("routing epoch peers do not share BPF objects")
	}
	cGeneration := uint16(c.core.datapathGeneration.Load())
	peerGeneration := uint16(peer.core.datapathGeneration.Load())
	if cBpf != nil && cBpf == peerBpf {
		if registered := bpfDatapathGeneration(cBpf); registered != 0 {
			if cGeneration != 0 && cGeneration != registered {
				return fmt.Errorf("routing epoch owner generation %d does not match shared BPF generation %d", cGeneration, registered)
			}
			if peerGeneration != 0 && peerGeneration != registered {
				return fmt.Errorf("routing epoch peer generation %d does not match shared BPF generation %d", peerGeneration, registered)
			}
			cGeneration = registered
			peerGeneration = registered
		}
	}
	if cGeneration != 0 && peerGeneration != 0 && cGeneration != peerGeneration {
		return fmt.Errorf("routing epoch peers use different datapath generations %d and %d", cGeneration, peerGeneration)
	}
	sharedGeneration := cGeneration
	if sharedGeneration == 0 {
		sharedGeneration = peerGeneration
	}
	if sharedGeneration != 0 {
		c.core.datapathGeneration.Store(uint32(sharedGeneration))
		peer.core.datapathGeneration.Store(uint32(sharedGeneration))
	}

	routingEpochPeerLinkMu.Lock()
	defer routingEpochPeerLinkMu.Unlock()

	c.routingEpochPeerMu.Lock()
	defer c.routingEpochPeerMu.Unlock()
	peer.routingEpochPeerMu.Lock()
	defer peer.routingEpochPeerMu.Unlock()
	if c.routingEpochPeer != nil && c.routingEpochPeer != peer {
		return fmt.Errorf("control plane already has a routing epoch peer")
	}
	if peer.routingEpochPeer != nil && peer.routingEpochPeer != c {
		return fmt.Errorf("routing epoch peer already belongs to another control plane")
	}
	c.routingEpochPeer = peer
	peer.routingEpochPeer = c
	c.routingEpochSlot.Store(cSlot)
	c.routingEpochSlotKnown.Store(true)
	peer.routingEpochSlot.Store(peerSlot)
	peer.routingEpochSlotKnown.Store(true)
	return nil
}

// UnlinkRoutingEpochPeer removes a staged reload association. Passing nil
// clears the current link regardless of its peer, which is useful while a
// generation is closing.
func (c *ControlPlane) UnlinkRoutingEpochPeer(peer *ControlPlane) {
	if c == nil {
		return
	}
	routingEpochPeerLinkMu.Lock()
	defer routingEpochPeerLinkMu.Unlock()

	c.routingEpochPeerMu.Lock()
	current := c.routingEpochPeer
	if current == nil || (peer != nil && current != peer) {
		c.routingEpochPeerMu.Unlock()
		return
	}
	c.routingEpochPeer = nil
	c.routingEpochPeerMu.Unlock()

	current.routingEpochPeerMu.Lock()
	if current.routingEpochPeer == c {
		current.routingEpochPeer = nil
	}
	current.routingEpochPeerMu.Unlock()
}

func (c *ControlPlane) routingEpochSlotMatches(slot uint32) bool {
	if c == nil {
		return false
	}
	if c.routingEpochSlotKnown.Load() {
		return c.routingEpochSlot.Load() == slot
	}
	return c.core != nil && c.core.RoutingEpochSlot() == slot
}

func (c *ControlPlane) routingEpochExecutionMatches(result *bpfRoutingResult) bool {
	if c == nil {
		return false
	}
	if result == nil {
		return true
	}
	resultGeneration := result.DatapathGeneration
	ownerGeneration := uint16(0)
	if c.core != nil {
		ownerGeneration = uint16(c.core.datapathGeneration.Load())
	}
	if resultGeneration != 0 && resultGeneration != ownerGeneration {
		return false
	}
	slot, known := decodeBpfRoutingEpochSlot(result.RoutingEpochSlot)
	return !known || c.routingEpochSlotMatches(slot)
}

func routingEpochOwnerUnavailableError(result *bpfRoutingResult) error {
	if result == nil {
		return errRoutingEpochOwnerUnavailable
	}
	slot, known := decodeBpfRoutingEpochSlot(result.RoutingEpochSlot)
	if !known {
		return fmt.Errorf("%w for unknown slot in datapath generation %d", errRoutingEpochOwnerUnavailable, result.DatapathGeneration)
	}
	return fmt.Errorf("%w for slot %d in datapath generation %d", errRoutingEpochOwnerUnavailable, slot, result.DatapathGeneration)
}

func publishedRoutingEpochExecutionOwner(source *ControlPlane, result *bpfRoutingResult) *ControlPlane {
	activeControlPlanePublication.mu.RLock()
	defer activeControlPlanePublication.mu.RUnlock()

	owner := activeControlPlanePublication.plane.Load()
	if owner != nil && owner != source && owner.acceptsRoutingEpochExecution() && owner.routingEpochExecutionMatches(result) {
		return owner
	}
	for candidate, publication := range activeControlPlanePublication.owners {
		if publication == 0 {
			continue
		}
		if candidate == nil || candidate == source || candidate == owner {
			continue
		}
		if candidate.acceptsRoutingEpochExecution() && candidate.routingEpochExecutionMatches(result) {
			return candidate
		}
	}
	return nil
}

func (c *ControlPlane) routingEpochExecutionOwner(result *bpfRoutingResult) (*ControlPlane, error) {
	if c == nil {
		return nil, errRoutingEpochOwnerUnavailable
	}
	if c.routingEpochExecutionMatches(result) {
		return c, nil
	}

	c.routingEpochPeerMu.RLock()
	peer := c.routingEpochPeer
	c.routingEpochPeerMu.RUnlock()
	if peer != nil && peer.routingEpochExecutionMatches(result) {
		return peer, nil
	}
	if published := publishedRoutingEpochExecutionOwner(c, result); published != nil {
		return published, nil
	}
	return nil, routingEpochOwnerUnavailableError(result)
}

// acquireRoutingEpochExecutionOwner resolves an attributed BPF result and,
// when it targets a staged peer, acquires that peer's execution lease before
// releasing the peer-link lock. StopRoutingEpochExecution closes admission by
// storing its gate flag; the ticket double-check below keeps a selected peer
// from beginning work after retirement has committed to closing it.
func (c *ControlPlane) acquireRoutingEpochExecutionOwner(result *bpfRoutingResult) (*ControlPlane, func(), error) {
	if c == nil {
		return nil, nil, errRoutingEpochOwnerUnavailable
	}
	if c.routingEpochExecutionMatches(result) {
		return c, nil, nil
	}

	routingEpochPeerLinkMu.Lock()
	defer routingEpochPeerLinkMu.Unlock()
	c.routingEpochPeerMu.RLock()
	peer := c.routingEpochPeer
	c.routingEpochPeerMu.RUnlock()
	if peer == nil || !peer.routingEpochExecutionMatches(result) {
		peer = publishedRoutingEpochExecutionOwner(c, result)
		if peer == nil {
			return nil, nil, routingEpochOwnerUnavailableError(result)
		}
	}

	release, ok := peer.acquireDrainTicketIfAdmitting(func() bool {
		return peer.acceptsRoutingEpochExecution() && peer.routingEpochExecutionMatches(result)
	})
	if !ok {
		return nil, nil, routingEpochOwnerUnavailableError(result)
	}
	return peer, release, nil
}

func (c *ControlPlane) ownsActiveRoutingEpoch() bool {
	if c == nil || c.core == nil || !c.core.routingEpochEnabled() {
		return true
	}
	active, err := c.core.readActiveRoutingEpochSlot()
	return err == nil && active == c.core.RoutingEpochSlot()
}

// acceptsRoutingEpochExecution reports whether this generation still admits
// new connection work. It is called without any lock; callers that need
// admission commit pair it with acquireDrainTicketIfAdmitting's recheck.
func (c *ControlPlane) acceptsRoutingEpochExecution() bool {
	return c != nil && !c.rejectNewConnections.Load() && !c.routingEpochExecutionClosed.Load()
}

// acquireDrainTicketIfAdmitting implements the admission protocol from the
// incomingConnectionOwnershipMu documentation: pre-check, ticket add,
// recheck. A failed recheck releases the just-added ticket so a closer can
// never observe an orphaned count.
func (c *ControlPlane) acquireDrainTicketIfAdmitting(recheck func() bool) (func(), bool) {
	if !c.acceptsRoutingEpochExecution() {
		return nil, false
	}
	release := c.acquireDrainTicket()
	if !recheck() {
		release()
		return nil, false
	}
	return release, true
}

func (c *ControlPlane) acquireRoutingEpochExecutionLeaseFor(result *bpfRoutingResult) (func(), bool) {
	return c.acquireDrainTicketIfAdmitting(func() bool {
		return c.acceptsRoutingEpochExecution() && c.routingEpochExecutionMatches(result)
	})
}

func (c *ControlPlane) acquireIncomingConnectionLease(conn net.Conn) (*incomingConnectionLease, bool) {
	if c == nil || conn == nil {
		return nil, false
	}
	release, ok := c.acquireDrainTicketIfAdmitting(c.acceptsRoutingEpochExecution)
	if !ok {
		_ = conn.Close()
		return nil, false
	}
	lease := &incomingConnectionLease{
		conn:         conn,
		owner:        c,
		drainRelease: release,
	}
	c.inConnections.Store(conn, lease)
	return lease, true
}

func (l *incomingConnectionLease) storePendingEgress(egress netproxy.Conn) {
	if l == nil || egress == nil {
		return
	}
	l.egress.Store(&egress)
}

func (l *incomingConnectionLease) takePendingEgress() netproxy.Conn {
	if l == nil {
		return nil
	}
	ptr := l.egress.Swap(nil)
	if ptr == nil || *ptr == nil {
		return nil
	}
	return *ptr
}

func (l *incomingConnectionLease) transferRoutingEpoch(owner *ControlPlane, result *bpfRoutingResult) bool {
	if l == nil || owner == nil || owner == l.owner {
		return l != nil && owner == l.owner && owner.routingEpochExecutionMatches(result)
	}
	// The swap is optimistic and rollback-safe: both gates are monotone
	// (closed stays closed within a generation), so a failed recheck means
	// the move must not stand and one rollback converges to rejection.
	if l.owner == nil ||
		!l.owner.acceptsRoutingEpochExecution() ||
		!owner.acceptsRoutingEpochExecution() ||
		!owner.routingEpochExecutionMatches(result) {
		return false
	}
	previous := l.owner
	previousRelease := l.drainRelease
	newRelease := owner.acquireDrainTicket()
	owner.inConnections.Store(l.conn, l)
	previous.inConnections.Delete(l.conn)
	l.owner = owner
	l.drainRelease = newRelease

	if !previous.acceptsRoutingEpochExecution() || !owner.acceptsRoutingEpochExecution() {
		// A generation closed underneath the move: undo it atomically from
		// this lease's point of view (its fields are private to the single
		// handler goroutine driving the lease).
		l.owner = previous
		l.drainRelease = previousRelease
		newRelease()
		previous.inConnections.Store(l.conn, l)
		owner.inConnections.Delete(l.conn)
		return false
	}

	if previousRelease != nil {
		previousRelease()
	}
	return true
}

func (l *incomingConnectionLease) release() {
	if l == nil {
		return
	}
	drainRelease := l.releaseLocked()
	if drainRelease != nil {
		drainRelease()
	}
}

// releaseLocked detaches the generation-owned ingress. It needs no lock: the
// lease fields belong to the connection's single handler goroutine, and its
// only shared effects (the inConnections entry and one drain ticket) are
// internally synchronized.
func (l *incomingConnectionLease) releaseLocked() (drainRelease func()) {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if egress := l.takePendingEgress(); egress != nil {
			_ = egress.Close()
		}
		owner := l.owner
		drainRelease = l.drainRelease
		l.owner = nil
		l.drainRelease = nil
		if owner != nil && l.conn != nil {
			owner.inConnections.Delete(l.conn)
		}
	})
	return drainRelease
}

func (c *ControlPlane) closeRoutingEpochExecution() {
	if c == nil {
		return
	}
	incomingConnectionOwnershipMu.Lock()
	c.routingEpochExecutionClosed.Store(true)
	incomingConnectionOwnershipMu.Unlock()
	c.unregisterRoutingEpochExecutionOwner()
}

// StopRoutingEpochExecution prevents further staged-peer dispatch and waits
// for work that acquired an execution lease before the gate closed. It is used
// immediately before a retired generation is canceled and closed.
func (c *ControlPlane) StopRoutingEpochExecution() {
	c.StopRoutingEpochExecutionWithTimeout(0)
}

// StopRoutingEpochExecutionWithTimeout seals admission and waits for drain
// tickets. A positive timeout bounds the IdleCh wait so a stuck ticket cannot
// pin retirement forever; timeout still proceeds to cancel the generation.
func (c *ControlPlane) StopRoutingEpochExecutionWithTimeout(timeout time.Duration) {
	if c == nil {
		return
	}
	c.closeRoutingEpochExecution()
	c.udpIngressAdmission.closeAndWait()
	if c.drainTracker == nil {
		return
	}
	idle := c.drainTracker.IdleCh()
	if timeout <= 0 {
		<-idle
		return
	}
	timer := time.NewTimer(timeout)
	select {
	case <-idle:
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	case <-timer.C:
		if c.log != nil {
			c.log.Warnln("routing epoch drain wait timed out; continuing retirement")
		}
	}
}

func (c *ControlPlane) takeIncomingConnectionsForAbort() ([]net.Conn, []netproxy.Conn, []error) {
	if c == nil {
		return nil, nil, nil
	}
	incomingConnectionOwnershipMu.Lock()
	c.routingEpochExecutionClosed.Store(true)
	c.rejectNewConnections.Store(true)
	var connections []net.Conn
	var flows []netproxy.Conn
	var errs []error
	c.inConnections.Range(func(key, value any) bool {
		conn, ok := key.(net.Conn)
		if ok {
			connections = append(connections, conn)
			switch stored := value.(type) {
			case *incomingConnectionLease:
				if egress := stored.takePendingEgress(); egress != nil {
					flows = append(flows, egress)
				}
			case netproxy.Conn:
				if stored != nil {
					flows = append(flows, stored)
				}
			}
		} else {
			errs = append(errs, fmt.Errorf("unexpected type %T in inConnections", key))
		}
		c.inConnections.Delete(key)
		return true
	})
	incomingConnectionOwnershipMu.Unlock()
	c.unregisterRoutingEpochExecutionOwner()
	return connections, flows, errs
}
