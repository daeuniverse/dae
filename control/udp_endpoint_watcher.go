/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"io"
	"net/netip"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/sirupsen/logrus"
)

// startTransportReceiver registers the endpoint's reply handler with a
// transport-owned packet receiver ("push mode"). The transport then delivers
// upstream packets through handleReceivedPacket on its existing reader (QUIC
// family) or a shared epoll loop (direct), instead of this endpoint owning a
// blocking ReadFrom goroutine. Returns false when the conn does not support
// registration, leaving the caller to start a ReadFrom loop.
func (ue *UdpEndpoint) startTransportReceiver() bool {
	if ue == nil || ue.conn == nil {
		return false
	}
	receiver, ok := ue.conn.(netproxy.PacketReceiver)
	if !ok {
		return false
	}
	// Create the reply queue before registering. Some transports (hysteria2)
	// drain datagrams queued between session creation and registration
	// synchronously inside RegisterPacketReceiver; those deliveries must
	// already see a live queue.
	ue.replyQueueMu.Lock()
	ue.replyQueueCh = make(chan *udpEndpointReply, udpEndpointReplyQueueSize)
	ue.replyQueueDone = make(chan struct{})
	ue.replyQueueStop = make(chan struct{})
	ch, done, stopSignal := ue.replyQueueCh, ue.replyQueueDone, ue.replyQueueStop
	ue.replyQueueMu.Unlock()
	go ue.replySender(ch, stopSignal, done, ue.markRetiredFromReceiver)

	stop, registered := receiver.RegisterPacketReceiver(ue.handleReceivedPacket)
	if !registered {
		ue.stopTransportReceiver()
		return false
	}
	ue.receiverMu.Lock()
	ue.receiverStop = stop
	ue.receiverMu.Unlock()
	// hysteria2 drains queued datagrams inside RegisterPacketReceiver. A
	// hard error there calls markRetiredFromReceiver and stopPacketReceiver
	// before this assignment, so the first unregister is a no-op. Re-run
	// now that stop is visible; Close is idempotent via closeOnce.
	if ue.dead.Load() {
		ue.stopPacketReceiver()
	}

	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.Debug("[UdpEndpoint] Using transport-owned packet receiver")
	}
	return true
}

// stopPacketReceiver unregisters the transport receiver. Safe to call from
// inside handleReceivedPacket and any number of times.
func (ue *UdpEndpoint) stopPacketReceiver() {
	if ue == nil {
		return
	}
	ue.receiverMu.Lock()
	stop := ue.receiverStop
	ue.receiverStop = nil
	ue.receiverMu.Unlock()
	if stop != nil {
		stop()
	}
}

// stopTransportReceiver tears down push mode: unregister first so no further
// deliveries race the queue close, then close the bounded queue and wait for
// the replySender goroutine to drain what it already accepted. ReadFrom-loop
// endpoints have no shared queue; their loop closes its own locals.
func (ue *UdpEndpoint) stopTransportReceiver() {
	ue.stopPacketReceiver()
	ue.replyQueueMu.Lock()
	ch := ue.replyQueueCh
	done := ue.replyQueueDone
	if ch != nil && !ue.replyQueueClosed {
		ue.replyQueueClosed = true
		ue.replyQueueCh = nil
	} else {
		ch = nil
	}
	ue.replyQueueMu.Unlock()
	if ch == nil {
		return
	}
	close(ch)
	if done != nil {
		<-done
	}
}

// enqueueReceivedReply hands one transport-owned packet to the reply sender.
// A full queue drops only this packet (after releasing it) and keeps the
// receiver registered; a closed queue rejects the packet so the caller can
// unregister.
func (ue *UdpEndpoint) enqueueReceivedReply(data []byte, from netip.AddrPort, release func()) bool {
	ue.replyQueueMu.Lock()
	ch := ue.replyQueueCh
	if ch == nil || ue.replyQueueClosed {
		ue.replyQueueMu.Unlock()
		if release != nil {
			release()
		}
		return false
	}
	queued := takeUdpEndpointReply(pool.PB(data), from)
	queued.release = release
	select {
	case ch <- queued:
		ue.replyQueueMu.Unlock()
		return true
	default:
		ue.replyQueueMu.Unlock()
		recycleUdpEndpointReply(queued, false)
		return true
	}
}

// applyUpstreamReadErrorPolicy runs the upstream error policy shared by the
// push-mode receiver and the ReadFrom loop. Soft errors (replay/auth) are
// absorbed under a dynamic threshold: 3 before any valid reply to fail fast on
// wrong credentials, 100 afterwards when they are mostly network noise. Hard
// errors retire the endpoint via the mode-specific retire callback and
// invalidate the cached proxy IP on connection-refused. Returns true when the
// error is fatal and delivery must stop.
func (ue *UdpEndpoint) applyUpstreamReadErrorPolicy(err error, retire func()) bool {
	if stderrors.Is(err, io.ErrShortBuffer) {
		return false
	}
	// A peer-supplied address that could not be resolved in time is a datagram
	// we cannot attribute, not a broken session. The outbound reader has already
	// consumed the frame, so dropping this one datagram keeps the stream aligned
	// and keeps the session: under full-cone NAT this endpoint carries every
	// destination of the client, and no single unresolvable source address may
	// take all of them down.
	if stderrors.Is(err, protocol.ErrDomainResolution) {
		if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
			ue.log.WithFields(logrus.Fields{
				"lAddr":      ue.lAddr.String(),
				"dialer":     ue.Dialer.Property().Name,
				"proxy_addr": ue.DialTarget,
				"sniffed":    ue.SniffedDomain,
			}).WithError(err).Debug("UdpEndpoint dropped a datagram whose source address did not resolve")
		}
		return false
	}
	if errors.IsReplayAttackError(err) || errors.IsAuthError(err) {
		threshold := 3
		if ue.hasReply.Load() {
			threshold = 100
		}
		if ue.softErrorCount < threshold {
			ue.softErrorCount++
			if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) && ue.softErrorCount%10 == 1 {
				ue.log.WithFields(logrus.Fields{
					"lAddr":      ue.lAddr.String(),
					"dialer":     ue.Dialer.Property().Name,
					"proxy_addr": ue.DialTarget,
					"sniffed":    ue.SniffedDomain,
				}).WithError(err).Debugf("UdpEndpoint soft error (hit %d/%d, ignored)", ue.softErrorCount, threshold)
			}
			return false
		}
	}
	if ue.shouldRetireOnReadError(err) {
		retire()
		if ue.isConnectionRefused(err) {
			ue.handleProxyServerFailure()
		}
	}
	return true
}

// handleReceivedPacket is the push-mode delivery callback. Some transports
// deliver concurrently from multiple stream readers, so endpoint probing and
// error counters stay serialized exactly as in ReadFrom mode.
func (ue *UdpEndpoint) handleReceivedPacket(packet *netproxy.ReceivedPacket) bool {
	if packet == nil {
		return false
	}

	ue.receiveMu.Lock()
	defer ue.receiveMu.Unlock()

	if ue.dead.Load() {
		packet.Release()
		ue.stopPacketReceiver()
		return false
	}

	if packet.Err != nil {
		if ue.applyUpstreamReadErrorPolicy(packet.Err, ue.markRetiredFromReceiver) {
			ue.logEndpointExit(packet.Err, "packet receiver")
			packet.Release()
			ue.stopPacketReceiver()
			return false
		}
		packet.Release()
		return true
	}

	ue.softErrorCount = 0
	from := packet.From
	if !ue.hasReply.Load() && !ue.acceptsInitialReplyFrom(from) {
		packet.Release()
		return true
	}
	if lifecycle, ok := newUdpSessionLifecycleContext(ue, consts.IpVersionFromAddr(from.Addr())); ok {
		lifecycle.handleReply(ue, time.Now().UnixNano())
	} else {
		ue.markReplied(time.Now().UnixNano())
	}

	if !ue.enqueueReceivedReply(packet.Data, from, packet.Release) {
		ue.stopPacketReceiver()
		return false
	}
	return true
}

func (ue *UdpEndpoint) startReadLoop() {
	if ue.log != nil && ue.log.IsLevelEnabled(logrus.DebugLevel) {
		ue.log.WithFields(logrus.Fields{
			"lAddr":      ue.lAddr.String(),
			"dialer":     ue.Dialer.Property().Name,
			"proxy_addr": ue.DialTarget,
		}).Debug("[UdpEndpoint] Read loop started")
	}

	// Async reply dispatch keeps slow sendPkt operations off the blocking read
	// loop: the bounded replyCh channel decouples the sender goroutine from
	// the read loop while preserving per-endpoint FIFO.
	var replyCh chan *udpEndpointReply
	var senderStop chan struct{}
	var senderDone chan struct{}

	buf := pool.GetFullCap(consts.EthernetMtu)
	defer func() {
		// The read loop owns exactly one buffer at a time: buf is replaced only
		// after its ownership has been transferred to a reply consumer, so this
		// is the single release point for whichever buffer is still held.
		putUdpEndpointReplyData(buf)
		if replyCh != nil {
			close(replyCh)
			<-senderDone
		}
	}()
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			if ue.applyUpstreamReadErrorPolicy(err, ue.retire) {
				ue.logEndpointExit(err, "read loop")
				break
			}
			continue
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
		// Dispatch reply asynchronously by transferring ownership of the current
		// read buffer to the sender goroutine. This removes one per-packet copy
		// from the hot reply path while keeping the same backpressure semantics.
		reply := udpEndpointReply{data: buf[:n], from: from}
		if replyCh == nil {
			replyCh = make(chan *udpEndpointReply, udpEndpointReplyQueueSize)
			senderStop = make(chan struct{})
			senderDone = make(chan struct{})
			go ue.replySender(replyCh, senderStop, senderDone, ue.retire)
		}
		queued := takeUdpEndpointReply(reply.data, reply.from)
		select {
		case replyCh <- queued:
			buf = pool.GetFullCap(consts.EthernetMtu)
		case <-senderStop:
			recycleUdpEndpointReply(queued, false)
			return
		}
	}
}

func endpointTransportDoneChannel(ue *UdpEndpoint) <-chan struct{} {
	if ue == nil {
		return nil
	}
	if value := ue.transportDone.Load(); value != nil {
		return value.(<-chan struct{})
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
	if !ue.transportDone.CompareAndSwap(nil, transportDone) {
		transportDone = ue.transportDone.Load().(<-chan struct{})
	}

	// Reset holds the write side of this lock while stopping all existing
	// transport watchers. A registration that starts after Reset has completed
	// therefore cannot be stranded in an index that was already drained.
	p.transportWatchMu.RLock()
	defer p.transportWatchMu.RUnlock()
	for {
		actual, _ := p.transportIndex.LoadOrStore(transportDone, &udpEndpointTransportBucket{
			endpoints: make(map[*UdpEndpoint]struct{}),
			stop:      make(chan struct{}),
			done:      make(chan struct{}),
		})
		bucket := actual.(*udpEndpointTransportBucket)
		bucket.mu.Lock()
		if bucket.closed {
			bucket.mu.Unlock()
			p.transportIndex.CompareAndDelete(transportDone, bucket)
			continue
		}
		bucket.endpoints[ue] = struct{}{}
		bucket.mu.Unlock()

		bucket.watchOnce.Do(func() {
			go p.watchTransportLifecycle(transportDone, bucket)
		})
		return
	}
}

func (p *UdpEndpointPool) watchTransportLifecycle(transportDone <-chan struct{}, bucket *udpEndpointTransportBucket) {
	defer close(bucket.done)
	select {
	case <-transportDone:
	case <-bucket.stop:
		return
	}
	p.transportIndex.CompareAndDelete(transportDone, bucket)

	bucket.mu.Lock()
	if bucket.closed {
		bucket.mu.Unlock()
		return
	}
	bucket.closed = true
	endpoints := make([]*UdpEndpoint, 0, len(bucket.endpoints))
	for ue := range bucket.endpoints {
		endpoints = append(endpoints, ue)
	}
	bucket.endpoints = make(map[*UdpEndpoint]struct{})
	bucket.mu.Unlock()

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

func (bucket *udpEndpointTransportBucket) stopWatching() {
	if bucket == nil {
		return
	}
	bucket.stopOnce.Do(func() { close(bucket.stop) })
}

// stopTransportWatchers cancels every transport lifecycle watcher owned by the
// pool and waits for the watcher goroutines to exit. It is called after pooled
// endpoints have been closed, so no endpoint remains eligible for retirement
// from a reset generation.
func (p *UdpEndpointPool) stopTransportWatchers() {
	if p == nil {
		return
	}
	p.transportWatchMu.Lock()
	defer p.transportWatchMu.Unlock()

	var done []<-chan struct{}
	p.transportIndex.Range(func(key, value any) bool {
		bucket, ok := value.(*udpEndpointTransportBucket)
		if !ok || bucket == nil {
			p.transportIndex.CompareAndDelete(key, value)
			return true
		}
		bucket.mu.Lock()
		bucket.closed = true
		bucket.endpoints = make(map[*UdpEndpoint]struct{})
		bucket.mu.Unlock()
		p.transportIndex.CompareAndDelete(key, bucket)
		bucket.stopWatching()
		done = append(done, bucket.done)
		return true
	})
	for _, wait := range done {
		<-wait
	}
}
