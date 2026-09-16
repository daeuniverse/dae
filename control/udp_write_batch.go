/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	// udpWriteBatchMaxItems bounds the explicitly enabled experimental batch.
	// Direct-UDP sendmmsg showed no end-to-end throughput gain in real-kernel
	// validation. Stream transports are a different story: anytls UDP-over-TLS
	// measured socket writes 107,934 -> 11,141 (-90%) and daemon CPU -22.5%
	// at 1Gbps/1200B (1.04M datagrams / 10s) with zero loss, because each
	// per-datagram write otherwise costs its own TLS record burst + flush.
	// Batching stays opt-in (1ms tail-latency budget, see udpWriteBatchWindow);
	// latency-sensitive UDP workloads should keep it off.
	udpWriteBatchMaxItems = 32
	// udpWriteBatchWindow is the opt-in batch's hard tail-latency budget.
	udpWriteBatchWindow = time.Millisecond
	// udpWriteBatchItemSize sizes the batch backing buffer (32 x MTU).
	udpWriteBatchItemSize = consts.EthernetMtu
)

// errUDPWriteBatchOversized is returned by Append when a single datagram is
// larger than the whole batch backing buffer; the caller falls back to a
// direct synchronous write for that datagram.
var errUDPWriteBatchOversized = stderrors.New("udp write batch: datagram too large")

const udpWriteBatchOptInEnv = "DAE_ENABLE_UDP_WRITE_BATCH"

func udpWriteBatchOptedIn() bool { return os.Getenv(udpWriteBatchOptInEnv) == "1" }

// udpWriteBatchAggregator accumulates datagrams for one UdpEndpoint and
// flushes them through the transport's batched writer (sendmmsg on direct
// UDP, per the netproxy.PacketBatchWriter extension). Flush triggers: batch
// full (udpWriteBatchMaxItems) or udpWriteBatchWindow timer, whichever comes
// first. Write errors are routed through the endpoint's existing retirement
// policy asynchronously, after releasing the endpoint-local mutex.
//
// Per-flow ordering is preserved: the per-flow convoy task pool funnels each
// flow's WriteTo calls through a single producer, Append preserves order, and
// flush drains in order.
type udpWriteBatchAggregator struct {
	ue *UdpEndpoint

	mu    sync.Mutex
	items []netproxy.BatchItem
	buf   []byte
	used  int
	timer *time.Timer

	closed bool // guarded by mu

	// unflushedFirst is true while the first datagram of this endpoint is
	// queued but not yet flushed. Health-invalidation must treat that as
	// an in-flight first write, not an unused session.
	unflushedFirst bool
}

func newUDPWriteBatchAggregator(ue *UdpEndpoint) *udpWriteBatchAggregator {
	return &udpWriteBatchAggregator{ue: ue}
}

// Append copies data into the batch backing buffer and returns immediately.
// The batch is flushed when it reaches udpWriteBatchMaxItems or after
// udpWriteBatchWindow. Returns errUDPWriteBatchOversized for datagrams that
// do not fit the backing buffer (caller falls back to a direct write); other
// errors mean the aggregator is closed.
func (a *udpWriteBatchAggregator) Append(data []byte, addr string) error {
	for {
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			return net.ErrClosed
		}
		if len(a.items) >= udpWriteBatchMaxItems || (a.used+len(data) > len(a.buf) && len(a.buf) > 0) {
			a.mu.Unlock()
			a.flush()
			continue
		}
		if a.buf == nil {
			a.buf = make([]byte, udpWriteBatchMaxItems*udpWriteBatchItemSize)
		}
		if a.used+len(data) > len(a.buf) {
			a.mu.Unlock()
			return errUDPWriteBatchOversized
		}
		copy(a.buf[a.used:], data)
		a.items = append(a.items, netproxy.BatchItem{
			Data: a.buf[a.used : a.used+len(data)],
			Addr: addr,
		})
		a.used += len(data)
		if len(a.items) == 1 {
			a.timer = time.AfterFunc(udpWriteBatchWindow, a.flush)
		}
		if a.ue != nil && !a.ue.hasSent.Load() && !a.ue.hasReply.Load() {
			a.unflushedFirst = true
		}
		a.mu.Unlock()
		return nil
	}
}

func (a *udpWriteBatchAggregator) hasUnflushedFirst() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	pending := a.unflushedFirst && !a.closed
	a.mu.Unlock()
	return pending
}

// flush drains the current batch through the batched writer. It is safe to
// call from the timer callback, from Append when the batch is full, and from
// Close. The aggregator mutex is held across the actual transport write:
// BatchItem.Data must remain valid until WriteBatch returns (netproxy
// contract), and the shared backing buffer may not be reused by a concurrent
// Append while a batch is in flight. Write-error classification is
// deliberately deferred until after the unlock — handleWriteError can retire
// the endpoint, whose Close re-enters this aggregator via writeBatch.Close,
// and Go's mutex is not reentrant.
//
// Holding mu across the syscall is a deliberate final design, not an
// oversight. The contention domain is one endpoint only: dae's per-flow FIFO
// ingress (UdpTaskPool) funnels each endpoint's writes through its own convoy
// sender, so there is a single producer goroutine in the steady state, and
// the underlying socket serializes datagrams in-kernel anyway. Slot-swap or
// copy-out variants would relocate that same serialization into an atomic
// handshake (or pay an extra memcpy per packet) while adding tail latency for
// cross-batch reordering — strictly worse here. Revisit only if a future
// consumer feeds one aggregator from many goroutines.
func (a *udpWriteBatchAggregator) flush() {
	a.mu.Lock()
	// Reuse the items backing array instead of dropping it for GC: the next
	// Append runs under this same mutex only after the transport write below
	// completes, so nothing can observe half-reset entries. This avoids
	// reallocating a 32-item slice on every flush window per batched endpoint.
	var items []netproxy.BatchItem
	if len(a.items) > 0 {
		items = a.items
		a.items = a.items[:0]
	}
	a.used = 0
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	if len(items) == 0 {
		a.unflushedFirst = false
		a.mu.Unlock()
		return
	}
	a.unflushedFirst = false
	a.ue.armWriteDeadline(time.Now())
	bw, ok := a.ue.conn.(netproxy.PacketBatchWriter)
	if !ok {
		// The aggregator is only installed on batched transports; this is a
		// defensive fallback that preserves ordering via synchronous writes.
		// It also runs under the mutex for the same buffer-lifetime reason.
		var fallbackErr error
		sentDatagrams := 0
		sentBytes := 0
		for _, it := range items {
			if _, err := a.ue.conn.WriteTo(it.Data, it.Addr); err != nil {
				fallbackErr = err
				break
			}
			sentDatagrams++
			sentBytes += len(it.Data)
		}
		a.mu.Unlock()
		a.reportFlushed(sentDatagrams, sentBytes)
		if fallbackErr != nil {
			a.reportFlushFailure(fallbackErr)
			return
		}
		return
	}
	n, err := bw.WriteBatch(items)
	// Sum the accepted prefix while the mutex is still held: Append reuses the
	// items backing array, so reading items[i].Data after the unlock would race
	// with the next Append (the -race gate catches exactly that).
	sentBytes := 0
	for i := 0; i < n && i < len(items); i++ {
		sentBytes += len(items[i].Data)
	}
	a.mu.Unlock()

	a.reportFlushed(n, sentBytes)
	if err != nil {
		a.reportFlushFailure(err)
		return
	}
	if n < len(items) {
		a.reportFlushFailure(fmt.Errorf("%w: batched write sent %d/%d datagrams", io.ErrShortWrite, n, len(items)))
	}
}

// reportFlushed accounts the datagrams the transport actually accepted. It is
// the only place that knows the real count for a batched endpoint: the caller
// observes a successful Append, not a send. Non-batched endpoints keep the
// caller-side accounting and have no reporter installed.
func (a *udpWriteBatchAggregator) reportFlushed(datagrams, bytes int) {
	if a.ue == nil {
		return
	}
	if datagrams > 0 {
		a.ue.hasSent.Store(true)
		a.ue.lastSendNano.Store(time.Now().UnixNano())
	}
	if reporter := a.ue.sentReporter; reporter != nil && datagrams > 0 {
		reporter(a.ue, datagrams, bytes)
	}
}

// reportFlushFailure makes a failed asynchronous flush visible. The synchronous
// WriteTo path returns its error to a caller that logs, penalizes and retires;
// a flush runs on the aggregator's timer/Append stack where the endpoint's
// tolerated-error policy would otherwise swallow it (no report, no count, no
// log) while the batch's datagrams were already counted as uploaded.
func (a *udpWriteBatchAggregator) reportFlushFailure(err error) {
	if a.ue == nil || err == nil {
		return
	}
	if werr := a.ue.handleWriteError(err); werr != nil {
		a.ue.reportBatchFlushFailure(werr)
	}
}

// reportBatchFlushFailure reports one failed batched flush to the health plane
// and logs it (counted, first / 2^n-th occurrence) so a broken batched
// transport cannot stay invisible.
func (ue *UdpEndpoint) reportBatchFlushFailure(err error) {
	if ue == nil || err == nil {
		return
	}
	count := ue.batchFlushFailureCount.Add(1)
	if lifecycle, ok := newUdpSessionLifecycleContext(ue, ""); ok {
		lifecycle.reportUnavailable(fmt.Errorf("udp batch flush failed: %w", err))
	}
	if ue.log != nil && ue.log.IsLevelEnabled(logrus.WarnLevel) && count&(count-1) == 0 {
		ue.log.WithError(err).WithFields(logrus.Fields{
			"failures": count,
			"laddr":    ue.lAddr.String(),
			"proxy":    ue.DialTarget,
		}).Warn("[UdpEndpoint] batched write flush failed")
	}
}

// Close prevents future appends, waits for any active write, and flushes the
// remaining batch before the endpoint closes its transport.
func (a *udpWriteBatchAggregator) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	a.unflushedFirst = false
	timer := a.timer
	a.timer = nil
	a.mu.Unlock()
	if timer != nil {
		// AfterFunc timers have a nil C. Stop(false) means the callback has
		// started; flush and Close synchronize through a.mu instead.
		timer.Stop()
	}
	a.flush()
}
