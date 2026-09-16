/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// UdpTaskQueueLength is the buffer size for each per-flow UDP task queue.
	// QUIC sniff needs at most 3-5 ordered Initial packets; 128 is deliberately
	// chosen as a safe ceiling that is still 25× larger than the typical sniff
	// window but reduces per-flow channel allocation by 32× vs the old 4096.
	UdpTaskQueueLength = 128
	// UdpTaskQueueMaxOverflow keeps a hot flow bounded without blocking other
	// flows. Once both tiers are full, new UDP work is dropped explicitly.
	UdpTaskQueueMaxOverflow = 128
)

var (
	// UdpTaskPoolAgingTime is the idle timeout before a queue is garbage collected.
	// Active flows continuously reset the timer with each packet.
	// 100ms is sufficient for burst traffic while enabling fast memory reclamation.
	UdpTaskPoolAgingTime = 100 * time.Millisecond
)

// UdpTask is the unit of per-flow UDP work. It used to be a plain func
// closure; it is an interface so hot paths can submit pooled owned
// structures (see udpIngressTask) instead of allocating an escaping closure
// per packet. udpTaskFunc keeps func literals usable for tests and benches.
type UdpTask interface {
	Run()
}

// udpTaskDiscarder is implemented by tasks that own resources released by
// Run's defers (pool buffers, admission tickets, the pooled task object).
// Queue teardown must discard those tasks without running them.
type udpTaskDiscarder interface {
	Discard()
}

// discardTask releases the resources a queued-but-never-run task holds.
// Plain func tasks carry nothing and are dropped for GC.
func discardTask(task UdpTask) {
	if d, ok := task.(udpTaskDiscarder); ok {
		d.Discard()
	}
}

// udpTaskFunc adapts a func literal to UdpTask.
type udpTaskFunc func()

func (f udpTaskFunc) Run() { f() }

// UdpTaskQueue makes sure packets with the same UDP flow key are sent in order.
// Field order optimized for memory alignment (Go best practice).
type UdpTaskQueue struct {
	// 8-byte aligned fields first
	p         *UdpTaskPool
	ch        chan UdpTask
	wake      chan struct{}
	done      chan struct{}
	overflow  []UdpTask
	enqueueMu sync.Mutex

	// 8-byte fields
	agingTime time.Duration

	// 4-byte fields with padding
	refs atomic.Int32

	// 1-byte fields
	overflowLen atomic.Int32 // track overflow length for lock-free idle check
	closed      bool         // guarded by enqueueMu
	chReturned  atomic.Bool  // guards queueChPool.Put against defensive double cleanup

	// Producer-side tier choice: set when a channel send observed the channel
	// full, cleared by popOverflowTask once overflow drains. The flag and the
	// tier writes it orders are both made under enqueueMu, so the convoy never
	// sees a channel task that is newer than a queued overflow task.
	overflowMode bool

	key UdpFlowKey
}

// udpTaskQueueTrace and udpTaskTraceEvent belong to the ordering diagnostic
// (udp_task_pool_order_diag_test.go). The production type only carries the
// attachment point.
type udpTaskQueueTrace struct {
	// The ring is written without a lock: its slots are claimed by an atomic
	// ordinal, and the diagnostic reads it after the pool has quiesced. A lock
	// (or an append under one) would change the very timing under study.
	written atomic.Uint64
	ring    [udpTaskTraceCap]udpTaskTraceEvent
}

type udpTaskTraceEvent struct {
	ord          int
	op           string
	seq          int
	chLen        int
	ovfLen       int
	overflowMode bool
	poppedFromCh bool
}

func (tr *udpTaskQueueTrace) record(e udpTaskTraceEvent) {
	n := tr.written.Add(1)
	if n > udpTaskTraceCap {
		return
	}
	e.ord = int(n)
	tr.ring[(n-1)%udpTaskTraceCap] = e
}

// snapshot returns the recorded events in ordinal order.
func (tr *udpTaskQueueTrace) snapshot() []udpTaskTraceEvent {
	written := tr.written.Load()
	n := min(written, udpTaskTraceCap)
	out := make([]udpTaskTraceEvent, 0, n)
	start := written - n
	for i := start; i < written; i++ {
		e := tr.ring[i%udpTaskTraceCap]
		if e.ord == int(i)+1 {
			out = append(out, e)
		}
	}
	return out
}

// udpTaskTraceCap bounds the lock-free event ring the diagnostic reads.
const udpTaskTraceCap = 4096

func (q *UdpTaskQueue) notifyWake() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// enqueue keeps accepted work FIFO across the channel-to-overflow transition.
//
// The queue has two storage tiers and one consumer. The channel holds the
// older tasks and overflow the newer ones, so popReadyTask drains the channel
// first. That ordering only holds if the producer's tier decision is atomic
// with respect to the dequeue: a channel send that succeeds *after* an earlier
// task was appended to overflow publishes a newer task into the older tier,
// and the convoy then runs it before the overflow task - precisely the
// out-of-order execution issue #8 reports.
//
// enqueueMu is therefore held across the tier decision *and* the tier write.
// The channel send cannot block while it is held: the channel is only reached
// when overflowMode is false, and overflowMode is only set when that send was
// observed full, so the channel has room. Overflow bookkeeping stays under the
// same lock, which makes "task is in overflow" and "task is in the channel"
// mutually ordered rather than interleaved.
func (q *UdpTaskQueue) enqueue(task UdpTask) bool {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()

	if q.closed {
		return false
	}
	if tr := q.p.traceOf(); tr != nil {
		if v, ok := task.(udpTaskTraceSeq); ok {
			tr.record(udpTaskTraceEvent{
				op: "enq-pre", seq: v.traceSeq(), chLen: len(q.ch),
				ovfLen: len(q.overflow), overflowMode: q.overflowMode,
			})
		}
	}
	// overflowMode means the channel was full at the last send attempt and is
	// drained before overflow, so new work belongs to overflow until the
	// channel empties again (popOverflowTask clears the flag).
	if q.overflowMode {
		if len(q.overflow) >= UdpTaskQueueMaxOverflow {
			return false
		}
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(int32(len(q.overflow)))
		q.traceRecord("enq-ovf", task, len(q.ch), len(q.overflow), true)
		q.notifyWake()
		return true
	}

	// Same ordering contract without blocking producers: the transition to
	// overflow appends the task that did not fit and keeps it FIFO. UDP
	// overload drops the newest task once the bounded overflow tier is full.
	select {
	case q.ch <- task:
		q.traceRecord("enq-ch", task, len(q.ch), len(q.overflow), false)
		return true
	default:
		q.overflowMode = true
		q.overflow = append(q.overflow, task)
		q.overflowLen.Store(1)
		q.traceRecord("enq-ovf", task, len(q.ch), len(q.overflow), true)
		q.notifyWake()
		return true
	}
}

// udpTaskTraceSeq is implemented by tasks that carry their submission index so
// the ordering diagnostic can line the pool's tier timeline up with the
// execution order it observes. Production tasks do not implement it.
type udpTaskTraceSeq interface {
	traceSeq() int
}

// traceRecord appends one enqueue event to the queue's attached trace. It is a
// no-op unless a diagnostic attached one.
func (q *UdpTaskQueue) traceRecord(op string, task UdpTask, chLen, ovfLen int, overflowMode bool) {
	tr := q.p.traceOf()
	if tr == nil {
		return
	}
	seq := -1
	if v, ok := task.(udpTaskTraceSeq); ok {
		seq = v.traceSeq()
	}
	tr.record(udpTaskTraceEvent{
		op: op, seq: seq, chLen: chLen, ovfLen: ovfLen, overflowMode: overflowMode,
	})
}

// tracePop records one pop event with the tier it was served from.
func (q *UdpTaskQueue) tracePop(op string, task UdpTask, chLen, ovfLen int) {
	tr := q.p.traceOf()
	if tr == nil {
		return
	}
	seq := -1
	if v, ok := task.(udpTaskTraceSeq); ok {
		seq = v.traceSeq()
	}
	// overflowMode is deliberately not read here: the convoy does not hold
	// enqueueMu, so reading the producer-owned flag would itself be a race.
	// The enqueue events already carry it.
	tr.record(udpTaskTraceEvent{
		op: op, seq: seq, chLen: chLen, ovfLen: ovfLen,
		poppedFromCh: op == "pop-ch",
	})
}

// traceOf returns the diagnostic trace attached to the pool, if any.
func (p *UdpTaskPool) traceOf() *udpTaskQueueTrace {
	return p.trace.Load()
}

// popOverflowTask pops the oldest overflow task. It takes enqueueMu itself;
// callers that already hold it (popReadyTask) use popOverflowTaskLocked.
func (q *UdpTaskQueue) popOverflowTask() (UdpTask, bool) {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()
	return q.popOverflowTaskLocked()
}

// popOverflowTaskLocked is popOverflowTask with enqueueMu already held.
func (q *UdpTaskQueue) popOverflowTaskLocked() (UdpTask, bool) {
	if len(q.overflow) == 0 {
		q.overflowMode = false
		return nil, false
	}
	task := q.overflow[0]
	q.overflow[0] = nil
	q.overflow = q.overflow[1:]
	if len(q.overflow) == 0 {
		q.overflowMode = false
		q.overflowLen.Store(0)
		// Keep a small preallocated slice to reduce allocations for bursty traffic
		if cap(q.overflow) > UdpTaskQueueLength*2 {
			q.overflow = make([]UdpTask, 0, UdpTaskQueueLength/4)
		} else {
			q.overflow = q.overflow[:0]
		}
	} else {
		q.overflowLen.Store(int32(len(q.overflow)))
		if len(q.overflow) > 0 && len(q.overflow) < cap(q.overflow)/4 && cap(q.overflow) > UdpTaskQueueLength {
			// Slice Drift Memory Leak prevention: shrink active capacity.
			shrunk := make([]UdpTask, len(q.overflow))
			copy(shrunk, q.overflow)
			q.overflow = shrunk
		}
	}
	return task, true
}

// popReadyTask returns the oldest queued task: the channel first, then
// overflow.
//
// The tier choice is made under enqueueMu, the same lock the producer holds
// across its send and its overflow append. Without that, the two sides race:
// the producer can observe a full channel, decide to overflow, and a dequeue
// running in between sees an empty channel and serves overflow - handing the
// convoy a task that is newer than the ones the producer is about to publish
// into the channel. Serializing the choice with the publication is what makes
// "channel is older than overflow" true at every instant (issue #8).
func (q *UdpTaskQueue) popReadyTask() (UdpTask, bool) {
	q.enqueueMu.Lock()
	defer q.enqueueMu.Unlock()

	select {
	case task := <-q.ch:
		q.tracePop("pop-ch", task, len(q.ch), len(q.overflow))
		return task, true
	default:
	}
	if task, ok := q.popOverflowTaskLocked(); ok {
		q.tracePop("pop-ovf", task, len(q.ch), len(q.overflow))
		return task, true
	}
	return nil, false
}

// drainAndRelease empties any tasks still queued before the channel returns
// to the pool, discarding them with their per-packet cleanup. Without this,
// a convoy teardown (panic recover or pool Close) would both leak the tasks'
// buffers and admission tickets — hanging closeAndWait — and hand a channel
// holding stale packets to an unrelated flow. releaseQueueCh's CAS still
// guards against double-put.
func (q *UdpTaskQueue) drainAndRelease() {
	for {
		select {
		case task := <-q.ch:
			discardTask(task)
			continue
		default:
		}
		break
	}
	for {
		task, ok := q.popOverflowTask()
		if !ok {
			break
		}
		discardTask(task)
	}
	q.p.releaseQueueCh(q)
}

// safeTimerReset resets the timer following Go best practice.
// Per Go documentation: "To reuse a Timer, call Reset and drain the channel
// if it fired." This ensures no stale timer event interferes with the next cycle.
func (q *UdpTaskQueue) safeTimerReset(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(q.agingTime)
}

func (q *UdpTaskQueue) convoy() {
	defer func() {
		if r := recover(); r != nil {
			reportPacketPathPanic("convoy", "lifecycle", &udpTaskPoolPanicCount, r)
			q.refs.Store(-1000000)
			q.p.queues.CompareAndDelete(q.key, q)
		}
		// The convoy is the sole queue cleanup owner. Close waits for done,
		// so the channel cannot be reused while this goroutine still reads it.
		q.drainAndRelease()
		close(q.done)
		q.p.convoys.Done()
	}()
	timer := time.NewTimer(q.agingTime)
	defer timer.Stop()

	for {
		if q.refs.Load() < 0 {
			return
		}
		// Batch drain: process every immediately-ready task in a tight loop
		// without touching the timer between iterations. This replaces the
		// legacy per-task safeTimerReset (Stop + drain + Reset) that
		// dominated the hot path under high packet rates. The idle timer is
		// only armed once the queue goes quiet.
		drainedAny := false
		for {
			if q.refs.Load() < 0 {
				return
			}
			if task, ok := q.popReadyTask(); ok {
				runConvoyTask(task)
				drainedAny = true
				continue
			}
			break
		}
		if drainedAny {
			q.safeTimerReset(timer)
			continue
		}

		select {
		case task := <-q.ch:
			runConvoyTask(task)
			// Drain follow-up tasks that arrived while we were running the
			// first one, then re-arm the timer once.
			for {
				if q.refs.Load() < 0 {
					return
				}
				if task, ok := q.popReadyTask(); ok {
					runConvoyTask(task)
					continue
				}
				break
			}
			q.safeTimerReset(timer)
		case <-q.wake:
			// Check if pool is shutting down
			if q.refs.Load() < 0 {
				return
			}
		case <-timer.C:
			// Idle GC: only remove queue when no in-flight EmitTask and no pending tasks.
			// Use atomic checks first to avoid lock contention.
			if q.refs.Load() > 0 || len(q.ch) > 0 || q.overflowLen.Load() > 0 {
				q.safeTimerReset(timer)
				continue
			}

			// CAS refs to lock out new acquireQueue while the queue is removed
			if !q.refs.CompareAndSwap(0, -1000000) {
				q.safeTimerReset(timer)
				continue
			}

			// Try to delete from pool using CAS-like semantics via sync.Map
			if q.p.tryDeleteQueue(q.key, q) {
				return
			}
			// Check if mapping still points to current queue.
			// If not, this convoy is stale and must exit to prevent goroutine leak.
			if v, ok := q.p.queues.Load(q.key); !ok || v.(*UdpTaskQueue) != q {
				return
			}

			// Restore refs to 0 if deletion failed
			q.refs.Store(0)
			q.safeTimerReset(timer)
		}
	}
}

type UdpTaskPool struct {
	queueChPool sync.Pool
	queues      sync.Map // map[UdpFlowKey]*UdpTaskQueue
	createMu    sync.Mutex
	convoys     sync.WaitGroup
	closed      atomic.Bool
	dropped     atomic.Uint64
	// trace is attached by the ordering diagnostic only; nil in production.
	trace atomic.Pointer[udpTaskQueueTrace]
}

func NewUdpTaskPool() *UdpTaskPool {
	return &UdpTaskPool{
		queueChPool: sync.Pool{New: func() any {
			return make(chan UdpTask, UdpTaskQueueLength)
		}},
	}
}

// EmitTask makes sure accepted packets with the same UDP flow key run in order.
// It returns false when the pool is closed or that flow's bounded queue is full;
// the caller retains ownership and must discard the rejected task.
func (p *UdpTaskPool) EmitTask(key UdpFlowKey, task UdpTask) bool {
	q := p.acquireQueue(key)
	if q == nil {
		return false
	}
	accepted := q.enqueue(task)
	q.refs.Add(-1)
	if !accepted {
		count := p.dropped.Add(1)
		if shouldReportEveryPow2(count) {
			logrus.WithFields(logrus.Fields{
				"dropped_tasks": count,
				"queue_limit":   UdpTaskQueueLength + UdpTaskQueueMaxOverflow,
			}).Warn("dropping UDP task from saturated per-flow queue")
		}
	}
	return accepted
}

// DroppedTasks reports overload drops since the pool was created.
func (p *UdpTaskPool) DroppedTasks() uint64 { return p.dropped.Load() }

func (p *UdpTaskPool) acquireQueue(key UdpFlowKey) *UdpTaskQueue {
	// Reject new queue creation after Close
	if p.closed.Load() {
		return nil
	}
	// Fast path: check if queue exists without any lock contention
	if v, ok := p.queues.Load(key); ok {
		q := v.(*UdpTaskQueue)
		for {
			refs := q.refs.Load()
			if refs < 0 {
				goto createNew
			}
			if q.refs.CompareAndSwap(refs, refs+1) {
				return q
			}
		}
	}

createNew:

	// Serialize only queue creation with Close. Existing flows keep the
	// lock-free sync.Map/refcount fast path.
	p.createMu.Lock()
	if p.closed.Load() {
		p.createMu.Unlock()
		return nil
	}
	ch := p.queueChPool.Get().(chan UdpTask)
	newQ := &UdpTaskQueue{
		key:       key,
		p:         p,
		ch:        ch,
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
		agingTime: UdpTaskPoolAgingTime,
	}

	actual, loaded := p.queues.LoadOrStore(key, newQ)
	if loaded {
		// Another goroutine created the queue first, put our channel back.
		p.queueChPool.Put(ch)
		q := actual.(*UdpTaskQueue)
		for {
			refs := q.refs.Load()
			if refs < 0 {
				p.queues.CompareAndDelete(key, q)
				p.createMu.Unlock()
				goto createNew
			}
			if q.refs.CompareAndSwap(refs, refs+1) {
				p.createMu.Unlock()
				return q
			}
		}
	}
	q := actual.(*UdpTaskQueue)
	q.refs.Add(1)
	p.convoys.Add(1)
	go q.convoy()
	p.createMu.Unlock()
	return q
}

// Close stops all convoy goroutines and releases resources.
// After Close, the pool must not be reused (shutdown-only path).
func (p *UdpTaskPool) Close() {
	p.createMu.Lock()
	if p.closed.Swap(true) {
		p.createMu.Unlock()
		return
	}
	var done []<-chan struct{}
	p.queues.Range(func(key, value any) bool {
		if q, ok := p.queues.LoadAndDelete(key); ok {
			queue := q.(*UdpTaskQueue)
			queue.close()
			done = append(done, queue.done)
		}
		return true
	})
	p.createMu.Unlock()
	for _, ch := range done {
		<-ch
	}
	// An idle convoy may have removed itself from queues immediately before
	// Close took the snapshot. Wait for those already-retiring convoys too.
	p.convoys.Wait()
}

// releaseQueueCh returns the queue channel to the pool exactly once. Close
// and the exiting convoy goroutine race over the same channel; the CAS makes
// double-put impossible (a double-put would let sync.Pool hand the same
// channel to two different queues, silently cross-mixing flows).
func (p *UdpTaskPool) releaseQueueCh(q *UdpTaskQueue) {
	if q.chReturned.CompareAndSwap(false, true) {
		p.queueChPool.Put(q.ch)
	}
}

// close rejects future enqueues and wakes the convoy. Cleanup remains owned by
// the convoy so Close can wait for done before the channel is reused.
func (q *UdpTaskQueue) close() {
	q.enqueueMu.Lock()
	if q.closed {
		q.enqueueMu.Unlock()
		return
	}
	q.closed = true
	q.refs.Store(-1000000)
	q.enqueueMu.Unlock()
	q.notifyWake()
}

// tryDeleteQueue attempts to delete the queue if it's still the same instance.
// Returns true if deletion was successful, false otherwise.
// Uses CompareAndDelete for atomic CAS semantics (Go 1.20+ best practice).
func (p *UdpTaskPool) tryDeleteQueue(key UdpFlowKey, expected *UdpTaskQueue) bool {
	return p.queues.CompareAndDelete(key, expected)
}

var (
	DefaultUdpTaskPool = NewUdpTaskPool()
)

// udpTaskPoolPanicCount backs the rate-limited panic reporting for the convoy
// task pool.
var udpTaskPoolPanicCount atomic.Uint64

// runConvoyTask executes one queued task with panic isolation: a panic in one
// packet's handling unwinds the task's own resource-releasing defers but must
// not take down the convoy goroutine or the whole process.
func runConvoyTask(task UdpTask) {
	defer func() {
		if recovered := recover(); recovered != nil {
			reportPacketPathPanic("convoy", "run", &udpTaskPoolPanicCount, recovered)
		}
	}()
	task.Run()
}

// runDirectDispatchTask executes one directly dispatched ingress task with the
// same panic isolation the convoy path has: the task's own defers (dispatch
// semaphore, admission ticket, packet buffer, pooled task object) already ran
// during the unwind, so the recovery handler must only report - releasing
// anything again here would double-free the buffer and the pool slot.
func runDirectDispatchTask(task *udpIngressTask, panicCount *atomic.Uint64) {
	defer func() {
		if recovered := recover(); recovered != nil {
			reportPacketPathPanic("direct_dispatch", "run", panicCount, recovered)
		}
	}()
	task.Run()
}

// shouldReportEveryPow2 returns true on the 1st, 2nd, 4th, ... occurrence so
// recurring panics log at exponentially decreasing rates.
func shouldReportEveryPow2(count uint64) bool {
	return count&(count-1) == 0
}

// reportPacketPathPanic reports a recovered panic from a per-packet or
// per-connection execution path. The deferred recover handler still runs on
// the panicking goroutine's stack, so debug.Stack() captures the panic site
// frames; without it the log line only carries the panic value and the site
// stays unknown.
func reportPacketPathPanic(path, taskKind string, panicCount *atomic.Uint64, recovered any) {
	count := panicCount.Add(1)
	if !shouldReportEveryPow2(count) {
		return
	}
	logrus.WithFields(logrus.Fields{
		"path":        path,
		"task_kind":   taskKind,
		"panic":       recovered,
		"panic_count": count,
		"stack":       string(debug.Stack()),
	}).Error("recovered panic in packet path task")
}
