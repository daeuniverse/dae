/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"container/heap"
	"time"

	"github.com/sirupsen/logrus"
)

// bpfUpdateTask represents a BPF map update request.
type bpfUpdateTask struct {
	cache                *DnsCache
	routeProjectionEpoch uint64
	retryAttempt         uint8
}

const (
	bpfProjectionRetryLimit     = 5
	bpfProjectionRetryBaseDelay = 25 * time.Millisecond
	bpfProjectionRetryMaxDelay  = time.Second
	bpfProjectionRetryCapacity  = 4096
)

type bpfProjectionRetryKey struct {
	cacheKey             string
	routeProjectionEpoch uint64
}

func (task *bpfUpdateTask) retryKey() (bpfProjectionRetryKey, bool) {
	if task == nil || task.cache == nil || task.cache.RouteOwnerKey == "" {
		return bpfProjectionRetryKey{}, false
	}
	return bpfProjectionRetryKey{
		cacheKey:             task.cache.RouteOwnerKey,
		routeProjectionEpoch: task.routeProjectionEpoch,
	}, true
}

type bpfProjectionRetryItem struct {
	task  *bpfUpdateTask
	due   time.Time
	key   bpfProjectionRetryKey
	index int
}

type bpfProjectionRetryHeap []*bpfProjectionRetryItem

func (h bpfProjectionRetryHeap) Len() int {
	return len(h)
}

func (h bpfProjectionRetryHeap) Less(i, j int) bool {
	return h[i].due.Before(h[j].due)
}

func (h bpfProjectionRetryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *bpfProjectionRetryHeap) Push(value any) {
	item := value.(*bpfProjectionRetryItem)
	item.index = len(*h)
	*h = append(*h, item)
}

func (h *bpfProjectionRetryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	old[last] = nil
	item.index = -1
	*h = old[:last]
	return item
}

type bpfProjectionRetryScheduler struct {
	queue   bpfProjectionRetryHeap
	pending map[bpfProjectionRetryKey]*bpfProjectionRetryItem
}

func newBpfProjectionRetryScheduler() *bpfProjectionRetryScheduler {
	return &bpfProjectionRetryScheduler{
		pending: make(map[bpfProjectionRetryKey]*bpfProjectionRetryItem),
	}
}

func (s *bpfProjectionRetryScheduler) add(task *bpfUpdateTask) bool {
	if s == nil || task == nil {
		return false
	}
	return s.addAt(task, time.Now())
}

func (s *bpfProjectionRetryScheduler) addAt(task *bpfUpdateTask, now time.Time) bool {
	if s == nil || task == nil {
		return false
	}
	key, ok := task.retryKey()
	if !ok {
		return false
	}
	due := now.Add(bpfProjectionRetryDelay(task.retryAttempt))
	if pending := s.pending[key]; pending != nil {
		if pending.task.cache != task.cache {
			pending.task = task
			pending.due = due
			heap.Fix(&s.queue, pending.index)
			return true
		}
		if !due.Before(pending.due) && task.retryAttempt >= pending.task.retryAttempt {
			return true
		}
		pending.task = task
		pending.due = due
		heap.Fix(&s.queue, pending.index)
		return true
	}
	if len(s.pending) >= bpfProjectionRetryCapacity {
		return false
	}
	item := &bpfProjectionRetryItem{task: task, due: due, key: key}
	heap.Push(&s.queue, item)
	s.pending[key] = item
	return true
}

func (s *bpfProjectionRetryScheduler) nextDue() (time.Time, bool) {
	if s == nil || s.queue.Len() == 0 {
		return time.Time{}, false
	}
	return s.queue[0].due, true
}

func (s *bpfProjectionRetryScheduler) popDue(now time.Time) []*bpfUpdateTask {
	if s == nil {
		return nil
	}
	var tasks []*bpfUpdateTask
	for s.queue.Len() > 0 && !s.queue[0].due.After(now) {
		item := heap.Pop(&s.queue).(*bpfProjectionRetryItem)
		delete(s.pending, item.key)
		tasks = append(tasks, item.task)
	}
	return tasks
}

func bpfProjectionRetryDelay(attempt uint8) time.Duration {
	delay := bpfProjectionRetryBaseDelay
	for retry := uint8(1); retry < attempt && delay < bpfProjectionRetryMaxDelay; retry++ {
		delay *= 2
	}
	if delay > bpfProjectionRetryMaxDelay {
		return bpfProjectionRetryMaxDelay
	}
	return delay
}

func (c *DnsController) reprojectCachedRoutes(rt *dnsControllerRuntimeState) {
	if c == nil || c.dnsControllerStore == nil || rt == nil || rt.projectCacheRoute == nil {
		return
	}

	now := time.Now()
	c.dnsCache.Range(func(key, value any) bool {
		cacheKey, ok := key.(string)
		if !ok {
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok || cache == nil || cache.RouteProjectionEpoch == rt.routeProjectionEpoch {
			return true
		}

		replacement := cache.CloneForReload()
		ensureDNSCacheRouteOwnerKey(cacheKey, replacement)
		replacement.RouteProjectionEpoch = rt.routeProjectionEpoch
		replacement.DomainBitmap = rt.projectCacheRoute(replacement)

		// Pair the rebuilt bitmap with the runtime that supplied its epoch.
		// A reload can replace the runtime while the matcher is running, in
		// which case the stale projection must not be published.
		c.runtimeMu.RLock()
		if c.runtime() == rt {
			c.cacheProjectionMu.Lock()
			if c.runtime() == rt && c.dnsCache.CompareAndSwap(key, cache, replacement) {
				c.triggerBpfUpdateIfNeededForRuntime(replacement, now, rt)
			}
			c.cacheProjectionMu.Unlock()
		}
		c.runtimeMu.RUnlock()
		return true
	})
}

// startBpfUpdateWorker lazily starts the BPF update worker goroutine.
// This is called on-demand when the first BPF update is needed.
func (c *DnsController) startBpfUpdateWorker() {
	c.requireStore()
	c.bpfUpdateOnce.Do(func() {
		c.bpfUpdateStopMu.Lock()
		if c.bpfUpdateClosed.Load() {
			c.bpfUpdateStopMu.Unlock()
			return
		}
		const bpfUpdateQueueSize = 1024
		c.bpfUpdateCh = make(chan *bpfUpdateTask, bpfUpdateQueueSize)
		c.bpfRetryMu.Lock()
		c.bpfRetryWake = make(chan struct{}, 1)
		c.bpfRetryPending = make(map[bpfProjectionRetryKey]*bpfUpdateTask)
		c.bpfRetryMu.Unlock()
		c.bpfUpdateStop = make(chan struct{})
		c.bpfUpdateWg.Add(1)
		c.bpfUpdateStopMu.Unlock()
		go c.bpfUpdateWorker()
	})
}

// processBpfUpdateTask executes a single BPF map update task.
// Returns true if the task was processed, false if it was nil/empty.
func (c *DnsController) processBpfUpdateTask(task *bpfUpdateTask, draining bool) bool {
	processed, _ := c.processBpfUpdateTaskInternal(task, draining, !draining)
	return processed
}

func (c *DnsController) processBpfUpdateTaskInternal(task *bpfUpdateTask, draining, scheduleRetry bool) (processed, failed bool) {
	if task == nil || task.cache == nil {
		return false, false
	}
	if c.bpfUpdateClosed.Load() {
		return true, false
	}
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	c.cacheProjectionMu.RLock()
	defer c.cacheProjectionMu.RUnlock()
	if c.bpfUpdateClosed.Load() {
		return true, false
	}
	rt := c.runtime()
	if !c.bpfUpdateTaskCurrent(task, rt) {
		return true, false
	}
	if err := rt.cacheAccessCallback(task.cache); err != nil {
		if c.log != nil {
			suffix := ""
			if draining {
				suffix = " (during shutdown)"
			}
			c.log.WithError(err).Warnf("async BPF map update failed%s", suffix)
		}
		if scheduleRetry {
			c.scheduleBpfProjectionRetry(task)
		}
		failed = true
	} else {
		task.cache.MarkBpfUpdated(time.Now())
	}
	return true, failed
}

func (c *DnsController) bpfUpdateTaskCurrent(task *bpfUpdateTask, rt *dnsControllerRuntimeState) bool {
	if task == nil || task.cache == nil || rt == nil || rt.cacheAccessCallback == nil ||
		task.routeProjectionEpoch != rt.routeProjectionEpoch {
		return false
	}
	if task.cache.RouteProjectionEpoch != task.routeProjectionEpoch {
		return false
	}
	cacheKey := task.cache.RouteOwnerKey
	if cacheKey == "" {
		return task.retryAttempt == 0
	}
	value, ok := c.dnsCache.Load(cacheKey)
	return ok && value == task.cache
}

func (c *DnsController) scheduleBpfProjectionRetry(task *bpfUpdateTask) {
	key, ok := task.retryKey()
	if !ok || task.retryAttempt >= bpfProjectionRetryLimit || c.bpfUpdateClosed.Load() {
		return
	}
	retry := *task
	retry.retryAttempt++
	c.bpfRetryMu.Lock()
	if c.bpfUpdateClosed.Load() || c.bpfRetryWake == nil || c.bpfRetryPending == nil {
		c.bpfRetryMu.Unlock()
		return
	}
	if pending := c.bpfRetryPending[key]; pending != nil {
		if retry.retryAttempt < pending.retryAttempt || pending.cache != retry.cache {
			c.bpfRetryPending[key] = &retry
		}
	} else if len(c.bpfRetryPending) < bpfProjectionRetryCapacity {
		c.bpfRetryPending[key] = &retry
	} else {
		// Preserve a bounded retry set. The worker will reconcile current cache
		// ownership without retaining one task per cache entry.
		c.bpfRetryOverflow = true
	}
	wake := c.bpfRetryWake
	c.bpfRetryMu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
		// A wake is already pending. The durable intent remains in the shared
		// map and will be consumed by the worker before it blocks again.
	}
}

func (c *DnsController) takeBpfProjectionRetryIntents() (tasks []*bpfUpdateTask, overflow bool) {
	c.bpfRetryMu.Lock()
	defer c.bpfRetryMu.Unlock()
	overflow = c.bpfRetryOverflow
	c.bpfRetryOverflow = false
	if len(c.bpfRetryPending) == 0 {
		return nil, overflow
	}
	tasks = make([]*bpfUpdateTask, 0, len(c.bpfRetryPending))
	for _, task := range c.bpfRetryPending {
		tasks = append(tasks, task)
	}
	clear(c.bpfRetryPending)
	return tasks, overflow
}

// reconcileCurrentBpfProjections recovers work coalesced by the bounded retry
// queue. It walks the authoritative cache in place and never builds an
// O(cache-size) task slice.
func (c *DnsController) reconcileCurrentBpfProjections() (failed bool) {
	if c == nil || c.bpfUpdateClosed.Load() {
		return false
	}
	rt := c.runtime()
	if rt == nil || rt.cacheAccessCallback == nil {
		return false
	}
	c.dnsCache.Range(func(key, value any) bool {
		if c.bpfUpdateClosed.Load() {
			return false
		}
		if c.runtime() != rt {
			failed = true
			return false
		}
		cacheKey, keyOK := key.(string)
		cache, cacheOK := value.(*DnsCache)
		if !keyOK || !cacheOK || cache == nil || cache.RouteOwnerKey != cacheKey ||
			cache.RouteProjectionEpoch != rt.routeProjectionEpoch {
			return true
		}
		currentHash := cache.ComputeBpfDataHash()
		if currentHash == 0 || currentHash == cache.lastBpfDataHash.Load() {
			return true
		}
		_, taskFailed := c.processBpfUpdateTaskInternal(&bpfUpdateTask{
			cache:                cache,
			routeProjectionEpoch: rt.routeProjectionEpoch,
		}, false, false)
		failed = failed || taskFailed
		if c.runtime() != rt {
			failed = true
			return false
		}
		return true
	})
	if !c.bpfUpdateClosed.Load() && c.runtime() != rt {
		failed = true
	}
	return failed
}

// bpfUpdateWorker processes BPF map updates asynchronously.
// It runs until bpfUpdateStop is closed, then drains remaining tasks and exits.
// Note: bpfUpdateCh is never closed; the worker exits when bpfUpdateStop is signaled.
//
// IMPORTANT: This goroutine intentionally does NOT watch baseContext().Done().
// When the DnsController is reused across reload generations (ReuseDNSControllerFrom),
// UpdateRuntime swaps the lifecycleCtx, but goroutines blocked in select still hold
// a reference to the OLD context's Done channel. If the old generation's context is
// canceled during retirement, the worker would exit prematurely, permanently killing
// BPF domain_routing_map updates (sync.Once prevents restart). The worker exits only
// via bpfUpdateStop, which is closed during DnsController.Close().
func (c *DnsController) bpfUpdateWorker() {
	defer c.bpfUpdateWg.Done()
	// Snapshot all lifecycle channels under the mutexes that guard their
	// fields. Close may nil the fields after the graceful timeout while a
	// stuck worker is still selecting on them; reading them once here keeps
	// later receives race-free and preserves the stop signal.
	c.bpfUpdateStopMu.Lock()
	bpfUpdateCh := c.bpfUpdateCh
	bpfUpdateStop := c.bpfUpdateStop
	c.bpfUpdateStopMu.Unlock()
	c.bpfRetryMu.Lock()
	bpfRetryWake := c.bpfRetryWake
	c.bpfRetryMu.Unlock()
	if bpfUpdateCh == nil || bpfUpdateStop == nil {
		return
	}
	retries := newBpfProjectionRetryScheduler()
	retryTimer := time.NewTimer(time.Hour)
	if !retryTimer.Stop() {
		select {
		case <-retryTimer.C:
		default:
		}
	}
	defer retryTimer.Stop()
	var retryTimerCh <-chan time.Time
	var (
		reconcilePending bool
		reconcileAttempt uint8
		reconcileDue     time.Time
	)
	scheduleReconcile := func(now time.Time) {
		if reconcilePending {
			return
		}
		reconcilePending = true
		reconcileAttempt = 1
		reconcileDue = now.Add(bpfProjectionRetryDelay(reconcileAttempt))
	}
	resetRetryTimer := func() {
		due, ok := retries.nextDue()
		if reconcilePending && (!ok || reconcileDue.Before(due)) {
			due, ok = reconcileDue, true
		}
		if !ok {
			if retryTimerCh != nil && !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			retryTimerCh = nil
			return
		}
		if retryTimerCh != nil && !retryTimer.Stop() {
			select {
			case <-retryTimer.C:
			default:
			}
		}
		delay := max(time.Until(due), 0)
		retryTimer.Reset(delay)
		retryTimerCh = retryTimer.C
	}

	for {
		select {
		case task := <-bpfUpdateCh:
			c.processBpfUpdateTask(task, false)
			c.drainBpfUpdateTasks(bpfUpdateCh, false)
		case <-bpfRetryWake:
			tasks, overflow := c.takeBpfProjectionRetryIntents()
			if overflow {
				scheduleReconcile(time.Now())
			}
			for _, task := range tasks {
				if !retries.add(task) {
					scheduleReconcile(time.Now())
				}
			}
			resetRetryTimer()
		case <-retryTimerCh:
			retryTimerCh = nil
			now := time.Now()
			for _, task := range retries.popDue(now) {
				c.processBpfUpdateTask(task, false)
			}
			if reconcilePending && !reconcileDue.After(now) {
				failed := c.reconcileCurrentBpfProjections()
				if failed && reconcileAttempt < bpfProjectionRetryLimit {
					reconcileAttempt++
					reconcileDue = now.Add(bpfProjectionRetryDelay(reconcileAttempt))
				} else {
					if failed && c.log != nil {
						c.log.Warn("BPF projection reconciliation exhausted its retry budget")
					}
					reconcilePending = false
					reconcileAttempt = 0
					reconcileDue = time.Time{}
				}
			}
			resetRetryTimer()
		case <-bpfUpdateStop:
			c.drainBpfUpdateTasks(bpfUpdateCh, true)
			return
		}
	}
}

const bpfUpdateDrainBatch = 64

// drainBpfUpdateTasks processes a bounded primary-task batch. Returning to the
// worker select between batches prevents a sustained cache-write stream from
// starving delayed retries or shutdown.
func (c *DnsController) drainBpfUpdateTasks(bpfUpdateCh <-chan *bpfUpdateTask, draining bool) {
	for range bpfUpdateDrainBatch {
		select {
		case task := <-bpfUpdateCh:
			c.processBpfUpdateTask(task, draining)
		default:
			return
		}
	}
}

// triggerBpfUpdateIfNeeded enqueues a BPF update task if needed. It never
// blocks cache readers; a full primary queue is handed to the bounded retry
// scheduler when the cache still belongs to the current runtime.
func (c *DnsController) triggerBpfUpdateIfNeeded(cache *DnsCache, now time.Time) {
	c.triggerBpfUpdateIfNeededForRuntime(cache, now, c.runtime())
}

func (c *DnsController) triggerBpfUpdateIfNeededForRuntime(cache *DnsCache, now time.Time, rt *dnsControllerRuntimeState) {
	c.requireStore()
	if cache == nil || rt == nil || rt.cacheAccessCallback == nil || c.runtime() != rt {
		return
	}
	if !cache.NeedsBpfUpdate(now) {
		return
	}

	if c.bpfUpdateClosed.Load() {
		return
	}

	c.startBpfUpdateWorker()

	if c.bpfUpdateClosed.Load() || c.runtime() != rt {
		return
	}

	task := &bpfUpdateTask{
		cache:                cache,
		routeProjectionEpoch: rt.routeProjectionEpoch,
	}
	if !c.sendBpfUpdateTask(task) {
		c.scheduleBpfProjectionRetry(task)
		if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.Debug("BPF update queue full or closed, skipping update")
		}
	}
}

func (c *DnsController) sendBpfUpdateTask(task *bpfUpdateTask) (sent bool) {
	// Check if controller is shutting down before attempting send.
	// This avoids the data race of reading bpfUpdateStop while it's being initialized.
	if c.bpfUpdateClosed.Load() {
		return false
	}
	c.bpfUpdateStopMu.Lock()
	bpfUpdateCh := c.bpfUpdateCh
	c.bpfUpdateStopMu.Unlock()
	if bpfUpdateCh == nil {
		return false
	}

	// Try to send without blocking. The caller may move a dropped task to the
	// bounded retry scheduler, which revalidates cache ownership before retry.
	select {
	case bpfUpdateCh <- task:
		return true
	default:
		// Queue is full; the caller decides whether this cache is eligible for
		// a bounded delayed retry.
		return false
	}
}
