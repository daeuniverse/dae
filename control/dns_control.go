/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// dnsResponseBufPool is a pool for DNS response buffers.
// This avoids memory allocation on every cache hit for ID patching.
// Typical DNS response size is under 512 bytes, we allocate 1024 to be safe.
var dnsResponseBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 1024)
		return &buf
	},
}

const (
	MaxDnsLookupDepth  = 3
	minFirefoxCacheTtl = 120
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	ErrUnsupportedQuestionType          = fmt.Errorf("unsupported question type")
	ErrDNSQueryConcurrencyLimitExceeded = errors.New("dns query concurrency limit exceeded")
	ErrDNSUDPConnPoolExhausted          = errors.New("dns udp conn pool exhausted")
	ErrDNSTruncated                     = errors.New("dns response truncated")
	// ErrDnsForwardersClosed is returned when a forwarder is requested after
	// the controller's forwarder cache has been swept by Close. In-flight
	// queries that outlived the close handle-gate must fail instead of
	// repopulating forwarders that nothing will ever close again.
	ErrDnsForwardersClosed = errors.New("dns forwarder cache is closed")
	// errConnPoolClosed is returned when a pooled connection is requested
	// after the pool has been closed; the fresh dial is discarded instead of
	// being appended to a dead pool.
	errConnPoolClosed = errors.New("dns connection pool is closed")
)

var (
	UnspecifiedAddressA     = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA  = netip.MustParseAddr("::")
	dnsCacheJanitorInterval = 30 * time.Second
	dnsForwarderIdleTTL     = 2 * time.Minute
)

type DnsControllerOption struct {
	Log                  *logrus.Logger
	LifecycleContext     context.Context
	CacheAccessCallback  func(cache *DnsCache) (err error)
	CacheDeleteCallback  func(cacheKey string, cache *DnsCache) (err error)
	NewCache             func(fqdn string, answers, ns, extra []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	RouteProjectionEpoch uint64
	// RouteProjectionHash identifies the semantic policy content used to build
	// DomainBitmap. A non-zero hash lets reload reuse an existing projection
	// without walking or cloning the DNS cache when only the generation epoch
	// changed.
	RouteProjectionHash [32]byte
	ProjectCacheRoute   func(cache *DnsCache) []uint32
	// BestDialerChooser is the transport-independent dialer selector: it takes
	// the routing facts of the request rather than its socket.
	BestDialerChooser     func(ctx context.Context, snapshot DnsRequestSnapshot, upstream *dns.Upstream) (*dialArgument, error)
	TimeoutExceedCallback func(dialArgument *dialArgument, err error)
	IpVersionPrefer       int
	FixedDomainTtl        map[string]int
	ConcurrencyLimit      int
	OptimisticCache       bool
	OptimisticCacheTtl    int // 0 means never expire (rely on LRU eviction)
	// OptimisticStaleReplyTtl bounds the TTL advertised for served-stale
	// answers (RFC 8767); 0 keeps the previously packed TTL.
	OptimisticStaleReplyTtl int
	MaxCacheSize            int // maximum number of cache entries (0 = unlimited)
}

type dnsControllerStore struct {
	// dnsCache uses sync.Map for lock-free concurrent access
	dnsCache     sync.Map // map[string]*DnsCache
	dnsCacheSize atomic.Int64
	// dnsCacheByBase indexes the exact cache keys stored under each base cache
	// key (map[string]*dnsCacheKeySet). It lets family removal and knowledge
	// resync touch only the affected family instead of walking the whole cache
	// while holding cacheProjectionMu. It is maintained exclusively by
	// storeDnsCache, loadAndDeleteDnsCache and compareAndDeleteDnsCache (plus
	// Close, which drops it wholesale), and the janitor reconciles it against
	// dnsCacheSize so drift is reported instead of silently disabling family
	// removal.
	dnsCacheByBase sync.Map
	// dnsCacheIndexReconciles counts janitor runs that found the base-key index
	// out of sync with the live cache and rebuilt it.
	dnsCacheIndexReconciles atomic.Uint64
	// dnsCacheStoreFailureAlert paces the report of DNS responses that could
	// not be stored in the cache. Caching is a latency optimization - the
	// response has already been sent to the client - so one line per query
	// reports a working DNS path as if it were an outage; the paced line
	// carries the number of failed stores so the repeats stay visible. It
	// lives on the shared store because the per-query entry points run on both
	// the owning controller and its reload facades, which must share one pace
	// and one count.
	dnsCacheStoreFailureAlert pacedAlert
	dnsKnowledge              sync.Map // map[string]int64 (base cache key -> original deadline unix nano)
	dnsKnowledgeMu            sync.Mutex
	// runtimeState owns the complete immutable runtime and behavior snapshot so
	// one load cannot combine fields from different reload generations.
	runtimeState      atomic.Pointer[dnsControllerRuntimeState]
	runtimeMu         sync.RWMutex // Serializes runtime publication with reload cache projection.
	cacheProjectionMu sync.RWMutex // Serializes cache membership with BPF projection callbacks.
	dnsForwarderCache sync.Map     // map[dnsForwarderKey]*cachedDnsForwarder
	// dnsForwardersClosed is set before closeAllDnsForwarders sweeps the
	// cache. getOrCreateDnsForwarder re-checks it after a store so an
	// in-flight query admitted before the close handle-gate expired cannot
	// repopulate a forwarder that nothing will ever sweep or close again.
	dnsForwardersClosed atomic.Bool
	sf                  singleflight.Group

	janitorStop  chan struct{}
	janitorDone  chan struct{}
	lruScratchMu sync.Mutex
	lruScratch   []cacheEntry
	closeOnce    sync.Once

	// Async BPF update uses one worker and a durable, deduplicated retry intent
	// set. A full primary queue must not discard a projection for a cache entry
	// that has no later reader.
	bpfUpdateCh      chan *bpfUpdateTask
	bpfRetryWake     chan struct{}
	bpfRetryMu       sync.Mutex
	bpfRetryPending  map[bpfProjectionRetryKey]*bpfUpdateTask
	bpfRetryOverflow bool
	bpfUpdateStop    chan struct{}
	bpfUpdateStopMu  sync.Mutex // Protects bpfUpdateStop initialization and closing
	bpfUpdateWg      sync.WaitGroup
	bpfUpdateOnce    sync.Once
	bpfUpdateClosed  atomic.Bool

	// prefWaitRegistry manages waits for preferred DNS response types.
	// When ip_version_prefer is set, non-preferred responses wait briefly
	// for preferred responses to arrive (RFC 8305 Happy Eyeballs).
	prefWaitRegistry *preferenceWaitRegistry
	// dnsPreferWaitNotified counts resolution-delay waits released by a
	// preferred (A/AAAA) answer; dnsPreferWaitTimeout counts waits that ran to
	// their full RFC 8305 delay without one; dnsPreferFiltered counts the
	// answers an already-known preferred family replaced with an empty reply
	// (the ipversion_prefer filter) plus the cached non-preferred entries that
	// filter dropped.
	dnsPreferWaitNotified atomic.Uint64
	dnsPreferWaitTimeout  atomic.Uint64
	dnsPreferFiltered     atomic.Uint64

	// Truncated-answer bookkeeping (RFC 7766 §5). Upgrades count UDP answers
	// whose TC=1 bit triggered a TCP retry and whether that retry produced an
	// answer; ClientReplies counts TC=1 answers handed back to a client because
	// no TCP upgrade delivered the full answer. The lastReported* copies hold
	// the values the janitor published last, so the periodic summary can report
	// an interval rate instead of a lifetime total only; they are written by
	// the single DNS cache janitor goroutine (startDnsCacheJanitor) and are
	// atomic only so a future reader cannot introduce a data race.
	dnsUdpTruncatedUpgrades        atomic.Uint64
	dnsUdpTruncatedUpgradeFailures atomic.Uint64
	dnsTruncatedRepliesToClient    atomic.Uint64
	lastDnsTruncatedLogTime        atomic.Int64
	lastReportedTruncatedUpgrades  atomic.Uint64
	lastReportedTruncatedFailures  atomic.Uint64
	lastReportedTruncatedReplies   atomic.Uint64

	// handleGate accounts for request handlers that entered through the
	// active-plane dispatch. The publication RWMutex used to be held across
	// whole DNS queries, which let one slow upstream head-of-line block a
	// reload publish (and every new reader queued behind it). Dispatch now
	// releases the lock immediately after admission; Close flips the gate
	// shut and drains the counter before forwarders are torn down, which
	// preserves the old lifetime guarantee for in-flight queries.
	handleClosed   atomic.Bool
	handleInflight atomic.Int64
}

// DnsController is a lightweight generation-local facade over a shared
// dnsControllerStore. The zero value is not ready for production use; construct
// controllers with NewDnsController, ReuseForReload, or dedicated test helpers
// so the shared store invariant is established before business methods run.
type DnsController struct {
	*dnsControllerStore

	concurrencyLimiter chan struct{}

	dnsForwarderIdleTTL time.Duration
	// log is assigned only at construction (NewDnsController) and never
	// rewritten afterwards, so lock-free readers are race-free. Reloads keep
	// it valid without reassignment: the daemon builds exactly one
	// logrus.Logger (cmd/run.go) and mutates it in place on reload via
	// logger.SetLogger (SetLevel/SetFormatter are mutex-safe), so the
	// construction-time pointer stays correct across generations. Never store
	// nil: several call sites branch on log != nil. If per-generation loggers
	// are ever introduced (e.g. per-generation log files), convert this field
	// to atomic.Pointer[logrus.Logger] and re-add the updateRuntime
	// assignment.
	log *logrus.Logger
}

func newDnsControllerStore() *dnsControllerStore {
	return &dnsControllerStore{
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},
		janitorStop:       make(chan struct{}),
		janitorDone:       make(chan struct{}),
		prefWaitRegistry:  newPreferenceWaitRegistry(),
	}
}

func (c *DnsController) requireStore() *dnsControllerStore {
	if c == nil {
		return nil
	}
	if c.dnsControllerStore == nil {
		// Business-path DNS methods require the shared store invariant to have
		// been established by NewDnsController, ReuseForReload, or test helpers.
		// Panic here so misuse fails fast instead of silently constructing an
		// empty store and masking initialization bugs.
		panic("DnsController.dnsControllerStore is nil; construct controllers with NewDnsController or test helpers")
	}
	return c.dnsControllerStore
}

func (c *DnsController) ensureStoreForReload() *dnsControllerStore {
	if c == nil {
		return nil
	}
	if c.dnsControllerStore == nil {
		c.dnsControllerStore = newDnsControllerStore()
	}
	return c.dnsControllerStore
}

func (c *DnsController) sharedStoreFacade() *DnsController {
	if c == nil {
		return nil
	}
	store := c.requireStore()
	facade := &DnsController{
		dnsControllerStore:  store,
		concurrencyLimiter:  c.concurrencyLimiter,
		dnsForwarderIdleTTL: c.dnsForwarderIdleTTL,
		log:                 c.log,
	}
	return facade
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	if option == nil {
		option = &DnsControllerOption{}
	}

	// Set concurrency limit for DNS queries
	// This prevents resource exhaustion from DNS query storms.
	//
	// Best Practice (based on CoreDNS/AdGuard Home):
	// Go DNS apps typically don't have hard concurrency limits because:
	// - Go goroutines are lightweight (~2KB stack)
	// - Real bottleneck is upstream latency, not goroutine count
	//
	// However, for proxy chains (Shadowsocks/VMess), each query takes longer,
	// so we need a higher limit to maintain throughput.
	//
	// Memory calculation: Each concurrent query uses ~4KB
	//   * 16384 concurrent = ~64MB memory (default)
	//   * 32768 concurrent = ~128MB memory
	//
	// Comparison with other DNS apps:
	//   * CoreDNS: No hard limit (relies on Go runtime)
	//   * AdGuard Home: No hard limit
	//   * Unbound (C): 10000 (outgoing-range)
	//   * PowerDNS: 2048 (max-mthreads)
	//
	// Default: 16384 (suitable for proxy scenarios)
	// - Handles up to ~8000 QPS with 2s upstream latency
	// - Memory usage: ~64MB for concurrent queries
	//
	// Configuration:
	// - <= 0: Use default (16384)
	// - > 0: Use specified value
	const defaultConcurrencyLimit = 16384
	limit := option.ConcurrencyLimit
	if limit <= 0 {
		limit = defaultConcurrencyLimit
	}

	controller := &DnsController{
		dnsControllerStore:  newDnsControllerStore(),
		concurrencyLimiter:  make(chan struct{}, limit),
		log:                 option.Log,
		dnsForwarderIdleTTL: dnsForwarderIdleTTL, // Use package-level default
	}
	if err := controller.TryUpdateRuntime(option, routing); err != nil {
		return nil, err
	}
	controller.startDnsCacheJanitor()
	return controller, nil
}

func (c *DnsController) Close() error {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	var (
		bpfWorkerDone <-chan struct{}
		janitorDone   <-chan struct{}
	)

	// Acquire lock before closeOnce to synchronize with startBpfUpdateWorker.
	// This prevents the race where Close and startBpfUpdateWorker access
	// bpfUpdateStop concurrently.
	c.bpfUpdateStopMu.Lock()
	c.closeOnce.Do(func() {
		c.bpfUpdateClosed.Store(true)
		// Stop BPF update worker (if it was started).
		if c.bpfUpdateStop != nil {
			// Signal worker to stop and drain remaining tasks
			close(c.bpfUpdateStop)
			// Wait for worker to finish draining.
			done := make(chan struct{})
			go func() {
				c.bpfUpdateWg.Wait()
				close(done)
			}()
			bpfWorkerDone = done
			// Note: We intentionally do NOT close bpfUpdateCh here.
			// Closing the channel while concurrent sends might be in progress
			// would cause panics. Instead, the channel will be garbage collected
			// when the DnsController is no longer referenced.
		}

		if c.janitorStop != nil {
			close(c.janitorStop)
		}
		if c.janitorDone != nil {
			janitorDone = c.janitorDone
		}
	})
	c.bpfUpdateStopMu.Unlock()
	// Wait for any in-flight projection callback before cache teardown. A task
	// that arrives after this barrier observes bpfUpdateClosed and is discarded.
	c.cacheProjectionMu.Lock()
	// This lock/unlock pair is an intentional barrier for in-flight projection callbacks.
	//nolint:staticcheck // The empty critical section provides the required wait barrier.
	c.cacheProjectionMu.Unlock()

	if bpfWorkerDone != nil || janitorDone != nil {
		timer := time.NewTimer(gracefulShutdownWaitTimeout)
		defer timer.Stop()

		for bpfWorkerDone != nil || janitorDone != nil {
			select {
			case <-bpfWorkerDone:
				bpfWorkerDone = nil
			case <-janitorDone:
				janitorDone = nil
			case <-timer.C:
				if c.log != nil {
					if bpfWorkerDone != nil {
						c.log.Warn("DnsController.Close: timeout waiting for bpfUpdateWg")
					}
					if janitorDone != nil {
						c.log.Warn("DnsController.Close: timeout waiting for janitorDone")
					}
				}
				bpfWorkerDone = nil
				janitorDone = nil
			}
		}
	}

	// Reject new active-plane dispatches and let in-flight handlers finish
	// before forwarders are torn down, bounded by the same graceful budget.
	c.closeHandleGate()

	errs := c.closeAllDnsForwarders()
	// Clear dnsCache to prevent memory leak on reload.
	// Each DnsCache entry contains DomainBitmap and Answer which can accumulate
	// significant memory over time if not released.
	c.cacheProjectionMu.Lock()
	c.dnsCache.Range(func(key, value any) bool {
		c.dnsCache.Delete(key)
		return true
	})
	c.dnsCacheSize.Store(0)
	c.clearDnsCacheIndex()
	c.cacheProjectionMu.Unlock()
	c.dnsKnowledge.Range(func(key, value any) bool {
		c.dnsKnowledge.Delete(key)
		return true
	})
	c.lruScratchMu.Lock()
	c.lruScratch = nil
	c.lruScratchMu.Unlock()
	c.bpfUpdateStopMu.Lock()
	c.bpfUpdateCh = nil
	c.bpfUpdateStop = nil
	c.bpfUpdateStopMu.Unlock()
	c.bpfRetryMu.Lock()
	c.bpfRetryWake = nil
	c.bpfRetryPending = nil
	c.bpfRetryMu.Unlock()

	return errors.Join(errs...)
}

// acquireHandleGate admits an active-plane dispatch while the controller is
// open. The double-check makes admission atomic with Close's flip: a caller
// racing the flip either observes closed and fails fast, or is counted
// before closeHandleGate's drain observes it.
func (c *DnsController) acquireHandleGate() bool {
	if c.handleClosed.Load() {
		return false
	}
	c.handleInflight.Add(1)
	if c.handleClosed.Load() {
		c.handleInflight.Add(-1)
		return false
	}
	return true
}

func (c *DnsController) releaseHandleGate() {
	c.handleInflight.Add(-1)
}

// closeHandleGate rejects new dispatches and waits for the in-flight ones so
// Close does not tear forwarders down under a running handler.
func (c *DnsController) closeHandleGate() {
	c.handleClosed.Store(true)
	if c.handleInflight.Load() == 0 {
		return
	}
	if c.log != nil {
		c.log.Debug("DnsController.Close: waiting for in-flight DNS request handlers")
	}
	timer := time.NewTimer(gracefulShutdownWaitTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for c.handleInflight.Load() > 0 {
		select {
		case <-timer.C:
			if c.log != nil {
				c.log.Warn("DnsController.Close: timeout waiting for in-flight DNS request handlers")
			}
			return
		case <-ticker.C:
		}
	}
}

// Pre-computed strings for common DNS query types to reduce allocations
// in the hot path. Fallback to strconv.Itoa for uncommon types.
var qtypeStrCache = map[uint16]string{
	dnsmessage.TypeA:     "1",
	dnsmessage.TypeNS:    "2",
	dnsmessage.TypeCNAME: "5",
	dnsmessage.TypePTR:   "12",
	dnsmessage.TypeMX:    "15",
	dnsmessage.TypeTXT:   "16",
	dnsmessage.TypeAAAA:  "28",
	dnsmessage.TypeSRV:   "33",
}
