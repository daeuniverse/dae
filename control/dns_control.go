/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

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
)

var (
	UnspecifiedAddressA          = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA       = netip.MustParseAddr("::")
	DnsCacheRouteRefreshInterval = 10 * time.Second // Aligned with health check granularity (default 30s)
	dnsCacheJanitorInterval      = 30 * time.Second
	dnsForwarderIdleTTL          = 2 * time.Minute
)

type DnsControllerOption struct {
	Log                   *logrus.Logger
	CacheAccessCallback   func(cache *DnsCache) (err error)
	CacheRemoveCallback   func(cache *DnsCache) (err error)
	NewCache              func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	BestDialerChooser     func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	TimeoutExceedCallback func(dialArgument *dialArgument, err error)
	IpVersionPrefer       int
	FixedDomainTtl        map[string]int
	ConcurrencyLimit      int
}

type DnsController struct {
	concurrencyLimiter chan struct{}

	routing     *dns.Dns
	qtypePrefer uint16

	log                 *logrus.Logger
	cacheAccessCallback func(cache *DnsCache) (err error)
	cacheRemoveCallback func(cache *DnsCache) (err error)
	newCache            func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	bestDialerChooser   func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	// timeoutExceedCallback is used to report this dialer is broken for the NetworkType
	timeoutExceedCallback func(dialArgument *dialArgument, err error)

	fixedDomainTtl map[string]int
	// dnsCache uses sync.Map for lock-free concurrent access
	dnsCache          sync.Map // map[string]*DnsCache
	dnsForwarderCache sync.Map // map[dnsForwarderKey]*cachedDnsForwarder
	sf                singleflight.Group

	janitorStop chan struct{}
	janitorDone chan struct{}
	evictorDone chan struct{}
	evictorQ    chan *DnsCache
	closeOnce   sync.Once
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	if option == nil {
		option = &DnsControllerOption{}
	}

	// Parse ip version preference.
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	// Set concurrency limit for DNS queries
	// This prevents resource exhaustion from DNS query storms.
	//
	// Best Practice (based on CoreDNS):
	// max_concurrent should be at least: expected_qps * upstream_latency
	// - Example: 1000 QPS * 0.05s latency = 50 minimum
	// - Upper bound: Each concurrent query uses ~2KB memory
	//   * 8192 concurrent = ~16MB memory footprint
	//   * 16384 concurrent = ~32MB memory footprint
	//
	// Default: 8192 (suitable for most scenarios)
	// - Handles up to ~4000 QPS with 50ms upstream latency
	// - Memory usage: ~16MB for concurrent queries
	// - Protects against DNS query storms while allowing high throughput
	//
	// Tuning Guidelines:
	// - Too low (<1000): DNS queries may be rejected under normal load
	// - Recommended (4096-16384): Suitable for most production deployments
	// - Too high (>32768): May exhaust memory under attack scenarios
	limit := option.ConcurrencyLimit
	if limit <= 0 {
		limit = 8192 // Default: handle ~4k QPS with 2s latency, ~16MB memory
	}

	controller := &DnsController{
		routing:            routing,
		qtypePrefer:        prefer,
		concurrencyLimiter: make(chan struct{}, limit),

		log:                   option.Log,
		cacheAccessCallback:   option.CacheAccessCallback,
		cacheRemoveCallback:   option.CacheRemoveCallback,
		newCache:              option.NewCache,
		bestDialerChooser:     option.BestDialerChooser,
		timeoutExceedCallback: option.TimeoutExceedCallback,

		fixedDomainTtl:    option.FixedDomainTtl,
		dnsCache:          sync.Map{},
		dnsForwarderCache: sync.Map{},

		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
		evictorDone: make(chan struct{}),
		evictorQ:    make(chan *DnsCache, 512),
	}
	controller.startDnsCacheJanitor()
	controller.startCacheEvictor()
	return controller, nil
}

func (c *DnsController) Close() error {
	c.closeOnce.Do(func() {
		if c.janitorStop != nil {
			close(c.janitorStop)
		}
		if c.janitorDone != nil {
			<-c.janitorDone
		}
		if c.evictorDone != nil {
			<-c.evictorDone
		}
	})

	var errs []error
	c.dnsForwarderCache.Range(func(key, value interface{}) bool {
		k := key.(dnsForwarderKey)
		forwarder := c.extractDnsForwarder(value)
		if forwarder != nil {
			if err := forwarder.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", k.upstream, err))
			}
		}
		c.dnsForwarderCache.Delete(k)
		return true
	})

	return errors.Join(errs...)
}

var (
	// Pre-computed strings for common DNS query types to reduce allocations
	// in the hot path. Fallback to strconv.Itoa for uncommon types.
	qtypeStrCache = map[uint16]string{
		dnsmessage.TypeA:     "1",
		dnsmessage.TypeNS:    "2",
		dnsmessage.TypeCNAME: "5",
		dnsmessage.TypePTR:   "12",
		dnsmessage.TypeMX:    "15",
		dnsmessage.TypeTXT:   "16",
		dnsmessage.TypeAAAA:  "28",
		dnsmessage.TypeSRV:   "33",
	}
)

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	// To fqdn.
	qname = dnsmessage.CanonicalName(qname)
	// Fast path: use pre-computed string for common qtypes
	if s, ok := qtypeStrCache[qtype]; ok {
		return qname + s
	}
	// Slow path: fallback to strconv for uncommon types
	return qname + strconv.Itoa(int(qtype))
}

func (c *DnsController) RemoveDnsRespCache(cacheKey string) {
	if removed, ok := c.dnsCache.LoadAndDelete(cacheKey); ok {
		if cache, ok := removed.(*DnsCache); ok {
			c.onDnsCacheEvicted(cache)
		}
	}
}

func (c *DnsController) onDnsCacheEvicted(cache *DnsCache) {
	if cache == nil || c.cacheRemoveCallback == nil {
		return
	}

	if c.evictorQ == nil {
		c.invokeCacheRemoveCallback(cache)
		return
	}

	if c.janitorStop != nil {
		select {
		case <-c.janitorStop:
			c.invokeCacheRemoveCallback(cache)
			return
		default:
		}
	}

	select {
	case c.evictorQ <- cache:
	default:
		// Keep datapath non-blocking under eviction bursts.
		go c.invokeCacheRemoveCallback(cache)
	}
}

func (c *DnsController) invokeCacheRemoveCallback(cache *DnsCache) {
	if cache == nil || c.cacheRemoveCallback == nil {
		return
	}
	if err := c.cacheRemoveCallback(cache); err != nil {
		if c.log != nil {
			c.log.Warnf("failed to remove dns cache side effects: %v", err)
		}
	}
}

func (c *DnsController) evictDnsRespCacheIfSame(cacheKey string, cache *DnsCache) {
	if cache == nil {
		return
	}
	if c.dnsCache.CompareAndDelete(cacheKey, cache) {
		c.onDnsCacheEvicted(cache)
	}
}

func (c *DnsController) evictExpiredDnsCache(now time.Time) {
	c.dnsCache.Range(func(key, value interface{}) bool {
		cacheKey, ok := key.(string)
		if !ok {
			c.dnsCache.Delete(key)
			return true
		}
		cache, ok := value.(*DnsCache)
		if !ok {
			c.dnsCache.Delete(cacheKey)
			return true
		}
		if cache.Deadline.After(now) {
			return true
		}
		c.evictDnsRespCacheIfSame(cacheKey, cache)
		return true
	})
}

func (c *DnsController) startDnsCacheJanitor() {
	go func() {
		ticker := time.NewTicker(dnsCacheJanitorInterval)
		defer ticker.Stop()
		defer close(c.janitorDone)

		for {
			select {
			case <-c.janitorStop:
				return
			case now := <-ticker.C:
				c.evictExpiredDnsCache(now)
				c.evictIdleDnsForwarders(now)
			}
		}
	}()
}

func (c *DnsController) startCacheEvictor() {
	go func() {
		defer close(c.evictorDone)
		if c.evictorQ == nil {
			return
		}

		for {
			select {
			case cache := <-c.evictorQ:
				c.invokeCacheRemoveCallback(cache)
			case <-c.janitorStop:
				for {
					select {
					case cache := <-c.evictorQ:
						c.invokeCacheRemoveCallback(cache)
					default:
						return
					}
				}
			}
		}
	}()
}

func (c *DnsController) LookupDnsRespCache(cacheKey string, ignoreFixedTtl bool) (cache *DnsCache) {
	val, ok := c.dnsCache.Load(cacheKey)
	if !ok {
		return nil
	}
	cache = val.(*DnsCache)
	now := time.Now()
	var deadline time.Time
	if !ignoreFixedTtl {
		deadline = cache.Deadline
	} else {
		deadline = cache.OriginalDeadline
	}
	// We should make sure the cache did not expire, or
	// return nil and request a new lookup to refresh the cache.
	if !deadline.After(now) {
		c.evictDnsRespCacheIfSame(cacheKey, cache)
		return nil
	}
	if c.cacheAccessCallback != nil {
		if cache.ShouldRefreshRouteBinding(now, DnsCacheRouteRefreshInterval) {
			if err := c.cacheAccessCallback(cache); err != nil {
				c.log.Warnf("failed to BatchUpdateDomainRouting: %v", err)
				return nil
			}
		}
	}
	return cache
}

// LookupDnsRespCache_ will modify the msg in place.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) (resp []byte) {
	cache := c.LookupDnsRespCache(cacheKey, ignoreFixedTtl)
	if cache != nil {
		cache.FillInto(msg)
		msg.Compress = true
		b, err := msg.Pack()
		if err != nil {
			c.log.Warnf("failed to pack: %v", err)
			return nil
		}
		return b
	}
	return nil
}

// NormalizeAndCacheDnsResp_ handle DNS resp in place.
func (c *DnsController) NormalizeAndCacheDnsResp_(msg *dnsmessage.Msg) (err error) {
	// Check healthy resp.
	if !msg.Response || len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]

	// Check suc resp.
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return nil
	}

	// Get TTL.
	var ttl uint32
	for i := range msg.Answer {
		if ttl == 0 {
			ttl = msg.Answer[i].Header().Ttl
			break
		}
	}
	if ttl == 0 {
		// It seems no answers (NXDomain).
		ttl = minFirefoxCacheTtl
	}

	// Check req type.
	switch q.Qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Set ttl.
	for i := range msg.Answer {
		// Set TTL = zero. This requests applications must resend every request.
		// However, it may be not defined in the standard.
		msg.Answer[i].Header().Ttl = 0
	}

	// Check if request A/AAAA record.
	var reqIpRecord bool
loop:
	for i := range msg.Question {
		switch msg.Question[i].Qtype {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			reqIpRecord = true
			break loop
		}
	}
	if !reqIpRecord {
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Update DnsCache.
	if err = c.updateDnsCache(msg, ttl, &q); err != nil {
		return err
	}
	// Pack to get newData.
	return nil
}

func (c *DnsController) updateDnsCache(msg *dnsmessage.Msg, ttl uint32, q *dnsmessage.Question) error {
	// Update DnsCache.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"_qname": q.Name,
			"rcode":  msg.Rcode,
			"ans":    FormatDnsRsc(msg.Answer),
		}).Tracef("Update DNS record cache")
	}

	if err := c.UpdateDnsCacheTtl(q.Name, q.Qtype, msg.Answer, int(ttl)); err != nil {
		return err
	}
	return nil
}

type daedlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time)

func (c *DnsController) __updateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadlineFunc daedlineFunc) (err error) {
	var fqdn string
	if strings.HasSuffix(host, ".") {
		fqdn = strings.ToLower(host)
		host = host[:len(host)-1]
	} else {
		fqdn = dnsmessage.CanonicalName(host)
	}
	// Bypass pure IP.
	if _, err = netip.ParseAddr(host); err == nil {
		return nil
	}

	now := time.Now()
	deadline, originalDeadline := deadlineFunc(now, host)

	cacheKey := c.cacheKey(fqdn, dnsTyp)

	// Atomic cache update: create new cache entry and store it atomically
	// This allows concurrent updates without blocking each other
	newCache, err := c.newCache(fqdn, answers, deadline, originalDeadline)
	if err != nil {
		return err
	}

	// Store atomically - concurrent writes don't block each other
	c.dnsCache.Store(cacheKey, newCache)

	if err = c.cacheAccessCallback(newCache); err != nil {
		return err
	}
	newCache.MarkRouteBindingRefreshed(now)

	return nil
}

func (c *DnsController) UpdateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadline time.Time) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		if fixedTtl, ok := c.fixedDomainTtl[host]; ok {
			/// NOTICE: Cannot set TTL accurately.
			if now.Sub(deadline).Seconds() > float64(fixedTtl) {
				deadline := now.Add(time.Duration(fixedTtl) * time.Second)
				return deadline, deadline
			}
		}
		return deadline, deadline
	})
}

func (c *DnsController) UpdateDnsCacheTtl(host string, dnsTyp uint16, answers []dnsmessage.RR, ttl int) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		originalDeadline = now.Add(time.Duration(ttl) * time.Second)
		if fixedTtl, ok := c.fixedDomainTtl[host]; ok {
			return now.Add(time.Duration(fixedTtl) * time.Second), originalDeadline
		} else {
			return originalDeadline, originalDeadline
		}
	})
}

type udpRequest struct {
	realSrc       netip.AddrPort
	realDst       netip.AddrPort
	src           netip.AddrPort
	lConn         *net.UDPConn
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	bestDialer   *dialer.Dialer
	bestOutbound *outbound.DialerGroup
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

type dnsForwarderKey struct {
	upstream     string
	dialArgument dialArgument
}

type cachedDnsForwarder struct {
	forwarder    DnsForwarder
	lastUsedNano atomic.Int64
	inFlight     atomic.Int32
}

func newCachedDnsForwarder(forwarder DnsForwarder, now time.Time) *cachedDnsForwarder {
	entry := &cachedDnsForwarder{forwarder: forwarder}
	entry.touch(now)
	return entry
}

func (c *cachedDnsForwarder) touch(now time.Time) {
	c.lastUsedNano.Store(now.UnixNano())
}

func (c *cachedDnsForwarder) beginUse() {
	c.inFlight.Add(1)
	c.touch(time.Now())
}

func (c *cachedDnsForwarder) endUse() {
	c.touch(time.Now())
	c.inFlight.Add(-1)
}

var dnsForwarderFactory = newDnsForwarder

func (c *DnsController) extractDnsForwarder(value interface{}) DnsForwarder {
	switch v := value.(type) {
	case *cachedDnsForwarder:
		return v.forwarder
	case DnsForwarder:
		return v
	default:
		return nil
	}
}

func (c *DnsController) evictIdleDnsForwarders(now time.Time) {
	if dnsForwarderIdleTTL <= 0 {
		return
	}

	nowNano := now.UnixNano()
	idleNano := dnsForwarderIdleTTL.Nanoseconds()
	var toClose []DnsForwarder

	c.dnsForwarderCache.Range(func(key, value interface{}) bool {
		k, ok := key.(dnsForwarderKey)
		if !ok {
			c.dnsForwarderCache.Delete(key)
			return true
		}

		entry, ok := value.(*cachedDnsForwarder)
		if !ok {
			if forwarder := c.extractDnsForwarder(value); forwarder != nil {
				if c.dnsForwarderCache.CompareAndDelete(k, value) {
					toClose = append(toClose, forwarder)
				}
			} else {
				c.dnsForwarderCache.Delete(k)
			}
			return true
		}

		if entry.inFlight.Load() > 0 {
			return true
		}
		lastUsedNano := entry.lastUsedNano.Load()
		if lastUsedNano == 0 || nowNano-lastUsedNano <= idleNano {
			return true
		}

		if c.dnsForwarderCache.CompareAndDelete(k, entry) {
			toClose = append(toClose, entry.forwarder)
		}
		return true
	})

	for _, forwarder := range toClose {
		if forwarder == nil {
			continue
		}
		if err := forwarder.Close(); err != nil && c.log != nil {
			c.log.WithError(err).Debugln("failed to close idle dns forwarder")
		}
	}
}

func (c *DnsController) reportDnsForwardFailure(dialArg *dialArgument, err error) {
	if c.timeoutExceedCallback == nil || dialArg == nil || err == nil {
		return
	}
	// Caller-driven cancellation should not mark a dialer as unavailable.
	if errors.Is(err, context.Canceled) {
		return
	}
	c.timeoutExceedCallback(dialArg, err)
}

func (c *DnsController) getOrCreateDnsForwarder(upstream *dns.Upstream, dialArg *dialArgument) (*cachedDnsForwarder, error) {
	key := dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArg}
	now := time.Now()

	for i := 0; i < 3; i++ {
		if cached, ok := c.dnsForwarderCache.Load(key); ok {
			switch entry := cached.(type) {
			case *cachedDnsForwarder:
				entry.touch(now)
				return entry, nil
			case DnsForwarder:
				wrapped := newCachedDnsForwarder(entry, now)
				if c.dnsForwarderCache.CompareAndSwap(key, cached, wrapped) {
					return wrapped, nil
				}
				continue
			default:
				c.dnsForwarderCache.CompareAndDelete(key, cached)
				continue
			}
		}
		break
	}

	createdForwarder, createErr := dnsForwarderFactory(upstream, *dialArg, c.log)
	if createErr != nil {
		return nil, createErr
	}
	created := newCachedDnsForwarder(createdForwarder, now)

	actual, loaded := c.dnsForwarderCache.LoadOrStore(key, created)
	if loaded {
		// Another goroutine won the race; close the redundant instance.
		_ = createdForwarder.Close()
		if entry, ok := actual.(*cachedDnsForwarder); ok {
			entry.touch(now)
			return entry, nil
		}
		if old, ok := actual.(DnsForwarder); ok {
			wrapped := newCachedDnsForwarder(old, now)
			if c.dnsForwarderCache.CompareAndSwap(key, actual, wrapped) {
				return wrapped, nil
			}
			if latest, ok := c.dnsForwarderCache.Load(key); ok {
				if latestEntry, ok := latest.(*cachedDnsForwarder); ok {
					latestEntry.touch(now)
					return latestEntry, nil
				}
			}
		}
		return nil, fmt.Errorf("unexpected cached dns forwarder type: %T", actual)
	}
	return created, nil
}

func (c *DnsController) forwardWithDialArg(ctx context.Context, upstream *dns.Upstream, dialArg *dialArgument, data []byte) (*dnsmessage.Msg, error) {
	entry, err := c.getOrCreateDnsForwarder(upstream, dialArg)
	if err != nil {
		return nil, err
	}
	entry.beginUse()
	defer entry.endUse()

	respMsg, err := entry.forwarder.ForwardDNS(ctx, data)
	if err != nil {
		c.reportDnsForwardFailure(dialArg, err)
		return nil, err
	}
	return respMsg, nil
}

func (c *DnsController) forwardWithFallback(
	ctx context.Context,
	req *udpRequest,
	upstream *dns.Upstream,
	primaryDialArg *dialArgument,
	data []byte,
) (respMsg *dnsmessage.Msg, usedDialArg *dialArgument, err error) {
	respMsg, err = c.forwardWithDialArg(ctx, upstream, primaryDialArg, data)
	if err == nil {
		return respMsg, primaryDialArg, nil
	}

	primaryErr := err

	// For tcp+udp upstream, perform immediate same-request fallback:
	// prefer UDP, fallback to TCP on failure.
	if upstream == nil || upstream.Scheme != dns.UpstreamScheme_TCP_UDP || primaryDialArg.l4proto != consts.L4ProtoStr_UDP {
		return nil, primaryDialArg, primaryErr
	}

	fallbackUpstream := *upstream
	fallbackUpstream.Scheme = dns.UpstreamScheme_TCP

	fallbackDialArg, chooseErr := c.bestDialerChooser(req, &fallbackUpstream)
	if chooseErr != nil {
		return nil, primaryDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback select failed: %v", primaryErr, chooseErr)
	}
	if fallbackDialArg == nil || fallbackDialArg.l4proto != consts.L4ProtoStr_TCP {
		return nil, primaryDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback select returned invalid network", primaryErr)
	}

	if c.log != nil && c.log.IsLevelEnabled(logrus.DebugLevel) {
		c.log.WithFields(logrus.Fields{
			"upstream": upstream.String(),
			"from":     primaryDialArg.l4proto,
			"to":       fallbackDialArg.l4proto,
		}).Debugln("DNS fallback to TCP after UDP failure")
	}

	respMsg, err = c.forwardWithDialArg(ctx, upstream, fallbackDialArg, data)
	if err != nil {
		return nil, fallbackDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback failed: %v", primaryErr, err)
	}

	return respMsg, fallbackDialArg, nil
}

func (c *DnsController) Handle_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	return c.HandleWithResponseWriter_(dnsMessage, req, nil)
}

func (c *DnsController) HandleWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	// Try to acquire semaphore
	select {
	case c.concurrencyLimiter <- struct{}{}:
		defer func() { <-c.concurrencyLimiter }()
	default:
		if responseWriter != nil || (req != nil && req.lConn != nil) {
			if sendErr := c.sendRefusedWithResponseWriter_(dnsMessage, req, responseWriter); sendErr != nil {
				return errors.Join(ErrDNSQueryConcurrencyLimitExceeded, sendErr)
			}
		}
		return ErrDNSQueryConcurrencyLimitExceeded
	}

	// Singleflight Key Generation
	// We use qname + qtype as the key. We don't distinguish between clients (client IP) here,
	// because the result should be cacheable and shareable globally (standard DNS behavior).
	// NOTE: If EDNS0 Client Subnet (ECS) is involved later, the key MUST include the subnet.
	// Currently dae doesn't explicitly handle ECS for differentiation in 'resolve_',
	// so merging requests is safe.
	var sfKey string
	if len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		sfKey = c.cacheKey(q.Name, q.Qtype)
	}

	if sfKey != "" && !dnsMessage.Response {
		// execute via singleflight
		res, err, _ := c.sf.Do(sfKey, func() (interface{}, error) {
			// This goroutine performs the actual resolution.
			// It returns the DNS response message, or an error.
			return c.resolveForSingleflight(dnsMessage, req)
		})

		if err != nil {
			return err
		}

		// res is the *dnsmessage.Msg
		respMsg := res.(*dnsmessage.Msg)

		// Write response.
		// For packet-send path, avoid deep-copying DNS message and just patch ID in packed bytes.
		if responseWriter != nil {
			respMsgUnique := respMsg.Copy()
			respMsgUnique.Id = dnsMessage.Id
			return responseWriter.WriteMsg(respMsgUnique)
		}

		// If no responseWriter (internal UDP path), pack and send directly.
		data, err := respMsg.Pack()
		if err != nil {
			return fmt.Errorf("pack DNS packet: %w", err)
		}
		if len(data) >= 2 {
			binary.BigEndian.PutUint16(data[:2], dnsMessage.Id)
		}
		if req == nil || req.lConn == nil {
			return fmt.Errorf("dns request connection is nil for singleflight response")
		}
		if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
			return err
		}
		return nil
	}

	return c.handleWithResponseWriterInternal(dnsMessage, req, responseWriter)
}

func (c *DnsController) resolveForSingleflight(dnsMessage *dnsmessage.Msg, req *udpRequest) (*dnsmessage.Msg, error) {
	// We need a way to capture the response message from the resolution process.
	// Currently `handleWithResponseWriterInternal` writes to a writer or sends a packet.
	// We need to refactor or spy on it.

	// Since refactoring everything is risky, let's use a Fake ResponseWriter to capture the message.
	capturer := &msgCapturer{}
	err := c.handleWithResponseWriterInternal(dnsMessage, req, capturer)
	if err != nil {
		return nil, err
	}
	if capturer.msg == nil {
		return nil, fmt.Errorf("no response captured during singleflight resolution")
	}
	return capturer.msg, nil
}

type msgCapturer struct {
	msg *dnsmessage.Msg
}

func (m *msgCapturer) LocalAddr() net.Addr  { return nil }
func (m *msgCapturer) RemoteAddr() net.Addr { return nil }
func (m *msgCapturer) WriteMsg(msg *dnsmessage.Msg) error {
	m.msg = msg
	return nil
}
func (m *msgCapturer) Write(b []byte) (int, error) { return 0, nil }
func (m *msgCapturer) Close() error                { return nil }
func (m *msgCapturer) TsigStatus() error           { return nil }
func (m *msgCapturer) TsigTimersOnly(bool)         {}
func (m *msgCapturer) Hijack()                     {}

// Renamed from HandleWithResponseWriter_ to internal to avoid recursion loop with SF
func (c *DnsController) handleWithResponseWriterInternal(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		qname = dnsMessage.Question[0].Name
		qtype = dnsMessage.Question[0].Qtype
	}

	// Check ip version preference and qtype.
	switch qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			return c.handleWithResponseWriter_(dnsMessage, req, true, responseWriter)
		}
	default:
		return c.handleWithResponseWriter_(dnsMessage, req, true, responseWriter)
	}

	// Try to make both A and AAAA lookups.
	dnsMessage2 := dnsMessage.Copy()
	dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
	var qtype2 uint16
	switch qtype {
	case dnsmessage.TypeA:
		qtype2 = dnsmessage.TypeAAAA
	case dnsmessage.TypeAAAA:
		qtype2 = dnsmessage.TypeA
	default:
		return fmt.Errorf("unexpected qtype path")
	}
	dnsMessage2.Question[0].Qtype = qtype2

	needWaitSecondary := c.qtypePrefer != qtype
	var done chan struct{}
	if needWaitSecondary {
		done = make(chan struct{}, 1)
	}
	go func() {
		defer func() {
			// Ensure the goroutine always signals completion, even if it panics.
			if r := recover(); r != nil {
				c.log.Errorf("Goroutine panic recovered in HandleWithResponseWriter_: %v\n%v", r, string(debug.Stack()))
			}
			if done != nil {
				done <- struct{}{}
			}
		}()
		_ = c.handleWithResponseWriter_(dnsMessage2, req, false, responseWriter)
	}()
	err = c.handleWithResponseWriter_(dnsMessage, req, false, responseWriter)

	// If current query type is already preferred, the final response decision does not
	// depend on the secondary lookup result. Avoid waiting here to reduce serial latency.
	// The secondary lookup still runs asynchronously to keep cache warming behavior.
	if needWaitSecondary {
		<-done
	}
	if err != nil {
		return err
	}

	// Join results and consider whether to response.
	resp := c.LookupDnsRespCache_(dnsMessage, c.cacheKey(qname, qtype), true)
	if resp == nil {
		// resp is not valid.
		c.log.WithFields(logrus.Fields{
			"qname": qname,
		}).Tracef("Reject %v due to resp not valid", qtype)
		return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
	}
	// resp is valid.
	cache2 := c.LookupDnsRespCache(c.cacheKey(qname, qtype2), true)
	if c.qtypePrefer == qtype || cache2 == nil || !cache2.IncludeAnyIp() {
		if responseWriter != nil {
			var respMsg dnsmessage.Msg
			if err = respMsg.Unpack(resp); err != nil {
				return fmt.Errorf("failed to unpack DNS response: %w", err)
			}
			return responseWriter.WriteMsg(&respMsg)
		}
		return sendPkt(c.log, resp, req.realDst, req.realSrc, req.src, req.lConn)
	} else {
		return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
	}
}

func (c *DnsController) handle_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
) (err error) {
	return c.handleWithResponseWriter_(dnsMessage, req, needResp, nil)
}

func (c *DnsController) handleWithResponseWriter_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
	responseWriter dnsmessage.ResponseWriter,
) (err error) {
	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
	}

	// Route request.
	upstreamIndex, upstream, err := c.routing.RequestSelect(qname, qtype)
	if err != nil {
		return err
	}

	cacheKey := c.cacheKey(qname, qtype)

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		// Reject with empty answer.
		c.RemoveDnsRespCache(cacheKey)
		return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
	}

	if resp := c.LookupDnsRespCache_(dnsMessage, cacheKey, false); resp != nil {
		// Send cache to client directly.
		if needResp {
			if err = c.writeCachedResponse(resp, req, responseWriter); err != nil {
				return err
			}
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 {
			q := dnsMessage.Question[0]
			if req != nil {
				c.log.Debugf("UDP(DNS) %v <-> Cache: %v %v",
					RefineSourceToShow(req.realSrc, req.realDst.Addr()), strings.ToLower(q.Name), QtypeToString(q.Qtype),
				)
			} else {
				c.log.Debugf("UDP(DNS) Cache: %v %v", strings.ToLower(q.Name), QtypeToString(q.Qtype))
			}
		}
		return nil
	}

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := upstreamIndex.String()
		if upstream != nil {
			upstreamName = upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}

	// Re-pack DNS packet.
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return c.dialSend(0, req, data, dnsMessage.Id, upstream, needResp)
}

// sendReject_ send empty answer.
func (c *DnsController) sendReject_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	return c.sendRejectWithResponseWriter_(dnsMessage, req, nil)
}

func (c *DnsController) writeCachedResponse(resp []byte, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	if responseWriter != nil {
		var respMsg dnsmessage.Msg
		if err := respMsg.Unpack(resp); err != nil {
			return fmt.Errorf("failed to unpack DNS response: %w", err)
		}
		return responseWriter.WriteMsg(&respMsg)
	}

	if req == nil || req.lConn == nil {
		return fmt.Errorf("dns request connection is nil for cached response")
	}
	if err := sendPkt(c.log, resp, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
		return fmt.Errorf("failed to write cached DNS resp: %w", err)
	}
	return nil
}

// sendRefusedWithResponseWriter_ sends REFUSED response when overload protection is triggered.
func (c *DnsController) sendRefusedWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeRefused
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Refused due to concurrency limit")
	}

	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	if req == nil || req.lConn == nil {
		return nil
	}

	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
		return err
	}
	return nil
}

// sendRejectWithResponseWriter_ send empty answer using response writer.
func (c *DnsController) sendRejectWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeSuccess
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Reject")
	}
	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
		return err
	}
	return nil
}

func (c *DnsController) dialSend(invokingDepth int, req *udpRequest, data []byte, id uint16, upstream *dns.Upstream, needResp bool) (err error) {
	if invokingDepth >= MaxDnsLookupDepth {
		return fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}

	upstreamName := "asis"
	if upstream == nil {
		// As-is.

		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		var ip46 netutils.Ip46
		if req.realDst.Addr().Is4() {
			ip46.Ip4 = req.realDst.Addr()
		} else {
			ip46.Ip6 = req.realDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.realDst.Addr().String(),
			Port:     req.realDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
	dialArgument, err := c.bestDialerChooser(req, upstream)
	if err != nil {
		return err
	}

	// Dial and send.
	var respMsg *dnsmessage.Msg
	usedDialArgument := dialArgument

	ctxDial, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()

	respMsg, usedDialArgument, err = c.forwardWithFallback(ctxDial, req, upstream, dialArgument, data)
	if err != nil {
		return err
	}

	networkType := &dialer.NetworkType{
		L4Proto:   usedDialArgument.l4proto,
		IpVersion: usedDialArgument.ipversion,
		IsDns:     true,
	}

	// Route response.
	upstreamIndex, nextUpstream, err := c.routing.ResponseSelect(respMsg, upstream)
	if err != nil {
		return err
	}
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		// Accept.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		// Reject the request with empty answer.
		respMsg.Answer = nil
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
		// We also cache response reject.
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      respMsg.Question,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.dialSend(invokingDepth+1, req, data, id, nextUpstream, needResp)
	}
	if upstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.InfoLevel) {
		var (
			qname string
			qtype string
		)
		if len(respMsg.Question) > 0 {
			q := respMsg.Question[0]
			qname = strings.ToLower(q.Name)
			qtype = QtypeToString(q.Qtype)
		}
		fields := logrus.Fields{
			"network":  networkType.String(),
			"outbound": usedDialArgument.bestOutbound.Name,
			"policy":   usedDialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   usedDialArgument.bestDialer.Property().Name,
			"_qname":   qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch upstreamIndex {
		case consts.DnsResponseOutboundIndex_Accept:
			c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(usedDialArgument.bestTarget))
		case consts.DnsResponseOutboundIndex_Reject:
			c.log.WithFields(fields).Infof("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr()))
		default:
			return fmt.Errorf("unknown upstream: %v", upstreamIndex.String())
		}
	}
	if err = c.NormalizeAndCacheDnsResp_(respMsg); err != nil {
		return err
	}
	if needResp {
		// Keep the id the same with request.
		respMsg.Id = id
		respMsg.Compress = true
		data, err = respMsg.Pack()
		if err != nil {
			return err
		}
		if err = sendPkt(c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
			return err
		}
	}
	return nil
}
