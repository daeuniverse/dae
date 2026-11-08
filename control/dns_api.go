/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
)

// DnsLogCapacity is the bounded size of the DNS query log ring.
const DnsLogCapacity = 1024

type dnsLogRecord struct {
	id         string
	observedAt time.Time
	src        string
	question   dnsmessage.Question
	status     string
	cached     bool
	upstream   string
	elapsed    time.Duration
	answers    []dnsmessage.RR
}

// DnsLogRecordSnapshot is one entry of the DNS query log.
type DnsLogRecordSnapshot struct {
	ID         string
	ObservedAt time.Time
	Src        string
	Question   dnsmessage.Question
	Status     string
	Cached     bool
	Upstream   string
	Elapsed    time.Duration
	Answers    []dnsmessage.RR
}

// DnsCacheEntrySnapshot is one runtime DNS cache entry.
type DnsCacheEntrySnapshot struct {
	ID         string
	Domain     string
	QType      uint16
	Answers    []dnsmessage.RR
	Deadline   time.Time
	StaleUntil time.Time
	Negative   bool
}

func dnsEntryIDOfKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "de_" + hex.EncodeToString(sum[:8])
}

// dnsLogDisabled turns the DNS log off. The log only feeds the API, so with the
// API off every query would pay for a record nobody can read. The zero value
// keeps it on, so a controller built outside the daemon still records.
var dnsLogDisabled atomic.Bool

// ConfigureDnsLog sets whether DNS queries are recorded. The control plane
// calls it from api.enabled before each build.
func ConfigureDnsLog(enabled bool) {
	dnsLogDisabled.Store(!enabled)
}

func dnsLogActive() bool {
	return !dnsLogDisabled.Load()
}

func (c *DnsController) recordDnsLog(question dnsmessage.Question, req *udpRequest, status string, cached bool, upstream string, answers []dnsmessage.RR, started time.Time) {
	if !dnsLogActive() || c == nil || c.dnsControllerStore == nil || question.Name == "" {
		return
	}
	elapsed := time.Duration(0)
	if !started.IsZero() {
		elapsed = time.Since(started)
	}
	src := ""
	if req != nil {
		src = req.realSrc.String()
	}
	store := c.dnsControllerStore
	store.dnsLogMu.Lock()
	defer store.dnsLogMu.Unlock()
	store.dnsLogSeq++
	id := "dl_" + strconv.FormatUint(store.dnsLogSeq, 10)
	if store.dnsLogRing == nil {
		store.dnsLogRing = make([]dnsLogRecord, DnsLogCapacity)
	}
	record := dnsLogRecord{
		id:         id,
		observedAt: time.Now(),
		src:        src,
		question:   question,
		status:     status,
		cached:     cached,
		upstream:   upstream,
		elapsed:    elapsed,
		answers:    append([]dnsmessage.RR(nil), answers...),
	}
	if store.dnsLogLen < len(store.dnsLogRing) {
		index := (store.dnsLogStart + store.dnsLogLen) % len(store.dnsLogRing)
		store.dnsLogRing[index] = record
		store.dnsLogLen++
		return
	}
	store.dnsLogRing[store.dnsLogStart] = record
	store.dnsLogStart = (store.dnsLogStart + 1) % len(store.dnsLogRing)
}

// DnsLogEpoch identifies the store behind the DNS log.
func (c *DnsController) DnsLogEpoch() uint64 {
	if c == nil || c.dnsControllerStore == nil {
		return 0
	}
	return c.dnsLogEpoch
}

// DnsLogRecords returns the retained DNS log records, newest last.
func (c *DnsController) DnsLogRecords() []DnsLogRecordSnapshot {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	store := c.dnsControllerStore
	store.dnsLogMu.Lock()
	defer store.dnsLogMu.Unlock()
	records := make([]DnsLogRecordSnapshot, 0, store.dnsLogLen)
	for i := 0; i < store.dnsLogLen; i++ {
		record := store.dnsLogRing[(store.dnsLogStart+i)%len(store.dnsLogRing)]
		records = append(records, DnsLogRecordSnapshot{
			ID:         record.id,
			ObservedAt: record.observedAt,
			Src:        record.src,
			Question:   record.question,
			Status:     record.status,
			Cached:     record.cached,
			Upstream:   record.upstream,
			Elapsed:    record.elapsed,
			Answers:    append([]dnsmessage.RR(nil), record.answers...),
		})
	}
	return records
}

// DnsCacheEntries snapshots the runtime cache. Expired entries are included;
// the API layer filters them unless include_expired is set.
func (c *DnsController) DnsCacheEntries() []DnsCacheEntrySnapshot {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	entries := make([]DnsCacheEntrySnapshot, 0, c.dnsCacheSize.Load())
	c.dnsCache.Range(func(key, value any) bool {
		cache, ok := value.(*DnsCache)
		if !ok || cache == nil {
			return true
		}
		cacheKey, _ := key.(string)
		negative := len(cache.Answer) == 0
		entries = append(entries, DnsCacheEntrySnapshot{
			ID:       dnsEntryIDOfKey(cacheKey),
			Domain:   cache.Domain,
			QType:    cache.QType,
			Answers:  append([]dnsmessage.RR(nil), cache.Answer...),
			Deadline: cache.Deadline,
			Negative: negative,
		})
		return true
	})
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Domain != entries[j].Domain {
			return entries[i].Domain < entries[j].Domain
		}
		if entries[i].QType != entries[j].QType {
			return entries[i].QType < entries[j].QType
		}
		return entries[i].ID < entries[j].ID
	})
	return entries
}

// EvictDnsCache removes the entries selected by predicate and reports how many
// matched and were deleted.
func (c *DnsController) evictDnsCacheWhere(predicate func(key string, cache *DnsCache) bool) (matched, deleted int) {
	if c == nil || c.dnsControllerStore == nil {
		return 0, 0
	}
	type target struct {
		key   string
		cache *DnsCache
	}
	// Take the mutation lock before enumerating: a resolution that stores
	// between the enumeration and the delete would otherwise survive a flush
	// the caller was told had happened. The epoch advances on every call, even
	// when nothing matches, so an exchange already in flight cannot repopulate
	// an entry this delete/flush was asked to remove.
	c.cacheMutationMu.Lock()
	defer c.cacheMutationMu.Unlock()
	c.cacheEpoch++
	targets := make([]target, 0, 8)
	c.dnsCache.Range(func(key, value any) bool {
		cache, ok := value.(*DnsCache)
		if !ok || cache == nil {
			return true
		}
		cacheKey, _ := key.(string)
		if predicate(cacheKey, cache) {
			targets = append(targets, target{key: cacheKey, cache: cache})
		}
		return true
	})
	c.cacheProjectionMu.Lock()
	defer c.cacheProjectionMu.Unlock()
	for _, item := range targets {
		if c.dnsCache.CompareAndDelete(item.key, item.cache) {
			c.decrementDnsCacheSize()
			c.dnsCacheIndexRemove(item.key)
			c.forgetDnsKnowledge(item.key, item.cache)
			c.invokeCacheDeleteCallback(item.key, item.cache)
			deleted++
		}
	}
	return len(targets), deleted
}

// DeleteDnsCacheEntry removes one entry by its opaque ID.
func (c *DnsController) DeleteDnsCacheEntry(entryID string) int {
	_, deleted := c.evictDnsCacheWhere(func(key string, _ *DnsCache) bool {
		return dnsEntryIDOfKey(key) == entryID
	})
	return deleted
}

// DeleteDnsCacheByName removes every entry for one canonical name, optionally
// limited to the given qtypes.
func (c *DnsController) DeleteDnsCacheByName(name string, qtypes []uint16) (matched, deleted int) {
	fqdn := dnsmessage.CanonicalName(name)
	allowed := make(map[uint16]struct{}, len(qtypes))
	for _, qtype := range qtypes {
		allowed[qtype] = struct{}{}
	}
	return c.evictDnsCacheWhere(func(_ string, cache *DnsCache) bool {
		if cache.Domain != fqdn {
			return false
		}
		if len(allowed) == 0 {
			return true
		}
		_, ok := allowed[cache.QType]
		return ok
	})
}

// FlushDnsCache removes every runtime cache entry.
func (c *DnsController) FlushDnsCache() (matched, deleted int) {
	return c.evictDnsCacheWhere(func(string, *DnsCache) bool { return true })
}

// ErrDnsUpstreamNotFound reports a forced upstream that is not configured.
var ErrDnsUpstreamNotFound = stderrors.New("dns upstream not found")

// DnsQueryResultSnapshot is one record type's active query result.
type DnsQueryResultSnapshot struct {
	QType        uint16
	Cached       bool
	CacheEntryID string
	Upstream     string
	Status       string
	Elapsed      time.Duration
	Question     dnsmessage.Question
	Answers      []dnsmessage.RR
}

// QueryDns resolves one name for each requested record type through the same
// routing and cache the listener uses. bypass skips the response cache.
func (c *DnsController) QueryDns(ctx context.Context, domain string, qtypes []uint16, upstreamName string, bypass bool) ([]DnsQueryResultSnapshot, error) {
	// This entry point is the API's active query: the advertised query budget
	// must cover the upstream exchange, unlike internal health/work queries
	// that intentionally use the controller lifecycle budget.
	ctx = dnsWithCallerDeadline(ctx)
	runtime := c.runtime()
	if runtime == nil || runtime.routing == nil {
		return nil, fmt.Errorf("dns routing is not configured")
	}
	var forced *dns.Upstream
	if upstreamName != "" {
		candidate, ok, err := runtime.routing.UpstreamByName(ctx, upstreamName)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrDnsUpstreamNotFound, upstreamName)
		}
		forced = candidate
	}
	results := make([]DnsQueryResultSnapshot, 0, len(qtypes))
	for _, qtype := range qtypes {
		qname := dnsmessage.Fqdn(domain)
		question := dnsmessage.Question{Name: qname, Qtype: qtype, Qclass: dnsmessage.ClassINET}
		msg := new(dnsmessage.Msg)
		msg.SetQuestion(qname, qtype)
		msg.Id = dnsmessage.Id()

		upstreamIndex := consts.DnsRequestOutboundIndex_AsIs
		var upstream *dns.Upstream
		var err error
		if forced != nil {
			upstream = forced
			if idx, ok := runtime.routing.UpstreamIndexFor(forced); ok {
				upstreamIndex = idx
			}
		} else {
			upstreamIndex, upstream, err = runtime.routing.RequestSelect(ctx, qname, qtype)
			if err != nil {
				return nil, err
			}
		}

		result := DnsQueryResultSnapshot{QType: qtype, Question: question}
		started := time.Now()
		switch upstreamIndex {
		case consts.DnsRequestOutboundIndex_Reject:
			result.Status = "REJECT"
		case consts.DnsRequestOutboundIndex_AsIs:
			result.Status = "ASIS_UNAVAILABLE"
		default:
			if upstream != nil {
				result.Upstream = upstream.String()
			}
			baseKey := c.cacheKey(qname, qtype)
			responseCacheKey := c.responseCacheKey(baseKey, nil, upstreamIndex, upstream)
			if !bypass {
				if packed, needRefresh := c.LookupDnsRespCache_(msg, responseCacheKey, false); packed != nil {
					// The lookup just claimed the entry's refreshing flag by CAS, and
					// only backgroundRefresh clears it. Dropping needRefresh here would
					// leave the flag set for good, so every later refresh of this entry
					// would be skipped.
					if needRefresh {
						epoch := c.cacheEpochSnapshot()
						go c.backgroundRefreshAt(responseCacheKey, msg, nil, upstreamIndex, upstream, epoch)
					}
					response := new(dnsmessage.Msg)
					if unpackErr := response.Unpack(packed); unpackErr == nil {
						result.Cached = true
						result.CacheEntryID = dnsEntryIDOfKey(responseCacheKey)
						result.Status = dnsRcodeName(response.Rcode)
						result.Answers = response.Answer
						break
					}
				}
			}
			data, packErr := msg.Pack()
			if packErr != nil {
				return nil, packErr
			}
			if bypass {
				resolution, resolveErr := c.resolveDNSUpstream(ctx, 0, nil, data, upstream)
				if resolveErr != nil {
					result.Status = dnsErrorStatus(resolveErr)
					break
				}
				result.Status = dnsRcodeName(resolution.response.Rcode)
				result.Answers = resolution.response.Answer
				break
			}
			response, resolveErr := c.resolveForSingleflight(ctx, msg, nil, upstreamIndex, upstream, responseCacheKey)
			if resolveErr != nil {
				result.Status = dnsErrorStatus(resolveErr)
				break
			}
			result.CacheEntryID = dnsEntryIDOfKey(responseCacheKey)
			result.Status = dnsRcodeName(response.Rcode)
			result.Answers = response.Answer
		}
		result.Elapsed = time.Since(started)
		results = append(results, result)
	}
	return results, nil
}

func dnsRcodeName(rcode int) string {
	if name, ok := dnsmessage.RcodeToString[rcode]; ok && name != "" {
		return name
	}
	return "NOERROR"
}

func dnsErrorStatus(err error) string {
	if err == nil {
		return "NOERROR"
	}
	if stderrors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "TIMEOUT"
	}
	return "ERROR"
}

// DnsCacheSize reports the number of entries currently in the runtime cache.
func (c *DnsController) DnsCacheSize() int {
	if c == nil {
		return 0
	}
	return int(c.dnsCacheSize.Load())
}

// DnsCacheCapacity reports the configured entry limit, or 0 when unlimited.
func (c *DnsController) DnsCacheCapacity() int {
	if c == nil {
		return 0
	}
	_, _, _, maxCacheSize := c.currentOptimisticCacheConfig()
	return maxCacheSize
}
