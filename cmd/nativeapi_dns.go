/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	stderrors "errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/control"
	dnsmessage "github.com/miekg/dns"
)

func (p *nativeAPIProvider) activeDnsController() (*control.DnsController, error) {
	plane, err := p.activeControlPlane()
	if err != nil {
		return nil, err
	}
	controller := plane.ActiveDnsController()
	if controller == nil {
		return nil, nativeapi.NewAPIError(503, "temporarily_unavailable", "dns controller is not available")
	}
	return controller, nil
}

func dnsTypeName(qtype uint16) string {
	if name, ok := dnsmessage.TypeToString[qtype]; ok && name != "" {
		return name
	}
	return "TYPE" + strconv.Itoa(int(qtype))
}

func dnsClassName(class uint16) string {
	if name, ok := dnsmessage.ClassToString[class]; ok && name != "" {
		return name
	}
	return "CLASS" + strconv.Itoa(int(class))
}

func nativeDnsAnswers(records []dnsmessage.RR) []nativeapi.DnsAnswer {
	answers := make([]nativeapi.DnsAnswer, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		header := record.Header()
		answers = append(answers, nativeapi.DnsAnswer{
			Name:  header.Name,
			Type:  dnsTypeName(header.Rrtype),
			Class: dnsClassName(header.Class),
			TTL:   header.Ttl,
			Data:  dnsRecordData(record),
		})
	}
	return answers
}

func dnsRecordData(record dnsmessage.RR) string {
	fields := strings.SplitN(record.String(), "\t", 5)
	if len(fields) == 5 {
		return fields[4]
	}
	return record.String()
}

func parseDnsTypes(values []string) (map[uint16]struct{}, error) {
	if len(values) == 0 {
		return nil, nil
	}
	set := make(map[uint16]struct{}, len(values))
	for _, value := range values {
		qtype, ok := dnsmessage.StringToType[strings.ToUpper(value)]
		if !ok {
			return nil, nativeapi.NewAPIError(422, "unsupported_value", "unsupported record type: "+value)
		}
		set[qtype] = struct{}{}
	}
	return set, nil
}

// DnsCache serves the runtime DNS cache.
func (p *nativeAPIProvider) DnsCache(ctx context.Context, filter nativeapi.DnsCacheFilter) (nativeapi.DnsCacheList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.DnsCacheList{}, err
	}
	controller, err := p.activeDnsController()
	if err != nil {
		return nativeapi.DnsCacheList{}, err
	}
	now := time.Now()
	observed := now.UTC().Format(time.RFC3339)
	types, err := parseDnsTypes(filter.Types)
	if err != nil {
		return nativeapi.DnsCacheList{}, err
	}
	name := ""
	if filter.Name != "" {
		name = dnsmessage.CanonicalName(filter.Name)
	}
	domain := ""
	if filter.Domain != "" {
		domain = dnsmessage.CanonicalName(filter.Domain)
	}

	entries := make([]nativeapi.DnsCacheEntry, 0, 32)
	for _, entry := range controller.DnsCacheEntries() {
		if entry.Domain == "" {
			continue
		}
		if name != "" && entry.Domain != name {
			continue
		}
		if domain != "" && !strings.Contains(entry.Domain, domain) {
			continue
		}
		if len(types) > 0 {
			if _, ok := types[entry.QType]; !ok {
				continue
			}
		}
		expired := !entry.Deadline.IsZero() && !entry.Deadline.After(now)
		if expired && !filter.IncludeExpired {
			continue
		}
		status := "positive"
		if entry.Negative {
			status = "negative"
		}
		expiresAt := entry.Deadline
		if expiresAt.IsZero() {
			expiresAt = now
		}
		entries = append(entries, nativeapi.DnsCacheEntry{
			EntryID:   entry.ID,
			Domain:    entry.Domain,
			Type:      dnsTypeName(entry.QType),
			Class:     "IN",
			Status:    status,
			Answers:   nativeDnsAnswers(entry.Answers),
			ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		})
	}
	// The cache is a map, so the walk needs one deterministic order to make the
	// keyset anchor meaningful.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Domain != entries[j].Domain {
			return entries[i].Domain < entries[j].Domain
		}
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].EntryID < entries[j].EntryID
	})
	instance := p.status.snapshot().InstanceID
	// The bind names the filter set and limit, never the cache revision: every
	// store bumps the revision, so binding it made page 2 unreachable on a busy
	// resolver (and reported the mismatch as 400 instead of the contract's 410
	// snapshot_expired).
	bind := pageCursorBind(name, domain, filter.Types, filter.IncludeExpired, filter.Limit)
	after, expectNext := "", ""
	if filter.Cursor != "" {
		parsed, next, _, err := decodePageCursorNext(instance, "dns_cache", bind, filter.Cursor, now)
		if err != nil {
			return nativeapi.DnsCacheList{}, err
		}
		after, expectNext = parsed, next
	}
	// A cache entry can expire or be evicted between two pages, which would
	// silently skip every unread entry that disappeared. The walk therefore
	// checks the successor the previous page promised, exactly like the ring
	// backed lists; there is no oldest-key guard because the cache is ordered by
	// name, not by eviction order.
	page, next, err := pageAfterExpecting(entries, func(entry nativeapi.DnsCacheEntry) string { return entry.EntryID },
		after, expectNext, "", filter.Limit, instance, "dns_cache", bind, now)
	if err != nil {
		return nativeapi.DnsCacheList{}, err
	}
	list := nativeapi.DnsCacheList{
		ObservedAt: observed,
		Coverage: nativeapi.DnsCacheCoverage{
			Positive:   true,
			Negative:   true,
			Persistent: false,
		},
		Entries:    page,
		Total:      uint64(len(entries)),
		NextCursor: next,
	}
	usage := &nativeapi.DnsCacheUsage{Entries: strconv.FormatUint(uint64(controller.DnsCacheSize()), 10)}
	if capacity := controller.DnsCacheCapacity(); capacity > 0 {
		value := strconv.Itoa(capacity)
		usage.EntryCapacity = &value
	}
	list.Usage = usage
	return list, nil
}

// DeleteDnsCacheByName deletes the entries for one exact name.
func (p *nativeAPIProvider) DeleteDnsCacheByName(ctx context.Context, name string, types []string) (nativeapi.DeleteMatchingCount, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.DeleteMatchingCount{}, err
	}
	controller, err := p.activeDnsController()
	if err != nil {
		return nativeapi.DeleteMatchingCount{}, err
	}
	parsedTypes, err := parseDnsTypes(types)
	if err != nil {
		return nativeapi.DeleteMatchingCount{}, err
	}
	qtypes := make([]uint16, 0, len(parsedTypes))
	for qtype := range parsedTypes {
		qtypes = append(qtypes, qtype)
	}
	matched, deleted := controller.DeleteDnsCacheByName(name, qtypes)
	return nativeapi.DeleteMatchingCount{Matched: uint64(matched), Deleted: uint64(deleted)}, nil
}

// DeleteDnsCacheEntry deletes one cache entry by ID.
func (p *nativeAPIProvider) DeleteDnsCacheEntry(ctx context.Context, entryID string) (nativeapi.DeleteCount, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.DeleteCount{}, err
	}
	controller, err := p.activeDnsController()
	if err != nil {
		return nativeapi.DeleteCount{}, err
	}
	return nativeapi.DeleteCount{Deleted: uint64(controller.DeleteDnsCacheEntry(entryID))}, nil
}

// FlushDnsCache clears the whole runtime cache.
func (p *nativeAPIProvider) FlushDnsCache(ctx context.Context) (nativeapi.DeleteMatchingCount, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.DeleteMatchingCount{}, err
	}
	controller, err := p.activeDnsController()
	if err != nil {
		return nativeapi.DeleteMatchingCount{}, err
	}
	matched, deleted := controller.FlushDnsCache()
	return nativeapi.DeleteMatchingCount{Matched: uint64(matched), Deleted: uint64(deleted)}, nil
}

// dnsLogNameMatches applies the contract's substring name filter. The filter is
// matched literally against the canonical question name, lower-cased because DNS
// names are case-insensitive: canonicalising the filter too appended a dot, so
// name=exam became exam. and never matched example.com. Substring means
// substring, not a suffix match.
func dnsLogNameMatches(questionName, name string) bool {
	if name == "" {
		return true
	}
	return strings.Contains(dnsmessage.CanonicalName(questionName), strings.ToLower(name))
}

// DnsLog serves the bounded DNS query log.
func (p *nativeAPIProvider) DnsLog(ctx context.Context, filter nativeapi.DnsLogFilter) (nativeapi.DnsLogList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.DnsLogList{}, err
	}
	controller, err := p.activeDnsController()
	if err != nil {
		return nativeapi.DnsLogList{}, err
	}
	records := controller.DnsLogRecords()
	total := len(records)
	types, err := parseDnsTypes(filter.Types)
	if err != nil {
		return nativeapi.DnsLogList{}, err
	}
	// The name filter is a substring of the canonical question name, so pass
	// it through untouched: canonicalising it appended a trailing dot and
	// turned name=exam into a filter that could never match example.com.
	name := filter.Name
	matched := make([]nativeapi.DnsLogRecord, 0, len(records))
	for i := len(records) - 1; i >= 0; i-- {
		record := records[i]
		if !dnsLogNameMatches(record.Question.Name, name) {
			continue
		}
		if len(types) > 0 {
			if _, ok := types[record.Question.Qtype]; !ok {
				continue
			}
		}
		if filter.Src != "" && !dnsLogSrcMatches(record.Src, filter.Src) {
			continue
		}
		var src *string
		if record.Src != "" {
			value := record.Src
			src = &value
		}
		var upstream *string
		if record.Upstream != "" {
			value := record.Upstream
			upstream = &value
		}
		matched = append(matched, nativeapi.DnsLogRecord{
			ID:         record.ID,
			ObservedAt: record.ObservedAt.UTC().Format(time.RFC3339),
			Src:        src,
			Question: nativeapi.DnsQuestion{
				Name: record.Question.Name,
				Type: dnsTypeName(record.Question.Qtype),
			},
			Status:    record.Status,
			Cached:    record.Cached,
			Upstream:  upstream,
			Route:     nativeapi.DnsRoute{Source: "dns.routing", Rule: nil},
			ElapsedMs: uint64(max(record.Elapsed.Milliseconds(), 0)),
			Answers:   nativeDnsAnswers(record.Answers),
		})
	}
	now := time.Now()
	instance := p.status.snapshot().InstanceID
	bind := pageCursorBind(name, filter.Types, filter.Src, filter.Limit)
	// The epoch ties a cursor to this log: a replaced store restarts the ids.
	kind := "dns_log:" + strconv.FormatUint(controller.DnsLogEpoch(), 10)
	after, expectNext, oldest := "", "", ""
	if filter.Cursor != "" {
		var err error
		after, expectNext, oldest, err = decodePageCursorNext(instance, kind, bind, filter.Cursor, now)
		if err != nil {
			return nativeapi.DnsLogList{}, err
		}
	}
	page, next, err := pageAfterExpecting(matched, func(record nativeapi.DnsLogRecord) string { return record.ID }, after, expectNext, oldest, filter.Limit, instance, kind, bind, now)
	if err != nil {
		return nativeapi.DnsLogList{}, err
	}
	list := nativeapi.DnsLogList{
		ObservedAt: now.UTC().Format(time.RFC3339),
		Total:      uint64(total),
		Records:    page,
		NextCursor: next,
	}
	return list, nil
}

// DnsRules projects the running DNS rule dictionary.
func (p *nativeAPIProvider) DnsRules(ctx context.Context) (nativeapi.DnsRuleList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.DnsRuleList{}, err
	}
	plane, err := p.activeControlPlane()
	if err != nil {
		return nativeapi.DnsRuleList{}, err
	}
	snapshot := plane.SnapshotDnsRules()
	list := nativeapi.DnsRuleList{GenerationID: snapshot.GenerationID}
	list.Request = nativeDnsRules("request", snapshot.Request, snapshot.RequestFallback)
	list.Response = nativeDnsRules("response", snapshot.Response, snapshot.ResponseFallback)
	return list, nil
}

func nativeDnsRules(kind string, rules []control.DnsRuleSnapshot, fallback control.DnsRuleSnapshot) []nativeapi.DnsRoutingRule {
	result := make([]nativeapi.DnsRoutingRule, 0, len(rules)+1)
	for index, rule := range rules {
		action := nativeDnsAction(kind, rule.Action)
		result = append(result, nativeapi.DnsRoutingRule{
			RuleID:     "dns-" + kind + ":" + strconv.Itoa(index),
			Index:      uint64(index),
			Expression: rule.Expression,
			Action:     action,
			Upstream:   nativeDnsUpstreamOf(action, rule.Action, rule.Upstream),
			Kind:       "rule",
		})
	}
	fallbackAction := nativeDnsAction(kind, fallback.Action)
	result = append(result, nativeapi.DnsRoutingRule{
		RuleID:     "dns-" + kind + ":fallback",
		Index:      uint64(len(result)),
		Expression: fallback.Expression,
		Action:     fallbackAction,
		Upstream:   nativeDnsUpstreamOf(fallbackAction, fallback.Action, fallback.Upstream),
		Kind:       "fallback",
	})
	return result
}

func nativeDnsAction(kind, action string) string {
	action = strings.ToLower(action)
	switch kind {
	case "request":
		switch action {
		case "upstream", "asis", "reject":
			return action
		}
		// Anything else is a configured upstream name: the rule sends the query
		// there, which the contract spells action "upstream". Reporting "asis"
		// claimed the query went to its original destination instead.
		return "upstream"
	default:
		switch action {
		case "accept", "reject", "requery":
			return action
		}
		// A response rule that names an upstream asks for that answer to be
		// requeried through it; projecting "accept" dropped both the action
		// and the upstream from the contract body.
		return "requery"
	}
}

// nativeDnsUpstreamOf names the upstream a rule reaches. The contract requires
// it for action upstream/requery and forbids it otherwise. A request rule writes
// the name as the outbound itself ("-> alidns") and requery writes it as a
// parameter, so both forms resolve here.
func nativeDnsUpstreamOf(action, rawAction, upstream string) *string {
	switch action {
	case "upstream", "requery":
	default:
		return nil
	}
	if upstream != "" {
		return &upstream
	}
	if rawAction != "" && !strings.EqualFold(rawAction, action) {
		name := rawAction
		return &name
	}
	return nil
}

// QueryDns runs an active query through the same routing and cache.
func (p *nativeAPIProvider) QueryDns(ctx context.Context, request nativeapi.DnsQueryRequest) (nativeapi.DnsQueryResponse, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.DnsQueryResponse{}, err
	}
	if !p.allowDnsQuery(time.Now()) {
		return nativeapi.DnsQueryResponse{}, &nativeapi.APIError{
			Status:            429,
			Code:              "rate_limited",
			Message:           "dns query rate limit exceeded",
			RetryAfterSeconds: 60,
		}
	}
	controller, err := p.activeDnsController()
	if err != nil {
		return nativeapi.DnsQueryResponse{}, err
	}
	qtypes := make([]uint16, 0, len(request.Type))
	for _, typeName := range request.Type {
		qtype, ok := dnsmessage.StringToType[strings.ToUpper(typeName)]
		if !ok {
			return nativeapi.DnsQueryResponse{}, nativeapi.NewAPIError(422, "unsupported_value", "unsupported record type: "+typeName)
		}
		qtypes = append(qtypes, qtype)
	}
	queryCtx, cancel := context.WithTimeout(ctx, time.Duration(nativeapi.DnsQueryTimeoutMs)*time.Millisecond)
	defer cancel()
	results, err := controller.QueryDns(queryCtx, request.Domain, qtypes, request.Upstream, request.CacheMode == "bypass")
	if err != nil {
		if stderrors.Is(err, control.ErrDnsUpstreamNotFound) {
			return nativeapi.DnsQueryResponse{}, nativeapi.NewAPIError(422, "unsupported_value", err.Error())
		}
		return nativeapi.DnsQueryResponse{}, err
	}
	routeSource := "dns.routing"
	switch {
	case request.Upstream != "":
		routeSource = "forced"
	default:
		if plane, planeErr := p.activeControlPlane(); planeErr == nil && len(plane.SnapshotDnsRules().Request) == 0 {
			routeSource = "default"
		}
	}
	response := nativeapi.DnsQueryResponse{
		Domain:    request.Domain,
		CacheMode: request.CacheMode,
		QueryTime: time.Now().UTC().Format(time.RFC3339),
		Results:   make([]nativeapi.DnsQueryResult, 0, len(results)),
	}
	for _, result := range results {
		item := nativeapi.DnsQueryResult{
			Type:      dnsTypeName(result.QType),
			Cached:    result.Cached,
			Status:    result.Status,
			ElapsedMs: uint64(max(result.Elapsed.Milliseconds(), 0)),
			Question: nativeapi.DnsQuestion{
				Name: result.Question.Name,
				Type: dnsTypeName(result.Question.Qtype),
			},
			Route:   nativeapi.DnsRoute{Source: routeSource, Rule: nil},
			Answers: nativeDnsAnswers(result.Answers),
		}
		if result.CacheEntryID != "" {
			value := result.CacheEntryID
			item.CacheEntryID = &value
		}
		// A cache hit did not contact an upstream; naming one would claim an
		// exchange that never happened.
		if !result.Cached && result.Upstream != "" {
			value := result.Upstream
			item.Upstream = &value
		}
		response.Results = append(response.Results, item)
	}
	return response, nil
}

func (p *nativeAPIProvider) allowDnsQuery(now time.Time) bool {
	const limit = 60
	p.dnsQueryMu.Lock()
	defer p.dnsQueryMu.Unlock()
	if p.dnsQueryWindow.IsZero() || now.Sub(p.dnsQueryWindow) >= time.Minute {
		p.dnsQueryWindow = now
		p.dnsQueryCount = 0
	}
	if p.dnsQueryCount >= limit {
		return false
	}
	p.dnsQueryCount++
	return true
}

// dnsLogSrcMatches compares the recorded client address with the filter value.
// The log records the source as the datapath saw it (address and port), while
// the contract's src filter is an IP literal.
func dnsLogSrcMatches(recorded, wanted string) bool {
	if recorded == wanted {
		return true
	}
	host, _, err := net.SplitHostPort(recorded)
	if err != nil {
		return false
	}
	return host == wanted
}
