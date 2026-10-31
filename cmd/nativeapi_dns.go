/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	stderrors "errors"
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
	bind := pageCursorBind(name, domain, filter.Types, filter.IncludeExpired, filter.Limit)
	offset := 0
	if filter.Cursor != "" {
		parsed, err := decodePageCursor("dns_cache", bind, filter.Cursor, now)
		if err != nil {
			return nativeapi.DnsCacheList{}, err
		}
		offset = parsed
	}
	start, end, next := pageOf(len(entries), offset, filter.Limit, "dns_cache", bind, now)
	list := nativeapi.DnsCacheList{
		ObservedAt: observed,
		Coverage: nativeapi.DnsCacheCoverage{
			Positive:   true,
			Negative:   true,
			Persistent: false,
		},
		Entries:    entries[start:end],
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
	name := ""
	if filter.Name != "" {
		name = dnsmessage.CanonicalName(filter.Name)
	}
	matched := make([]nativeapi.DnsLogRecord, 0, len(records))
	for i := len(records) - 1; i >= 0; i-- {
		record := records[i]
		if name != "" && dnsmessage.CanonicalName(record.Question.Name) != name {
			continue
		}
		if len(types) > 0 {
			if _, ok := types[record.Question.Qtype]; !ok {
				continue
			}
		}
		if filter.Src != "" && record.Src != filter.Src {
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
	bind := pageCursorBind(name, filter.Types, filter.Src, filter.Limit)
	offset := 0
	if filter.Cursor != "" {
		parsed, err := decodePageCursor("dns_log", bind, filter.Cursor, now)
		if err != nil {
			return nativeapi.DnsLogList{}, err
		}
		offset = parsed
	}
	start, end, next := pageOf(len(matched), offset, filter.Limit, "dns_log", bind, now)
	list := nativeapi.DnsLogList{
		ObservedAt: now.UTC().Format(time.RFC3339),
		Total:      uint64(total),
		Records:    matched[start:end],
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
		result = append(result, nativeapi.DnsRoutingRule{
			RuleID:     "dns-" + kind + ":" + strconv.Itoa(index),
			Index:      uint64(index),
			Expression: rule.Expression,
			Action:     nativeDnsAction(kind, rule.Action),
			Upstream:   nativeDnsUpstream(kind, rule.Action, rule.Upstream),
			Kind:       "rule",
		})
	}
	result = append(result, nativeapi.DnsRoutingRule{
		RuleID:     "dns-" + kind + ":fallback",
		Index:      uint64(len(result)),
		Expression: fallback.Expression,
		Action:     nativeDnsAction(kind, fallback.Action),
		Upstream:   nativeDnsUpstream(kind, fallback.Action, fallback.Upstream),
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
		return "asis"
	default:
		switch action {
		case "accept", "reject", "requery":
			return action
		}
		return "accept"
	}
}

func nativeDnsUpstream(kind, action, upstream string) *string {
	action = strings.ToLower(action)
	if (kind == "request" && action != "upstream") || (kind == "response" && action != "requery") {
		return nil
	}
	if upstream == "" {
		return nil
	}
	return &upstream
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
			Route:   nativeapi.DnsRoute{Source: "dns.routing", Rule: nil},
			Answers: nativeDnsAnswers(result.Answers),
		}
		if result.CacheEntryID != "" {
			value := result.CacheEntryID
			item.CacheEntryID = &value
		}
		if result.Upstream != "" {
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
