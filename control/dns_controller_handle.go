/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type udpRequest struct {
	realSrc        netip.AddrPort
	realDst        netip.AddrPort
	src            netip.AddrPort
	lConn          *net.UDPConn
	routingResult  *bpfRoutingResult
	uploadRecord   func(int64)
	downloadRecord func(int64)
}

func (r *udpRequest) downloadRecorder() func(int64) {
	if r == nil {
		return RecordDownloadTraffic
	}
	return normalizeTrafficRecord(r.downloadRecord)
}

func (c *DnsController) baseContext() context.Context {
	if rt := c.runtime(); rt != nil && rt.lifecycleCtx != nil {
		return rt.lifecycleCtx
	}
	return context.Background()
}

func (c *DnsController) newWorkContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c.baseContext(), timeout)
}

func (c *DnsController) forwardWithFallback(
	ctx context.Context, // Request-scoped context from dialSend/handler
	req *udpRequest,
	upstream *dns.Upstream,
	primaryDialArg *dialArgument,
	data []byte,
	// isAsIs marks the transparent destination synthesized by
	// resolveDNSUpstream, which has no configured scheme of its own. It is
	// passed explicitly instead of being inferred from the "udp" scheme that
	// synthesis happens to write, so the two cases can never be confused when
	// the synthesized scheme changes.
	isAsIs bool,
) (respMsg *dnsmessage.Msg, usedDialArg *dialArgument, err error) {
	// Per-attempt timeout: each attempt gets the full DefaultDialTimeout budget.
	// Deriving from the controller's lifecycle base (instead of the singleflight
	// work context) strips that shorter deadline so a UDP black-hole timeout
	// cannot exhaust the budget before the TCP fallback starts, while reload /
	// shutdown cancellation still reaches in-flight attempts.
	attemptCtx := c.baseContext()
	primaryCtx, primaryCancel := context.WithTimeout(attemptCtx, consts.DefaultDialTimeout)
	defer primaryCancel()

	respMsg, err = c.forwardWithDialArg(primaryCtx, upstream, primaryDialArg, data)
	if err == nil {
		return respMsg, primaryDialArg, nil
	}

	primaryErr := err

	// RFC 7766 §5 requires a forwarder that receives a truncated answer to
	// retry the query over TCP, whatever transport carried the first attempt. A
	// `tcp+udp://` upstream already retried on every UDP failure; a `udp://`
	// upstream only does so for the truncation signal, so an operator that
	// answers large zones with TC=1 over UDP (which RFC 1035 §4.2.1 permits)
	// no longer turns into a client-visible failure. Every other scheme keeps
	// its declared transport contract unchanged.
	truncated := errors.Is(primaryErr, ErrDNSTruncated)
	// An upstream may serve this query when it speaks both transports, or when
	// the answer was truncated and the operator declared `udp://` (the caller
	// then retries over TCP). Expressed as the positive predicate so the
	// condition stays readable.
	//
	// An as-is destination is deliberately not in that second case even though
	// the scheme resolveDNSUpstream synthesizes for it reads "udp". As-is means
	// "ask the server the request was addressed to, as the request arrived"
	// (docs/zh/configuration/dns.md, docs/en/configuration/dns.md), so dae
	// forwards it verbatim and does not change the transport on the client's
	// behalf: a client that receives TC=1 from that server decides for itself
	// whether to retry over TCP, exactly as it would without dae in the path.
	// The explicit isAsIs flag, not the synthesized spelling, is what keeps the
	// two cases apart.
	udpUpgradeable := upstream != nil && !isAsIs && upstream.Scheme == dns.UpstreamScheme_UDP
	canServe := upstream != nil &&
		(upstream.Scheme == dns.UpstreamScheme_TCP_UDP ||
			(truncated && udpUpgradeable))
	if !canServe || primaryDialArg.l4proto != consts.L4ProtoStr_UDP {
		return nil, primaryDialArg, primaryErr
	}

	// The retry is a different transport for the same destination, so the
	// forwarder has to be built from the rewritten scheme: building it from the
	// pre-rewrite upstream makes newDnsForwarder reject the TCP transport with
	// "unexpected scheme: udp", which discards the selection above and puts
	// that internal string into the error the caller sees.
	fallbackUpstream := *upstream
	fallbackUpstream.Scheme = dns.UpstreamScheme_TCP

	fallbackDialArg, chooseErr := c.runtime().chooseBestDnsDialer(ctx, dnsRequestSnapshotFromUDPRequest(req), &fallbackUpstream)
	if chooseErr != nil {
		return nil, primaryDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback select failed: %w", primaryErr, chooseErr)
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

	fallbackCtx, fallbackCancel := context.WithTimeout(attemptCtx, consts.DefaultDialTimeout)
	defer fallbackCancel()

	respMsg, err = c.forwardWithDialArg(fallbackCtx, &fallbackUpstream, fallbackDialArg, data)
	if err != nil {
		if truncated {
			c.reportDnsTruncatedFallback(upstream, false, primaryErr, err)
		}
		return nil, fallbackDialArg, fmt.Errorf("udp forward failed: %w; tcp fallback failed: %w", primaryErr, err)
	}
	if truncated {
		c.reportDnsTruncatedFallback(upstream, true, primaryErr, nil)
	}

	return respMsg, fallbackDialArg, nil
}

// dnsTruncatedFallbackLogInterval rate-limits the truncation warnings: an
// upstream that answers every large query with TC=1 would otherwise log on
// every query.
const dnsTruncatedFallbackLogInterval = time.Minute

// reportDnsTruncatedFallback records the outcome of a TCP retry that was
// triggered by a truncated (TC=1) UDP answer. Upgrades and failures are counted
// separately, and a failure additionally reports the retry error, so an
// upstream whose answers never survive UDP stays visible instead of degrading
// into a silent client-visible failure.
func (c *DnsController) reportDnsTruncatedFallback(upstream *dns.Upstream, upgraded bool, primaryErr, fallbackErr error) {
	if c.dnsControllerStore == nil {
		return
	}
	if upgraded {
		c.dnsUdpTruncatedUpgrades.Add(1)
	} else {
		c.dnsUdpTruncatedUpgradeFailures.Add(1)
	}
	if c.log == nil {
		return
	}
	fields := logrus.Fields{}
	if upstream != nil {
		fields["upstream"] = upstream.String()
		fields["scheme"] = upstream.Scheme
	}
	if upgraded {
		// A truncated UDP answer that the TCP retry upgrades is RFC 7766 §5
		// normal operation, not an anomaly: the client gets the complete
		// answer. The upgrade counter and the janitor's interval summary carry
		// the magnitude, so this per-query detail belongs on the debug level
		// that answers "why did this query go over TCP?". Only the failed
		// upgrade below stays a warning, because those clients really did
		// receive a truncated answer.
		if c.log.IsLevelEnabled(logrus.DebugLevel) {
			c.log.WithFields(fields).Debug("UDP DNS answer was truncated (TC=1); the TCP retry succeeded")
		}
		return
	}
	if !c.allowDnsTruncatedLog(time.Now()) {
		return
	}
	c.log.WithError(fallbackErr).WithFields(fields).Warnf("UDP DNS answer was truncated (TC=1) and the TCP retry failed "+
		"(primary error: %v)", primaryErr)
}

// reportDnsTruncationSummary publishes the RFC 7766 §5 upgrade counters to the
// operator. The per-event warning above is rate-limited to one line per minute
// and therefore cannot answer the two questions an operator actually has: are
// truncation upgrades happening at all, and what fraction of them fail. This
// summary is emitted by the DNS cache janitor on every tick that saw activity,
// as an interval delta plus the lifetime totals, and stays silent on an idle
// interval so a resolver that never truncates costs nothing. It follows the
// visibility pattern already used for the datapath counters
// (ControlPlane.checkBpfMapHealth): periodic read, one line per interval, warn
// only when the numbers say something is wrong.
func (c *DnsController) reportDnsTruncationSummary() {
	if c == nil || c.dnsControllerStore == nil || c.log == nil {
		return
	}
	upgrades := c.dnsUdpTruncatedUpgrades.Load()
	failures := c.dnsUdpTruncatedUpgradeFailures.Load()
	replies := c.dnsTruncatedRepliesToClient.Load()

	intervalUpgrades := upgrades - c.lastReportedTruncatedUpgrades.Swap(upgrades)
	intervalFailures := failures - c.lastReportedTruncatedFailures.Swap(failures)
	intervalReplies := replies - c.lastReportedTruncatedReplies.Swap(replies)
	if intervalUpgrades == 0 && intervalFailures == 0 && intervalReplies == 0 {
		return
	}

	fields := logrus.Fields{
		"upgrades_total":         upgrades,
		"upgrade_failures_total": failures,
		"truncated_to_client":    replies,
		"upgrades":               intervalUpgrades,
		"upgrade_failures":       intervalFailures,
		"truncated_replies":      intervalReplies,
	}
	if attempts := intervalUpgrades + intervalFailures; attempts > 0 {
		// Rendered instead of a float so the ratio is exact at any volume.
		fields["upgrade_failure_ratio"] = fmt.Sprintf("%d/%d", intervalFailures, attempts)
	}
	if intervalFailures > 0 {
		c.log.WithFields(fields).Warn("DNS truncation (TC=1) TCP upgrades failed; those clients got a truncated answer. " +
			"Check the upstream's TCP availability and whether its answers fit the client's UDP size limit")
		return
	}
	c.log.WithFields(fields).Info("DNS truncation (TC=1) answers were upgraded to TCP")
}

func (c *DnsController) allowDnsTruncatedLog(now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		last := c.lastDnsTruncatedLogTime.Load()
		if nowNano-last < int64(dnsTruncatedFallbackLogInterval) {
			return false
		}
		if c.lastDnsTruncatedLogTime.CompareAndSwap(last, nowNano) {
			return true
		}
	}
}

// noteDnsTruncatedReplyToClient records a TC=1 answer handed back to a client
// because the upstream answer did not survive the UDP attempt and no TCP
// upgrade delivered it.
func (c *DnsController) noteDnsTruncatedReplyToClient() {
	if c == nil || c.dnsControllerStore == nil {
		return
	}
	c.dnsTruncatedRepliesToClient.Add(1)
}

func (c *DnsController) Handle_(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	return c.HandleWithResponseWriter_(ctx, dnsMessage, req, nil)
}

func (c *DnsController) HandleWithResponseWriter_(ctx context.Context, dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	c.requireStore()
	if responseWriter != nil && !dnsResponseWriterUsesTCP(responseWriter) {
		responseWriter = &dnsUDPResponseWriter{ResponseWriter: responseWriter, limit: dnsUDPResponseSizeLimit(dnsMessage)}
	}
	var upstreamIndex consts.DnsRequestOutboundIndex
	var upstream *dns.Upstream

	if cap(c.concurrencyLimiter) > 0 {
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
	}

	// Prepare qname, qtype for cache lookup
	var qname string
	var qtype uint16
	var baseCacheKey string
	var responseCacheKey string
	if len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
		baseCacheKey = c.cacheKey(qname, qtype)
	}

	// Route request first, then check cache.
	// This ensures Reject rules are always applied, even if cache exists.
	// Cache lookup overhead (~1µs) is negligible compared to network latency (~ms).
	if baseCacheKey != "" && !dnsMessage.Response {
		// Route request to get upstream
		rt := c.runtime()
		if rt == nil || rt.routing == nil {
			return fmt.Errorf("dns routing is not configured")
		}
		var err error
		upstreamIndex, upstream, err = rt.routing.RequestSelect(ctx, qname, qtype)
		if err != nil {
			return err
		}
		responseCacheKey = c.responseCacheKey(baseCacheKey, req, upstreamIndex, upstream)

		if handled, herr := c.serveRejectWithWriter_(dnsMessage, req, responseWriter, baseCacheKey, upstreamIndex); handled {
			return herr
		}

		// Check cache after routing (non-reject case). Cache hits return
		// immediately without singleflight; stale entries background-refresh.
		if handled, herr := c.serveFromRespCacheWithRefresh_(dnsMessage, req, responseWriter,
			responseCacheKey, upstreamIndex, upstream); handled {
			return herr
		}

		// Cache miss - use singleflight to coalesce concurrent requests
		// This prevents thundering herd on upstream DNS servers
		res, err, _ := c.sf.Do(responseCacheKey, func() (any, error) {
			// Shared singleflight resolution should ignore individual client
			// cancellation, but it must still stop promptly when the DNS
			// controller is closing during reload/shutdown.
			resCtx, resCancel := c.newWorkContext(5 * time.Second)
			defer resCancel()

			// This goroutine performs the actual resolution.
			// It returns the DNS response message, or an error.
			return c.resolveForSingleflight(resCtx, dnsMessage, req, upstreamIndex, upstream, responseCacheKey)
		})

		if err != nil {
			return err
		}

		// res is the *dnsmessage.Msg
		respMsg := res.(*dnsmessage.Msg)

		// RFC 8305 resolution delay runs here, outside the singleflight leader:
		// the shared resolution is complete, so waiting for the preferred
		// address family only delays this delivery instead of stalling every
		// follower behind the same key.
		respMsg = c.applyPreferenceWait(respMsg)

		// Optimization: Try to get pre-packed response from cache after singleflight.
		// This avoids another Pack() call which is common in high-concurrency scenarios.
		if responseCacheKey != "" {
			if resp, _ := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
				if err = c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter, dnsMessage); err != nil {
					return err
				}
				return nil
			}
		}

		// Write response.
		// For packet-send path, avoid deep-copying DNS message and just patch ID in packed bytes.
		if responseWriter != nil {
			respMsgUnique := respMsg.Copy()
			respMsgUnique.Id = dnsMessage.Id
			return responseWriter.WriteMsg(respMsgUnique)
		}

		// If no responseWriter (internal UDP path), pack and send directly.
		// Reuse the DNS response buffer pool; data is consumed synchronously by the send.
		bufPtr := dnsResponseBufPool.Get().(*[]byte)
		defer dnsResponseBufPool.Put(bufPtr)
		data, err := respMsg.PackBuffer((*bufPtr)[:cap(*bufPtr)])
		if err != nil {
			return fmt.Errorf("pack DNS packet: %w", err)
		}
		if len(data) >= 2 {
			binary.BigEndian.PutUint16(data[:2], dnsMessage.Id)
		}
		// Apply the client's UDP size limit (512 or its EDNS0 advertisement)
		// with the TC bit so an oversized reply triggers a TCP retry instead
		// of an unsendable datagram; every other UDP send path already does.
		// truncateDNSResponse unpacks into a fresh message, so the shared
		// singleflight result is never mutated.
		data = truncateDNSResponse(data, dnsUDPResponseSizeLimit(dnsMessage))
		if req == nil || req.lConn == nil {
			return fmt.Errorf("dns request connection is nil for singleflight response")
		}
		if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
			return err
		}
		return nil
	}

	return c.handleWithResponseWriter_(ctx, dnsMessage, req, responseWriter, upstreamIndex, upstream, responseCacheKey, baseCacheKey)
}

func (c *DnsController) resolveForSingleflight(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	responseCacheKey string,
) (*dnsmessage.Msg, error) {
	// Preserve the second cache lookup from the former response-writer path.
	// Another request may have populated the entry after the outer cache miss
	// and before this singleflight leader starts upstream resolution.
	if resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false); resp != nil {
		if needRefresh {
			go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
		}
		respMsg := new(dnsmessage.Msg)
		if err := respMsg.Unpack(resp); err != nil {
			return nil, fmt.Errorf("unpack cached DNS response: %w", err)
		}
		respMsg.Id = dnsMessage.Id
		return respMsg, nil
	}

	data, err := dnsMessage.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS packet: %w", err)
	}
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return nil, err
	}

	respMsg := resolution.response
	respMsg.Id = dnsMessage.Id
	respMsg.Compress = true
	if err := c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
		c.noteDnsCacheStoreFailure("controller response", err)
	}
	return respMsg, nil
}

// serveRejectWithWriter_ applies a routing-reject verdict if one was selected.
func (c *DnsController) serveRejectWithWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest,
	responseWriter dnsmessage.ResponseWriter, baseCacheKey string,
	upstreamIndex consts.DnsRequestOutboundIndex,
) (bool, error) {
	if upstreamIndex != consts.DnsRequestOutboundIndex_Reject {
		return false, nil
	}
	c.RemoveDnsRespCacheFamily(baseCacheKey)
	return true, c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
}

// serveFromRespCacheWithRefresh_ answers from the response cache when present,
// scheduling optimistic background refreshes for stale entries.
func (c *DnsController) serveFromRespCacheWithRefresh_(dnsMessage *dnsmessage.Msg, req *udpRequest,
	responseWriter dnsmessage.ResponseWriter, responseCacheKey string,
	upstreamIndex consts.DnsRequestOutboundIndex, upstream *dns.Upstream,
) (bool, error) {
	resp, needRefresh := c.LookupDnsRespCache_(dnsMessage, responseCacheKey, false)
	if resp == nil {
		return false, nil
	}
	// ipversion_prefer: a cached non-preferred answer must not be released
	// while the preferred family has records. The cache may hold such an entry
	// because the optimistic refresh and the forwarder store bypass the
	// delivery filter, so the preference is enforced here as well.
	if c.suppressNonPreferredCacheHit(dnsMessage) {
		empty := dnsMessage.Copy()
		return true, c.sendDnsErrorResponse_(empty, dnsmessage.RcodeSuccess, false,
			"ipversion_prefer: cached non-preferred answer replaced with an empty reply", req, responseWriter)
	}
	// A cache hit can answer a query waiting out the RFC 8305 resolution delay:
	// the preferred address family is available now, so release the waiter
	// instead of letting it pay the full delay. This is the delivery side, so
	// the wake-up is not deferred behind the upstream resolution.
	c.notifyPreferenceWait(dnsMessage)
	if needRefresh {
		go c.backgroundRefresh(responseCacheKey, dnsMessage, req, upstreamIndex, upstream)
	}
	if err := c.writeCachedResponse(resp, dnsMessage.Id, req, responseWriter, dnsMessage); err != nil {
		return true, err
	}
	if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		l := c.log.WithFields(logrus.Fields{
			"_qname": strings.ToLower(q.Name),
			"qtype":  QtypeToString(q.Qtype),
		})
		if req != nil {
			l = l.WithFields(logrus.Fields{
				"network": "udp(dns)",
				"source":  RefineSourceToShow(req.realSrc, req.realDst.Addr()),
				"dest":    RefineAddrPortToShow(req.realDst),
			})
		}
		l.Debug("cache hit")
	}
	return true, nil
}

func (c *DnsController) handleWithResponseWriter_(
	ctx context.Context,
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	responseWriter dnsmessage.ResponseWriter,
	upstreamIndex consts.DnsRequestOutboundIndex,
	upstream *dns.Upstream,
	responseCacheKey string,
	baseCacheKey string,
) (err error) {
	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
	}

	// Route request if not already routed.
	if upstream == nil && upstreamIndex == 0 {
		rt := c.runtime()
		if rt == nil || rt.routing == nil {
			return fmt.Errorf("dns routing is not configured")
		}
		upstreamIndex, upstream, err = rt.routing.RequestSelect(ctx, qname, qtype)
		if err != nil {
			return err
		}
	}

	if baseCacheKey == "" {
		baseCacheKey = c.cacheKey(qname, qtype)
	}
	if responseCacheKey == "" {
		responseCacheKey = c.responseCacheKey(baseCacheKey, req, upstreamIndex, upstream)
	}

	if handled, herr := c.serveRejectWithWriter_(dnsMessage, req, responseWriter, baseCacheKey, upstreamIndex); handled {
		return herr
	}

	if handled, herr := c.serveFromRespCacheWithRefresh_(dnsMessage, req, responseWriter,
		responseCacheKey, upstreamIndex, upstream); handled {
		return herr
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
	return c.dialSend(ctx, req, data, dnsMessage.Id, upstream, responseWriter, responseCacheKey)
}

type dnsUpstreamResolution struct {
	response      *dnsmessage.Msg
	networkType   *dialer.NetworkType
	upstreamIndex consts.DnsResponseOutboundIndex
	dialArgument  *dialArgument
}

// resolveDNSUpstream obtains a DNS response without writing it to the client
// or mutating the response cache. It owns response routing and recursive
// upstream fallback so delivery can be shared by UDP, TCP, and singleflight.
func (c *DnsController) resolveDNSUpstream(
	ctx context.Context,
	invokingDepth int,
	req *udpRequest,
	data []byte,
	upstream *dns.Upstream,
) (*dnsUpstreamResolution, error) {
	data = append([]byte(nil), data...) // defensive copy: callers may reuse the slice across recursive retries
	if invokingDepth >= MaxDnsLookupDepth {
		return nil, fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}

	// Question echo (RFC 5452): transaction IDs are only 16 bits, so a
	// matching ID does not prove the reply belongs to this request. Capture
	// the request question once; every transport funnel (UDP, TCP pipeline,
	// DoH, DoQ) converges here, so validating the reply here guards the
	// response cache and clients from spoofed or cross-talked answers on all
	// upstream hops including recursive fallback.
	var reqQuestion dnsmessage.Question
	{
		var reqMsg dnsmessage.Msg
		if err := reqMsg.Unpack(data); err == nil && len(reqMsg.Question) > 0 {
			reqQuestion = reqMsg.Question[0]
		}
	}

	upstreamName := "asis"
	// isAsIs records that this destination was synthesized from the request's
	// real destination rather than configured by the operator. The synthesized
	// value is spelled "udp" to mean "carried over UDP", which is not the same
	// statement as "the operator wrote udp://"; the transport decision below
	// reads this flag, never the synthesized spelling.
	isAsIs := upstream == nil
	if isAsIs {
		// As-is.

		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		var ip46 netutils.Ip46
		if req.realDst.Addr().Is4() {
			ip46.Ip4 = req.realDst.Addr()
		} else {
			ip46.Ip6 = req.realDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   dns.UpstreamScheme_UDP,
			Hostname: req.realDst.Addr().String(),
			Port:     req.realDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
	dialArg, err := c.runtime().chooseBestDnsDialer(ctx, dnsRequestSnapshotFromUDPRequest(req), upstream)
	if err != nil {
		return nil, err
	}

	// Dial and send.
	var respMsg *dnsmessage.Msg
	var usedDialArg *dialArgument
	respMsg, usedDialArg, err = c.forwardWithFallback(ctx, req, upstream, dialArg, data, isAsIs)
	if err != nil {
		return nil, err
	}
	if reqQuestion.Name != "" && !questionEchoMatches(reqQuestion, respMsg) {
		return nil, fmt.Errorf("upstream %v reply does not echo the request question (possible spoofing or upstream cross-talk); dropped", upstreamName)
	}

	networkType := &dialer.NetworkType{
		L4Proto:         usedDialArg.l4proto,
		IpVersion:       usedDialArg.ipversion,
		IsDns:           true,
		UdpHealthDomain: dialer.UdpHealthDomainDns,
	}

	// Route response.
	rt := c.runtime()
	if rt == nil || rt.routing == nil {
		return nil, fmt.Errorf("dns routing is not configured")
	}
	upstreamIndex, nextUpstream, err := rt.routing.ResponseSelect(ctx, respMsg, upstream)
	if err != nil {
		return nil, err
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
		return c.resolveDNSUpstream(ctx, invokingDepth+1, req, data, nextUpstream)
	}

	// NOTE: RFC 8305 resolution-delay handling is deliberately NOT applied
	// here. resolveDNSUpstream also runs inside the singleflight leader (and in
	// background refreshes), where sleeping would hold the shared key for every
	// follower. Delivery paths call applyPreferenceWait instead.
	return &dnsUpstreamResolution{
		response:      respMsg,
		networkType:   networkType,
		upstreamIndex: upstreamIndex,
		dialArgument:  usedDialArg,
	}, nil
}
