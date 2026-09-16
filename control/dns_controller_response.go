/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/binary"
	"fmt"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// dnsDefaultUDPSize is the classic DNS-over-UDP response size limit
// (RFC 1035 section 4.2.1) applied when the client does not advertise
// EDNS0. Responses larger than the limit must be truncated with the TC
// bit set so the client retries over TCP instead of silently dropping
// the answers (which manifests as "noerror, 0 answer, tc=0").
const dnsDefaultUDPSize = 512

// dnsUDPResponseSizeLimit returns the maximum UDP response size allowed
// for a client request: its EDNS0 advertised size (RFC 6891) when
// present, otherwise the classic 512-byte limit. Values below 512 are
// clamped up per RFC 6891 section 6.2.5.
func dnsUDPResponseSizeLimit(req *dnsmessage.Msg) int {
	limit := dnsDefaultUDPSize
	if opt := req.IsEdns0(); opt != nil {
		if s := int(opt.UDPSize()); s > limit {
			limit = s
		}
	}
	return limit
}

type dnsUDPResponseWriter struct {
	dnsmessage.ResponseWriter
	limit int
}

func (w *dnsUDPResponseWriter) WriteMsg(msg *dnsmessage.Msg) error {
	if msg.Len() > w.limit {
		// Truncate changes sections and compression; cached and singleflight
		// payloads must stay intact for clients that retry over TCP.
		msg = msg.Copy()
		truncateDNSMessage(msg, w.limit)
	}
	return w.ResponseWriter.WriteMsg(msg)
}

// questionEchoMatches reports whether an upstream response echoes the
// request question. Transaction IDs are only 16 bits, so ID equality alone
// cannot prove a response belongs to a request: a hijacked upstream, a
// cross-talked connection, or an off-path spoofer that collides with the ID
// must not reach the response cache or the client (RFC 5452). The question
// section is the mandatory second factor; compliant upstreams echo it
// verbatim, including on CNAME-chased and pipelined replies.
func questionEchoMatches(req dnsmessage.Question, resp *dnsmessage.Msg) bool {
	if len(resp.Question) == 0 {
		return false
	}
	rq := resp.Question[0]
	// CanonicalName lowercases and FQDN-terminates, giving the
	// case-insensitive name equality DNS requires.
	return req.Qtype == rq.Qtype && req.Qclass == rq.Qclass &&
		dnsmessage.CanonicalName(req.Name) == dnsmessage.CanonicalName(rq.Name)
}

// truncateDNSMessage requires exclusive ownership of msg and its records.
func truncateDNSMessage(msg *dnsmessage.Msg, limit int) {
	msg.Truncate(limit)
	opt := msg.IsEdns0()
	if opt == nil || msg.Len() <= limit {
		return
	}

	// Truncate retains the entire OPT even when its options exceed the
	// budget. Keep its header and every complete option that still fits;
	// omitted options require TCP retry just like omitted resource records.
	options := opt.Option
	opt.Option = nil
	for _, option := range options {
		opt.Option = append(opt.Option, option)
		if msg.Len() > limit {
			opt.Option = opt.Option[:len(opt.Option)-1]
			msg.Truncated = true
		}
	}
}

// truncateDNSResponse returns packed unchanged if it fits within limit;
// otherwise it returns a truncated repack with the TC bit set (RFC 1035
// section 4.2.1) so the client retries over TCP. On unpack/pack failure the
// original bytes are returned unchanged.
func truncateDNSResponse(packed []byte, limit int) []byte {
	if len(packed) <= limit {
		return packed
	}
	var msg dnsmessage.Msg
	if err := msg.Unpack(packed); err != nil {
		return packed
	}
	truncateDNSMessage(&msg, limit)
	if data, err := msg.Pack(); err == nil {
		return data
	}
	return packed
}

// echoWireQuestionCase rewrites the question name of a packed DNS response with
// the spelling the requester used. The response cache stores one canonical wire
// per name, so without this rewrite every client that spelled the name
// differently would see its own question echoed in someone else's case: DNS
// name comparison is case-insensitive (RFC 1035 §4.1.2), but stub resolvers and
// 0x20-randomizing clients compare the echoed question byte for byte.
//
// The rewrite is a same-length, in-place copy inside the question section at
// offset 12, so no offset in the message can move. A response whose question
// name has a different wire length (a different name, or an escaped spelling)
// is left untouched and reported at debug level. resp must be caller-owned.
func (c *DnsController) echoWireQuestionCase(resp []byte, reqMsg *dnsmessage.Msg) bool {
	if len(resp) < 12 || reqMsg == nil || len(reqMsg.Question) == 0 {
		return false
	}
	bufPtr := dnsResponseBufPool.Get().(*[]byte)
	defer dnsResponseBufPool.Put(bufPtr)
	want := packQuestionWireName(reqMsg.Question[0].Name, *bufPtr)
	if len(want) == 0 {
		return false
	}
	end := skipDnsWireName(resp, 12)
	if end < 0 {
		return false
	}
	if end-12 != len(want) {
		c.debugQuestionCaseMismatch(end-12, len(want), reqMsg.Question[0].Name)
		return false
	}
	copy(resp[12:end], want)
	return true
}

// echoMsgQuestionCase is the unpacked-message counterpart of
// echoWireQuestionCase for delivery paths that hand a *dnsmessage.Msg to a
// ResponseWriter. It only substitutes the name, and only when both spellings
// encode to the same wire length, so the packed size cannot change.
func (c *DnsController) echoMsgQuestionCase(respMsg, reqMsg *dnsmessage.Msg) bool {
	if respMsg == nil || reqMsg == nil || len(respMsg.Question) == 0 || len(reqMsg.Question) == 0 {
		return false
	}
	bufPtr := dnsResponseBufPool.Get().(*[]byte)
	defer dnsResponseBufPool.Put(bufPtr)
	wantLen := len(packQuestionWireName(reqMsg.Question[0].Name, *bufPtr))
	if wantLen == 0 {
		return false
	}
	if gotLen := len(packQuestionWireName(respMsg.Question[0].Name, *bufPtr)); gotLen != wantLen {
		c.debugQuestionCaseMismatch(gotLen, wantLen, reqMsg.Question[0].Name)
		return false
	}
	respMsg.Question[0].Name = reqMsg.Question[0].Name
	return true
}

func (c *DnsController) debugQuestionCaseMismatch(responseWireLen, requesterWireLen int, requesterName string) {
	if c.log == nil || !c.log.IsLevelEnabled(logrus.DebugLevel) {
		return
	}
	c.log.Debugf("kept the cached DNS question spelling: response question is %d wire bytes, requester %q is %d",
		responseWireLen, requesterName, requesterWireLen)
}

// writeCachedResponse sends a cached DNS response to the client.
// OPTIMIZED: Uses pre-packed response with ID patching to avoid Pack() overhead.
// For responseWriter path, uses Unpack/WriteMsg (slower but handles ID correctly).
// For UDP path, patches the ID directly using buffer pool to avoid allocations.
// If the packed response exceeds the client's UDP size limit (512 or EDNS0),
// it is truncated with the TC bit set (rare path: only large answers pay the
// Unpack/Truncate cost).
func (c *DnsController) writeCachedResponse(resp []byte, reqId uint16, req *udpRequest, responseWriter dnsmessage.ResponseWriter, reqMsg *dnsmessage.Msg) error {
	// Optimization: Patch ID directly in the packed buffer if possible.
	// For UDP, we can use Write() directly. For TCP, we might need WriteMsg or manual length.
	// However, most responseWriters here are either UDP or wrappers that handle message framing.

	if responseWriter != nil {
		var respMsg dnsmessage.Msg
		if err := respMsg.Unpack(resp); err != nil {
			return fmt.Errorf("failed to unpack DNS response: %w", err)
		}
		// Set the correct ID from the original request
		respMsg.Id = reqId
		// Restore the requester's own question spelling before delivery.
		c.echoMsgQuestionCase(&respMsg, reqMsg)
		return responseWriter.WriteMsg(&respMsg)
	}

	// For UDP path, directly send pre-packed response with patched ID
	if req == nil || req.lConn == nil {
		return fmt.Errorf("dns request connection is nil for cached response")
	}

	// OPTIMIZATION: Use buffer pool to avoid memory allocation on every cache hit.
	// DNS Message ID is in the first 2 bytes (big-endian).
	if len(resp) >= 2 && len(resp) <= 1024 {
		bufPtr := dnsResponseBufPool.Get().(*[]byte)
		defer dnsResponseBufPool.Put(bufPtr)

		patchedResp := (*bufPtr)[:len(resp)]
		copy(patchedResp, resp)
		binary.BigEndian.PutUint16(patchedResp[0:2], reqId)
		// Restore the requester's own question spelling on this private copy;
		// the shared cached wire must never be rewritten in place.
		c.echoWireQuestionCase(patchedResp, reqMsg)

		// Truncate oversized UDP responses with the TC bit set so the client
		// retries over TCP (RFC 1035). Without this the client receives a
		// "noerror, 0 answer, tc=0" reply and believes the name has no
		// addresses. Only large answers pay the Unpack/Truncate cost.
		limit := dnsDefaultUDPSize
		if reqMsg != nil {
			limit = dnsUDPResponseSizeLimit(reqMsg)
		}
		patchedResp = truncateDNSResponse(patchedResp, limit)

		// Transparent DNS replies must preserve the original DNS server tuple.
		// sendPkt also carries the DNS port-conflict raw fallback for host-local
		// clients where binding the source address may fail transiently.
		if err := sendRuntimeTrackedPkt(c.log, patchedResp, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
			return fmt.Errorf("failed to write cached DNS resp: %w", err)
		}
		return nil
	}

	// Fallback for oversized responses (rare)
	patchedResp := make([]byte, len(resp))
	copy(patchedResp, resp)
	if len(resp) >= 2 {
		binary.BigEndian.PutUint16(patchedResp[0:2], reqId)
	}
	// Restore the requester's own question spelling on this private copy.
	c.echoWireQuestionCase(patchedResp, reqMsg)

	limit := dnsDefaultUDPSize
	if reqMsg != nil {
		limit = dnsUDPResponseSizeLimit(reqMsg)
	}
	patchedResp = truncateDNSResponse(patchedResp, limit)

	if err := sendRuntimeTrackedPkt(c.log, patchedResp, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return fmt.Errorf("failed to write oversized cached DNS resp: %w", err)
	}
	return nil
}

// sendDnsErrorResponse_ is the shared implementation for the reject/refused/
// truncated control responses. It sets the common response fields, logs at
// trace level, and sends the response via responseWriter or UDP.
func (c *DnsController) sendDnsErrorResponse_(
	dnsMessage *dnsmessage.Msg,
	rcode int,
	truncated bool,
	traceMsg string,
	req *udpRequest,
	responseWriter dnsmessage.ResponseWriter,
) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = rcode
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = truncated
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln(traceMsg)
	}
	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	if req == nil || req.lConn == nil {
		return nil
	}
	// Pack into a pooled DNS response buffer; data is consumed synchronously by the send.
	bufPtr := dnsResponseBufPool.Get().(*[]byte)
	defer dnsResponseBufPool.Put(bufPtr)
	data, err := dnsMessage.PackBuffer((*bufPtr)[:cap(*bufPtr)])
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	data = truncateDNSResponse(data, dnsUDPResponseSizeLimit(dnsMessage))
	if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return err
	}
	return nil
}

// sendRefusedWithResponseWriter_ sends REFUSED response when overload protection is triggered.
func (c *DnsController) sendRefusedWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	return c.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeRefused, false, "Refused due to concurrency limit", req, responseWriter)
}

// sendDnsTruncatedResponse_ sends a TC=1 success response for oversized answers.
func (c *DnsController) sendDnsTruncatedResponse_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) error {
	return c.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeSuccess, true, "Truncated", req, responseWriter)
}

// sendRejectWithResponseWriter_ send empty answer.
func (c *DnsController) sendRejectWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	return c.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeSuccess, false, "Reject", req, responseWriter)
}

// notifyPreferenceWait releases any query that is waiting out the RFC 8305
// resolution delay for msg's name and address family. It is the single entry
// point for "a preferred answer is now available", so every delivery path -
// freshly resolved and served from the response cache - wakes the waiter
// instead of leaving it to run out its full delay.
func (c *DnsController) notifyPreferenceWait(msg *dnsmessage.Msg) bool {
	if msg == nil || len(msg.Question) == 0 {
		return false
	}
	qtypePrefer := c.currentQtypePrefer()
	if qtypePrefer == 0 {
		return false
	}
	q := msg.Question[0]
	if !isPreferredType(q.Qtype, qtypePrefer) {
		return false
	}
	if !c.prefWaitRegistry.notifyPreferred(dnsmessage.CanonicalName(q.Name), q.Qtype, qtypePrefer, hasAddressRecords(msg, q.Qtype)) {
		return false
	}
	c.dnsPreferWaitNotified.Add(1)
	return true
}

// applyPreferenceWait implements RFC 8305 Happy Eyeballs Resolution Delay and
// the documented ipversion_prefer answer filter.
// When ip_version_prefer is set and a non-preferred A/AAAA response is received,
// wait briefly (50ms) for the preferred response to arrive before proceeding.
//
// This function handles two scenarios:
//  1. Preferred response arrives (e.g., AAAA when prefer=6): Notify any waiting
//     requests and drop the cached non-preferred family, which must not be
//     served while the preferred family has records.
//  2. Non-preferred response arrives (e.g., A when prefer=6): Register wait and
//     wait for the preferred family. If the preferred family is known to have
//     records - already in the response cache, or delivered during the wait -
//     the non-preferred answer is replaced by an empty reply, which is what
//     ipversion_prefer documents and what steers clients to the preferred
//     family. With no such knowledge the original answer is returned unchanged.
//
// It must be called on the delivery side (after a shared singleflight
// resolution returns, not inside it), so the delay is paid per delivered
// response instead of holding the singleflight key for followers.
func (c *DnsController) applyPreferenceWait(respMsg *dnsmessage.Msg) *dnsmessage.Msg {
	c.requireStore()
	// Fast path: preference not enabled
	if c.currentQtypePrefer() == 0 {
		return respMsg
	}

	// Only handle A/AAAA responses
	if len(respMsg.Question) == 0 {
		return respMsg
	}
	q := respMsg.Question[0]
	if q.Qtype != dnsmessage.TypeA && q.Qtype != dnsmessage.TypeAAAA {
		return respMsg
	}

	// Get canonical qname for matching
	qname := dnsmessage.CanonicalName(q.Name)

	// Case 1: This is the preferred response type - notify waiting requests
	qtypePrefer := c.currentQtypePrefer()
	if isPreferredType(q.Qtype, qtypePrefer) {
		// The response-cache fast path releases a cached answer without ever
		// reaching this function, so the non-preferred family must not stay
		// cached while the preferred family has records: that entry would be
		// served verbatim to the next non-preferred query.
		if hasAddressRecords(respMsg, q.Qtype) {
			if counterpart, ok := counterpartAddressQtype(q.Qtype); ok && c.dropCachedAddressFamily(qname, counterpart) {
				c.dnsPreferFiltered.Add(1)
			}
		}
		// Notify any waiting requests for this domain
		if c.notifyPreferenceWait(respMsg) {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.Tracef("Preferred %v response for %v notified waiting request", QtypeToString(q.Qtype), qname)
			}
		}
		return respMsg
	}

	// Case 2: This is a non-preferred response. When the preferred family is
	// already cached there is nothing to wait for: answer with the empty reply
	// the preference promises instead of paying the resolution delay.
	if c.cachedAddressFamilyHasRecords(qname, qtypePrefer) {
		if filtered := c.filterNonPreferredResponse(qname, respMsg); filtered != nil {
			return filtered
		}
	}

	// Otherwise register a wait and give the preferred response a chance to
	// arrive before this non-preferred answer is released.
	if wait := c.prefWaitRegistry.registerWait(qname, q.Qtype, qtypePrefer); wait != nil {
		// Non-preferred response arrived before preferred - wait briefly for preferred
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("Non-preferred %v response for %v, waiting %v for preferred %v",
				QtypeToString(q.Qtype), qname, PreferenceResolutionDelay, QtypeToString(qtypePrefer))
		}

		// Wait for preferred response or timeout
		preferred, preferredHasRecords := wait.waitFor()

		// Clean up wait registry
		c.prefWaitRegistry.remove(wait)

		if !preferred {
			c.dnsPreferWaitTimeout.Add(1)
		}

		// The preferred family can become visible without notifying this wait:
		// a cache hit notifies with the client's question (which carries no
		// answers), and the optimistic refresh stores a preferred family
		// without touching the registry at all. So the cache is re-read after
		// the wait, including when the wait timed out, instead of trusting the
		// wake-up alone.
		if (preferred && preferredHasRecords) || c.cachedAddressFamilyHasRecords(qname, qtypePrefer) {
			// The preferred family has records, so the non-preferred answer
			// must not be delivered.
			if filtered := c.filterNonPreferredResponse(qname, respMsg); filtered != nil {
				if c.log.IsLevelEnabled(logrus.TraceLevel) {
					c.log.Tracef("Preferred %v response with records for %v is known; answering the %v query with an empty reply",
						QtypeToString(qtypePrefer), qname, QtypeToString(q.Qtype))
				}
				return filtered
			}
		}

		if preferred {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.Tracef("Preferred %v response arrived for %v during wait for %v",
					QtypeToString(qtypePrefer), qname, QtypeToString(q.Qtype))
			}
		} else {
			if c.log.IsLevelEnabled(logrus.TraceLevel) {
				c.log.Tracef("Preferred %v response not arrived for %v within %v, using %v response",
					QtypeToString(qtypePrefer), qname, PreferenceResolutionDelay, QtypeToString(q.Qtype))
			}
		}

		// No preferred family was observed, so the answer is delivered as-is.
		return respMsg
	}

	return respMsg
}

// filterNonPreferredResponse applies the documented ipversion_prefer contract:
// while the preferred address family has records for qname, a non-preferred
// A/AAAA answer is replaced by an empty NOERROR reply so clients fall back to
// the preferred family. The cached non-preferred entry is dropped as well,
// because a later query could otherwise be answered from the response-cache
// fast path, which cannot perform this check.
//
// It returns nil when the answer carries no record of the non-preferred family
// (there is nothing to filter), leaving the caller's response untouched. The
// returned message is a copy: the input may be a shared singleflight result or
// a cached message that other deliveries still use.
func (c *DnsController) filterNonPreferredResponse(qname string, respMsg *dnsmessage.Msg) *dnsmessage.Msg {
	if len(respMsg.Question) == 0 || !hasAddressRecords(respMsg, respMsg.Question[0].Qtype) {
		return nil
	}
	c.dropCachedAddressFamily(qname, respMsg.Question[0].Qtype)

	empty := *respMsg
	empty.Answer = nil
	empty.Truncated = false
	empty.Response = true
	empty.RecursionAvailable = true
	empty.Compress = true
	c.dnsPreferFiltered.Add(1)
	return &empty
}
