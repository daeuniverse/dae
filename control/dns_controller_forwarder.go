/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	commonerrors "github.com/daeuniverse/dae/common/errors"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

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
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	dialerName   string
	outboundName string
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

type cachedDnsForwarder struct {
	forwarder    DnsForwarder
	lastUsedNano atomic.Int64
	inFlight     atomic.Int32
	retired      atomic.Bool
	closeOnce    sync.Once
	// consecutiveErrors counts back-to-back failures.  A single success
	// resets the counter.  When it reaches maxConsecutiveForwardErrors the
	// forwarder is retired even for stream-based upstream schemes.
	consecutiveErrors atomic.Int32
}

const maxConsecutiveForwardErrors = 3

func newCachedDnsForwarder(forwarder DnsForwarder, now time.Time) *cachedDnsForwarder {
	entry := &cachedDnsForwarder{forwarder: forwarder}
	entry.touch(now)
	return entry
}

func (c *cachedDnsForwarder) touch(now time.Time) {
	c.lastUsedNano.Store(now.UnixNano())
}

func (c *cachedDnsForwarder) beginUse() bool {
	if c == nil || c.retired.Load() {
		return false
	}
	c.inFlight.Add(1)
	c.touch(time.Now())
	if !c.retired.Load() {
		return true
	}
	if c.inFlight.Add(-1) == 0 {
		_ = c.closeNow()
	}
	return false
}

func (c *cachedDnsForwarder) endUse() {
	if c == nil {
		return
	}
	c.touch(time.Now())
	if c.inFlight.Add(-1) == 0 && c.retired.Load() {
		_ = c.closeNow()
	}
}

func (c *cachedDnsForwarder) closeNow() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		if c.forwarder != nil {
			err = c.forwarder.Close()
		}
	})
	return err
}

func (c *cachedDnsForwarder) retire() error {
	if c == nil {
		return nil
	}
	c.retired.Store(true)
	if c.inFlight.Load() == 0 {
		return c.closeNow()
	}
	return nil
}

var dnsForwarderFactory = newDnsForwarder

func (c *DnsController) extractDnsForwarder(value any) DnsForwarder {
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
	if c.dnsForwarderIdleTTL <= 0 {
		return
	}

	nowNano := now.UnixNano()
	idleNano := c.dnsForwarderIdleTTL.Nanoseconds()

	c.dnsForwarderCache.Range(func(key, value any) bool {
		k, ok := key.(dnsForwarderKey)
		if !ok {
			c.dnsForwarderCache.Delete(key)
			return true
		}

		entry, ok := value.(*cachedDnsForwarder)
		if !ok {
			if forwarder := c.extractDnsForwarder(value); forwarder != nil {
				if c.dnsForwarderCache.CompareAndDelete(k, value) {
					if err := forwarder.Close(); err != nil && c.log != nil {
						c.log.WithError(err).Debugln("failed to close idle dns forwarder")
					}
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

		// retire() marks the entry retired and defers Close until in-flight
		// work finishes, closing the TOCTOU where a query grabbed the entry
		// between the scan and this Close.
		if c.dnsForwarderCache.CompareAndDelete(k, entry) {
			if err := entry.retire(); err != nil && c.log != nil {
				c.log.WithError(err).Debugln("failed to retire idle dns forwarder")
			}
		}
		return true
	})
}

func (c *DnsController) reportDnsForwardFailure(dialArg *dialArgument, err error) {
	if dialArg == nil || err == nil {
		return
	}
	// Caller-driven cancellation should not mark a dialer as unavailable.
	if commonerrors.IsCanceledOrClosed(err) || errors.Is(err, ErrDNSUDPConnPoolExhausted) {
		return
	}
	if lifecycle, ok := newDnsUdpLifecycleContext(dialArg, UdpLifecycleProfile{}); ok {
		lifecycle.reportUnavailable(err)
	}
	if rt := c.runtime(); rt != nil && rt.timeoutExceedCallback != nil {
		rt.timeoutExceedCallback(dialArg, err)
	}
	notifyProxyDialerHealthCheck(dialArg.bestDialer, dialArg.l4proto, err)
}

func (c *DnsController) logDnsForwardFailure(upstream *dns.Upstream, dialArg *dialArgument, err error) {
	if c == nil || c.log == nil || err == nil {
		return
	}
	if commonerrors.IsCanceledOrClosed(err) || errors.Is(err, ErrDNSUDPConnPoolExhausted) {
		return
	}
	fields := logrus.Fields{}
	if upstream != nil {
		fields["upstream"] = upstream.String()
	}
	if dialArg != nil {
		fields["network"] = string(dialArg.l4proto) + "+" + string(dialArg.ipversion)
		if dialArg.bestTarget.IsValid() {
			fields["target"] = dialArg.bestTarget.String()
		}
		if dialArg.bestOutbound != nil {
			fields["outbound"] = dialArg.bestOutbound.Name
			fields["policy"] = dialArg.bestOutbound.GetSelectionPolicy()
		}
		if dialArg.bestDialer != nil && dialArg.bestDialer.Property() != nil {
			fields["dialer"] = dialArg.bestDialer.Property().Name
		}
	}
	c.log.WithError(err).WithFields(fields).Warn("DNS forward to upstream failed")
}

func (c *DnsController) shouldRetireCachedDnsForwarder(upstream *dns.Upstream, dialArg *dialArgument, entry *cachedDnsForwarder, err error) bool {
	if dialArg == nil || err == nil {
		return false
	}
	if commonerrors.IsCanceledOrClosed(err) || errors.Is(err, ErrDNSUDPConnPoolExhausted) {
		return false
	}
	// UDP forwarders keep pooled sockets whose state can be poisoned by a single
	// timeout or stale-response burst. Flush the whole cached forwarder so the
	// next query starts from a clean socket pool.
	if dialArg.l4proto == consts.L4ProtoStr_UDP {
		return true
	}
	if upstream == nil || !isProxyBackedDialer(dialArg.bestDialer) {
		return false
	}
	// Retire any forwarder that has failed too many times in a row, even
	// stream-style ones, to prevent a permanently broken instance from
	// accumulating retries without relief.
	if entry != nil && entry.consecutiveErrors.Load() >= maxConsecutiveForwardErrors {
		return true
	}
	switch upstream.Scheme {
	case dns.UpstreamScheme_TCP,
		dns.UpstreamScheme_TCP_UDP,
		dns.UpstreamScheme_TLS,
		dns.UpstreamScheme_HTTPS,
		dns.UpstreamScheme_H3,
		dns.UpstreamScheme_QUIC:
		// Stream-style forwarders already rebuild their own transport state on
		// request failures. Retiring the whole cached forwarder for an ordinary
		// timeout only forces extra cold starts and can amplify control-plane
		// DNS failures into repeated proxy-host re-resolution loops.
		return false
	default:
		return false
	}
}

func (c *DnsController) retireCachedDnsForwarder(key dnsForwarderKey, entry *cachedDnsForwarder) {
	if entry == nil {
		return
	}
	if !c.dnsForwarderCache.CompareAndDelete(key, entry) {
		return
	}
	if err := entry.retire(); err != nil && c.log != nil {
		c.log.WithError(err).Debugln("failed to close retired dns forwarder")
	}
}

func newDnsForwarderKey(upstream *dns.Upstream, dialArg *dialArgument) dnsForwarderKey {
	key := dnsForwarderKey{}
	if upstream != nil {
		key.upstream = upstream.String()
	}
	if dialArg == nil {
		return key
	}
	key.l4proto = dialArg.l4proto
	key.ipversion = dialArg.ipversion
	if dialArg.bestDialer != nil && dialArg.bestDialer.Property() != nil {
		key.dialerName = dialArg.bestDialer.Property().Name
	}
	if dialArg.bestOutbound != nil {
		key.outboundName = dialArg.bestOutbound.Name
	}
	key.bestTarget = dialArg.bestTarget
	key.mark = dialArg.mark
	key.mptcp = dialArg.mptcp
	return key
}

func (c *DnsController) getOrCreateDnsForwarder(upstream *dns.Upstream, dialArg *dialArgument) (*cachedDnsForwarder, error) {
	if c.dnsForwardersClosed.Load() {
		return nil, ErrDnsForwardersClosed
	}
	key := newDnsForwarderKey(upstream, dialArg)
	now := time.Now()

	for range 3 {
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
	if c.dnsForwardersClosed.Load() {
		// The controller was closed between the entry check and this store.
		// Stores that landed before the sweep's Range reaches the key get
		// swept anyway; stores that land after the sweep passed would never
		// be closed by anyone, so undo this one and fail the in-flight
		// query instead. closeNow routes through the cached wrapper's
		// closeOnce, keeping the double-close with a concurrent sweep
		// idempotent.
		c.dnsForwarderCache.CompareAndDelete(key, created)
		_ = created.closeNow()
		return nil, ErrDnsForwardersClosed
	}
	return created, nil
}

func (c *DnsController) forwardWithDialArg(ctx context.Context, upstream *dns.Upstream, dialArg *dialArgument, data []byte) (*dnsmessage.Msg, error) {
	c.requireStore()
	key := newDnsForwarderKey(upstream, dialArg)
	for range 2 {
		entry, err := c.getOrCreateDnsForwarder(upstream, dialArg)
		if err != nil {
			return nil, err
		}
		if !entry.beginUse() {
			continue
		}

		respMsg, err := entry.forwarder.ForwardDNS(ctx, data)
		entry.endUse()
		if err != nil {
			// ErrDNSTruncated is a valid DNS protocol signal (response too
			// large for UDP), not a transport failure.  Propagate the error
			// so the caller can react (e.g. tcp+udp fallback, or TC=1 to
			// client), but do NOT retire the forwarder, penalise the dialer
			// or emit a misleading failure log.
			if !errors.Is(err, ErrDNSTruncated) {
				entry.consecutiveErrors.Add(1)
				if c.shouldRetireCachedDnsForwarder(upstream, dialArg, entry, err) {
					c.retireCachedDnsForwarder(key, entry)
				}
				c.logDnsForwardFailure(upstream, dialArg, err)
				c.reportDnsForwardFailure(dialArg, err)
			}
			return nil, err
		}
		entry.consecutiveErrors.Store(0)
		return respMsg, nil
	}
	return nil, fmt.Errorf("dns forwarder retired before request could start")
}

func (c *DnsController) closeAllDnsForwarders() []error {
	if c == nil {
		return nil
	}
	// Set the closed flag before sweeping: combined with the post-store
	// recheck in getOrCreateDnsForwarder, this makes it impossible for an
	// in-flight query to leave a freshly created forwarder in the cache
	// after this sweep returns (see the ordering argument there).
	c.dnsForwardersClosed.Store(true)
	var errs []error
	c.dnsForwarderCache.Range(func(key, value any) bool {
		k := key.(dnsForwarderKey)
		c.dnsForwarderCache.Delete(k)
		switch entry := value.(type) {
		case *cachedDnsForwarder:
			if err := entry.closeNow(); err != nil {
				errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", k.upstream, err))
			}
		default:
			forwarder := c.extractDnsForwarder(value)
			if forwarder != nil {
				if err := forwarder.Close(); err != nil {
					errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", k.upstream, err))
				}
			}
		}
		return true
	})
	return errs
}

func (c *DnsController) retireAllDnsForwarders() []error {
	if c == nil {
		return nil
	}
	var errs []error
	c.dnsForwarderCache.Range(func(key, value any) bool {
		k := key.(dnsForwarderKey)
		switch entry := value.(type) {
		case *cachedDnsForwarder:
			if !c.dnsForwarderCache.CompareAndDelete(k, entry) {
				return true
			}
			if err := entry.retire(); err != nil {
				errs = append(errs, fmt.Errorf("retire dns forwarder %q: %w", k.upstream, err))
			}
		default:
			if !c.dnsForwarderCache.CompareAndDelete(k, value) {
				return true
			}
			forwarder := c.extractDnsForwarder(value)
			if forwarder != nil {
				if err := forwarder.Close(); err != nil {
					errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", k.upstream, err))
				}
			}
		}
		return true
	})
	return errs
}

func (c *DnsController) ResetDnsForwarders() error {
	if c == nil || c.dnsControllerStore == nil {
		return nil
	}
	// Retire cached forwarders so new requests redial using the replacement
	// generation's runtime, while in-flight upstream exchanges finish cleanly.
	return errors.Join(c.retireAllDnsForwarders()...)
}

func (c *DnsController) dialSend(
	ctx context.Context,
	req *udpRequest,
	data []byte,
	id uint16,
	upstream *dns.Upstream,
	responseWriter dnsmessage.ResponseWriter,
	responseCacheKey string,
) (err error) {
	// Keep a reference to the original request bytes: data is later
	// overwritten with the packed response, but the client's EDNS0 size
	// must be read from the request when truncating oversized replies.
	dnsRequestData := data
	resolution, err := c.resolveDNSUpstream(ctx, 0, req, data, upstream)
	if err != nil {
		return err
	}
	respMsg := resolution.response

	// RFC 8305 resolution delay: this is the delivery side, so a non-preferred
	// A/AAAA answer waits here for a preferred one without holding any shared
	// resolution state.
	respMsg = c.applyPreferenceWait(respMsg)

	if resolution.upstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.DebugLevel) {
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
			"network":  resolution.networkType.String(),
			"outbound": resolution.dialArgument.bestOutbound.Name,
			"policy":   resolution.dialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   resolution.dialArgument.bestDialer.Property().Name,
			"_qname":   qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch resolution.upstreamIndex {
		case consts.DnsResponseOutboundIndex_Accept:
			c.log.WithFields(fields).Debugf("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(resolution.dialArgument.bestTarget))
		case consts.DnsResponseOutboundIndex_Reject:
			c.log.WithFields(fields).Debugf("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr()))
		default:
			return fmt.Errorf("unknown upstream: %v", resolution.upstreamIndex.String())
		}
	}

	// Optimization: Send response first, then cache asynchronously.
	// This reduces client-perceived latency.
	//
	// Cache operations and BPF updates are fast, but doing them async is still beneficial:
	// - Reduces tail latency under load
	// - Follows "respond first, process later" best practice
	//
	// Trade-off: If caching fails, the response is still valid but won't be cached.
	// This is acceptable because:
	// - Cache failures are rare
	// - The response is already sent to the client
	// - Next request for same domain will just hit upstream again
	// Keep the id the same with request.
	respMsg.Id = id
	respMsg.Compress = true
	// If responseWriter is provided, use it to write the response.
	if responseWriter != nil {
		// For responseWriter path, cache synchronously because
		// responseWriter may need the message after we return.
		if err = c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
			c.noteDnsCacheStoreFailure("response writer", err)
		}
		return responseWriter.WriteMsg(respMsg)
	}
	// Pack into a pooled DNS response buffer; data is consumed synchronously by the send.
	bufPtr := dnsResponseBufPool.Get().(*[]byte)
	defer dnsResponseBufPool.Put(bufPtr)
	data, err = respMsg.PackBuffer((*bufPtr)[:cap(*bufPtr)])
	if err != nil {
		return err
	}

	// Truncate only the outgoing wire message, including oversized OPT options.
	// Keep respMsg intact for asynchronous caching and later TCP retries.
	limit := dnsDefaultUDPSize
	if len(data) > limit {
		var reqMsg dnsmessage.Msg
		if err = reqMsg.Unpack(dnsRequestData); err == nil {
			limit = dnsUDPResponseSizeLimit(&reqMsg)
		}
		data = truncateDNSResponse(data, limit)
	}

	if err = sendRuntimeTrackedPkt(c.log, data, req.realDst, req.realSrc, req.replySoMark(), req.downloadRecorder()); err != nil {
		return err
	}

	// Cache asynchronously after sending response (UDP path only).
	// respMsg is owned by this function and won't be accessed after return,
	// so it's safe to use in goroutine without copying.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.log.Errorf("panic in async DNS cache: %v", r)
			}
		}()
		if err := c.NormalizeAndCacheDnsResp_(respMsg, responseCacheKey); err != nil {
			c.noteDnsCacheStoreFailure("async after send", err)
		}
	}()

	return nil
}
