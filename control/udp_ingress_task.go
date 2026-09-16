/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	stderrors "errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pool"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// cachedRoutingLookup is the per-packet routing-cache probe. Endpoint
// pointers live only for this packet; they are never stored on UdpFlowDecision.
type cachedRoutingLookup struct {
	bound       *bpfRoutingResult
	bindingHit  bool
	owner       *UdpEndpoint
	prefetch    *UdpEndpoint
	prefetchKey UdpEndpointKey
	prefetchOK  bool
}

// lookupCachedRoutingBinding resolves the flow's bound routing result from the
// routing-cache endpoints referenced by the flow decision: the primary cached
// endpoint first, then the symmetric fallback endpoint when the primary's
// binding missed. owner is the last endpoint Get actually found (primary, or
// fallback if primary was absent) so Run can UpdateCachedRoutingResult without
// a second pool lookup. prefetch is the primary endpoint only when its bound
// result hit AND its pool key is the same key handlePkt would Get first
// without a cross-probe; a binding miss must not prefetch, because handlePkt
// still has to probe the live NAT key independently.
func lookupCachedRoutingBinding(flowDecision UdpFlowDecision, realDst netip.AddrPort) cachedRoutingLookup {
	out := cachedRoutingLookup{}
	primaryKey := flowDecision.CachedRoutingEndpointKey()
	if ue, ok := DefaultUdpEndpointPool.Get(primaryKey); ok {
		out.owner = ue
		if bound, bindingHit := ue.GetBoundRoutingResult(realDst, unix.IPPROTO_UDP); bindingHit {
			out.bound = bound
			out.bindingHit = true
			if canPrefetchCachedEndpoint(flowDecision, primaryKey) {
				out.prefetch = ue
				out.prefetchKey = primaryKey
				out.prefetchOK = true
			}
			return out
		}
		// Binding miss: keep owner for a later cache write, but still try
		// the fallback endpoint in case it holds the dst+proto binding.
	}
	if fallbackKey, ok := flowDecision.CachedRoutingFallbackKey(); ok {
		if ue, ok := DefaultUdpEndpointPool.Get(fallbackKey); ok {
			out.owner = ue
			if bound, bindingHit := ue.GetBoundRoutingResult(realDst, unix.IPPROTO_UDP); bindingHit {
				out.bound = bound
				out.bindingHit = true
				if canPrefetchCachedEndpoint(flowDecision, fallbackKey) {
					out.prefetch = ue
					out.prefetchKey = fallbackKey
					out.prefetchOK = true
				}
			}
		}
	}
	return out
}

// canPrefetchCachedEndpoint reports whether handlePkt's first Get uses key
// with no required src-only/symmetric cross-probe. Prefetch is only valid
// for this packet and only when that first lookup would be a pure hit.
//
// The NAT cross-probe in handlePkt runs only after a first-Get miss. A
// prefetch of the same first key therefore cannot skip a required probe:
// if the first Get would have missed, prefetchOK is already false because
// this function requires firstKey == key. Sniff-eligible ordinary UDP
// starts at the symmetric key, so a FullCone cache hit never prefetches.
func canPrefetchCachedEndpoint(flowDecision UdpFlowDecision, key UdpEndpointKey) bool {
	emptyScope := udpEndpointRouteScope{}
	firstKey := flowDecision.EndpointKeyForInitialLookupWithScope(emptyScope, false)
	return firstKey == key
}

// routingCacheOwnerEndpoint finds the endpoint that owns the flow's cached
// routing result: the primary cached endpoint if present, else the fallback.
func routingCacheOwnerEndpoint(flowDecision UdpFlowDecision) *UdpEndpoint {
	return lookupCachedRoutingBinding(flowDecision, netip.AddrPort{}).owner
}

// udpIngressTask is the pooled owned form of the per-packet ingress task
// that used to be an escaping closure inside processPacket. Under saturated
// UDP load the closure was ~200-300B allocated per packet (~20% of the
// hot-path allocation profile); this structure captures the same variables
// by value (they are per-packet locals that never change after submission,
// so snapshotting is semantically identical) and is returned to the pool
// when Run completes.
type udpIngressTask struct {
	c            *ControlPlane
	lConn        *net.UDPConn
	pktBuf       pool.PB
	admission    *routingEpochIngressGate
	realDst      netip.AddrPort
	convergeSrc  netip.AddrPort
	flowDecision UdpFlowDecision
	// dispatchSem, when non-nil, is the direct-dispatch concurrency slot this
	// task holds; Run releases it together with the other resources. It must
	// be assigned on every pool checkout (nil for queued dispatch) so a stale
	// pointer left by a previous use can never release a slot that was never
	// acquired.
	dispatchSem chan struct{}
}

var udpIngressTaskPool = sync.Pool{
	New: func() any { return &udpIngressTask{} },
}

// releaseDispatchSem returns the direct-dispatch concurrency slot, if any.
// It must run before the task object returns to the pool.
func (t *udpIngressTask) releaseDispatchSem() {
	if sem := t.dispatchSem; sem != nil {
		<-sem
	}
}

// Discard releases the packet resources without executing the task. It is
// used when queue teardown (convoy panic recovery or pool Close) strands
// tasks that never ran: their buffer, admission ticket, and pooled object
// must still be returned, in the same order Run's defers would.
func (t *udpIngressTask) Discard() {
	t.releaseDispatchSem()
	t.pktBuf.Put()
	t.admission.release()
	*t = udpIngressTask{}
	udpIngressTaskPool.Put(t)
}

// Run executes the ingress packet handling. The buffer and admission gate
// are released and the task is returned to the pool in all paths.
func (t *udpIngressTask) Run() {
	c := t.c
	data := t.pktBuf
	realDst := t.realDst
	convergeSrc := t.convergeSrc
	flowDecision := t.flowDecision

	// Defers run in LIFO order: dispatch slot, admission, buffer, then the
	// task itself (the pool must not see the task before its deferred cleanup
	// completes, and the dispatch slot must be read before the task returns
	// to the pool). The final defer zeroes the task before Put so no stale
	// field can leak into the next checkout, matching Discard.
	defer func() {
		*t = udpIngressTask{}
		udpIngressTaskPool.Put(t)
	}()
	defer data.Put()
	defer t.admission.release()
	defer t.releaseDispatchSem()
	var routingResult *bpfRoutingResult
	var freshRoutingResult *bpfRoutingResult

	// DNS ingress fast path: valid DNS packets to port 53 do not need
	// UdpEndpoint state tracking on ingress. Keep userspace handling to
	// reduce hot-path overhead, but best-effort preserve tuple metadata
	// for rules matching (pname/mac/dscp).
	if realDst.Port() == 53 {
		// Only self-directed traffic to the local DNS listener should be
		// short-circuited here. External LAN clients targeting a LAN-bound
		// listener have already entered the ingress/TProxy userspace path
		// and still need fast-path DNS handling.
		if c.dnsListener != nil {
			listenAddr := c.dnsListener.Addr()
			if shouldSkipDNSFastPathForLocalListenerTraffic(listenAddr, convergeSrc, realDst) {
				if c.log.IsLevelEnabled(logrus.TraceLevel) {
					c.log.WithFields(logrus.Fields{
						"src":        convergeSrc.String(),
						"dst":        realDst.String(),
						"listenAddr": listenAddr,
					}).Trace("Local traffic to our own DNS listener; handling via DNS fast path instead of NAT-tracking")
				}
				// Fall through: kernel already TC_ACT_OKs unmarked local
				// sockets, but a packet that reached TProxy must still be
				// answered. Dropping here black-holes 127.0.0.1:53.
			}
		}

		if dnsMessage, _ := ChooseNatTimeout(data, true); dnsMessage != nil {
			dnsRoutingResult := &bpfRoutingResult{
				Outbound: uint8(consts.OutboundControlPlaneRouting),
			}
			if rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP); retrieveErr == nil {
				dnsRoutingResult = rr
			} else if !stderrors.Is(retrieveErr, ebpf.ErrKeyNotExist) && c.log.IsLevelEnabled(logrus.DebugLevel) {
				c.log.WithFields(logrus.Fields{
					"src": convergeSrc.String(),
					"dst": realDst.String(),
				}).WithError(retrieveErr).Debug("UDP routing tuple lookup failed for DNS ingress fast path; fallback to minimal routing metadata")
			}
			handler, release, ownerErr := c.acquireRoutingEpochExecutionOwner(dnsRoutingResult)
			if ownerErr != nil {
				// The owner is missing for every DNS packet of every flow while
				// the owning generation retires, so this is a condition rather
				// than an event: pace it like the UDP ingress path paces the
				// same condition instead of writing one line per packet.
				if c.log.IsLevelEnabled(logrus.WarnLevel) && c.allowHandlePktEpochWarn(time.Now()) {
					c.log.WithError(ownerErr).WithFields(logrus.Fields{
						"src": convergeSrc.String(),
						"dst": realDst.String(),
					}).Warn("DNS ingress routing epoch owner is unavailable; DNS packets are dropped while the owning generation retires")
				}
				return
			}
			if release != nil {
				defer release()
			}
			if dnsRoutingResult.Mark == 0 {
				dnsRoutingResult.Mark = handler.soMarkFromDae
			}
			// Account the query like the ordinary UDP paths do; the
			// ingress plane owns the packet, so its recorders are used
			// (matching what the removed udp.go fast path recorded).
			c.recordUploadTraffic(int64(len(data)))
			req := &udpRequest{
				realSrc:       convergeSrc,
				realDst:       realDst,
				src:           convergeSrc,
				lConn:         t.lConn,
				routingResult: dnsRoutingResult,

				uploadRecord:   c.runtimeUploadRecorder(),
				downloadRecord: c.runtimeDownloadRecorder(),
			}

			dnsController := handler.ActiveDnsController()
			if dnsController == nil {
				return
			}
			if e := dnsController.Handle_(handler.dnsRequestContext(handler.ctx, dnsController), dnsMessage, req); e != nil {
				if stderrors.Is(e, ErrDNSQueryConcurrencyLimitExceeded) {
					if handler.log.IsLevelEnabled(logrus.DebugLevel) {
						handler.log.WithFields(logrus.Fields{
							"src": convergeSrc.String(),
							"dst": realDst.String(),
						}).Debug("DNS query concurrency limit exceeded in fast path")
					}
					return
				}
				if stderrors.Is(e, ErrDNSTruncated) {
					if handler.log.IsLevelEnabled(logrus.DebugLevel) {
						handler.log.WithFields(logrus.Fields{
							"src":      convergeSrc.String(),
							"dst":      realDst.String(),
							"question": dnsMessage.Question,
						}).Debug("DNS ingress fast path got truncated UDP response; returning TC=1 to client")
					}
					if sendErr := dnsController.sendDnsTruncatedResponse_(dnsMessage, req, nil); sendErr != nil {
						if handler.log.IsLevelEnabled(logrus.WarnLevel) && handler.allowDnsFastPathServfailLog(time.Now()) {
							handler.log.WithError(stderrors.Join(e, sendErr)).WithFields(logrus.Fields{
								"src": convergeSrc.String(),
								"dst": realDst.String(),
							}).Warn("Failed to send truncated DNS response in DNS fast path")
						}
					}
					return
				}
				if handler.log.IsLevelEnabled(logrus.WarnLevel) && handler.allowDnsFastPathErrorLog(time.Now()) {
					handler.log.WithFields(logrus.Fields{
						"src":      convergeSrc.String(),
						"dst":      realDst.String(),
						"question": dnsMessage.Question,
						"error":    e.Error(),
					}).Warn("DNS ingress fast path failed; sending SERVFAIL response")
				}
				if sendErr := dnsController.sendDnsErrorResponse_(dnsMessage, dnsmessage.RcodeServerFailure, false, "ServeFail (dns ingress fast path)", req, nil); sendErr != nil {
					if handler.log.IsLevelEnabled(logrus.WarnLevel) && handler.allowDnsFastPathServfailLog(time.Now()) {
						handler.log.WithError(stderrors.Join(e, sendErr)).WithFields(logrus.Fields{
							"src": convergeSrc.String(),
							"dst": realDst.String(),
						}).Warn("Failed to send SERVFAIL response in DNS fast path")
					}
					return
				}
			} else if handler.log.IsLevelEnabled(logrus.TraceLevel) {
				// Success logging for DNS fast path (trace level only)
				handler.log.WithFields(logrus.Fields{
					"src":      convergeSrc.String(),
					"dst":      realDst.String(),
					"question": dnsMessage.Question,
				}).Trace("DNS ingress fast path handled successfully")
			}
			return
		}
	}

	var cacheLookup cachedRoutingLookup
	if !c.udpRouteScopeSensitive && c.ownsActiveRoutingEpoch() {
		cacheLookup = lookupCachedRoutingBinding(flowDecision, realDst)
		if cacheLookup.bindingHit {
			routingResult = cacheLookup.bound
		}
	}

	if routingResult == nil {
		rr, retrieveErr := c.core.RetrieveRoutingResult(convergeSrc, realDst, unix.IPPROTO_UDP)
		if retrieveErr != nil {
			switch {
			case stderrors.Is(retrieveErr, ebpf.ErrKeyNotExist):
				// Keep behavior consistent with TCP path: missing tuple can happen
				// in short race windows; fallback to userspace routing instead of
				// dropping the packet.
				routingResult = &bpfRoutingResult{
					Outbound: uint8(consts.OutboundControlPlaneRouting),
				}
				if c.log.IsLevelEnabled(logrus.DebugLevel) {
					c.log.WithFields(logrus.Fields{
						"src": convergeSrc.String(),
						"dst": realDst.String(),
					}).WithError(retrieveErr).Debug("UDP routing tuple missing; fallback to userspace routing")
				}
			case realDst.Port() == 53:
				// DNS should never be silently dropped due to transient eBPF lookup
				// failures. Fall back to userspace routing to preserve availability.
				routingResult = &bpfRoutingResult{
					Outbound: uint8(consts.OutboundControlPlaneRouting),
				}
				c.logUdpDNSRoutingTupleFailure(convergeSrc, realDst, retrieveErr)
			default:
				c.logUdpRoutingTupleFailure(retrieveErr)
				return
			}
		} else {
			routingResult = rr
			rrCopy := *routingResult
			freshRoutingResult = &rrCopy
		}
	}

	if e := c.handlePktWithPrefetch(data, convergeSrc, realDst, routingResult, flowDecision, cacheLookup.prefetch, cacheLookup.prefetchKey, cacheLookup.prefetchOK); e != nil {
		// Both branches report a condition that repeats per packet: the
		// reload-window routing-epoch ownership loss, and any other failure
		// that persists for the flow (and therefore for every later packet of
		// it). Each is paced on its own so neither can hide the other, and the
		// emitted line carries the number of packets seen so far.
		if stderrors.Is(e, errRoutingEpochOwnerUnavailable) {
			if c.log.IsLevelEnabled(logrus.WarnLevel) && c.allowHandlePktEpochWarn(time.Now()) {
				c.log.Warnln("handlePkt:", e)
			}
		} else {
			c.logUdpHandlePktFailure(e)
		}
		return
	}

	if !c.udpRouteScopeSensitive && c.ownsActiveRoutingEpoch() && freshRoutingResult != nil {
		owner := cacheLookup.owner
		if owner == nil {
			owner = routingCacheOwnerEndpoint(flowDecision)
		}
		if owner != nil {
			owner.UpdateCachedRoutingResult(realDst, unix.IPPROTO_UDP, freshRoutingResult)
		}
	}
}
