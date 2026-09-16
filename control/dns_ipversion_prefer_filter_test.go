/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the documented ipversion_prefer contract: while the preferred
// address family has records for a name, the other family is answered with an
// empty reply (NOERROR, no answers) so clients fall back to the preferred
// family, and the non-preferred answer never survives in the response cache.
//
// The RFC 8305 resolution delay stays: with no knowledge about the preferred
// family the non-preferred answer is still delivered unchanged.

func preferIPv4(t *testing.T, ctrl *DnsController) {
	t.Helper()
	setTestDnsControllerRuntime(ctrl, func(rt *dnsControllerRuntimeState) {
		rt.qtypePrefer = dnsmessage.TypeA
	})
}

// newPreferenceFilterController builds a controller whose upstream answers the
// given AAAA response for every query.
func newPreferenceFilterController(t *testing.T, aaaa *dnsmessage.Msg) *DnsController {
	t.Helper()
	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return aaaa.Copy(), nil
		}}, nil
	})
	return newCorpusControllerWithDefaultChooser(t, truncatedTestConfig())
}

func cacheAddressAnswer(t *testing.T, ctrl *DnsController, qname string, qtype uint16, answers []dnsmessage.RR) {
	t.Helper()
	req := defaultUdpRequest()
	baseKey := ctrl.cacheKey(qname, qtype)
	cacheKey := ctrl.responseCacheKey(baseKey, req, consts.DnsRequestOutboundIndex_AsIs, nil)
	installCorpusCache(t, ctrl, cacheKey, qname, qtype, answers, 300)
}

// TestIPVersionPreferFiltersNonPreferredQuery covers the documented behavior on
// the delivery path: the preferred A family is cached with a record, so the
// AAAA answer resolved for the client must be replaced by an empty reply.
func TestIPVersionPreferFiltersNonPreferredQuery(t *testing.T) {
	const qname = "prefer-filter.test."
	ctrl := newPreferenceFilterController(t, dnsAAAAResponseMsg(qname, "2001:db8::7"))
	preferIPv4(t, ctrl)

	cacheAddressAnswer(t, ctrl, qname, dnsmessage.TypeA, dnsAResponseMsg(qname, "198.51.100.7").Answer)

	writer := &dnsCorpusCaptureWriter{}
	query := corpusDnsQuery(0x7701, qname, dnsmessage.TypeAAAA)
	if err := ctrl.HandleWithResponseWriter_(context.Background(), query, defaultUdpRequest(), writer); err != nil {
		t.Fatalf("HandleWithResponseWriter_: %v", err)
	}
	served := writer.Message()
	if served == nil {
		t.Fatal("no response served")
	}
	if len(served.Answer) != 0 {
		t.Fatalf("answer count = %d, want the documented empty reply for the non-preferred family", len(served.Answer))
	}
	if served.Rcode != dnsmessage.RcodeSuccess {
		t.Fatalf("rcode = %v, want NOERROR", served.Rcode)
	}
	if len(served.Question) == 0 || served.Question[0].Qtype != dnsmessage.TypeAAAA {
		t.Fatalf("question = %v, want the client's AAAA question echoed", served.Question)
	}
	if served.Truncated {
		t.Fatal("an empty reply must not keep the TC bit set")
	}
	// The AAAA answer must not stay cached: the response-cache fast path
	// releases cached answers without consulting the preference.
	if keys := ctrl.dnsCacheIndexSnapshot(ctrl.cacheKey(qname, dnsmessage.TypeAAAA)); len(keys) != 0 {
		t.Fatalf("cached AAAA family survived the filter: %v", keys)
	}
	if got := ctrl.dnsPreferFiltered.Load(); got == 0 {
		t.Fatal("the filter counter must record the dropped non-preferred answer")
	}
}

// TestIPVersionPreferFiltersWhenPreferredArrivesDuringWait covers the resolution
// delay path: the non-preferred answer waits, a preferred answer with records
// arrives, so the non-preferred answer is replaced by an empty reply instead of
// being delivered after the wait.
func TestIPVersionPreferFiltersWhenPreferredArrivesDuringWait(t *testing.T) {
	const qname = "prefer-wait.test."
	ctrl := newSemanticsController(t)
	preferIPv4(t, ctrl)

	resp := dnsAAAAResponseMsg(qname, "2001:db8::8")
	go func() {
		time.Sleep(10 * time.Millisecond)
		ctrl.notifyPreferenceWait(dnsAResponseMsg(qname, "198.51.100.8"))
	}()

	served := ctrl.applyPreferenceWait(resp)
	if served == resp {
		t.Fatal("the AAAA answer was delivered although the preferred A family has records")
	}
	if len(served.Answer) != 0 {
		t.Fatalf("answer count = %d, want an empty reply", len(served.Answer))
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("the shared resolution result was mutated (answers = %d)", len(resp.Answer))
	}
	if got := ctrl.dnsPreferWaitNotified.Load(); got != 1 {
		t.Fatalf("preference-wait notify counter = %d, want 1", got)
	}
	if got := ctrl.dnsPreferWaitTimeout.Load(); got != 0 {
		t.Fatalf("preference-wait timeout counter = %d, want 0 (the preferred answer arrived)", got)
	}
}

// TestIPVersionPreferKeepsAnswerWhenPreferredHasNoRecords: a preferred response
// that carries no address record (NODATA) proves nothing about the preferred
// family, so the non-preferred answer must still be delivered.
func TestIPVersionPreferKeepsAnswerWhenPreferredHasNoRecords(t *testing.T) {
	const qname = "prefer-nodata.test."
	ctrl := newSemanticsController(t)
	preferIPv4(t, ctrl)

	nodata := new(dnsmessage.Msg)
	nodata.SetQuestion(qname, dnsmessage.TypeA)
	nodata.Response = true

	resp := dnsAAAAResponseMsg(qname, "2001:db8::9")
	go func() {
		time.Sleep(10 * time.Millisecond)
		ctrl.notifyPreferenceWait(nodata)
	}()

	served := ctrl.applyPreferenceWait(resp)
	if served != resp {
		t.Fatal("a preferred NODATA answer must not suppress the non-preferred answer")
	}
	if len(served.Answer) != 1 {
		t.Fatalf("answer count = %d, want the original AAAA answer", len(served.Answer))
	}
}

// TestIPVersionPreferKeepsAnswerWithoutPreferredKnowledge: with no preferred
// answer in the cache and none arriving, the non-preferred answer is delivered
// unchanged after the resolution delay.
func TestIPVersionPreferKeepsAnswerWithoutPreferredKnowledge(t *testing.T) {
	const qname = "prefer-unknown.test."
	ctrl := newSemanticsController(t)
	preferIPv4(t, ctrl)

	resp := dnsAAAAResponseMsg(qname, "2001:db8::a")
	served := ctrl.applyPreferenceWait(resp)
	if served != resp {
		t.Fatal("without knowledge about the preferred family the answer must be delivered unchanged")
	}
	if got := ctrl.dnsPreferWaitTimeout.Load(); got != 1 {
		t.Fatalf("preference-wait timeout counter = %d, want 1", got)
	}
	if got := ctrl.dnsPreferFiltered.Load(); got != 0 {
		t.Fatalf("filter counter = %d, want 0", got)
	}
}

// TestIPVersionPreferPreferredDeliveryDropsCachedNonPreferred: delivering the
// preferred family must invalidate the cached non-preferred answer, otherwise a
// later non-preferred query would be answered from the cache fast path.
func TestIPVersionPreferPreferredDeliveryDropsCachedNonPreferred(t *testing.T) {
	const qname = "prefer-purge.test."
	ctrl := newSemanticsController(t)
	preferIPv4(t, ctrl)

	cacheAddressAnswer(t, ctrl, qname, dnsmessage.TypeAAAA, dnsAAAAResponseMsg(qname, "2001:db8::b").Answer)

	served := ctrl.applyPreferenceWait(dnsAResponseMsg(qname, "198.51.100.9"))
	if served == nil || len(served.Answer) != 1 {
		t.Fatal("the preferred answer itself must be delivered unchanged")
	}
	if keys := ctrl.dnsCacheIndexSnapshot(ctrl.cacheKey(qname, dnsmessage.TypeAAAA)); len(keys) != 0 {
		t.Fatalf("cached AAAA family survived the preferred delivery: %v", keys)
	}
	if got := ctrl.dnsPreferFiltered.Load(); got != 1 {
		t.Fatalf("filter counter = %d, want 1", got)
	}
}

// TestIPVersionPreferIsSymmetricPreferAAAA checks the opposite preference: with
// prefer=6 the cached AAAA records make an A answer empty.
func TestIPVersionPreferIsSymmetricPreferAAAA(t *testing.T) {
	const qname = "prefer-six.test."
	ctrl := newSemanticsController(t)
	preferAAAA(t, ctrl)

	cacheAddressAnswer(t, ctrl, qname, dnsmessage.TypeAAAA, dnsAAAAResponseMsg(qname, "2001:db8::c").Answer)

	served := ctrl.applyPreferenceWait(dnsAResponseMsg(qname, "198.51.100.10"))
	if served == nil || len(served.Answer) != 0 {
		t.Fatalf("answer count = %d, want an empty reply for the non-preferred A family", len(served.Answer))
	}
}

// TestIPVersionPreferSuppressesCachedNonPreferredAnswer covers the state a path
// outside the delivery filter can leave behind - the optimistic background
// refresh and the forwarder store write the cache directly - so the cache can
// hold a fresh non-preferred answer while the preferred family is fresh too.
// The response-cache fast path releases that entry without passing through
// applyPreferenceWait, so the preference must be enforced at the release point:
// before the fix this test observes a served AAAA answer.
func TestIPVersionPreferSuppressesCachedNonPreferredAnswer(t *testing.T) {
	const qname = "prefer-cache-hit.test."
	ctrl := newPreferenceFilterController(t, dnsAAAAResponseMsg(qname, "2001:db8::d"))
	preferIPv4(t, ctrl)

	cacheAddressAnswer(t, ctrl, qname, dnsmessage.TypeA, dnsAResponseMsg(qname, "198.51.100.11").Answer)
	cacheAddressAnswer(t, ctrl, qname, dnsmessage.TypeAAAA, dnsAAAAResponseMsg(qname, "2001:db8::d").Answer)

	writer := &dnsCorpusCaptureWriter{}
	query := corpusDnsQuery(0x7702, qname, dnsmessage.TypeAAAA)
	if err := ctrl.HandleWithResponseWriter_(context.Background(), query, defaultUdpRequest(), writer); err != nil {
		t.Fatalf("HandleWithResponseWriter_: %v", err)
	}
	served := writer.Message()
	if served == nil {
		t.Fatal("no response served")
	}
	if len(served.Answer) != 0 {
		t.Fatalf("served %d cached AAAA answer(s); the fast path must apply the preference", len(served.Answer))
	}
	if served.Rcode != dnsmessage.RcodeSuccess {
		t.Fatalf("rcode = %v, want NOERROR", served.Rcode)
	}
	if keys := ctrl.dnsCacheIndexSnapshot(ctrl.cacheKey(qname, dnsmessage.TypeAAAA)); len(keys) != 0 {
		t.Fatalf("cached AAAA family survived the suppressed cache hit: %v", keys)
	}
	if got := ctrl.dnsPreferFiltered.Load(); got == 0 {
		t.Fatal("the filter counter must record the suppressed cached answer")
	}
}

// TestIPVersionPreferRechecksCacheAfterWaitTimeout covers the other hole: the
// preferred family can be cached during the 50ms wait by a path that never
// notifies the wait (optimistic refresh). The delivery must re-read the cache
// after the wait instead of trusting the wake-up, so a timed-out wait with a
// late preferred answer yields the empty reply.
func TestIPVersionPreferRechecksCacheAfterWaitTimeout(t *testing.T) {
	const qname = "prefer-late-cache.test."
	ctrl := newSemanticsController(t)
	preferIPv4(t, ctrl)

	resp := dnsAAAAResponseMsg(qname, "2001:db8::e")
	done := make(chan *dnsmessage.Msg, 1)
	go func() { done <- ctrl.applyPreferenceWait(resp) }()

	// Publish the preferred family once the resolution delay is registered.
	// Holding the registry lock keeps the delivery from retiring its wait, so
	// the cache write is guaranteed to land inside the delay window; the loop
	// only waits for the registration itself.
	canonical := dnsmessage.CanonicalName(qname)
	deadline := time.Now().Add(2 * time.Second)
	for {
		ctrl.prefWaitRegistry.mu.Lock()
		_, waiting := ctrl.prefWaitRegistry.waits[canonical]
		if waiting {
			cacheAddressAnswer(t, ctrl, qname, dnsmessage.TypeA, dnsAResponseMsg(qname, "198.51.100.12").Answer)
			ctrl.prefWaitRegistry.mu.Unlock()
			break
		}
		ctrl.prefWaitRegistry.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("preference wait was never registered")
		}
		runtime.Gosched()
	}

	served := <-done
	if served == resp {
		t.Fatal("a preferred family cached during the wait must suppress the non-preferred answer")
	}
	if len(served.Answer) != 0 {
		t.Fatalf("answer count = %d, want an empty reply", len(served.Answer))
	}
	if got := ctrl.dnsPreferWaitTimeout.Load(); got != 1 {
		t.Fatalf("preference-wait timeout counter = %d, want 1 (the wait itself timed out)", got)
	}
}
