/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// These tests pin the two properties that can be fixed without deciding
// the qtypePrefer answer semantics: the resolution delay is released by answers
// served from the response cache, and it runs on the delivery side instead of
// inside the singleflight leader.

func preferAAAA(t *testing.T, ctrl *DnsController) {
	t.Helper()
	setTestDnsControllerRuntime(ctrl, func(rt *dnsControllerRuntimeState) {
		rt.qtypePrefer = dnsmessage.TypeAAAA
	})
}

// TestRespCacheHitNotifiesPreferenceWait: a preferred (AAAA) answer served from
// the response cache must release the query waiting out the RFC 8305 delay,
// instead of leaving it to time out even though the answer was already
// available.
func TestRespCacheHitNotifiesPreferenceWait(t *testing.T) {
	ctrl := newSemanticsController(t)
	preferAAAA(t, ctrl)

	const qname = "pref-hit.test."
	req := defaultUdpRequest()
	baseKey := ctrl.cacheKey(qname, dnsmessage.TypeAAAA)
	cacheKey := ctrl.responseCacheKey(baseKey, req, consts.DnsRequestOutboundIndex_AsIs, nil)
	installCorpusCache(t, ctrl, cacheKey, qname, dnsmessage.TypeAAAA,
		dnsAAAAResponseMsg(qname, "2001:db8::42").Answer, 300)

	// A concurrent A query is waiting for the preferred family.
	wait := ctrl.prefWaitRegistry.registerWait(dnsmessage.CanonicalName(qname), dnsmessage.TypeA, dnsmessage.TypeAAAA)
	if wait == nil {
		t.Fatal("the A query must register a wait for the preferred AAAA answer")
	}
	t.Cleanup(func() { ctrl.prefWaitRegistry.remove(wait) })

	writer := &dnsCorpusCaptureWriter{}
	query := corpusDnsQuery(0x6601, qname, dnsmessage.TypeAAAA)
	if err := ctrl.HandleWithResponseWriter_(context.Background(), query, defaultUdpRequest(), writer); err != nil {
		t.Fatalf("HandleWithResponseWriter_: %v", err)
	}
	if got := dnsAnswerIPv6(t, writer.Message()); got != "2001:db8::42" {
		t.Fatalf("served answer = %s, want the cached IPv6 answer", got)
	}

	preferred, _ := wait.waitFor()
	if !preferred {
		t.Fatal("the served preferred answer must release the waiting query")
	}
	if got := ctrl.dnsPreferWaitNotified.Load(); got != 1 {
		t.Fatalf("preference-wait notify counter = %d, want 1", got)
	}
	if got := ctrl.dnsPreferWaitTimeout.Load(); got != 0 {
		t.Fatalf("preference-wait timeout counter = %d, want 0", got)
	}
}

// TestSingleflightLeaderDoesNotRunResolutionDelay pins that the 50ms wait is not
// paid inside the shared resolution: with a wait already registered, a
// non-preferred answer resolved through resolveForSingleflight must return
// without touching the registry, so followers behind the same key are not
// stalled by one client's preference.
func TestSingleflightLeaderDoesNotRunResolutionDelay(t *testing.T) {
	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return dnsAResponseMsg("pref-leader.test.", "203.0.113.7"), nil
		}}, nil
	})
	ctrl := newCorpusControllerWithDefaultChooser(t, truncatedTestConfig())
	preferAAAA(t, ctrl)

	wait := ctrl.prefWaitRegistry.registerWait(dnsmessage.CanonicalName("pref-leader.test."), dnsmessage.TypeA, dnsmessage.TypeAAAA)
	if wait == nil {
		t.Fatal("the A query must register a wait for the preferred AAAA answer")
	}
	t.Cleanup(func() { ctrl.prefWaitRegistry.remove(wait) })

	query := corpusDnsQuery(0x6602, "pref-leader.test.", dnsmessage.TypeA)
	respMsg, err := ctrl.resolveForSingleflight(context.Background(), query, defaultUdpRequest(),
		consts.DnsRequestOutboundIndex_AsIs, nil, "pref-leader.test.:1|asis")
	if err != nil {
		t.Fatalf("resolveForSingleflight: %v", err)
	}
	if respMsg == nil || len(respMsg.Answer) == 0 {
		t.Fatalf("resolveForSingleflight returned %#v, want the resolved answer", respMsg)
	}
	if got := ctrl.dnsPreferWaitTimeout.Load(); got != 0 {
		t.Fatalf("the singleflight leader must not wait out the resolution delay (timeout counter = %d)", got)
	}
	select {
	case <-wait.done:
		t.Fatal("the leader must not consume another query's wait")
	default:
	}
}

// TestDeliveryAppliesResolutionDelay is the counterpart: the delay must still
// happen when the answered response is delivered to a client.
func TestDeliveryAppliesResolutionDelay(t *testing.T) {
	installCorpusDnsForwarderFactory(t, func(_ *componentdns.Upstream, _ dialArgument, _ *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(context.Context, []byte) (*dnsmessage.Msg, error) {
			return dnsAResponseMsg("pref-deliver.test.", "203.0.113.8"), nil
		}}, nil
	})
	ctrl := newCorpusControllerWithDefaultChooser(t, truncatedTestConfig())
	preferAAAA(t, ctrl)

	writer := &dnsCorpusCaptureWriter{}
	query := corpusDnsQuery(0x6603, "pref-deliver.test.", dnsmessage.TypeA)
	if err := ctrl.HandleWithResponseWriter_(context.Background(), query, defaultUdpRequest(), writer); err != nil {
		t.Fatalf("HandleWithResponseWriter_: %v", err)
	}
	if got := dnsAnswerIPv4(t, writer.Message()); got != "203.0.113.8" {
		t.Fatalf("served answer = %s, want the resolved A answer (never substituted)", got)
	}
	if got := ctrl.dnsPreferWaitTimeout.Load(); got != 1 {
		t.Fatalf("preference-wait timeout counter = %d, want 1 (the delivery waits for the preferred family)", got)
	}
}

// TestApplyPreferenceWaitNeverSubstitutesTheAnswer guards the semantics
// still has to decide: the delay may not change the delivered answer.
func TestApplyPreferenceWaitNeverSubstitutesTheAnswer(t *testing.T) {
	ctrl := newSemanticsController(t)
	preferAAAA(t, ctrl)

	resp := dnsAResponseMsg("pref-same.test.", "203.0.113.9")
	start := time.Now()
	got := ctrl.applyPreferenceWait(resp)
	if got != resp {
		t.Fatal("applyPreferenceWait returned a different message; the wait must only delay delivery")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("answer count = %d, want the original answer untouched", len(got.Answer))
	}
	if got.Question[0].Qtype != dnsmessage.TypeA {
		t.Fatalf("question type = %d, want the original A question", got.Question[0].Qtype)
	}
	if elapsed := time.Since(start); elapsed < PreferenceResolutionDelay/2 {
		t.Fatalf("the non-preferred answer returned after %v; the RFC 8305 delay was not applied", elapsed)
	}
}
