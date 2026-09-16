/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"testing"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// gateRecorderResponseWriter records every write so the test can assert the
// handler dropped a message before replying.
type gateRecorderResponseWriter struct {
	msgs      []*dnsmessage.Msg
	rawWrites int
}

func (w *gateRecorderResponseWriter) LocalAddr() net.Addr  { return nil }
func (w *gateRecorderResponseWriter) RemoteAddr() net.Addr { return nil }
func (w *gateRecorderResponseWriter) WriteMsg(m *dnsmessage.Msg) error {
	w.msgs = append(w.msgs, m)
	return nil
}
func (w *gateRecorderResponseWriter) Write(b []byte) (int, error) { w.rawWrites++; return len(b), nil }
func (w *gateRecorderResponseWriter) Close() error                { return nil }
func (w *gateRecorderResponseWriter) TsigStatus() error           { return nil }
func (w *gateRecorderResponseWriter) TsigTimersOnly(_ bool)       {}
func (w *gateRecorderResponseWriter) AdvertiseCompress(_ bool)    {}
func (w *gateRecorderResponseWriter) Hijack()                     {}

// TestServeDNSDropsResponseFormedMessages verifies the local DNS listener
// gate: a message with the QR bit set is a response, not a query, and must be
// dropped before request routing — its question section would otherwise be
// misrouted (a Reject verdict could evict a live cache family). The UDP and
// TCP fast paths reject response-formed messages already; the listener must
// not be the hole in that set.
func TestServeDNSDropsResponseFormedMessages(t *testing.T) {
	h := &dnsHandler{log: logrus.StandardLogger()}

	dropped := &gateRecorderResponseWriter{}
	resp := new(dnsmessage.Msg)
	resp.Response = true
	h.ServeDNS(dropped, resp)
	if len(dropped.msgs) != 0 || dropped.rawWrites != 0 {
		t.Fatalf("response-formed message was not dropped: msgs=%d rawWrites=%d", len(dropped.msgs), dropped.rawWrites)
	}

	// Control: a genuine request must pass the gate. It proceeds until the
	// nil listener trips the handler's panic recovery, which replies
	// SERVFAIL — proving the drop is specific to QR=1, not a blanket gate.
	proceeded := &gateRecorderResponseWriter{}
	req := new(dnsmessage.Msg)
	h.ServeDNS(proceeded, req)
	if len(proceeded.msgs) != 1 || proceeded.msgs[0].Rcode != dnsmessage.RcodeServerFailure {
		t.Fatalf("request did not pass the QR gate: msgs=%d", len(proceeded.msgs))
	}
}
