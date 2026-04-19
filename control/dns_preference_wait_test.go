/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package control

import (
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func TestApplyPreferenceWaitPreservesOriginalQType(t *testing.T) {
	c := &DnsController{
		log:              logrus.New(),
		qtypePrefer:      dnsmessage.TypeAAAA,
		prefWaitRegistry: newPreferenceWaitRegistry(),
	}

	original := new(dnsmessage.Msg)
	original.SetQuestion("example.com.", dnsmessage.TypeA)
	original.Response = true
	original.Answer = append(original.Answer, &dnsmessage.A{
		Hdr: dnsmessage.RR_Header{
			Name:   "example.com.",
			Rrtype: dnsmessage.TypeA,
			Class:  dnsmessage.ClassINET,
			Ttl:    60,
		},
		A: []byte{1, 1, 1, 1},
	})

	done := make(chan *dnsmessage.Msg, 1)
	go func() {
		done <- c.applyPreferenceWait(original)
	}()

	waitForPreferenceWaiter(t, c.prefWaitRegistry, "example.com.")

	if ok := c.prefWaitRegistry.notifyPreferred("example.com.", dnsmessage.TypeAAAA, dnsmessage.TypeAAAA); !ok {
		t.Fatal("expected preferred response to notify waiter")
	}

	select {
	case got := <-done:
		if got != original {
			t.Fatal("expected the original response to be returned")
		}
		if len(got.Question) == 0 || got.Question[0].Qtype != dnsmessage.TypeA {
			t.Fatalf("unexpected response qtype: %+v", got.Question)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for preference wait to complete")
	}
}

func waitForPreferenceWaiter(t *testing.T, r *preferenceWaitRegistry, qname string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.mu.RLock()
		_, ok := r.waits[qname]
		r.mu.RUnlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waiter for %s was not registered in time", qname)
}
