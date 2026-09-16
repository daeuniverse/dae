/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

func TestQuestionEchoMatches(t *testing.T) {
	req := dnsmessage.Question{Name: "Example.COM.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET}
	response := func(q dnsmessage.Question) *dnsmessage.Msg {
		return &dnsmessage.Msg{Question: []dnsmessage.Question{q}}
	}

	cases := []struct {
		name string
		resp *dnsmessage.Msg
		want bool
	}{
		{"exact echo", response(req), true},
		{"case-insensitive name", response(dnsmessage.Question{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET}), true},
		{"qtype mismatch", response(dnsmessage.Question{Name: "example.com.", Qtype: dnsmessage.TypeAAAA, Qclass: dnsmessage.ClassINET}), false},
		{"qclass mismatch", response(dnsmessage.Question{Name: "example.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassCHAOS}), false},
		{"name mismatch", response(dnsmessage.Question{Name: "other.com.", Qtype: dnsmessage.TypeA, Qclass: dnsmessage.ClassINET}), false},
		{"empty question", &dnsmessage.Msg{}, false},
	}
	for _, c := range cases {
		if got := questionEchoMatches(req, c.resp); got != c.want {
			t.Errorf("%s: questionEchoMatches = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestResponseSlotAbandonDiscardsLateDelivery pins the recycle discipline: a
// slot abandoned by a timed-out waiter must never hand its late response to
// the next checkout. The setter recycles the slot, and the recycle drains the
// result channel, so the pooled slot starts clean.
func TestResponseSlotAbandonDiscardsLateDelivery(t *testing.T) {
	stale := new(dnsmessage.Msg)
	stale.Id = 0xdead

	slot := newResponseSlot()
	// Waiter times out while readLoop has already claimed the pending entry:
	// abandon transfers recycling to the setter.
	slot.abandon()
	if !slot.abandoned {
		t.Fatal("abandon before settlement must mark the slot for setter recycle")
	}
	// The late delivery arrives after the abandon.
	slot.set(stale)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if msg, err := slot.get(ctx); err == nil {
		t.Fatalf("recycled slot delivered a stale response: id=%x", msg.Id)
	}

	// The recycled checkout must observe a clean slot.
	next := newResponseSlot()
	if msg, err := next.get(ctx); err == nil {
		t.Fatalf("pooled slot leaked a stale response to the next checkout: id=%x", msg.Id)
	}
}

// TestResponseSlotAbandonAfterSetRecyclesImmediately covers the other leg of
// the ownership hand-off: when the setter finished before the waiter's
// cleanup, abandon itself returns the slot to the pool.
func TestResponseSlotAbandonAfterSetRecyclesImmediately(t *testing.T) {
	slot := newResponseSlot()
	fresh := new(dnsmessage.Msg)
	slot.set(fresh)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if msg, err := slot.get(ctx); err != nil || msg != fresh {
		t.Fatalf("delivered response = %v, %v; want the fresh message", msg, err)
	}
	slot.abandon() // waiter consumed the delivery, then abandoned
	if slot.abandoned {
		t.Fatal("abandon after settlement must recycle immediately, not flag for a setter")
	}
}
