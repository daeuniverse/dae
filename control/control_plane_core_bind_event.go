/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/sirupsen/logrus"
)

// bindEventState tracks the datapath-bind outcome for one (interface, scope)
// pair across the lifetime of a link.
//
// A link appearing (and matching a LAN/WAN pattern) is expected operation on
// hosts that create veth/bridge devices at runtime, so the first bind is a
// lifecycle milestone at info, not an anomaly. A bind that fails is an
// anomaly and must stay at warn, but the InterfaceManager can re-invoke the
// attach path for one link, and a warn per attempt would turn one broken
// interface into a warning wall that hides how many interfaces are affected.
// consecutiveFailures carries that magnitude: the first failure warns, and
// every later failure warns again with the running count.
type bindEventState struct {
	// attempts counts every bind attempt for the link, including the routine
	// re-binds that are folded away (never silently: the count is reported in
	// every emitted line).
	attempts uint64
	// bound is true once a bind for the link succeeded; it separates "first
	// attempt" from "first attempt after the link came back".
	bound bool
	// consecutiveFailures counts failures since the last success.
	consecutiveFailures uint64
}

type bindEventKey struct {
	ifname string
	lan    bool
}

// bindEventScope names the datapath direction for log fields.
func bindEventScope(lan bool) string {
	if lan {
		return "lan"
	}
	return "wan"
}

// bindStateFor returns the mutable state for one (interface, scope) pair,
// allocating it on first use. The caller must hold bindStateMu.
func (c *controlPlaneCore) bindStateFor(ifname string, lan bool) *bindEventState {
	if c.bindStates == nil {
		c.bindStates = make(map[bindEventKey]*bindEventState)
	}
	key := bindEventKey{ifname: ifname, lan: lan}
	state := c.bindStates[key]
	if state == nil {
		state = &bindEventState{}
		c.bindStates[key] = state
	}
	return state
}

// logBindOutcome reports one datapath-bind attempt for a link.
//
// Decision table (the "first binding or consecutive failure" rule):
//
//	attempt 1, success        -> info, "first"      (milestone: a link is bound)
//	attempt N, success        -> nothing            (routine re-bind, no new fact)
//	attempt 1, failure        -> info, "first"      (first attempt is always visible)
//	attempt N, failure        -> warn, with the consecutive failure count
//	success after >=1 failure -> info, "recovered"  (the failure state ended)
//
// (A re-created link starts over through forgetBindState, so its bind is a
// "first bind" again, which is the milestone the lazy bind exists for.)
//
// Nothing is dropped silently: attempt and failure counters keep the magnitude
// visible even when a repeated success is folded away, and the recovery line
// closes the interval opened by the last warning.
func (c *controlPlaneCore) logBindOutcome(ifname string, lan bool, err error) {
	if c == nil || c.log == nil {
		return
	}
	if c.closed != nil {
		select {
		case <-c.closed.Done():
			// The generation is retiring; its binds no longer describe live
			// state.
			return
		default:
		}
	}

	c.bindStateMu.Lock()
	state := c.bindStateFor(ifname, lan)
	first := !state.bound && state.consecutiveFailures == 0
	recovered := state.consecutiveFailures > 0
	if err != nil {
		state.consecutiveFailures++
	} else {
		state.consecutiveFailures = 0
		state.bound = true
	}
	consecutiveFailures := state.consecutiveFailures
	state.attempts++
	attempts := state.attempts
	c.bindStateMu.Unlock()

	fields := logrus.Fields{
		"ifname":  ifname,
		"scope":   bindEventScope(lan),
		"attempt": attempts,
	}
	if first {
		fields["first_bind"] = true
		fields["bind_attempts"] = c.bindAttempts.Add(1)
		c.log.WithFields(fields).Infof("Bind datapath to %v (%v); first attempt for this link", ifname, bindEventScope(lan))
		return
	}
	if err != nil {
		fields["consecutive_failures"] = consecutiveFailures
		fields["bind_failures"] = c.bindFailures.Add(1)
		c.log.WithFields(fields).Warnf("Bind datapath to %v (%v) failed; %d consecutive failures", ifname, bindEventScope(lan), consecutiveFailures)
		return
	}
	if recovered {
		c.log.WithFields(fields).Infof("Bind datapath to %v (%v) recovered after failures", ifname, bindEventScope(lan))
		return
	}
	// Routine re-bind on a healthy link: the datapath state did not change, so
	// there is no new event to report (bind_attempts still counts it).
	c.bindAttempts.Add(1)
}

// forgetBindState marks a link that went away, so the next appearance of that
// interface starts over: its bind is reported as a first bind again (the
// lazy-bind path ran for a new link, which is the event the info line
// describes), with attempt counting restarted. The recorded failure count is
// cleared with it: those failures belonged to the previous link, and carrying
// them over would mislabel the new link's first attempt as a repeat.
//
// The entries are deleted rather than reset in place. bindEventState's fields
// are exactly the three counters below, so an entry that has been reset and an
// entry that is absent are the same state to bindStateFor, and deleting is what
// keeps the map's size tied to the interfaces that currently exist instead of
// to every interface name that has ever matched a lan/wan pattern in this
// generation. A host that creates veth/bridge devices at runtime is normal for
// dae, so "ever matched" is unbounded while "currently present" is not.
func (c *controlPlaneCore) forgetBindState(ifname string) {
	if c == nil {
		return
	}
	c.bindStateMu.Lock()
	defer c.bindStateMu.Unlock()
	for _, lan := range []bool{true, false} {
		delete(c.bindStates, bindEventKey{ifname: ifname, lan: lan})
	}
}

// bindAttemptCount reports every bind attempt (logged or folded away).
func (c *controlPlaneCore) bindAttemptCount() uint64 {
	if c == nil {
		return 0
	}
	return c.bindAttempts.Load()
}

// bindFailureCount reports every bind failure that was logged at warn.
func (c *controlPlaneCore) bindFailureCount() uint64 {
	if c == nil {
		return 0
	}
	return c.bindFailures.Load()
}
