/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"sync"
	"sync/atomic"
)

type controlPlaneDatapathJanitor struct {
	connStateJanitorStop    chan struct{}
	connStateJanitorDone    chan struct{}
	connStateJanitorOnce    sync.Once
	connStateJanitorStarted atomic.Bool
	connStateCleanupMu      sync.Mutex
	connStateScratch        *connStateJanitorScratch
}

type connStateJanitorScratch struct {
	redirectKeys   []bpfRedirectTuple
	redirectValues []bpfRedirectEntry
	redirectDelete []bpfRedirectTuple

	cookiePidKeys   []uint64
	cookiePidValues []bpfPidPname
	cookiePidDelete []uint64

	udpKeys   []bpfTuplesKey
	udpValues []bpfConnState
	udpDelete []bpfTuplesKey

	tcpDelete []bpfTuplesKey

	routingHandoffKeys   []bpfTuplesKey
	routingHandoffValues []bpfRoutingHandoffEntry
	routingHandoffDelete []bpfTuplesKey
}

func (s *connStateJanitorScratch) release() {
	if s == nil {
		return
	}
	*s = connStateJanitorScratch{}
}

func newControlPlaneDatapathJanitor() controlPlaneDatapathJanitor {
	return controlPlaneDatapathJanitor{
		connStateJanitorStop: make(chan struct{}),
		connStateJanitorDone: make(chan struct{}),
	}
}

func (j *controlPlaneDatapathJanitor) scratch() *connStateJanitorScratch {
	if j.connStateScratch == nil {
		j.connStateScratch = &connStateJanitorScratch{}
	}
	return j.connStateScratch
}

func (j *controlPlaneDatapathJanitor) releaseRetainedState() {
	if j == nil {
		return
	}
	if j.connStateScratch != nil {
		j.connStateScratch.release()
		j.connStateScratch = nil
	}
}
