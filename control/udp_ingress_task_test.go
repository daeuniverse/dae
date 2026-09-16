/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"net/netip"
	"testing"
)

// TestUdpIngressTaskPoolReuse guards the pooled owned-task optimization
// (d2085352): the per-packet ingress task must be reusable without any
// allocation. If this test starts failing, the hot path is allocating again
// (e.g. the struct gained an escaping field or the pool was replaced by a
// fresh construction) and the -62%/-60% allocation profile regression will
// silently come back.
func TestUdpIngressTaskPoolReuse(t *testing.T) {
	allocs := testing.AllocsPerRun(1000, func() {
		task := udpIngressTaskPool.Get().(*udpIngressTask)
		task.c = nil
		task.lConn = nil
		task.pktBuf = nil
		task.admission = nil
		task.realDst = netip.MustParseAddrPort("192.0.2.1:40000")
		task.convergeSrc = netip.MustParseAddrPort("192.0.2.2:53")
		task.flowDecision = ClassifyUdpFlow(task.convergeSrc, task.realDst, nil)
		udpIngressTaskPool.Put(task)
	})
	if allocs != 0 {
		t.Fatalf("udpIngressTask Get/fill/Put allocated %v objects/op; the pooled owned-task hot path regressed", allocs)
	}
}

// TestUdpIngressTaskPoolConcurrent exercises concurrent Get/fill/Put, the
// shape the dispatcher workers and ingress reader produce together.
func TestUdpIngressTaskPoolConcurrent(t *testing.T) {
	const workers = 8
	const perWorker = 2000
	done := make(chan error, workers)
	for range workers {
		go func() {
			for range perWorker {
				task := udpIngressTaskPool.Get().(*udpIngressTask)
				task.c = nil
				task.realDst = netip.MustParseAddrPort("192.0.2.1:40000")
				udpIngressTaskPool.Put(task)
			}
			done <- nil
		}()
	}
	for range workers {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// silence unused import in some build configurations
var _ = net.IPv4len
