/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"strconv"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/pool"
)

var udpIngressBufferSink byte

func benchmarkIngressOldCopyPath(b *testing.B, payloadSize int) {
	sharedBuf := pool.GetFullCap(consts.EthernetMtu)
	defer sharedBuf.Put()

	sharedBuf[0] = 0x42

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pool.Get(payloadSize)
		copy(pkt, sharedBuf[:payloadSize])
		udpIngressBufferSink ^= pkt[0]
		pkt.Put()
	}
}

func benchmarkIngressExclusiveNoCopyPath(b *testing.B, payloadSize int) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := pool.GetFullCap(consts.EthernetMtu)
		pkt[0] = 0x42
		view := pkt[:payloadSize]
		udpIngressBufferSink ^= view[0]
		view.Put()
	}
}

func BenchmarkUdpIngressBufferStrategy(b *testing.B) {
	sizes := []int{128, 1200}
	for _, size := range sizes {
		b.Run("OldCopyPath_size="+strconv.Itoa(size), func(b *testing.B) {
			benchmarkIngressOldCopyPath(b, size)
		})
		b.Run("ExclusiveNoCopy_size="+strconv.Itoa(size), func(b *testing.B) {
			benchmarkIngressExclusiveNoCopyPath(b, size)
		})
	}
}
