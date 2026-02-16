/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkUdpTaskPool_ParallelManyKeys(b *testing.B) {
	p := NewUdpTaskPool()
	const keyN = 1024
	keys := make([]netip.AddrPort, 0, keyN)
	for i := 0; i < keyN; i++ {
		keys = append(keys, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), uint16(10000+i)))
	}
	var counter atomic.Uint64
	var done atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := counter.Add(1) - 1
			k := keys[i%keyN]
			p.EmitTask(k, func() {
				done.Add(1)
			})
		}
	})
	b.StopTimer()

	deadline := time.Now().Add(5 * time.Second)
	for done.Load() < int64(b.N) && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got := done.Load(); got < int64(b.N) {
		b.Fatalf("unfinished tasks: got=%d want=%d", got, b.N)
	}
}

func BenchmarkUdpTaskPool_ParallelHotKey(b *testing.B) {
	p := NewUdpTaskPool()
	k := netip.MustParseAddrPort("10.0.0.1:12345")
	var done atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.EmitTask(k, func() {
				done.Add(1)
			})
		}
	})
	b.StopTimer()

	deadline := time.Now().Add(5 * time.Second)
	for done.Load() < int64(b.N) && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got := done.Load(); got < int64(b.N) {
		b.Fatalf("unfinished tasks: got=%d want=%d", got, b.N)
	}
}

func BenchmarkUdpEndpointPool_GetOrCreateError_Parallel(b *testing.B) {
	p := NewUdpEndpointPool()
	lAddr := netip.MustParseAddrPort("10.0.0.2:54321")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := p.GetOrCreate(lAddr, &UdpEndpointOptions{})
			if err == nil {
				b.Fatal("expected error")
			}
		}
	})
}

func BenchmarkPacketSnifferPool_CreateRemove_ParallelManyKeys(b *testing.B) {
	p := NewPacketSnifferPool()
	var counter atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := counter.Add(1)
			key := PacketSnifferKey{
				LAddr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), uint16(i)),
				RAddr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)}), uint16(53+i%128)),
			}
			sniffer, _ := p.GetOrCreate(key, &PacketSnifferOptions{Ttl: time.Second})
			_ = p.Remove(key, sniffer)
		}
	})
}
