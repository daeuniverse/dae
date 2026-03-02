//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"strconv"
	"testing"

	"golang.org/x/net/ipv4"
)

func newUDPBenchPair(b *testing.B) (*net.UDPConn, *net.UDPConn) {
	b.Helper()

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		b.Fatalf("listen udp: %v", err)
	}

	send, err := net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = recv.Close()
		b.Fatalf("dial udp: %v", err)
	}

	b.Cleanup(func() {
		_ = send.Close()
		_ = recv.Close()
	})
	return recv, send
}

func BenchmarkUdpReadSingleVsBatch(b *testing.B) {
	payload := make([]byte, 128)

	b.Run("single_ReadMsgUDPAddrPort", func(b *testing.B) {
		recv, send := newUDPBenchPair(b)
		buf := make([]byte, 2048)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := send.Write(payload); err != nil {
				b.Fatalf("send: %v", err)
			}
			if _, _, _, _, err := recv.ReadMsgUDPAddrPort(buf, nil); err != nil {
				b.Fatalf("recv single: %v", err)
			}
		}
	})

	for _, batchSize := range []int{4, 8, 16} {
		b.Run("batch_ReadBatch_size="+strconv.Itoa(batchSize), func(b *testing.B) {
			recv, send := newUDPBenchPair(b)
			pc := ipv4.NewPacketConn(recv)

			msgs := make([]ipv4.Message, batchSize)
			for i := range msgs {
				msgs[i].Buffers = [][]byte{make([]byte, 2048)}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; {
				want := batchSize
				if remaining := b.N - i; remaining < want {
					want = remaining
				}

				for j := 0; j < want; j++ {
					if _, err := send.Write(payload); err != nil {
						b.Fatalf("send: %v", err)
					}
				}

				n, err := pc.ReadBatch(msgs[:want], 0)
				if err != nil {
					b.Fatalf("recv batch: %v", err)
				}
				i += n
			}
		})
	}
}
