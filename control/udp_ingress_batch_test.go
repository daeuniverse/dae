/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pool"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// ingressDatagramSocket supplies real Linux datagram lengths and MSG_TRUNC
// without IP routing. It does not exercise UDP recvmmsg or tproxy: the adapter
// supplies the source address and batch shape through the reader seam.
// Separate seam tests cover ownership and OOB, and IPv6 tests cover UDP/OOB.
type ingressDatagramSocket struct {
	fd         int
	lastFlags  int
	extraFlags int
}

func (c *ingressDatagramSocket) ReadMsgUDPAddrPort(buf, oob []byte) (int, int, int, netip.AddrPort, error) {
	n, nn, flags, _, err := unix.Recvmsg(c.fd, buf, oob, 0)
	c.lastFlags = flags | c.extraFlags
	return n, nn, c.lastFlags, receiverTestFrom(), err
}

func (c *ingressDatagramSocket) ReadBatch(msgs []ipv6.Message, _ int) (int, error) {
	msg := &msgs[0]
	n, nn, flags, _, err := unix.RecvmsgBuffers(c.fd, msg.Buffers, msg.OOB, 0)
	if err != nil {
		return 0, err
	}
	c.lastFlags = flags | c.extraFlags
	msg.N, msg.NN, msg.Flags = n, nn, c.lastFlags
	msg.Addr = net.UDPAddrFromAddrPort(receiverTestFrom())
	return 1, nil
}

func newIngressSocketReader(t *testing.T, mode string) (*ingressDatagramSocket, func([]byte), func() pool.PB) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	pc := &ingressDatagramSocket{fd: fds[0]}
	send := func(payload []byte) {
		t.Helper()
		require.NoError(t, unix.Send(fds[1], payload, 0))
	}
	if mode == "single" {
		r := &udpIngressSingleReader{pc: pc}
		oob := make([]byte, udpIngressOobSize)
		return pc, send, func() pool.PB {
			t.Helper()
			buf, src, _, err := r.Read(oob)
			require.NoError(t, err)
			if buf != nil {
				require.Equal(t, receiverTestFrom(), src)
			}
			return buf
		}
	}
	// Bind only to exercise the production constructor; no IP traffic is sent.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	r := newUDPIngressBatchReader(conn, 1)
	require.NotNil(t, r)
	r.pc = pc
	t.Cleanup(r.Close)
	return pc, send, func() pool.PB {
		t.Helper()
		n, err := r.ReadBatch()
		require.NoError(t, err)
		require.Equal(t, 1, n)
		buf, src, _, ok := r.Take(0)
		if ok {
			require.Equal(t, receiverTestFrom(), src)
		} else {
			require.Nil(t, buf)
		}
		return buf
	}
}

func TestUDPIngressPreservesLargeDatagram(t *testing.T) {
	for _, mode := range []string{"batch", "single"} {
		t.Run(mode, func(t *testing.T) {
			pc, send, read := newIngressSocketReader(t, mode)
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			send(payload)
			buf := read()
			defer buf.Put()
			t.Logf("sent=%d received=%d flags=%#x", len(payload), len(buf), pc.lastFlags)
			require.Equal(t, len(payload), len(buf), "complete datagram must not be forwarded as a prefix")
			require.True(t, bytes.Equal(payload, buf))
			require.Zero(t, pc.lastFlags&unix.MSG_TRUNC)
			require.LessOrEqual(t, cap(buf), 4096, "large replies must use the matching pool size class")
		})
	}
}

func TestUDPIngressRejectsTruncatedDatagram(t *testing.T) {
	for _, mode := range []string{"batch", "single"} {
		t.Run(mode, func(t *testing.T) {
			pc, send, read := newIngressSocketReader(t, mode)
			// Larger than any ordinary UDP payload, even with IPv6. The real
			// datagram socket reports truncation at the reader's capacity.
			send(bytes.Repeat([]byte{0x5a}, 65537))
			buf := read()
			defer buf.Put()
			require.NotZero(t, pc.lastFlags&unix.MSG_TRUNC)
			require.True(t, buf == nil, "MSG_TRUNC must discard the whole datagram, got %d bytes", len(buf))

			send([]byte("next"))
			next := read()
			defer next.Put()
			require.Equal(t, "next", string(next), "discard must not stop the ingress reader")
		})
	}
}

func TestUDPIngressDatagramSizes(t *testing.T) {
	for _, mode := range []string{"batch", "single"} {
		t.Run(mode, func(t *testing.T) {
			_, send, read := newIngressSocketReader(t, mode)
			for _, size := range []int{0, 1500, 2048, 2049, 8192, 65507, 65527} {
				t.Run(fmt.Sprint(size), func(t *testing.T) {
					payload := bytes.Repeat([]byte{byte(size)}, size)
					send(payload)
					buf := read()
					defer buf.Put()
					require.NotNil(t, buf, "empty complete datagrams are not drops")
					require.Len(t, buf, size)
					require.True(t, bytes.Equal(payload, buf))
					if size <= 2048 {
						require.LessOrEqual(t, cap(buf), 2048, "small packets must not retain maximum-size receive storage")
					}
				})
			}
		})
	}
}

type ingressBatchReadFunc func([]ipv6.Message, int) (int, error)

func (f ingressBatchReadFunc) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	return f(msgs, flags)
}

func TestUDPIngressBatchPacketAndOOBOwnership(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	flags := []int{0, 0, unix.MSG_TRUNC, unix.MSG_CTRUNC}
	r := newUDPIngressBatchReader(conn, len(flags))
	defer r.Close()
	round := byte(1)
	payload := func(i int) []byte {
		size := []int{1500, 3000}[i%2]
		return bytes.Repeat([]byte{round*16 + byte(i)}, size)
	}
	r.pc = ingressBatchReadFunc(func(msgs []ipv6.Message, _ int) (int, error) {
		for i := range flags {
			msg := &msgs[i]
			data := payload(i)
			for _, buf := range msg.Buffers {
				msg.N += copy(buf, data[msg.N:])
			}
			msg.Flags = flags[i]
			if msg.N != len(data) {
				msg.Flags |= unix.MSG_TRUNC
			}
			msg.Addr = net.UDPAddrFromAddrPort(receiverTestFrom())
			// Opaque bytes isolate OOB ownership from original-destination
			// parsing, which the real IPv6 socket test covers separately.
			msg.NN = copy(msg.OOB, []byte{round, byte(i)})
		}
		return len(flags), nil
	})
	n, err := r.ReadBatch()
	require.NoError(t, err)
	require.Equal(t, len(flags), n)
	var owned []pool.PB
	var borrowedOOB, consumedOOB [][]byte
	for i, flag := range flags {
		buf, src, oob, ok := r.Take(i)
		if flag != 0 {
			require.False(t, ok)
			require.Nil(t, buf)
			require.False(t, src.IsValid())
			require.Nil(t, oob, "rejected metadata must not reach forwarding")
			continue
		}
		require.True(t, ok)
		defer buf.Put()
		require.True(t, bytes.Equal(payload(i), buf))
		require.Equal(t, receiverTestFrom(), src)
		owned = append(owned, buf)
		borrowedOOB = append(borrowedOOB, oob)
		consumedOOB = append(consumedOOB, append([]byte(nil), oob...))
		_, _, _, ok = r.Take(i)
		require.False(t, ok, "each packet must be transferred only once")
	}
	for i, oob := range borrowedOOB {
		require.Equal(t, []byte{1, byte(i)}, oob, "taking another slot must not overwrite OOB")
	}
	round = 2
	_, err = r.ReadBatch()
	require.NoError(t, err)
	r.Close()
	// Packet storage remains owned across another batch and reader shutdown.
	// Borrowed OOB was consumed before the next read and is not used here.
	round = 1
	for i, buf := range owned {
		require.True(t, bytes.Equal(payload(i), buf), "reader reused an in-flight packet")
		require.Equal(t, []byte{1, byte(i)}, consumedOOB[i])
	}
}

type ingressSingleReadFunc func([]byte, []byte) (int, int, int, netip.AddrPort, error)

func (f ingressSingleReadFunc) ReadMsgUDPAddrPort(buf, oob []byte) (int, int, int, netip.AddrPort, error) {
	return f(buf, oob)
}

func TestUDPIngressSinglePacketAndOOBOwnership(t *testing.T) {
	round := byte(1)
	r := udpIngressSingleReader{pc: ingressSingleReadFunc(func(buf, oob []byte) (int, int, int, netip.AddrPort, error) {
		data := bytes.Repeat([]byte{round}, 3000)
		return copy(buf, data), copy(oob, []byte{round}), 0, receiverTestFrom(), nil
	})}
	oob := make([]byte, udpIngressOobSize)
	first, src, nn, err := r.Read(oob)
	require.NoError(t, err)
	defer first.Put()
	require.Equal(t, receiverTestFrom(), src)
	require.Equal(t, []byte{1}, oob[:nn])
	consumedOOB := append([]byte(nil), oob[:nn]...)
	round = 2
	second, _, nn, err := r.Read(oob)
	require.NoError(t, err)
	defer second.Put()
	require.Equal(t, []byte{2}, oob[:nn], "caller-owned OOB must contain only the current message")
	require.Equal(t, []byte{1}, consumedOOB)
	require.True(t, bytes.Equal(bytes.Repeat([]byte{1}, 3000), first))
	require.True(t, bytes.Equal(bytes.Repeat([]byte{2}, 3000), second))
}

func TestUDPIngressBatchReusesReceiveStorage(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	r := newUDPIngressBatchReader(conn, 0)
	defer r.Close()
	r.pc = ingressBatchReadFunc(func(msgs []ipv6.Message, _ int) (int, error) {
		msgs[0].N = 1500
		msgs[0].Addr = net.UDPAddrFromAddrPort(receiverTestFrom())
		return 1, nil
	})
	overflowPointers := make([]*byte, len(r.slots))
	for pass := range 3 {
		n, err := r.ReadBatch()
		require.NoError(t, err)
		require.Equal(t, 1, n)
		for i := range r.slots {
			slot := &r.slots[i]
			require.Equal(t, udpIngressMaxDatagramSize, len(slot.buffers[0])+len(slot.buffers[1]))
			require.LessOrEqual(t, cap(slot.overflow), 65536)
			if pass == 0 {
				overflowPointers[i] = &slot.overflow[0]
			} else {
				require.True(t, overflowPointers[i] == &slot.overflow[0], "overflow storage was reallocated")
			}
		}
		prefix := &r.msgs[0].Buffers[0][0]
		buf, _, _, ok := r.Take(0)
		require.True(t, ok)
		require.True(t, prefix == &buf[0], "small batch packets must transfer without a copy")
		require.LessOrEqual(t, cap(buf), 2048)
		buf.Put()
		_, _, _, ok = r.Take(0)
		require.False(t, ok, "a slot must transfer ownership only once")
	}
	r.Close()
	for i := range r.slots {
		require.Nil(t, r.slots[i].buf)
		require.Nil(t, r.slots[i].overflow)
	}
}

func TestUDPIngressBuffersStayOwnedAcrossReads(t *testing.T) {
	for _, mode := range []string{"batch", "single"} {
		t.Run(mode, func(t *testing.T) {
			_, send, read := newIngressSocketReader(t, mode)
			for _, size := range []int{1500, 3000} {
				firstPayload := bytes.Repeat([]byte{0x5a}, size)
				send(firstPayload)
				first := read()
				defer first.Put()
				send(bytes.Repeat([]byte{0x2a}, 8192))
				second := read()
				defer second.Put()
				require.True(t, bytes.Equal(firstPayload, first), "next read overwrote an in-flight packet")
			}
		})
	}
}

func TestUDPIngressRealIPv6Datagrams(t *testing.T) {
	for _, mode := range []string{"batch", "single"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			raw, err := conn.SyscallConn()
			require.NoError(t, err)
			var optionErr error
			require.NoError(t, raw.Control(func(fd uintptr) {
				optionErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
			}))
			require.NoError(t, optionErr)
			sender, err := net.DialUDP("udp6", nil, conn.LocalAddr().(*net.UDPAddr))
			require.NoError(t, err)
			defer func() { _ = sender.Close() }()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			n, err := sender.Write(payload)
			require.NoError(t, err)
			require.Equal(t, len(payload), n)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))

			var buf pool.PB
			var src netip.AddrPort
			var oob []byte
			if mode == "batch" {
				r := newUDPIngressBatchReader(conn, 0)
				defer r.Close()
				n, err = r.ReadBatch()
				require.NoError(t, err)
				require.Equal(t, 1, n)
				var ok bool
				buf, src, oob, ok = r.Take(0)
				require.True(t, ok)
			} else {
				r := udpIngressSingleReader{pc: conn}
				oob = make([]byte, udpIngressOobSize)
				var nn int
				buf, src, nn, err = r.Read(oob)
				require.NoError(t, err)
				oob = oob[:nn]
			}
			defer buf.Put()
			require.Equal(t, len(payload), len(buf))
			require.True(t, bytes.Equal(payload, buf))
			require.Equal(t, sender.LocalAddr().(*net.UDPAddr).AddrPort(), src)
			require.Equal(t, conn.LocalAddr().(*net.UDPAddr).AddrPort(), RetrieveOriginalDest(oob))
		})
	}
}

func TestUDPIngressRejectsTruncatedControlMessage(t *testing.T) {
	for _, mode := range []string{"batch", "single"} {
		t.Run(mode, func(t *testing.T) {
			pc, send, read := newIngressSocketReader(t, mode)
			pc.extraFlags = unix.MSG_CTRUNC
			send([]byte("payload"))
			buf := read()
			defer buf.Put()
			require.Nil(t, buf, "incomplete original-destination metadata must not reach forwarding")
		})
	}
}

// Listener.Close unblocks a parked UDP ingress read by installing an immediate
// read deadline, so the resulting timeout ends the read loop cleanly. Treating
// it as fatal aborted the retiring generation during a reload's listener
// handoff; fd-exhaustion errors must keep their retry path instead.
func TestIngressWakeTimeoutClassification(t *testing.T) {
	wake := &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
	require.True(t, ingressWakeTimeout(wake), "read-deadline expiry is the close wake-up")
	require.True(t, ingressWakeTimeout(fmt.Errorf("wrap: %w", wake)), "the wake-up is wrapped by the batch reader")
	require.False(t, ingressWakeTimeout(net.ErrClosed), "closed connections are handled separately")
	require.False(t, ingressWakeTimeout(unix.EMFILE), "fd exhaustion must keep its retry path")
	require.False(t, ingressWakeTimeout(nil))
}
