/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	obdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type zombieMockPacketConn struct{}

func (m *zombieMockPacketConn) WriteTo(b []byte, addr string) (int, error) {
	return len(b), nil
}
func (m *zombieMockPacketConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (m *zombieMockPacketConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}
func (m *zombieMockPacketConn) Write(b []byte) (int, error) {
	return len(b), nil
}
func (m *zombieMockPacketConn) Close() error { return nil }
func (m *zombieMockPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *zombieMockPacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}
}
func (m *zombieMockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *zombieMockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *zombieMockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestUdpEndpoint_ZombieDetection(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	setup := func() (*obdialer.Dialer, *UdpEndpoint) {
		d := obdialer.NewDialer(
			nil,
			&obdialer.GlobalOption{
				Log:           log,
				CheckInterval: time.Minute,
			},
			obdialer.InstanceOption{},
			&obdialer.Property{
				Property: D.Property{Name: "test-dialer"},
			},
		)
		lAddr := netip.MustParseAddrPort("127.0.0.1:10001")
		ue := &UdpEndpoint{
			conn:       &zombieMockPacketConn{},
			Dialer:     d,
			lAddr:      lAddr,
			NatTimeout: 30 * time.Second,
			log:        log,
		}
		// Fresh endpoint, all timestamps 0
		return d, ue
	}

	t.Run("FreshConnection", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.NoError(t, err)
		require.False(t, ue.IsDead())
		require.NotZero(t, ue.unansweredStartNano.Load(), "unansweredStartNano should be set on first write")
	})

	t.Run("TotalBlackhole", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Connection never established - we send but never receive anything.
		// Simulated by setting unansweredStartNano to a past time.
		past := time.Now().Add(-35 * time.Second).UnixNano()
		ue.unansweredStartNano.Store(past)
		ue.unansweredWriteCount.Store(1)

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.Error(t, err, "Total blackhole should trigger zombie detection after ZombieDetectionTimeout")
		require.Equal(t, net.ErrClosed, err)
		require.True(t, ue.IsDead())
	})

	t.Run("FastZombieDetection_KnownBidirectionalPort", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Multiple packets sent over 3+ seconds with no reply, on STUN port (3478)
		past := time.Now().Add(-4 * time.Second).UnixNano()
		ue.unansweredStartNano.Store(past)
		ue.unansweredWriteCount.Store(5) // 5 packets already sent
		ue.hasReceived.Store(false)      // Never received any packet

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:3478")
		require.Error(t, err, "Fast zombie detection should trigger for known bidirectional port")
		require.Equal(t, net.ErrClosed, err)
		require.True(t, ue.IsDead())
	})

	t.Run("FastZombieDetection_MidStreamDrop", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Multiple packets sent over 3+ seconds with no reply, on UNKNOWN port
		// BUT the connection has previously received packets (hasReceived = true)
		past := time.Now().Add(-4 * time.Second).UnixNano()
		ue.unansweredStartNano.Store(past)
		ue.unansweredWriteCount.Store(5) // 5 packets already sent
		ue.hasReceived.Store(true)       // Proved to be bidirectional

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:54321") // 54321 is not in whitelist
		require.Error(t, err, "Fast zombie detection should trigger if hasReceived is true")
		require.Equal(t, net.ErrClosed, err)
		require.True(t, ue.IsDead())
	})

	t.Run("OneWayUDP_Protection", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Multiple packets sent over 3+ seconds with no reply, on UNKNOWN port
		// AND connection has never received packets (hasReceived = false)
		past := time.Now().Add(-4 * time.Second).UnixNano()
		ue.unansweredStartNano.Store(past)
		ue.unansweredWriteCount.Store(5)
		ue.hasReceived.Store(false)

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:54321") // 54321 is not in whitelist
		require.NoError(t, err, "One-way UDP should be protected from Fast Zombie Detection")
		require.False(t, ue.IsDead())
	})

	t.Run("FastZombieDetection_NotEnoughTime", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Many packets but not enough time elapsed
		past := time.Now().Add(-2 * time.Second).UnixNano()
		ue.unansweredStartNano.Store(past)
		ue.unansweredWriteCount.Store(10)

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:3478")
		require.NoError(t, err)
		require.False(t, ue.IsDead())
	})

	t.Run("FastZombieDetection_NotEnoughPackets", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Enough time but not enough packets
		past := time.Now().Add(-5 * time.Second).UnixNano()
		ue.unansweredStartNano.Store(past)
		ue.unansweredWriteCount.Store(3)

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:3478")
		require.NoError(t, err)
		require.False(t, ue.IsDead())
	})

	t.Run("IdleHealthyWakeup", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Connection was healthy and then idle for a long time.
		// Since it was healthy, unansweredStartNano is 0.
		ue.unansweredStartNano.Store(0)

		// Idle for 2 minutes
		_ = time.Now().Add(-120 * time.Second).UnixNano() // Just to show it's idle in the test logically

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.NoError(t, err, "Idle healthy connection should NOT be marked zombie on wakeup")
		require.False(t, ue.IsDead())
		require.NotZero(t, ue.unansweredStartNano.Load(), "unansweredStartNano should be reset to now")
	})

	t.Run("RecoveryAfterRead", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: We were in a potential zombie state, but then a read happened.
		ue.unansweredStartNano.Store(time.Now().Add(-25 * time.Second).UnixNano())

		// Read happens! (This is usually called from start() loop)
		ue.unansweredStartNano.Store(0)

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.NoError(t, err)
		require.False(t, ue.IsDead())
	})

	t.Run("MidSessionBlackhole", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: We had successful traffic, but now it's blackholed.
		ue.unansweredStartNano.Store(time.Now().Add(-35 * time.Second).UnixNano())

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.Error(t, err)
		require.True(t, ue.IsDead())
	})

	t.Run("DelayedResponse", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Sent 10s ago, still waiting. Not a zombie yet.
		ue.unansweredStartNano.Store(time.Now().Add(-10 * time.Second).UnixNano())

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.NoError(t, err)
		require.False(t, ue.IsDead())
	})
}
