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

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.Error(t, err, "Total blackhole should trigger zombie detection after ZombieDetectionTimeout")
		require.Equal(t, net.ErrClosed, err)
		require.True(t, ue.IsDead())
	})

	t.Run("IdleHealthyWakeup", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: Connection was healthy and then idle for a long time.
		// Since it was healthy, unansweredStartNano is 0.
		ue.unansweredStartNano.Store(0)

		// Idle for 2 minutes
		past := time.Now().Add(-120 * time.Second).UnixNano()
		ue.lastReadNano.Store(past)
		ue.lastWriteNano.Store(past)

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
		ue.lastReadNano.Store(time.Now().UnixNano())

		_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
		require.NoError(t, err)
		require.False(t, ue.IsDead())
	})

	t.Run("MidSessionBlackhole", func(t *testing.T) {
		d, ue := setup()
		defer d.Close()

		// Case: We had successful traffic, but now it's blackholed.
		ue.lastReadNano.Store(time.Now().Add(-60 * time.Second).UnixNano())
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
