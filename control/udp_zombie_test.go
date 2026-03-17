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

	"github.com/daeuniverse/dae/common/consts"
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
	defer d.Close()

	conn := &zombieMockPacketConn{}
	lAddr := netip.MustParseAddrPort("127.0.0.1:10001")
	ue := &UdpEndpoint{
		conn:       conn,
		Dialer:     d,
		lAddr:      lAddr,
		NatTimeout: 30 * time.Second,
		log:        log,
	}

	now := time.Now().UnixNano()
	ue.lastWriteNano.Store(now)
	ue.lastReadNano.Store(now)

	// Simulate passage of time (31 seconds)
	past := time.Now().Add(-31 * time.Second).UnixNano()
	ue.lastReadNano.Store(past)

	// Attempt a write. This should trigger zombie detection.
	_, err := ue.WriteTo([]byte("hello"), "1.1.1.1:53")
	
	require.Error(t, err)
	require.Equal(t, net.ErrClosed, err)
	require.True(t, ue.IsDead(), "Endpoint should be marked dead after zombie detection")

	// Verify that the dialer's failCount was incremented
	networkType := &obdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_UDP,
		IpVersion: consts.IpVersionStr_4,
	}
	require.True(t, d.MustGetAlive(networkType), "Should still be alive after 1 passive failure")
	
	// Report 2 more times (simulated)
	d.ReportUnavailable(networkType, nil)
	d.ReportUnavailable(networkType, nil)
	require.False(t, d.MustGetAlive(networkType), "Should be dead after 3 cumulative failures")
}
