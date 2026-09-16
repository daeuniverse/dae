/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// Scripted packet-conn mock family shared by connectivity / udp_flow_binding /
// udp_proxy_dial_bench / udp_quic_e2e_bench / quic_corpus tests.
// Recovered verbatim from the pruned udp_endpoint_pool_test.go (Sprint 5 T1):
// the 3013-line file's *tests* were bloat, but this mock fixture is a shared
// dependency of multiple surviving (including non-bulk) test files, so it is
// kept here as a centralized helper. No build tag (matches original).

type scriptedPacketRead struct {
	data []byte
	from netip.AddrPort
	err  error
}

type scriptedPacketConn struct {
	reads          chan scriptedPacketRead
	writeErr       error
	writeN         int
	forceWriteN    bool
	writeStarted   chan struct{}
	writeRelease   <-chan struct{}
	writeStartOnce sync.Once
	closeCh        chan struct{}
	closeCalls     atomic.Int32
	readCalls      atomic.Int32
}

type scriptedDialer struct {
	conns []netproxy.Conn
	idx   atomic.Int32
}

func (d *scriptedDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	if len(d.conns) == 0 {
		return nil, io.EOF
	}
	i := int(d.idx.Add(1)) - 1
	if i >= len(d.conns) {
		i = len(d.conns) - 1
	}
	return d.conns[i], nil
}

func (c *scriptedPacketConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *scriptedPacketConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *scriptedPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	c.readCalls.Add(1)
	select {
	case <-c.closeCh:
		return 0, netip.AddrPort{}, io.EOF
	case read := <-c.reads:
		if read.err != nil {
			return 0, netip.AddrPort{}, read.err
		}
		copy(p, read.data)
		return len(read.data), read.from, nil
	}
}

func (c *scriptedPacketConn) WriteTo(b []byte, _ string) (int, error) {
	if c.writeStarted != nil {
		c.writeStartOnce.Do(func() {
			close(c.writeStarted)
		})
	}
	if c.writeRelease != nil {
		<-c.writeRelease
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.forceWriteN {
		return c.writeN, nil
	}
	return len(b), nil
}

func (c *scriptedPacketConn) Close() error {
	if c.closeCalls.Add(1) == 1 && c.closeCh != nil {
		close(c.closeCh)
	}
	return nil
}

func (c *scriptedPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *scriptedPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *scriptedPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
