/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package control

import (
	"fmt"
	"foo/pkg/pool"
	"golang.org/x/net/proxy"
	"net"
	"net/netip"
	"sync"
	"time"
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn net.PacketConn
	// mu protects deadlineTimer
	mu            sync.Mutex
	deadlineTimer *time.Timer
	handler       UdpHandler
	NatTimeout    time.Duration
}

func (ue *UdpEndpoint) start() {
	buf := pool.Get(0xffff)
	defer pool.Put(buf)
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			break
		}
		ue.mu.Lock()
		ue.deadlineTimer.Reset(ue.NatTimeout)
		ue.mu.Unlock()
		if err = ue.handler(buf[:n], from.(*net.UDPAddr).AddrPort()); err != nil {
			break
		}
	}
	ue.mu.Lock()
	ue.deadlineTimer.Stop()
	ue.mu.Unlock()
}

func (ue *UdpEndpoint) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return ue.conn.WriteTo(b, net.UDPAddrFromAddrPort(addr))
}

func (ue *UdpEndpoint) Close() error {
	ue.mu.Lock()
	if ue.deadlineTimer != nil {
		ue.deadlineTimer.Stop()
	}
	ue.mu.Unlock()
	return ue.conn.Close()
}

// UdpEndpointPool is a full-cone udp conn pool
type UdpEndpointPool struct {
	pool map[netip.AddrPort]*UdpEndpoint
	mu   sync.Mutex
}
type UdpEndpointOptions struct {
	Handler    UdpHandler
	NatTimeout time.Duration
	Dialer     proxy.Dialer
	// Target is useful only if the underlay does not support Full-cone.
	Target netip.AddrPort
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	return &UdpEndpointPool{
		pool: make(map[netip.AddrPort]*UdpEndpoint),
	}
}

func (p *UdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ue, ok := p.pool[lAddr]
	if !ok {
		// Create an UdpEndpoint.
		if createOption == nil {
			createOption = &UdpEndpointOptions{}
		}
		if createOption.NatTimeout == 0 {
			createOption.NatTimeout = DefaultNatTimeout
		}
		if createOption.Handler == nil {
			return nil, fmt.Errorf("createOption.Handler cannot be nil")
		}

		udpConn, err := createOption.Dialer.Dial("udp", createOption.Target.String())
		//udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		p.pool[lAddr] = &UdpEndpoint{
			conn: udpConn.(net.PacketConn),
			deadlineTimer: time.AfterFunc(createOption.NatTimeout, func() {
				p.mu.Lock()
				defer p.mu.Unlock()
				if ue, ok := p.pool[lAddr]; ok {
					ue.Close()
					delete(p.pool, lAddr)
				}
			}),
			handler:    createOption.Handler,
			NatTimeout: createOption.NatTimeout,
		}
		ue = p.pool[lAddr]
		// Receive UDP messages.
		go ue.start()
	} else {
		// Postpone the deadline.
		ue.mu.Lock()
		ue.deadlineTimer.Reset(ue.NatTimeout)
		ue.mu.Unlock()
	}
	return ue, nil
}
