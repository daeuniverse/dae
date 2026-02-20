/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/sirupsen/logrus"
)

type UdpHandler func(data []byte, from netip.AddrPort) error

type UdpEndpoint struct {
	conn netproxy.PacketConn
	// mu protects deadlineTimer
	mu            sync.Mutex
	deadlineTimer *time.Timer
	handler       UdpHandler
	NatTimeout    time.Duration

	Dialer   *dialer.Dialer
	Outbound *outbound.DialerGroup

	// Non-empty indicates this UDP Endpoint is related with a sniffed domain.
	SniffedDomain string
	DialTarget    string
}

func (ue *UdpEndpoint) start() {
	buf := pool.GetFullCap(consts.EthernetMtu)
	defer pool.Put(buf)
	for {
		n, from, err := ue.conn.ReadFrom(buf[:])
		if err != nil {
			logrus.WithError(err).Warnln("UdpEndpoint read loop exited")
			break
		}
		ue.mu.Lock()
		ue.deadlineTimer.Reset(ue.NatTimeout)
		ue.mu.Unlock()
		if err = ue.handler(buf[:n], from); err != nil {
			logrus.WithError(err).Warnln("UdpEndpoint handler error, scheduling immediate cleanup")
			break
		}
	}
	// Trigger immediate pool cleanup: Reset(0) fires the deadline timer callback which calls
	// pool.LoadAndDelete + ue.Close(), removing the endpoint without waiting for NatTimeout.
	ue.mu.Lock()
	if ue.deadlineTimer != nil {
		ue.deadlineTimer.Reset(0)
	}
	ue.mu.Unlock()
}

func (ue *UdpEndpoint) WriteTo(b []byte, addr string) (int, error) {
	return ue.conn.WriteTo(b, addr)
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
	pool        sync.Map
	createMuMap sync.Map
}
type UdpEndpointOptions struct {
	Handler    UdpHandler
	NatTimeout time.Duration
	// GetTarget is useful only if the underlay does not support Full-cone.
	GetDialOption func() (option *DialOption, err error)
}

var DefaultUdpEndpointPool = NewUdpEndpointPool()

func NewUdpEndpointPool() *UdpEndpointPool {
	return &UdpEndpointPool{}
}

func (p *UdpEndpointPool) Remove(lAddr netip.AddrPort, udpEndpoint *UdpEndpoint) (err error) {
	if ue, ok := p.pool.LoadAndDelete(lAddr); ok {
		if ue != udpEndpoint {
			udpEndpoint.Close()
			return fmt.Errorf("target udp endpoint is not in the pool")
		}
		ue.(*UdpEndpoint).Close()
	}
	return nil
}

func (p *UdpEndpointPool) Get(lAddr netip.AddrPort) (udpEndpoint *UdpEndpoint, ok bool) {
	_ue, ok := p.pool.Load(lAddr)
	if !ok {
		return nil, ok
	}
	return _ue.(*UdpEndpoint), ok
}

func (p *UdpEndpointPool) GetOrCreate(lAddr netip.AddrPort, createOption *UdpEndpointOptions) (udpEndpoint *UdpEndpoint, isNew bool, err error) {
	_ue, ok := p.pool.Load(lAddr)
begin:
	if !ok {
		createMu, _ := p.createMuMap.LoadOrStore(lAddr, &sync.Mutex{})
		createMu.(*sync.Mutex).Lock()
		defer createMu.(*sync.Mutex).Unlock()
		defer p.createMuMap.Delete(lAddr)
		_ue, ok = p.pool.Load(lAddr)
		if ok {
			goto begin
		}
		// Create an UdpEndpoint.
		if createOption == nil {
			createOption = &UdpEndpointOptions{}
		}
		if createOption.NatTimeout == 0 {
			createOption.NatTimeout = DefaultNatTimeout
		}
		if createOption.Handler == nil {
			return nil, true, fmt.Errorf("createOption.Handler cannot be nil")
		}

		dialOption, err := createOption.GetDialOption()
		if err != nil {
			return nil, false, err
		}
		ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
		defer cancel()
		udpConn, err := dialOption.Dialer.DialContext(ctx, dialOption.Network, dialOption.Target)
		if err != nil {
			return nil, true, err
		}
		if _, ok = udpConn.(netproxy.PacketConn); !ok {
			return nil, true, fmt.Errorf("protocol does not support udp")
		}
		ue := &UdpEndpoint{
			conn:          udpConn.(netproxy.PacketConn),
			deadlineTimer: nil,
			handler:       createOption.Handler,
			NatTimeout:    createOption.NatTimeout,
			Dialer:        dialOption.Dialer,
			Outbound:      dialOption.Outbound,
			SniffedDomain: dialOption.SniffedDomain,
			DialTarget:    dialOption.Target,
		}
		ue.deadlineTimer = time.AfterFunc(createOption.NatTimeout, func() {
			if _ue, ok := p.pool.LoadAndDelete(lAddr); ok {
				if _ue == ue {
					ue.Close()
				} else {
					// FIXME: ?
				}
			}
		})
		_ue = ue
		p.pool.Store(lAddr, ue)
		// Receive UDP messages.
		go ue.start()
		isNew = true
	} else {
		ue := _ue.(*UdpEndpoint)
		// Postpone the deadline.
		ue.mu.Lock()
		ue.deadlineTimer.Reset(ue.NatTimeout)
		ue.mu.Unlock()
	}
	return _ue.(*UdpEndpoint), isNew, nil
}
