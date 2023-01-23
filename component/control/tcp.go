/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"time"
)

func (c *ControlPlane) handleConn(lConn net.Conn) (err error) {
	defer lConn.Close()
	rAddr := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	ip6 := rAddr.Addr().As16()

	var value bpfIpPortOutbound
	if err := c.bpf.DstMap.Lookup(bpfIpPortProto{
		Ip:    common.Ipv6ByteSliceToUint32Array(ip6[:]),
		Port:  swap16(rAddr.Port()),
		Proto: unix.IPPROTO_TCP,
	}, &value); err != nil {
		return fmt.Errorf("reading map: key %v: %w", rAddr.String(), err)
	}
	var dstIP [4]byte
	binary.LittleEndian.PutUint32(dstIP[:], value.Ip[3])
	dst := netip.AddrPortFrom(netip.AddrFrom4(dstIP), swap16(value.Port))

	switch consts.OutboundIndex(value.Outbound) {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneRoute:
		// FIXME: check and re-route.
		value.Outbound = uint8(consts.OutboundDirect)
		c.log.Debugf("outbound: %v => %v",
			consts.OutboundControlPlaneRoute.String(),
			consts.OutboundIndex(value.Outbound).String(),
		)
	default:
	}
	outbound := c.outbounds[value.Outbound]
	// TODO: Set-up ip to domain mapping and show domain if possible.
	c.log.Infof("TCP: %v <-[%v]-> %v", lConn.RemoteAddr(), outbound.Name, dst.String())
	if value.Outbound < 0 || int(value.Outbound) >= len(c.outbounds) {
		return fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", value.Outbound, len(c.outbounds)-1)
	}
	rConn, err := outbound.Dial("tcp", dst.String())
	if err != nil {
		return fmt.Errorf("failed to dial %v: %w", dst, err)
	}
	defer rConn.Close()
	if err = RelayTCP(lConn, rConn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil // ignore i/o timeout
		}
		return fmt.Errorf("handleTCP relay error: %w", err)
	}
	return nil
}

type WriteCloser interface {
	CloseWrite() error
}

func RelayTCP(lConn, rConn net.Conn) (err error) {
	eCh := make(chan error, 1)
	go func() {
		_, e := io.Copy(rConn, lConn)
		if rConn, ok := rConn.(WriteCloser); ok {
			rConn.CloseWrite()
		}
		rConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		eCh <- e
	}()
	_, e := io.Copy(lConn, rConn)
	if lConn, ok := lConn.(WriteCloser); ok {
		lConn.CloseWrite()
	}
	lConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if e != nil {
		<-eCh
		return e
	}
	return <-eCh
}
