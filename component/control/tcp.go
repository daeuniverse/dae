/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/pkg/zeroalloc/io"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	internal "github.com/v2rayA/dae/pkg/ebpf_internal"
	"net"
	"net/netip"
	"time"
)

func (c *ControlPlane) handleConn(lConn net.Conn) (err error) {
	defer lConn.Close()
	rAddr := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	ip6 := rAddr.Addr().As16()

	var value bpfIpPortOutbound
	if err := c.bpf.TcpDstMap.Lookup(bpfIpPort{
		Ip:   common.Ipv6ByteSliceToUint32Array(ip6[:]),
		Port: internal.Htons(rAddr.Port()),
	}, &value); err != nil {
		return fmt.Errorf("reading map: key %v: %w", rAddr.String(), err)
	}
	dstSlice, ok := netip.AddrFromSlice(common.Ipv6Uint32ArrayToByteSlice(value.Ip))
	if !ok {
		return fmt.Errorf("failed to parse dest ip: %v", value.Ip)
	}
	dst := netip.AddrPortFrom(dstSlice, internal.Htons(value.Port))

	switch consts.OutboundIndex(value.Outbound) {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneDirect:
		value.Outbound = uint8(consts.OutboundDirect)
		c.log.Debugf("outbound: %v => %v",
			consts.OutboundControlPlaneDirect.String(),
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
