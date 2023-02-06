/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"fmt"
	"github.com/mzz2017/softwind/pkg/zeroalloc/io"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"golang.org/x/sys/unix"
	"net"
	"strings"
	"time"
)

func (c *ControlPlane) handleConn(lConn net.Conn) (err error) {
	defer lConn.Close()
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	outboundIndex, _, err := c.RetrieveOutboundIndex(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("RetrieveOutboundIndex: %w", err)
	}

	switch consts.OutboundIndex(outboundIndex) {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneDirect:
		outboundIndex = consts.OutboundDirect
		c.log.Tracef("outbound: %v => %v",
			consts.OutboundControlPlaneDirect.String(),
			consts.OutboundIndex(outboundIndex).String(),
		)
	default:
	}
	outbound := c.outbounds[outboundIndex]
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if outboundIndex < 0 || int(outboundIndex) >= len(c.outbounds) {
		return fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	dialer, err := outbound.Select()
	if err != nil {
		return fmt.Errorf("failed to select dialer from group %v: %w", outbound.Name, err)
	}
	c.log.WithFields(logrus.Fields{
		"l4proto":  "TCP",
		"outbound": outbound.Name,
		"dialer":   dialer.Name(),
	}).Infof("%v <-> %v", RefineSourceToShow(src, dst.Addr()), RefineAddrPortToShow(dst))
	rConn, err := dialer.Dial("tcp", dst.String())
	if err != nil {
		return fmt.Errorf("failed to dial %v: %w", dst, err)
	}
	defer rConn.Close()
	if err = RelayTCP(lConn, rConn); err != nil {
		switch {
		case strings.HasSuffix(err.Error(), "write: broken pipe"),
			strings.HasSuffix(err.Error(), "i/o timeout"):
			return nil // ignore
		default:
			return fmt.Errorf("handleTCP relay error: %w", err)
		}
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
