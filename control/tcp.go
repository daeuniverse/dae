/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2022, v2rayA Organization <team@v2raya.org>
 */

package control

import (
	"fmt"
	"github.com/mzz2017/softwind/pkg/zeroalloc/io"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/component/sniffing"
	internal "github.com/v2rayA/dae/pkg/ebpf_internal"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	TcpSniffBufSize = 4096
)

func (c *ControlPlane) handleConn(lConn net.Conn) (err error) {
	defer lConn.Close()

	// Sniff target domain.
	sniffer := sniffing.NewConnSniffer(lConn, TcpSniffBufSize)
	domain, err := sniffer.SniffTcp()
	if err != nil && !sniffing.IsSniffingError(err) {
		return err
	}
	// ConnSniffer should be used later, so we cannot close it now.
	defer sniffer.Close()

	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	outboundIndex, err := c.core.RetrieveOutboundIndex(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		// WAN. Old method.
		var value bpfIpPortOutbound
		ip6 := src.Addr().As16()
		if e := c.core.bpf.TcpDstMap.Lookup(bpfIpPort{
			Ip:   struct{ U6Addr8 [16]uint8 }{U6Addr8: ip6},
			Port: internal.Htons(src.Port()),
		}, &value); e != nil {
			return fmt.Errorf("failed to retrieve target info %v: %v, %v", src.String(), err, e)
		}
		outboundIndex = consts.OutboundIndex(value.Outbound)

		dstAddr, ok := netip.AddrFromSlice(common.Ipv6Uint32ArrayToByteSlice(value.Ip))
		if !ok {
			return fmt.Errorf("failed to parse dest ip: %v", value.Ip)
		}
		dst = netip.AddrPortFrom(dstAddr, internal.Htons(value.Port))
	}

	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundMustDirect:
		fallthrough
	case consts.OutboundControlPlaneDirect:
		c.log.Tracef("outbound: %v => %v",
			outboundIndex.String(),
			consts.OutboundDirect.String(),
		)
		outboundIndex = consts.OutboundDirect
	default:
	}
	outbound := c.outbounds[outboundIndex]
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if outboundIndex < 0 || int(outboundIndex) >= len(c.outbounds) {
		return fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionFromAddr(dst.Addr()),
		IsDns:     false,
	}
	d, _, err := outbound.Select(networkType)
	if err != nil {
		return fmt.Errorf("failed to select dialer from group %v (%v): %w", outbound.Name, networkType.String(), err)
	}
	c.log.WithFields(logrus.Fields{
		"network":  networkType.String(),
		"outbound": outbound.Name,
		"policy":   outbound.GetSelectionPolicy(),
		"dialer":   d.Name(),
		"domain":   domain,
	}).Infof("%v <-> %v", RefineSourceToShow(src, dst.Addr(), consts.LanWanFlag_NotApplicable), RefineAddrPortToShow(dst))

	// Dial and relay.
	rConn, err := d.Dial("tcp", dst.String())
	if err != nil {
		return fmt.Errorf("failed to dial %v: %w", dst, err)
	}
	defer rConn.Close()

	if err = RelayTCP(sniffer, rConn); err != nil {
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
