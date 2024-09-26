/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/component/sniffing"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/zeroalloc/io"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	TcpSniffBufSize = 4096
)

func (c *ControlPlane) handleConn(lConn net.Conn) (err error) {
	defer lConn.Close()

	// Sniff target domain.
	sniffer := sniffing.NewConnSniffer(lConn, TcpSniffBufSize, c.sniffingTimeout)
	// ConnSniffer should be used later, so we cannot close it now.
	defer sniffer.Close()
	domain, err := sniffer.SniffTcp()
	if err != nil && !sniffing.IsSniffingError(err) {
		return err
	}

	// Get tuples and outbound.
	src := lConn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst := lConn.LocalAddr().(*net.TCPAddr).AddrPort()
	routingResult, err := c.core.RetrieveRoutingResult(src, dst, unix.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to retrieve target info %v: %v", dst.String(), err)
	}
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

	// Dial and relay.
	rConn, err := c.RouteDialTcp(&RouteDialParam{
		Outbound:    consts.OutboundIndex(routingResult.Outbound),
		Domain:      domain,
		Mac:         routingResult.Mac,
		ProcessName: routingResult.Pname,
		Dscp:        routingResult.Dscp,
		Src:         src,
		Dest:        dst,
		Mark:        routingResult.Mark,
	})
	if err != nil {
		return fmt.Errorf("failed to dial %v: %w", dst, err)
	}
	defer rConn.Close()

	if err = RelayTCP(sniffer, rConn); err != nil {
		switch {
		case strings.HasSuffix(err.Error(), "write: broken pipe"),
			strings.HasSuffix(err.Error(), "i/o timeout"),
			strings.HasSuffix(err.Error(), "canceled by local with error code 0"),
			strings.HasSuffix(err.Error(), "canceled by remote with error code 0"):
			return nil // ignore
		default:
			return fmt.Errorf("handleTCP relay error: %w", err)
		}
	}
	return nil
}

type RouteDialParam struct {
	Outbound    consts.OutboundIndex
	Domain      string
	Mac         [6]uint8
	Dscp        uint8
	ProcessName [16]uint8
	Src         netip.AddrPort
	Dest        netip.AddrPort
	Mark        uint32
}

func (c *ControlPlane) RouteDialTcp(p *RouteDialParam) (conn netproxy.Conn, err error) {
	routingResult := &bpfRoutingResult{
		Mark:     p.Mark,
		Must:     0,
		Mac:      p.Mac,
		Outbound: uint8(p.Outbound),
		Pname:    p.ProcessName,
		Pid:      0,
		Dscp:     p.Dscp,
	}
	outboundIndex := consts.OutboundIndex(routingResult.Outbound)
	domain := p.Domain
	src := p.Src
	dst := p.Dest

	dialTarget, shouldReroute, dialIp := c.ChooseDialTarget(outboundIndex, dst, domain)
	if shouldReroute {
		outboundIndex = consts.OutboundControlPlaneRouting
	}

	switch outboundIndex {
	case consts.OutboundDirect:
	case consts.OutboundControlPlaneRouting:
		if outboundIndex, routingResult.Mark, _, err = c.Route(src, dst, domain, consts.L4ProtoType_TCP, routingResult); err != nil {
			return nil, err
		}
		routingResult.Outbound = uint8(outboundIndex)

		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.Tracef("outbound: %v => %v",
				consts.OutboundControlPlaneRouting.String(),
				outboundIndex.String(),
			)
		}
		// Reset dialTarget.
		dialTarget, _, dialIp = c.ChooseDialTarget(outboundIndex, dst, domain)
	default:
	}
	if routingResult.Mark == 0 {
		routingResult.Mark = c.soMarkFromDae
	}
	// TODO: Set-up ip to domain mapping and show domain if possible.
	if int(outboundIndex) >= len(c.outbounds) {
		if len(c.outbounds) == int(consts.OutboundUserDefinedMin) {
			return nil, fmt.Errorf("traffic was dropped due to no-load configuration")
		}
		return nil, fmt.Errorf("outbound id from bpf is out of range: %v not in [0, %v]", outboundIndex, len(c.outbounds)-1)
	}
	outbound := c.outbounds[outboundIndex]
	networkType := &dialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionFromAddr(dst.Addr()),
		IsDns:     false,
	}
	strictIpVersion := dialIp
	d, _, err := outbound.Select(networkType, strictIpVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to select dialer from group %v (%v): %w", outbound.Name, networkType.String(), err)
	}

	if c.log.IsLevelEnabled(logrus.InfoLevel) {
		c.log.WithFields(logrus.Fields{
			"network":  networkType.String(),
			"outbound": outbound.Name,
			"policy":   outbound.GetSelectionPolicy(),
			"dialer":   d.Property().Name,
			"sniffed":  domain,
			"ip":       RefineAddrPortToShow(dst),
			"pid":      routingResult.Pid,
			"dscp":     routingResult.Dscp,
			"pname":    ProcessName2String(routingResult.Pname[:]),
			"mac":      Mac2String(routingResult.Mac[:]),
		}).Infof("%v <-> %v", RefineSourceToShow(src, dst.Addr()), dialTarget)
	}
	ctx, cancel := context.WithTimeout(context.TODO(), consts.DefaultDialTimeout)
	defer cancel()
	return d.DialContext(ctx, common.MagicNetwork("tcp", routingResult.Mark), dialTarget)
}

type WriteCloser interface {
	CloseWrite() error
}

func RelayTCP(lConn, rConn netproxy.Conn) (err error) {
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
		e2 := <-eCh
		if e2 != nil {
			return fmt.Errorf("%w: %v", e, e2)
		}
		return e
	}
	return <-eCh
}
