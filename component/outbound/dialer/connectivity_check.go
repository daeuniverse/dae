/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/sirupsen/logrus"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/common/netutils"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

var (
	BootstrapDns = netip.MustParseAddrPort("223.5.5.5:53")
)

type Ip46 struct {
	Ip4 netip.Addr
	Ip6 netip.Addr
}

func ParseIp46(ctx context.Context, host string) (ipv46 *Ip46, err error) {
	addrs4, err := netutils.ResolveNetip(ctx, SymmetricDirect, BootstrapDns, host, dnsmessage.TypeA)
	if err != nil {
		return nil, err
	}
	if len(addrs4) == 0 {
		return nil, fmt.Errorf("domain \"%v\" has no ipv4 record", host)
	}
	addrs6, err := netutils.ResolveNetip(ctx, SymmetricDirect, BootstrapDns, host, dnsmessage.TypeAAAA)
	if err != nil {
		return nil, err
	}
	if len(addrs6) == 0 {
		return nil, fmt.Errorf("domain \"%v\" has no ipv6 record", host)
	}
	return &Ip46{
		Ip4: addrs4[0],
		Ip6: addrs6[0],
	}, nil
}

type TcpCheckOption struct {
	Url *netutils.URL
	*Ip46
}

func ParseTcpCheckOption(ctx context.Context, rawURL string) (opt *TcpCheckOption, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	ip46, err := ParseIp46(ctx, u.Hostname())
	if err != nil {
		return nil, err
	}
	return &TcpCheckOption{
		Url:  &netutils.URL{URL: u},
		Ip46: ip46,
	}, nil
}

type UdpCheckOption struct {
	DnsHost string
	DnsPort uint16
	*Ip46
}

func ParseUdpCheckOption(ctx context.Context, dnsHostPort string) (opt *UdpCheckOption, err error) {
	host, _port, err := net.SplitHostPort(dnsHostPort)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port: %v", err)
	}
	ip46, err := ParseIp46(ctx, host)
	if err != nil {
		return nil, err
	}
	return &UdpCheckOption{
		DnsHost: host,
		DnsPort: uint16(port),
		Ip46:    ip46,
	}, nil
}

type CheckOption struct {
	ResultLogger LatencyLogger
	CheckFunc    func(ctx context.Context) (ok bool, err error)
}

type LatencyLogger struct {
	L4proto           consts.L4ProtoStr
	IpVersion         consts.IpVersionStr
	LatencyN          *LatenciesN
	AliveDialerSetSet AliveDialerSetSet
}

func (d *Dialer) ActivateCheck() {
	d.tickerMu.Lock()
	defer d.tickerMu.Unlock()
	if d.instanceOption.CheckEnabled {
		return
	}
	d.instanceOption.CheckEnabled = true
	go d.aliveBackground()
}

func (d *Dialer) aliveBackground() {
	timeout := 10 * time.Second
	cycle := d.CheckInterval
	tcp4CheckOpt := &CheckOption{
		ResultLogger: LatencyLogger{
			L4proto:           consts.L4ProtoStr_TCP,
			IpVersion:         consts.IpVersionStr_4,
			LatencyN:          d.tcp4Latencies10,
			AliveDialerSetSet: d.tcp4AliveDialerSetSet,
		},
		CheckFunc: func(ctx context.Context) (ok bool, err error) {
			return d.HttpCheck(ctx, d.TcpCheckOption.Url, d.TcpCheckOption.Ip4)
		},
	}
	tcp6CheckOpt := &CheckOption{
		ResultLogger: LatencyLogger{
			L4proto:           consts.L4ProtoStr_TCP,
			IpVersion:         consts.IpVersionStr_6,
			LatencyN:          d.tcp6Latencies10,
			AliveDialerSetSet: d.tcp6AliveDialerSetSet,
		},
		CheckFunc: func(ctx context.Context) (ok bool, err error) {
			return d.HttpCheck(ctx, d.TcpCheckOption.Url, d.TcpCheckOption.Ip6)
		},
	}
	udp4CheckOpt := &CheckOption{
		ResultLogger: LatencyLogger{
			L4proto:           consts.L4ProtoStr_UDP,
			IpVersion:         consts.IpVersionStr_4,
			LatencyN:          d.udp4Latencies10,
			AliveDialerSetSet: d.udp4AliveDialerSetSet,
		},
		CheckFunc: func(ctx context.Context) (ok bool, err error) {
			return d.DnsCheck(ctx, netip.AddrPortFrom(d.UdpCheckOption.Ip4, d.UdpCheckOption.DnsPort))
		},
	}
	udp6CheckOpt := &CheckOption{
		ResultLogger: LatencyLogger{
			L4proto:           consts.L4ProtoStr_UDP,
			IpVersion:         consts.IpVersionStr_6,
			LatencyN:          d.udp6Latencies10,
			AliveDialerSetSet: d.udp6AliveDialerSetSet,
		},
		CheckFunc: func(ctx context.Context) (ok bool, err error) {
			return d.DnsCheck(ctx, netip.AddrPortFrom(d.UdpCheckOption.Ip4, d.UdpCheckOption.DnsPort))
		},
	}
	// Check once immediately.
	go d.Check(timeout, tcp4CheckOpt)
	go d.Check(timeout, udp4CheckOpt)
	go d.Check(timeout, tcp6CheckOpt)
	go d.Check(timeout, udp6CheckOpt)

	// Sleep to avoid avalanche.
	time.Sleep(time.Duration(fastrand.Int63n(int64(cycle))))
	d.tickerMu.Lock()
	d.ticker.Reset(cycle)
	d.tickerMu.Unlock()
	for range d.ticker.C {
		// No need to test if there is no dialer selection policy using its latency.
		if len(d.tcp4AliveDialerSetSet) > 0 {
			go d.Check(timeout, tcp4CheckOpt)
		}
		if len(d.tcp6AliveDialerSetSet) > 0 {
			go d.Check(timeout, tcp6CheckOpt)
		}
		if len(d.udp4AliveDialerSetSet) > 0 {
			go d.Check(timeout, udp4CheckOpt)
		}
		if len(d.udp6AliveDialerSetSet) > 0 {
			go d.Check(timeout, udp6CheckOpt)
		}
	}
}

func (d *Dialer) mustGetAliveDialerSetSet(l4proto consts.L4ProtoStr, ipversion consts.IpVersionStr) AliveDialerSetSet {
	switch l4proto {
	case consts.L4ProtoStr_TCP:
		switch ipversion {
		case consts.IpVersionStr_4:
			return d.tcp4AliveDialerSetSet
		case consts.IpVersionStr_6:
			return d.tcp6AliveDialerSetSet
		}
	case consts.L4ProtoStr_UDP:
		switch ipversion {
		case consts.IpVersionStr_4:
			return d.udp4AliveDialerSetSet
		case consts.IpVersionStr_6:
			return d.udp6AliveDialerSetSet
		}
	}
	panic("invalid param")
}

func (d *Dialer) MustGetLatencies10(l4proto consts.L4ProtoStr, ipversion consts.IpVersionStr) *LatenciesN {
	switch l4proto {
	case consts.L4ProtoStr_TCP:
		switch ipversion {
		case consts.IpVersionStr_4:
			return d.tcp4Latencies10
		case consts.IpVersionStr_6:
			return d.tcp6Latencies10
		}
	case consts.L4ProtoStr_UDP:
		switch ipversion {
		case consts.IpVersionStr_4:
			return d.udp4Latencies10
		case consts.IpVersionStr_6:
			return d.udp6Latencies10
		}
	}
	panic("invalid param")
}

// RegisterAliveDialerSet is thread-safe.
func (d *Dialer) RegisterAliveDialerSet(a *AliveDialerSet, l4proto consts.L4ProtoStr, ipversion consts.IpVersionStr) {
	d.aliveDialerSetSetMu.Lock()
	d.mustGetAliveDialerSetSet(l4proto, ipversion)[a]++
	d.aliveDialerSetSetMu.Unlock()
}

// UnregisterAliveDialerSet is thread-safe.
func (d *Dialer) UnregisterAliveDialerSet(a *AliveDialerSet, l4proto consts.L4ProtoStr, ipversion consts.IpVersionStr) {
	d.aliveDialerSetSetMu.Lock()
	defer d.aliveDialerSetSetMu.Unlock()
	setSet := d.mustGetAliveDialerSetSet(l4proto, ipversion)
	setSet[a]--
	if setSet[a] <= 0 {
		delete(setSet, a)
	}
}

func (d *Dialer) Check(timeout time.Duration,
	opts *CheckOption,
) (ok bool, err error) {
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	start := time.Now()
	// Calc latency.
	var alive bool
	if ok, err = opts.CheckFunc(ctx); ok && err == nil {
		// No error.
		latency := time.Since(start)
		opts.ResultLogger.LatencyN.AppendLatency(latency)
		avg, _ := opts.ResultLogger.LatencyN.AvgLatency()
		d.Log.WithFields(logrus.Fields{
			// Add a space to ensure alphabetical order is first.
			"network": string(opts.ResultLogger.L4proto) + string(opts.ResultLogger.IpVersion),
			"node":    d.name,
			"last":    latency.Truncate(time.Millisecond),
			"avg_10":  avg.Truncate(time.Millisecond),
		}).Debugln("Connectivity Check")
		alive = true
	} else {
		// Append timeout if there is any error or unexpected status code.
		if err != nil {
			d.Log.WithFields(logrus.Fields{
				// Add a space to ensure alphabetical order is first.
				"network": string(opts.ResultLogger.L4proto) + string(opts.ResultLogger.IpVersion),
				"node":    d.name,
				"err":     err.Error(),
			}).Debugln("Connectivity Check")
		}
		opts.ResultLogger.LatencyN.AppendLatency(timeout)
	}
	// Inform DialerGroups to update state.
	d.aliveDialerSetSetMu.Lock()
	for a := range opts.ResultLogger.AliveDialerSetSet {
		a.SetAlive(d, alive)
	}
	d.aliveDialerSetSetMu.Unlock()
	return ok, err
}

func (d *Dialer) HttpCheck(ctx context.Context, u *netutils.URL, ip netip.Addr) (ok bool, err error) {
	// HTTP(S) check.
	cd := netutils.ContextDialer{d.Dialer}
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				// Force to dial "ip".
				return cd.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), u.Port()))
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr); netErr.Timeout() {
			err = fmt.Errorf("timeout")
		}
		return false, err
	}
	defer resp.Body.Close()
	// Judge the status code.
	if page := path.Base(req.URL.Path); strings.HasPrefix(page, "generate_") {
		return strconv.Itoa(resp.StatusCode) == strings.TrimPrefix(page, "generate_"), nil
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 400, nil
}

func (d *Dialer) DnsCheck(ctx context.Context, dns netip.AddrPort) (ok bool, err error) {
	addrs, err := netutils.ResolveNetip(ctx, d, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, fmt.Errorf("bad DNS response: no record")
	}
	return true, nil
}
