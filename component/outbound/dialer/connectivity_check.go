/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"errors"
	"fmt"
	"github.com/mzz2017/softwind/netproxy"
	"github.com/mzz2017/softwind/pkg/fastrand"
	"github.com/mzz2017/softwind/protocol/direct"
	"github.com/sirupsen/logrus"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NetworkType struct {
	L4Proto   consts.L4ProtoStr
	IpVersion consts.IpVersionStr
	IsDns     bool
}

func (t *NetworkType) String() string {
	if t.IsDns {
		return t.StringWithoutDns() + "(DNS)"
	} else {
		return t.StringWithoutDns()
	}
}

func (t *NetworkType) StringWithoutDns() string {
	return string(t.L4Proto) + string(t.IpVersion)
}

type collection struct {
	// AliveDialerSetSet uses reference counting.
	AliveDialerSetSet AliveDialerSetSet
	Latencies10       *LatenciesN
	MovingAverage     time.Duration
	Alive             bool
}

func newCollection() *collection {
	return &collection{
		AliveDialerSetSet: make(AliveDialerSetSet),
		Latencies10:       NewLatenciesN(10),
		Alive:             true,
	}
}

func (d *Dialer) mustGetCollection(typ *NetworkType) *collection {
	if typ.IsDns {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.collections[0]
			case consts.IpVersionStr_6:
				return d.collections[1]
			}
		case consts.L4ProtoStr_UDP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.collections[2]
			case consts.IpVersionStr_6:
				return d.collections[3]
			}
		}
	} else {
		switch typ.L4Proto {
		case consts.L4ProtoStr_TCP:
			switch typ.IpVersion {
			case consts.IpVersionStr_4:
				return d.collections[4]
			case consts.IpVersionStr_6:
				return d.collections[5]
			}
		case consts.L4ProtoStr_UDP:
		}
	}
	panic("invalid param")
}

func (d *Dialer) MustGetAlive(typ *NetworkType) bool {
	return d.mustGetCollection(typ).Alive
}

type TcpCheckOption struct {
	Url *netutils.URL
	*netutils.Ip46
}

func ParseTcpCheckOption(ctx context.Context, rawURL string) (opt *TcpCheckOption, err error) {
	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDns1s()
		}
	}()

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	ip46, err := netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, u.Hostname(), false, false)
	if err != nil {
		return nil, err
	}
	return &TcpCheckOption{
		Url:  &netutils.URL{URL: u},
		Ip46: ip46,
	}, nil
}

type CheckDnsOption struct {
	DnsHost string
	DnsPort uint16
	*netutils.Ip46
}

func ParseCheckDnsOption(ctx context.Context, dnsHostPort string) (opt *CheckDnsOption, err error) {
	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDns1s()
		}
	}()

	host, _port, err := net.SplitHostPort(dnsHostPort)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(_port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port: %v", err)
	}
	ip46, err := netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, host, false, false)
	if err != nil {
		return nil, err
	}
	return &CheckDnsOption{
		DnsHost: host,
		DnsPort: uint16(port),
		Ip46:    ip46,
	}, nil
}

type TcpCheckOptionRaw struct {
	opt *TcpCheckOption
	mu  sync.Mutex
	Raw string
}

func (c *TcpCheckOptionRaw) Option() (opt *TcpCheckOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
		defer cancel()
		tcpCheckOption, err := ParseTcpCheckOption(ctx, c.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = tcpCheckOption
	}
	return c.opt, nil
}

type CheckDnsOptionRaw struct {
	opt *CheckDnsOption
	mu  sync.Mutex
	Raw string
}

func (c *CheckDnsOptionRaw) Option() (opt *CheckDnsOption, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.opt == nil {
		ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
		defer cancel()
		udpCheckOption, err := ParseCheckDnsOption(ctx, c.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tcp_check_url: %w", err)
		}
		c.opt = udpCheckOption
	}
	return c.opt, nil
}

type CheckOption struct {
	networkType *NetworkType
	CheckFunc   func(ctx context.Context, typ *NetworkType) (ok bool, err error)
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
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     false,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.TcpCheckOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip4.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.TcpCheckOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no record.")
				return false, nil
			}
			return d.HttpCheck(ctx, opt.Url, opt.Ip4)
		},
	}
	tcp6CheckOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     false,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.TcpCheckOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip6.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.TcpCheckOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no record.")
				return false, nil
			}
			return d.HttpCheck(ctx, opt.Url, opt.Ip6)
		},
	}
	tcp4CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     true,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.CheckDnsOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip4.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.CheckDnsOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no record.")
				return false, nil
			}
			return d.DnsCheck(ctx, netip.AddrPortFrom(opt.Ip4, opt.DnsPort), true)
		},
	}
	tcp6CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_TCP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     true,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.CheckDnsOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip6.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.CheckDnsOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no record.")
				return false, nil
			}
			return d.DnsCheck(ctx, netip.AddrPortFrom(opt.Ip6, opt.DnsPort), true)
		},
	}
	udp4CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_4,
			IsDns:     true,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.CheckDnsOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip4.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.CheckDnsOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no record.")
				return false, nil
			}
			return d.DnsCheck(ctx, netip.AddrPortFrom(opt.Ip4, opt.DnsPort), false)
		},
	}
	udp6CheckDnsOpt := &CheckOption{
		networkType: &NetworkType{
			L4Proto:   consts.L4ProtoStr_UDP,
			IpVersion: consts.IpVersionStr_6,
			IsDns:     true,
		},
		CheckFunc: func(ctx context.Context, typ *NetworkType) (ok bool, err error) {
			opt, err := d.CheckDnsOptionRaw.Option()
			if err != nil {
				return false, err
			}
			if !opt.Ip6.IsValid() {
				d.Log.WithFields(logrus.Fields{
					"link":    d.CheckDnsOptionRaw.Raw,
					"network": typ.String(),
				}).Debugln("Skip check due to no record.")
				return false, nil
			}
			return d.DnsCheck(ctx, netip.AddrPortFrom(opt.Ip6, opt.DnsPort), false)
		},
	}
	var CheckOpts = []*CheckOption{
		tcp4CheckOpt,
		tcp6CheckOpt,
		udp4CheckDnsOpt,
		udp6CheckDnsOpt,
		tcp4CheckDnsOpt,
		tcp6CheckDnsOpt,
	}

	ctx, cancel := context.WithCancel(d.ctx)
	defer cancel()
	go func() {
		/// Splice ticker.C to checkCh.
		// Sleep to avoid avalanche.
		time.Sleep(time.Duration(fastrand.Int63n(int64(cycle))))
		d.tickerMu.Lock()
		d.ticker = time.NewTicker(cycle)
		d.tickerMu.Unlock()
		for t := range d.ticker.C {
			select {
			case <-ctx.Done():
				return
			default:
				d.checkCh <- t
			}
		}
	}()
	var wg sync.WaitGroup
	for range d.checkCh {
		// No need to test if there is no dialer selection policy using its latency.
		for _, opt := range CheckOpts {
			if len(d.mustGetCollection(opt.networkType).AliveDialerSetSet) > 0 {
				wg.Add(1)
				go func(opt *CheckOption) {
					d.Check(timeout, opt)
					wg.Done()
				}(opt)
			}
		}
		// Wait to block the loop.
		wg.Wait()
	}
}

// NotifyCheck will succeed only when CheckEnabled is true.
func (d *Dialer) NotifyCheck() {
	select {
	case <-d.ctx.Done():
		return
	default:
	}

	select {
	// If fail to push elem to chan, the check is in process.
	case d.checkCh <- time.Now():
	default:
	}
}

func (d *Dialer) MustGetLatencies10(typ *NetworkType) *LatenciesN {
	return d.mustGetCollection(typ).Latencies10
}

// RegisterAliveDialerSet is thread-safe.
func (d *Dialer) RegisterAliveDialerSet(a *AliveDialerSet) {
	if a == nil {
		return
	}
	d.collectionFineMu.Lock()
	d.mustGetCollection(a.CheckTyp).AliveDialerSetSet[a]++
	d.collectionFineMu.Unlock()
}

// UnregisterAliveDialerSet is thread-safe.
func (d *Dialer) UnregisterAliveDialerSet(a *AliveDialerSet) {
	if a == nil {
		return
	}
	d.collectionFineMu.Lock()
	defer d.collectionFineMu.Unlock()
	setSet := d.mustGetCollection(a.CheckTyp).AliveDialerSetSet
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
	collection := d.mustGetCollection(opts.networkType)
	if ok, err = opts.CheckFunc(ctx, opts.networkType); ok && err == nil {
		// No error.
		latency := time.Since(start)
		collection.Latencies10.AppendLatency(latency)
		avg, _ := collection.Latencies10.AvgLatency()
		collection.MovingAverage = (collection.MovingAverage + latency) / 2
		collection.Alive = true

		d.Log.WithFields(logrus.Fields{
			"network": opts.networkType.String(),
			"node":    d.property.Name,
			"last":    latency.Truncate(time.Millisecond),
			"avg_10":  avg.Truncate(time.Millisecond),
			"mov_avg": collection.MovingAverage.Truncate(time.Millisecond),
		}).Debugln("Connectivity Check")
	} else {
		// Append timeout if there is any error or unexpected status code.
		if err != nil {
			if strings.HasSuffix(err.Error(), "network is unreachable") {
				err = fmt.Errorf("network is unreachable")
			} else if strings.HasSuffix(err.Error(), "no suitable address found") ||
				strings.HasSuffix(err.Error(), "non-IPv4 address") {
				err = fmt.Errorf("IPv%v is not supported", opts.networkType.IpVersion)
			}
			d.Log.WithFields(logrus.Fields{
				"network": opts.networkType.String(),
				"node":    d.property.Name,
				"err":     err.Error(),
			}).Debugln("Connectivity Check Failed")
		}
		collection.Latencies10.AppendLatency(timeout)
		collection.MovingAverage = (collection.MovingAverage + timeout) / 2
		collection.Alive = false
	}
	// Inform DialerGroups to update state.
	// We use lock because AliveDialerSetSet is a reference of that in collection.
	d.collectionFineMu.Lock()
	for a := range collection.AliveDialerSetSet {
		a.NotifyLatencyChange(d, collection.Alive)
	}
	d.collectionFineMu.Unlock()
	return ok, err
}

func (d *Dialer) HttpCheck(ctx context.Context, u *netutils.URL, ip netip.Addr) (ok bool, err error) {
	// HTTP(S) check.
	cd := &netproxy.ContextDialer{Dialer: d.Dialer}
	cli := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				// Force to dial "ip".
				conn, err := cd.DialTcpContext(ctx, net.JoinHostPort(ip.String(), u.Port()))
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  conn,
					LAddr: nil,
					RAddr: nil,
				}, nil
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
	return resp.StatusCode >= 200 && resp.StatusCode < 500, nil
}

func (d *Dialer) DnsCheck(ctx context.Context, dns netip.AddrPort, tcp bool) (ok bool, err error) {
	addrs, err := netutils.ResolveNetip(ctx, d, dns, consts.UdpCheckLookupHost, dnsmessage.TypeA, tcp)
	if err != nil {
		return false, err
	}
	if len(addrs) == 0 {
		return false, fmt.Errorf("bad DNS response: no record")
	}
	return true, nil
}
