/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 <mzz@tuta.io>
 */

package control

import (
	"context"
	"fmt"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/common/consts"
	"github.com/v2rayA/dae/common/netutils"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type DnsUpstreamScheme string

const (
	DnsUpstreamScheme_TCP     DnsUpstreamScheme = "tcp"
	DnsUpstreamScheme_UDP     DnsUpstreamScheme = "udp"
	DnsUpstreamScheme_TCP_UDP DnsUpstreamScheme = "tcp+udp"
)

type DnsUpstream struct {
	Scheme   DnsUpstreamScheme
	Hostname string
	Port     uint16
	*netutils.Ip46
}

func ResolveDnsUpstream(ctx context.Context, dnsUpstream *url.URL) (up *DnsUpstream, err error) {
	var _port string
	switch DnsUpstreamScheme(dnsUpstream.Scheme) {
	case DnsUpstreamScheme_TCP, DnsUpstreamScheme_UDP, DnsUpstreamScheme_TCP_UDP:
		_port = dnsUpstream.Port()
		if _port == "" {
			_port = "53"
		}
	default:
		return nil, fmt.Errorf("dns_upstream now only supports auto://, udp://, tcp:// and empty string (as-is)")
	}

	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDns1s()
		}
	}()

	port, err := strconv.ParseUint(dnsUpstream.Port(), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse dns_upstream port: %v", err)
	}
	hostname := dnsUpstream.Hostname()
	ip46, err := netutils.ParseIp46(ctx, dialer.SymmetricDirect, systemDns, hostname, false)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dns_upstream: %w", err)
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		return nil, fmt.Errorf("dns_upstream has no record")
	}
	return &DnsUpstream{
		Scheme:   DnsUpstreamScheme(dnsUpstream.Scheme),
		Hostname: hostname,
		Port:     uint16(port),
		Ip46:     ip46,
	}, nil
}

func (u *DnsUpstream) SupportedNetworks() (ipversions []consts.IpVersionStr, l4protos []consts.L4ProtoStr) {
	if u.Ip4.IsValid() && u.Ip6.IsValid() {
		ipversions = []consts.IpVersionStr{consts.IpVersionStr_4, consts.IpVersionStr_6}
	} else {
		if u.Ip4.IsValid() {
			ipversions = []consts.IpVersionStr{consts.IpVersionStr_4}
		} else {
			ipversions = []consts.IpVersionStr{consts.IpVersionStr_6}
		}
	}
	switch u.Scheme {
	case DnsUpstreamScheme_TCP:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_TCP}
	case DnsUpstreamScheme_UDP:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP}
	case DnsUpstreamScheme_TCP_UDP:
		// UDP first.
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP, consts.L4ProtoStr_TCP}
	}
	return ipversions, l4protos
}

type DnsUpstreamRaw struct {
	Raw common.UrlOrEmpty
	// FinishInitCallback may be invoked again if err is not nil
	FinishInitCallback func(raw common.UrlOrEmpty, upstream *DnsUpstream) (err error)
	mu                 sync.Mutex
	upstream           *DnsUpstream
	init               bool
}

func (u *DnsUpstreamRaw) GetUpstream() (_ *DnsUpstream, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.init {
		defer func() {
			if err == nil {
				if err = u.FinishInitCallback(u.Raw, u.upstream); err != nil {
					u.upstream = nil
					return
				}
				u.init = true
			}
		}()
		ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
		defer cancel()
		if !u.Raw.Empty {
			if u.upstream, err = ResolveDnsUpstream(ctx, u.Raw.Url); err != nil {
				return nil, fmt.Errorf("failed to init dns upstream: %v", err)
			}
		} else {
			// Empty string. As-is.
		}
	}
	return u.upstream, nil
}
