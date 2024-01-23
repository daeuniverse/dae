/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/softwind/protocol/direct"
)

var (
	ErrFormat = fmt.Errorf("format error")
)

type UpstreamScheme string

const (
	UpstreamScheme_TCP           UpstreamScheme = "tcp"
	UpstreamScheme_UDP           UpstreamScheme = "udp"
	UpstreamScheme_TCP_UDP       UpstreamScheme = "tcp+udp"
	upstreamScheme_TCP_UDP_Alias UpstreamScheme = "udp+tcp"
)

func (s UpstreamScheme) ContainsTcp() bool {
	switch s {
	case UpstreamScheme_TCP,
		UpstreamScheme_TCP_UDP:
		return true
	default:
		return false
	}
}

func ParseRawUpstream(raw *url.URL) (scheme UpstreamScheme, hostname string, port uint16, err error) {
	var __port string
	switch scheme = UpstreamScheme(raw.Scheme); scheme {
	case upstreamScheme_TCP_UDP_Alias:
		scheme = UpstreamScheme_TCP_UDP
		fallthrough
	case UpstreamScheme_TCP, UpstreamScheme_UDP, UpstreamScheme_TCP_UDP:
		__port = raw.Port()
		if __port == "" {
			__port = "53"
		}
	default:
		return "", "", 0, fmt.Errorf("unexpected scheme: %v", raw.Scheme)
	}
	_port, err := strconv.ParseUint(__port, 10, 16)
	if err != nil {
		return "", "", 0, fmt.Errorf("failed to parse dns_upstream port: %v", err)
	}
	port = uint16(_port)
	hostname = raw.Hostname()
	return scheme, hostname, port, nil
}

type Upstream struct {
	Scheme   UpstreamScheme
	Hostname string
	Port     uint16
	*netutils.Ip46
}

func NewUpstream(ctx context.Context, upstream *url.URL, resolverNetwork string) (up *Upstream, err error) {
	scheme, hostname, port, err := ParseRawUpstream(upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}

	systemDns, err := netutils.SystemDns()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = netutils.TryUpdateSystemDnsElapse(time.Second)
		}
	}()

	ip46, err := netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, hostname, resolverNetwork, false)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dns_upstream: %w", err)
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		return nil, fmt.Errorf("dns_upstream %v has no record", upstream.String())
	}

	return &Upstream{
		Scheme:   scheme,
		Hostname: hostname,
		Port:     port,
		Ip46:     ip46,
	}, nil
}

func (u *Upstream) SupportedNetworks() (ipversions []consts.IpVersionStr, l4protos []consts.L4ProtoStr) {
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
	case UpstreamScheme_TCP:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_TCP}
	case UpstreamScheme_UDP:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP}
	case UpstreamScheme_TCP_UDP:
		// UDP first.
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP, consts.L4ProtoStr_TCP}
	}
	return ipversions, l4protos
}

func (u *Upstream) String() string {
	return string(u.Scheme) + "://" + net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port)))
}

type UpstreamResolver struct {
	Raw     *url.URL
	Network string
	// FinishInitCallback may be invoked again if err is not nil
	FinishInitCallback func(raw *url.URL, upstream *Upstream) (err error)
	mu                 sync.Mutex
	upstream           *Upstream
	init               bool
}

func (u *UpstreamResolver) GetUpstream() (_ *Upstream, err error) {
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
		if u.upstream, err = NewUpstream(ctx, u.Raw, u.Network); err != nil {
			return nil, fmt.Errorf("failed to init dns upstream: %w", err)
		}
	}
	return u.upstream, nil
}
