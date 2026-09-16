/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
)

var (
	ErrFormat = fmt.Errorf("format error")
)

// newUpstreamFunc is a test seam for deterministic UpstreamResolver contract tests.
var newUpstreamFunc = NewUpstream

type resolveUpstreamIp46Func func(ctx context.Context, host string, network string) (*netutils.Ip46, error, error)

type UpstreamScheme string

const (
	UpstreamScheme_TCP           UpstreamScheme = "tcp"
	UpstreamScheme_UDP           UpstreamScheme = "udp"
	UpstreamScheme_TCP_UDP       UpstreamScheme = "tcp+udp"
	upstreamScheme_TCP_UDP_Alias UpstreamScheme = "udp+tcp"
	UpstreamScheme_TLS           UpstreamScheme = "tls"
	UpstreamScheme_QUIC          UpstreamScheme = "quic"
	UpstreamScheme_HTTPS         UpstreamScheme = "https"
	upstreamScheme_H3_Alias      UpstreamScheme = "http3"
	UpstreamScheme_H3            UpstreamScheme = "h3"
)

func ParseRawUpstream(raw *url.URL) (scheme UpstreamScheme, hostname string, port uint16, path string, err error) {
	var __port string
	var __path string
	switch scheme = UpstreamScheme(raw.Scheme); scheme {
	case upstreamScheme_TCP_UDP_Alias:
		scheme = UpstreamScheme_TCP_UDP
		fallthrough
	case UpstreamScheme_TCP, UpstreamScheme_UDP, UpstreamScheme_TCP_UDP:
		__port = raw.Port()
		if __port == "" {
			__port = "53"
		}
	case upstreamScheme_H3_Alias:
		scheme = UpstreamScheme_H3
		fallthrough
	case UpstreamScheme_HTTPS, UpstreamScheme_H3:
		__port = raw.Port()
		if __port == "" {
			__port = "443"
		}
		__path = raw.Path
		if __path == "" {
			__path = "/dns-query"
		}
	case UpstreamScheme_QUIC, UpstreamScheme_TLS:
		__port = raw.Port()
		if __port == "" {
			__port = "853"
		}
	default:
		return "", "", 0, "", fmt.Errorf("unexpected scheme: %v", raw.Scheme)
	}
	_port, err := strconv.ParseUint(__port, 10, 16)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("failed to parse dns_upstream port: %w", err)
	}
	port = uint16(_port)
	hostname = raw.Hostname()
	return scheme, hostname, port, __path, nil
}

type Upstream struct {
	Scheme   UpstreamScheme
	Hostname string
	Port     uint16
	Path     string
	*netutils.Ip46
}

func NewUpstream(ctx context.Context, upstream *url.URL, resolverNetwork string, resolveIp46 resolveUpstreamIp46Func) (up *Upstream, err error) {
	scheme, hostname, port, path, err := ParseRawUpstream(upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}

	ip46 := &netutils.Ip46{}
	if addr, parseErr := netip.ParseAddr(hostname); parseErr == nil {
		if addr.Is4() || addr.Is4In6() {
			ip46.Ip4 = addr.Unmap()
		} else {
			ip46.Ip6 = addr
		}
	} else {
		if resolveIp46 == nil {
			return nil, fmt.Errorf("dns_upstream %v requires global.bootstrap_resolver because hostname is not an IP address", upstream.String())
		}
		var err4, err6 error
		ip46, err4, err6 = resolveIp46(ctx, hostname, resolverNetwork)
		if ip46 == nil {
			ip46 = &netutils.Ip46{}
		}
		if err4 != nil && err6 != nil {
			return nil, fmt.Errorf("resolve dns_upstream %v: A(%v) AAAA(%v)", upstream.String(), err4, err6)
		}
	}
	if !ip46.Ip4.IsValid() && !ip46.Ip6.IsValid() {
		return nil, fmt.Errorf("dns_upstream %v has no record", upstream.String())
	}

	return &Upstream{
		Scheme:   scheme,
		Hostname: hostname,
		Port:     port,
		Path:     path,
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
	case UpstreamScheme_TCP, UpstreamScheme_HTTPS, UpstreamScheme_TLS:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_TCP}
	case UpstreamScheme_UDP, UpstreamScheme_QUIC, UpstreamScheme_H3:
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP}
	case UpstreamScheme_TCP_UDP:
		// UDP first.
		l4protos = []consts.L4ProtoStr{consts.L4ProtoStr_UDP, consts.L4ProtoStr_TCP}
	}
	return ipversions, l4protos
}

func (u *Upstream) String() string {
	return string(u.Scheme) + "://" + net.JoinHostPort(u.Hostname, strconv.Itoa(int(u.Port))) + u.Path
}

type UpstreamResolver struct {
	Raw         *url.URL
	Network     string
	ResolveIp46 resolveUpstreamIp46Func
	// FinishInitCallback may be invoked again if err is not nil
	FinishInitCallback func(raw *url.URL, upstream *Upstream) (err error)

	// state caches the initialization result for lock-free reads after a
	// successful initialization:
	//   - nil: not initialized yet
	//   - &errorSentinel: initialization failed; retry is allowed, rate
	//     limited by lastInitAttemptNano
	//   - *upstreamState: successfully initialized
	state atomic.Pointer[upstreamState]

	// initMu serializes the slow path so concurrent callers cannot each run
	// newUpstreamFunc (a bootstrap DNS resolution). During a bootstrap outage
	// every in-flight DNS query funnels through GetUpstream; without the
	// mutex each of them would fan out its own resolution attempt.
	initMu sync.Mutex
	// lastInitAttemptNano (UnixNano) is the negative-cache timestamp for
	// failed initialization: within upstreamInitRetryInterval, callers fail
	// fast instead of re-running the network-bound initialization.
	lastInitAttemptNano atomic.Int64
}

// upstreamInitRetryInterval is the minimum spacing between upstream
// initialization attempts after a failure.
const upstreamInitRetryInterval = 2 * time.Second

// upstreamState holds the result of initialization.
type upstreamState struct {
	upstream *Upstream
	err      error
}

// errorSentinel is a marker to indicate initialization failed and should retry.
// We use a pointer instead of a special value to avoid allocations on each failure.
var errorSentinel upstreamState

// GetUpstream returns the upstream resolver, initializing it if necessary.
// Reads after a successful initialization are lock-free; the slow path is
// serialized by initMu and rate limited after failures, so a bootstrap outage
// neither fans out one resolution per DNS query nor retries at query rate.
//
// State machine:
//   - nil: not initialized yet
//   - &errorSentinel: initialization failed; retry allowed after the
//     negative-cache window
//   - *upstreamState: successfully initialized
func (u *UpstreamResolver) GetUpstream(ctx context.Context) (_ *Upstream, err error) {
	// Fast path: check if already initialized (lock-free read)
	state := u.state.Load()
	if state != nil && state != &errorSentinel {
		return state.upstream, state.err
	}
	return u.initUpstream(ctx)
}

func (u *UpstreamResolver) initUpstream(ctx context.Context) (*Upstream, error) {
	u.initMu.Lock()
	defer u.initMu.Unlock()
	// Re-read under the mutex: a concurrent initializer may have finished
	// (or re-attempted) while this caller waited.
	state := u.state.Load()
	if state != nil && state != &errorSentinel {
		return state.upstream, state.err
	}
	if now := time.Now(); now.UnixNano()-u.lastInitAttemptNano.Load() < int64(upstreamInitRetryInterval) {
		return nil, fmt.Errorf("dns upstream init backed off after a recent failure; retry in <= %v", upstreamInitRetryInterval)
	}
	u.lastInitAttemptNano.Store(time.Now().UnixNano())

	upstream, err := newUpstreamFunc(ctx, u.Raw, u.Network, u.ResolveIp46)
	if err != nil {
		// Mark as failed; the negative-cache window above spaces out retries.
		u.state.Store(&errorSentinel)
		return nil, fmt.Errorf("failed to init dns upstream: %w", err)
	}

	// Call finish callback if set
	if u.FinishInitCallback != nil {
		if err = u.FinishInitCallback(u.Raw, upstream); err != nil {
			// Mark as failed; the negative-cache window above spaces out retries.
			u.state.Store(&errorSentinel)
			return nil, err
		}
	}

	// Success: atomically store the result
	newState := &upstreamState{upstream: upstream}
	u.state.Store(newState)
	return upstream, nil
}
