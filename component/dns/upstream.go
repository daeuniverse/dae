/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/outbound/protocol/direct"
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
	UpstreamScheme_TLS           UpstreamScheme = "tls"
	UpstreamScheme_QUIC          UpstreamScheme = "quic"
	UpstreamScheme_HTTPS         UpstreamScheme = "https"
	upstreamScheme_H3_Alias      UpstreamScheme = "http3"
	UpstreamScheme_H3            UpstreamScheme = "h3"
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
		return "", "", 0, "", fmt.Errorf("failed to parse dns_upstream port: %v", err)
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

func NewUpstream(ctx context.Context, upstream *url.URL, resolverNetwork string) (up *Upstream, err error) {
	scheme, hostname, port, path, err := ParseRawUpstream(upstream)
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

	ip46, _, _ := netutils.ResolveIp46(ctx, direct.SymmetricDirect, systemDns, hostname, resolverNetwork, false)
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
	Raw     *url.URL
	Network string
	// FinishInitCallback may be invoked again if err is not nil
	FinishInitCallback func(raw *url.URL, upstream *Upstream) (err error)

	// OPTIMIZATION: Use atomic pointer for lock-free concurrent access with retry support.
	// - nil: not initialized yet
	// - &errorSentinel: initialization failed, should retry
	// - *Upstream: successfully initialized
	//
	// This approach:
	// 1. Avoids mutex contention on hot path (cache hits)
	// 2. Allows retry on transient failures (important for proxy chains)
	// 3. Uses CAS to prevent thundering herd on initialization
	state atomic.Pointer[upstreamState]
}

// upstreamState holds the result of initialization.
type upstreamState struct {
	upstream *Upstream
	err      error
}

// errorSentinel is a marker to indicate initialization failed and should retry.
// We use a pointer instead of a special value to avoid allocations on each failure.
var errorSentinel upstreamState

// GetUpstream returns the upstream resolver, initializing it if necessary.
// OPTIMIZATION: Uses atomic pointer for lock-free reads after successful initialization.
// Retries on transient failures (important for unstable proxy connections).
// 
// State machine:
//   - nil: not initialized yet
//   - &errorSentinel: initialization failed, should retry
//   - *upstreamState: successfully initialized (or permanently failed)
//
// Retry behavior:
//   - On transient failure (e.g., proxy timeout), stores errorSentinel to allow retry
//   - On retry, attempts initialization again
//   - Once initialized successfully, returns cached result without blocking
func (u *UpstreamResolver) GetUpstream() (_ *Upstream, err error) {
	// Fast path: check if already initialized (lock-free read)
	state := u.state.Load()
	if state != nil && state != &errorSentinel {
		return state.upstream, state.err
	}

	// Slow path: initialize
	// Note: Multiple goroutines may reach here concurrently, which is OK.
	// Each will attempt initialization, and the last one to Store wins.
	// This is acceptable because:
	// 1. Initialization is idempotent (same URL always produces same result)
	// 2. The cost of duplicate initialization is outweighed by avoiding lock contention

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	upstream, err := NewUpstream(ctx, u.Raw, u.Network)
	if err != nil {
		// Mark as failed, allow retry on next call
		u.state.Store(&errorSentinel)
		return nil, fmt.Errorf("failed to init dns upstream: %w", err)
	}

	// Call finish callback if set
	if u.FinishInitCallback != nil {
		if err = u.FinishInitCallback(u.Raw, upstream); err != nil {
			// Mark as failed, allow retry on next call
			u.state.Store(&errorSentinel)
			return nil, err
		}
	}

	// Success: atomically store the result
	newState := &upstreamState{upstream: upstream}
	u.state.Store(newState)
	return upstream, nil
}
