/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"fmt"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/outbound/netproxy"
)

type LatencyProbeResult struct {
	Alive     bool
	Latency   time.Duration
	Message   string
	CheckedAt time.Time
}

func (d *Dialer) ProbeLatency() (*LatencyProbeResult, error) {
	checkOptions := d.latencyProbeCheckOptions()
	var (
		bestLatency time.Duration
		hasLatency  bool
		lastErr     error
	)

	for _, opt := range checkOptions {
		ok, err := d.Check(opt)
		if err != nil {
			lastErr = err
		}
		if !ok {
			continue
		}

		latency, hasLastLatency := d.MustGetLatencies10(opt.networkType).LastLatency()
		if !hasLastLatency {
			continue
		}
		if !hasLatency || latency < bestLatency {
			bestLatency = latency
			hasLatency = true
		}
	}

	result := &LatencyProbeResult{
		Alive:     hasLatency,
		CheckedAt: time.Now(),
	}
	if hasLatency {
		result.Latency = bestLatency
		return result, nil
	}

	if lastErr != nil {
		result.Message = lastErr.Error()
		return result, nil
	}

	result.Message = "no latency result"
	return result, nil
}

func (d *Dialer) latencyProbeCheckOptions() []*CheckOption {
	return []*CheckOption{
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
				IsDns:     false,
			},
			CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
				opt, err := d.TcpCheckOptionRaw.Option()
				if err != nil {
					return false, err
				}
				if !opt.Ip4.IsValid() {
					return false, nil
				}
				var tcpSomark uint32
				var mptcp bool
				if network, err := netproxy.ParseMagicNetwork(d.TcpCheckOptionRaw.ResolverNetwork); err == nil {
					tcpSomark = network.Mark
					mptcp = network.Mptcp
				}
				return d.HttpCheck(ctx, opt.Url, opt.Ip4, opt.Method, tcpSomark, mptcp)
			},
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
				IsDns:     false,
			},
			CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
				opt, err := d.TcpCheckOptionRaw.Option()
				if err != nil {
					return false, err
				}
				if !opt.Ip6.IsValid() {
					return false, nil
				}
				var tcpSomark uint32
				var mptcp bool
				if network, err := netproxy.ParseMagicNetwork(d.TcpCheckOptionRaw.ResolverNetwork); err == nil {
					tcpSomark = network.Mark
					mptcp = network.Mptcp
				}
				return d.HttpCheck(ctx, opt.Url, opt.Ip6, opt.Method, tcpSomark, mptcp)
			},
		},
	}
}

func FormatLatencyMessage(result *LatencyProbeResult) string {
	if result == nil {
		return "unknown"
	}
	if result.Alive {
		return fmt.Sprintf("%dms", result.Latency.Milliseconds())
	}
	if result.Message != "" {
		return result.Message
	}
	return "unavailable"
}
