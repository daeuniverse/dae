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

// LatencyProbeResult reports the latest ad-hoc latency probe result for a dialer.
type LatencyProbeResult struct {
	Alive     bool
	Latency   time.Duration
	Message   string
	CheckedAt time.Time
}

const fastLatencyProbeTimeout = 1500 * time.Millisecond

// ProbeLatency runs the normal TCP health-check path, mutates the dialer's
// health state/history, and returns the best recorded latency across
// supported IP families.
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

// ProbeLatencyFast runs a bounded TCP probe without mutating dialer health
// state and returns the best measured latency across supported IP families.
func (d *Dialer) ProbeLatencyFast() (*LatencyProbeResult, error) {
	checkOptions := d.latencyProbeCheckOptions()
	var (
		bestLatency time.Duration
		hasLatency  bool
		lastErr     error
	)

	probeParent := context.Background()
	if d != nil && d.ctx != nil {
		probeParent = d.ctx
	}

	for _, opt := range checkOptions {
		ctx, cancel := context.WithTimeout(probeParent, fastLatencyProbeTimeout)
		start := time.Now()
		ok, err := opt.CheckFunc(ctx, opt.networkType)
		latency := time.Since(start)
		cancel()

		if err != nil {
			lastErr = err
		}
		if !ok || err != nil {
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
			},
			CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
				opt, err := d.TcpCheckOptionRaw.Option()
				if err != nil {
					return false, err
				}
				if !opt.Ip4.IsValid() {
					return false, nil
				}
				var tcpSoMark uint32
				var mptcp bool
				if network, err := netproxy.ParseMagicNetwork(d.TcpCheckOptionRaw.ResolverNetwork); err == nil {
					tcpSoMark = network.Mark
					mptcp = network.Mptcp
				}
				return d.HttpCheck(ctx, IdxTcp4, opt.Url, opt.Ip4, opt.Method, tcpSoMark, mptcp)
			},
		},
		{
			networkType: &NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
			},
			CheckFunc: func(ctx context.Context, _ *NetworkType) (bool, error) {
				opt, err := d.TcpCheckOptionRaw.Option()
				if err != nil {
					return false, err
				}
				if !opt.Ip6.IsValid() {
					return false, nil
				}
				var tcpSoMark uint32
				var mptcp bool
				if network, err := netproxy.ParseMagicNetwork(d.TcpCheckOptionRaw.ResolverNetwork); err == nil {
					tcpSoMark = network.Mark
					mptcp = network.Mptcp
				}
				return d.HttpCheck(ctx, IdxTcp6, opt.Url, opt.Ip6, opt.Method, tcpSoMark, mptcp)
			},
		},
	}
}

// FormatLatencyMessage formats a latency probe result for status display.
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
