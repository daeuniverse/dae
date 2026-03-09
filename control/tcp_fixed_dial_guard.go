/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

var (
	ErrFixedTcpDialConcurrencyLimitExceeded = errors.New("fixed tcp dial concurrency limit exceeded")

	fixedTcpDialLimitLogLimiter sync.Map // map[fixedTcpDialLimitLogKey]int64(unix nano)
)

const (
	fixedTcpDialLimitLogInterval = 10 * time.Second
	minFixedTcpDialConcurrency   = 32
	maxFixedTcpDialConcurrency   = 128
	fixedTcpDialConcurrencyScale = 8
)

type fixedTcpDialLimitLogKey struct {
	outbound string
	dialer   string
}

func defaultFixedTcpDialConcurrencyLimit() int {
	limit := runtime.GOMAXPROCS(0) * fixedTcpDialConcurrencyScale
	if limit < minFixedTcpDialConcurrency {
		limit = minFixedTcpDialConcurrency
	}
	if limit > maxFixedTcpDialConcurrency {
		limit = maxFixedTcpDialConcurrency
	}
	return limit
}

func buildFixedTcpDialGuards(outbounds []*outbound.DialerGroup, limit int) map[*dialer.Dialer]chan struct{} {
	guards := make(map[*dialer.Dialer]chan struct{})
	if limit <= 0 {
		return guards
	}
	for _, out := range outbounds {
		if out == nil || out.GetSelectionPolicy() != consts.DialerSelectionPolicy_Fixed || len(out.Dialers) != 1 {
			continue
		}
		if out.Name == consts.OutboundDirect.String() || out.Name == consts.OutboundBlock.String() {
			continue
		}
		d := out.Dialers[0]
		if d == nil {
			continue
		}
		if _, exists := guards[d]; !exists {
			guards[d] = make(chan struct{}, limit)
		}
	}
	return guards
}

func (c *ControlPlane) acquireFixedTcpDialSlot(ctx context.Context, p *proxyDialParam, res *proxyDialResult) (func(), error) {
	if c == nil || p == nil || p.Network != "tcp" || res == nil || res.Outbound == nil || res.Dialer == nil {
		return nil, nil
	}
	guard, ok := c.fixedTcpDialGuards[res.Dialer]
	if !ok {
		return nil, nil
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	select {
	case guard <- struct{}{}:
		return func() { <-guard }, nil
	default:
		return nil, fmt.Errorf("%w: outbound=%s dialer=%s limit=%d",
			ErrFixedTcpDialConcurrencyLimitExceeded,
			res.Outbound.Name,
			res.Dialer.Property().Name,
			cap(guard),
		)
	}
}

func allowFixedTcpDialLimitLog(key fixedTcpDialLimitLogKey, now time.Time) bool {
	nowNano := now.UnixNano()
	for {
		prev, ok := fixedTcpDialLimitLogLimiter.Load(key)
		if !ok {
			if _, loaded := fixedTcpDialLimitLogLimiter.LoadOrStore(key, nowNano); !loaded {
				return true
			}
			continue
		}

		last, ok := prev.(int64)
		if !ok {
			fixedTcpDialLimitLogLimiter.Store(key, nowNano)
			return true
		}
		if nowNano-last < int64(fixedTcpDialLimitLogInterval) {
			return false
		}
		if fixedTcpDialLimitLogLimiter.CompareAndSwap(key, last, nowNano) {
			return true
		}
	}
}

func (c *ControlPlane) logFixedTcpDialLimitLimited(res *proxyDialResult, src netip.AddrPort, dst netip.AddrPort, domain string) {
	if c == nil || res == nil || res.Outbound == nil || res.Dialer == nil {
		return
	}
	key := fixedTcpDialLimitLogKey{
		outbound: res.Outbound.Name,
		dialer:   res.Dialer.Property().Name,
	}
	if !allowFixedTcpDialLimitLog(key, time.Now()) {
		return
	}
	limit := 0
	if guard, ok := c.fixedTcpDialGuards[res.Dialer]; ok {
		limit = cap(guard)
	}
	c.log.WithFields(logrus.Fields{
		"outbound":        res.Outbound.Name,
		"policy":          res.Outbound.GetSelectionPolicy(),
		"dialer":          res.Dialer.Property().Name,
		"network":         res.OrigNetworkType,
		"selection_type":  res.SelectionNetworkType,
		"strict_ip":       res.IsDialIp,
		"from":            src.String(),
		"to":              dst.String(),
		"sniffed":         domain,
		"dial_limit":      limit,
		"interval":        fixedTcpDialLimitLogInterval.String(),
	}).Warn("fixed single-upstream TCP dial guard triggered (rate-limited)")
}