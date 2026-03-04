/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

const relayHalfCloseTimeout = 10 * time.Second

type relayCore struct {
	left  netproxy.Conn
	right netproxy.Conn

	copyEngine       relayCopyEngine
	halfCloseTimeout time.Duration
}

type relayDirection struct {
	name string
	src  netproxy.Conn
	dst  netproxy.Conn
}

type relayResult struct {
	dir string
	err error
}

func newRelayCore(lConn, rConn netproxy.Conn, engine relayCopyEngine) *relayCore {
	return &relayCore{
		left:             lConn,
		right:            rConn,
		copyEngine:       engine,
		halfCloseTimeout: relayHalfCloseTimeout,
	}
}

func (c *relayCore) run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan relayResult, 2)
	var forceCloseOnce sync.Once

	forceClose := func() {
		forceCloseOnce.Do(func() {
			past := time.Unix(1, 0)
			_ = c.left.SetReadDeadline(past)
			_ = c.right.SetReadDeadline(past)
			_ = c.left.Close()
			_ = c.right.Close()
		})
	}

	runDirection := func(dir relayDirection) {
		_, err := c.copyEngine.Copy(ctx, dir.dst, dir.src)

		if wc, ok := dir.dst.(WriteCloser); ok {
			_ = wc.CloseWrite()
		}

		if err != nil {
			// Any directional copy error is treated as terminal for this relay:
			// cancel shared context and force-close both sides to promptly
			// unblock pending reads/writes in the peer direction.
			cancel()
			forceClose()
		} else {
			// Graceful half-close: bound the peer's pending read on dir.dst
			// (which is the source of the opposite direction).
			_ = dir.dst.SetReadDeadline(time.Now().Add(c.halfCloseTimeout))
		}

		results <- relayResult{
			dir: dir.name,
			err: err,
		}
	}

	go runDirection(relayDirection{
		name: "l2r",
		src:  c.left,
		dst:  c.right,
	})
	go runDirection(relayDirection{
		name: "r2l",
		src:  c.right,
		dst:  c.left,
	})

	first := <-results
	second := <-results
	return mergeRelayErrors(first.err, second.err)
}

func mergeRelayErrors(err1, err2 error) error {
	if err1 != nil {
		if err2 != nil {
			return fmt.Errorf("%w: %v", err1, err2)
		}
		return err1
	}
	return err2
}
