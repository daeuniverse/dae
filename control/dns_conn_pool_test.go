/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func newTestPipeConn() netproxy.Conn {
	client, server := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, server)
		_ = server.Close()
	}()
	return &mockPipeConn{Conn: client}
}

func TestConnPool_GetNotBlockedBySlowDial(t *testing.T) {
	var dialCalls atomic.Int32
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})

	pool := newConnPool(2, func(ctx context.Context) (netproxy.Conn, error) {
		call := dialCalls.Add(1)
		if call == 1 {
			return newTestPipeConn(), nil
		}
		close(dialStarted)
		select {
		case <-releaseDial:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return newTestPipeConn(), nil
	})
	defer pool.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn1, err := pool.get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn1)

	// Force next get() to enter scale-up path and start slow dial.
	conn1.pendingCount.Store(connPoolScaleUpPendingThreshold)

	done := make(chan error, 1)
	go func() {
		_, e := pool.get(ctx)
		done <- e
	}()

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("slow dial was not started")
	}

	// Lower load so another get() should quickly reuse existing conn.
	conn1.pendingCount.Store(0)

	start := time.Now()
	conn2, err := pool.get(ctx)
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.NotNil(t, conn2)
	require.Less(t, elapsed, 80*time.Millisecond, "get() should not be blocked by another goroutine's slow dial")

	close(releaseDial)
	require.NoError(t, <-done)
}

func TestResponseSlot_ReuseHasNoStaleData(t *testing.T) {
	slot := newResponseSlot()
	msg := &dnsmessage.Msg{}
	slot.set(msg)

	got, err := slot.get(context.Background())
	require.NoError(t, err)
	require.Same(t, msg, got)

	putResponseSlot(slot)

	slot2 := newResponseSlot()
	defer putResponseSlot(slot2)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	got, err = slot2.get(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, got)
}

func TestResponseSlot_NilMeansUnexpectedEOF(t *testing.T) {
	slot := newResponseSlot()
	defer putResponseSlot(slot)

	slot.set(nil)
	got, err := slot.get(context.Background())
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Nil(t, got)
}
