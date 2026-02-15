/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestPipelinedConn_PendingSlotsClearedOnSuccess(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		h := make([]byte, 2)
		if _, err := io.ReadFull(server, h); err != nil {
			return
		}
		l := binary.BigEndian.Uint16(h)
		buf := make([]byte, l)
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}
		var msg dnsmessage.Msg
		if err := msg.Unpack(buf); err != nil {
			return
		}
		msg.Response = true
		resp, err := msg.Pack()
		if err != nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		_, _ = server.Write(out)
	}()

	pc := newPipelinedConn(&mockPipeConn{Conn: client})
	defer pc.Close()

	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn("example.com."), dnsmessage.TypeA)
	data, _ := req.Pack()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := pc.RoundTrip(ctx, data)
	require.NoError(t, err)

	for i := range pc.pending {
		require.Nil(t, pc.pending[i].Load(), "pending slot %d should be empty", i)
	}
}

func TestPipelinedConn_PendingSlotsClearedOnTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Intentionally do not reply to trigger timeout.
	go func() {
		h := make([]byte, 2)
		if _, err := io.ReadFull(server, h); err != nil {
			return
		}
		l := binary.BigEndian.Uint16(h)
		buf := make([]byte, l)
		_, _ = io.ReadFull(server, buf)
	}()

	pc := newPipelinedConn(&mockPipeConn{Conn: client})
	defer pc.Close()

	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn("timeout.test."), dnsmessage.TypeA)
	data, _ := req.Pack()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	_, err := pc.RoundTrip(ctx, data)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	for i := range pc.pending {
		require.Nil(t, pc.pending[i].Load(), "pending slot %d should be empty", i)
	}
}

func TestPipelinedConn_RoundTripRestoresInputID(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		h := make([]byte, 2)
		if _, err := io.ReadFull(server, h); err != nil {
			return
		}
		l := binary.BigEndian.Uint16(h)
		buf := make([]byte, l)
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}
		var msg dnsmessage.Msg
		if err := msg.Unpack(buf); err != nil {
			return
		}
		msg.Response = true
		resp, err := msg.Pack()
		if err != nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		_, _ = server.Write(out)
	}()

	pc := newPipelinedConn(&mockPipeConn{Conn: client})
	defer pc.Close()

	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn("restore-id.test."), dnsmessage.TypeA)
	req.Id = 0x1234
	data, err := req.Pack()
	require.NoError(t, err)
	originalID := binary.BigEndian.Uint16(data[:2])

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = pc.RoundTrip(ctx, data)
	require.NoError(t, err)

	require.Equal(t, originalID, binary.BigEndian.Uint16(data[:2]), "RoundTrip should restore caller data ID")
}

func TestPipelinedConn_RoundTripTimeoutClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Read one request, then delay response long enough to trigger client timeout.
	go func() {
		h := make([]byte, 2)
		if _, err := io.ReadFull(server, h); err != nil {
			return
		}
		l := binary.BigEndian.Uint16(h)
		buf := make([]byte, l)
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}

		time.Sleep(80 * time.Millisecond)

		var msg dnsmessage.Msg
		if err := msg.Unpack(buf); err != nil {
			return
		}
		msg.Response = true
		resp, err := msg.Pack()
		if err != nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		_, _ = server.Write(out)
	}()

	pc := newPipelinedConn(&mockPipeConn{Conn: client})
	defer pc.Close()

	req := new(dnsmessage.Msg)
	req.SetQuestion(dnsmessage.Fqdn("timeout-close.test."), dnsmessage.TypeA)
	data, err := req.Pack()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err = pc.RoundTrip(ctx, data)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	select {
	case <-pc.closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pipelined connection should close after timeout/cancel")
	}
}
