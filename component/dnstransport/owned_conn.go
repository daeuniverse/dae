/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

// Package dnstransport holds the low-level DNS transport plumbing shared by
// the control-plane DnsController forwarders and the bootstrap daedns
// resolver: owned QUIC early connections, HTTP client generation bookkeeping,
// DoH/DoQ wire framing, and HTTP(S)/H3 transport construction. Everything
// dialer-specific is injected by the caller.
package dnstransport

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/olicesx/quic-go"
)

// OwnedEarlyConn pairs a package-level quic.DialEarly result with the
// caller-owned PacketConn that quic-go will not close. DialEarly records
// createdConn=false for a supplied PacketConn, so CloseWithError alone would
// leak the underlying UDP socket.
type OwnedEarlyConn struct {
	quic.EarlyConnection
	packetConn io.Closer
	closeOnce  sync.Once
	closeErr   error
}

// OwnEarlyConnection wraps qc so explicit close or natural connection shutdown
// releases the caller-owned socket exactly once.
func OwnEarlyConnection(qc quic.EarlyConnection, packetConn io.Closer) quic.EarlyConnection {
	if qc == nil || packetConn == nil {
		return qc
	}
	owned := &OwnedEarlyConn{EarlyConnection: qc, packetConn: packetConn}
	// Watch the session, not an individual request. HTTP/3 can evict a dead
	// connection without calling CloseWithError on the ownership wrapper.
	context.AfterFunc(qc.Context(), func() { _ = owned.CloseWithError(0, "") })
	return owned
}

func (c *OwnedEarlyConn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	c.closeOnce.Do(func() {
		c.closeErr = c.EarlyConnection.CloseWithError(code, reason)
		if err := c.packetConn.Close(); err != nil && c.closeErr == nil && !IsBenignConnCloseError(err) {
			c.closeErr = err
		}
	})
	return c.closeErr
}

// IsBenignConnCloseError reports whether err is a routine close-path error
// that must not surface to callers.
func IsBenignConnCloseError(err error) bool {
	return err == nil || stderrors.Is(err, net.ErrClosed) || stderrors.Is(err, io.EOF)
}

// ShouldReplaceHTTPClient reports whether an HTTP client that produced err
// must be replaced (closed transport, EOF, or any transport-level network
// error) before the request is retried.
func ShouldReplaceHTTPClient(err error) bool {
	if urlErr, ok := stderrors.AsType[*url.Error](err); ok && urlErr.Err != nil {
		err = urlErr.Err
	}
	if stderrors.Is(err, net.ErrClosed) || stderrors.Is(err, io.EOF) || stderrors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	_, ok := stderrors.AsType[net.Error](err)
	return ok
}

// CloseHTTPClient closes a client's idle connections and its transport.
func CloseHTTPClient(client *http.Client) {
	if client == nil {
		return
	}
	client.CloseIdleConnections()
	if closer, ok := client.Transport.(io.Closer); ok {
		_ = closer.Close()
	}
}
