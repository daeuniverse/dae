/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dnstransport

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	dnsmessage "github.com/miekg/dns"

	"github.com/daeuniverse/dae/component/dns"
)

const (
	httpIdleConnTimeout       = 90 * time.Second
	httpTLSHandshakeTimeout   = 10 * time.Second
	httpExpectContinueTimeout = time.Second
	maxDNSMessageSize         = 65535
)

// dnsBufPool recycles 64KiB wire buffers for DNS-over-HTTP(S) and DNS-over-
// stream framing; one buffer covers any legal DNS message.
var dnsBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxDNSMessageSize)
		return &buf
	},
}

// SendHTTPDNS performs one RFC 8484 GET request (wire format in the "dns"
// query parameter, message ID zeroed for cache friendliness) and unpacks the
// response.
func SendHTTPDNS(ctx context.Context, client *http.Client, target string, upstream *dns.Upstream, data []byte) (*dnsmessage.Msg, error) {
	serverURL := url.URL{
		Scheme: "https",
		Host:   target,
		Path:   upstream.Path,
	}
	wire := append([]byte(nil), data...)
	binary.BigEndian.PutUint16(wire[0:2], 0)
	q := serverURL.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(wire))
	serverURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Host = upstream.Hostname
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status code: %v", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/dns-message" {
		return nil, fmt.Errorf("unexpected content-type: %v", contentType)
	}
	// Read the response with io.ReadFull into a 64KiB pooled buffer. A
	// partial short read terminated by EOF returns io.ErrUnexpectedEOF and is
	// deliberately treated as success, keeping the partial payload. Note this
	// diverges from io.ReadAll for the empty body: ReadFull returns io.EOF
	// when zero bytes were read, which is surfaced as an error here (ReadAll
	// would have reported an empty, successful message).
	poolBuf := dnsBufPool.Get().(*[]byte)
	defer dnsBufPool.Put(poolBuf) //nolint:staticcheck
	n, err := io.ReadFull(io.LimitReader(resp.Body, maxDNSMessageSize), *poolBuf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	var msg dnsmessage.Msg
	if err = msg.Unpack((*poolBuf)[:n]); err != nil {
		return nil, err
	}
	return &msg, nil
}

// WriteFramedDNSQuery writes data with its two-byte big-endian length prefix
// (RFC 1035 TCP / RFC 9250 DoQ framing). The caller may close the write side
// of the stream immediately afterwards; DoQ servers wait for the query FIN
// before answering.
func WriteFramedDNSQuery(w io.Writer, data []byte) error {
	bufPtr := dnsBufPool.Get().(*[]byte)
	defer dnsBufPool.Put(bufPtr) //nolint:staticcheck
	buf := *bufPtr

	// Frame the request (length prefix + payload) into the pooled buffer.
	// Typical DNS queries fit comfortably; fall back to a one-off allocation
	// only for the pathological >64KiB query.
	var req []byte
	if reqLen := 2 + len(data); reqLen <= cap(buf) {
		req = buf[:reqLen]
	} else {
		req = make([]byte, reqLen)
	}
	binary.BigEndian.PutUint16(req[:2], uint16(len(data)))
	copy(req[2:], data)
	if _, err := w.Write(req); err != nil {
		return fmt.Errorf("failed to write DNS request: %w", err)
	}
	return nil
}

// ReadFramedDNSResponse reads one length-prefixed DNS message (RFC 1035
// TCP / RFC 9250 DoQ framing) and unpacks it.
func ReadFramedDNSResponse(r io.Reader) (*dnsmessage.Msg, error) {
	bufPtr := dnsBufPool.Get().(*[]byte)
	defer dnsBufPool.Put(bufPtr) //nolint:staticcheck
	buf := *bufPtr

	// The length prefix is read into a stack array; the response payload
	// reuses the pooled buffer. respLen is a uint16 so it always fits within
	// the 64KiB capacity.
	var lengthBuf [2]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read DNS response length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	respBuf := buf[:respLen]
	if _, err := io.ReadFull(r, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read DNS response payload: %w", err)
	}
	var msg dnsmessage.Msg
	if err := msg.Unpack(respBuf); err != nil {
		return nil, err
	}
	return &msg, nil
}

// SendStreamDNS writes data with its two-byte big-endian length prefix to
// stream and reads one framed response back (RFC 1035 TCP/DoQ framing).
// Stream transports that must close the write side before reading (DoQ) use
// WriteFramedDNSQuery + ReadFramedDNSResponse instead.
func SendStreamDNS(stream io.ReadWriter, data []byte) (*dnsmessage.Msg, error) {
	if err := WriteFramedDNSQuery(stream, data); err != nil {
		return nil, err
	}
	return ReadFramedDNSResponse(stream)
}
