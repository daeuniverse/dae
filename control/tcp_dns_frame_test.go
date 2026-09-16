/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	stderrors "errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// packLargeDnsMsg builds a valid DNS message whose packed size exceeds the
// default bufio.Reader window (4096), which RFC 7766 allows on TCP.
func packLargeDnsMsg(t *testing.T) []byte {
	t.Helper()
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeTXT)
	var txt []string
	for range 20 {
		txt = append(txt, strings.Repeat("a", 250))
	}
	msg.Extra = append(msg.Extra, &dnsmessage.TXT{
		Hdr: dnsmessage.RR_Header{
			Name:   "example.com.",
			Rrtype: dnsmessage.TypeTXT,
			Class:  dnsmessage.ClassINET,
		},
		Txt: txt,
	})
	data, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if len(data) <= 4096 {
		t.Fatalf("packed size = %d, want > 4096 to exercise the large-frame path", len(data))
	}
	return data
}

func frameDnsMsg(data []byte) []byte {
	framed := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(framed, uint16(len(data)))
	copy(framed[2:], data)
	return framed
}

// A DNS/TCP frame may be up to 65535 bytes (RFC 7766) while the probe reader
// buffers only 4096. Inside an established session the frame must be consumed
// and served; the probe (consumeLarge=false) must keep failing without
// consuming so the not-DNS fallback still works.
func TestReadDnsMsgFromBufioLargeFrame(t *testing.T) {
	payload := packLargeDnsMsg(t)
	framed := frameDnsMsg(payload)

	t.Run("session read consumes and parses", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader(framed))
		msg, frameLen, err := readDnsMsgFromBufio(reader, 0, nil, true)
		if err != nil {
			t.Fatalf("readDnsMsgFromBufio(consumeLarge=true) error = %v", err)
		}
		if frameLen != len(framed) {
			t.Fatalf("frameLen = %d, want %d", frameLen, len(framed))
		}
		if len(msg.Question) != 1 || msg.Question[0].Name != "example.com." {
			t.Fatalf("parsed question = %+v, want example.com.", msg.Question)
		}
		if reader.Buffered() != 0 {
			t.Fatalf("reader retains %d buffered bytes, want the frame fully consumed", reader.Buffered())
		}
	})

	t.Run("probe read fails without consuming", func(t *testing.T) {
		reader := bufio.NewReader(bytes.NewReader(framed))
		if _, _, err := readDnsMsgFromBufio(reader, 0, nil, false); !stderrors.Is(err, bufio.ErrBufferFull) {
			t.Fatalf("readDnsMsgFromBufio(consumeLarge=false) error = %v, want bufio.ErrBufferFull", err)
		}
	})
}

// deadlineRecordingConn records the most recent read deadline so tests can
// assert the DNS probe disarms what it armed.
type deadlineRecordingConn struct {
	reader           *bytes.Reader
	lastReadDeadline time.Time
}

func (c *deadlineRecordingConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *deadlineRecordingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *deadlineRecordingConn) Close() error                { return nil }
func (c *deadlineRecordingConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *deadlineRecordingConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *deadlineRecordingConn) SetDeadline(t time.Time) error {
	c.lastReadDeadline = t
	return nil
}

func (c *deadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.lastReadDeadline = t
	return nil
}
func (c *deadlineRecordingConn) SetWriteDeadline(time.Time) error { return nil }

// The DNS probe arms a read deadline before peeking. When the payload turns
// out not to be DNS, the connection falls through to the plain relay, which
// never re-arms read deadlines — so a leftover probe deadline would kill a
// healthy non-DNS port-53 connection a few seconds in.
func TestTCPDnsFastPathFallbackDisarmsProbeDeadline(t *testing.T) {
	conn := &deadlineRecordingConn{reader: bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))}
	bufReader := bufio.NewReader(conn)

	c := &ControlPlane{}
	handled, err := c.handleTCPDnsFastPathOwned(
		context.Background(),
		conn,
		bufReader,
		netip.MustParseAddrPort("192.0.2.1:1234"),
		netip.MustParseAddrPort("192.0.2.2:53"),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("handleTCPDnsFastPathOwned() error = %v", err)
	}
	if handled {
		t.Fatal("handleTCPDnsFastPathOwned() handled HTTP payload as DNS")
	}
	if !conn.lastReadDeadline.IsZero() {
		t.Fatalf("read deadline after fallback = %v, want disarmed (zero)", conn.lastReadDeadline)
	}
}
