/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package netutils

import (
	"context"
	"encoding/base64"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	ss2022 "github.com/daeuniverse/outbound/protocol/shadowsocks_2022"
	dnsmessage "github.com/miekg/dns"
)

type packetOnlyDialer struct {
	conn netproxy.Conn
}

func (d packetOnlyDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return d.conn, nil
}

type packetOnlyDNSConn struct {
	serverAddr netip.AddrPort

	mu          sync.Mutex
	response    []byte
	writeCalls  int
	readCalls   int
	writeToHits int
	readFromHit int
}

func (c *packetOnlyDNSConn) Write(_ []byte) (int, error) {
	c.mu.Lock()
	c.writeCalls++
	c.mu.Unlock()
	return 0, stderrors.New("Write should not be used for UDP PacketConn")
}

func (c *packetOnlyDNSConn) Read(_ []byte) (int, error) {
	c.mu.Lock()
	c.readCalls++
	c.mu.Unlock()
	return 0, stderrors.New("Read should not be used for UDP PacketConn")
}

func (c *packetOnlyDNSConn) WriteTo(p []byte, addr string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.writeToHits++
	if addr != c.serverAddr.String() {
		return 0, stderrors.New("unexpected upstream address")
	}

	var req dnsmessage.Msg
	if err := req.Unpack(p); err != nil {
		return 0, err
	}
	if len(req.Question) == 0 {
		return 0, stderrors.New("missing DNS question")
	}

	resp := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:       req.Id,
			Response: true,
		},
		Question: req.Question,
		Answer: []dnsmessage.RR{
			&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: []byte{203, 0, 113, 7},
			},
		},
	}
	packed, err := resp.Pack()
	if err != nil {
		return 0, err
	}
	c.response = packed
	return len(p), nil
}

func (c *packetOnlyDNSConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.readFromHit++
	if len(c.response) == 0 {
		return 0, netip.AddrPort{}, io.EOF
	}
	n := copy(p, c.response)
	c.response = nil
	return n, c.serverAddr, nil
}

func (c *packetOnlyDNSConn) Close() error                       { return nil }
func (c *packetOnlyDNSConn) SetDeadline(_ time.Time) error      { return nil }
func (c *packetOnlyDNSConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *packetOnlyDNSConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestResolveNetipUsesPacketConnForUDP(t *testing.T) {
	serverAddr := netip.MustParseAddrPort("203.0.113.53:53")
	conn := &packetOnlyDNSConn{serverAddr: serverAddr}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := ResolveNetip(ctx, packetOnlyDialer{conn: conn}, serverAddr, "example.com", dnsmessage.TypeA, "udp")
	if err != nil {
		t.Fatalf("ResolveNetip failed: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("unexpected address count: got %d want 1", len(addrs))
	}
	if got := addrs[0].String(); got != "203.0.113.7" {
		t.Fatalf("unexpected address: got %s want 203.0.113.7", got)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.writeCalls != 0 {
		t.Fatalf("unexpected stream Write usage: %d", conn.writeCalls)
	}
	if conn.readCalls != 0 {
		t.Fatalf("unexpected stream Read usage: %d", conn.readCalls)
	}
	if conn.writeToHits == 0 {
		t.Fatal("expected WriteTo to be used")
	}
	if conn.readFromHit == 0 {
		t.Fatal("expected ReadFrom to be used")
	}
}

type recordingNetConn struct {
	writes [][]byte
}

func (c *recordingNetConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *recordingNetConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *recordingNetConn) Close() error                       { return nil }
func (c *recordingNetConn) LocalAddr() net.Addr                { return packetTestAddr("local") }
func (c *recordingNetConn) RemoteAddr() net.Addr               { return packetTestAddr("remote") }
func (c *recordingNetConn) SetDeadline(_ time.Time) error      { return nil }
func (c *recordingNetConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *recordingNetConn) SetWriteDeadline(_ time.Time) error { return nil }

type packetTestAddr string

func (a packetTestAddr) Network() string { return "udp" }
func (a packetTestAddr) String() string  { return string(a) }

type ss2022ParentDialer struct {
	conn netproxy.Conn
}

func (d ss2022ParentDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return d.conn, nil
}

func mustPSKBase64(length int, fill byte) string {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = fill
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestWriteUDPConnWorksWithSS2022PacketConn(t *testing.T) {
	rawConn := &recordingNetConn{}
	ssDialer, err := ss2022.NewDialer(ss2022ParentDialer{conn: rawConn}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     mustPSKBase64(32, 0x42),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("NewDialer failed: %v", err)
	}

	conn, err := ssDialer.DialContext(context.Background(), "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	if _, ok := conn.(netproxy.PacketConn); !ok {
		t.Fatalf("expected PacketConn, got %T", conn)
	}

	payload := []byte("abc")
	if _, err := WriteUDPConn(conn, "8.8.8.8:53", payload); err != nil {
		t.Fatalf("WriteUDPConn failed: %v", err)
	}
	if len(rawConn.writes) == 0 {
		t.Fatal("expected underlying transport write")
	}
	lastWrite := rawConn.writes[len(rawConn.writes)-1]
	if string(lastWrite) == string(payload) {
		t.Fatalf("expected encoded packet, got raw payload %q", string(lastWrite))
	}
	if len(lastWrite) <= len(payload) {
		t.Fatalf("expected encoded packet larger than payload: got %d want > %d", len(lastWrite), len(payload))
	}
}
