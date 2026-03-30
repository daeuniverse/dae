/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package netutils

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

type stdNetDialer struct{}

func (stdNetDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func TestResolveNetipLargeTCPResponse(t *testing.T) {
	serverAddr := startTCPDNSServer(t, func(req *dnsmessage.Msg, conn net.Conn) error {
		resp := new(dnsmessage.Msg)
		resp.SetReply(req)
		for i := 0; i < 100; i++ {
			resp.Answer = append(resp.Answer, &dnsmessage.A{
				Hdr: dnsmessage.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(fmt.Sprintf("1.1.1.%d", i+1)).To4(),
			})
		}
		return writeTCPDNSResponse(conn, resp, false)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := ResolveNetip(ctx, stdNetDialer{}, serverAddr, "example.com", dnsmessage.TypeA, "tcp")
	if err != nil {
		t.Fatalf("ResolveNetip failed: %v", err)
	}
	if len(addrs) != 100 {
		t.Fatalf("unexpected address count: got %d want 100", len(addrs))
	}
}

func TestResolveNetipFragmentedTCPResponse(t *testing.T) {
	serverAddr := startTCPDNSServer(t, func(req *dnsmessage.Msg, conn net.Conn) error {
		resp := new(dnsmessage.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dnsmessage.A{
			Hdr: dnsmessage.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				Ttl:    60,
			},
			A: []byte{203, 0, 113, 7},
		})
		return writeTCPDNSResponse(conn, resp, true)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := ResolveNetip(ctx, stdNetDialer{}, serverAddr, "example.com", dnsmessage.TypeA, "tcp")
	if err != nil {
		t.Fatalf("ResolveNetip failed: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("unexpected address count: got %d want 1", len(addrs))
	}
	if got := addrs[0].String(); got != "203.0.113.7" {
		t.Fatalf("unexpected address: got %s want 203.0.113.7", got)
	}
}

func startTCPDNSServer(t *testing.T, handler func(req *dnsmessage.Msg, conn net.Conn) error) netip.AddrPort {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return
		}

		reqBuf := make([]byte, length)
		if _, err := io.ReadFull(conn, reqBuf); err != nil {
			return
		}

		var req dnsmessage.Msg
		if err := req.Unpack(reqBuf); err != nil {
			return
		}
		_ = handler(&req, conn)
	}()

	return netip.MustParseAddrPort(l.Addr().String())
}

func writeTCPDNSResponse(conn net.Conn, resp *dnsmessage.Msg, fragmented bool) error {
	respBuf, err := resp.Pack()
	if err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, uint16(len(respBuf))); err != nil {
		return err
	}

	if !fragmented {
		if _, err := conn.Write(respBuf); err != nil {
			return err
		}
		return nil
	}

	split := len(respBuf) / 2
	if split == 0 {
		split = 1
	}
	if _, err := conn.Write(respBuf[:split]); err != nil {
		return err
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := conn.Write(respBuf[split:]); err != nil {
		return err
	}
	return nil
}
