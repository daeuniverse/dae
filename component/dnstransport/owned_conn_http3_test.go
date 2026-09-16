/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dnstransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

type observedOwnedPacketConn struct {
	netproxy.PacketConn
	closes atomic.Int32
	closed chan struct{}
}

func (c *observedOwnedPacketConn) Close() error {
	err := c.PacketConn.Close()
	if c.closes.Add(1) == 1 {
		close(c.closed)
	}
	return err
}

type observedH3Dial struct {
	packet *observedOwnedPacketConn
	conn   quic.EarlyConnection
}

func TestHTTP3OwnedSocketClosesWithoutAnotherRequest(t *testing.T) {
	cert, roots := ownedConnTestCertificate(t)
	listener, err := quic.ListenAddrEarly("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan quic.Connection, 2)
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		ConnContext: func(ctx context.Context, conn quic.Connection) context.Context {
			accepted <- conn
			return ctx
		},
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = server.ServeListener(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	})

	target := netip.MustParseAddrPort(listener.Addr().String())
	dialer := direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{})
	dials := make(chan observedH3Dial, 2)
	transport := NewHTTP3Transport("localhost", func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		var packet *observedOwnedPacketConn
		conn, dialErr := DialEarlyOwned(ctx, func(ctx context.Context) (netproxy.Conn, error) {
			underlay, err := dialer.DialContext(ctx, "udp", target.String())
			if err != nil {
				return nil, err
			}
			packet = &observedOwnedPacketConn{
				PacketConn: underlay.(netproxy.PacketConn),
				closed:     make(chan struct{}),
			}
			return packet, nil
		}, target, tlsCfg, cfg)
		if dialErr == nil {
			dials <- observedH3Dial{packet: packet, conn: conn}
		}
		return conn, dialErr
	})
	transport.TLSClientConfig.RootCAs = roots
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(func() { CloseHTTPClient(client) })
	url := "https://" + target.String() + "/"

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	t.Cleanup(cancelRequest)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	first := <-dials
	remote := <-accepted
	t.Cleanup(func() { _ = first.conn.CloseWithError(0, "test cleanup") })

	// A completed request's cancellation must not close the shared session.
	cancelRequest()
	response, err = client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	select {
	case <-first.packet.closed:
		t.Fatal("request cancellation closed the shared socket")
	case <-dials:
		t.Fatal("request cancellation forced a new QUIC session")
	default:
	}

	if err := remote.CloseWithError(0, "remote shutdown"); err != nil {
		t.Fatal(err)
	}
	// No further request, client shutdown, or GC is needed to release ownership.
	select {
	case <-first.packet.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("remote shutdown did not release the owned UDP socket")
	}
	if err := first.conn.CloseWithError(0, "already closed"); err != nil {
		t.Fatal(err)
	}
	if got := first.packet.closes.Load(); got != 1 {
		t.Fatalf("socket Close count = %d, want 1", got)
	}

	// Eviction of the dead cached client may make the first retry fail. The
	// next request must use a new socket unaffected by the old owner's cleanup.
	response, err = client.Get(url)
	if err != nil {
		response, err = client.Get(url)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	second := <-dials
	<-accepted
	if err := first.conn.CloseWithError(0, "old generation"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.packet.closed:
		t.Fatal("old generation cleanup closed the new socket")
	default:
	}
	CloseHTTPClient(client)
	if got := second.packet.closes.Load(); got != 1 {
		t.Fatalf("new socket Close count = %d, want 1", got)
	}
}

func ownedConnTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
