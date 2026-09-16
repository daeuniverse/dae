package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

const (
	serverNextProto = "dae-semantic-smoke"
	serverDelay     = 250 * time.Millisecond
)

func main() {
	if len(os.Args) < 3 {
		fatalf("usage: %s server|client address port [payload] | http3-client url", os.Args[0])
	}
	mode := os.Args[1]
	switch mode {
	case "server":
		if len(os.Args) < 4 {
			fatalf("server mode requires address and port")
		}
		address := net.JoinHostPort(os.Args[2], os.Args[3])
		runServer(address)
	case "client":
		if len(os.Args) < 4 {
			fatalf("client mode requires address and port")
		}
		address := net.JoinHostPort(os.Args[2], os.Args[3])
		payload := "ready"
		if len(os.Args) >= 5 {
			payload = os.Args[4]
		}
		runClient(address, payload)
	case "http3-client":
		runHTTP3Client(os.Args[2])
	default:
		fatalf("unknown mode %q", mode)
	}
}

func runHTTP3Client(target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: 10 * time.Second},
	}
	defer func() { _ = transport.Close() }()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		fatalf("create HTTP/3 request: %v", err)
	}
	started := time.Now()
	response, err := transport.RoundTrip(request)
	if err != nil {
		fatalf("HTTP/3 request: %v", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if readErr != nil {
		fatalf("read HTTP/3 response: %v", readErr)
	}
	if closeErr != nil {
		fatalf("close HTTP/3 response: %v", closeErr)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		fatalf("HTTP/3 response status: %s", response.Status)
	}
	fmt.Printf("http3 status=%d bytes=%d elapsed-ms=%.1f\n", response.StatusCode, len(body), float64(time.Since(started).Microseconds())/1000)
}

func runServer(address string) {
	listener, err := quic.ListenAddr(address, serverTLSConfig(), &quic.Config{EnableDatagrams: true})
	if err != nil {
		fatalf("listen QUIC: %v", err)
	}
	defer func() { _ = listener.Close() }()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		go serveConnection(conn)
	}
}

func serveConnection(conn quic.Connection) {
	defer func() { _ = conn.CloseWithError(0, "smoke connection complete") }()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		message, err := conn.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			return
		}
		if string(message) == "__stop__" {
			return
		}
		time.Sleep(serverDelay)
		response := append([]byte("echo:"), message...)
		if err := conn.SendDatagram(response); err != nil {
			return
		}
	}
}

func runClient(address, payload string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{serverNextProto},
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		fatalf("dial QUIC: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "smoke client complete") }()

	message := []byte(payload)
	started := time.Now()
	if err := conn.SendDatagram(message); err != nil {
		fatalf("send QUIC datagram: %v", err)
	}
	response, err := conn.ReceiveDatagram(ctx)
	if err != nil {
		fatalf("receive QUIC datagram: %v", err)
	}
	want := append([]byte("echo:"), message...)
	if string(response) != string(want) {
		fatalf("unexpected QUIC response %q", response)
	}
	fmt.Printf("ok %.1f\n", float64(time.Since(started).Microseconds())/1000)
}

func serverTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("generate RSA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		fatalf("generate certificate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("198.20.0.2")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		fatalf("load certificate: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{serverNextProto}, MinVersion: tls.VersionTLS13}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
