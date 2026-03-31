package tls

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"
)

func TestUTLSConfigFromTLSConfigPreservesClientSettings(t *testing.T) {
	verifyCalled := false
	stdConfig := &tls.Config{
		ServerName:             "example.com",
		InsecureSkipVerify:     true,
		NextProtos:             []string{"h2", "http/1.1"},
		RootCAs:                x509.NewCertPool(),
		VerifyPeerCertificate:  func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error { verifyCalled = true; return nil },
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS13,
		CipherSuites:           []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SessionTicketsDisabled: true,
		KeyLogWriter:           io.Discard,
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	uConfig := uTLSConfigFromTLSConfig(stdConfig)
	if uConfig == nil {
		t.Fatal("expected uTLS config")
	}
	if uConfig.ServerName != stdConfig.ServerName {
		t.Fatalf("unexpected ServerName: got %q want %q", uConfig.ServerName, stdConfig.ServerName)
	}
	if !uConfig.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be preserved")
	}
	if len(uConfig.NextProtos) != 2 || uConfig.NextProtos[0] != "h2" || uConfig.NextProtos[1] != "http/1.1" {
		t.Fatalf("unexpected NextProtos: %#v", uConfig.NextProtos)
	}
	if len(uConfig.CipherSuites) != 1 || uConfig.CipherSuites[0] != stdConfig.CipherSuites[0] {
		t.Fatalf("unexpected CipherSuites: %#v", uConfig.CipherSuites)
	}
	if len(uConfig.CurvePreferences) != 2 || uint16(uConfig.CurvePreferences[0]) != uint16(stdConfig.CurvePreferences[0]) {
		t.Fatalf("unexpected CurvePreferences: %#v", uConfig.CurvePreferences)
	}
	if uConfig.RootCAs != stdConfig.RootCAs {
		t.Fatal("expected RootCAs to be preserved")
	}
	if uConfig.MinVersion != stdConfig.MinVersion || uConfig.MaxVersion != stdConfig.MaxVersion {
		t.Fatalf("unexpected TLS versions: got [%d,%d] want [%d,%d]", uConfig.MinVersion, uConfig.MaxVersion, stdConfig.MinVersion, stdConfig.MaxVersion)
	}
	if !uConfig.SessionTicketsDisabled {
		t.Fatal("expected SessionTicketsDisabled to be preserved")
	}
	if uConfig.KeyLogWriter != io.Discard {
		t.Fatal("expected KeyLogWriter to be preserved")
	}
	if err := uConfig.VerifyPeerCertificate(nil, nil); err != nil {
		t.Fatalf("VerifyPeerCertificate returned error: %v", err)
	}
	if !verifyCalled {
		t.Fatal("expected VerifyPeerCertificate callback to be preserved")
	}

	uConfig.NextProtos[0] = "mutated"
	if stdConfig.NextProtos[0] != "h2" {
		t.Fatal("expected NextProtos slice to be copied")
	}
	uConfig.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	if stdConfig.CipherSuites[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatal("expected CipherSuites slice to be copied")
	}
}
