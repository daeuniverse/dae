package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"net"
	"reflect"
	"testing"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

func mustGenerateX25519Key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return key
}

func TestRealityECDHEKeyPrefersKeyShareKeysEcdhe(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			KeyShareKeys: &utls.KeySharePrivateKeys{
				Ecdhe: key,
			},
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from KeyShareKeys.Ecdhe")
	}
}

func TestRealityECDHEKeyFallsBackToMlkemEcdhe(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			KeyShareKeys: &utls.KeySharePrivateKeys{
				MlkemEcdhe: key,
			},
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from KeyShareKeys.MlkemEcdhe")
	}
}

func TestRealityECDHEKeyFallsBackToDeprecatedField(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			EcdheKey: key,
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from deprecated EcdheKey field")
	}
}

func setUTLSPeerCertificates(t *testing.T, conn *utls.Conn, certs []*x509.Certificate) {
	t.Helper()
	field := reflect.ValueOf(conn).Elem().FieldByName("peerCertificates")
	if !field.IsValid() {
		t.Fatal("utls.Conn.peerCertificates field missing")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(certs))
}

func TestRealityPeerCertificatesReturnsStoredCertificates(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	uConn := utls.UClient(client, &utls.Config{InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	certs := []*x509.Certificate{{Raw: []byte{1}}}
	setUTLSPeerCertificates(t, uConn.Conn, certs)

	got, err := realityPeerCertificates(uConn.Conn)
	if err != nil {
		t.Fatalf("realityPeerCertificates returned error: %v", err)
	}
	if !reflect.DeepEqual(got, certs) {
		t.Fatalf("unexpected certificates: got %#v want %#v", got, certs)
	}
}

func TestRealityVerifyPeerCertificateRejectsUnavailablePeerCertificates(t *testing.T) {
	uConn := &RealityUConn{}
	if err := uConn.VerifyPeerCertificate(nil, nil); err == nil {
		t.Fatal("expected error when peer certificates are unavailable")
	}
}
