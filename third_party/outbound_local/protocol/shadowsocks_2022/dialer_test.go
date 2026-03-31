package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type nopDialer struct{}

func (nopDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return nil, nil
}

type recordingPacketDialer struct {
	conn netproxy.Conn
}

func (d recordingPacketDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return d.conn, nil
}

type recordingPacketNetConn struct {
	writes   [][]byte
	readBufs [][]byte
}

func (c *recordingPacketNetConn) Read(p []byte) (int, error) {
	if len(c.readBufs) == 0 {
		return 0, io.EOF
	}
	buf := c.readBufs[0]
	c.readBufs = c.readBufs[1:]
	n := copy(p, buf)
	return n, nil
}

func (c *recordingPacketNetConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *recordingPacketNetConn) Close() error                       { return nil }
func (c *recordingPacketNetConn) LocalAddr() net.Addr                { return udpConnTestAddr("local") }
func (c *recordingPacketNetConn) RemoteAddr() net.Addr               { return udpConnTestAddr("remote") }
func (c *recordingPacketNetConn) SetDeadline(_ time.Time) error      { return nil }
func (c *recordingPacketNetConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *recordingPacketNetConn) SetWriteDeadline(_ time.Time) error { return nil }

func pskBase64(length int, v byte) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = v
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestNewDialer_UnsupportedCipher(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305-unknown",
		Password:     pskBase64(32, 0x11),
		ProxyAddress: "127.0.0.1:443",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported shadowsocks 2022 cipher") {
		t.Fatalf("expected unsupported cipher error, got: %v", err)
	}
}

func TestNewDialer_Chacha20SinglePSK(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305",
		Password:     pskBase64(32, 0x11),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDialer_Chacha20MultiPSK(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305",
		Password:     strings.Join([]string{pskBase64(32, 0x11), pskBase64(32, 0x12)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDialer_TooManyPSKs(t *testing.T) {
	keys := make([]string, maxPSKListLength+1)
	for i := range keys {
		keys[i] = pskBase64(16, byte(i+1))
	}
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-128-gcm",
		Password:     strings.Join(keys, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err == nil || !strings.Contains(err.Error(), "too many PSKs") {
		t.Fatalf("expected too many PSKs error, got: %v", err)
	}
}

func TestNewDialer_ValidMultiPSK(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     strings.Join([]string{pskBase64(32, 0x21), pskBase64(32, 0x22)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDialer_Chacha20MultiPSKHasEIH(t *testing.T) {
	// Test that chacha multi-PSK creates EIH components
	netproxyDialer, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305",
		Password:     strings.Join([]string{pskBase64(32, 0x11), pskBase64(32, 0x12), pskBase64(32, 0x13)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := netproxyDialer.(*Dialer)

	// Verify EIH is enabled
	if !d.core.HasMultiPSK() {
		t.Fatal("expected HasMultiPSK to be true for multi-PSK chacha")
	}

	// Verify EIH length: 3 PSKs = 2 EIH blocks * 16 bytes = 32 bytes
	expectedEIHLen := 2 * 16
	if d.core.IdentityHeaderLen() != expectedEIHLen {
		t.Fatalf("expected EIH length %d, got %d", expectedEIHLen, d.core.IdentityHeaderLen())
	}

	// Verify IsUsingBlockCipher returns false for chacha
	if d.core.IsUsingBlockCipher() {
		t.Fatal("expected IsUsingBlockCipher to be false for chacha")
	}
}

func TestNewDialer_AESMultiPSKHasEIH(t *testing.T) {
	// Test that AES multi-PSK still works correctly
	netproxyDialer, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     strings.Join([]string{pskBase64(32, 0x21), pskBase64(32, 0x22), pskBase64(32, 0x23)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := netproxyDialer.(*Dialer)

	// Verify EIH is enabled
	if !d.core.HasMultiPSK() {
		t.Fatal("expected HasMultiPSK to be true for multi-PSK AES")
	}

	// Verify EIH length: 3 PSKs = 2 EIH blocks * 16 bytes = 32 bytes
	expectedEIHLen := 2 * 16
	if d.core.IdentityHeaderLen() != expectedEIHLen {
		t.Fatalf("expected EIH length %d, got %d", expectedEIHLen, d.core.IdentityHeaderLen())
	}

	// Verify IsUsingBlockCipher returns true for AES
	if !d.core.IsUsingBlockCipher() {
		t.Fatal("expected IsUsingBlockCipher to be true for AES")
	}
}

func TestNewDialer_SinglePSKNoEIH(t *testing.T) {
	// Test that single PSK doesn't create EIH for both AES and Chacha
	testCases := []struct {
		name   string
		cipher string
		psk    string
	}{
		{"chacha_single", "2022-blake3-chacha20-poly1305", pskBase64(32, 0x11)},
		{"aes256_single", "2022-blake3-aes-256-gcm", pskBase64(32, 0x21)},
		{"aes128_single", "2022-blake3-aes-128-gcm", pskBase64(16, 0x31)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			netproxyDialer, err := NewDialer(nopDialer{}, protocol.Header{
				Cipher:       tc.cipher,
				Password:     tc.psk,
				ProxyAddress: "127.0.0.1:443",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			d := netproxyDialer.(*Dialer)

			// Verify EIH is not enabled for single PSK
			if d.core.HasMultiPSK() {
				t.Fatal("expected HasMultiPSK to be false for single PSK")
			}

			// Verify EIH length is 0
			if d.core.IdentityHeaderLen() != 0 {
				t.Fatalf("expected EIH length 0, got %d", d.core.IdentityHeaderLen())
			}
		})
	}
}

func TestFakeNetPacketConn_WriteUsesPacketSemantics(t *testing.T) {
	rawConn := &recordingPacketNetConn{}
	netproxyDialer, err := NewDialer(recordingPacketDialer{conn: rawConn}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     pskBase64(32, 0x61),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	conn, err := netproxyDialer.DialContext(context.Background(), "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}

	payload := []byte("abc")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if len(rawConn.writes) == 0 {
		t.Fatal("expected underlying write")
	}

	lastWrite := rawConn.writes[len(rawConn.writes)-1]
	if string(lastWrite) == string(payload) {
		t.Fatalf("expected encoded packet, got raw payload %q", string(lastWrite))
	}
	if len(lastWrite) <= len(payload) {
		t.Fatalf("expected encoded packet larger than payload: got %d want > %d", len(lastWrite), len(payload))
	}
}

func TestFakeNetPacketConn_ReadUsesPacketSemantics(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x23
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remoteSessionID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	wantPayload := []byte("ss2022-read-through-wrapper")
	packet := buildServerPacket(t, core, remoteSessionID, localSessionID, 1, "203.0.113.9:853", wantPayload)

	rawConn := &recordingPacketNetConn{
		readBufs: [][]byte{packet},
	}
	netproxyDialer, err := NewDialer(recordingPacketDialer{conn: rawConn}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     pskBase64(32, 0x23),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	conn, err := netproxyDialer.DialContext(context.Background(), "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}

	ssConn, ok := conn.(*FakeNetPacketConn)
	if !ok {
		t.Fatalf("unexpected conn type: %T", conn)
	}
	inner, ok := ssConn.PacketConn.(*UdpConn)
	if !ok {
		t.Fatalf("unexpected inner conn type: %T", ssConn.PacketConn)
	}
	inner.sessionID = localSessionID

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("unexpected payload: got %q want %q", got, string(wantPayload))
	}
}
