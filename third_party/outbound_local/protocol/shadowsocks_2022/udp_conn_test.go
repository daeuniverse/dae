package shadowsocks_2022

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"golang.org/x/crypto/chacha20poly1305"
)

type udpReadBufferConn struct {
	packet []byte
	read   bool
}

func (c *udpReadBufferConn) Read(p []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	copy(p, c.packet)
	return len(c.packet), nil
}

func (c *udpReadBufferConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *udpReadBufferConn) Close() error                       { return nil }
func (c *udpReadBufferConn) LocalAddr() net.Addr                { return udpConnTestAddr("local") }
func (c *udpReadBufferConn) RemoteAddr() net.Addr               { return udpConnTestAddr("remote") }
func (c *udpReadBufferConn) SetDeadline(_ time.Time) error      { return nil }
func (c *udpReadBufferConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *udpReadBufferConn) SetWriteDeadline(_ time.Time) error { return nil }

type udpConnTestAddr string

func (a udpConnTestAddr) Network() string { return "udp-test" }
func (a udpConnTestAddr) String() string  { return string(a) }

func buildServerPacket(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte) []byte {
	t.Helper()

	var separateHeader [16]byte
	copy(separateHeader[:8], serverSessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	core.BlockCipherDecrypt().Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		t.Fatalf("AddressFromString: %v", err)
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		t.Fatalf("addrInfoEncodedLen: %v", err)
	}

	messageLen := 1 + 8 + 8 + 2 + addrLen + len(payload)
	message := make([]byte, messageLen)
	message[0] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(message[1:9], uint64(time.Now().Unix()))
	copy(message[9:17], clientSessionID[:])
	addrWritten, err := writeAddrInfoTo(message[19:], addrInfo)
	if err != nil {
		t.Fatalf("writeAddrInfoTo: %v", err)
	}
	copy(message[19+addrWritten:], payload)

	sessionCipher, err := CreateCipher(core.UPSK(), serverSessionID[:], core.CipherConf())
	if err != nil {
		t.Fatalf("CreateCipher: %v", err)
	}
	return sessionCipher.Seal(separateHeaderEncrypted[:], separateHeader[4:16], message, nil)
}

func buildServerPacketChacha(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte) []byte {
	t.Helper()

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		t.Fatalf("AddressFromString: %v", err)
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		t.Fatalf("addrInfoEncodedLen: %v", err)
	}

	messageLen := 16 + 1 + 8 + 8 + 2 + addrLen + len(payload)
	message := make([]byte, messageLen)
	copy(message[:8], serverSessionID[:])
	binary.BigEndian.PutUint64(message[8:16], packetID)
	message[16] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(message[17:25], uint64(time.Now().Unix()))
	copy(message[25:33], clientSessionID[:])
	addrWritten, err := writeAddrInfoTo(message[35:], addrInfo)
	if err != nil {
		t.Fatalf("writeAddrInfoTo: %v", err)
	}
	copy(message[35+addrWritten:], payload)

	udpCipher, err := chacha20poly1305.NewX(core.UPSK())
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}

	nonce := make([]byte, udpPacketNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	packet := make([]byte, udpPacketNonceSize, udpPacketNonceSize+messageLen+core.CipherConf().TagLen)
	copy(packet, nonce)
	return udpCipher.Seal(packet, nonce, message, nil)
}

func TestValidateTimestamp(t *testing.T) {
	now := time.Now()
	if err := validateTimestamp(now, now); err != nil {
		t.Fatalf("now should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance-time.Millisecond), now); err != nil {
		t.Fatalf("near-future timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance+time.Millisecond), now); err != nil {
		t.Fatalf("near-past timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance+time.Millisecond), now); err != protocol.ErrReplayAttack {
		t.Fatalf("too-far future timestamp should fail with replay, got: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance-time.Millisecond), now); err != protocol.ErrReplayAttack {
		t.Fatalf("too-old timestamp should fail with replay, got: %v", err)
	}
}

func TestUdpConn_NextPacketID_ConcurrentUnique(t *testing.T) {
	u := &UdpConn{}
	const n = 2000

	ids := make(chan uint64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids <- u.nextPacketID()
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[uint64]struct{}, n)
	var minID = ^uint64(0)
	var maxID uint64
	for id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate packetID: %d", id)
		}
		seen[id] = struct{}{}
		if id < minID {
			minID = id
		}
		if id > maxID {
			maxID = id
		}
	}

	if len(seen) != n {
		t.Fatalf("unexpected unique count: got %d, want %d", len(seen), n)
	}
	if minID != 1 {
		t.Fatalf("unexpected min packetID: got %d, want 1", minID)
	}
	if maxID != n {
		t.Fatalf("unexpected max packetID: got %d, want %d", maxID, n)
	}
}

func TestUdpConn_ReplayWindow_PerSessionAndExpiry(t *testing.T) {
	u := &UdpConn{}
	now := time.Now()

	var sid1 [8]byte
	copy(sid1[:], []byte{1, 1, 1, 1, 1, 1, 1, 1})
	var sid2 [8]byte
	copy(sid2[:], []byte{2, 2, 2, 2, 2, 2, 2, 2})

	if !u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 packet 1 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 duplicate packet 1 should fail")
	}
	if !u.checkAndUpdateReplay(sid1, 2, now) {
		t.Fatalf("sid1 packet 2 should pass")
	}
	if !u.checkAndUpdateReplay(sid2, 1, now) {
		t.Fatalf("sid2 packet 1 should pass independently")
	}

	if !u.checkAndUpdateReplay(sid1, 5000, now) {
		t.Fatalf("sid1 packet 5000 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 old packet should fail after large jump")
	}

	future := now.Add(ciphers.SaltStorageDuration + time.Second)
	if !u.checkAndUpdateReplay(sid1, 1, future) {
		t.Fatalf("sid1 should reset after expiry and accept packet 1")
	}
}

func TestUdpConn_ReadFromUsesRemoteSessionCipher(t *testing.T) {
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
	wantAddr := netip.MustParseAddrPort("203.0.113.9:853")
	wantPayload := []byte("ss2022-udp-remote-session")

	packet := buildServerPacket(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), wantPayload)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("unexpected payload: got %q want %q", got, string(wantPayload))
	}
}

func TestUdpConn_ReadFromChacha2022(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-chacha20-poly1305"]
	if conf == nil {
		t.Fatal("missing ss2022 chacha cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x31
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 3, 5, 7, 9, 11, 13, 15}
	remoteSessionID := [8]byte{2, 4, 6, 8, 10, 12, 14, 16}
	wantAddr := netip.MustParseAddrPort("198.51.100.7:443")
	wantPayload := []byte("ss2022-chacha-udp")

	packet := buildServerPacketChacha(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), wantPayload)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("unexpected payload: got %q want %q", got, string(wantPayload))
	}
}
