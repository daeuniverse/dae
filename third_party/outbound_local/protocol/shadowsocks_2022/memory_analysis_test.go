package shadowsocks_2022

import (
	"crypto/aes"
	"crypto/subtle"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"lukechampine.com/blake3"
)

type analysisDiscardConn struct{}

func (analysisDiscardConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (analysisDiscardConn) Write(p []byte) (int, error)        { return len(p), nil }
func (analysisDiscardConn) Close() error                       { return nil }
func (analysisDiscardConn) LocalAddr() net.Addr                { return analysisAddr("local") }
func (analysisDiscardConn) RemoteAddr() net.Addr               { return analysisAddr("remote") }
func (analysisDiscardConn) SetDeadline(_ time.Time) error      { return nil }
func (analysisDiscardConn) SetReadDeadline(_ time.Time) error  { return nil }
func (analysisDiscardConn) SetWriteDeadline(_ time.Time) error { return nil }

type analysisAddr string

func (a analysisAddr) Network() string { return "analysis" }
func (a analysisAddr) String() string  { return string(a) }

func analysisPSKList(count, keyLen int) [][]byte {
	pskList := make([][]byte, count)
	for i := 0; i < count; i++ {
		psk := make([]byte, keyLen)
		for j := range psk {
			psk[j] = byte(i + 1)
		}
		pskList[i] = psk
	}
	return pskList
}

func analysisHeapAlloc() uint64 {
	runtime.GC()
	debug.FreeOSMemory()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

func analysisReplayWindowLen(c *UdpConn) int {
	var n int
	c.replayWindow.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func analysisIdentityHeaderNoCache(dst []byte, conf *ciphers.CipherConf2022, pskList [][]byte, separateHeader []byte) (int, error) {
	if len(pskList) <= 1 {
		return 0, nil
	}
	headerLen := (len(pskList) - 1) * aes.BlockSize
	if len(dst) < headerLen {
		return 0, io.ErrShortBuffer
	}
	offset := 0
	for i := 0; i < len(pskList)-1; i++ {
		header := dst[offset : offset+aes.BlockSize]
		hash := blake3.Sum512(pskList[i+1])
		subtle.XORBytes(header, hash[:aes.BlockSize], separateHeader)
		blockCipher, err := conf.NewBlockCipher(pskList[i])
		if err != nil {
			return 0, err
		}
		blockCipher.Encrypt(header, header)
		offset += aes.BlockSize
	}
	return offset, nil
}

func analysisUDPWriteToNoSessionCipherCache(c *UdpConn, payload []byte, addr string) error {
	packetID := c.nextPacketID()
	var separateHeader [16]byte
	copy(separateHeader[:8], c.sessionID[:])
	putUint64 := func(b []byte, v uint64) {
		b[0] = byte(v >> 56)
		b[1] = byte(v >> 48)
		b[2] = byte(v >> 40)
		b[3] = byte(v >> 32)
		b[4] = byte(v >> 24)
		b[5] = byte(v >> 16)
		b[6] = byte(v >> 8)
		b[7] = byte(v)
	}
	putUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	c.blockCipherEncrypt.Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		return err
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		return err
	}
	messageLen := 1 + 8 + 2 + addrLen + len(payload)
	totalPacketLen := len(separateHeaderEncrypted) + c.IdentityHeaderLen() + messageLen + c.CipherConf().TagLen
	packet := make([]byte, totalPacketLen)
	offset := 0
	copy(packet[offset:], separateHeaderEncrypted[:])
	offset += len(separateHeaderEncrypted)

	identityHeaderLen, err := c.WriteIdentityHeader(packet[offset:], separateHeader[:])
	if err != nil {
		return err
	}
	offset += identityHeaderLen

	messageOffset := offset
	message := packet[messageOffset : messageOffset+messageLen]
	message[0] = HeaderTypeClientStream
	putUint64(message[1:9], uint64(time.Now().Unix()))
	message[9] = 0
	message[10] = 0
	addrWritten, err := writeAddrInfoTo(message[11:], addrInfo)
	if err != nil {
		return err
	}
	copy(message[11+addrWritten:], payload)

	sessionCipher, err := CreateCipher(c.UPSK(), c.sessionID[:], c.CipherConf())
	if err != nil {
		return err
	}
	packet = sessionCipher.Seal(packet[:messageOffset], separateHeader[4:16], message, nil)
	_, err = c.Write(packet)
	return err
}

func TestSS2022CoreRetainedHeapAndRelease(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	measure := func(name string, pskCount, connCount int) (liveGrowth int64, releasedGrowth int64) {
		t.Helper()

		baseline := analysisHeapAlloc()
		cores := make([]*SS2022Core, connCount)
		pskList := analysisPSKList(pskCount, conf.KeyLen)
		uPSK := pskList[len(pskList)-1]
		for i := 0; i < connCount; i++ {
			core, err := NewSS2022Core(conf, pskList, uPSK)
			if err != nil {
				t.Fatalf("%s: create core: %v", name, err)
			}
			cores[i] = core
		}
		live := analysisHeapAlloc()
		runtime.KeepAlive(cores)

		liveGrowth = int64(live) - int64(baseline)
		if liveGrowth <= 0 {
			t.Fatalf("%s: expected positive live heap growth, got %d", name, liveGrowth)
		}

		released := analysisHeapAlloc()
		releasedGrowth = int64(released) - int64(baseline)
		t.Logf("%s: live heap %+d bytes, after release %+d bytes", name, liveGrowth, releasedGrowth)
		return liveGrowth, releasedGrowth
	}

	const connCount = 4000
	singleLive, singleReleased := measure("single-psk", 1, connCount)
	multiLive, multiReleased := measure("multi-psk-8", maxPSKListLength, connCount)

	t.Logf("single-psk retained bytes/core: %.2f", float64(singleLive)/connCount)
	t.Logf("multi-psk-8 retained bytes/core: %.2f", float64(multiLive)/connCount)

	if multiLive <= singleLive {
		t.Fatalf("expected multi-psk cores to retain more heap than single-psk: single=%d multi=%d", singleLive, multiLive)
	}
	if singleReleased > singleLive/2 && singleReleased > 1<<20 {
		t.Fatalf("single-psk core memory did not return close enough after release: live=%d released=%d", singleLive, singleReleased)
	}
	if multiReleased > multiLive/2 && multiReleased > 1<<20 {
		t.Fatalf("multi-psk core memory did not return close enough after release: live=%d released=%d", multiLive, multiReleased)
	}
}

func TestSS2022TCPConnCloseReleasesReusableBuffers(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}
	sg, err := shadowsocks.NewRandomSaltGenerator(conf.SaltLen)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sg.Close() }()

	addr, err := socks5.AddressFromString("203.0.113.10:443")
	if err != nil {
		t.Fatal(err)
	}

	pskList := analysisPSKList(1, conf.KeyLen)
	uPSK := pskList[0]
	core, err := NewSS2022Core(conf, pskList, uPSK)
	if err != nil {
		t.Fatal(err)
	}

	const connCount = 256
	baseline := analysisHeapAlloc()
	conns := make([]*TCPConn, connCount)
	for i := 0; i < connCount; i++ {
		conn := NewTCPConn(analysisDiscardConn{}, core, sg, addr, nil).(*TCPConn)
		_ = conn.ensureReadCipherBuf(64 << 10)
		_ = conn.borrowWriteFrame(96 << 10)
		conns[i] = conn
	}

	live := analysisHeapAlloc()
	runtime.KeepAlive(conns)
	liveGrowth := int64(live) - int64(baseline)
	if liveGrowth < 8<<20 {
		t.Fatalf("expected cached buffers to retain noticeable heap, got %d bytes", liveGrowth)
	}

	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}

	released := analysisHeapAlloc()
	releasedGrowth := int64(released) - int64(baseline)
	t.Logf("tcp reusable buffers: live heap %+d bytes, after close %+d bytes", liveGrowth, releasedGrowth)

	if releasedGrowth > liveGrowth/3 && releasedGrowth > 4<<20 {
		t.Fatalf("tcp reusable buffer memory still retained after close: live=%d released=%d", liveGrowth, releasedGrowth)
	}
}

func TestSS2022UDPReplayWindowBounded(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	pskList := analysisPSKList(1, conf.KeyLen)
	uPSK := pskList[0]
	core, err := NewSS2022Core(conf, pskList, uPSK)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := NewUdpConn(analysisDiscardConn{}, core, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	for i := 0; i < maxTrackedUdpSessions*4; i++ {
		var sessionID [8]byte
		sessionID[0] = byte(i)
		sessionID[1] = byte(i >> 8)
		if !conn.checkAndUpdateReplay(sessionID, 1, now) {
			t.Fatalf("session %d should be accepted on first packet", i)
		}
	}

	if got := analysisReplayWindowLen(conn); got > maxTrackedUdpSessions {
		t.Fatalf("replay window exceeded bound: got %d want <= %d", got, maxTrackedUdpSessions)
	}
}

func BenchmarkSS2022IdentityHeader_PrecomputedMultiPSK(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	pskList := analysisPSKList(maxPSKListLength, conf.KeyLen)
	core, err := NewSS2022Core(conf, pskList, pskList[len(pskList)-1])
	if err != nil {
		b.Fatal(err)
	}

	var separateHeader [16]byte
	dst := make([]byte, core.IdentityHeaderLen())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := core.WriteIdentityHeader(dst, separateHeader[:]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSS2022IdentityHeader_RecomputeMultiPSK(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	pskList := analysisPSKList(maxPSKListLength, conf.KeyLen)

	var separateHeader [16]byte
	dst := make([]byte, (len(pskList)-1)*aes.BlockSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := analysisIdentityHeaderNoCache(dst, conf, pskList, separateHeader[:]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSS2022UDPWriteTo_SessionCipherReuse(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	pskList := analysisPSKList(1, conf.KeyLen)
	uPSK := pskList[0]
	core, err := NewSS2022Core(conf, pskList, uPSK)
	if err != nil {
		b.Fatal(err)
	}
	conn, err := NewUdpConn(analysisDiscardConn{}, core, nil)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1400)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.WriteTo(payload, "198.51.100.10:443"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSS2022UDPWriteTo_CreateCipherEveryPacket(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	pskList := analysisPSKList(1, conf.KeyLen)
	uPSK := pskList[0]
	core, err := NewSS2022Core(conf, pskList, uPSK)
	if err != nil {
		b.Fatal(err)
	}
	conn, err := NewUdpConn(analysisDiscardConn{}, core, nil)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1400)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := analysisUDPWriteToNoSessionCipherCache(conn, payload, "198.51.100.10:443"); err != nil {
			b.Fatal(err)
		}
	}
}
