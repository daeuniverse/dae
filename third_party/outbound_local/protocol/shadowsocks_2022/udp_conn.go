package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
)

// UdpConn represents a Shadowsocks 2022 UDP connection.
// Design follows sing-box: cipher is created once at session initialization.
type UdpConn struct {
	*SS2022Core

	net.Conn

	sessionID [8]byte
	packetID  atomic.Uint64
	ctx       context.Context
	ctxMu     sync.RWMutex

	// cipher is derived from the local session ID and reused for outbound
	// packets. Inbound packets must decrypt against the remote session ID
	// carried in each packet, so they use decryptCiphers instead.
	cipher     cipher.AEAD
	cipherOnce sync.Once
	cipherErr  error

	// decryptCiphers caches inbound AEAD instances by remote session ID.
	// Keeping this per-UdpConn avoids the old process-wide cache while
	// preserving the protocol requirement that receive-side decryption uses
	// the sender's session ID, not the local one.
	decryptCiphers sync.Map // map[[8]byte]cipher.AEAD

	bloom *disk_bloom.FilterGroup

	replayWindow sync.Map
	replayCount  atomic.Int64

	cleanupCounter atomic.Int64
}

const (
	udpPacketReplayWindowSize = 1024
	maxTrackedUdpSessions     = 128
	udpPacketNonceSize        = 24
)

type udpSessionReplayState struct {
	filter   *ciphers.SlidingWindowFilter
	lastSeen atomic.Int64
}

// NewUdpConn creates a new UDP connection bound to a shared SS2022 profile.
func NewUdpConn(conn net.Conn, core *SS2022Core, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	return NewUdpConnWithContext(context.Background(), conn, core, bloom)
}

// NewUdpConnWithContext creates a new UDP connection with the given context.
// For UDP, the context is only used to check for cancellation during the initial setup,
// not for ongoing I/O operations. UDP connections are long-lived and should not be
// bound to the dial context's timeout.
func NewUdpConnWithContext(ctx context.Context, conn net.Conn, core *SS2022Core, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := &UdpConn{
		SS2022Core: core,
		Conn:       conn,
		ctx:        context.Background(), // Use Background for long-lived UDP connections
		bloom:      bloom,
	}

	// Generate session ID
	_, _ = fastrand.Read(u.sessionID[:])
	return u, nil
}

// getContext returns the current context, defaulting to background if not set.
func (c *UdpConn) getContext() context.Context {
	c.ctxMu.RLock()
	defer c.ctxMu.RUnlock()
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

// checkContextAndSetReadDeadline checks if the context is cancelled before a blocking read.
// Returns true if the operation should proceed, false if it should be aborted.
// For UDP, we respect the context's deadline if set, but don't impose arbitrary short timeouts
// that could break legitimate long-lived connections over high-latency networks.
func (c *UdpConn) checkContextAndSetReadDeadline() bool {
	ctx := c.getContext()
	select {
	case <-ctx.Done():
		return false
	default:
	}
	// Only set a deadline if the context has one.
	// This preserves the original behavior (no timeout) while still supporting
	// context cancellation for graceful shutdown.
	if deadline, ok := ctx.Deadline(); ok {
		// Use the context's deadline, not a fixed 5-second timeout
		if dl, ok := c.Conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = dl.SetReadDeadline(deadline)
		}
	}
	return true
}

// checkContextAndSetWriteDeadline checks if the context is cancelled before a blocking write.
// Returns true if the operation should proceed, false if it should be aborted.
// For UDP, we respect the context's deadline if set, but don't impose arbitrary short timeouts
// that could break legitimate long-lived connections over high-latency networks.
func (c *UdpConn) checkContextAndSetWriteDeadline() bool {
	ctx := c.getContext()
	select {
	case <-ctx.Done():
		return false
	default:
	}
	// Only set a deadline if the context has one.
	// This preserves the original behavior (no timeout) while still supporting
	// context cancellation for graceful shutdown.
	if deadline, ok := ctx.Deadline(); ok {
		// Use the context's deadline, not a fixed 5-second timeout
		if dl, ok := c.Conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = dl.SetWriteDeadline(deadline)
		}
	}
	return true
}

func (c *UdpConn) ensureCipher() error {
	c.cipherOnce.Do(func() {
		if !c.IsUsingBlockCipher() {
			c.cipher, c.cipherErr = chacha20poly1305.NewX(c.UPSK())
		} else {
			c.cipher, c.cipherErr = CreateCipher(c.UPSK(), c.sessionID[:], c.CipherConf())
		}
		if c.cipherErr != nil {
			c.cipherErr = fmt.Errorf("failed to create session cipher: %w", c.cipherErr)
		}
	})
	return c.cipherErr
}

func (c *UdpConn) decryptCipherFor(sessionID [8]byte) (cipher.AEAD, error) {
	if cached, ok := c.decryptCiphers.Load(sessionID); ok {
		return cached.(cipher.AEAD), nil
	}

	sessionCipher, err := CreateCipher(c.UPSK(), sessionID[:], c.CipherConf())
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypt cipher for remote session: %w", err)
	}
	actual, _ := c.decryptCiphers.LoadOrStore(sessionID, sessionCipher)
	return actual.(cipher.AEAD), nil
}

func (c *UdpConn) nextPacketID() uint64 {
	return c.packetID.Add(1)
}

func (c *UdpConn) checkAndUpdateReplay(sessionID [8]byte, packetID uint64, now time.Time) bool {
	nowNano := now.UnixNano()
	expireNano := ciphers.SaltStorageDuration.Nanoseconds()

	if v, ok := c.replayWindow.Load(sessionID); ok {
		state := v.(*udpSessionReplayState)
		lastSeen := state.lastSeen.Load()
		if nowNano-lastSeen > expireNano {
			if c.replayWindow.CompareAndDelete(sessionID, v) {
				c.replayCount.Add(-1)
			}
		} else {
			state.lastSeen.Store(nowNano)
			return state.filter.CheckAndUpdate(packetID)
		}
	}

	if c.cleanupCounter.Add(1)%cleanupInterval == 0 {
		go c.cleanupExpiredSessions(nowNano, expireNano)
	}

	newState := &udpSessionReplayState{
		filter: ciphers.NewSlidingWindowFilter(udpPacketReplayWindowSize),
	}
	newState.lastSeen.Store(nowNano)

	actual, loaded := c.replayWindow.LoadOrStore(sessionID, newState)
	state := actual.(*udpSessionReplayState)

	if loaded {
		state.lastSeen.Store(nowNano)
	} else {
		c.replayCount.Add(1)
		c.evictOldestIfNeeded()
	}

	return state.filter.CheckAndUpdate(packetID)
}

const cleanupInterval = 1000

func (c *UdpConn) cleanupExpiredSessions(nowNano, expireNano int64) {
	c.replayWindow.Range(func(key, value interface{}) bool {
		state := value.(*udpSessionReplayState)
		if nowNano-state.lastSeen.Load() > expireNano {
			if c.replayWindow.CompareAndDelete(key, value) {
				c.replayCount.Add(-1)
			}
		}
		return true
	})
}

func (c *UdpConn) evictOldestIfNeeded() {
	for c.replayCount.Load() > maxTrackedUdpSessions {
		var (
			found      bool
			oldestKey  [8]byte
			oldestVal  any
			oldestNano = ^int64(0)
		)

		c.replayWindow.Range(func(key, value interface{}) bool {
			state := value.(*udpSessionReplayState)
			seen := state.lastSeen.Load()
			if !found || seen < oldestNano {
				found = true
				oldestKey = key.([8]byte)
				oldestVal = value
				oldestNano = seen
			}
			return true
		})

		if !found {
			c.replayCount.Store(0)
			return
		}
		if c.replayWindow.CompareAndDelete(oldestKey, oldestVal) {
			c.replayCount.Add(-1)
			continue
		}
		// Retry if the oldest entry changed concurrently.
	}
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	if !c.IsUsingBlockCipher() {
		return c.writeToChacha(b, addr)
	}

	if err := c.ensureCipher(); err != nil {
		return 0, err
	}

	packetID := c.nextPacketID()
	var separateHeader [16]byte
	copy(separateHeader[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	c.BlockCipherEncrypt().Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to parse target address")
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to calculate address length")
	}
	messageLen := 1 + 8 + 2 + addrLen + len(b)
	totalPacketLen := len(separateHeaderEncrypted) + c.IdentityHeaderLen() + messageLen + c.CipherConf().TagLen
	packet := pool.Get(totalPacketLen)
	defer pool.Put(packet)
	offset := 0
	copy(packet[offset:], separateHeaderEncrypted[:])
	offset += len(separateHeaderEncrypted)

	identityHeaderLen, err := c.WriteIdentityHeader(packet[offset:], separateHeader[:])
	if err != nil {
		return 0, oops.Wrapf(err, "fail to write identity header")
	}
	offset += identityHeaderLen

	messageOffset := offset
	message := packet[messageOffset : messageOffset+messageLen]
	message[0] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(message[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(message[9:11], 0)
	addrWritten, err := writeAddrInfoTo(message[11:], addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode request address")
	}
	copy(message[11+addrWritten:], b)

	// Use session-level cipher (no cache lookup needed)
	packet = c.cipher.Seal(packet[:messageOffset], separateHeader[4:16], message, nil)

	if !c.checkContextAndSetWriteDeadline() {
		return 0, io.EOF
	}
	_, err = c.Write(packet)
	return len(b), err
}

func (c *UdpConn) writeToChacha(b []byte, addr string) (int, error) {
	if err := c.ensureCipher(); err != nil {
		return 0, err
	}

	packetID := c.nextPacketID()

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to parse target address")
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to calculate address length")
	}

	// For Chacha, EIH is placed before the message content
	// Format: nonce + EIH + (session_id + packet_id + header + timestamp + padding_len + addr + payload)
	// The EIH is encrypted together with the message as associated data is not used here
	eihLen := c.IdentityHeaderLen()
	messageLen := 16 + 1 + 8 + 2 + addrLen + len(b)
	totalPacketLen := udpPacketNonceSize + eihLen + messageLen + c.CipherConf().TagLen
	packet := pool.Get(totalPacketLen)
	defer pool.Put(packet)

	nonce := packet[:udpPacketNonceSize]
	_, _ = fastrand.Read(nonce)

	// Build packet structure: nonce + EIH + message
	eihOffset := udpPacketNonceSize
	messageOffset := eihOffset + eihLen
	message := packet[messageOffset : messageOffset+messageLen]
	copy(message[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(message[8:16], packetID)
	message[16] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(message[17:25], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(message[25:27], 0)

	addrWritten, err := writeAddrInfoTo(message[27:], addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode request address")
	}
	copy(message[27+addrWritten:], b)

	// Write EIH if multi-PSK is enabled
	if eihLen > 0 {
		// Build separate header for EIH derivation (session_id + packet_id)
		var separateHeader [16]byte
		copy(separateHeader[:8], c.sessionID[:])
		binary.BigEndian.PutUint64(separateHeader[8:], packetID)

		_, err = c.WriteIdentityHeader(packet[eihOffset:], separateHeader[:])
		if err != nil {
			return 0, oops.Wrapf(err, "fail to write identity header")
		}
	}

	// Seal the entire message (EIH is included as part of plaintext)
	packet = c.cipher.Seal(packet[:udpPacketNonceSize], nonce, packet[eihOffset:messageOffset+messageLen], nil)
	if !c.checkContextAndSetWriteDeadline() {
		return 0, io.EOF
	}
	_, err = c.Write(packet)
	return len(b), err
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	if !c.IsUsingBlockCipher() {
		return c.readFromChacha(b)
	}

	buf := pool.Get(len(b) + 16 + c.CipherConf().TagLen)
	defer pool.Put(buf)
	if !c.checkContextAndSetReadDeadline() {
		return 0, netip.AddrPort{}, io.EOF
	}
	n, err = c.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	// Check context after read
	select {
	case <-c.getContext().Done():
		return 0, netip.AddrPort{}, c.getContext().Err()
	default:
	}
	if n < 16 {
		return 0, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}

	c.BlockCipherDecrypt().Decrypt(buf[:16], buf[:16])
	var sessionID [8]byte
	copy(sessionID[:], buf[:8])
	packetID := binary.BigEndian.Uint64(buf[8:16])
	now := time.Now()
	if !c.checkAndUpdateReplay(sessionID, packetID, now) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	payload := buf[16:n]
	sessionCipher, err := c.decryptCipherFor(sessionID)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload, err = sessionCipher.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	reader := bytes.NewReader(payload)

	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read header type: %w", err)
	}

	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	timestamp := time.Unix(int64(timestampRaw), 0)

	if _, err := reader.Seek(8, io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip session ID: %w", err)
	}

	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read padding length: %w", err)
	}

	if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip padding: %w", err)
	}

	if typ != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", typ)
	}

	if err := validateTimestamp(timestamp, now); err != nil {
		return 0, netip.AddrPort{}, err
	}

	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if udpAddr, ok := netAddr.(*net.UDPAddr); ok {
		ipAddr, _ := netip.AddrFromSlice(udpAddr.IP)
		addr = netip.AddrPortFrom(ipAddr, uint16(udpAddr.Port))
	}

	n, err = reader.Read(b)
	return
}

func (c *UdpConn) readFromChacha(b []byte) (n int, addr netip.AddrPort, err error) {
	if err := c.ensureCipher(); err != nil {
		return 0, netip.AddrPort{}, err
	}

	buf := pool.Get(len(b) + udpPacketNonceSize + c.CipherConf().TagLen + 320)
	defer pool.Put(buf)

	if !c.checkContextAndSetReadDeadline() {
		return 0, netip.AddrPort{}, io.EOF
	}
	n, err = c.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	// Check context after read
	select {
	case <-c.getContext().Done():
		return 0, netip.AddrPort{}, c.getContext().Err()
	default:
	}
	if n < udpPacketNonceSize+c.CipherConf().TagLen+16 {
		return 0, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}

	nonce := buf[:udpPacketNonceSize]
	payload := buf[udpPacketNonceSize:n]
	payload, err = c.cipher.Open(payload[:0], nonce, payload, nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	reader := bytes.NewReader(payload)

	// Skip EIH if present (for multi-PSK chacha)
	eihLen := c.IdentityHeaderLen()
	if eihLen > 0 {
		if _, err := reader.Seek(int64(eihLen), io.SeekCurrent); err != nil {
			return 0, netip.AddrPort{}, fmt.Errorf("failed to skip EIH: %w", err)
		}
	}

	var sessionID [8]byte
	if _, err := io.ReadFull(reader, sessionID[:]); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read session ID: %w", err)
	}

	var packetID uint64
	if err := binary.Read(reader, binary.BigEndian, &packetID); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read packet ID: %w", err)
	}

	now := time.Now()
	if !c.checkAndUpdateReplay(sessionID, packetID, now) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read header type: %w", err)
	}

	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	timestamp := time.Unix(int64(timestampRaw), 0)

	if _, err := reader.Seek(8, io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip session ID: %w", err)
	}

	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read padding length: %w", err)
	}

	if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip padding: %w", err)
	}

	if typ != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", typ)
	}

	if err := validateTimestamp(timestamp, now); err != nil {
		return 0, netip.AddrPort{}, err
	}

	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if udpAddr, ok := netAddr.(*net.UDPAddr); ok {
		ipAddr, _ := netip.AddrFromSlice(udpAddr.IP)
		addr = netip.AddrPortFrom(ipAddr, uint16(udpAddr.Port))
	}

	n, err = reader.Read(b)
	return
}
