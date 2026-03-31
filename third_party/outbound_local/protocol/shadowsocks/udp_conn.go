package shadowsocks

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"golang.org/x/crypto/hkdf"
)

// [LEGACY] Global switch for UDP cipher cache optimization (kept for reference):
// This optimization is now always enabled for 5x+ performance improvement.
// var enableUDPCipherCache int32 = 1 // enabled by default
//
// func EnableUDPCipherCache(enable bool) {
//     if enable {
//         atomic.StoreInt32(&enableUDPCipherCache, 1)
//     } else {
//         atomic.StoreInt32(&enableUDPCipherCache, 0)
//     }
// }
//
// func isUDPCipherCacheEnabled() bool {
//     return atomic.LoadInt32(&enableUDPCipherCache) == 1
// }

type UdpConn struct {
	netproxy.PacketConn

	proxyAddress string

	metadata   protocol.Metadata
	cipherConf *ciphers.CipherConf
	masterKey  []byte
	bloom      *disk_bloom.FilterGroup
	sg         SaltGenerator

	tgtAddr string
}

func NewUdpConn(conn netproxy.PacketConn, proxyAddress string, metadata protocol.Metadata, masterKey []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	conf := ciphers.AeadCiphersConf[metadata.Cipher]
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	sg, err := NewRandomSaltGenerator(conf.SaltLen)
	if err != nil {
		return nil, err
	}
	c := &UdpConn{
		PacketConn:   conn,
		proxyAddress: proxyAddress,
		metadata:     metadata,
		cipherConf:   conf,
		masterKey:    key,
		bloom:        bloom,
		sg:           sg,
		tgtAddr:      net.JoinHostPort(metadata.Hostname, strconv.Itoa(int(metadata.Port))),
	}
	return c, nil
}

func (c *UdpConn) Close() error {
	return c.PacketConn.Close()
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.tgtAddr)
}

// maxMetadataLen returns the maximum possible metadata length for pre-allocation.
// IPv6 (1 + 16 + 2) = 19 bytes is the maximum.

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	metadata := Metadata{
		Metadata: c.metadata,
	}
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata.Hostname = mdata.Hostname
	metadata.Port = mdata.Port
	metadata.Type = mdata.Type

	// Pre-calculate total size to allocate once
	// Layout: [salt][metadata][payload][tag]
	prefixLen := metadataLen(metadata.Type)
	totalLen := c.cipherConf.SaltLen + prefixLen + len(b) + c.cipherConf.TagLen

	// Single allocation for the entire packet
	buf := pool.Get(totalLen)
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()

	// Write salt at the beginning
	salt := c.sg.Get()
	copy(buf, salt)
	pool.Put(salt)

	// Write metadata inline after salt
	offset := c.cipherConf.SaltLen
	offset += writeMetadataInline(buf[offset:], &metadata)

	// Write payload
	copy(buf[offset:], b)
	payloadEnd := offset + len(b)

	// Encrypt in-place
	key := &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}

	toWrite, err := encryptUDPInPlace(key, buf, payloadEnd, ShadowsocksReusedInfo)
	if err != nil {
		return 0, err
	}
	defer pool.Put(toWrite)

	if c.bloom != nil {
		c.bloom.ExistOrAdd(toWrite[:c.cipherConf.SaltLen])
	}
	return c.PacketConn.WriteTo(toWrite, c.proxyAddress)
}

// metadataLen returns the length of metadata for a given type.
func metadataLen(typ protocol.MetadataType) int {
	switch typ {
	case protocol.MetadataTypeIPv4:
		return 1 + 4 + 2 // type + ipv4 + port
	case protocol.MetadataTypeIPv6:
		return 1 + 16 + 2 // type + ipv6 + port
	case protocol.MetadataTypeDomain:
		return 1 + 1 + 255 + 2 // type + len + max domain + port (will be truncated)
	case protocol.MetadataTypeMsg:
		return 1 + 1 + 4 // type + cmd + len
	default:
		return 19 // max possible
	}
}

// writeMetadataInline writes metadata directly to the buffer without extra allocation.
func writeMetadataInline(buf []byte, meta *Metadata) int {
	buf[0] = MetadataTypeToByte(meta.Type)
	switch meta.Type {
	case protocol.MetadataTypeIPv4:
		ip := net.ParseIP(meta.Hostname)
		if ip != nil {
			copy(buf[1:], ip.To4()[:4])
		}
		binary.BigEndian.PutUint16(buf[5:], meta.Port)
		return 7
	case protocol.MetadataTypeIPv6:
		ip := net.ParseIP(meta.Hostname)
		if ip != nil {
			copy(buf[1:], ip[:16])
		}
		binary.BigEndian.PutUint16(buf[17:], meta.Port)
		return 19
	case protocol.MetadataTypeDomain:
		hostname := []byte(meta.Hostname)
		lenDN := len(hostname)
		if lenDN > 255 {
			lenDN = 255
		}
		buf[1] = uint8(lenDN)
		copy(buf[2:], hostname[:lenDN])
		binary.BigEndian.PutUint16(buf[2+lenDN:], meta.Port)
		return 4 + lenDN
	case protocol.MetadataTypeMsg:
		buf[1] = uint8(meta.Cmd)
		binary.BigEndian.PutUint32(buf[2:], meta.LenMsgBody)
		return 6
	default:
		return 0
	}
}

// encryptUDPInPlace encrypts the buffer in place, returning the final packet.
func encryptUDPInPlace(key *Key, buf []byte, payloadLen int, reusedInfo []byte) (pool.PB, error) {
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)

	kdf := hkdf.New(sha1.New, key.MasterKey, buf[:key.CipherConf.SaltLen], reusedInfo)
	if _, err := io.ReadFull(kdf, subKey); err != nil {
		return nil, err
	}

	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return nil, err
	}

	// Seal in-place: we need space for tag at the end
	// Input is buf[saltLen:payloadLen], output goes to buf[saltLen:payloadLen+tagLen]
	encrypted := ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], 
		ciphers.ZeroNonce[:key.CipherConf.NonceLen], 
		buf[key.CipherConf.SaltLen:payloadLen], 
		nil)
	
	return buf[:key.CipherConf.SaltLen+len(encrypted)], nil
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	enc := pool.Get(len(b) + c.cipherConf.SaltLen)
	defer pool.Put(enc)
	n, addr, err = c.PacketConn.ReadFrom(enc)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	key := &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}

	n, err = DecryptUDP(b, key, enc[:n], ShadowsocksReusedInfo)

	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if c.bloom != nil {
		if exist := c.bloom.ExistOrAdd(enc[:c.cipherConf.SaltLen]); exist {
			err = protocol.ErrReplayAttack
			return
		}
	}
	// parse sAddr from metadata
	sizeMetadata, err := BytesSizeForMetadata(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	mdata, err := NewMetadata(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	switch mdata.Type {
	case protocol.MetadataTypeIPv4, protocol.MetadataTypeIPv6:
		ip, err := netip.ParseAddr(mdata.Hostname)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		addr = netip.AddrPortFrom(ip, mdata.Port)
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", mdata.Type)
	}
	copy(b, b[sizeMetadata:])
	n -= sizeMetadata
	return n, addr, nil
}
