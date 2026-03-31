package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KDFSaltConstAuthIDEncryptionKey             = "AES Auth ID Encryption"
	KDFSaltConstAEADRespHeaderLenKey            = "AEAD Resp Header Len Key"
	KDFSaltConstAEADRespHeaderLenIV             = "AEAD Resp Header Len IV"
	KDFSaltConstAEADRespHeaderPayloadKey        = "AEAD Resp Header Key"
	KDFSaltConstAEADRespHeaderPayloadIV         = "AEAD Resp Header IV"
	KDFSaltConstVMessAEADKDF                    = "VMess AEAD KDF"
	KDFSaltConstVMessHeaderPayloadAEADKey       = "VMess Header AEAD Key"
	KDFSaltConstVMessHeaderPayloadAEADIV        = "VMess Header AEAD Nonce"
	KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length"
	KDFSaltConstVMessHeaderPayloadLengthAEADIV  = "VMess Header AEAD Nonce_Length"
)

type BytesGenerator func() []byte

// ChunkSizeEncoder is a utility class to encode size value into bytes.
type ChunkSizeEncoder interface {
	SizeBytes() int32
	Encode(uint16, []byte) []byte
}

// ChunkSizeDecoder is a utility class to decode size value from bytes.
type ChunkSizeDecoder interface {
	SizeBytes() int32
	Decode([]byte) (uint16, error)
}

type Cipher string

const (
	CipherC20P1305  Cipher = "chacha20-poly1305"
	CipherAES128GCM Cipher = "aes-128-gcm"
)

const (
	OptionChunkStream        = 1
	OptionChunkLengthMasking = 4
	OptionGlobalPadding      = 8
)

func ContainOption(options byte, option byte) bool {
	return options&option == option
}

func ParseCipherFromSecurity(security byte) (Cipher, error) {
	switch security {
	case 4:
		return CipherC20P1305, nil
	case 3:
		return CipherAES128GCM, nil
	default:
		return "", fmt.Errorf("unexpected security: %v", security)
	}
}

func (c Cipher) ToSecurity() byte {
	switch c {
	case CipherC20P1305:
		return 4
	case CipherAES128GCM:
		return 3
	default:
		//log.Warn("unexpected cipher: %v", c)
		return CipherAES128GCM.ToSecurity()
	}
}

var (
	NewCipherMapper = map[Cipher]func(key []byte) (cipher.AEAD, error){
		CipherC20P1305:  NewC20P1305,
		CipherAES128GCM: NewAesGcm,
	}
)

type hMacCreator struct {
	parent *hMacCreator
	value  []byte
}

func (h *hMacCreator) Create() hash.Hash {
	if h.parent == nil {
		return hmac.New(sha256.New, h.value)
	}
	return hmac.New(h.parent.Create, h.value)
}

func KDF(key []byte, path ...[]byte) []byte {
	hmacCreator := &hMacCreator{value: []byte(KDFSaltConstVMessAEADKDF)}
	for _, v := range path {
		hmacCreator = &hMacCreator{value: []byte(v), parent: hmacCreator}
	}
	hmacf := hmacCreator.Create()
	hmacf.Write(key)
	return hmacf.Sum(nil)
}

func PutEAuthID(dst []byte, cmdKey []byte) []byte {
	binary.BigEndian.PutUint64(dst[:8], uint64(time.Now().Unix()))
	_, _ = fastrand.Read(dst[8:12])
	binary.BigEndian.PutUint32(dst[12:], crc32.ChecksumIEEE(dst[:12]))
	blk, _ := aes.NewCipher(KDF(cmdKey, []byte(KDFSaltConstAuthIDEncryptionKey))[:16])
	blk.Encrypt(dst[:16], dst[:16])
	return dst[:16]
}

func AuthEAuthID(blk cipher.Block, eAuthID []byte, doubleCuckoo *ReplayFilter, startTimestamp int64) error {
	buf := pool.Get(16)
	defer pool.Put(buf)
	blk.Decrypt(buf, eAuthID)
	if crc32.ChecksumIEEE(buf[:12]) != binary.BigEndian.Uint32(buf[12:16]) {
		return fmt.Errorf("incorrect checksum")
	}

	t := int64(binary.BigEndian.Uint64(buf[:8]))
	now := time.Now().Unix()
	var threshold int64 = 120
	if now-startTimestamp <= 40 {
		threshold = 3 * (now - startTimestamp)
	}
	if common.Abs64(now-t) > threshold {
		return fmt.Errorf("%w: time exceed", protocol.ErrFailAuth)
	}

	if !doubleCuckoo.Check(eAuthID) {
		return fmt.Errorf("%w: repeated EAuthID", protocol.ErrReplayAttack)
	}

	return nil
}

func ReqInstructionDataFromPool(metadata Metadata) []byte {
	P := fastrand.Intn(1 << 4)
	// 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + metadata.AddrLen() + P + 4
	buf := pool.Get(metadata.AddrLen() + P + 45)
	buf[0] = 1               // version
	_, _ = fastrand.Read(buf[1:34]) // random IV(16), Key(16), V(1)
	// https://github.com/v2fly/v2ray-core/blob/a66bb28aee661caa191b5746ba4915eb99e12c59/proxy/vmess/outbound/outbound.go#L112
	//buf[34] = OptionChunkStream | OptionChunkLengthMasking | OptionGlobalPadding
	buf[34] = OptionChunkStream | OptionChunkLengthMasking | OptionGlobalPadding
	// https://github.com/v2fly/v2ray-core/blob/054e6679830885c94cc37d27ab2aa96b5b37e019/common/protocol/headers.pb.go#L37
	buf[35] = byte(P)<<4 | Cipher(metadata.Cipher).ToSecurity()
	buf[36] = 0                                           // Reserved
	buf[37] = NetworkToByte(metadata.Network)             // TCP/UDP
	binary.BigEndian.PutUint16(buf[38:40], metadata.Port) // Port
	buf[40] = MetadataTypeToByte(metadata.Type)           // Address Type
	metadata.PutAddr(buf[41:])                            // Address
	n := len(buf) - 4
	h := fnv.New32a()
	h.Write(buf[:n])
	binary.BigEndian.PutUint32(buf[n:], h.Sum32()) // FNV1a
	return buf
}

func EncryptReqHeaderFromPool(instruction []byte, cmdKey []byte) ([]byte, error) {
	buf := pool.Get(58 + len(instruction)) // EAuthID(16) + length(2) + tag(16) + nonce(8) + len(instruction) + tag(16)
	eAuthID := PutEAuthID(buf, cmdKey)
	connectionNonce := buf[34:42] // 16+2+16
	_, _ = fastrand.Read(connectionNonce)

	gcm, err := NewAesGcm(KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), eAuthID, connectionNonce)[:16])
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	binary.BigEndian.PutUint16(buf[16:18], uint16(len(instruction)))
	gcm.Seal(buf[16:16], KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), eAuthID, connectionNonce)[:12], buf[16:18], eAuthID)

	gcm, err = NewAesGcm(KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADKey), eAuthID, connectionNonce)[:16])
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	copy(buf[42:], instruction) // 16+2+16+8
	gcm.Seal(buf[42:42], KDF(cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADIV), eAuthID, connectionNonce)[:12], instruction, eAuthID)

	return buf, nil
}

func RespHeaderFromPool(V byte) []byte {
	buf := pool.GetZero(4) // V(1)+Option(1)+Cmd(1)+InstructionLen(1)
	buf[0] = V
	// no instruction data
	return buf
}

func NewAesGcm(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// GenerateChacha20Poly1305Key generates a 32-byte key from a given 16-byte array.
func GenerateChacha20Poly1305KeyFromPool(b []byte) []byte {
	key := pool.Get(32)
	t := md5.Sum(b)
	copy(key, t[:])
	t = md5.Sum(key[:16])
	copy(key[16:], t[:])
	return key
}

func NewC20P1305(key []byte) (cipher.AEAD, error) {
	if len(key) == 16 {
		key = GenerateChacha20Poly1305KeyFromPool(key)
		defer pool.Put(key)
	}
	return chacha20poly1305.New(key)
}
