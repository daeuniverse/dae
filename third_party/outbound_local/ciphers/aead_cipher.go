package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"io"

	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type CipherConf struct {
	KeyLen    int
	SaltLen   int
	NonceLen  int
	TagLen    int
	NewCipher func(key []byte) (cipher.AEAD, error)
}

const (
	MaxNonceSize = 12
	ATypeIpv4    = 1
	ATypeDomain  = 3
	ATypeIpv6    = 4
)

var (
	AeadCiphersConf = map[string]*CipherConf{
		"chacha20-ietf-poly1305": {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: chacha20poly1305.New},
		"chacha20-poly1305":      {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: chacha20poly1305.New},
		"aes-256-gcm":            {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: NewGcm},
		"aes-128-gcm":            {KeyLen: 16, SaltLen: 16, NonceLen: 12, TagLen: 16, NewCipher: NewGcm},
	}
	ZeroNonce         [MaxNonceSize]byte
	JuicityReusedInfo = []byte("juicity-reused-info")
)

func NewGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Verify is used for legacy compatibility
func (conf *CipherConf) Verify(buf []byte, masterKey []byte, salt []byte, cipherText []byte, subKey *[]byte) ([]byte, bool) {
	var shadowsocksReusedInfo = []byte("ss-subkey")
	var sk []byte
	if subKey != nil && len(*subKey) == conf.KeyLen {
		sk = *subKey
	} else {
		sk = pool.Get(conf.KeyLen)
		defer pool.Put(sk)
		kdf := hkdf.New(
			sha1.New,
			masterKey,
			salt,
			shadowsocksReusedInfo,
		)
		_, _ = io.ReadFull(kdf, sk)
		if subKey != nil && cap(*subKey) >= conf.KeyLen {
			*subKey = (*subKey)[:conf.KeyLen]
			copy(*subKey, sk)
		}
	}

	ciph, _ := conf.NewCipher(sk)

	if _, err := ciph.Open(buf[:0], ZeroNonce[:conf.NonceLen], cipherText, nil); err != nil {
		return nil, false
	}
	return buf[:len(cipherText)-ciph.Overhead()], true
}
