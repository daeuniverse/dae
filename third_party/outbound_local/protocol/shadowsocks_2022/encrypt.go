package shadowsocks_2022

import (
	"crypto/cipher"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"lukechampine.com/blake3"
)

var (
	Shadowsocks2022ReusedInfo         = "shadowsocks 2022 session subkey"
	Shadowsocks2022IdentityHeaderInfo = "shadowsocks 2022 identity subkey"
)

// subKeyPool reuses subKey buffers to reduce allocations in the hot path.
// SS2022 uses either 16-byte (AES-128) or 32-byte (AES-256) keys.
var subKeyPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32) // max key size
	},
}

// keyMaterialPool reuses key material buffers.
// Key material = psk (max 32) + salt (max 32) = max 64 bytes.
var keyMaterialPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 64)
	},
}

func GenerateSubKey(psk []byte, salt []byte, context string) (subKey []byte) {
	// Get buffer from pool, trim to actual key length
	subKey = subKeyPool.Get().([]byte)[:len(psk)]

	// Get key material buffer from pool
	keyMaterial := keyMaterialPool.Get().([]byte)
	keyMaterial = keyMaterial[:0]
	keyMaterial = append(keyMaterial, psk...)
	keyMaterial = append(keyMaterial, salt...)

	blake3.DeriveKey(subKey, context, keyMaterial)

	// Return key material buffer to pool
	// nolint:staticcheck
	keyMaterialPool.Put(keyMaterial)

	return
}

// PutSubKey returns a subKey buffer to the pool.
// Callers should use this after they're done with the subKey.
func PutSubKey(subKey []byte) {
	if subKey != nil && cap(subKey) >= 16 && cap(subKey) <= 32 {
		// nolint:staticcheck
		subKeyPool.Put(subKey[:32])
	}
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher cipher.AEAD, err error) {
	subKey := GenerateSubKey(masterKey, salt, Shadowsocks2022ReusedInfo)
	defer PutSubKey(subKey)
	return cipherConf.NewCipher(subKey)
}
