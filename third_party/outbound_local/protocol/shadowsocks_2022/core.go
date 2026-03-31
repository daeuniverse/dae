package shadowsocks_2022

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/daeuniverse/outbound/ciphers"
	"lukechampine.com/blake3"
)

// SS2022Core contains shared logic for Shadowsocks 2022 protocol.
// Both TCPConn and UdpConn embed this struct to avoid code duplication.
type SS2022Core struct {
	cipherConf *ciphers.CipherConf2022
	pskList    [][]byte
	uPSK       []byte

	// Shared block ciphers derived from the configured PSKs.
	// Only used for AES ciphers.
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block

	// Pre-computed identity header hash components for multi-PSK scenario.
	// For AES: BLAKE3 hash truncated to aes.BlockSize.
	// For Chacha: BLAKE3 hash truncated to 16 bytes.
	pskHash [][]byte

	// Pre-created block ciphers for identity header encryption.
	// Only used for AES ciphers.
	identityBlockCiphers []cipher.Block

	// Pre-created AEAD ciphers for identity header encryption.
	// Only used for Chacha cipher (which has no block cipher).
	identityAEADCiphers []cipher.AEAD

	// Flag indicating if multi-PSK is enabled
	hasMultiPSK bool
}

// NewSS2022Core creates a new SS2022Core with pre-computed identity components.
func NewSS2022Core(conf *ciphers.CipherConf2022, pskList [][]byte, uPSK []byte) (*SS2022Core, error) {
	if len(pskList) == 0 {
		return nil, fmt.Errorf("empty PSK list")
	}
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid cipher config: missing AEAD constructor")
	}

	var (
		blockCipherEncrypt cipher.Block
		blockCipherDecrypt cipher.Block
		err                error
	)
	if conf.NewBlockCipher != nil {
		blockCipherEncrypt, err = conf.NewBlockCipher(pskList[0])
		if err != nil {
			return nil, fmt.Errorf("failed to create encrypt block cipher: %w", err)
		}
		blockCipherDecrypt, err = conf.NewBlockCipher(uPSK)
		if err != nil {
			return nil, fmt.Errorf("failed to create decrypt block cipher: %w", err)
		}
	}

	// Determine if multi-PSK with EIH is supported.
	// Both AES (with block cipher) and Chacha (with EIH support) are supported.
	hasMultiPSK := len(pskList) > 1 && (conf.NewBlockCipher != nil || conf.IdentityHeaderBlockSize > 0)

	core := &SS2022Core{
		cipherConf:         conf,
		pskList:            pskList,
		uPSK:               uPSK,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		hasMultiPSK:        hasMultiPSK,
	}

	// Pre-compute identity header components for multi-PSK scenario (like sing-box)
	if core.hasMultiPSK {
		eihBlockSize := conf.IdentityHeaderBlockSize
		if eihBlockSize == 0 {
			eihBlockSize = aes.BlockSize // Fallback for AES ciphers
		}

		core.pskHash = make([][]byte, len(pskList))

		// For AES: pre-create block ciphers
		// For Chacha: pre-create AEAD ciphers
		if conf.NewBlockCipher != nil {
			core.identityBlockCiphers = make([]cipher.Block, len(pskList)-1)
		} else {
			core.identityAEADCiphers = make([]cipher.AEAD, len(pskList)-1)
		}

		for i, psk := range pskList {
			// Pre-compute BLAKE3 hash of each PSK (same as sing-box)
			hash := blake3.Sum512(psk)
			core.pskHash[i] = make([]byte, eihBlockSize)
			copy(core.pskHash[i], hash[:eihBlockSize])

			// Pre-create cipher for identity header encryption
			if i < len(pskList)-1 {
				if conf.NewBlockCipher != nil {
					// AES path: use block cipher
					blockCipher, err := conf.NewBlockCipher(pskList[i])
					if err != nil {
						return nil, fmt.Errorf("failed to create identity block cipher: %w", err)
					}
					core.identityBlockCiphers[i] = blockCipher
				} else {
					// Chacha path: create AEAD cipher with derived key
					// Use a fixed nonce for EIH encryption (key derivation context provides uniqueness)
					identityKey := GenerateSubKey(pskList[i], []byte("ss2022 identity header key"), Shadowsocks2022IdentityHeaderInfo)
					aeadCipher, err := conf.NewCipher(identityKey)
					if err != nil {
						PutSubKey(identityKey)
						return nil, fmt.Errorf("failed to create identity AEAD cipher: %w", err)
					}
					PutSubKey(identityKey)
					core.identityAEADCiphers[i] = aeadCipher
				}
			}
		}
	}

	return core, nil
}

// WriteIdentityHeader writes the identity header to dst for multi-PSK scenario.
// Returns the number of bytes written.
// For single PSK, this is a no-op and returns 0.
func (c *SS2022Core) WriteIdentityHeader(dst []byte, separateHeader []byte) (int, error) {
	if !c.hasMultiPSK {
		return 0, nil
	}

	eihBlockSize := c.cipherConf.IdentityHeaderBlockSize
	if eihBlockSize == 0 {
		eihBlockSize = aes.BlockSize // Fallback for AES ciphers
	}
	headerLen := (len(c.pskList) - 1) * eihBlockSize
	if len(dst) < headerLen {
		return 0, io.ErrShortBuffer
	}

	offset := 0
	if c.cipherConf.NewBlockCipher != nil {
		// AES path: use block cipher encryption
		for i := 0; i < len(c.pskList)-1; i++ {
			header := dst[offset : offset+eihBlockSize]
			// XOR pskHash with separateHeader, then encrypt (same as sing-box)
			subtle.XORBytes(header, c.pskHash[i+1], separateHeader)
			c.identityBlockCiphers[i].Encrypt(header, header)
			offset += eihBlockSize
		}
	} else {
		// Chacha path: use AEAD encryption with fixed nonce
		// Format: Seal(plaintext=eihHash||padding, nonce=zero, ad=separateHeader)
		// The EIH block is the ciphertext (which includes the tag)
		eihNonce := make([]byte, c.cipherConf.NonceLen) // All zeros
		for i := 0; i < len(c.pskList)-1; i++ {
			maxDstLen := c.identityAEADCiphers[i].NonceSize() + len(c.pskHash[i+1]) + c.identityAEADCiphers[i].Overhead()
			if offset+maxDstLen > len(dst) {
				return 0, io.ErrShortBuffer
			}

			// Encrypt pskHash with AEAD using separateHeader as associated data
			// The ciphertext includes the AEAD tag
			eihCipher := c.identityAEADCiphers[i]
			eihCiphertext := eihCipher.Seal(dst[offset:offset], eihNonce, c.pskHash[i+1], separateHeader)

			// EIH block is the full ciphertext (for 32-byte key + 16-byte tag = 48 bytes total)
			// But we only use the first 16 bytes as the EIH block (SS2022 spec)
			eihBlockLen := eihBlockSize
			if len(eihCiphertext) < eihBlockLen {
				eihBlockLen = len(eihCiphertext)
			}

			// Move to next block position
			offset += eihBlockLen
		}
	}

	return headerLen, nil
}

// IdentityHeaderLen returns the length of identity header for this connection.
func (c *SS2022Core) IdentityHeaderLen() int {
	if !c.hasMultiPSK {
		return 0
	}
	eihBlockSize := c.cipherConf.IdentityHeaderBlockSize
	if eihBlockSize == 0 {
		eihBlockSize = aes.BlockSize // Fallback for AES ciphers
	}
	return (len(c.pskList) - 1) * eihBlockSize
}

// HasMultiPSK returns true if multiple PSKs are configured.
func (c *SS2022Core) HasMultiPSK() bool {
	return c.hasMultiPSK
}

// CipherConf returns the cipher configuration.
func (c *SS2022Core) CipherConf() *ciphers.CipherConf2022 {
	return c.cipherConf
}

// UPSK returns the user PSK.
func (c *SS2022Core) UPSK() []byte {
	return c.uPSK
}

// BlockCipherEncrypt returns the shared block cipher used for encrypting the
// separate header on outbound packets.
func (c *SS2022Core) BlockCipherEncrypt() cipher.Block {
	return c.blockCipherEncrypt
}

// BlockCipherDecrypt returns the shared block cipher used for decrypting the
// separate header on inbound packets.
func (c *SS2022Core) BlockCipherDecrypt() cipher.Block {
	return c.blockCipherDecrypt
}

// PSKList returns the list of PSKs.
func (c *SS2022Core) PSKList() [][]byte {
	return c.pskList
}

// PSKHash returns pre-computed PSK hash at index i.
func (c *SS2022Core) PSKHash(i int) []byte {
	if i < 0 || i >= len(c.pskHash) {
		return nil
	}
	return c.pskHash[i]
}

// IdentityBlockCipher returns pre-created identity block cipher at index i.
func (c *SS2022Core) IdentityBlockCipher(i int) cipher.Block {
	if i < 0 || i >= len(c.identityBlockCiphers) {
		return nil
	}
	return c.identityBlockCiphers[i]
}

// IsUsingBlockCipher returns true if this cipher uses block cipher for separate header encryption.
// Returns true for AES ciphers, false for Chacha.
func (c *SS2022Core) IsUsingBlockCipher() bool {
	return c.cipherConf.NewBlockCipher != nil
}
