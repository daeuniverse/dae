package shadowsocks

import (
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
)

// BenchmarkNonceIncrementFunction benchmarks current function call approach
func BenchmarkNonceIncrementFunction(b *testing.B) {
	nonce := make([]byte, 12) // AES-GCM nonce size

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate current approach: function call
		incrementNonce(nonce)
	}
}

// BenchmarkNonceIncrementInline benchmarks inlined approach
func BenchmarkNonceIncrementInline(b *testing.B) {
	nonce := make([]byte, 12)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Inlined nonce increment
		for j := 0; j < len(nonce); j++ {
			nonce[j]++
			if nonce[j] != 0 {
				break
			}
		}
	}
}

// incrementNonce is the current function-based approach
func incrementNonce(nonce []byte) {
	for i := 0; i < len(nonce); i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// BenchmarkSealWithFunctionNonce benchmarks seal with function-based nonce increment
func BenchmarkSealWithFunctionNonce(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, 32)
	ciph, _ := conf.NewCipher(key)

	plaintext := make([]byte, 16384) // 16KB
	ciphertext := make([]byte, len(plaintext)+16)
	nonce := make([]byte, conf.NonceLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Seal first chunk (length)
		_ = ciph.Seal(ciphertext[:0], nonce, []byte{0x40, 0x00}, nil)
		incrementNonce(nonce)

		// Seal second chunk (payload)
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
		incrementNonce(nonce)
	}
}

// BenchmarkSealWithInlineNonce benchmarks seal with inlined nonce increment
func BenchmarkSealWithInlineNonce(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, 32)
	ciph, _ := conf.NewCipher(key)

	plaintext := make([]byte, 16384)
	ciphertext := make([]byte, len(plaintext)+16)
	nonce := make([]byte, conf.NonceLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Seal first chunk with inlined increment
		_ = ciph.Seal(ciphertext[:0], nonce, []byte{0x40, 0x00}, nil)
		for j := 0; j < len(nonce); j++ {
			nonce[j]++
			if nonce[j] != 0 {
				break
			}
		}

		// Seal second chunk with inlined increment
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
		for j := 0; j < len(nonce); j++ {
			nonce[j]++
			if nonce[j] != 0 {
				break
			}
		}
	}
}

// BenchmarkSealMultipleChunksFunction benchmarks multiple chunks with function calls
func BenchmarkSealMultipleChunksFunction(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, 32)
	ciph, _ := conf.NewCipher(key)

	// Simulate 4 chunks (64KB total)
	plaintext := make([]byte, 16384)
	ciphertext := make([]byte, len(plaintext)+16)
	nonce := make([]byte, conf.NonceLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for chunk := 0; chunk < 4; chunk++ {
			// Seal length
			_ = ciph.Seal(ciphertext[:0], nonce, []byte{0x40, 0x00}, nil)
			incrementNonce(nonce)

			// Seal payload
			_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
			incrementNonce(nonce)
		}
	}
}

// BenchmarkSealMultipleChunksInline benchmarks multiple chunks with inline increment
func BenchmarkSealMultipleChunksInline(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, 32)
	ciph, _ := conf.NewCipher(key)

	plaintext := make([]byte, 16384)
	ciphertext := make([]byte, len(plaintext)+16)
	nonce := make([]byte, conf.NonceLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for chunk := 0; chunk < 4; chunk++ {
			// Seal length with inline increment
			_ = ciph.Seal(ciphertext[:0], nonce, []byte{0x40, 0x00}, nil)
			for j := 0; j < len(nonce); j++ {
				nonce[j]++
				if nonce[j] != 0 {
					break
				}
			}

			// Seal payload with inline increment
			_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
			for j := 0; j < len(nonce); j++ {
				nonce[j]++
				if nonce[j] != 0 {
					break
				}
			}
		}
	}
}
