package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
)

// Benchmark to find optimal chunk size
func BenchmarkChunkSize_1KB(b *testing.B)  { benchmarkChunkSize(b, 1024) }
func BenchmarkChunkSize_2KB(b *testing.B)  { benchmarkChunkSize(b, 2048) }
func BenchmarkChunkSize_4KB(b *testing.B)  { benchmarkChunkSize(b, 4096) }
func BenchmarkChunkSize_8KB(b *testing.B)  { benchmarkChunkSize(b, 8192) }
func BenchmarkChunkSize_16KB(b *testing.B) { benchmarkChunkSize(b, 16384) }
func BenchmarkChunkSize_32KB(b *testing.B) { benchmarkChunkSize(b, 32768) }
func BenchmarkChunkSize_64KB(b *testing.B) { benchmarkChunkSize(b, 65536) }

func benchmarkChunkSize(b *testing.B, chunkSize int) {
	// Simulate seal operation for different chunk sizes
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)

	plaintext := make([]byte, chunkSize)
	ciphertext := make([]byte, len(plaintext)+conf.TagLen)

	b.SetBytes(int64(chunkSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// Compare AES vs ChaCha20 for different data sizes
func BenchmarkAES_64B(b *testing.B)   { benchmarkCipher(b, "aes-256-gcm", 64) }
func BenchmarkAES_512B(b *testing.B)  { benchmarkCipher(b, "aes-256-gcm", 512) }
func BenchmarkAES_1KB(b *testing.B)   { benchmarkCipher(b, "aes-256-gcm", 1024) }
func BenchmarkAES_4KB(b *testing.B)   { benchmarkCipher(b, "aes-256-gcm", 4096) }
func BenchmarkAES_16KB(b *testing.B)  { benchmarkCipher(b, "aes-256-gcm", 16384) }
func BenchmarkAES_64KB(b *testing.B)  { benchmarkCipher(b, "aes-256-gcm", 65536) }
func BenchmarkAES_128KB(b *testing.B) { benchmarkCipher(b, "aes-256-gcm", 131072) }

func BenchmarkChaCha20_64B(b *testing.B)   { benchmarkCipher(b, "chacha20-ietf-poly1305", 64) }
func BenchmarkChaCha20_512B(b *testing.B)  { benchmarkCipher(b, "chacha20-ietf-poly1305", 512) }
func BenchmarkChaCha20_1KB(b *testing.B)   { benchmarkCipher(b, "chacha20-ietf-poly1305", 1024) }
func BenchmarkChaCha20_4KB(b *testing.B)   { benchmarkCipher(b, "chacha20-ietf-poly1305", 4096) }
func BenchmarkChaCha20_16KB(b *testing.B)  { benchmarkCipher(b, "chacha20-ietf-poly1305", 16384) }
func BenchmarkChaCha20_64KB(b *testing.B)  { benchmarkCipher(b, "chacha20-ietf-poly1305", 65536) }
func BenchmarkChaCha20_128KB(b *testing.B) { benchmarkCipher(b, "chacha20-ietf-poly1305", 131072) }

func benchmarkCipher(b *testing.B, cipherName string, size int) {
	conf := ciphers.AeadCiphersConf[cipherName]
	key := make([]byte, conf.KeyLen)
	_, err := rand.Read(key)
	if err != nil {
		b.Fatalf("rand.Read(key) failed: %v", err)
	}

	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)
	plaintext := make([]byte, size)
	ciphertext := make([]byte, len(plaintext)+conf.TagLen)

	b.SetBytes(int64(size))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// Benchmark memory allocation patterns
func BenchmarkPoolAlloc_Reuse(b *testing.B) {
	size := 16384
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, size)
		_ = buf[0] // Prevent optimization
		// No pool - each allocation is new
	}
}

func BenchmarkPoolAlloc_New(b *testing.B) {
	size := 16384
	buf := make([]byte, size)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Reuse same buffer
		_ = buf[0]
	}
}

// Benchmark nonce increment performance
func BenchmarkNonceIncrement(b *testing.B) {
	nonce := make([]byte, 12)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Simulate BytesIncLittleEndian
		for j := 0; j < len(nonce); j++ {
			nonce[j]++
			if nonce[j] != 0 {
				break
			}
		}
	}
}

// Benchmark chunk overhead
func BenchmarkChunkOverhead_Single(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)

	// 16KB in single chunk
	plaintext := make([]byte, 16384)
	chunk := make([]byte, 2+conf.TagLen+len(plaintext)+conf.TagLen)

	b.SetBytes(16384)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		offset := 0
		// Single chunk: length(2+tag) + data(tag)
		_ = ciph.Seal(chunk[offset:offset], nonce, []byte{0x40, 0x00}, nil)
		offset += 2 + conf.TagLen

		_ = ciph.Seal(chunk[offset:offset], nonce, plaintext, nil)
	}
}

func BenchmarkChunkOverhead_Multiple(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)

	// 16KB split into 1KB chunks
	chunkSize := 1024
	numChunks := 16
	plaintext := make([]byte, chunkSize)
	chunk := make([]byte, (2+conf.TagLen+chunkSize+conf.TagLen)*numChunks)

	b.SetBytes(int64(chunkSize * numChunks))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		offset := 0
		for j := 0; j < numChunks; j++ {
			// Length chunk
			_ = ciph.Seal(chunk[offset:offset], nonce, []byte{0x04, 0x00}, nil)
			offset += 2 + conf.TagLen

			// Data chunk
			_ = ciph.Seal(chunk[offset:offset], nonce, plaintext, nil)
			offset += chunkSize + conf.TagLen
		}
	}
}

// Benchmark copy overhead
func BenchmarkCopyOverhead_Single(b *testing.B) {
	src := make([]byte, 16384)
	dst := make([]byte, 16384)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(dst, src)
	}
}

func BenchmarkCopyOverhead_Multiple(b *testing.B) {
	src := make([]byte, 1024)
	dst := make([]byte, 16384)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		offset := 0
		for j := 0; j < 16; j++ {
			copy(dst[offset:], src)
			offset += len(src)
		}
	}
}

// Benchmark throughput for different patterns
func BenchmarkThroughput_Stream(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)

	// Simulate 1MB stream
	totalSize := 1024 * 1024
	chunkSize := 16384

	plaintext := make([]byte, chunkSize)
	ciphertext := make([]byte, chunkSize+conf.TagLen)

	b.SetBytes(int64(totalSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for j := 0; j < totalSize/chunkSize; j++ {
			_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
		}
	}
}

func BenchmarkThroughput_Interactive(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)

	// Simulate interactive traffic: many small packets
	packetSize := 64

	plaintext := make([]byte, packetSize)
	ciphertext := make([]byte, packetSize+conf.TagLen)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// Test to verify correctness
func TestChunkSizeCorrectness(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("rand.Read(key) failed: %v", err)
	}

	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)

	sizes := []int{1024, 2048, 4096, 8192, 16384, 32768, 65536}

	for _, size := range sizes {
		plaintext := make([]byte, size)
		_, err = rand.Read(plaintext)
		if err != nil {
			t.Fatalf("rand.Read(plaintext) failed: %v", err)
		}

		ciphertext := make([]byte, len(plaintext)+conf.TagLen)
		decrypted := make([]byte, len(plaintext))

		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
		_, err = ciph.Open(decrypted[:0], nonce, ciphertext, nil)

		if err != nil {
			t.Errorf("Failed for size %d: %v", size, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Mismatch for size %d", size)
		}
	}
}
