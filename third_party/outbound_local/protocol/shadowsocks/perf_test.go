/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package shadowsocks

import (
	"crypto/sha1"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

// BenchmarkSubKeyPool benchmarks subKey allocation with sync.Pool
func BenchmarkSubKeyPool_Get(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subKey := getSubKey(32)
		putSubKey(subKey)
	}
}

// BenchmarkSubKeyAlloc benchmarks subKey allocation without sync.Pool
func BenchmarkSubKeyAlloc(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subKey := make([]byte, 32)
		_ = subKey[0] // Prevent compiler optimization
	}
}

// BenchmarkHKDF benchmarks HKDF key derivation
func BenchmarkHKDF(b *testing.B) {
	masterKey := make([]byte, 32)
	salt := make([]byte, 32)
	subKey := make([]byte, 32)
	reusedInfo := []byte("ss-subkey")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kdf := hkdf.New(sha1.New, masterKey, salt, reusedInfo)
		_, _ = io.ReadFull(kdf, subKey)
	}
}

// BenchmarkHKDFWithPool benchmarks HKDF with pooled subKey
func BenchmarkHKDFWithPool(b *testing.B) {
	masterKey := make([]byte, 32)
	salt := make([]byte, 32)
	reusedInfo := []byte("ss-subkey")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subKey := getSubKey(32)
		kdf := hkdf.New(sha1.New, masterKey, salt, reusedInfo)
		_, _ = io.ReadFull(kdf, subKey)
		putSubKey(subKey)
	}
}

// BenchmarkAEADEncrypt benchmarks AEAD encryption
func BenchmarkAEADEncrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)
	plaintext := make([]byte, 1024)
	ciphertext := make([]byte, len(plaintext)+conf.TagLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// BenchmarkAEADDecrypt benchmarks AEAD decryption
func BenchmarkAEADDecrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)
	plaintext := make([]byte, 1024)
	ciphertext := make([]byte, len(plaintext)+conf.TagLen)
	_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)

	plaintextOut := make([]byte, len(plaintext))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ciph.Open(plaintextOut[:0], nonce, ciphertext, nil)
	}
}

// BenchmarkChaCha20Poly1305Encrypt benchmarks ChaCha20-Poly1305 encryption
func BenchmarkChaCha20Poly1305Encrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["chacha20-ietf-poly1305"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)
	plaintext := make([]byte, 1024)
	ciphertext := make([]byte, len(plaintext)+conf.TagLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)
	}
}

// BenchmarkChaCha20Poly1305Decrypt benchmarks ChaCha20-Poly1305 decryption
func BenchmarkChaCha20Poly1305Decrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["chacha20-ietf-poly1305"]
	key := make([]byte, conf.KeyLen)
	ciph, _ := conf.NewCipher(key)
	nonce := make([]byte, conf.NonceLen)
	plaintext := make([]byte, 1024)
	ciphertext := make([]byte, len(plaintext)+conf.TagLen)
	_ = ciph.Seal(ciphertext[:0], nonce, plaintext, nil)

	plaintextOut := make([]byte, len(plaintext))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ciph.Open(plaintextOut[:0], nonce, ciphertext, nil)
	}
}

// BenchmarkPoolGetPut benchmarks pool.Get/Put operations
func BenchmarkPoolGetPut(b *testing.B) {
	size := 1024
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get(size)
		pool.Put(buf)
	}
}

// BenchmarkPoolGetPutLarge benchmarks pool.Get/Put for large buffers
func BenchmarkPoolGetPutLarge(b *testing.B) {
	size := 16 * 1024 // 16KB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get(size)
		pool.Put(buf)
	}
}

// BenchmarkEncryptUDPFromPool benchmarks UDP encryption with pool
func BenchmarkEncryptUDPFromPool(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		shadowBytes.Put()
	}
}

// BenchmarkDecryptUDPFromPool benchmarks UDP decryption with pool
func BenchmarkDecryptUDPFromPool(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	defer shadowBytes.Put()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ := DecryptUDPFromPool(key, shadowBytes, reusedInfo)
		buf.Put()
	}
}

// BenchmarkCipherCreation benchmarks creating a new cipher
func BenchmarkCipherCreation_AES256GCM(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := make([]byte, conf.KeyLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = conf.NewCipher(key)
	}
}

// BenchmarkCipherCreation_ChaCha20 benchmarks creating a new ChaCha20 cipher
func BenchmarkCipherCreation_ChaCha20(b *testing.B) {
	conf := ciphers.AeadCiphersConf["chacha20-ietf-poly1305"]
	key := make([]byte, conf.KeyLen)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = conf.NewCipher(key)
	}
}

// BenchmarkFullEncryptionPipeline benchmarks the full encryption pipeline
func BenchmarkFullEncryptionPipeline(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Generate salt (simulated)
		salt := make([]byte, conf.SaltLen)

		// Encrypt
		shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)

		// Decrypt
		buf, _ := DecryptUDPFromPool(key, shadowBytes, reusedInfo)

		shadowBytes.Put()
		buf.Put()
	}
}

// BenchmarkEncryptionSizeComparison compares different payload sizes
func BenchmarkEncryption_64B(b *testing.B)  { benchmarkEncryptSize(b, 64) }
func BenchmarkEncryption_512B(b *testing.B) { benchmarkEncryptSize(b, 512) }
func BenchmarkEncryption_1KB(b *testing.B)  { benchmarkEncryptSize(b, 1024) }
func BenchmarkEncryption_4KB(b *testing.B)  { benchmarkEncryptSize(b, 4096) }
func BenchmarkEncryption_16KB(b *testing.B) { benchmarkEncryptSize(b, 16384) }

func benchmarkEncryptSize(b *testing.B, size int) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, size)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		shadowBytes.Put()
	}
}
