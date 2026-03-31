package trojanc

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
)

// BenchmarkPasswordHashBaseline tests the current password hash implementation
func BenchmarkPasswordHashBaseline(b *testing.B) {
	password := "test-password-12345"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash := sha256.New224()
		hash.Write([]byte(password))
		var result [56]byte
		hex.Encode(result[:], hash.Sum(nil))
		_ = result
	}
}

// BenchmarkPasswordHashCached tests using cached password hash
func BenchmarkPasswordHashCached(b *testing.B) {
	password := "test-password-12345"
	cache := make(map[string][56]byte)

	// Pre-compute
	hash := sha256.New224()
	hash.Write([]byte(password))
	var result [56]byte
	hex.Encode(result[:], hash.Sum(nil))
	cache[password] = result

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if cached, ok := cache[password]; ok {
			_ = cached
		}
	}
}

// BenchmarkPasswordHashSyncMap tests using sync.Map for caching
func BenchmarkPasswordHashSyncMap(b *testing.B) {
	password := "test-password-12345"
	var cache sync.Map

	// 预计算
	hash := sha256.New224()
	hash.Write([]byte(password))
	var result [56]byte
	hex.Encode(result[:], hash.Sum(nil))
	cache.Store(password, result)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if cached, ok := cache.Load(password); ok {
			_ = cached.([56]byte)
		}
	}
}

// BenchmarkNewConnComparison compares NewConn performance before and after optimization
func BenchmarkNewConnComparison(b *testing.B) {
	password := "test-password-12345"

	b.Run("Original", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 原始实现：每次都重新计算
			hash := sha256.New224()
			hash.Write([]byte(password))
			var pass [56]byte
			hex.Encode(pass[:], hash.Sum(nil))
			_ = pass
		}
	})

	b.Run("OptimizedCached", func(b *testing.B) {
		// 预热缓存
		_ = getPasswordHash(password)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 优化后：使用缓存
			pass := getPasswordHash(password)
			_ = pass
		}
	})
}

// BenchmarkMultiplePasswords tests scenarios with multiple different passwords
func BenchmarkMultiplePasswords(b *testing.B) {
	passwords := []string{
		"password1",
		"password2",
		"password3",
		"password4",
		"password5",
	}

	b.Run("Baseline", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			password := passwords[i%len(passwords)]
			hash := sha256.New224()
			hash.Write([]byte(password))
			var result [56]byte
			hex.Encode(result[:], hash.Sum(nil))
			_ = result
		}
	})

	b.Run("SyncMap", func(b *testing.B) {
		var cache sync.Map

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			password := passwords[i%len(passwords)]

			if cached, ok := cache.Load(password); ok {
				_ = cached.([56]byte)
				continue
			}

			hash := sha256.New224()
			hash.Write([]byte(password))
			var result [56]byte
			hex.Encode(result[:], hash.Sum(nil))
			cache.Store(password, result)
		}
	})
}
