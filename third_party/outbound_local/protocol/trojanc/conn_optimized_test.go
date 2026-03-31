package trojanc

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

// BenchmarkNewConnOptimized tests optimized NewConn performance
func BenchmarkNewConnOptimized(b *testing.B) {
	// Mock network connection (nil is fine in benchmarks as we don't actually read/write)
	var mockConn netproxy.Conn

	metadata := Metadata{
		Metadata: protocol.Metadata{
			Hostname: "example.com",
			Port:     443,
		},
		Network: "tcp",
	}
	password := "test-password-12345"

	// 预热缓存
	_, _ = NewConn(mockConn, metadata, password)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = NewConn(mockConn, metadata, password)
	}
}

// BenchmarkNewConnMultiplePasswords tests multiple password scenarios
func BenchmarkNewConnMultiplePasswords(b *testing.B) {
	var mockConn netproxy.Conn

	passwords := []string{
		"password1",
		"password2",
		"password3",
		"password4",
		"password5",
	}

	metadata := Metadata{
		Metadata: protocol.Metadata{
			Hostname: "example.com",
			Port:     443,
		},
		Network: "tcp",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		password := passwords[i%len(passwords)]
		_, _ = NewConn(mockConn, metadata, password)
	}
}

// TestPasswordHashConsistency tests password hash consistency
func TestPasswordHashConsistency(t *testing.T) {
	password := "test-password"

	// First retrieval (computation)
	hash1 := getPasswordHash(password)

	// 第二次获取（缓存）
	hash2 := getPasswordHash(password)

	// 验证一致性
	if hash1 != hash2 {
		t.Errorf("password hash inconsistency")
	}
}

// TestPasswordHashCorrectness tests password hash correctness
func TestPasswordHashCorrectness(t *testing.T) {
	password := "test-password"

	// Compute using new function
	hash := getPasswordHash(password)

	// 手动计算预期值
	expected := [56]byte{}
	h := sha256.New224()
	h.Write([]byte(password))
	hex.Encode(expected[:], h.Sum(nil))

	// 验证正确性
	if hash != expected {
		t.Errorf("password hash incorrect")
	}
}
