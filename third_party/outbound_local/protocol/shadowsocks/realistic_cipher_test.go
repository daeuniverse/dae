package shadowsocks

import (
	"crypto/rand"
	"crypto/sha1"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"golang.org/x/crypto/hkdf"
)

// BenchmarkUDPRealistic 模拟真实的 UDP 场景：每个包使用不同的 salt
func BenchmarkUDPRealistic(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey: masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 1400) // MTU

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// 真实场景：每个 UDP 包使用不同的随机 salt
		salt := make([]byte, 32)
		_, err := rand.Read(salt) // 模拟 RandomSaltGenerator
		if err != nil {
			b.Fatal(err)
		}

		// 使用 EncryptUDPFromPool 进行完整的加密流程
		_, err = EncryptUDPFromPool(key, data, salt, reusedInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUDPSameSalt 错误的场景：所有包使用相同的 salt（我之前的测试）
func BenchmarkUDPSameSalt(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey: masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 1400)
	salt := make([]byte, 32) // 固定的 salt

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := EncryptUDPFromPool(key, data, salt, reusedInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTCPRealistic 模拟真实的 TCP 场景：每个连接只初始化一次 cipher
func BenchmarkTCPRealistic(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey: masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		b.Fatal(err)
	}

	// 模拟 TCP 连接建立：一次性派生 subKey 和 cipher
	subKey := make([]byte, key.CipherConf.KeyLen)
	kdf := hkdf.New(sha1.New, key.MasterKey, salt, reusedInfo)
	_, _ = kdf.Read(subKey)
	ciph, _ := key.CipherConf.NewCipher(subKey)

	// 模拟多个数据包使用同一个 cipher
	data := make([]byte, 1400)
	nonce := make([]byte, key.CipherConf.NonceLen)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// TCP 场景：cipher 已预先创建，只需要 Seal
		_ = ciph.Seal(data[:0], nonce, data, nil)
	}
}

// BenchmarkTCPOverheadIncludingInit 包含初始化开销的 TCP
func BenchmarkTCPOverheadIncludingInit(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey: masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 1400)
	nonce := make([]byte, key.CipherConf.NonceLen)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// 每次都重新初始化（模拟新建连接）
		salt := make([]byte, 32)
		_, err := rand.Read(salt)
		if err != nil {
			b.Fatal(err)
		}

		subKey := make([]byte, key.CipherConf.KeyLen)
		kdf := hkdf.New(sha1.New, key.MasterKey, salt, reusedInfo)
		_, _ = kdf.Read(subKey)
		ciph, _ := key.CipherConf.NewCipher(subKey)

		_ = ciph.Seal(data[:0], nonce, data, nil)
	}
}

// BenchmarkUDPSmallPacketRealistic 真实的 UDP 小包场景
func BenchmarkUDPSmallPacketRealistic(b *testing.B) {
	masterKey := make([]byte, 32)
	key := &Key{
		MasterKey: masterKey,
		CipherConf: ciphers.AeadCiphersConf["aes-128-gcm"],
	}
	reusedInfo := []byte("ss-subkey")
	data := make([]byte, 64) // DNS 查询大小的包

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		salt := make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			b.Fatal(err)
		}

		_, err = EncryptUDPFromPool(key, data, salt, reusedInfo)
		if err != nil {
			b.Fatal(err)
		}
	}
}
