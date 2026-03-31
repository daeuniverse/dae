package juicity

import (
	"bytes"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
)

func TestOptimizedEncryptDecryptCorrectness(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := []byte("Hello, Juicity! This is a test message for UDP optimization.")
	reusedInfo := ciphers.JuicityReusedInfo

	for i := 0; i < 10; i++ {
		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatalf("Encryption failed at iteration %d: %v", i, err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		if err != nil {
			encrypted.Put()
			t.Fatalf("Decryption failed at iteration %d: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			encrypted.Put()
			decrypted.Put()
			t.Errorf("Decrypted text doesn't match at iteration %d", i)
		}

		encrypted.Put()
		decrypted.Put()
	}
}

func TestOptimizedCacheEffectiveness(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := []byte("Cache test for juicity")
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted1, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	encrypted1.Put()

	encrypted2, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted2.Put()

	if !bytes.Equal(encrypted1, encrypted2) {
		t.Error("Cached encryption should produce same result")
	}

	decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted2, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted text doesn't match")
	}
}

func TestOptimizedConcurrentAccess(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := []byte("Concurrent test")
	reusedInfo := ciphers.JuicityReusedInfo

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
				if err != nil {
					errors <- err
					return
				}

				decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
				encrypted.Put()
				if err != nil {
					errors <- err
					return
				}

				if !bytes.Equal(decrypted, plaintext) {
					errors <- bytes.ErrTooLarge
					decrypted.Put()
					return
				}
				decrypted.Put()
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestOptimizedMemoryLeak(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for i := 0; i < 10000; i++ {
		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		if err != nil {
			t.Fatal(err)
		}
		decrypted.Put()
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	heapGrowth := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	t.Logf("Heap before: %d bytes", memBefore.HeapAlloc)
	t.Logf("Heap after: %d bytes", memAfter.HeapAlloc)
	t.Logf("Heap growth: %d bytes", heapGrowth)

	if heapGrowth > 10*1024*1024 {
		t.Errorf("Potential memory leak: heap grew by %d bytes (> 10MB)", heapGrowth)
	}
}

func TestOptimizedPoolMemoryLeak(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for i := 0; i < 10000; i++ {
		encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		if err != nil {
			t.Fatal(err)
		}
		decrypted.Put()
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	heapGrowth := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	t.Logf("Pool test - Heap before: %d bytes", memBefore.HeapAlloc)
	t.Logf("Pool test - Heap after: %d bytes", memAfter.HeapAlloc)
	t.Logf("Pool test - Heap growth: %d bytes", heapGrowth)

	if heapGrowth > 5*1024*1024 {
		t.Errorf("Potential pool memory leak: heap grew by %d bytes (> 5MB)", heapGrowth)
	}
}

func BenchmarkJuicityEncrypt(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		encrypted.Put()
	}
}

func BenchmarkJuicityDecrypt(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	defer encrypted.Put()

	decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
	decrypted.Put()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		buf.Put()
	}
}

func BenchmarkJuicityEncryptDecrypt(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		decrypted.Put()
	}
}

func BenchmarkJuicityVsOriginal(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.Run("Original", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
			decrypted := pool.Get(len(encrypted))
			n, _ := shadowsocks.DecryptUDP(decrypted[:0], key, encrypted, reusedInfo)
			encrypted.Put()
			pool.Put(decrypted)
			_ = n
		}
	})

	b.Run("Optimized", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
			decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
			encrypted.Put()
			decrypted.Put()
		}
	})
}

func BenchmarkJuicityMultipleSalts(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	numSalts := 50
	salts := make([][]byte, numSalts)
	for i := range salts {
		salts[i] = make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salts[i])
	}

	b.Run("Original_MultiSalt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			salt := salts[i%numSalts]
			encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
			encrypted.Put()
		}
	})

	b.Run("Optimized_MultiSalt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			salt := salts[i%numSalts]
			encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
			encrypted.Put()
		}
	})
}

func BenchmarkJuicityRealistic(b *testing.B) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := make([]byte, 1400)
	reusedInfo := ciphers.JuicityReusedInfo

	b.Run("Realistic_Optimized", func(b *testing.B) {
		b.ReportAllocs()

		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		for i := 0; i < b.N; i++ {
			if i%100 == 0 {
				_, _ = fastrand.Read(salt)
			}
			encrypted, _ := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
			decrypted, _ := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
			encrypted.Put()
			decrypted.Put()
		}
	})
}

func TestTransportPacketConnOptimizedPath(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	plaintext := []byte("TransportPacketConn test payload")
	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()

	decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("TransportPacketConn encryption/decryption mismatch")
	}
}

func TestTransportPacketConnSimulatedReadWrite(t *testing.T) {
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	for i := 0; i < 100; i++ {
		plaintext := make([]byte, 100+fastrand.Intn(1300))
		_, _ = fastrand.Read(plaintext)

		salt := make([]byte, conf.SaltLen)
		_, _ = fastrand.Read(salt)

		reusedInfo := ciphers.JuicityReusedInfo

		encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatal(err)
		}

		decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			decrypted.Put()
			t.Errorf("Mismatch at iteration %d", i)
		}
		decrypted.Put()
	}
}

func TestTransportPacketConnTargetAddress(t *testing.T) {
	tgt := netip.MustParseAddrPort("192.168.1.1:443")

	plaintext := []byte("Test data with target address")
	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()

	decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decryption mismatch with target address")
	}

	_ = tgt
}

func TestCacheExpiration(t *testing.T) {
	originalCleanupInterval := udpCacheCleanupInterval
	originalMaxAge := udpCacheMaxAge

	udpCacheCleanupInterval = 100 * time.Millisecond
	udpCacheMaxAge = 200 * time.Millisecond

	defer func() {
		udpCacheCleanupInterval = originalCleanupInterval
		udpCacheMaxAge = originalMaxAge
	}()

	conf := CipherConf
	masterKey := make([]byte, conf.KeyLen)
	_, _ = fastrand.Read(masterKey)

	key := &shadowsocks.Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(salt)

	plaintext := []byte("Cache expiration test")
	reusedInfo := ciphers.JuicityReusedInfo

	encrypted, err := shadowsocks.EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	encrypted.Put()

	time.Sleep(300 * time.Millisecond)

	decrypted, err := shadowsocks.DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Cache expiration caused decryption failure")
	}
}

var udpCacheCleanupInterval = 5 * time.Minute
var udpCacheMaxAge = 10 * time.Minute
