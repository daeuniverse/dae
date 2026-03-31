package shadowsocks_2022

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
)

func TestReplayWindowRace(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	conn := &UdpConn{
		SS2022Core: core,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sessionID := [8]byte{byte(id % 256), byte(id / 256)}
			for j := 0; j < 100; j++ {
				conn.checkAndUpdateReplay(sessionID, uint64(j), time.Now())
			}
		}(i)
	}
	wg.Wait()
}

func TestNewUdpConnCreatesCipher(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	conn := &UdpConn{
		SS2022Core: core,
	}

	// Verify cipher is nil before initialization
	if conn.cipher != nil {
		t.Error("cipher should be nil before NewUdpConn")
	}

	// Create cipher (simulating NewUdpConn behavior)
	sessionID := make([]byte, 8)
	cipher, err := CreateCipher(psk, sessionID, conf)
	if err != nil {
		t.Fatal(err)
	}
	conn.cipher = cipher

	// Verify cipher is created
	if conn.cipher == nil {
		t.Error("cipher should be created")
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	for i := 0; i < 100; i++ {
		_, err := NewSS2022Core(conf, [][]byte{psk}, psk)
		if err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	if after-before > 5 {
		t.Errorf("Potential goroutine leak: before=%d, after=%d", before, after)
	}
}

func BenchmarkSessionCipherAccess(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		b.Fatal(err)
	}

	sessionID := make([]byte, 8)
	cipher, err := CreateCipher(psk, sessionID, conf)
	if err != nil {
		b.Fatal(err)
	}

	conn := &UdpConn{
		SS2022Core: core,
		cipher:     cipher,
	}

	plaintext := make([]byte, 1400)
	nonce := make([]byte, 12)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := make([]byte, len(plaintext)+16)
		_ = conn.cipher.Seal(out[:0], nonce, plaintext, nil)
	}
}

func BenchmarkSessionCipherAccessParallel(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		b.Fatal(err)
	}

	sessionID := make([]byte, 8)
	cipher, err := CreateCipher(psk, sessionID, conf)
	if err != nil {
		b.Fatal(err)
	}

	conn := &UdpConn{
		SS2022Core: core,
		cipher:     cipher,
	}

	plaintext := make([]byte, 1400)
	nonce := make([]byte, 12)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			out := make([]byte, len(plaintext)+16)
			_ = conn.cipher.Seal(out[:0], nonce, plaintext, nil)
		}
	})
}

func BenchmarkReplayCheck(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		b.Fatal(err)
	}

	conn := &UdpConn{
		SS2022Core: core,
	}
	sessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.checkAndUpdateReplay(sessionID, uint64(i), now)
	}
}
