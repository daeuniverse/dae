package shadowsocks

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
)

func TestEncryptDecrypt(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	salt := make([]byte, conf.SaltLen)
	fillRandom(t, salt)

	plaintext := []byte("Hello, World! This is a test message for Shadowsocks encryption.")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	encrypted, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatalf("EncryptUDPFromPool failed: %v", err)
	}
	defer encrypted.Put()

	decrypted, err := DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatalf("DecryptUDPFromPool failed: %v", err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match plaintext:\n  decrypted: %x\n  plaintext: %x", decrypted, plaintext)
	}
}

func TestMultipleSalts(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	plaintext := []byte("Multi-salt test")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	for i := 0; i < 10; i++ {
		salt := make([]byte, conf.SaltLen)
		fillRandom(t, salt)

		encrypted, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatalf("Encrypt iteration %d failed: %v", i, err)
		}

		decrypted, err := DecryptUDPFromPool(key, encrypted, reusedInfo)
		if err != nil {
			encrypted.Put()
			t.Fatalf("Decrypt iteration %d failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Salt %d failed", i)
		}

		encrypted.Put()
		decrypted.Put()
	}
}

func BenchmarkEncrypt(b *testing.B) {
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

func BenchmarkDecrypt(b *testing.B) {
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
