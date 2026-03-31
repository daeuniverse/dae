package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

func fillRandom(t *testing.T, b []byte) {
	t.Helper()
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
}

// TestEncryptUDPInPlaceEquivalence verifies that encryptUDPInPlace produces
// the same output as EncryptUDPFromPool when given the same inputs.
func TestEncryptUDPInPlaceEquivalence(t *testing.T) {
	testCases := []struct {
		name      string
		cipher    string
		payloadSz int
	}{
		{"aes-128-gcm small", "aes-128-gcm", 64},
		{"aes-128-gcm medium", "aes-128-gcm", 1400},
		{"aes-256-gcm small", "aes-256-gcm", 64},
		{"aes-256-gcm medium", "aes-256-gcm", 1400},
		{"chacha20-poly1305 small", "chacha20-poly1305", 64},
		{"chacha20-poly1305 medium", "chacha20-poly1305", 1400},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf, ok := ciphers.AeadCiphersConf[tc.cipher]
			if !ok {
				t.Skipf("cipher %s not available", tc.cipher)
			}

				masterKey := make([]byte, conf.KeyLen)
				fillRandom(t, masterKey)

				payload := make([]byte, tc.payloadSz)
				fillRandom(t, payload)

				salt := make([]byte, conf.SaltLen)
				fillRandom(t, salt)

			reusedInfo := []byte("ss-subkey")

			key := &Key{
				CipherConf: conf,
				MasterKey:  masterKey,
			}

			// Encrypt using original method
			encryptedOriginal, err := EncryptUDPFromPool(key, payload, salt, reusedInfo)
			if err != nil {
				t.Fatalf("EncryptUDPFromPool failed: %v", err)
			}
			defer pool.Put(encryptedOriginal)

			// Prepare buffer for in-place encryption
			// Layout: [salt][payload][space for tag]
			totalLen := conf.SaltLen + len(payload) + conf.TagLen
			buf := pool.Get(totalLen)
			defer pool.Put(buf)

			// Copy salt at the beginning
			copy(buf, salt)
			// Copy payload after salt
			copy(buf[conf.SaltLen:], payload)
			payloadEnd := conf.SaltLen + len(payload)

			// Encrypt using in-place method
			encryptedInPlace, err := encryptUDPInPlace(key, buf, payloadEnd, reusedInfo)
			if err != nil {
				t.Fatalf("encryptUDPInPlace failed: %v", err)
			}
			defer pool.Put(encryptedInPlace)

			// Compare outputs
			if !bytes.Equal(encryptedOriginal, encryptedInPlace) {
				t.Errorf("Outputs differ:\n  original:  %x\n  inPlace:   %x\n  len(orig)=%d, len(inPlace)=%d",
					encryptedOriginal[:min(64, len(encryptedOriginal))],
					encryptedInPlace[:min(64, len(encryptedInPlace))],
					len(encryptedOriginal),
					len(encryptedInPlace))
			}
		})
	}
}

// TestEncryptUDPInPlaceDecryptRoundTrip verifies that data encrypted with
// encryptUDPInPlace can be decrypted with DecryptUDPFromPool.
func TestEncryptUDPInPlaceDecryptRoundTrip(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	payload := []byte("Test message for round-trip encryption with in-place method")
	salt := make([]byte, conf.SaltLen)
	fillRandom(t, salt)

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	// Prepare buffer for in-place encryption
	totalLen := conf.SaltLen + len(payload) + conf.TagLen
	buf := pool.Get(totalLen)

	copy(buf, salt)
	copy(buf[conf.SaltLen:], payload)
	payloadEnd := conf.SaltLen + len(payload)

	encrypted, err := encryptUDPInPlace(key, buf, payloadEnd, nil)
	if err != nil {
		pool.Put(buf)
		t.Fatalf("encryptUDPInPlace failed: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptUDPFromPool(key, encrypted, nil)
	if err != nil {
		pool.Put(encrypted)
		t.Fatalf("DecryptUDPFromPool failed: %v", err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, payload) {
		t.Errorf("Decrypted data doesn't match:\n  got:      %x\n  expected: %x", decrypted, payload)
	}
}

// TestEncryptUDPInPlaceConcurrent verifies thread safety of the encryption functions.
func TestEncryptUDPInPlaceConcurrent(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	const goroutines = 20
	const iterations = 100

	done := make(chan bool, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
				for i := 0; i < iterations; i++ {
					payload := make([]byte, 100)
					fillRandom(t, payload)
					salt := make([]byte, conf.SaltLen)
					fillRandom(t, salt)

				// Test in-place encryption
				totalLen := conf.SaltLen + len(payload) + conf.TagLen
				buf := pool.Get(totalLen)
				copy(buf, salt)
				copy(buf[conf.SaltLen:], payload)

				encrypted, err := encryptUDPInPlace(key, buf, conf.SaltLen+len(payload), nil)
				if err != nil {
					t.Errorf("encryptUDPInPlace failed: %v", err)
					pool.Put(buf)
					continue
				}

				// Verify decryption works
				decrypted, err := DecryptUDPFromPool(key, encrypted, nil)
				if err != nil {
					t.Errorf("DecryptUDPFromPool failed: %v", err)
					pool.Put(encrypted)
					continue
				}

				if !bytes.Equal(decrypted, payload) {
					t.Errorf("Decrypted data mismatch")
				}

				pool.Put(encrypted)
				decrypted.Put()
			}
			done <- true
		}()
	}

	for g := 0; g < goroutines; g++ {
		<-done
	}
}
