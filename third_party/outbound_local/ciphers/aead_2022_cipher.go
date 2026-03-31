package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type CipherConf2022 struct {
	KeyLen         int
	SaltLen        int
	NonceLen       int
	TagLen         int
	NewCipher      func(key []byte) (cipher.AEAD, error)
	NewBlockCipher func(key []byte) (cipher.Block, error)
	// IdentityHeaderBlockSize specifies the EIH block size for this cipher.
	// For AES ciphers: 16 bytes (AES block size).
	// For Chacha: 16 bytes (defined by SS2022 spec).
	IdentityHeaderBlockSize int
}

const (
	// Timestamp tolerance
	TimestampTolerance = 30 * time.Second

	// Salt storage duration
	SaltStorageDuration = 60 * time.Second
)

var (
	Aead2022CiphersConf = map[string]*CipherConf2022{
		"2022-blake3-aes-256-gcm": {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: NewGcm, NewBlockCipher: aes.NewCipher, IdentityHeaderBlockSize: aes.BlockSize},
		"2022-blake3-aes-128-gcm": {KeyLen: 16, SaltLen: 16, NonceLen: 12, TagLen: 16, NewCipher: NewGcm, NewBlockCipher: aes.NewCipher, IdentityHeaderBlockSize: aes.BlockSize},
		"2022-blake3-chacha20-poly1305": {KeyLen: 32, SaltLen: 32, NonceLen: 12, TagLen: 16, NewCipher: chacha20poly1305.New, IdentityHeaderBlockSize: 16},
	}
)

// ValidateBase64PSK validates that the PSK is a valid base64 string with correct length
func ValidateBase64PSK(pskBase64 string, expectedKeyLen int) ([]byte, error) {
	if pskBase64 == "" {
		return nil, fmt.Errorf("PSK cannot be empty for SIP022 methods")
	}

	psk, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		return nil, fmt.Errorf("PSK must be valid base64 for SIP022 methods: %w", err)
	}

	if len(psk) != expectedKeyLen {
		return nil, fmt.Errorf("PSK length must be %d bytes for this method, got %d", expectedKeyLen, len(psk))
	}

	return psk, nil
}

// SlidingWindowFilter implements a sliding window filter for packet ID replay protection
type SlidingWindowFilter struct {
	window      []uint64
	windowSize  uint64
	latest      uint64
	initialized bool
	mutex       sync.Mutex
}

// NewSlidingWindowFilter creates a new sliding window filter
func NewSlidingWindowFilter(windowSize int) *SlidingWindowFilter {
	if windowSize <= 0 {
		windowSize = 1024
	}
	wordCount := (windowSize + 63) / 64
	return &SlidingWindowFilter{
		window:     make([]uint64, wordCount),
		windowSize: uint64(windowSize),
	}
}

// CheckAndUpdate checks if the packet ID is valid and updates the window
func (f *SlidingWindowFilter) CheckAndUpdate(packetID uint64) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if !f.initialized {
		f.initialized = true
		f.latest = packetID
		f.setBit(0)
		return true
	}

	if packetID > f.latest {
		shift := packetID - f.latest
		f.shiftWindow(shift)
		f.latest = packetID
		f.setBit(0)
		return true
	}

	distance := f.latest - packetID
	if distance >= f.windowSize {
		return false
	}
	if f.getBit(distance) {
		return false
	}
	f.setBit(distance)
	return true
}

func (f *SlidingWindowFilter) getBit(index uint64) bool {
	wordIndex := index / 64
	bitIndex := index % 64
	return f.window[wordIndex]&(uint64(1)<<bitIndex) != 0
}

func (f *SlidingWindowFilter) setBit(index uint64) {
	wordIndex := index / 64
	bitIndex := index % 64
	f.window[wordIndex] |= uint64(1) << bitIndex
}

func (f *SlidingWindowFilter) shiftWindow(shift uint64) {
	if shift >= f.windowSize {
		// Clear all bits in-place
		for i := range f.window {
			f.window[i] = 0
		}
		return
	}

	// Optimized in-place shift to avoid allocation
	wordShift := int(shift / 64)
	bitShift := shift % 64

	// Shift right by wordShift positions
	if wordShift > 0 {
		for i := len(f.window) - 1; i >= wordShift; i-- {
			f.window[i] = f.window[i-wordShift]
		}
		for i := 0; i < wordShift; i++ {
			f.window[i] = 0
		}
	}

	// Handle remaining bit shift
	if bitShift > 0 {
		for i := len(f.window) - 1; i > 0; i-- {
			f.window[i] = (f.window[i] >> bitShift) | (f.window[i-1] << (64 - bitShift))
		}
		f.window[0] = f.window[0] >> bitShift
	}
}
