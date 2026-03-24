/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

const (
	MaxVarintLen64 = 8

	MaxPacketNumberLength = 4
	SampleSize            = 16
)

type Keys struct {
	version             Version
	clientInitialSecret []byte
	key                 []byte
	iv                  []byte
	headerProtectionKey []byte
	newAead             func(key []byte) (cipher.AEAD, error)
}

func (k *Keys) Close() error {
	pool.Put(k.clientInitialSecret)
	pool.Put(k.headerProtectionKey)
	pool.Put(k.iv)
	pool.Put(k.key)
	return nil
}

func NewKeys(clientDstConnectionId []byte, version Version, newAead func(key []byte) (cipher.AEAD, error)) (keys *Keys, err error) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-keys
	initialSecret := hkdf.Extract(sha256.New, clientDstConnectionId, version.InitialSalt())
	clientInitialSecret, err := HkdfExpandLabelFromPool(sha256.New, initialSecret, version.InitialSecretLabel(), nil, 32)
	if err != nil {
		return nil, err
	}

	keys = &Keys{
		clientInitialSecret: clientInitialSecret,
		version:             version,
		newAead:             newAead,
	}
	// We differentiated a deriveKeys func is just for example test.
	if err = keys.deriveKeys(); err != nil {
		_ = keys.Close()
		return nil, err
	}

	return keys, nil
}

func (k *Keys) deriveKeys() (err error) {
	k.key, err = HkdfExpandLabelFromPool(sha256.New, k.clientInitialSecret, k.version.KeyLabel(), nil, 16)
	if err != nil {
		return err
	}
	k.iv, err = HkdfExpandLabelFromPool(sha256.New, k.clientInitialSecret, k.version.IvLabel(), nil, 12)
	if err != nil {
		return err
	}
	k.headerProtectionKey, err = HkdfExpandLabelFromPool(sha256.New, k.clientInitialSecret, k.version.HpLabel(), nil, 16)
	if err != nil {
		return err
	}
	return nil
}

// HeaderProtection_ encrypt/decrypt firstByte and packetNumber in place.
func (k *Keys) HeaderProtection_(sample []byte, longHeader bool, firstByte *byte, potentialPacketNumber []byte) (packetNumber []byte, pnLen int, err error) {
	block, err := aes.NewCipher(k.headerProtectionKey)
	if err != nil {
		return nil, 0, err
	}
	// Get mask.
	mask := pool.Get(block.BlockSize())
	defer pool.Put(mask)
	block.Encrypt(mask, sample)
	// Encrypt/decrypt first byte.
	if longHeader {
		// Long header: 4 bits masked
		// High 4 bits are not protected.
		*firstByte ^= mask[0] & 0x0f
	} else {
		// Short header: 5 bits masked
		// High 3 bits are not protected.
		*firstByte ^= mask[0] & 0x1f
	}
	// The length of the Packet Number field is the value of this field plus one.
	pnLen = int((*firstByte & 0b11) + 1)
	packetNumber = potentialPacketNumber[:pnLen]

	// Encrypt/decrypt packet number.
	for i := range packetNumber {
		packetNumber[i] ^= mask[1+i]
	}
	return packetNumber, pnLen, nil
}

func (k *Keys) PayloadDecrypt(ciphertext []byte, pn uint64, header []byte) (plaintext pool.PB, err error) {
	// https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets

	aead, err := k.newAead(k.key)
	if err != nil {
		return nil, err
	}

	// XOR the full 64-bit PN into the IV.
	nonce := pool.Get(len(k.iv))
	defer pool.Put(nonce)
	copy(nonce, k.iv)

	// RFC 9001: The nonce is formed by XORing the packet number with the IV.
	// The packet number is left-padded with zeros to the size of the IV.
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], binary.BigEndian.Uint64(nonce[len(nonce)-8:])^pn)

	plaintext = pool.Get(len(ciphertext) - aead.Overhead())
	plaintext, err = aead.Open(plaintext[:0], nonce, ciphertext, header)
	if err != nil {
		plaintext.Put()
		return nil, err
	}
	return plaintext, nil
}

func DecryptQuic_(buf []byte, pnOffset int, blockEnd int, destConnId []byte) (plaintext pool.PB, err error) {
	_version := binary.BigEndian.Uint32(buf[1:])
	version, err := ParseVersion(_version)
	if err != nil {
		return nil, err
	}
	keys, err := NewKeys(destConnId, version, common.NewGcm)
	if err != nil {
		return nil, err
	}
	defer func() { _ = keys.Close() }()

	// RFC 9001: The sample is taken from the ciphertext, starting 4 bytes after the beginning of the PN.
	// Since Initial packets use 1-4 byte PN, we must ensure we have enough data.
	sampleOffset := pnOffset + MaxPacketNumberLength
	if blockEnd-sampleOffset < SampleSize {
		return nil, io.ErrUnexpectedEOF
	}
	sample := buf[sampleOffset : sampleOffset+SampleSize]

	// Decrypt header flag and packet number.
	var packetNumber []byte
	var pnLen int
	header := buf[:pnOffset]
	if packetNumber, pnLen, err = keys.HeaderProtection_(sample, true, &header[0], buf[pnOffset:pnOffset+MaxPacketNumberLength]); err != nil {
		return nil, err
	}
	// Parse packet number as uint64
	var pn uint64
	for _, b := range packetNumber {
		pn = (pn << 8) | uint64(b)
	}

	// Payload starts after PN field
	payloadOffset := pnOffset + pnLen
	payload := buf[payloadOffset:blockEnd]
	headerEnd := buf[:payloadOffset]

	plaintext, err = keys.PayloadDecrypt(payload, pn, headerEnd)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
