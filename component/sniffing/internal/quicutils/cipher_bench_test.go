/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"encoding/hex"
	"testing"

	"github.com/daeuniverse/dae/common"
)

func BenchmarkNewKeys(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
		if err != nil {
			b.Fatal(err)
		}
		_ = keys.Close()
	}
}

func BenchmarkKeys_HeaderProtection(b *testing.B) {
	keys, err := NewKeys(destConnId, Version_V1, common.NewGcm)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = keys.Close() }()

	sample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flag := byte(0xc3)
		pn, _ := hex.DecodeString("00000002")
		_, _, _ = keys.HeaderProtection_(sample, true, &flag, pn)
	}
}

func BenchmarkKeys_PayloadDecrypt(b *testing.B) {
	destConnId, _ := hex.DecodeString("7f9863b69d513af6a050f0272dfe4dd1")
	keys, err := NewKeys(destConnId, Version_Draft, common.NewGcm)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = keys.Close() }()

	rawData, _ := hex.DecodeString("cfff00001d107f9863b69d513af6a050f0272dfe4dd114cb9b88815f5c3e385f2a8756c2a76c61fe0a6ddf0041222cce1ec1f09bb7d134541f214437ebaac82ad3044e24abffb166407f6e8e41584fe9717fbec115d345c934408aa9314bb9e8a3487ea2c17a7ff02f65d3ed8f76a462034260bb41d6ef8f0fa78d6920074a10091f85d322c10f1f4eb7e207c2283c4df5857edea1279248ba03ba83c4727b759f564dcd4db3e6e11d40abce3d4362caf5ef592a3cde2d66acadc7428b5cccf28eb1461b0c3ca595ff7425f5898b95bf4917786a5f9ce7226dd0be61cff453bd74decfa057d3afaef136226e9ba23ad3e28da820a367b4788786efa97bf59033b87bc8a4555b86148cfde85ea16772eb1d81e14c9056f3f36a4f789bc608145712fa7cd28f93e76d3f90e80815e267aeefff2bc44299f8b65e3cf99816c96f33723d20565162cc843024bdbd83a90d2f")

	data := make([]byte, len(rawData))
	copy(data, rawData)
	header := data[:50]
	potentialPacketNumber := make([]byte, 4)
	copy(potentialPacketNumber, header[len(header)-4:])
	sample := data[50 : 50+16]
	flag := header[0]
	pn, pnLen, err := keys.HeaderProtection_(sample, true, &flag, potentialPacketNumber)
	if err != nil {
		b.Fatal(err)
	}
	actualHeader := make([]byte, len(header)-4+pnLen)
	copy(actualHeader, data[:len(header)-4])
	actualHeader[0] = flag
	copy(actualHeader[len(actualHeader)-pnLen:], pn)
	payload := make([]byte, len(data)-len(actualHeader))
	copy(payload, data[len(actualHeader):])

	var pnUint uint64
	for _, by := range pn {
		pnUint = (pnUint << 8) | uint64(by)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payloadCopy := make([]byte, len(payload))
		copy(payloadCopy, payload)
		pt, err := keys.PayloadDecrypt(payloadCopy, pnUint, actualHeader)
		if err != nil {
			b.Fatal(err)
		}
		_ = pt
	}
}

func BenchmarkDecryptQuic(b *testing.B) {
	destConnId, _ := hex.DecodeString("7f9863b69d513af6a050f0272dfe4dd1")
	data, _ := hex.DecodeString("cfff00001d107f9863b69d513af6a050f0272dfe4dd114cb9b88815f5c3e385f2a8756c2a76c61fe0a6ddf0041222cce1ec1f09bb7d134541f214437ebaac82ad3044e24abffb166407f6e8e41584fe9717fbec115d345c934408aa9314bb9e8a3487ea2c17a7ff02f65d3ed8f76a462034260bb41d6ef8f0fa78d6920074a10091f85d322c10f1f4eb7e207c2283c4df5857edea1279248ba03ba83c4727b759f564dcd4db3e6e11d40abce3d4362caf5ef592a3cde2d66acadc7428b5cccf28eb1461b0c3ca595ff7425f5898b95bf4917786a5f9ce7226dd0be61cff453bd74decfa057d3afaef136226e9ba23ad3e28da820a367b4788786efa97bf59033b87bc8a4555b86148cfde85ea16772eb1d81e14c9056f3f36a4f789bc608145712fa7cd28f93e76d3f90e80815e267aeefff2bc44299f8b65e3cf99816c96f33723d20565162cc843024bdbd83a90d2f")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptQuic_(data, 1, len(data), destConnId)
	}
}

func BenchmarkBigEndianUvarint(b *testing.B) {
	buf := []byte{0x44, 0xd0}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = BigEndianUvarint(buf)
	}
}
