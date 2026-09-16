/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package geodata

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestEmitBytesRejectsOversizedEntry(t *testing.T) {
	path := t.TempDir() + "/oversized.dat"
	data := append([]byte{0x0a}, protowire.AppendVarint(nil, maxGeoEntryLength+1)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = file.Close() }()

	_, err = emitBytes(file, "CN")
	if !errors.Is(err, errInvalidGeodataVarintLength) {
		t.Fatalf("expected oversized-entry error, got %v", err)
	}
}

func TestEmitBytesRejectsUnterminatedVarint(t *testing.T) {
	path := t.TempDir() + "/unterminated.dat"
	data := make([]byte, binary.MaxVarintLen64+2)
	data[0] = 0x0a
	for i := 1; i < len(data); i++ {
		data[i] = 0x80
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = file.Close() }()

	_, err = emitBytes(file, "CN")
	if !errors.Is(err, errInvalidGeodataVarintLength) {
		t.Fatalf("expected unterminated-varint error, got %v", err)
	}
}

func TestGeoIPFallbackRejectsOversizedFile(t *testing.T) {
	path := t.TempDir() + "/oversized.dat"
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err = file.Truncate(maxGeoEntryLength + 1); err != nil {
		_ = file.Close()
		t.Fatalf("truncate fixture: %v", err)
	}
	if err = file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	_, err = UnmarshalGeoIp(log, path, "CN")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected oversized-file error, got %v", err)
	}
}
