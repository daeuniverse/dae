/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package assets

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestGetLocationAssetRejectsParentTraversal(t *testing.T) {
	root := t.TempDir()
	assetDir := filepath.Join(root, "assets")
	if err := os.Mkdir(assetDir, 0o755); err != nil {
		t.Fatalf("mkdir asset dir: %v", err)
	}
	outside := filepath.Join(root, "outside.dat")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	finder := NewLocationFinder([]string{assetDir})
	if _, err := finder.GetLocationAsset(log, filepath.Join("..", filepath.Base(outside))); err == nil {
		t.Fatal("parent traversal unexpectedly resolved an asset")
	}
}
