/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package bitlist

import (
	"fmt"
	"testing"
)

func TestBitList6(t *testing.T) {
	bm := NewCompactBitList(6)
	bm.Set(1, 0b110010)
	if v := bm.Get(1); v != 0b110010 {
		t.Fatal(fmt.Errorf("expect 0b%08b, got 0b%08b", 0b110010, v))
	}
	bm.Tighten()
	if v := bm.Get(1); v != 0b110010 {
		t.Fatal(fmt.Errorf("expect 0b%08b, got 0b%08b", 0b110010, v))
	}
	bm.Set(13, 0b110010)
	if v := bm.Get(13); v != 0b110010 {
		t.Fatal(fmt.Errorf("expect 0b%08b, got 0b%08b", 0b110010, v))
	}
	capBeforeTighten := bm.b.Cap()
	bm.Tighten()
	if bm.b.Cap() != bm.b.Len() || bm.b.Cap() > capBeforeTighten {
		t.Fatal("failed to tighten", bm.b.Cap(), bm.b.Len(), capBeforeTighten)
	}
	if v := bm.Get(13); v != 0b110010 {
		t.Fatal(fmt.Errorf("expect 0b%08b, got 0b%08b", 0b110010, v))
	}
	bm.Append(0b110010)
	if v := bm.Get(14); v != 0b110010 {
		t.Fatal(fmt.Errorf("expect 0b%08b, got 0b%08b", 0b110010, v))
	}
	capBeforeTighten = bm.b.Cap()
	bm.Tighten()
	if bm.b.Cap() != bm.b.Len() || bm.b.Cap() > capBeforeTighten {
		t.Fatal("failed to tighten", bm.b.Cap(), bm.b.Len(), capBeforeTighten)
	}
}

func TestBitList19(t *testing.T) {
	bm := NewCompactBitList(19)
	bm.Set(1, 0b1110010110010110010)
	if v := bm.Get(1); v != 0b1110010110010110010 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1110010110010110010, v))
	}
	bm.Tighten()
	if v := bm.Get(1); v != 0b1110010110010110010 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1110010110010110010, v))
	}
	bm.Set(13, 0b1110010110010110010)
	if v := bm.Get(13); v != 0b1110010110010110010 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1110010110010110010, v))
	}
	capBeforeTighten := bm.b.Cap()
	bm.Tighten()
	if bm.b.Cap() != bm.b.Len() || bm.b.Cap() > capBeforeTighten {
		t.Fatal("failed to tighten", bm.b.Cap(), bm.b.Len(), capBeforeTighten)
	}
	if v := bm.Get(13); v != 0b1110010110010110010 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1110010110010110010, v))
	}
	bm.Append(0b1110010110010110010)
	if v := bm.Get(14); v != 0b1110010110010110010 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1110010110010110010, v))
	}
	capBeforeTighten = bm.b.Cap()
	bm.Tighten()
	if bm.b.Cap() != bm.b.Len() || bm.b.Cap() > capBeforeTighten {
		t.Fatal("failed to tighten", bm.b.Cap(), bm.b.Len(), capBeforeTighten)
	}
	bm.Set(1, 0b0000000000000000000)
	if v := bm.Get(1); v != 0b0000000000000000000 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b0000000000000000000, v))
	}
	bm.Set(2, 0b1111111111111111111)
	if v := bm.Get(2); v != 0b1111111111111111111 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1111111111111111111, v))
	}
	if v := bm.Get(1); v != 0b0000000000000000000 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b0000000000000000000, v))
	}
}
