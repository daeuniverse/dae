/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
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
	bm.Tighten()
	if bm.b.Cap() != 11 {
		t.Fatal("failed to tighten", bm.b.Cap())
	}
	if v := bm.Get(13); v != 0b110010 {
		t.Fatal(fmt.Errorf("expect 0b%08b, got 0b%08b", 0b110010, v))
	}
	bm.Append(0b110010)
	if v := bm.Get(14); v != 0b110010 {
		t.Fatal(fmt.Errorf("expect 0b%08b, got 0b%08b", 0b110010, v))
	}
	if bm.b.Cap() != 32 {
		t.Fatal("unexpected grow behavior", bm.b.Cap())
	}
	bm.Tighten()
	if bm.b.Cap() != 12 {
		t.Fatal("failed to tighten", bm.b.Cap())
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
	bm.Tighten()
	if bm.b.Cap() != 34 {
		t.Fatal("failed to tighten", bm.b.Cap())
	}
	if v := bm.Get(13); v != 0b1110010110010110010 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1110010110010110010, v))
	}
	bm.Append(0b1110010110010110010)
	if v := bm.Get(14); v != 0b1110010110010110010 {
		t.Fatal(fmt.Errorf("expect 0b%019b, got 0b%019b", 0b1110010110010110010, v))
	}
	if bm.b.Cap() != 128 {
		t.Fatal("unexpected grow behavior", bm.b.Cap())
	}
	bm.Tighten()
	if bm.b.Cap() != 36 {
		t.Fatal("failed to tighten", bm.b.Cap())
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
