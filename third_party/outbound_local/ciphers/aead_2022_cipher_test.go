package ciphers

import "testing"

func TestAead2022CiphersConf_IncludesChacha20(t *testing.T) {
	conf := Aead2022CiphersConf["2022-blake3-chacha20-poly1305"]
	if conf == nil {
		t.Fatal("missing 2022-blake3-chacha20-poly1305 cipher config")
	}
	if conf.KeyLen != 32 {
		t.Fatalf("unexpected key length: got %d want 32", conf.KeyLen)
	}
	if conf.NewCipher == nil {
		t.Fatal("missing AEAD constructor for chacha20 cipher config")
	}
}

func TestSlidingWindowFilter_BasicAndDuplicate(t *testing.T) {
	f := NewSlidingWindowFilter(64)

	if !f.CheckAndUpdate(100) {
		t.Fatalf("first packet should pass")
	}
	if f.CheckAndUpdate(100) {
		t.Fatalf("duplicate packet should be rejected")
	}
	if !f.CheckAndUpdate(101) {
		t.Fatalf("next packet should pass")
	}
	if !f.CheckAndUpdate(99) {
		t.Fatalf("out-of-order but in-window packet should pass")
	}
	if f.CheckAndUpdate(99) {
		t.Fatalf("duplicate out-of-order packet should be rejected")
	}
}

func TestSlidingWindowFilter_ShiftAndTooOld(t *testing.T) {
	f := NewSlidingWindowFilter(8)

	if !f.CheckAndUpdate(1) {
		t.Fatalf("packet 1 should pass")
	}
	if !f.CheckAndUpdate(2) {
		t.Fatalf("packet 2 should pass")
	}
	if !f.CheckAndUpdate(20) {
		t.Fatalf("packet 20 should pass")
	}
	if f.CheckAndUpdate(2) {
		t.Fatalf("packet 2 should be too old after large shift")
	}
	if !f.CheckAndUpdate(19) {
		t.Fatalf("packet 19 should pass within current window")
	}
	if f.CheckAndUpdate(19) {
		t.Fatalf("duplicate packet 19 should be rejected")
	}
}
