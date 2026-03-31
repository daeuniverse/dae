package key

import (
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestStringKey(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{}, ""},
		{"nil", nil, ""},
		{"single byte", []byte{0x61}, "a"},
		{"multiple bytes", []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}, "hello"},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xff}, string([]byte{0x00, 0x01, 0x02, 0xff})},
		{"with null", []byte{0x61, 0x00, 0x62}, "a\x00b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringKey(tt.input)
			if result != tt.expected {
				t.Errorf("StringKey() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConcatKey(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []byte
		expected string
	}{
		{"both empty", []byte{}, []byte{}, ""},
		{"both nil", nil, nil, ""},
		{"a nil", nil, []byte{0x61, 0x62}, "ab"},
		{"b nil", []byte{0x63, 0x64}, nil, "cd"},
		{"a empty", []byte{}, []byte{0x61, 0x62}, "ab"},
		{"b empty", []byte{0x63, 0x64}, []byte{}, "cd"},
		{"both non-empty", []byte{0x61, 0x62}, []byte{0x63, 0x64}, "abcd"},
		{"binary data", []byte{0x00, 0x01}, []byte{0x02, 0xff}, string([]byte{0x00, 0x01, 0x02, 0xff})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConcatKey(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("ConcatKey() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConcatKey3(t *testing.T) {
	tests := []struct {
		name     string
		a, b, c  []byte
		expected string
	}{
		{"all empty", []byte{}, []byte{}, []byte{}, ""},
		{"partial empty", []byte{0x61}, []byte{}, []byte{0x62}, "ab"},
		{"all non-empty", []byte{0x61, 0x62}, []byte{0x63}, []byte{0x64, 0x65}, "abcde"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConcatKey3(tt.a, tt.b, tt.c)
			if result != tt.expected {
				t.Errorf("ConcatKey3() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConcatKeyBytes(t *testing.T) {
	dst := make([]byte, 0, 64)

	tests := []struct {
		name     string
		parts    [][]byte
		expected string
	}{
		{"no parts", [][]byte{}, ""},
		{"single part", [][]byte{{0x61, 0x62}}, "ab"},
		{"multiple parts", [][]byte{{0x61}, {0x62, 0x63}, {0x64}}, "abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConcatKeyBytes(dst, tt.parts...)
			if result != tt.expected {
				t.Errorf("ConcatKeyBytes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestStringKeyRace(t *testing.T) {
	data := []byte{0x61, 0x62, 0x63, 0x64, 0x65}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				result := StringKey(data)
				if result != "abcde" {
					t.Error("unexpected result")
				}
			}
		}()
	}
	wg.Wait()
}

func TestConcatKeyRace(t *testing.T) {
	a := []byte{0x61, 0x62}
	b := []byte{0x63, 0x64}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				result := ConcatKey(a, b)
				if result != "abcd" {
					t.Error("unexpected result")
				}
			}
		}()
	}
	wg.Wait()
}

func TestConcatKey3Race(t *testing.T) {
	a := []byte{0x61}
	b := []byte{0x62}
	c := []byte{0x63}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				result := ConcatKey3(a, b, c)
				if result != "abc" {
					t.Error("unexpected result")
				}
			}
		}()
	}
	wg.Wait()
}

func TestKeyPoolNoLeak(t *testing.T) {
	a := make([]byte, 16)
	b := make([]byte, 32)

	for i := 0; i < 1000; i++ {
		_ = ConcatKey(a, b)
	}
	runtime.GC()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	for i := 0; i < 100000; i++ {
		_ = ConcatKey(a, b)
	}
	runtime.GC()

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	growth := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	if growth > 1<<20 {
		t.Errorf("Potential memory leak: heap grew by %d bytes", growth)
	}
}

func BenchmarkStringKey(b *testing.B) {
	data := []byte(strings.Repeat("a", 48))
	for i := 0; i < b.N; i++ {
		_ = StringKey(data)
	}
}

func BenchmarkConcatKey(b *testing.B) {
	a := make([]byte, 16)
	b_ := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		_ = ConcatKey(a, b_)
	}
}

func BenchmarkConcatKey3(b *testing.B) {
	a := make([]byte, 8)
	b2 := make([]byte, 16)
	c := make([]byte, 8)
	for i := 0; i < b.N; i++ {
		_ = ConcatKey3(a, b2, c)
	}
}

func BenchmarkConcatKeyParallel(b *testing.B) {
	a := make([]byte, 16)
	b_ := make([]byte, 32)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = ConcatKey(a, b_)
		}
	})
}

func BenchmarkOldConcatKey(b *testing.B) {
	a := make([]byte, 16)
	b_ := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		key := make([]byte, len(a)+len(b_))
		copy(key, a)
		copy(key[len(a):], b_)
		_ = string(key)
	}
}
