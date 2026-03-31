package pool

import (
	"fmt"
	"testing"
)

// TestPoolGetPanicScenario 测试原始 panic 场景
func TestPoolGetPanicScenario(t *testing.T) {
	fmt.Println("=== Testing Original Panic Scenario ===")
	fmt.Println()
	
	// 原始 panic: pool.Get(2080) 返回 cap=2048 的 buffer
	// 2080 = 2048 (len(b)) + 16 (salt) + 16 (tagLen)
	
	testCases := []struct {
		description string
		size        int
	}{
		{"Original panic: 2080 bytes", 2080},
		{"2048 bytes", 2048},
		{"2049 bytes", 2049},
		{"4096 bytes", 4096},
		{"4097 bytes", 4097},
	}
	
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			buf := Get(tc.size)
			defer buf.Put()
			
			actualCap := cap(buf)
			actualLen := len(buf)
			
			fmt.Printf("Test: %s\n", tc.description)
			fmt.Printf("  Requested: %d bytes\n", tc.size)
			fmt.Printf("  Got: len=%d, cap=%d\n", actualLen, actualCap)
			
			if actualCap < tc.size {
				t.Errorf("❌ PANIC: cap=%d < requested size=%d\n", actualCap, tc.size)
			} else {
				fmt.Printf("✅ PASS: capacity sufficient\n\n")
			}
		})
	}
}

// TestAllPoolFunctions 测试所有 pool 函数
func TestAllPoolFunctions(t *testing.T) {
	fmt.Println("=== Testing All Pool Functions ===")
	fmt.Println()
	
	functions := []struct {
		name string
		fn   func(int) PB
	}{
		{"Get", Get},
		{"GetMustBigger", GetMustBigger},
		{"GetFullCap", GetFullCap},
	}
	
	sizes := []int{1024, 1025, 2048, 2049, 2080, 4096, 4097}
	
	for _, fn := range functions {
		fmt.Printf("\nTesting %s:\n", fn.name)
		for _, size := range sizes {
			buf := fn.fn(size)
			defer buf.Put()
			
			if cap(buf) < size {
				t.Errorf("%s(%d): cap=%d < size=%d ❌", fn.name, size, cap(buf), size)
				fmt.Printf("  %s(%d): ❌ cap=%d < %d\n", fn.name, size, cap(buf), size)
			} else {
				fmt.Printf("  %s(%d): ✅ cap=%d >= %d\n", fn.name, size, cap(buf), size)
			}
		}
	}
}
