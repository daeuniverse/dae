package pool

import (
	"fmt"
	"testing"
)

// TestPool_Get_Bug 测试 pool.Get 对于 2 的幂次的问题
func TestPool_Get_Bug(t *testing.T) {
	fmt.Println("=== Testing pool.Get for powers of 2 ===")
	fmt.Println()
	
	testCases := []struct {
		size          int
		minExpectedCap int
		description   string
	}{
		{1024, 1024, "1024 bytes (power of 2)"},
		{2048, 2048, "2048 bytes (power of 2) - LIKELY BUG"},
		{4096, 4096, "4096 bytes (power of 2)"},
		{1025, 2048, "1025 bytes (not power of 2)"},
		{2049, 4096, "2049 bytes (not power of 2)"},
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
			fmt.Printf("  Min expected cap: %d\n", tc.minExpectedCap)
			
			if actualCap < tc.size {
				t.Errorf("❌ CRITICAL: cap=%d < requested size=%d (WILL PANIC!)\n", actualCap, tc.size)
			} else if actualCap < tc.minExpectedCap {
				t.Errorf("⚠️  WARNING: cap=%d < min expected=%d\n", actualCap, tc.minExpectedCap)
			} else {
				fmt.Printf("✅ PASS\n\n")
			}
		})
	}
}

// TestGetMustBiggerBug 测试 GetMustBigger 是否返回足够容量的 buffer
func TestGetMustBiggerBug(t *testing.T) {
	testCases := []struct {
		size          int
		expectedCap   int
		description   string
	}{
		{2080, 4096, "2080 bytes - should get bucket 12 (4096)"},
		{2048, 2048, "2048 bytes - should get bucket 11 (2048)"},
		{2049, 4096, "2049 bytes - should get bucket 12 (4096)"},
		{1536, 2048, "1536 bytes - should get bucket 11 (2048)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			buf := GetMustBigger(tc.size)
			defer buf.Put()
			
			actualCap := cap(buf)
			actualLen := len(buf)
			
			fmt.Printf("Test: %s\n", tc.description)
			fmt.Printf("  Requested: %d bytes\n", tc.size)
			fmt.Printf("  Got: len=%d, cap=%d\n", actualLen, actualCap)
			fmt.Printf("  Expected cap: %d\n", tc.expectedCap)
			
			if actualCap < tc.size {
				t.Errorf("❌ FAIL: cap=%d < requested size=%d (PANIC!)\n", actualCap, tc.size)
			} else if actualCap < tc.expectedCap {
				t.Errorf("⚠️  WARNING: cap=%d < expected=%d\n", actualCap, tc.expectedCap)
			} else {
				fmt.Printf("✅ PASS\n\n")
			}
		})
	}
}

// TestPoolInitialization 测试 pool 初始化是否正确
func TestPoolInitialization(t *testing.T) {
	fmt.Println("\n=== Pool Initialization Test ===")
	
	// 测试每个 bucket
	for i := minsizePower; i < num; i++ {
		buf := pools[i].Get().([]byte)
		actualCap := cap(buf)
		expectedCap := 1 << i
		
		fmt.Printf("Bucket %d: expected cap=%d, actual cap=%d", i, expectedCap, actualCap)
		
		if actualCap != expectedCap {
			fmt.Printf(" ❌ MISMATCH!\n")
			t.Errorf("Bucket %d: expected cap=%d, got %d", i, expectedCap, actualCap)
		} else {
			fmt.Printf(" ✅\n")
		}
	}
	fmt.Println()
}
