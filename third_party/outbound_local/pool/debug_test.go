package pool

import (
	"fmt"
	"math/bits"
	"testing"
)

// TestGetBiggerClosestN 测试 GetBiggerClosestN 的逻辑
func TestGetBiggerClosestN(t *testing.T) {
	testCases := []struct {
		input    int
		expected int
	}{
		{1024, 10},  // 2^10 = 1024
		{1025, 11},  // 需要 2^11 = 2048
		{2048, 11},  // 2^11 = 2048
		{2049, 12},  // 需要 2^12 = 4096
		{4096, 12},  // 2^12 = 4096
		{4097, 13},  // 需要 2^13 = 8192
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.input), func(t *testing.T) {
			result := GetBiggerClosestN(tc.input)
			fmt.Printf("GetBiggerClosestN(%d) = %d (expected %d)\n", tc.input, result, tc.expected)
			
			bitsResult := bits.Len32(uint32(tc.input))
			fmt.Printf("  bits.Len32(%d) = %d\n", tc.input, bitsResult)
			fmt.Printf("  1 << %d = %d\n", bitsResult, 1 << bitsResult)
			
			if tc.input > (1 << bitsResult) {
				fmt.Printf("  %d > %d, so result = %d + 1 = %d\n", tc.input, 1 << bitsResult, bitsResult, bitsResult + 1)
			} else {
				fmt.Printf("  %d <= %d, so result = %d\n", tc.input, 1 << bitsResult, bitsResult)
			}
			
			if result != tc.expected {
				t.Errorf("Expected %d, got %d", tc.expected, result)
			} else {
				fmt.Printf("✅ CORRECT\n")
			}
			fmt.Println()
		})
	}
}
