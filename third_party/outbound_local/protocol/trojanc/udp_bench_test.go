package trojanc

import (
	"testing"
)

// BenchmarkUDPPacketOverhead tests memory allocation for UDP packet processing
func BenchmarkUDPPacketOverhead(b *testing.B) {
	b.Run("SmallPacket", func(b *testing.B) {
		data := make([]byte, 100)
		for i := range data {
			data[i] = byte(i)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Simulate SealUDP allocation
			_ = make([]byte, 100+4+100)
		}
	})

	b.Run("LargePacket", func(b *testing.B) {
		data := make([]byte, 1400)
		for i := range data {
			data[i] = byte(i)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Simulate SealUDP allocation
			_ = make([]byte, 100+4+1400)
		}
	})
}
