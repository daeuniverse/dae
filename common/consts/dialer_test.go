package consts

import (
	"testing"
)

func TestL4ProtoStr_ToL4Proto(t *testing.T) {
	tests := []struct {
		name string
		l    L4ProtoStr
		want uint8
	}{
		{"TCP", L4ProtoStr_TCP, IPPROTO_TCP},
		{"UDP", L4ProtoStr_UDP, IPPROTO_UDP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.l.ToL4Proto(); got != tt.want {
				t.Errorf("L4ProtoStr.ToL4Proto() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestL4ProtoStr_ToL4ProtoType(t *testing.T) {
	// Just verify it doesn't panic for known types
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("The code panicked: %v", r)
		}
	}()

	if got := L4ProtoStr_TCP.ToL4ProtoType(); got != L4ProtoType_TCP {
		t.Errorf("Expected TCP, got %v", got)
	}
	if got := L4ProtoStr_UDP.ToL4ProtoType(); got != L4ProtoType_UDP {
		t.Errorf("Expected UDP, got %v", got)
	}
}
