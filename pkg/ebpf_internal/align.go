// Copied from https://github.com/cilium/ebpf/blob/v0.10.0/internal/align.go

package internal

// Align returns 'n' updated to 'alignment' boundary.
func Align(n, alignment int) int {
	return (int(n) + alignment - 1) / alignment * alignment
}
