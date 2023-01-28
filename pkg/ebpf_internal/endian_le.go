//go:build 386 || amd64 || amd64p32 || arm || arm64 || mipsle || mips64le || mips64p32le || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mipsle mips64le mips64p32le ppc64le riscv64

// Copied from https://github.com/cilium/ebpf/blob/v0.10.0/internal/endian_le.go

package internal

import "encoding/binary"

// NativeEndian is set to either binary.BigEndian or binary.LittleEndian,
// depending on the host's endianness.
var NativeEndian binary.ByteOrder = binary.LittleEndian

// ClangEndian is set to either "el" or "eb" depending on the host's endianness.
const ClangEndian = "el"
