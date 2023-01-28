//go:build armbe || arm64be || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build armbe arm64be mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

// Copied from https://github.com/cilium/ebpf/blob/v0.10.0/internal/endian_be.go

package internal

import "encoding/binary"

// NativeEndian is set to either binary.BigEndian or binary.LittleEndian,
// depending on the host's endianness.
var NativeEndian binary.ByteOrder = binary.BigEndian

// ClangEndian is set to either "el" or "eb" depending on the host's endianness.
const ClangEndian = "eb"
