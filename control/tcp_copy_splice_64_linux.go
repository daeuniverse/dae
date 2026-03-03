//go:build linux && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x)
// +build linux
// +build amd64 arm64 loong64 mips64 mips64le ppc64 ppc64le riscv64 s390x

package control

import "golang.org/x/sys/unix"

func spliceCount(srcFD, dstFD, count int) (int64, error) {
	return unix.Splice(srcFD, nil, dstFD, nil, count, unix.SPLICE_F_MOVE)
}
