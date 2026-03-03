//go:build linux && (386 || arm || mips || mipsle)
// +build linux
// +build 386 arm mips mipsle

package control

import "golang.org/x/sys/unix"

func spliceCount(srcFD, dstFD, count int) (int64, error) {
	n, err := unix.Splice(srcFD, nil, dstFD, nil, count, unix.SPLICE_F_MOVE)
	return int64(n), err
}
