package key

import (
	"unsafe"
)

func StringKey(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return string(b)
}

func ConcatKey(a, b []byte) string {
	totalLen := len(a) + len(b)
	if totalLen == 0 {
		return ""
	}

	result := make([]byte, totalLen)
	copy(result, a)
	copy(result[len(a):], b)
	return unsafe.String(&result[0], totalLen)
}

func ConcatKey3(a, b, c []byte) string {
	totalLen := len(a) + len(b) + len(c)
	if totalLen == 0 {
		return ""
	}

	result := make([]byte, totalLen)
	copy(result, a)
	copy(result[len(a):], b)
	copy(result[len(a)+len(b):], c)
	return unsafe.String(&result[0], totalLen)
}

func ConcatKeyBytes(dst []byte, parts ...[]byte) string {
	dst = dst[:0]
	for _, p := range parts {
		dst = append(dst, p...)
	}
	return string(dst)
}
