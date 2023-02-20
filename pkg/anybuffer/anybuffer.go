/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, v2rayA Organization <team@v2raya.org>
 */

package anybuffer

import (
	"errors"
	"golang.org/x/exp/constraints"
)

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

var smallBufferSize = 16
var defaultBufferSize = 64

// A Buffer is a variable-sized buffer of bytes with Read and Write methods.
// The zero value for Buffer is an empty buffer ready to use.
type Buffer[T constraints.Unsigned] struct {
	buf []T // contents are the bytes buf[off : len(buf)]
}

// ErrTooLarge is passed to panic if memory cannot be allocated to store data in a buffer.
var ErrTooLarge = errors.New("bytes.Buffer: too large")

const maxInt = int(^uint(0) >> 1)

// Slice returns a slice of length b.Len() holding the unread portion of the buffer.
// The slice is valid for use only until the next buffer modification (that is,
// only until the next call to a method like Read, Write, Reset, or Truncate).
// The slice aliases the buffer content at least until the next buffer modification,
// so immediate changes to the slice will affect the result of future reads.
func (b *Buffer[T]) Slice() []T { return b.buf }

// empty reports whether the unread portion of the buffer is empty.
func (b *Buffer[T]) empty() bool { return len(b.buf) <= 0 }

// Len returns the number of bytes of the unread portion of the buffer;
// b.Len() == len(b.Slice()).
func (b *Buffer[T]) Len() int { return len(b.buf) - 0 }

// Cap returns the capacity of the buffer's underlying byte slice, that is, the
// total space allocated for the buffer's data.
func (b *Buffer[T]) Cap() int { return cap(b.buf) }

// Truncate discards all but the first n unread bytes from the buffer
// but continues to use the same allocated storage.
// It panics if n is negative or greater than the length of the buffer.
func (b *Buffer[T]) Truncate(n int) {
	if n == 0 {
		b.Reset()
		return
	}
	if n < 0 || n > b.Len() {
		panic("bytes.Buffer: truncation out of range")
	}
	b.buf = b.buf[:0+n]
}

// Reset resets the buffer to be empty,
// but it retains the underlying storage for use by future writes.
// Reset is the same as Truncate(0).
func (b *Buffer[T]) Reset() {
	b.buf = b.buf[:0]
}

// tryGrowByReslice is a inlineable version of grow for the fast-case where the
// internal buffer only needs to be resliced.
// It returns the index where bytes should be written and whether it succeeded.
func (b *Buffer[T]) tryGrowByReslice(n int) (int, bool) {
	if l := len(b.buf); n <= cap(b.buf)-l {
		b.buf = b.buf[:l+n]
		return l, true
	}
	return 0, false
}

// grow grows the buffer to guarantee space for n more bytes.
// It returns the index where bytes should be written.
// If the buffer can't grow it will panic with ErrTooLarge.
func (b *Buffer[T]) grow(n int) int {
	m := b.Len()
	// Try to grow by means of a reslice.
	if i, ok := b.tryGrowByReslice(n); ok {
		return i
	}
	if b.buf == nil && n <= smallBufferSize {
		b.buf = make([]T, n, smallBufferSize)
		return 0
	}
	c := cap(b.buf)
	if n <= c/2-m {
		// We can slide things down instead of allocating a new
		// slice. We only need m+n <= c to slide, but
		// we instead let capacity get twice as large so we
		// don't spend all our time copying.
	} else if c > maxInt-c-n {
		panic(ErrTooLarge)
	} else {
		// Not enough space anywhere, we need to allocate.
		buf := makeSlice[T](2*c + n)
		copy(buf, b.buf)
		b.buf = buf
	}
	// Restore len(b.buf).
	b.buf = b.buf[:m+n]
	return m
}

// Grow grows the buffer's capacity, if necessary, to guarantee space for
// another n bytes. After Grow(n), at least n bytes can be written to the
// buffer without another allocation.
// If n is negative, Grow will panic.
// If the buffer can't grow it will panic with ErrTooLarge.
func (b *Buffer[T]) Grow(n int) {
	if n < 0 {
		panic("bytes.Buffer.Grow: negative count")
	}
	m := b.grow(n)
	b.buf = b.buf[:m]
}

// Extend extends the Buffer.Len() by n.
func (b *Buffer[T]) Extend(n int) {
	b.extend(n)
}

func (b *Buffer[T]) extend(n int) int {
	m, ok := b.tryGrowByReslice(n)
	if !ok {
		m = b.grow(n)
	}
	return m
}

// makeSlice allocates a slice of size n. If the allocation fails, it panics
// with ErrTooLarge.
func makeSlice[T constraints.Unsigned](n int) []T {
	// If the make fails, give a known error.
	defer func() {
		if recover() != nil {
			panic(ErrTooLarge)
		}
	}()
	return make([]T, n)
}

// NewBuffer creates and initializes a new Buffer using buf as its
// initial contents. The new Buffer takes ownership of buf, and the
// caller should not use buf after this call. NewBuffer is intended to
// prepare a Buffer to read existing data. It can also be used to set
// the initial size of the internal buffer for writing. To do that,
// buf should have the desired capacity but a length of zero.
//
// In most cases, new(Buffer) (or just declaring a Buffer variable) is
// sufficient to initialize a Buffer.
func NewBuffer[T constraints.Unsigned](size int) *Buffer[T] {
	if size == 0 {
		size = defaultBufferSize
	}
	return &Buffer[T]{buf: make([]T, 0, size)}
}

func NewBufferFrom[T constraints.Unsigned](b []T) *Buffer[T] {
	return &Buffer[T]{buf: b}
}
