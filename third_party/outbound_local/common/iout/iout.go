/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package iout

import (
	"io"

	"github.com/daeuniverse/outbound/pool"
)

const smallWriteThreshold = 4096

func MultiWrite(dst io.Writer, bs ...[]byte) (int64, error) {
	var total int
	for _, b := range bs {
		total += len(b)
	}

	if total <= smallWriteThreshold {
		var written int64
		for _, b := range bs {
			n, err := dst.Write(b)
			written += int64(n)
			if err != nil {
				return written, err
			}
		}
		return written, nil
	}

	buf := pool.Get(total)[:0]
	defer buf.Put()
	for _, b := range bs {
		buf = append(buf, b...)
	}
	n, err := dst.Write(buf)
	return int64(n), err
}
