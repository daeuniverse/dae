/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2024, daeuniverse Organization <dae@v2raya.org>
 */

package bandwidth

// /////// The following code is adapted from https://github.com/apernet/hysteria/blob/21ea2a0/app/internal/utils/bpsconv.go
// and is subject to its original license terms, not the license of dae.

import (
	"errors"
	"strconv"
	"strings"
)

const (
	Byte     = 1
	Kilobyte = Byte * 1000
	Megabyte = Kilobyte * 1000
	Gigabyte = Megabyte * 1000
	Terabyte = Gigabyte * 1000
)

// Parse converts a string to a bandwidth value in bytes per second.
// E.g. "100 Mbps", "512 kbps", "1g" are all valid.
func Parse(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))

	spl := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			spl = i
			break
		}
	}
	if spl == 0 {
		return strconv.ParseUint(s, 10, 64)
	}

	v, err := strconv.ParseUint(s[:spl], 10, 64)
	if err != nil {
		return 0, err
	}

	switch strings.TrimSpace(s[spl:]) {
	case "b", "bps":
		return v * Byte / 8, nil
	case "k", "kb", "kbps":
		return v * Kilobyte / 8, nil
	case "m", "mb", "mbps":
		return v * Megabyte / 8, nil
	case "g", "gb", "gbps":
		return v * Gigabyte / 8, nil
	case "t", "tb", "tbps":
		return v * Terabyte / 8, nil
	default:
		return 0, errors.New("unsupported unit")
	}
}

// /////// reference end
