/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"crypto/sha256"
	"encoding/hex"
)

// Revision returns an opaque, deterministic identifier for the accepted
// configuration. It changes only when the canonical marshalled form changes,
// so a reload that produces the same effective configuration keeps the same
// revision.
func (c *Config) Revision() string {
	if c == nil {
		return ""
	}
	b, err := c.Marshal(2)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
