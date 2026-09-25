/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"testing"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

// TestValidateFixedDomainTtlRejectsMalformedEntries is a regression guard:
// `dae validate` never ran control.ParseFixedDomainTtl, so every entry below
// exited 0 and then aborted daemon startup with "failed to parse ttl". The
// dry-run reuses the run-path parser, so "validate exits 0 => the daemon
// starts" holds again.
func TestValidateFixedDomainTtlRejectsMalformedEntries(t *testing.T) {
	parse := func(t *testing.T, entry string) *config.Config {
		t.Helper()
		sections, err := config_parser.Parse(`
global {}
dns {
  fixed_domain_ttl {
    ` + entry + `
  }
}
routing {
  fallback: direct
}
`)
		require.NoError(t, err)
		conf, err := config.New(sections)
		require.NoError(t, err)
		return conf
	}

	bad := map[string]string{
		"empty ttl":       `'123.example.com:'`,
		"missing colon":   `'123.example.com'`,
		"non-numeric ttl": `'123.example.com: abc'`,
	}
	for name, entry := range bad {
		t.Run(name, func(t *testing.T) {
			err := validateFixedDomainTtl(parse(t, entry))
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid fixed_domain_ttl")
			// The offending entry has to be named, otherwise the error cannot
			// be acted on in a config with several fixed TTLs.
			require.Contains(t, err.Error(), "123.example.com")
		})
	}

	t.Run("valid entry passes", func(t *testing.T) {
		require.NoError(t, validateFixedDomainTtl(parse(t, `'123.example.com: 10'`)))
	})

	t.Run("no entries passes", func(t *testing.T) {
		sections, err := config_parser.Parse("global {}\nrouting {\n  fallback: direct\n}\n")
		require.NoError(t, err)
		conf, err := config.New(sections)
		require.NoError(t, err)
		require.NoError(t, validateFixedDomainTtl(conf))
	})
}
