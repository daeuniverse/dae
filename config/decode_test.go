/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/stretchr/testify/require"
)

func TestNewUsesExplicitSectionDecoders(t *testing.T) {
	sections, err := config_parser.Parse(`
global {
  log_level: info
  so_mark_from_dae: 1234
}

subscription {
  "https://example.com/sub"
}

node {
  "ss://example"
}

group {
  proxy {
    policy: random
    filter: name(keyword: hk)
  }
}

routing {
  pname(NetworkManager) -> direct
  fallback: proxy
}

dns {
  ipversion_prefer: 6
  upstream {
    google:"8.8.8.8:53"
  }
  routing {
    request {
      qname(geosite:geolocation-!cn) -> proxy
      fallback: direct
    }
    response {
      fallback: proxy
    }
  }
}
`)
	require.NoError(t, err)

	conf, err := New(sections)
	require.NoError(t, err)
	require.True(t, conf.Global.SoMarkFromDaeSet)
	require.Len(t, conf.Subscription, 1)
	require.Len(t, conf.Node, 1)
	require.Len(t, conf.Group, 1)
	require.Equal(t, "proxy", conf.Group[0].Name)
	require.Equal(t, 6, conf.Dns.IpVersionPrefer)
	require.NotNil(t, conf.Routing.Fallback)
	require.NotNil(t, conf.Dns.Routing.Request.Fallback)
	require.NotNil(t, conf.Dns.Routing.Response.Fallback)
}

func TestGlobalMemoryDefaults(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {
  fallback: direct
}
`)
	require.NoError(t, err)

	conf, err := New(sections)
	require.NoError(t, err)
	// disable_thp defaults to false: dae does not alter kernel memory policy
	// unless the user opts in.
	require.False(t, conf.Global.DisableTHP)
	require.EqualValues(t, 262144, conf.Global.BpfConnStateMapSize)
}

func TestDnsMemoryDefaultsAndExplicitUnlimited(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
dns {}
routing {
  fallback: direct
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)
	require.Equal(t, 65536, conf.Dns.MaxCacheSize)

	sections, err = config_parser.Parse(`
global {}
dns {
  max_cache_size: 0
}
routing {
  fallback: direct
}
`)
	require.NoError(t, err)
	conf, err = New(sections)
	require.NoError(t, err)
	require.Zero(t, conf.Dns.MaxCacheSize)
}

func TestDecodeConfigSectionRejectsUnknownSection(t *testing.T) {
	conf := &Config{}
	err := decodeConfigSection(conf, "unknown", &config_parser.Section{Name: "unknown"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown section")
}

func TestGlobalCheckIntervalRejectsNonPositive(t *testing.T) {
	for _, section := range []string{`
global {
  check_interval: 0s
}
routing {
  fallback: direct
}
`, `
global {
  check_interval: -5s
}
routing {
  fallback: direct
}
`} {
		sections, err := config_parser.Parse(section)
		require.NoError(t, err)

		_, err = New(sections)
		require.Error(t, err)
		require.Contains(t, err.Error(), "check_interval")
	}
}

func TestGroupCheckIntervalRejectsNegativeButAllowsInherit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "inherit", value: "0s"},
		{name: "negative", value: "-5s", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sections, err := config_parser.Parse(fmt.Sprintf(`
global {}
group {
  proxy {
    policy: random
    check_interval: %s
  }
}
routing {
  fallback: proxy
}
`, tc.value))
			require.NoError(t, err)

			_, err = New(sections)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "check_interval")
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestMissingOptionalSectionsStillApplyDefaults is a regression guard: a
// config that omits an optional section must decode that section from an empty
// section so its documented `default:` tags apply, instead of silently keeping
// the Go zero values (a missing dns section used to leave MaxCacheSize == 0,
// which means "unlimited" rather than the documented 65536).
func TestMissingOptionalSectionsStillApplyDefaults(t *testing.T) {
	sections, err := config_parser.Parse(`
global {}
routing {
  fallback: direct
}
`)
	require.NoError(t, err)
	conf, err := New(sections)
	require.NoError(t, err)

	require.Equal(t, 65536, conf.Dns.MaxCacheSize, "missing dns section must take the documented default")
	require.True(t, conf.Dns.OptimisticCache)
	require.Equal(t, 60, conf.Dns.OptimisticCacheTtl)
	require.Equal(t, 30, conf.Dns.OptimisticStaleReplyTtl)
	require.Nil(t, conf.Group)
	require.Nil(t, conf.Node)
	require.Nil(t, conf.Subscription)

	// An explicit 0 must still mean "unlimited" (the documented opt-out); it is
	// the runtime that must not remap it.
	sections, err = config_parser.Parse(`
global {}
dns {
  max_cache_size: 0
}
routing {
  fallback: direct
}
`)
	require.NoError(t, err)
	conf, err = New(sections)
	require.NoError(t, err)
	require.Zero(t, conf.Dns.MaxCacheSize)
}
