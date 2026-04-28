/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
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
	require.True(t, conf.Global.DisableTHP)
	require.EqualValues(t, 262144, conf.Global.BpfConnStateMapSize)
}

func TestDecodeConfigSectionRejectsUnknownSection(t *testing.T) {
	conf := &Config{}
	err := decodeConfigSection(conf, "unknown", &config_parser.Section{Name: "unknown"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown section")
}
