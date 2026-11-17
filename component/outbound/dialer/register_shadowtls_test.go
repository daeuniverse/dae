/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/sirupsen/logrus"

	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	_ "github.com/daeuniverse/outbound/transport/shadowtls"
)

func shadowTLSNodeID(d *Dialer) string {
	property := d.Property()
	sum := sha256.Sum256([]byte(property.Link))
	return "n_" + hex.EncodeToString(sum[:])
}

// A node is written as "name:link", but ShadowTLS normalization only applies to
// the URI. Normalizing the whole string made the saved-config node id differ
// from the id the API validated before the write.
func TestShadowTLSNodeIDMatchesWithAndWithoutName(t *testing.T) {
	link := `ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@127.0.0.1:8388?plugin=shadowtls%3BskipVerify%3Dtrue%3Bhost%3Dexample.com%3Bpassword%3Dtest#x`
	option := &GlobalOption{Log: logrus.New()}
	bare, err := NewFromLinkContext(context.Background(), option, InstanceOption{DisableCheck: true}, link, "")
	if err != nil {
		t.Fatalf("bare link: %v", err)
	}
	t.Cleanup(func() { _ = bare.Close() })
	named, err := NewFromLinkContext(context.Background(), option, InstanceOption{DisableCheck: true}, "edge:"+link, "")
	if err != nil {
		t.Fatalf("named link: %v", err)
	}
	t.Cleanup(func() { _ = named.Close() })
	if got, want := shadowTLSNodeID(named), shadowTLSNodeID(bare); got != want {
		t.Fatalf("named node id = %s, want the bare-link id %s (links %q / %q)", got, want, named.Property().Link, bare.Property().Link)
	}
}
