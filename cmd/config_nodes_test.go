/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/sirupsen/logrus"
)

// mockLink is a share link the engine parses; nothing connects during a test.
const mockLink = "socks5://user:pass@192.0.2.10:1080"

func emptyNodeIndex() (map[string]nodeRef, error) { return map[string]nodeRef{}, nil }

func nodeIndexWith(refs ...map[string]nodeRef) nodeIndexFunc {
	return func() (map[string]nodeRef, error) {
		out := map[string]nodeRef{}
		for _, r := range refs {
			for k, v := range r {
				out[k] = v
			}
		}
		return out, nil
	}
}

func TestInsertNodeEntryIntoExistingBlock(t *testing.T) {
	text := "node {\n  existing: 'socks5://192.0.2.1:1080'\n}\n"
	got := insertNodeEntry(text, "mock-01", mockLink)
	want := "node {\n  mock-01: '" + mockLink + "'\n  existing: 'socks5://192.0.2.1:1080'\n}\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestInsertNodeEntryAppendsBlock(t *testing.T) {
	// A module without a node block gets one, and the existing text is untouched.
	text := "# nodes live here\n"
	got := insertNodeEntry(text, "mock-01", mockLink)
	want := "# nodes live here\n\nnode {\n  mock-01: '" + mockLink + "'\n}\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRemoveNodeEntryKeepsSurroundingText(t *testing.T) {
	text := "# keep me\nnode {\n  keep: 'socks5://192.0.2.1:1080'\n  drop: 'socks5://192.0.2.2:1080' # trailing\n}\n# and me\n"
	got, ok := removeNodeEntry(text, "drop")
	if !ok {
		t.Fatal("drop was not removed")
	}
	want := "# keep me\nnode {\n  keep: 'socks5://192.0.2.1:1080'\n}\n# and me\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
	if _, again := removeNodeEntry(got, "drop"); again {
		t.Fatal("a removed node must not be removable twice")
	}
}

func TestValidateNodeName(t *testing.T) {
	for _, ok := range []string{"mock-01", "hk_01", "node.01", "a"} {
		if err := validateNodeName(ok); err != nil {
			t.Fatalf("%q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "with space", "quote'name", "brace}", strings.Repeat("a", 65)} {
		if err := validateNodeName(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestShareLinkScheme(t *testing.T) {
	cases := map[string]string{
		"socks5://192.0.2.1:1080": "socks5",
		"VLESS://x@y:1":           "vless",
		"no-scheme":               "",
		"://missing":              "",
		"1abc://x":                "",
	}
	for link, want := range cases {
		if got := shareLinkScheme(link); got != want {
			t.Fatalf("shareLinkScheme(%q) = %q, want %q", link, got, want)
		}
	}
}

func TestConfigCreateNodeWritesManagedModule(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	accepted, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{
		Name: "mock-01",
		Link: mockLink,
	}, emptyNodeIndex)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.OperationID == "" {
		t.Fatal("a queued node_create must report an operation")
	}
	if ops.calls != 1 {
		t.Fatalf("StartOperation calls = %d, want 1", ops.calls)
	}
	target := flowSource(t, e, "config.d/node.dae")
	content, err := os.ReadFile(target.abs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "mock-01: '"+mockLink+"'") {
		t.Fatalf("node not written:\n%s", content)
	}
	if bak, _ := os.ReadFile(target.abs + ".bak"); !strings.Contains(string(bak), "node {}") {
		t.Fatalf("backup must hold the previous bytes: %q", bak)
	}
}

func TestConfigCreateNodeRejectsDuplicateName(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	// A name a subscription delivered is taken too: names are global.
	index := nodeIndexWith(map[string]nodeRef{"n_sub": {Name: "mock-01", ProviderID: "p_abc"}})
	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, index)
	if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "state_conflict" {
		t.Fatalf("got %d %s, want 409 state_conflict", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("a rejected create must not queue a reload")
	}
}

func TestConfigCreateNodeRejectsUnsupportedLink(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	before := flowSource(t, e, "config.d/node.dae")

	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: "vless://not-a-real-node"}, emptyNodeIndex)
	if apiErr := flowAPIError(t, err); apiErr.Status != 422 || apiErr.Code != "unsupported_value" {
		t.Fatalf("got %d %s, want 422 unsupported_value", apiErr.Status, apiErr.Code)
	}
	if content, _ := os.ReadFile(before.abs); string(content) != string(before.raw) {
		t.Fatal("a rejected link must not touch the file")
	}
	if ops.calls != 0 {
		t.Fatal("a rejected create must not queue a reload")
	}
}

func TestConfigCreateNodeNeedsWritesEnabled(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, false, &fakeConfigOperations{})

	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
}

func TestConfigDeleteNodeRemovesLine(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")

	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex); err != nil {
		t.Fatal(err)
	}
	ops.calls = 0

	index := nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: "inline"}})
	outcome, err := e.DeleteNode(context.Background(), nativeapi.NodeDeleteRequest{NodeID: "n_mock"}, index)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", outcome.Deleted)
	}
	if ops.calls != 1 {
		t.Fatalf("StartOperation calls = %d, want 1", ops.calls)
	}
	content, _ := os.ReadFile(target.abs)
	if strings.Contains(string(content), "mock-01") {
		t.Fatalf("node still present:\n%s", content)
	}
}

func TestConfigDeleteNodeRejectsProviderOwnedNode(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	index := nodeIndexWith(map[string]nodeRef{"n_sub": {Name: "sub-01", ProviderID: "p_abc"}})
	_, err := e.DeleteNode(context.Background(), nativeapi.NodeDeleteRequest{NodeID: "n_sub"}, index)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
}

func TestConfigDeleteNodeIsIdempotentForUnknownID(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	outcome, err := e.DeleteNode(context.Background(), nativeapi.NodeDeleteRequest{NodeID: "n_missing"}, emptyNodeIndex)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Deleted != 0 {
		t.Fatalf("deleted = %d, want 0", outcome.Deleted)
	}
	if ops.calls != 0 {
		t.Fatal("an unknown id must not queue a reload")
	}
}

func TestValidateNodeLinkAcceptsRealShareLinks(t *testing.T) {
	// Mock links in the shapes the panel pastes: the same parse the reload does
	// has to accept them, otherwise a stored node would break the next reload.
	links := []string{
		"socks5://user:pass@192.0.2.10:1080",
		"vless://11111111-2222-3333-4444-555555555555@192.0.2.10:443?security=tls&sni=example.com#mock-01",
		"trojan://pass@192.0.2.10:443?sni=example.com#mock-02",
	}
	for _, link := range links {
		if _, err := validateNodeLink(context.Background(), logrus.New(), link); err != nil {
			t.Fatalf("%s: %v", link, err)
		}
	}
	// A link the engine cannot load must be refused with a sanitized reason.
	if _, err := validateNodeLink(context.Background(), logrus.New(), "vless://only-a-host"); err == nil {
		t.Fatal("a link without host and port must be refused")
	}
}

func TestInsertNodeEntryMatchesFileIndentation(t *testing.T) {
	// The real configuration uses four spaces; a new entry should look native.
	text := "node {\n    keep: 'socks5://192.0.2.1:1080'\n}\n"
	got := insertNodeEntry(text, "mock-01", mockLink)
	want := "node {\n    mock-01: '" + mockLink + "'\n    keep: 'socks5://192.0.2.1:1080'\n}\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}

	// An empty block falls back to two spaces, the style the fixtures use.
	got = insertNodeEntry("node {\n}\n", "mock-01", mockLink)
	if !strings.Contains(got, "\n  mock-01: ") {
		t.Fatalf("empty block should use two spaces: %q", got)
	}
}
