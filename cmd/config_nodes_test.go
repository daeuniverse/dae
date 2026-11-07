/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/pkg/config_parser"
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

func insertNodeEntryOrFail(t *testing.T, text, name, link string) string {
	t.Helper()
	got, err := insertNodeEntry(text, name, link)
	if err != nil {
		t.Fatalf("insertNodeEntry(%q): %v", name, err)
	}
	return got
}

func TestInsertNodeEntryIntoExistingBlock(t *testing.T) {
	text := "node {\n  existing: 'socks5://192.0.2.1:1080'\n}\n"
	got := insertNodeEntryOrFail(t, text, "mock-01", mockLink)
	want := "node {\n  mock-01: '" + mockLink + "'\n  existing: 'socks5://192.0.2.1:1080'\n}\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestInsertNodeEntryAppendsBlock(t *testing.T) {
	// A module without a node block gets one, and the existing text is untouched.
	text := "# nodes live here\n"
	got := insertNodeEntryOrFail(t, text, "mock-01", mockLink)
	want := "# nodes live here\n\nnode {\n  mock-01: '" + mockLink + "'\n}\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestNodeBlockPatternMatchesCommentAndCRLF(t *testing.T) {
	for _, block := range []string{"node { # inline nodes\n", "node {\r\n"} {
		if !nodeBlockPattern.MatchString(block) {
			t.Errorf("node block pattern does not match %q", block)
		}
	}
	if nodeBlockPattern.MatchString("node min {\n") {
		t.Fatal("node block pattern matched a named subsection")
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
	}, emptyNodeIndex, nil)
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
	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, index, nil)
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

	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: "vless://not-a-real-node"}, emptyNodeIndex, nil)
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

	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
}

func TestConfigDeleteNodeRemovesLine(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")

	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	ops.calls = 0

	index := nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}})
	outcome, err := e.DeleteNode(context.Background(), nativeapi.NodeDeleteRequest{NodeID: "n_mock"}, index, nil)
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
	_, err := e.DeleteNode(context.Background(), nativeapi.NodeDeleteRequest{NodeID: "n_sub"}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
}

func TestConfigDeleteNodeRejectsProviderNodeSharingInlineName(t *testing.T) {
	// Names are global, so a subscription node and an inline node can carry the
	// same name. Deleting the subscription node must not edit the file: the
	// ownership check has to run before the edit by name.
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "dup", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	ops.calls = 0
	target := flowSource(t, e, "config.d/node.dae")
	before, _ := os.ReadFile(target.abs)

	index := nodeIndexWith(map[string]nodeRef{"n_sub": {Name: "dup", ProviderID: "p_sub"}})
	_, err := e.DeleteNode(context.Background(), nativeapi.NodeDeleteRequest{NodeID: "n_sub"}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
	after, _ := os.ReadFile(target.abs)
	if string(before) != string(after) {
		t.Fatalf("the managed file changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if ops.calls != 0 {
		t.Fatalf("StartOperation calls = %d, want 0", ops.calls)
	}
}

func TestConfigDeleteNodeIsIdempotentForUnknownID(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	outcome, err := e.DeleteNode(context.Background(), nativeapi.NodeDeleteRequest{NodeID: "n_missing"}, emptyNodeIndex, nil)
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

// nodeStringPtr is the "value is set" form of a NodeUpdateRequest field.
func nodeStringPtr(value string) *string { return &value }

func TestUpdateNodeEntryRewritesLineInPlace(t *testing.T) {
	text := "# keep me\nnode {\n    old: 'socks5://192.0.2.1:1080' # trailing\n    other: 'socks5://192.0.2.2:1080'\n}\n# and me\n"
	got, ok, err := updateNodeEntry(text, "old", "new", mockLink)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("old was not found")
	}
	want := "# keep me\nnode {\n    new: '" + mockLink + "' # trailing\n    other: 'socks5://192.0.2.2:1080'\n}\n# and me\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
	if _, ok, _ := updateNodeEntry(text, "missing", "new", mockLink); ok {
		t.Fatal("an unknown name must not match")
	}
	if _, _, err := updateNodeEntry(text, "old", "new", "vless://192.0.2.1:1\"'"); err == nil {
		t.Fatal("a link with both quote characters must be refused")
	}
}

func TestUpdateNodeEntryKeepsBareValuesAndLineEndings(t *testing.T) {
	// An unquoted value runs to the end of the line. Dropping the line ending
	// there would glue the next entry onto the rewritten one.
	text := "node {\n  a: socks5://192.0.2.1:1080\n  b: 'socks5://192.0.2.2:1080'\n}\n"
	got, ok, err := updateNodeEntry(text, "a", "a", mockLink)
	if err != nil || !ok {
		t.Fatalf("updateNodeEntry: %v, ok=%v", err, ok)
	}
	want := "node {\n  a: '" + mockLink + "'\n  b: 'socks5://192.0.2.2:1080'\n}\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestNodeLinkOfReadsTheManagedValue(t *testing.T) {
	text := "node {\n  a: 'socks5://192.0.2.1:1080'\n  b: \"socks5://192.0.2.2:1080\"\n  c: socks5://192.0.2.3:1080 # bare\n}\n"
	cases := map[string]string{
		"a": "socks5://192.0.2.1:1080",
		"b": "socks5://192.0.2.2:1080",
		"c": "socks5://192.0.2.3:1080",
	}
	for name, want := range cases {
		got, ok := nodeLinkOf(text, name)
		if !ok || got != want {
			t.Fatalf("nodeLinkOf(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	if _, ok := nodeLinkOf(text, "missing"); ok {
		t.Fatal("an unknown name must not resolve")
	}
}

func TestConfigUpdateNodeRenamesAndRelinks(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")

	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	ops.calls = 0
	relinked := "socks5://user:pass@192.0.2.11:1080"

	index := nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}})
	outcome, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Name:   nodeStringPtr("mock-02"),
		Link:   nodeStringPtr(relinked),
	}, index, func(nodeID string) (any, error) { return nodeID, nil })
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Updated != 1 {
		t.Fatalf("updated = %d, want 1", outcome.Updated)
	}
	if ops.calls != 1 || ops.resolver == nil {
		t.Fatalf("StartOperation calls = %d, resolver installed = %v", ops.calls, ops.resolver != nil)
	}
	if result, err := ops.resolver(); err != nil || result != nodeIDOfLink(relinked, "mock-02") {
		t.Fatalf("resolver returned %v, %v", result, err)
	}
	content, err := os.ReadFile(target.abs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "mock-02: '"+relinked+"'") {
		t.Fatalf("node not updated:\n%s", content)
	}
	if strings.Contains(string(content), "mock-01") {
		t.Fatalf("the old name is still present:\n%s", content)
	}
	if bak, _ := os.ReadFile(target.abs + ".bak"); !strings.Contains(string(bak), "mock-01") {
		t.Fatalf("backup must hold the previous bytes: %q", bak)
	}
}

func TestConfigUpdateNodeKeepsNameWhenOnlyTheLinkChanges(t *testing.T) {
	// A nil field keeps the current value, so a link-only patch must not rename
	// the node to the empty string.
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}

	index := nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}})
	relinked := "socks5://user:pass@192.0.2.11:1080"
	if _, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Link:   nodeStringPtr(relinked),
	}, index, nil); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(target.abs)
	if !strings.Contains(string(content), "mock-01: '"+relinked+"'") {
		t.Fatalf("node not updated in place:\n%s", content)
	}
}

func TestConfigUpdateNodeRejectsDuplicateName(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(target.abs)
	ops.calls = 0

	// A name a subscription delivered is taken too: names are global.
	index := nodeIndexWith(
		map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}},
		map[string]nodeRef{"n_sub": {Name: "taken", ProviderID: "p_abc"}},
	)
	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Name:   nodeStringPtr("taken"),
	}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "state_conflict" {
		t.Fatalf("got %d %s, want 409 state_conflict", apiErr.Status, apiErr.Code)
	}
	if after, _ := os.ReadFile(target.abs); string(after) != string(before) {
		t.Fatal("a rejected update must not touch the file")
	}
	if ops.calls != 0 {
		t.Fatal("a rejected update must not queue a reload")
	}
}

func TestConfigUpdateNodeRejectsUnsupportedLink(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(target.abs)
	ops.calls = 0

	index := nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}})
	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Link:   nodeStringPtr("vless://not-a-real-node"),
	}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 422 || apiErr.Code != "unsupported_value" {
		t.Fatalf("got %d %s, want 422 unsupported_value", apiErr.Status, apiErr.Code)
	}
	if after, _ := os.ReadFile(target.abs); string(after) != string(before) {
		t.Fatal("a rejected link must not touch the file")
	}
	if ops.calls != 0 {
		t.Fatal("a rejected update must not queue a reload")
	}
}

func TestConfigUpdateNodeRejectsProviderOwnedNode(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	index := nodeIndexWith(map[string]nodeRef{"n_sub": {Name: "sub-01", ProviderID: "p_abc"}})
	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_sub",
		Name:   nodeStringPtr("sub-02"),
	}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("a rejected update must not queue a reload")
	}
}

func TestConfigUpdateNodeRejectsALinkAnotherInlineNodeUses(t *testing.T) {
	// A node's API identity is derived from its link, so a relink that reuses an
	// existing link would merge two entries into one node.
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	other := "socks5://user:pass@192.0.2.12:1080"
	// The second node exists in the file but not yet in the running index: the
	// file check has to catch it alone.
	content, _ := os.ReadFile(target.abs)
	updated := insertNodeEntryOrFail(t, string(content), "mock-02", other)
	if err := os.WriteFile(target.abs, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(target.abs)
	ops.calls = 0

	index := nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}})
	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Link:   nodeStringPtr(other),
	}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "state_conflict" {
		t.Fatalf("got %d %s, want 409 state_conflict", apiErr.Status, apiErr.Code)
	}
	if after, _ := os.ReadFile(target.abs); string(after) != string(before) {
		t.Fatal("a rejected relink must not touch the file")
	}
	if ops.calls != 0 {
		t.Fatal("a rejected relink must not queue a reload")
	}
}

func TestConfigUpdateNodeRejectsALinkAnotherNodeUses(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	ops.calls = 0

	taken := "socks5://user:pass@192.0.2.13:1080"
	index := nodeIndexWith(
		map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}},
		map[string]nodeRef{nodeIDOfLink(taken, "sub-01"): {Name: "sub-01", ProviderID: "p_abc"}},
	)
	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Link:   nodeStringPtr(taken),
	}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "state_conflict" {
		t.Fatalf("got %d %s, want 409 state_conflict", apiErr.Status, apiErr.Code)
	}
}

func TestConfigUpdateNodeChecksTheNodeBeforeItsValues(t *testing.T) {
	// An unknown id answers 404 even when the patch carries a value the engine
	// could not parse: the node has to exist before its values are judged.
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, true, &fakeConfigOperations{})

	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_missing",
		Link:   nodeStringPtr("vless://not-a-real-node"),
	}, emptyNodeIndex, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "resource_not_found" {
		t.Fatalf("got %d %s, want 404 resource_not_found", apiErr.Status, apiErr.Code)
	}
}

func TestConfigUpdateNodeUnknownIDIs404(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_missing",
		Name:   nodeStringPtr("mock-02"),
	}, emptyNodeIndex, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "resource_not_found" {
		t.Fatalf("got %d %s, want 404 resource_not_found", apiErr.Status, apiErr.Code)
	}
}

func TestConfigUpdateNodeWithoutAFileLineIs409(t *testing.T) {
	// The generation can still hold a node the managed file no longer defines,
	// e.g. someone removed the line by hand without a reload.
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)

	index := nodeIndexWith(map[string]nodeRef{"n_stale": {Name: "ghost", ProviderID: inlineProviderID}})
	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_stale",
		Name:   nodeStringPtr("ghost-2"),
	}, index, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "state_conflict" {
		t.Fatalf("got %d %s, want 409 state_conflict", apiErr.Status, apiErr.Code)
	}
}

func TestConfigUpdateNodeNoOpWritesNothing(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	target := flowSource(t, e, "config.d/node.dae")
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(target.abs)
	ops.calls = 0

	index := nodeIndexWith(map[string]nodeRef{"n_mock": {Name: "mock-01", ProviderID: inlineProviderID}})
	outcome, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Name:   nodeStringPtr("mock-01"),
		Link:   nodeStringPtr(mockLink),
	}, index, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Updated != 0 {
		t.Fatalf("updated = %d, want 0", outcome.Updated)
	}
	if after, _ := os.ReadFile(target.abs); string(after) != string(before) {
		t.Fatal("a no-op patch must not rewrite the file")
	}
	if ops.calls != 0 {
		t.Fatal("a no-op patch must not queue a reload")
	}
}

// A completed PATCH must replay for its Idempotency-Key even after the link
// change moved the node id, or after the reload already applied the write. The
// replay check used to sit in commitSourceUpdate, behind the node lookup and the
// no-op check, so a retry answered 404/409/200-updated-0 instead of 202.
func TestConfigUpdateNodeReplaysAfterTheNodeIDChanges(t *testing.T) {
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	if _, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "mock-01", Link: mockLink}, emptyNodeIndex, nil); err != nil {
		t.Fatal(err)
	}
	index := nodeIndexWith(map[string]nodeRef{"n_old": {Name: "mock-01", ProviderID: inlineProviderID}})
	newLink := "socks5://user:pass@192.0.2.11:1080"
	first, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID:         "n_old",
		Link:           nodeStringPtr(newLink),
		IdempotencyKey: "patch-key",
	}, index, func(nodeID string) (any, error) { return nodeID, nil })
	if err != nil {
		t.Fatal(err)
	}
	if first.Updated != 1 || first.Accepted.OperationID == "" {
		t.Fatalf("first patch = %+v, want one queued update", first)
	}
	queued := ops.calls

	// The write changed the link, so the old id no longer names the node: the
	// generation now publishes a different id for the same inline entry.
	replayedIndex := nodeIndexWith(map[string]nodeRef{"n_new": {Name: "mock-01", ProviderID: inlineProviderID}})
	second, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID:         "n_old",
		Link:           nodeStringPtr(newLink),
		IdempotencyKey: "patch-key",
	}, replayedIndex, func(nodeID string) (any, error) { return nodeID, nil })
	if err != nil {
		t.Fatalf("retry must replay, got %v", err)
	}
	if second.Accepted.OperationID != first.Accepted.OperationID || second.Updated != 1 {
		t.Fatalf("retry = %+v, want the original operation %q", second, first.Accepted.OperationID)
	}
	if ops.calls != queued {
		t.Fatalf("retry queued another operation: calls %d -> %d", queued, ops.calls)
	}
}

func TestConfigUpdateNodeRequiresWritesEnabled(t *testing.T) {
	main, _ := newManagedTree(t)
	e := newFlowEditor(t, main, false, &fakeConfigOperations{})

	_, err := e.UpdateNode(context.Background(), nativeapi.NodeUpdateRequest{
		NodeID: "n_mock",
		Name:   nodeStringPtr("mock-02"),
	}, emptyNodeIndex, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 404 || apiErr.Code != "capability_not_supported" {
		t.Fatalf("got %d %s, want 404 capability_not_supported", apiErr.Status, apiErr.Code)
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
	got := insertNodeEntryOrFail(t, text, "mock-01", mockLink)
	want := "node {\n    mock-01: '" + mockLink + "'\n    keep: 'socks5://192.0.2.1:1080'\n}\n"
	if got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}

	// An empty block falls back to two spaces, the style the fixtures use.
	got = insertNodeEntryOrFail(t, "node {\n}\n", "mock-01", mockLink)
	if !strings.Contains(got, "\n  mock-01: ") {
		t.Fatalf("empty block should use two spaces: %q", got)
	}
}

func TestQuoteNodeValuePicksASafeQuote(t *testing.T) {
	// A single quote inside the link must not close the literal: the parser has
	// no escapes, so the whole value has to switch to double quotes.
	quoted, err := quoteNodeValue(`socks5://u:pa'ss@192.0.2.10:1080`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(quoted, `"`) || !strings.HasSuffix(quoted, `"`) {
		t.Fatalf("value with a single quote should use double quotes: %s", quoted)
	}
	if strings.Contains(quoted, "'\n") {
		t.Fatal("the quote must not leak a line break")
	}

	// A value with both quote characters cannot be represented at all.
	if _, err := quoteNodeValue(`socks5://u:"a'b"@192.0.2.10:1080`); err == nil {
		t.Fatal("a value containing both quote characters must be refused")
	}
	// A newline would end the entry and let the rest become configuration.
	if _, err := quoteNodeValue("socks5://192.0.2.10:1080\napi {\n  secret: x\n}"); err == nil {
		t.Fatal("a value containing a newline must be refused")
	}
}

func TestInsertNodeEntryRejectsInjectedSection(t *testing.T) {
	// The link below previously closed the literal, ended the entry and started
	// an api section of its own.
	injected := "socks5://192.0.2.10:1080\n}\napi {\n  secret: 'own'\n}\nnode {"
	if _, err := insertNodeEntry("node {\n}\n", "evil", injected); err == nil {
		t.Fatal("a link carrying a newline must be refused")
	}
}

func TestConfigNodeWriteSharesTheConfigPutGuards(t *testing.T) {
	// The node write paths used to skip three checks the config PUT had: the
	// listener secret, the API section and a running reload. They are one
	// implementation now, so a node create must refuse all three.
	main, _ := newManagedTree(t)
	reload := newReloadManager(make(chan reloadRequest, 1), make(chan struct{}, 1), make(chan os.Signal, 1))

	// A link that carries the listener secret would plant it in a visible file.
	ops := &fakeConfigOperations{}
	e := newFlowEditorWithReload(t, main, true, ops, reload)
	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{
		Name: "leak",
		Link: "socks5://flow-secret@192.0.2.10:1080",
	}, emptyNodeIndex, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 403 || apiErr.Code != "permission_denied" {
		t.Fatalf("got %d %s, want 403 permission_denied", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("a refused write must not queue a reload")
	}

	// A reload in progress must refuse the write instead of racing it.
	reload.reloadActive.Store(true)
	defer reload.reloadActive.Store(false)
	_, err = e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{
		Name: "racy",
		Link: mockLink,
	}, emptyNodeIndex, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 409 || apiErr.Code != "state_conflict" {
		t.Fatalf("got %d %s, want 409 state_conflict", apiErr.Status, apiErr.Code)
	}
}

func TestConfigNodeCreateRefusesAnApiSectionInjection(t *testing.T) {
	// A newline in the link used to end the entry and start an api section,
	// which flipped the tree to layout_unmanaged and made every later write 404.
	main, _ := newManagedTree(t)
	ops := &fakeConfigOperations{}
	e := newFlowEditor(t, main, true, ops)
	injected := "socks5://192.0.2.10:1080\n}\napi {\n  secret: 'own'\n}\nnode {"
	_, err := e.CreateNode(context.Background(), nativeapi.NodeCreateRequest{Name: "evil", Link: injected}, emptyNodeIndex, nil)
	if apiErr := flowAPIError(t, err); apiErr.Status != 422 {
		t.Fatalf("got %d %s, want 422 unsupported_value", apiErr.Status, apiErr.Code)
	}
	if ops.calls != 0 {
		t.Fatal("a refused write must not queue a reload")
	}
}

func TestPublishSubscriptionHealthReportsTheOutcome(t *testing.T) {
	// A refresh that fell back to the cache must not read as a success, and the
	// registry must forget subscriptions the running config no longer defines.
	publishSubscriptionHealth(map[string]error{
		"subA": errors.New("subscription answered HTTP 500"),
		"subB": nil,
	})
	defer publishSubscriptionHealth(nil)

	record, ok := subscriptionHealth("subA")
	if !ok || record.err == "" {
		t.Fatalf("subA should report a failure, got %+v", record)
	}
	if record, ok := subscriptionHealth("subB"); !ok || record.err != "" {
		t.Fatalf("subB should report success, got %+v", record)
	}

	publishSubscriptionHealth(map[string]error{"subB": nil})
	if _, ok := subscriptionHealth("subA"); ok {
		t.Fatal("a subscription removed from the config must be forgotten")
	}
}

func TestInsertNodeEntrySurvivesAParseRoundTrip(t *testing.T) {
	// The fix has to hold at the parser, not just in the string: whatever
	// quoteNodeValue picks must parse back to exactly the original link.
	links := []string{
		"socks5://192.0.2.10:1080",
		`socks5://u:pa'ss@192.0.2.10:1080`,
		`socks5://u:pa"ss@192.0.2.10:1080`,
		`vless://id@192.0.2.10:443?security=tls&sni=example.com#tag'with"both`,
	}
	for _, link := range links {
		text, err := insertNodeEntry("node {\n}\n", "n1", link)
		if err == nil {
			// The written text must parse and carry the value unchanged.
			sections, parseErr := config_parser.Parse(text)
			if parseErr != nil {
				t.Fatalf("%q: written config does not parse: %v\n%s", link, parseErr, text)
			}
			got := ""
			for _, s := range sections {
				for _, item := range s.Items {
					if item.Type != config_parser.ItemType_Param {
						continue
					}
					if p := item.Value.(*config_parser.Param); p.Key == "n1" {
						got = p.Val
					}
				}
			}
			if got != link {
				t.Fatalf("value changed: got %q want %q\n%s", got, link, text)
			}
			continue
		}
		// A value the parser cannot express must be refused, never written.
		if strings.Contains(err.Error(), "cannot be written") && strings.Count(link, `'`) > 0 && strings.Count(link, `"`) > 0 {
			continue
		}
		t.Fatalf("%q: unexpected refusal: %v", link, err)
	}
}

func TestValidateNodeLinkRejectsOutOfRangePort(t *testing.T) {
	for _, link := range []string{
		"socks5://u:p@127.0.0.1:0",
		"socks5://u:p@127.0.0.1:65536",
	} {
		if _, err := validateNodeLink(context.Background(), logrus.New(), link); err == nil {
			t.Fatalf("validateNodeLink(%q) accepted a port outside 1..65535", link)
		}
	}
	if _, err := validateNodeLink(context.Background(), logrus.New(), "socks5://u:p@127.0.0.1:65535"); err != nil {
		t.Fatalf("validateNodeLink rejected port 65535: %v", err)
	}
}
