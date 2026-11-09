/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// nodeSourceName is the module that owns inline nodes in the managed layout.
// A node codex only lives here: nodes a subscription delivered are managed by
// that subscription and are never written back into the file.
const nodeSourceName = "node.dae"

// nodeBlockPattern matches the opening of the node section.
var nodeBlockPattern = sectionBlockPattern("node")

// nodeNamePattern is the name shape the configuration can quote and the
// frontend accepts: word characters, dots and dashes.
var nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// nodeSource returns the writable module that holds the node section.
func (e *configEditor) nodeSource(all []configSourceFile) (configSourceFile, error) {
	target := filepath.Join(e.baseDir, "config.d", nodeSourceName)
	for _, s := range all {
		if s.abs != target {
			continue
		}
		if !e.sourceWritable(s) {
			return configSourceFile{}, permissionDenied("this source is read-only", "entry_source")
		}
		return s, nil
	}
	return configSourceFile{}, &nativeapi.APIError{
		Status:  404,
		Code:    "capability_not_supported",
		Message: "the managed layout has no " + nodeSourceName,
	}
}

// validateNodeName rejects a name the configuration cannot carry as a bare key.
func validateNodeName(name string) error {
	if !nodeNamePattern.MatchString(name) {
		return fmt.Errorf("node name %q must be 1-64 characters of letters, digits, '_', '.' or '-'", name)
	}
	return nil
}

// validateNodeLink builds a dialer from the link, which is the same parse the
// reload performs, and then checks the address it produced. The dialer alone is
// not enough: a protocol dialer parses lazily, so a link without host and port
// still constructs and only fails when someone dials it. The returned id is the
// one the rest of the API derives from the same dialer, which a plugin link may
// normalize before it is hashed.
func validateNodeLink(ctx context.Context, log *logrus.Logger, link string) (string, error) {
	scheme := shareLinkScheme(link)
	if scheme == "" {
		return "", fmt.Errorf("the share link is not a URI")
	}
	// A share link is one line. A newline would end the entry early and let the
	// rest of the value become configuration of its own.
	if strings.ContainsAny(link, "\r\n\x00") {
		return scheme, fmt.Errorf("the share link must not contain control characters")
	}
	d, err := dialer.NewFromLinkContext(ctx, &dialer.GlobalOption{Log: log}, dialer.InstanceOption{DisableCheck: true}, link, "")
	if err != nil {
		// Every parser error quotes the link, and the link carries the credential.
		// Log only the scheme; the caller answers with a reason that names the
		// scheme as well, so nothing echoes the link back to the client either.
		log.WithField("scheme", scheme).Debugln("node link rejected")
		return scheme, fmt.Errorf("the share link is not a supported %s link", scheme)
	}
	if d == nil {
		return scheme, fmt.Errorf("unsupported share link")
	}
	defer func() { _ = d.Close() }()
	property := d.Property()
	if property == nil {
		return scheme, fmt.Errorf("the share link carries no node")
	}
	host, port, err := net.SplitHostPort(property.Address)
	if err != nil || host == "" || port == "" {
		return scheme, fmt.Errorf("the share link has no host and port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return scheme, fmt.Errorf("the share link has a port outside 1..65535")
	}
	return nodeIDOf(property), nil
}

// shareLinkScheme returns the lowercased URI scheme, or "" when the text is not
// a scheme:// URI.
func shareLinkScheme(link string) string {
	idx := strings.Index(link, "://")
	if idx <= 0 {
		return ""
	}
	scheme := strings.ToLower(link[:idx])
	for i, r := range scheme {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '+' && r != '-' && r != '.' {
			return ""
		}
		if i == 0 && !unicode.IsLetter(r) {
			return ""
		}
	}
	return scheme
}

// quoteNodeValue renders one configuration value as a quoted literal.
//
// The parser has no escape sequences: a `\` is data, and a quote character ends
// the literal. So the value picks the quote style it does not contain, and a
// value that contains both quote characters cannot be written at all. Writing it
// bare was the previous behaviour and let a `'` in a password close the literal
// so the rest of the link became configuration.
func quoteNodeValue(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("the node link must not contain control characters")
	}
	switch {
	case !strings.Contains(value, "'"):
		return "'" + value + "'", nil
	case !strings.Contains(value, `"`):
		return `"` + value + `"`, nil
	default:
		return "", fmt.Errorf(`the node link contains both ' and " and cannot be written as a configuration literal`)
	}
}

// insertNodeEntry adds one node line. An existing node block gets the line first,
// so the surrounding text, comments included, stays byte for byte as it was;
// a file without a node block gets one appended.
func insertNodeEntry(text, name, link string) (string, error) {
	quoted, err := quoteNodeValue(link)
	if err != nil {
		return "", err
	}
	// The name is written bare: validateNodeName has already restricted it to the
	// characters a configuration key may hold, so quoting would only add noise.
	entry := func(indent string) string {
		return indent + name + ": " + quoted + "\n"
	}
	if loc := nodeBlockPattern.FindStringIndex(text); loc != nil {
		// Insert after the newline that ends the "node {" line, so the entry is
		// the first thing inside the block and no blank line is introduced.
		insertAt := loc[1]
		if nl := strings.IndexByte(text[insertAt:], '\n'); nl >= 0 {
			insertAt += nl + 1
		}
		// Match the file's own indentation instead of imposing one, so a tree
		// written with a different style keeps its shape.
		return text[:insertAt] + entry(nodeBlockIndent(text, insertAt)) + text[insertAt:], nil
	}
	trimmed := strings.TrimRight(text, "\n")
	if trimmed == "" {
		return "node {\n" + entry("  ") + "}\n", nil
	}
	return trimmed + "\n\nnode {\n" + entry("  ") + "}\n", nil
}

// nodeBlockIndent returns the indentation the entries inside a node block use,
// defaulting to two spaces when the block has no entry to copy from.
func nodeBlockIndent(text string, from int) string {
	for _, line := range strings.Split(text[from:], "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "}") {
			if strings.HasPrefix(trimmed, "}") {
				break
			}
			continue
		}
		return line[:len(line)-len(trimmed)]
	}
	return "  "
}

// removeNodeEntry removes the line that defines name inside the node block.
// It reports whether anything was removed.
func removeNodeEntry(text, name string) (string, bool) {
	start := nodeBlockPattern.FindStringIndex(text)
	if start == nil {
		return text, false
	}
	open := strings.Index(text[start[0]:], "{") + start[0]
	closeIdx := matchingBrace(text, open)
	if closeIdx < 0 {
		return text, false
	}
	body := text[open+1 : closeIdx]
	lines := strings.SplitAfter(body, "\n")
	offset := open + 1
	for _, line := range lines {
		if key, ok := nodeLineKey(line); ok && key == name {
			return text[:offset] + text[offset+len(line):], true
		}
		offset += len(line)
	}
	return text, false
}

// updateNodeEntry rewrites the line that defines oldName, keeping the entry's
// indentation and any trailing comment. It reports whether the name was found.
func updateNodeEntry(text, oldName, newName, link string) (string, bool, error) {
	start := nodeBlockPattern.FindStringIndex(text)
	if start == nil {
		return text, false, nil
	}
	open := strings.Index(text[start[0]:], "{") + start[0]
	closeIdx := matchingBrace(text, open)
	if closeIdx < 0 {
		return text, false, nil
	}
	quoted, err := quoteNodeValue(link)
	if err != nil {
		return text, false, err
	}
	offset := open + 1
	for _, line := range strings.SplitAfter(text[open+1:closeIdx], "\n") {
		if key, ok := nodeLineKey(line); ok && key == oldName {
			rewritten := rewriteNodeLine(line, newName, quoted)
			return text[:offset] + rewritten + text[offset+len(line):], true, nil
		}
		offset += len(line)
	}
	return text, false, nil
}

// rewriteNodeLine replaces the key and value of one "name: value" line while
// keeping its indentation, the spacing after the colon and any trailing comment.
func rewriteNodeLine(line, name, quoted string) string {
	trimmed := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmed)]
	colon := strings.Index(trimmed, ":")
	if colon < 0 {
		return line
	}
	rest := trimmed[colon+1:]
	valueStart := len(rest) - len(strings.TrimLeft(rest, " \t"))
	return indent + name + ":" + rest[:valueStart] + quoted + nodeValueTail(rest[valueStart:])
}

// nodeValueTail returns what follows the value on the same line: a trailing
// comment and the line ending. A value that cannot be read returns "" so the
// rewrite drops it instead of copying it into the new line.
func nodeValueTail(value string) string {
	if value == "" {
		return ""
	}
	if value[0] == '\'' || value[0] == '"' {
		if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
			return value[end+2:]
		}
		return ""
	}
	for i := 0; i < len(value); i++ {
		if isNodeValueDelimiter(value[i]) {
			return value[i:]
		}
	}
	return ""
}

// isNodeValueDelimiter reports whether c ends an unquoted node value. The line
// ending is a delimiter too: an unquoted value runs to the end of the line, and
// dropping it would glue the next entry onto the rewritten one.
func isNodeValueDelimiter(c byte) bool {
	switch c {
	case '#', ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

// nodeLinkOf reads the link a node block defines under name. The managed line
// is the source of truth for an inline node's current link, which the runtime
// projection does not carry.
func nodeLinkOf(text, name string) (string, bool) {
	start := nodeBlockPattern.FindStringIndex(text)
	if start == nil {
		return "", false
	}
	open := strings.Index(text[start[0]:], "{") + start[0]
	closeIdx := matchingBrace(text, open)
	if closeIdx < 0 {
		return "", false
	}
	for _, line := range strings.Split(text[open+1:closeIdx], "\n") {
		if key, ok := nodeLineKey(line); ok && key == name {
			return nodeLineValue(line)
		}
	}
	return "", false
}

// nodeLineValue returns the value of a "name: value" line without its quotes.
func nodeLineValue(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	colon := strings.Index(trimmed, ":")
	if colon < 0 {
		return "", false
	}
	rest := strings.TrimLeft(trimmed[colon+1:], " \t")
	if rest == "" {
		return "", false
	}
	if rest[0] == '\'' || rest[0] == '"' {
		if end := strings.IndexByte(rest[1:], rest[0]); end >= 0 {
			return rest[1 : 1+end], true
		}
		return "", false
	}
	for i := 0; i < len(rest); i++ {
		if isNodeValueDelimiter(rest[i]) {
			return rest[:i], true
		}
	}
	return rest, true
}

// nodeLineKey returns the key of a "name: value" line.
func nodeLineKey(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	colon := strings.Index(trimmed, ":")
	if colon <= 0 {
		return "", false
	}
	key := strings.TrimSpace(trimmed[:colon])
	if len(key) >= 2 {
		if (key[0] == '\'' && key[len(key)-1] == '\'') || (key[0] == '"' && key[len(key)-1] == '"') {
			key = key[1 : len(key)-1]
		}
	}
	return key, true
}

// matchingBrace returns the index of the "}" closing the "{" at open, skipping
// quoted text and comments.
func matchingBrace(text string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// nodeRef is one node the running generation holds.
type nodeRef struct {
	Name       string
	ProviderID string
}

// nodeIndexFunc returns the running generation's nodes keyed by node ID. It lets
// a create reject a name any provider already uses - names are global - and a
// delete know whether the node belongs to the managed file.
type nodeIndexFunc func() (map[string]nodeRef, error)

// inlineNodeNames reads the names the managed node source defines.
func inlineNodeNames(text string) map[string]bool {
	names := map[string]bool{}
	start := nodeBlockPattern.FindStringIndex(text)
	if start == nil {
		return names
	}
	open := strings.Index(text[start[0]:], "{") + start[0]
	closeIdx := matchingBrace(text, open)
	if closeIdx < 0 {
		return names
	}
	for _, line := range strings.Split(text[open+1:closeIdx], "\n") {
		if key, ok := nodeLineKey(line); ok {
			names[key] = true
		}
	}
	return names
}

// inlineNodeLinks maps every link the node block defines to the name that
// defines it. A relink must not reuse a link: the API derives a node's identity
// from its link, so two entries with one link collapse into one node.
func inlineNodeLinks(text string) map[string]string {
	links := map[string]string{}
	start := nodeBlockPattern.FindStringIndex(text)
	if start == nil {
		return links
	}
	open := strings.Index(text[start[0]:], "{") + start[0]
	closeIdx := matchingBrace(text, open)
	if closeIdx < 0 {
		return links
	}
	for _, line := range strings.Split(text[open+1:closeIdx], "\n") {
		name, ok := nodeLineKey(line)
		if !ok {
			continue
		}
		if link, ok := nodeLineValue(line); ok {
			links[link] = name
		}
	}
	return links
}

// commitSourceUpdate validates content as the next configuration, backs up the
// current bytes and queues kind. A failed start restores the previous bytes,
// because no operation will ever read the rejected edit.
func (e *configEditor) commitSourceUpdate(ctx context.Context, target configSourceFile, content []byte, kind, idempotencyKey, fingerprint string, resolve func() (any, error)) (nativeapi.OperationAccepted, error) {
	scope := sourceUpdateScope(target.abs, fingerprint)
	if accepted, replayed, err := e.replaySourceUpdate(kind, scope, idempotencyKey); err != nil || replayed {
		return accepted, err
	}
	if err := e.guardConfigWrite(target, content); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	candidate, err := e.buildCandidate(map[string][]byte{target.abs: content}, nil)
	if err != nil {
		return nativeapi.OperationAccepted{}, e.unprocessable(err, target)
	}
	if err := e.fullValidate(candidate); err != nil {
		return nativeapi.OperationAccepted{}, e.unprocessable(err, target)
	}
	if err := e.guardApiUnchanged(candidate); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	return e.commitValidatedSource(ctx, target, content, kind, scope, idempotencyKey, resolve)
}

// commitValidatedSource writes an already validated candidate, queues its
// operation and restores the previous bytes if the operation cannot start. The
// config PUT and node write paths share it so their guard/backup/rollback
// sequence cannot drift apart.
func (e *configEditor) commitValidatedSource(
	ctx context.Context,
	target configSourceFile,
	content []byte,
	kind, scope, idempotencyKey string,
	resolve func() (any, error),
) (nativeapi.OperationAccepted, error) {
	mode := os.FileMode(0o600)
	if fi, statErr := os.Stat(target.abs); statErr == nil {
		mode = fi.Mode().Perm()
	}
	// Hold the read lock across write, queue and rollback: the reload worker
	// must not read this candidate while it is still owned by an admission that
	// may reject it.
	unlockRead := e.lockConfigRead()
	defer unlockRead()
	if err := writeFileAtomic(target.abs+".bak", target.raw, 0o600); err != nil {
		return nativeapi.OperationAccepted{}, fmt.Errorf("write config backup: %w", err)
	}
	if err := writeFileAtomic(target.abs, content, mode); err != nil {
		return nativeapi.OperationAccepted{}, fmt.Errorf("write config source: %w", err)
	}
	accepted, err := e.operations.StartOperationWithResult(ctx, kind, scope, idempotencyKey, resolve)
	if err != nil {
		if restoreErr := writeFileAtomic(target.abs, target.raw, mode); restoreErr != nil {
			e.log.WithError(restoreErr).Error("failed to restore config source after rejected operation")
		}
		return nativeapi.OperationAccepted{}, err
	}
	return accepted, nil
}

// CreateNode writes one inline node into the managed node source. resolve turns
// the completed operation into the Node body the contract asks for; it is
// installed with the operation, before the reload is queued.
func (e *configEditor) CreateNode(ctx context.Context, req nativeapi.NodeCreateRequest, index nodeIndexFunc, resolve func() (any, error)) (nativeapi.OperationAccepted, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	fingerprint := rawSHA256([]byte("node_create\x00" + req.Name + "\x00" + req.Link))
	if err := validateNodeName(req.Name); err != nil {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}
	// The reason is built from sanitized parts only: it never echoes the link,
	// which may carry a credential.
	if _, err := validateNodeLink(ctx, e.log, req.Link); err != nil {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if ok, _ := e.layoutOK(all); !ok {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "node management is not supported by this engine",
		}
	}
	target, err := e.nodeSource(all)
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindNodeCreate, sourceUpdateScope(target.abs, fingerprint), req.IdempotencyKey); err != nil || replayed {
		return accepted, err
	}
	if err := e.rejectDuplicateNodeName(index, target, req.Name); err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	updated, err := insertNodeEntry(string(target.raw), req.Name, req.Link)
	if err != nil {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}
	return e.commitSourceUpdate(ctx, target, []byte(updated), nativeapi.OperationKindNodeCreate, req.IdempotencyKey, fingerprint, resolve)
}

// rejectDuplicateNodeName enforces global uniqueness: a name may not collide
// with any node of any provider, nor with an entry already written but not yet
// loaded.
func (e *configEditor) rejectDuplicateNodeName(index nodeIndexFunc, target configSourceFile, name string) error {
	taken := inlineNodeNames(string(target.raw))
	if index != nil {
		refs, err := index()
		if err != nil {
			return err
		}
		for _, ref := range refs {
			taken[ref.Name] = true
		}
	}
	if taken[name] {
		return &nativeapi.APIError{
			Status: 409, Code: "state_conflict",
			Message: "An inline node named " + name + " already exists",
		}
	}
	return nil
}

// nodeUpdateFingerprint binds an Idempotency-Key to one node and one pair of
// proposed values, with an explicit marker so a missing value cannot collide
// with an empty one.
func nodeUpdateFingerprint(req nativeapi.NodeUpdateRequest) string {
	name, link := "\x00", "\x00"
	if req.Name != nil {
		name = "\x01" + *req.Name
	}
	if req.Link != nil {
		link = "\x01" + *req.Link
	}
	return rawSHA256([]byte("node_update\x00" + req.NodeID + "\x00" + name + "\x00" + link))
}

// UpdateNode rewrites one inline node's line in the managed node source. A nil
// Name or Link keeps the current value. The write reuses the config PUT guards
// (listener secret, API section, running reload) and the create path's
// validation, and a patch that names the values the node already has writes
// nothing and starts no reload. resolve receives the node id the reload will
// publish, which the write itself computes from the effective link.
func (e *configEditor) UpdateNode(ctx context.Context, req nativeapi.NodeUpdateRequest, index nodeIndexFunc, resolve func(nodeID string) (any, error)) (nativeapi.NodeUpdateOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.NodeUpdateOutcome{}, err
	}
	fingerprint := nodeUpdateFingerprint(req)

	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.NodeUpdateOutcome{}, err
	}
	if ok, _ := e.layoutOK(all); !ok {
		return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "node management is not supported by this engine",
		}
	}
	target, err := e.nodeSource(all)
	if err != nil {
		return nativeapi.NodeUpdateOutcome{}, err
	}
	// A retry must replay before the node lookup: a link change moves the node
	// id, and a completed update must answer the original operation instead of
	// 404/409/200-updated-0 depending on how far the reload has got.
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindNodeUpdate, sourceUpdateScope(target.abs, fingerprint), req.IdempotencyKey); err != nil || replayed {
		return nativeapi.NodeUpdateOutcome{Accepted: accepted, Updated: 1}, err
	}
	refs, err := e.nodeRefs(index)
	if err != nil {
		return nativeapi.NodeUpdateOutcome{}, err
	}
	ref, found := refs[req.NodeID]
	if !found {
		return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
			Status: 404, Code: "resource_not_found", Message: "node not found",
		}
	}
	// Check ownership before touching the file. Editing by name first would
	// rewrite an inline node that merely shares the name with the subscription
	// node the caller named, because names are global.
	if ref.ProviderID != inlineProviderID {
		return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "Only inline nodes can be updated; edit the provider instead",
		}
	}
	currentLink, found := nodeLinkOf(string(target.raw), ref.Name)
	if !found {
		// The generation may be ahead of the file (a write that has not
		// reloaded yet), or the entry is a keyless link, which has no name to
		// address. Neither can be edited from here.
		return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
			Status: 409, Code: "state_conflict",
			Message: "the managed node source has no editable \"name: link\" entry for this node; reload or edit the file directly",
		}
	}
	name, link := ref.Name, currentLink
	if req.Name != nil {
		name = *req.Name
	}
	if req.Link != nil {
		link = *req.Link
	}
	if name == ref.Name && link == currentLink {
		return nativeapi.NodeUpdateOutcome{}, nil
	}

	// Values are validated only once the node is known to be editable, so an
	// unknown id or a provider-owned node answers 404 rather than 422. The
	// returned id is what the reload will publish after the write.
	if req.Name != nil {
		if err := validateNodeName(name); err != nil {
			return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
				Status: 422, Code: "unsupported_value", Message: err.Error(),
			}
		}
	}
	nodeID, err := validateNodeLink(ctx, e.log, link)
	if err != nil {
		// The reason is built from sanitized parts only: it never echoes the
		// link, which may carry a credential.
		return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}
	if link != currentLink {
		// The API identifies a node by its link, so reusing a link would merge
		// two entries into one node and leave one of them unmanageable.
		if owner, taken := inlineNodeLinks(string(target.raw))[link]; taken && owner != ref.Name {
			return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
				Status: 409, Code: "state_conflict", Message: "Another inline node already uses this link",
			}
		}
		if nodeID != req.NodeID {
			if _, taken := refs[nodeID]; taken {
				return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
					Status: 409, Code: "state_conflict", Message: "Another node already uses this link",
				}
			}
		}
	}
	if name != ref.Name {
		if err := e.rejectDuplicateNodeName(index, target, name); err != nil {
			return nativeapi.NodeUpdateOutcome{}, err
		}
	}
	updated, found, err := updateNodeEntry(string(target.raw), ref.Name, name, link)
	if err != nil {
		return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
			Status: 422, Code: "unsupported_value", Message: err.Error(),
		}
	}
	if !found {
		return nativeapi.NodeUpdateOutcome{}, &nativeapi.APIError{
			Status: 409, Code: "state_conflict", Message: "the node is not defined in the managed node source; reload to reconcile",
		}
	}
	accepted, err := e.commitSourceUpdate(ctx, target, []byte(updated), nativeapi.OperationKindNodeUpdate, req.IdempotencyKey, fingerprint, func() (any, error) {
		return resolve(nodeID)
	})
	if err != nil {
		return nativeapi.NodeUpdateOutcome{}, err
	}
	return nativeapi.NodeUpdateOutcome{Accepted: accepted, Updated: 1}, nil
}

// DeleteNode removes one inline node from the managed node source. resolve
// reports the deletion count for the completed operation.
func (e *configEditor) DeleteNode(ctx context.Context, req nativeapi.NodeDeleteRequest, index nodeIndexFunc, resolve func() (any, error)) (nativeapi.NodeDeleteOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.NodeDeleteOutcome{}, err
	}
	fingerprint := rawSHA256([]byte("node_delete\x00" + req.NodeID))

	e.mu.Lock()
	defer e.mu.Unlock()
	all, err := e.loadSources()
	if err != nil {
		return nativeapi.NodeDeleteOutcome{}, err
	}
	if ok, _ := e.layoutOK(all); !ok {
		return nativeapi.NodeDeleteOutcome{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "node management is not supported by this engine",
		}
	}
	target, err := e.nodeSource(all)
	if err != nil {
		return nativeapi.NodeDeleteOutcome{}, err
	}
	if accepted, replayed, err := e.replaySourceUpdate(nativeapi.OperationKindNodeDelete, sourceUpdateScope(target.abs, fingerprint), req.IdempotencyKey); err != nil || replayed {
		return nativeapi.NodeDeleteOutcome{Accepted: accepted, Deleted: 1}, err
	}
	ref, found, err := e.lookupNode(index, req.NodeID)
	if err != nil {
		return nativeapi.NodeDeleteOutcome{}, err
	}
	if !found {
		// Idempotent: the id names nothing the engine knows.
		return nativeapi.NodeDeleteOutcome{}, nil
	}
	// Check ownership before touching the file. Editing by name first would
	// delete an inline node that merely shares the name with the subscription
	// node the caller named, because names are global.
	if ref.ProviderID != inlineProviderID {
		// A subscription or file provider owns this node: refresh or delete
		// that provider instead.
		return nativeapi.NodeDeleteOutcome{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "Only inline nodes can be deleted; refresh or delete the provider instead",
		}
	}
	updated, removed := removeNodeEntry(string(target.raw), ref.Name)
	if !removed {
		// The index came from the running generation, which may still hold a
		// node the file no longer defines (an edit that has not reloaded yet).
		return nativeapi.NodeDeleteOutcome{}, nil
	}
	accepted, err := e.commitSourceUpdate(ctx, target, []byte(updated), nativeapi.OperationKindNodeDelete, req.IdempotencyKey, fingerprint, resolve)
	if err != nil {
		return nativeapi.NodeDeleteOutcome{}, err
	}
	return nativeapi.NodeDeleteOutcome{Accepted: accepted, Deleted: 1}, nil
}

func (e *configEditor) lookupNode(index nodeIndexFunc, nodeID string) (nodeRef, bool, error) {
	refs, err := e.nodeRefs(index)
	if err != nil {
		return nodeRef{}, false, err
	}
	ref, ok := refs[nodeID]
	return ref, ok, nil
}

// nodeRefs snapshots the running generation's node index.
func (e *configEditor) nodeRefs(index nodeIndexFunc) (map[string]nodeRef, error) {
	if index == nil {
		return nil, nil
	}
	return index()
}
