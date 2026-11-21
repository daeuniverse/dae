/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

type sip008 struct {
	Version        int            `json:"version"`
	Servers        []sip008Server `json:"servers"`
	BytesUsed      int64          `json:"bytes_used"`
	BytesRemaining int64          `json:"bytes_remaining"`
}

type sip008Server struct {
	Id         string `json:"id"`
	Remarks    string `json:"remarks"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Plugin     string `json:"plugin"`
	PluginOpts string `json:"plugin_opts"`
}

func ResolveSubscriptionAsBase64(log *logrus.Logger, b []byte) (nodes []string) {
	log.Debugln("Try to resolve as base64")

	// base64 decode
	raw, e := common.Base64StdDecode(string(b))
	if e != nil {
		raw, _ = common.Base64UrlDecode(string(b))
	}

	// Simply check and preprocess.
	lines := strings.SplitSeq(raw, "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !isShareLinkLine(line) {
			continue
		}
		nodes = append(nodes, line)
	}
	return nodes
}

// isShareLinkLine reports whether a line is shaped like a share link: a scheme
// token, "://", then a non-empty remainder. Cutting the line at the first
// "://" anywhere is not enough: an HTML login page (`<a href="https://...">`)
// would otherwise count as one node and replace the cached subscription with a
// page no dialer can load.
func isShareLinkLine(line string) bool {
	i := strings.Index(line, "://")
	if i <= 0 || i+3 == len(line) {
		return false
	}
	// A subscription may name a node before the link: "edge:socks5://...".
	// The downstream outbound parser strips that tag before reading the scheme,
	// so the filter must validate the scheme after the last colon rather than
	// rejecting the line outright. Without this, every named node disappeared
	// from a plaintext subscription.
	schemeStart := 0
	for j := 0; j < i; j++ {
		if line[j] == ':' {
			schemeStart = j + 1
		}
	}
	if schemeStart >= i {
		return false
	}
	if schemeStart > 0 {
		// The tag itself must be one token: a second colon means the line is
		// malformed, not a tag followed by a scheme.
		for j := 0; j < schemeStart-1; j++ {
			if line[j] == ' ' || line[j] == '\t' || line[j] == ':' {
				return false
			}
		}
	}
	for j := schemeStart; j < i; j++ {
		c := line[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j == schemeStart:
			return false
		case c >= '0' && c <= '9', c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

func ResolveSubscriptionAsSIP008(log *logrus.Logger, b []byte) (nodes []string, err error) {
	log.Debugln("Try to resolve as sip008")

	var sip sip008
	err = json.Unmarshal(b, &sip)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json to sip008")
	}
	if sip.Version != 1 || sip.Servers == nil {
		return nil, fmt.Errorf("does not seems like a standard sip008 subscription")
	}
	for _, server := range sip.Servers {
		query := make(url.Values)
		if server.Plugin != "" {
			plugin := server.Plugin
			if server.PluginOpts != "" {
				plugin += ";" + server.PluginOpts
			}
			query.Set("plugin", plugin)
		}
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(server.Method + ":" + server.Password))
		u := url.URL{
			Scheme:   "ss",
			User:     url.User(userinfo),
			Host:     net.JoinHostPort(server.Server, strconv.Itoa(server.ServerPort)),
			RawQuery: query.Encode(),
			Fragment: server.Remarks,
		}
		nodes = append(nodes, u.String())
	}
	return nodes, nil
}

func ResolveFile(u *url.URL, configDir string) (b []byte, err error) {
	if u.Host == "" {
		return nil, fmt.Errorf("not support absolute path")
	}
	/// Relative location.
	// Make sure path is secure.
	path := filepath.Join(configDir, u.Host, u.Path)
	if err = common.EnsureFileInSubDir(path, configDir); err != nil {
		return nil, err
	}
	/// Read and resolve.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// Check file access.
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("subscription file cannot be a directory: %v", path)
	}
	if fi.Mode()&0037 > 0 {
		return nil, fmt.Errorf("permissions %04o for '%v' are too open; requires the file is NOT writable by the same group and NOT accessible by others; suggest 0640 or 0600", fi.Mode()&0777, path)
	}
	// Resolve the first line instruction.
	fReader := bufio.NewReader(f)
	b, err = fReader.Peek(1)
	if err != nil {
		return nil, err
	}
	if string(b[0]) == "@" {
		// Instruction line. But not support yet.
		_, _, err = fReader.ReadLine()
		if err != nil {
			return nil, err
		}
	}

	b, err = io.ReadAll(fReader)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), err
}

// Resolution is one subscription refresh. CacheFallback is set when the fetch
// failed and the returned nodes are the last good copy, so a caller can report
// the subscription as stale instead of as refreshed.
type Resolution struct {
	Tag           string
	Nodes         []string
	CacheFallback bool
	FetchErr      error
	// Payload is the fetched body when the fetch succeeded. The caller owns
	// persisting it: a body only replaces the cached copy after the links
	// actually became dialers, otherwise an unusable payload would destroy the
	// last good copy.
	Payload []byte
	// CacheKey names the persisted copy of this subscription. Empty for a file
	// subscription, which is not cached.
	CacheKey string
}

// ResolveSubscription keeps the tag/nodes/error shape for callers that do not
// need to distinguish a cached fallback from a real refresh.
func ResolveSubscription(log *logrus.Logger, client *http.Client, configDir string, subscription string) (tag string, nodes []string, err error) {
	result, err := Resolve(log, client, configDir, subscription)
	return result.Tag, result.Nodes, err
}

// Resolve refreshes one subscription and reports whether the nodes came from the
// cache.
func Resolve(log *logrus.Logger, client *http.Client, configDir string, subscription string) (Resolution, error) {
	/// Get tag.
	tag, subscription := common.GetTagFromLinkLikePlaintext(subscription)
	result := Resolution{Tag: tag}

	/// Parse url.
	u, err := url.Parse(subscription)
	if err != nil {
		// The parser error quotes the link it could not parse, and a
		// subscription URL is a credential. Redact both the message and the
		// error text instead of wrapping the raw error, which would carry the
		// URL into every caller and every log line that prints it.
		redacted := common.RedactURL(subscription)
		return result, fmt.Errorf("failed to parse subscription %s: %s",
			redacted, strings.ReplaceAll(err.Error(), subscription, redacted))
	}
	log.Debugf("ResolveSubscription: %v", common.RedactURL(subscription))

	switch u.Scheme {
	case "file":
		b, err := ResolveFile(u, configDir)
		if err != nil {
			return result, err
		}
		result.Nodes, err = resolveSubscriptionNodes(log, b)
		return result, err
	case "http-file", "https-file":
		if len(tag) == 0 {
			return result, fmt.Errorf("tag is required for http-file/https-file subscription")
		}
		subscription = strings.Replace(subscription, "-file", "", 1)
	default:
	}

	// Every remote subscription is cached, tagged or not: the cached copy is
	// what the running generation is already forwarding, so losing it turns a
	// transient fetch failure into an outage.
	cacheKey := CacheKey(tag, subscription)
	cachePath := filepath.Join(configDir, "persist.d", cacheKey+".sub")
	result.CacheKey = cacheKey

	fetched, fetchErr := fetchSubscription(client, subscription)
	if fetchErr == nil {
		nodes, verr := resolveSubscriptionNodes(log, fetched)
		if verr == nil {
			// The caller persists the body only after the links became
			// dialers. Writing here would let a login page or a link-shaped
			// payload that no protocol accepts replace a good copy.
			result.Nodes = nodes
			result.Payload = fetched
			return result, nil
		}
		fetchErr = verr
	}
	// A transport error quotes the request URL, so the failure text carries the
	// subscription token. Redact before it reaches a log line or an API status.
	fetchErr = fmt.Errorf("%s", common.RedactInlineURLs(fetchErr.Error()))

	// The fetch failed or the payload was unusable. Keep the last good nodes
	// instead of dropping them: the generation already runs on them, and a
	// failed refresh must not cut proxied traffic.
	if cached, cacheErr := os.ReadFile(cachePath); cacheErr == nil {
		if cachedNodes, resolveErr := resolveSubscriptionNodes(log, cached); resolveErr == nil {
			log.Warnf(`failed to refresh subscription "%v": %v; keeping %d cached node(s)`, common.RedactURL(subscription), fetchErr, len(cachedNodes))
			result.Nodes = cachedNodes
			result.CacheFallback = true
			result.FetchErr = fetchErr
			return result, nil
		}
	}
	return result, fetchErr
}

// CacheKey names the persisted copy of one subscription: a tagged subscription
// keeps its tag, which is the historical name; an untagged one is keyed by its
// URL so it can be cached too.
func CacheKey(tag, subscription string) string {
	return ProviderKey(tag, subscription)
}

// ProviderKey is the stable identity of one configured subscription: its tag
// when it has one, otherwise a key derived from its URL. The same value names
// the cached copy and the provider that owns the subscription's nodes, so an
// untagged subscription no longer shares the inline provider's identity and its
// nodes cannot be deleted as if they were inline nodes.
func ProviderKey(tag, subscription string) string {
	if tag != "" {
		return tag
	}
	_, link := common.GetTagFromLinkLikePlaintext(subscription)
	link = normalizeRemoteSubscription(link)
	sum := sha256.Sum256([]byte(link))
	return "sub_" + hex.EncodeToString(sum[:8])
}

// normalizeRemoteSubscription mirrors the http-file/https-file rewrite Resolve
// applies before deriving the cache key, so every caller computes one key.
func normalizeRemoteSubscription(subscription string) string {
	u, err := url.Parse(subscription)
	if err != nil {
		return subscription
	}
	switch u.Scheme {
	case "http-file", "https-file":
		return strings.Replace(subscription, "-file", "", 1)
	}
	return subscription
}

// fetchSubscription performs the HTTP GET and rejects a non-2xx answer. A 500 or
// a 200 login page both have to count as a failed refresh; without the status
// check a 500 body parsed as "0 nodes" and the caller could not tell the
// difference from an intentionally empty subscription.
func fetchSubscription(client *http.Client, subscription string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, subscription, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("dae/%v (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)", config.Version))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("subscription answered HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max subscription size
}

// resolveSubscriptionNodes parses a subscription payload and refuses an empty
// result, which is what a login page or garbage resolves to.
func resolveSubscriptionNodes(log *logrus.Logger, b []byte) ([]string, error) {
	nodes, err := ResolveSubscriptionAsSIP008(log, b)
	if err != nil {
		log.Debugln(err)
		nodes = ResolveSubscriptionAsBase64(log, b)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("subscription resolved to 0 nodes")
	}
	return nodes, nil
}

// writeSubscriptionCache stores the fetched payload for the next failure.
func writeSubscriptionCache(configDir, cachePath string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		return err
	}
	return os.WriteFile(cachePath, b, 0600)
}

// PersistPayload stores a fetched body as the subscription's cached copy. The
// control plane calls it once the body's links have become dialers, so a payload
// nobody can load never replaces a good copy.
func PersistPayload(configDir, cacheKey string, b []byte) error {
	return writeSubscriptionCache(configDir, filepath.Join(configDir, "persist.d", cacheKey+".sub"), b)
}
