/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/subscription"
	"github.com/daeuniverse/dae/component/nativeapi"
	"github.com/sirupsen/logrus"
)

// inlineProviderID is the provider ID of the node section. It is the ID a node
// carries when no subscription delivered it, so it is also the ownership test
// for inline management.
const inlineProviderID = "p_inline"

// subscriptionHealth records the last refresh outcome per subscription tag.
//
// A refresh that fell back to the cached copy kept traffic alive but did not
// refresh anything, and a failed fetch that had no cache produced no nodes at
// all. Provider metadata is the only place a client can see either, so the
// resolution loop records the outcome here and providers() reports it.
type subscriptionHealthRecord struct {
	err string
	// updatedAt is the last successful load or refresh, which is what the
	// contract calls updated_at. A failed refresh keeps the previous value:
	// reporting the attempt time made a failure look like a refresh.
	updatedAt time.Time
}

var subscriptionHealthRegistry = struct {
	mu      sync.Mutex
	records map[string]subscriptionHealthRecord
}{records: map[string]subscriptionHealthRecord{}}

// publishSubscriptionHealth replaces the registry with one generation's outcome
// map. Replacing rather than merging also forgets subscriptions the running
// configuration no longer defines. A nil error marks a refreshed subscription.
func publishSubscriptionHealth(outcomes map[string]error) {
	now := time.Now()
	subscriptionHealthRegistry.mu.Lock()
	defer subscriptionHealthRegistry.mu.Unlock()
	previous := subscriptionHealthRegistry.records
	records := make(map[string]subscriptionHealthRecord, len(outcomes))
	for tag, err := range outcomes {
		if tag == "" {
			continue
		}
		record := subscriptionHealthRecord{}
		// Carry the last success across generations: this map is replaced on
		// every build, and a failed refresh must not forget when the copy that
		// is still running was loaded.
		if prev, ok := previous[tag]; ok {
			record.updatedAt = prev.updatedAt
		}
		if err != nil {
			record.err = sanitizeLogMessage(err.Error())
		} else {
			record.updatedAt = now
		}
		records[tag] = record
	}
	subscriptionHealthRegistry.records = records
}

// subscriptionHealth returns the last recorded outcome for a tag.
func subscriptionHealth(tag string) (subscriptionHealthRecord, bool) {
	subscriptionHealthRegistry.mu.Lock()
	defer subscriptionHealthRegistry.mu.Unlock()
	record, ok := subscriptionHealthRegistry.records[tag]
	return record, ok
}

// providerIDOf turns a subscription tag into the opaque, stable provider ID
// shared with Node.provider_id. The empty tag is the inline provider that
// carries the node section and any untagged subscription.
func providerIDOf(tag string) string {
	if tag == "" {
		return inlineProviderID
	}
	sum := sha256.Sum256([]byte(tag))
	return "p_" + hex.EncodeToString(sum[:8])
}

func providerNameOf(key, tag string) string {
	if tag != "" {
		return tag
	}
	if key == "" {
		return "inline"
	}
	// An untagged subscription has no configured name; its derived identity is
	// the only stable label a client can use.
	return key
}

// providers projects the accepted configuration onto provider metadata. Node
// counts come from the running generation's dialers, so a provider with no
// usable node reports status stale without inventing an update time.
func (p *nativeAPIProvider) providers(active *nativeActiveGeneration) ([]nativeapi.Provider, error) {
	nodes, err := active.nodes("")
	if err != nil {
		return nil, err
	}

	type definition struct {
		kind string
		url  string
		tag  string
	}
	// Keyed by provider identity: a configured subscription tag, or the
	// URL-derived key of an untagged subscription. The inline node section keeps
	// the empty key, so an untagged subscription no longer collapses into it.
	definitions := make(map[string]definition)
	if active.conf != nil {
		for _, raw := range active.conf.Subscription {
			tag, link := common.GetTagFromLinkLikePlaintext(string(raw))
			key := subscription.ProviderKey(tag, string(raw))
			if _, exists := definitions[key]; !exists {
				definitions[key] = definition{kind: "subscription", url: link, tag: tag}
			}
		}
		if len(active.conf.Node) > 0 {
			// The node section is the inline provider; it wins over an
			// untagged subscription because inline nodes are editable and the
			// frontend uses kind inline to decide that.
			definitions[""] = definition{kind: "inline"}
		}
	}
	keyByProviderID := make(map[string]string, len(definitions))
	for key := range definitions {
		keyByProviderID[providerIDOf(key)] = key
	}
	counts := make(map[string]int, len(definitions))
	for _, node := range nodes {
		providerID := inlineProviderID
		if node.ProviderID != nil {
			providerID = *node.ProviderID
		}
		key, ok := keyByProviderID[providerID]
		if !ok {
			// A node whose provider is no longer in the accepted configuration
			// still has to appear somewhere; its own ID is the stable name
			// left for it.
			key = providerID
			definitions[key] = definition{kind: "subscription"}
			keyByProviderID[providerID] = key
		}
		counts[key]++
	}

	providers := make([]nativeapi.Provider, 0, len(definitions))
	for key, definition := range definitions {
		provider := nativeapi.Provider{
			ID:        providerIDOf(key),
			Name:      providerNameOf(key, definition.tag),
			Kind:      definition.kind,
			NodeCount: uint64(counts[key]),
			Status:    "stale",
		}
		if provider.NodeCount > 0 {
			provider.Status = "ok"
		}
		// A refresh that fell back to the cached nodes, or failed outright, is
		// not a success: the contract has last_error and updated_at so a client
		// can tell the two apart.
		if health, ok := subscriptionHealth(key); ok {
			if !health.updatedAt.IsZero() {
				updatedAt := health.updatedAt.UTC().Format(time.RFC3339)
				provider.UpdatedAt = &updatedAt
			}
			if health.err != "" {
				provider.Status = "stale"
				provider.LastError = &nativeapi.SafeError{Code: "fetch_failed", Message: health.err}
			}
		}
		if definition.url != "" {
			// The field is what a client may display: the userinfo and query of
			// a subscription URL carry its token, so they must not survive here
			// even though the API is authenticated.
			url := common.RedactURL(definition.url)
			provider.URLRedacted = &url
		}
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool {
		if providers[i].Name != providers[j].Name {
			return providers[i].Name < providers[j].Name
		}
		return providers[i].ID < providers[j].ID
	})
	return providers, nil
}

// ListProviders serves one page of provider metadata.
func (p *nativeAPIProvider) ListProviders(ctx context.Context, limit int, cursor string) (nativeapi.ProviderList, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.ProviderList{}, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nativeapi.ProviderList{}, err
	}
	providers, err := p.providers(active)
	if err != nil {
		return nativeapi.ProviderList{}, err
	}
	offset := 0
	if cursor != "" {
		decoded, ok := decodeNodeCursor(cursor)
		if !ok || decoded.generation != active.generation.id || decoded.offset > len(providers) {
			return nativeapi.ProviderList{}, nativeapi.NewAPIError(410, "snapshot_expired", "cursor does not belong to the current provider snapshot")
		}
		offset = decoded.offset
	}
	end := offset + limit
	if end > len(providers) {
		end = len(providers)
	}
	page := nativeapi.ProviderList{Providers: providers[offset:end]}
	if end < len(providers) {
		next := encodeNodeCursor(nodeCursor{generation: active.generation.id, offset: end})
		page.NextCursor = &next
	}
	return page, nil
}

// GetProvider returns one provider by its opaque ID.
func (p *nativeAPIProvider) GetProvider(ctx context.Context, providerID string) (*nativeapi.Provider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nil, err
	}
	providers, err := p.providers(active)
	if err != nil {
		return nil, err
	}
	for i := range providers {
		if providers[i].ID == providerID {
			provider := providers[i]
			return &provider, nil
		}
	}
	return nil, nativeapi.NewAPIError(404, "resource_not_found", "provider not found")
}

type geoAssetCache struct {
	size    int64
	modTime time.Time
	sha256  string
}

// GeoData reports the geodata files the running configuration loads.
func (p *nativeAPIProvider) GeoData(ctx context.Context) (nativeapi.GeoData, error) {
	if err := ctx.Err(); err != nil {
		return nativeapi.GeoData{}, err
	}
	observed := time.Now().UTC().Format(time.RFC3339)
	result := nativeapi.GeoData{ObservedAt: observed, Assets: []nativeapi.GeoAsset{}}
	logger := p.log
	if logger == nil {
		logger = logrus.New()
	}
	finder := assets.NewLocationFinder(p.geoDirs)
	for _, kind := range []string{"geoip", "geosite"} {
		filename := kind + ".dat"
		path, err := finder.GetLocationAsset(logger, filename)
		if err != nil {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		digest, err := p.geoFileDigest(path, info)
		if err != nil {
			continue
		}
		asset := nativeapi.GeoAsset{
			Kind:      kind,
			SHA256:    digest,
			SizeBytes: strconv.FormatInt(info.Size(), 10),
		}
		if !info.ModTime().IsZero() {
			modified := info.ModTime().UTC().Format(time.RFC3339)
			asset.ModifiedAt = &modified
		}
		result.Assets = append(result.Assets, asset)
	}
	return result, nil
}

func (p *nativeAPIProvider) geoFileDigest(path string, info os.FileInfo) (string, error) {
	p.geoMu.Lock()
	if p.geoCache == nil {
		p.geoCache = make(map[string]geoAssetCache)
	}
	cached, ok := p.geoCache[path]
	p.geoMu.Unlock()
	if ok && cached.size == info.Size() && cached.modTime.Equal(info.ModTime()) {
		return cached.sha256, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	p.geoMu.Lock()
	p.geoCache[path] = geoAssetCache{size: info.Size(), modTime: info.ModTime(), sha256: digest}
	p.geoMu.Unlock()
	return digest, nil
}
