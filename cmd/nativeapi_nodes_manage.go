/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"

	"github.com/daeuniverse/dae/component/nativeapi"
)

// NodeCapabilities reports inline-node management, which follows the same gate
// as configuration writes: the listener switch plus the managed layout.
func (p *nativeAPIProvider) NodeCapabilities() nativeapi.NodeCapabilities {
	if p.config == nil {
		return nativeapi.NodeCapabilities{}
	}
	return nativeapi.NodeCapabilities{CanManage: p.config.ConfigCapabilities().Writable}
}

// CreateNode adds one inline node to the managed node source.
func (p *nativeAPIProvider) CreateNode(ctx context.Context, req nativeapi.NodeCreateRequest) (nativeapi.OperationAccepted, error) {
	if p.config == nil {
		return nativeapi.OperationAccepted{}, errNodeManagementUnavailable
	}
	if !p.NodeCapabilities().CanManage {
		return nativeapi.OperationAccepted{}, errNodeManagementUnavailable
	}
	// The contract asks a node_create operation for the inline Node it produced.
	// Predicting the id would hash the raw link, which a plugin link may
	// normalize before the engine derives its id. The resolver is handed to the
	// editor so it is installed with the operation, not after.
	resolve := func() (any, error) {
		node, nodeErr := p.nodeByName(req.Name, inlineProviderID)
		if nodeErr != nil {
			return nil, nodeErr
		}
		return *node, nil
	}
	return p.config.CreateNode(ctx, req, p.nodeIndex, resolve)
}

// UpdateNode changes the name and/or link of one inline node. A changed link
// changes the node id, so the editor hands the resolver the id the write will
// publish rather than letting the adapter predict it.
func (p *nativeAPIProvider) UpdateNode(ctx context.Context, req nativeapi.NodeUpdateRequest) (nativeapi.NodeUpdateOutcome, error) {
	if p.config == nil {
		return nativeapi.NodeUpdateOutcome{}, errNodeManagementUnavailable
	}
	if !p.NodeCapabilities().CanManage {
		return nativeapi.NodeUpdateOutcome{}, errNodeManagementUnavailable
	}
	resolve := func(nodeID string) (any, error) {
		node, nodeErr := p.GetNode(context.Background(), nodeID)
		if nodeErr != nil {
			return nil, nodeErr
		}
		return *node, nil
	}
	return p.config.UpdateNode(ctx, req, p.nodeIndex, resolve)
}

// DeleteNode removes one inline node. A node a subscription delivered is
// reported as not manageable, and an unknown id is an idempotent no-op.
func (p *nativeAPIProvider) DeleteNode(ctx context.Context, req nativeapi.NodeDeleteRequest) (nativeapi.NodeDeleteOutcome, error) {
	if p.config == nil {
		return nativeapi.NodeDeleteOutcome{}, errNodeManagementUnavailable
	}
	if !p.NodeCapabilities().CanManage {
		return nativeapi.NodeDeleteOutcome{}, errNodeManagementUnavailable
	}
	resolve := func() (any, error) {
		return nativeapi.NodeDeleteResult{Deleted: 1}, nil
	}
	outcome, err := p.config.DeleteNode(ctx, req, p.nodeIndex, resolve)
	if err != nil {
		return nativeapi.NodeDeleteOutcome{}, err
	}
	return outcome, nil
}

var errNodeManagementUnavailable = &nativeapi.APIError{
	Status:  404,
	Code:    "capability_not_supported",
	Message: "node management is not supported by this engine",
}

// nodeByName returns the node the running generation publishes under name and
// provider, without predicting its ID from a link that a plugin may normalize.
func (p *nativeAPIProvider) nodeByName(name, providerID string) (*nativeapi.Node, error) {
	active, err := p.activeGeneration()
	if err != nil {
		return nil, err
	}
	nodes, err := active.nodes("")
	if err != nil {
		return nil, err
	}
	if node := findNodeByNameAndProvider(nodes, name, providerID); node != nil {
		return node, nil
	}
	return nil, nativeapi.NewAPIError(404, "resource_not_found", "node not found")
}

func findNodeByNameAndProvider(nodes []nativeapi.Node, name, providerID string) *nativeapi.Node {
	for i := range nodes {
		nodeProviderID := inlineProviderID
		if nodes[i].ProviderID != nil {
			nodeProviderID = *nodes[i].ProviderID
		}
		if nodes[i].Name == name && nodeProviderID == providerID {
			node := nodes[i]
			return &node
		}
	}
	return nil
}

// nodeIndex maps the running generation's nodes by ID, with the provider that
// owns each one.
func (p *nativeAPIProvider) nodeIndex() (map[string]nodeRef, error) {
	active, err := p.activeGeneration()
	if err != nil {
		return nil, err
	}
	nodes, err := active.nodes("")
	if err != nil {
		return nil, err
	}
	index := make(map[string]nodeRef, len(nodes))
	for _, node := range nodes {
		providerID := inlineProviderID
		if node.ProviderID != nil {
			providerID = *node.ProviderID
		}
		index[node.ID] = nodeRef{Name: node.Name, ProviderID: providerID}
	}
	return index, nil
}

// ProviderCapabilities advertises on-demand refresh. Refetching a subscription
// takes a reload, which is what RefreshProvider queues.
func (p *nativeAPIProvider) ProviderCapabilities() nativeapi.ProviderCapabilities {
	return nativeapi.ProviderCapabilities{CanRefresh: p.operations != nil}
}

// RefreshProvider queues a reload for one subscription. A reload refetches every
// subscription, so the refresh needs no separate fetch path and a failed fetch
// leaves the previously loaded nodes in place.
func (p *nativeAPIProvider) RefreshProvider(ctx context.Context, req nativeapi.ProviderRefreshRequest) (nativeapi.OperationAccepted, error) {
	if p.operations == nil {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "this provider cannot be refreshed",
		}
	}
	active, err := p.activeGeneration()
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	providers, err := p.providers(active)
	if err != nil {
		return nativeapi.OperationAccepted{}, err
	}
	kind := ""
	for _, provider := range providers {
		if provider.ID == req.ProviderID {
			kind = provider.Kind
			break
		}
	}
	// An inline provider is the node section itself and a file provider has
	// nothing to fetch, so only a subscription can be refreshed.
	if kind != "subscription" {
		return nativeapi.OperationAccepted{}, &nativeapi.APIError{
			Status: 404, Code: "capability_not_supported", Message: "This provider cannot be refreshed",
		}
	}
	// A refresh reports the Provider whose nodes the reload replaced. A fetch
	// that fell back to the cached copy still reloads successfully, so the
	// failure has to travel through the resolver as an error; otherwise the
	// operation would report success for a refresh that changed nothing.
	// The resolver is installed with the operation rather than after it.
	return p.operations.StartOperationWithResult(ctx, nativeapi.OperationKindProviderRefresh, req.ProviderID, req.IdempotencyKey, func() (any, error) {
		provider, err := p.GetProvider(context.Background(), req.ProviderID)
		if err != nil {
			return nil, err
		}
		if provider.LastError != nil {
			return nil, &providerRefreshError{code: provider.LastError.Code, message: provider.LastError.Message}
		}
		return *provider, nil
	})
}

// providerRefreshError reports why a queued refresh did not load new nodes. The
// operation completes after the reload, so this travels through the result
// resolver and becomes the operation's SafeError.
type providerRefreshError struct {
	code    string
	message string
}

func (e *providerRefreshError) Error() string { return e.message }

func (e *providerRefreshError) SafeError() *nativeapi.SafeError {
	return &nativeapi.SafeError{Code: e.code, Message: e.message}
}
