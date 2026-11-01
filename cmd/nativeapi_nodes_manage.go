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
	return p.config.CreateNode(ctx, req, p.nodeIndex)
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
	return p.config.DeleteNode(ctx, req, p.nodeIndex)
}

var errNodeManagementUnavailable = &nativeapi.APIError{
	Status:  404,
	Code:    "capability_not_supported",
	Message: "node management is not supported by this engine",
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
		providerID := "inline"
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
	return p.operations.StartOperation(ctx, nativeapi.OperationKindProviderRefresh, req.IdempotencyKey)
}
