/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package nativeapi

// NodeCapabilities describes what a provider allows control callers to do with
// nodes. Only the nodes written in the managed node source are editable; a node
// that a subscription or file provider delivered is managed by that provider.
type NodeCapabilities struct {
	// CanManage reports whether inline nodes can be created, updated and
	// deleted.
	CanManage bool
}

// NodeCreateRequest asks the provider to add one inline node.
type NodeCreateRequest struct {
	Name           string
	Link           string
	IdempotencyKey string
}

// NodeDeleteRequest asks the provider to remove one inline node.
type NodeDeleteRequest struct {
	NodeID         string
	IdempotencyKey string
}

// NodeDeleteOutcome reports what a delete did. Deleted is zero when nothing was
// queued, which makes an unknown id answer 200 with deleted 0 the way the
// contract requires.
type NodeDeleteOutcome struct {
	Accepted OperationAccepted
	Deleted  int
}

// NodeUpdateRequest asks the provider to change one inline node. A nil Name or
// Link keeps the current value; the caller sets at least one of them.
type NodeUpdateRequest struct {
	NodeID         string
	Name           *string
	Link           *string
	IdempotencyKey string
}

// NodeUpdateOutcome reports what an update did. Updated is zero when the
// request named the values the node already has, which answers 200 with
// updated 0 instead of writing the same line and starting a reload.
type NodeUpdateOutcome struct {
	Accepted OperationAccepted
	Updated  int
}

// ProviderCapabilities describes provider actions beyond listing.
type ProviderCapabilities struct {
	// CanRefresh reports whether a subscription can be refetched on demand.
	CanRefresh bool
}

// ProviderRefreshRequest asks the provider to refetch one subscription.
type ProviderRefreshRequest struct {
	ProviderID     string
	IdempotencyKey string
}
