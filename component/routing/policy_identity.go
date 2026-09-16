/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"fmt"
)

// PolicyEpoch identifies an immutable policy generation.
type PolicyEpoch uint64

// PolicyIdentity is the compact, immutable identity of one normalized policy.
// It can outlive the policy program without retaining the program's rule tree,
// which is what lets a reload compare policies without keeping the previous
// generation's rules alive.
type PolicyIdentity struct {
	epoch PolicyEpoch
	hash  [sha256.Size]byte
}

// NewPolicyIdentity calculates a generation identity without retaining program.
func NewPolicyIdentity(epoch PolicyEpoch, program *NormalizedProgram) (PolicyIdentity, error) {
	if program == nil {
		return PolicyIdentity{}, fmt.Errorf("nil normalized routing program")
	}

	policyHash, err := hashNormalizedProgram(program)
	if err != nil {
		return PolicyIdentity{}, fmt.Errorf("hash normalized routing policy: %w", err)
	}

	return PolicyIdentity{
		epoch: epoch,
		hash:  policyHash,
	}, nil
}

// Epoch returns the immutable generation identifier.
func (i PolicyIdentity) Epoch() PolicyEpoch {
	return i.epoch
}

// Hash returns the semantic content hash without the generation identifier.
func (i PolicyIdentity) Hash() [sha256.Size]byte {
	return i.hash
}
