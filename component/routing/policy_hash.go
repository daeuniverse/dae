/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"hash"
)

const normalizedPolicyHashSchema = "dae.normalized-policy.v1"

type canonicalPolicyHasher struct {
	digest   hash.Hash
	scratch  [8]byte
	buffer   [1024]byte
	buffered int
}

func newCanonicalPolicyHasher(schema string) *canonicalPolicyHasher {
	hasher := &canonicalPolicyHasher{digest: sha256.New()}
	hasher.writeString(schema)
	return hasher
}

func (h *canonicalPolicyHasher) sum() (sum [sha256.Size]byte) {
	h.flush()
	h.digest.Sum(sum[:0])
	return sum
}

func (h *canonicalPolicyHasher) writeByte(value byte) {
	if h.buffered == len(h.buffer) {
		h.flush()
	}
	h.buffer[h.buffered] = value
	h.buffered++
}

func (h *canonicalPolicyHasher) writeBool(value bool) {
	if value {
		h.writeByte(1)
		return
	}
	h.writeByte(0)
}

func (h *canonicalPolicyHasher) writeUint64(value uint64) {
	if len(h.buffer)-h.buffered >= len(h.scratch) {
		binary.LittleEndian.PutUint64(h.buffer[h.buffered:], value)
		h.buffered += len(h.scratch)
		return
	}
	binary.LittleEndian.PutUint64(h.scratch[:], value)
	h.writeRawBytes(h.scratch[:])
}

func (h *canonicalPolicyHasher) writeString(value string) {
	h.writeUint64(uint64(len(value)))
	h.writeRawString(value)
}

func (h *canonicalPolicyHasher) writeRawString(value string) {
	for len(value) > 0 {
		if h.buffered == len(h.buffer) {
			h.flush()
		}
		written := copy(h.buffer[h.buffered:], value)
		h.buffered += written
		value = value[written:]
	}
}

func (h *canonicalPolicyHasher) writeRawBytes(value []byte) {
	for len(value) > 0 {
		if h.buffered == len(h.buffer) {
			h.flush()
		}
		written := copy(h.buffer[h.buffered:], value)
		h.buffered += written
		value = value[written:]
	}
}

func (h *canonicalPolicyHasher) flush() {
	if h.buffered == 0 {
		return
	}
	_, _ = h.digest.Write(h.buffer[:h.buffered])
	h.buffered = 0
}

func (h *canonicalPolicyHasher) writeFunction(function *config_parser.Function) {
	if function == nil {
		h.writeByte(0)
		return
	}
	h.writeByte(1)
	h.writeFunctionValue(function)
}

func (h *canonicalPolicyHasher) writeFunctionValue(function *config_parser.Function) {
	h.writeString(function.Name)
	h.writeBool(function.Not)
	h.writeParams(function.Params)
}

func (h *canonicalPolicyHasher) writeFunctions(functions []*config_parser.Function) {
	h.writeBool(functions != nil)
	h.writeUint64(uint64(len(functions)))
	for _, function := range functions {
		h.writeFunction(function)
	}
}

func (h *canonicalPolicyHasher) writeParam(param *config_parser.Param) {
	if param == nil {
		h.writeByte(0)
		return
	}
	h.writeByte(1)
	h.writeString(param.Key)
	h.writeString(param.Val)
	h.writeFunctions(param.AndFunctions)
	h.writeParams(param.Annotation)
}

func (h *canonicalPolicyHasher) writeParams(params []*config_parser.Param) {
	h.writeBool(params != nil)
	h.writeUint64(uint64(len(params)))
	for _, param := range params {
		h.writeParam(param)
	}
}

func (h *canonicalPolicyHasher) writeRules(rules []*config_parser.RoutingRule) {
	h.writeBool(rules != nil)
	h.writeUint64(uint64(len(rules)))
	for _, rule := range rules {
		if rule == nil {
			h.writeByte(0)
			continue
		}
		h.writeByte(1)
		h.writeFunctions(rule.AndFunctions)
		h.writeFunctionValue(&rule.Outbound)
	}
}

func (h *canonicalPolicyHasher) writeFallback(fallback config.FunctionOrString) error {
	switch fallback := fallback.(type) {
	case nil:
		h.writeByte(0)
	case string:
		h.writeByte(1)
		h.writeString(fallback)
	case *config_parser.Function:
		h.writeByte(2)
		h.writeFunction(fallback)
	case []*config_parser.Function:
		h.writeByte(3)
		h.writeFunctions(fallback)
	default:
		return fmt.Errorf("unsupported function-or-string value type: %T", fallback)
	}
	return nil
}

func hashNormalizedProgram(program *NormalizedProgram) ([sha256.Size]byte, error) {
	if program == nil {
		return [sha256.Size]byte{}, fmt.Errorf("nil normalized routing program")
	}
	hasher := newCanonicalPolicyHasher(normalizedPolicyHashSchema)
	hasher.writeRules(program.Rules)
	if err := hasher.writeFallback(program.Fallback); err != nil {
		return [sha256.Size]byte{}, err
	}
	return hasher.sum(), nil
}
