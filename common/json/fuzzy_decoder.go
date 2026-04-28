/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package json

import (
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

type FuzzyBoolDecoder struct {
}

func (decoder *FuzzyBoolDecoder) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	valueType := iter.WhatIsNext()
	switch valueType {
	case jsoniter.NumberValue:
		*((*bool)(ptr)) = iter.ReadFloat64() != 0
	case jsoniter.StringValue:
		str := iter.ReadString()
		switch str {
		case "", "0":
			*((*bool)(ptr)) = false
		default:
			*((*bool)(ptr)) = true
		}
	case jsoniter.BoolValue:
		*((*bool)(ptr)) = iter.ReadBool()
	case jsoniter.NilValue:
		iter.Skip()
		*((*bool)(ptr)) = false
	default:
		iter.ReportError("FuzzyBoolDecoder", "not number, string or bool")
	}
}
