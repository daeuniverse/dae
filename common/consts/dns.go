/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2023, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import (
	"strconv"
	"strings"
)

type DnsRequestOutboundIndex int16

const (
	DnsRequestOutboundIndex_Reject      DnsRequestOutboundIndex = 0xFC
	DnsRequestOutboundIndex_AsIs        DnsRequestOutboundIndex = 0xFD
	DnsRequestOutboundIndex_LogicalOr   DnsRequestOutboundIndex = 0xFE
	DnsRequestOutboundIndex_LogicalAnd  DnsRequestOutboundIndex = 0xFF
	DnsRequestOutboundIndex_LogicalMask DnsRequestOutboundIndex = 0xFE

	DnsRequestOutboundIndex_UserDefinedMax = DnsRequestOutboundIndex_AsIs - 1
)

func (i DnsRequestOutboundIndex) String() string {
	switch i {
	case DnsRequestOutboundIndex_Reject:
		return "reject"
	case DnsRequestOutboundIndex_AsIs:
		return "asis"
	case DnsRequestOutboundIndex_LogicalOr:
		return "<OR>"
	case DnsRequestOutboundIndex_LogicalAnd:
		return "<AND>"
	default:
		return "<index: " + strconv.Itoa(int(i)) + ">"
	}
}

type DnsResponseOutboundIndex uint8

const (
	DnsResponseOutboundIndex_Accept      DnsResponseOutboundIndex = 0xFC
	DnsResponseOutboundIndex_Reject      DnsResponseOutboundIndex = 0xFD
	DnsResponseOutboundIndex_LogicalOr   DnsResponseOutboundIndex = 0xFE
	DnsResponseOutboundIndex_LogicalAnd  DnsResponseOutboundIndex = 0xFF
	DnsResponseOutboundIndex_LogicalMask DnsResponseOutboundIndex = 0xFE

	DnsResponseOutboundIndex_UserDefinedMax = DnsResponseOutboundIndex_Accept - 1
)

func (i DnsResponseOutboundIndex) String() string {
	switch i {
	case DnsResponseOutboundIndex_Accept:
		return "accept"
	case DnsResponseOutboundIndex_Reject:
		return "reject"
	case DnsResponseOutboundIndex_LogicalOr:
		return "<OR>"
	case DnsResponseOutboundIndex_LogicalAnd:
		return "<AND>"
	default:
		return "<index: " + strconv.Itoa(int(i)) + ">"
	}
}

func (i DnsResponseOutboundIndex) IsReserved() bool {
	return !strings.HasPrefix(i.String(), "<index: ")
}
