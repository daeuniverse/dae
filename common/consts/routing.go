/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package consts

type RoutingDomainKey string

const (
	RoutingDomainKey_Full    RoutingDomainKey = "full"
	RoutingDomainKey_Keyword RoutingDomainKey = "keyword"
	RoutingDomainKey_Suffix  RoutingDomainKey = "suffix"
	RoutingDomainKey_Regex   RoutingDomainKey = "regex"

	Function_Domain      = "domain"
	Function_Ip          = "ip"
	Function_SourceIp    = "sip"
	Function_Port        = "port"
	Function_SourcePort  = "sport"
	Function_L4Proto     = "l4proto"
	Function_IpVersion   = "ipversion"
	Function_Mac         = "mac"
	Function_ProcessName = "pname"
	Function_Dscp        = "dscp"

	Function_QName    = "qname"
	Function_QType    = "qtype"
	Function_Upstream = "upstream"

	OutboundParam_Mark = "mark"
)
