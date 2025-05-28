/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package consts

import "fmt"

type DialMode string

const (
	DialMode_Ip         DialMode = "ip"
	DialMode_Domain     DialMode = "domain"
	DialMode_DomainPlus DialMode = "domain+"
	DialMode_DomainCao  DialMode = "domain++"
)

func ParseDialMode(mode string) (DialMode, error) {
	switch mode {
	case "ip", "domain", "domain+", "domain++":
		return DialMode(mode), nil
	default:
		return "", fmt.Errorf("unsupported dial mode: %v", mode)
	}
}
