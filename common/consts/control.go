/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package consts

import "fmt"

type DialMode string

const (
	DialMode_Ip     DialMode = "ip"
	DialMode_Domain DialMode = "domain"
)

func ParseDialMode(mode string) (DialMode, error) {
	switch mode {
	case "ip", "domain":
		return DialMode(mode), nil
	default:
		return "", fmt.Errorf("unsupported dial mode: %v", mode)
	}
}
