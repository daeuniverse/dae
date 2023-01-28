/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package consts

type DialerSelectionPolicy string

const (
	DialerSelectionPolicy_Random                DialerSelectionPolicy = "random"
	DialerSelectionPolicy_Fixed                 DialerSelectionPolicy = "fixed"
	DialerSelectionPolicy_MinAverage10Latencies DialerSelectionPolicy = "min_avg10"
	DialerSelectionPolicy_MinLastLatency        DialerSelectionPolicy = "min"
)
