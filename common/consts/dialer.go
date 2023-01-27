/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package consts

type DialerSelectionPolicy string

const (
	DialerSelectionPolicy_Random                DialerSelectionPolicy = "random"
	DialerSelectionPolicy_Fixed                 DialerSelectionPolicy = "fixed"
	DialerSelectionPolicy_MinAverage10Latencies DialerSelectionPolicy = "min_avg10"
	DialerSelectionPolicy_MinLastLatency        DialerSelectionPolicy = "min"
)
