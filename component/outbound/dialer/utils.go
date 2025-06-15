/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import "time"

func showDuration(d time.Duration) string {
	return d.Truncate(time.Millisecond).String()
}

func latencyString(realLatency, latencyOffset time.Duration) string {
	var offsetSign string = "+"
	if latencyOffset < 0 {
		offsetSign = "-"
	}

	var offsetPart string = ""
	if latencyOffset != 0 {
		offsetPart = "(" + offsetSign + showDuration(latencyOffset.Abs()) + "=" + showDuration(realLatency+latencyOffset) + ")"
	}

	return showDuration(realLatency) + offsetPart
}
