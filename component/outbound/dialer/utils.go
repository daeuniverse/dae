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
