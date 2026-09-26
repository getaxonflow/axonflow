// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
	"time"
)

// #4249 rows 5781567856 and 5766609846: eval_time_ms was computed as
// Microseconds()/1000, so every evaluation under one microsecond reported 0 -
// and a warm single-condition policy preview is that fast. The reported metric
// read "took no time", and the integration cell that asserted it was positive
// went red on fast or contended runs. This cell pins the resolution with fixed
// durations, so it fails on the truncation without claiming anything about the
// machine it runs on.
func TestEvalTimeMsKeepsSubMicrosecondResolution(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want float64
	}{
		{500 * time.Nanosecond, 0.0005},
		{1 * time.Nanosecond, 0.000001},
		{1500 * time.Microsecond, 1.5},
		{2 * time.Second, 2000},
		{0, 0},
	}
	for _, c := range cases {
		if got := evalTimeMs(c.d); got != c.want {
			t.Errorf("evalTimeMs(%v) = %v, want %v", c.d, got, c.want)
		}
	}
}
