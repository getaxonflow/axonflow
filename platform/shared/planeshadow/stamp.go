// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import "time"

// stampLayouts are the renderings a policy row's updated_at arrives in.
//
// Two producers, two spellings of one instant. Postgres's row_to_json renders
// a timestamptz as RFC3339 with a numeric offset and a variable number of
// fractional digits; a Go caller formats a time.Time itself. Both have to
// collapse to ONE key, because a key that differs by spelling makes every
// comparison not-comparable forever - a permanently empty denominator that
// reads as a healthy zero-unexplained gate, which is the failure mode this
// whole package is built around.
//
// RFC3339Nano is first because it is what both producers emit in the ordinary
// case; the rest exist so an unusual driver rendering degrades to a normalized
// key rather than to a raw string that will never match its counterpart.
var stampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
}

func parseStamp(layout, s string) (time.Time, error) { return time.Parse(layout, s) }

// StampKey renders one instant as the snapshot key both sides use. The engines
// call it for the updated_at they loaded; the row source calls it for the
// updated_at it read.
func StampKey(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
