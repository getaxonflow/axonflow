// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package moneyfacts

import (
	"encoding/json"
	"math"
	"testing"
)

func TestMinorRequiresExactPositiveInteger(t *testing.T) {
	for _, tc := range []struct {
		value any
		valid bool
	}{
		{94900, true}, {float64(94900), true}, {json.Number("94900"), true},
		{0, false}, {-1, false}, {500.5, false}, {"94900", false}, {true, false},
		{math.NaN(), false}, {math.Inf(1), false}, {float64(9007199254740992), false},
		{json.Number("9007199254740993"), false},
	} {
		_, valid := Minor(tc.value)
		if valid != tc.valid {
			t.Errorf("Minor(%v) valid = %t, want %t", tc.value, valid, tc.valid)
		}
	}
}

func TestCurrencyRequiresUppercaseThreeLetters(t *testing.T) {
	for _, tc := range []struct {
		value any
		valid bool
	}{{"USD", true}, {"IDR", true}, {"usd", false}, {"US1", false}, {"US", false}, {1, false}} {
		_, valid := Currency(tc.value)
		if valid != tc.valid {
			t.Errorf("Currency(%v) valid = %t, want %t", tc.value, valid, tc.valid)
		}
	}
}
