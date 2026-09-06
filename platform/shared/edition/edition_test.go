// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package edition

import "testing"

// TestCurrentIsOneOfTheTwo is the anti-typo pin: Current is set in one of two
// build-tagged files, and a typo in either ("enterprize") would compile and
// then be published on every /health response and every platform ping.
func TestCurrentIsOneOfTheTwo(t *testing.T) {
	for _, v := range All() {
		if Current == v {
			return
		}
	}
	t.Fatalf("Current = %q, which is not in All() = %v — a build-tagged file has drifted "+
		"from the vocabulary", Current, All())
}

// TestAllIsExactlyTwoSortedValues pins the vocabulary itself. The edition
// dimension exists because the build tag is binary; a third value would mean
// the dimension no longer answers the question it was added for, and the
// receiver's ValidEditions map would silently bucket it as "unknown".
func TestAllIsExactlyTwoSortedValues(t *testing.T) {
	got := All()
	want := []string{"community", "enterprise"}
	if len(got) != len(want) {
		t.Fatalf("All() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("All() = %v, want %v (sorted; the vocabulary parity pin compares "+
				"these lists element-wise)", got, want)
		}
	}
}
