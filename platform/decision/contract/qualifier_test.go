// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import (
	"strconv"
	"strings"
	"testing"
)

// TestValidateQualifierIsTheGrammarValidateParsesWith pins the exported
// qualifier check against ID.Validate on the same inputs: what one refuses the
// other refuses, in both directions, so a producer that delegates to
// ValidateQualifier (identity.ValidateRealmID, #3709 row 3) admits exactly the
// qualifiers the PDP will parse.
func TestValidateQualifierIsTheGrammarValidateParsesWith(t *testing.T) {
	cases := []struct {
		q      string
		accept bool
	}{
		{"security", true}, {"acme-prod", true}, {"eu.central_1", true}, {"0realm", true}, {"A", true},
		{"acme+prod", false}, {"eu/central", false}, {"realm@okta", false}, {"réalm", false},
		{"-leading", false}, {"_leading", false}, {".leading", false}, {"", false},
		{"se:curity", false}, {"realm okta", false}, {"realm\x00okta", false},
	}
	accepted, refused := 0, 0
	for _, tc := range cases {
		err := ValidateQualifier(tc.q)
		if (err == nil) != tc.accept {
			t.Errorf("ValidateQualifier(%q) = %v, want accept=%v", tc.q, err, tc.accept)
			continue
		}
		id := ID{Kind: KindPrincipal, Type: "User", Qualifier: tc.q, Local: "00u1"}
		if (id.Validate() == nil) != tc.accept {
			t.Errorf("ID.Validate with qualifier %q disagrees with ValidateQualifier (accept=%v)", tc.q, tc.accept)
		}
		if tc.accept {
			accepted++
		} else {
			refused++
			// The refusal quotes the qualifier with %q, so a NUL renders as \x00.
			for _, want := range []string{strconv.Quote(tc.q), "[A-Za-z0-9][A-Za-z0-9_.-]*", "':'"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("ValidateQualifier(%q) refusal does not name %q:\n%v", tc.q, want, err)
				}
			}
		}
	}
	if accepted < 3 || refused < 3 {
		t.Fatalf("corpus produced %d accepts and %d refusals; one-sided", accepted, refused)
	}
}
