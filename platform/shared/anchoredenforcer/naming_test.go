// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
)

// TestEveryUnknownReasonHasItsOwnPhrase: a reason added to the contract without
// its own words would name a constraint with the fallback phrase (#4227).
func TestEveryUnknownReasonHasItsOwnPhrase(t *testing.T) {
	fallback := UnknownReasonPhrase("not-a-declared-reason")
	seen := map[string]contract.UnknownReason{}
	for _, r := range contract.AllUnknownReasons() {
		phrase := UnknownReasonPhrase(r)
		if phrase == fallback {
			t.Errorf("%s has no phrase of its own; it reads %q", r, phrase)
		}
		if strings.Count(phrase, "%") != 1 || !strings.Contains(phrase, "%s") {
			t.Errorf("%s: phrase %q must take the attributes exactly once, as %%s", r, phrase)
		}
		if other, dup := seen[phrase]; dup {
			t.Errorf("%s and %s share the phrase %q", r, other, phrase)
		}
		seen[phrase] = r
	}
}

// TestAnUnknownConstraintIsNamedByWhoseItIs: the source and version beside the
// id, as policy_identities names them (PRD v11 §1.14).
func TestAnUnknownConstraintIsNamedByWhoseItIs(t *testing.T) {
	u := contract.UnknownPolicy{Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied, Paths: []string{"args.request_type"}}
	const why = " could not be evaluated: no value was supplied for args.request_type"
	for _, c := range []struct {
		identity activation.PolicyIdentity
		want     string
	}{
		{activation.PolicyIdentity{ID: "ceiling.refund", Source: activation.SourceOrganization, Version: 1}, "ceiling.refund (organization, document version 1)" + why},
		{activation.PolicyIdentity{ID: "pack.ceiling", Source: activation.SourcePack, Version: 2}, "pack.ceiling (pack, version 2)" + why},
		{activation.PolicyIdentity{ID: "corpus:static_policies:sys__x:block", Source: activation.SourceShipped}, "corpus:static_policies:sys__x:block (shipped)" + why},
		{activation.PolicyIdentity{ID: "not.activated"}, "not.activated" + why},
	} {
		if got := UnknownConstraintReason(c.identity, u); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.identity, got, c.want)
		}
	}
}
