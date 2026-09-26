// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// exportApproval is an approval requirement on the export, which only the
// multi-agent plane presents in catalogWithPlanes.
func exportApproval(binds *[]string) pdp.Policy {
	return pdp.Policy{
		ID:          "req.export.approval",
		Authority:   contract.AuthorityRequirement,
		Root:        pdp.RootSystem,
		Scope:       pdp.Scope{Organization: true},
		Actions:     pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, actionExport)}},
		Where:       pdp.True(),
		Obligations: []contract.Obligation{approvalObligation("req.export.approval", "1", groupFinance)},
		Mandatory:   true,
		BindsOn:     binds,
	}
}

// TestEveryNoHoldWarningIsOnAScopeThatHoldsNothing holds the publish warnings
// to legacycompile's one declaration of what each scope does with an approval
// challenge (#4249 row 5768885106): a warned scope that the declaration says
// HOLDS would warn an author away from a plane that holds, and a scope that
// withholds every challenge (the multi-agent plane since #4382) must be warned,
// because a requirement bound there never lets its step run and nothing says
// so at publish (#4249 row 5774872368).
//
// The Refused scopes that warn are the two an approval requirement lands on
// beside a sibling that holds (mcp:response beside mcp:request, the request
// routes beside the step gate); the other Refused scopes are not warned, so a
// requirement with no binds_on is not warned on every plane it touches.
func TestEveryNoHoldWarningIsOnAScopeThatHoldsNothing(t *testing.T) {
	byName := map[string]legacycompile.EnforcementScope{}
	for _, s := range legacycompile.AllScopes() {
		byName[s.String()] = s
	}
	warned := map[string]bool{}
	for _, w := range noHoldApprovalScopes {
		warned[w.scope] = true
		s, ok := byName[w.scope]
		if !ok {
			t.Errorf("%s warns on %q, which is no enforcement scope", w.code, w.scope)
			continue
		}
		h := legacycompile.ApprovalHandlingOf(s)
		if h == 0 {
			t.Errorf("%s warns on %s, where legacycompile declares no approval handling", w.code, w.scope)
			continue
		}
		if h.Holds() {
			t.Errorf("%s warns that %s holds no approval, and legacycompile declares it %s", w.code, w.scope, h)
		}
	}
	withheld := 0
	for name, s := range byName {
		if legacycompile.ApprovalHandlingOf(s) != legacycompile.ApprovalWithheld {
			continue
		}
		withheld++
		if !warned[name] {
			t.Errorf("%s withholds every approval challenge, and no publish warning names it: a requirement bound there never lets its step run", name)
		}
	}
	if withheld == 0 {
		t.Fatal("no scope withholds a challenge; the multi-agent plane does since #4382")
	}
}

// TestTheMapNoHoldWarningFollowsWhatBindsOnNames holds BINDS_ON_MAP_NO_HOLD to
// binds_on over a completion presented on both wcp and map: naming map, or
// leaving binds_on absent, warns; naming wcp alone - the workflow step gate,
// which holds - does not.
func TestTheMapNoHoldWarningFollowsWhatBindsOnNames(t *testing.T) {
	cases := []struct {
		binds *[]string
		warns bool
	}{
		{nil, true},
		{&[]string{"map"}, true},
		{&[]string{"wcp", "map"}, true},
		{&[]string{"wcp"}, false},
	}
	for _, tc := range cases {
		cat := catalogWithPlanes(t)
		e := cat.Actions[actionCompletion]
		e.Planes = append(append([]string(nil), e.Planes...), "map")
		cat.Actions[actionCompletion] = e
		d := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
			d.Policies = append(d.Policies, completionApproval(tc.binds))
		})
		findings := Validate(d, cat)
		if findings.Rejected() {
			t.Fatalf("binds_on %v: the document was rejected: %v", tc.binds, findings.Rejections())
		}
		if got := findings.Has(CodeBindsOnMapNoHold); got != tc.warns {
			t.Errorf("binds_on %v: %s fired = %v, want %v\nfindings: %v", tc.binds, CodeBindsOnMapNoHold, got, tc.warns, findings)
		}
	}
	// An approval on an action map does not present, with binds_on absent, is
	// silent: nothing is withheld there. (Naming map explicitly for such an
	// action is ACTION_NOT_PRESENTED_ON_PLANE, TestSaveTimeChecks' case.)
	cat := catalogWithPlanes(t)
	d := documentWith(t, cat, func(_ *Metadata, d *pdp.Document) {
		d.Policies = append(d.Policies, completionApproval(nil))
	})
	if findings := Validate(d, cat); findings.Has(CodeBindsOnMapNoHold) {
		t.Errorf("an approval on an action map does not present warned %s: %v", CodeBindsOnMapNoHold, findings)
	}
}
