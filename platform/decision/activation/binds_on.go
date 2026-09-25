// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"slices"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// A CONTROL BINDS WHERE ITS DOCUMENT SAYS (#4371).
//
// An organization's control may name the scopes it binds on (pdp.Policy.
// BindsOn). On every other scope the composition leaves it out, through the
// same omission the organization template's unbound controls take
// (Composition.Compose), so the engine on that scope never carries it: nothing
// is refused or held for it there, and no decision names it. That is the same
// as withdrawing the control on that scope, EXACTLY: a pack's or the
// baseline's policy the document carries by its id and scopes elsewhere is not
// carried on the other scopes (notCarried), so the pack's own policy of that id
// composes there in its place, as it would had the document deleted the copy.
// Composition.Compose frees an omitted id for that one addition.
//
// Absent binds on every scope, as every document published before #4371 does,
// so such a document omits nothing here and its bundle and PolicyBundle are
// what they were (binds_on_digest_4371_test.go proves it against digests the
// base tree computed).

// RefusalBindsOnInvalid is the code Activate refuses with when the active
// document's binds_on is one the publish validator refuses: an empty list, or a
// scope this vocabulary does not admit. Publication refuses both
// (authoring.CodeBindsOnEmpty, authoring.CodePlaneNotDeclared) against the
// same statement - the planes the resolved vocabulary states per action
// (pdp.ActionEntry.Planes) - so a document reaches here with one only across
// vocabularies: published under one that admits a scope this one does not,
// then rolled back to. Neither reading is
// safe: "nowhere" removes a constraint from every scope, and "everywhere"
// enforces what the author confined. So the activation refuses, and the plane
// fails closed.
const RefusalBindsOnInvalid = "BINDS_ON_INVALID"

// RefusalBindsOnCarriedOffScope is the code of the backstop after composition
// (refuseCarriedOffScope): the organization root would carry a control on a
// scope its binds_on excludes. It holds by construction, so it names a defect.
const RefusalBindsOnCarriedOffScope = "BINDS_ON_CARRIED_OFF_SCOPE"

// admittedScopes is the planes cat admits in binds_on: the union of what its
// actions state (pdp.ActionEntry.Planes), the one statement publication
// checks against.
func admittedScopes(cat *authoring.Catalog) []string {
	set := map[string]bool{}
	for _, a := range cat.Actions {
		for _, p := range a.Planes {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// scopeUnboundControls is the ids of doc's controls whose binds_on does not
// name scope, in the document's order. admitted is the vocabulary's
// admittedScopes, and pin the catalog version the document was published
// against (0 for one published before the pin existed), which decides what
// `wcp` meant when it was written (legacycompile.BindsOnPinned).
func scopeUnboundControls(scope legacycompile.EnforcementScope, doc *pdp.Document, admitted []string, pin int64) ([]string, error) {
	var out []string
	for _, p := range doc.Policies {
		if p.BindsOn == nil {
			continue
		}
		if len(*p.BindsOn) == 0 {
			return nil, &pdp.ActivationRefusal{Code: RefusalBindsOnInvalid, Detail: fmt.Sprintf(
				"control %q declares binds_on as an empty list, which publication refuses: it would bind the control on no scope, "+
					"and read as absent it would bind it on every scope", p.ID)}
		}
		for _, s := range *p.BindsOn {
			if !slices.Contains(admitted, s) {
				return nil, &pdp.ActivationRefusal{Code: RefusalBindsOnInvalid, Detail: fmt.Sprintf(
					"control %q binds on %q, which this vocabulary does not admit (it admits %v); the document was published "+
						"against another vocabulary", p.ID, s, admitted)}
			}
		}
		if !legacycompile.BindsOnPinned(p.BindsOn, pin, scope) {
			out = append(out, p.ID)
		}
	}
	return out, nil
}

// refuseCarriedOffScope is the backstop after composition: no policy of the
// organization root this engine activates may name scopes that exclude this
// one. It holds by construction (scopeUnboundControls feeds the omission), so
// a failure is a defect, and it refuses rather than activates the control
// where its author said it does not bind. It reads the SAME pinned answer the
// omission did, so a pre-split document whose control the alias keeps on the
// route plane is not refused by the backstop that follows it.
func refuseCarriedOffScope(scope legacycompile.EnforcementScope, org *pdp.Document, pin int64) error {
	if org == nil {
		return nil
	}
	for _, p := range org.Policies {
		if !legacycompile.BindsOnPinned(p.BindsOn, pin, scope) {
			return &pdp.ActivationRefusal{Code: RefusalBindsOnCarriedOffScope, Detail: fmt.Sprintf(
				"the organization root on %s carries control %q, which binds only on %s", scope, p.ID, describeBindsOn(p.BindsOn))}
		}
	}
	return nil
}

// describeBindsOn renders binds for a refusal: the list, or "every scope" when
// it is absent. It never dereferences a nil list, so the backstop reports
// rather than panics under the defect it exists to catch.
func describeBindsOn(binds *[]string) string {
	if binds == nil {
		return "every scope"
	}
	return fmt.Sprintf("%v", *binds)
}
