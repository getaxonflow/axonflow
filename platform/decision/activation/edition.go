// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"strings"

	"axonflow/platform/decision/authoring"
)

// CodeCapabilityRequiresUpgrade is the wire code an activation refused for the
// edition boundary carries. ADR-066's enforcement response is written around
// it ("CAPABILITY_REQUIRES_ENTERPRISE", naming the capability and both
// editions), and it is deliberately NOT a policy DENY: policy denied nothing,
// and a caller that reads a deny goes looking for the rule that did it.
//
// # WHY IT IS DECLARED HERE AND NOT IN authoring's CHECK TABLE
//
// That table is the SAVE-TIME check list. Every entry needs a case that
// provokes it and a mutant proving the case can fail, and the operator-facing
// check list is generated from it. This code is neither a save-time check nor
// produced by newFinding - the refusal CARRIES the findings authoring raised -
// so a row there would be an entry no save-time case could ever fire.
const CodeCapabilityRequiresUpgrade = "CAPABILITY_REQUIRES_UPGRADE"

// CapabilityRefusal is an activation refused because the document spends a
// construct the deployment's edition does not carry.
//
// It is a distinct type rather than a plain error, and distinct from
// pdp.ActivationRefusal, because a transport has to be able to tell this apart
// from every other activation failure WITHOUT parsing a message. The deployment
// is not equipped to enforce what the document asks for.
//
// Findings carry the same codes the author would have seen at publication, so
// the two doors say the same sentence about the same construct.
type CapabilityRefusal struct {
	// Code is CodeCapabilityRequiresUpgrade.
	Code string
	// Edition is the edition this deployment resolved to.
	Edition string
	// Findings are the per-policy construct refusals, complete rather than
	// first-error, in the authoring package's own idiom.
	Findings authoring.Findings
}

func (e *CapabilityRefusal) Error() string {
	parts := make([]string, 0, len(e.Findings))
	for _, f := range e.Findings {
		parts = append(parts, f.String())
	}
	return fmt.Sprintf("activation: %s: this document spends constructs the %s edition does not carry: %s",
		e.Code, e.Edition, strings.Join(parts, "; "))
}

// refuseConstructsOutsideEdition is ADR-066 chokepoint 2: the edition boundary
// applied to a document that is becoming, or staying, active.
//
// # WHY THIS RUNS AT ALL, WHEN PUBLICATION ALREADY CHECKED
//
// authoring.Publish is the only function that produces an Artifact, so no
// document SIGNED through this tree can miss the check. That guarantee covers
// one door. It says nothing about a document that reached the store another
// way, and on main there are two such ways: ee/platform/policy/cmd/
// axonflow-policy-import builds its profile from an operator FLAG rather than
// from the licence, and migrations/core/176 grants the application role INSERT
// on typed_policy_artifacts (its triggers block UPDATE and DELETE, not INSERT).
// Either can put a document carrying Enterprise constructs in front of a
// Community deployment's engine, and until this check existed the engine would
// build and enforce it.
//
// # WHY THE CALLER DECIDES WHETHER IT RUNS
//
// See Inputs.RefuseConstructsOutsideEdition. The short version: the transports'
// dry run always refuses, because that is an author reading a refusal at the
// moment they choose what to write; the enforcement seam refuses only when the
// deployment's tier is established and not in a declared licence transition,
// because there a refusal is a 503 rather than a sentence.
func refuseConstructsOutsideEdition(in Inputs) error {
	if !in.RefuseConstructsOutsideEdition {
		return nil
	}
	// A zero-value Profile is constructible by any caller, and reading it as an
	// edition would silently apply "Community constructs, duties on" to a
	// deployment that never said so. Refuse the INPUT rather than the document.
	if err := in.Profile.Validate(); err != nil {
		return fmt.Errorf("activation: the edition-construct check was requested without a usable profile: %w", err)
	}
	// No organization document: the shipped corpus alone is what activates, and
	// it is this deployment's own, signed by its system root. There is nothing
	// an author wrote to check.
	if in.Organization == nil {
		return nil
	}
	doc, err := in.Organization.Document()
	if err != nil {
		return fmt.Errorf("activation: the active document could not be read to check its constructs: %w", err)
	}
	findings := in.Profile.CheckConstructs(doc).Rejections()
	if len(findings) == 0 {
		return nil
	}
	return &CapabilityRefusal{
		Code:     CodeCapabilityRequiresUpgrade,
		Edition:  string(in.Profile.Edition()),
		Findings: findings,
	}
}
