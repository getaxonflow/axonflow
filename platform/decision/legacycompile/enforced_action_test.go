// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import "testing"

// EnforcedAction and StatusForPlane are exported from a MIRRORED file, and
// their only tests lived in ee/platform/policy/legacyimport, which the
// community sync strips.
//
// That is the whole reason this file exists. A new public field and a new
// public method were reaching the mirror with nothing downstream that would
// notice either going missing: in the mirrored tree the mutant that deletes
// `pr.EnforcedAction = string(enforced)` was GREEN. Coverage that lives on the
// other side of a sync boundary is not coverage of what ships.

// TestEveryPlaneThatEmitsPolicyStatesItsEnforcedAction is the invariant the
// importer relies on: an empty EnforcedAction means "this plane applies
// nothing", so a plane that emitted policy and left it empty would be read as
// enforcing nothing at all.
func TestEveryPlaneThatEmitsPolicyStatesItsEnforcedAction(t *testing.T) {
	rep, err := Compile([]RawRow{
		staticRow(t, "sys_pii", nil),
		dynamicRow(t, "dyn_role", nil),
	}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	checked := 0
	for _, rec := range rep.Records {
		for _, pr := range rec.Planes {
			if len(pr.Policies) == 0 {
				continue
			}
			checked++
			if pr.EnforcedAction == "" {
				t.Errorf("%s/%s on plane %q emitted %d policy/policies and states no enforced action",
					rec.Source.Table, rec.Source.PolicyID, pr.Plane, len(pr.Policies))
			}
		}
	}
	// THE DENOMINATOR. "No plane emitted a policy" would make the loop above
	// vacuous while reading as a pass.
	if checked == 0 {
		t.Fatal("no plane result emitted a policy, so this test asserted nothing")
	}
}

// TestTheEnforcedActionCarriesTheOverrideOnlyWhereTheOverrideReaches pins the
// difference between ResolvedAction and EnforcedAction, per plane.
//
// The two fields are equal on most planes, and that is exactly why a test is
// needed: a change that made EnforcedAction a copy of ResolvedAction would
// pass every assertion that only looks at a override-passing plane.
func TestTheEnforcedActionCarriesTheOverrideOnlyWhereTheOverrideReaches(t *testing.T) {
	opts := testOptions()
	// security-sqli, not a PII category: cowork_ingest coerces PII to redact,
	// and since #4253 retired proxy_tier it is the one static plane without an
	// override map, so the untouched half needs a category it does not coerce.
	opts.CategoryActions = CategoryActions{"security-sqli": ActionWarn}
	// action_response block, so the override's `warn` is a REAL displacement
	// rather than a value identical to the one already stored.
	rep, err := Compile([]RawRow{staticRow(t, "sys_pii", map[string]any{
		"category": "security-sqli", "action": "block",
		"action_request": "block", "action_response": "block",
	})}, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_pii")

	sawOverridden, sawNotOverridden := false, false
	for _, pr := range rec.Planes {
		if pr.ResolvedAction == "" {
			continue
		}
		spec := MustSpecFor(pr.Plane)
		_, forces := spec.Forces("security-sqli")
		switch {
		case spec.PassesOrgOverrides:
			sawOverridden = true
			if pr.EnforcedAction != string(ActionWarn) {
				t.Errorf("plane %q is reached by the organization override; enforced=%q, want warn (resolved was %q)",
					pr.Plane, pr.EnforcedAction, pr.ResolvedAction)
			}
		case forces:
			// Covered by its own test below; the coercion, not the override.
		default:
			sawNotOverridden = true
			if pr.EnforcedAction != pr.ResolvedAction {
				t.Errorf("plane %q has neither an override map nor a coercion, so what it enforces is what it resolved; enforced=%q resolved=%q",
					pr.Plane, pr.EnforcedAction, pr.ResolvedAction)
			}
		}
	}
	if !sawOverridden {
		t.Fatal("no override-passing plane was examined, so the displacement half asserted nothing")
	}
	if !sawNotOverridden {
		t.Fatal("no override-free plane was examined, so the untouched half asserted nothing")
	}
}

// TestTheCoworkIngestPlaneCoercesItsActionIntoTheEnforcedAction is the second
// displacement, and the one an override-only reading misses entirely.
//
// cowork_ingest has PassesOrgOverrides false and ForcedAction redact, scoped to the
// PII categories: a warn or log deployment still masks before it persists. A
// consumer re-deriving the enforced action from the override alone gets `block`
// here, where the plane actually applies `redact`.
func TestTheCoworkIngestPlaneCoercesItsActionIntoTheEnforcedAction(t *testing.T) {
	rep, err := Compile([]RawRow{staticRow(t, "sys_pii_cowork", map[string]any{
		"category": "pii-global", "phase": "both",
		"action": "block", "action_request": "block", "action_response": "block",
	})}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_pii_cowork")

	found := false
	for _, pr := range rec.Planes {
		if pr.Plane != PlaneCoworkIngest || pr.ResolvedAction == "" {
			continue
		}
		found = true
		if pr.ResolvedAction != "block" {
			t.Errorf("resolved=%q, want block; the row stores block on the response phase", pr.ResolvedAction)
		}
		if pr.EnforcedAction != string(ActionRedact) {
			t.Errorf("enforced=%q, want redact; this plane COERCES redact for a PII category regardless of the stored action, "+
				"and a consumer reading the resolved action would mask nothing", pr.EnforcedAction)
		}
	}
	if !found {
		t.Fatal("the cowork ingest plane produced no result for a PII row, so the coercion was never examined")
	}

	// THE NEGATIVE CONTROL. The coercion is scoped to the PII categories, so a
	// non-PII row on the SAME plane must keep what it resolved. Without this,
	// a plane that forced redact unconditionally would pass above.
	rep2, err := Compile([]RawRow{staticRow(t, "sys_sqli_cowork", map[string]any{
		"category": "security-sqli", "phase": "both",
		"action": "block", "action_request": "block", "action_response": "block",
	})}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, pr := range recordFor(t, rep2, "sys_sqli_cowork").Planes {
		if pr.Plane != PlaneCoworkIngest || pr.ResolvedAction == "" {
			continue
		}
		if pr.EnforcedAction != pr.ResolvedAction {
			t.Errorf("a non-PII row on the cowork plane was coerced to %q from %q; the coercion is scoped to the PII categories",
				pr.EnforcedAction, pr.ResolvedAction)
		}
	}
}

// TestStatusForPlaneSeparatesAbsentFromUncompilable pins the distinction the
// second return exists for.
//
// A plane the record does not carry and a plane whose row the compiler could
// not express are different facts, and folding them onto the single word
// "uncompilable" would let a caller report a migration gap that does not exist.
func TestStatusForPlaneSeparatesAbsentFromUncompilable(t *testing.T) {
	// THE FIXTURE HAS TO BE DEFECT-FREE, and the default one is not - which is
	// worth stating because it caught this test on its first run. staticRow
	// stores a pii-us category, which is coerced to redact on the cowork plane
	// and records a displacement: a defect reason, which makes the status
	// preserved_defect on every plane.
	//
	// A non-PII category with all three action columns agreeing, and no
	// posture, is the row that actually compiles cleanly. The point here is the
	// PRESENT/ABSENT distinction, not the status value, and pinning a status
	// that depends on neither would fail for reasons this test is not about.
	rep, err := Compile([]RawRow{staticRow(t, "sys_agreed_sqli", map[string]any{
		"category": "security-sqli", "phase": "both",
		"action": "block", "action_request": "block", "action_response": "block",
	})}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_agreed_sqli")

	// Present: a static row on a static plane.
	got, ok := rec.StatusForPlane(PlaneDecide)
	if !ok {
		t.Fatal("decide is absent from a static row's record; the present half asserted nothing")
	}
	if got != StatusCompiled {
		t.Errorf("decide status = %q, want compiled", got)
	}

	// Absent: a DYNAMIC plane never appears on a static row's record. It is
	// not uncompilable - the compiler was never asked.
	if _, ok := rec.StatusForPlane(PlaneWCP); ok {
		t.Fatal("wcp reported present on a static-only record; the absent half asserted nothing")
	}

	// And the row-level status is untouched by either question.
	if rec.Status != StatusCompiled {
		t.Errorf("row-level status = %q, want compiled", rec.Status)
	}
}
