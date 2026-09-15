// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"strings"
	"testing"

	"axonflow/platform/decision/pdp"
)

// The `tenant_id` column, read and deliberately not translated (#3899).
//
// # What these tests are FOR, which is the opposite of what the issue asked
//
// #3899 reports that a tenant-scoped row compiles to Scope{Organization: true}
// and concludes it "now applies to every principal in the organisation". The
// compiled behaviour is right; the implied contrast is not. Neither enforcement
// path selects on `tenant_id`, so the row ALREADY applies to the whole
// organisation before anything is compiled, and the compiled scope reproduces
// that rather than widening it. See ReasonTenantColumnNotAPredicate for the two
// predicates and for the one thing that looks like counter-evidence.
//
// So the assertion that matters most here is a NEGATIVE one: that the compiled
// scope did not change. Translating the column would make an imported policy
// apply to FEWER principals than the engine applies it to today - for a
// constraint, a loss of governance coverage arriving in the shape of a bug fix.
// TestTheCompiledScopeIsUnchanged is what stops a later reader "fixing" it.

// tenantScopedStaticRow is a static row owned by a real tenant rather than the
// global sentinel. tier must move off "system" too: a system-tier row is the
// platform's own and routes to the system root whatever its tenant says.
func tenantScopedStaticRow(t *testing.T, id string) RawRow {
	t.Helper()
	return staticRow(t, id, map[string]any{
		"tier": "tenant", "tenant_id": "team-finance", "org_id": "acme",
	})
}

func reasonWithCode(rec Record, code ReasonCode) *Reason {
	for i := range rec.Reasons {
		if rec.Reasons[i].Code == code {
			return &rec.Reasons[i]
		}
	}
	return nil
}

// TestATenantScopedRowReportsTheUntranslatedColumn is the positive case.
func TestATenantScopedRowReportsTheUntranslatedColumn(t *testing.T) {
	rep, err := Compile([]RawRow{tenantScopedStaticRow(t, "sys_tenant_scoped")}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_tenant_scoped")

	r := reasonWithCode(rec, ReasonTenantColumnNotAPredicate)
	if r == nil {
		t.Fatalf("a row carrying tenant_id=%q produced no %s reason, so the import proposal an operator reviews "+
			"does not mention the column at all - which is the doc.go contract this fixes: "+
			"\"zero silent drops\". Codes present: %v", "team-finance", ReasonTenantColumnNotAPredicate, codesOf(rec))
	}
	// THE DETAIL NAMES THE VALUE. A reason whose detail did not carry the
	// tenant would tell an operator that something was not translated without
	// saying what, which is the shape of a finding nobody can act on.
	if !strings.Contains(r.Detail, "team-finance") {
		t.Fatalf("the reason does not name the tenant it is about: %q", r.Detail)
	}
	// It is NEITHER a preserved legacy defect NOR a compiler gap, and the
	// classification decides the row's Status and the migration report's
	// headline counts. Filing it as either would make the report say the
	// compiler could not express something, or that a defect was carried
	// across, when neither is true.
	if issue, isDefect := IsDefectReason(ReasonTenantColumnNotAPredicate); isDefect {
		t.Fatalf("the tenant-column reason is classified as a preserved defect owned by %s; it is a modelling "+
			"statement about a column that selects nothing, not a defect", issue)
	}
	if IsCompilerGapReason(ReasonTenantColumnNotAPredicate) {
		t.Fatal("the tenant-column reason is classified as a compiler gap; the compiler expressed the row completely")
	}
}

// TestTheCompiledScopeIsUnchanged is the load-bearing assertion.
//
// It is the one that fails if somebody implements #3899 as written. The scope
// of a tenant-owned row must be exactly the scope of an org-owned one, because
// the legacy engine gives them the same population.
func TestTheCompiledScopeIsUnchanged(t *testing.T) {
	rep, err := Compile([]RawRow{tenantScopedStaticRow(t, "sys_tenant_scoped")}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_tenant_scoped")

	seen := 0
	for _, pr := range rec.Planes {
		for _, p := range pr.Policies {
			seen++
			if !p.Scope.Organization {
				t.Fatalf("policy %q on plane %q compiled to a narrower scope than organisation (%+v). "+
					"Narrowing an imported policy to its tenant makes it apply to FEWER principals than the legacy "+
					"engine applies it to - for a constraint, a control that governs an organisation today would "+
					"silently govern one team. See ReasonTenantColumnNotAPredicate for the two enforcement "+
					"predicates that establish the population", p.ID, pr.Plane, p.Scope)
			}
			if len(p.Scope.Principals) != 0 || len(p.Scope.Groups) != 0 {
				t.Fatalf("policy %q carries a principal or group selector (%+v); the tenant column must not become one",
					p.ID, p.Scope)
			}
			// And no condition may reach for a tenant attribute either - the
			// other way the same narrowing could arrive.
			for _, path := range p.ReferencedPaths() {
				if strings.Contains(path, "tenant_id") {
					t.Fatalf("policy %q reads %q; the tenant column must not become a condition either. The legacy "+
						"vocabulary does not even agree with itself about whose tenant it names - compile.go maps "+
						"user.tenant_id to principal.tenant_id and bare tenant_id to agent.tenant_id - so picking "+
						"one invents a semantics the rows never had", p.ID, path)
				}
			}
		}
	}
	// ANTI-VACUITY. A row that compiled to no policies at all would satisfy
	// every assertion in the loop above by never entering it.
	if seen == 0 {
		t.Fatal("the tenant-scoped row compiled to no policies, so the scope assertions above examined nothing")
	}
	// The root is the customer's, which is the other half of the claim: a
	// tenant-owned row is organization-root, not system-root.
	for _, pr := range rec.Planes {
		for _, p := range pr.Policies {
			if p.Root != pdp.RootOrganization {
				t.Fatalf("policy %q compiled under root %q; a tenant-owned row is the customer's", p.ID, p.Root)
			}
		}
	}
}

// TestARowWithNothingToReportDoesNotReportIt is the negative control.
//
// Without it the positive test is satisfied by an emitter that fires on every
// row, which would put a reason nobody can act on against the whole shipped
// corpus - and the shipped corpus is the population this compiler mostly runs
// against.
func TestARowWithNothingToReportDoesNotReportIt(t *testing.T) {
	cases := []struct {
		name string
		row  RawRow
		why  string
	}{
		{
			name: "global tenant",
			row:  staticRow(t, "sys_global", nil), // tier=system, tenant_id=global
			why:  "tenant_id='global' is the sentinel that routes a row to the system root; there is no tenant to report",
		},
		{
			name: "system tier with a tenant value",
			row: staticRow(t, "sys_tiered", map[string]any{
				"tier": "system", "tenant_id": "team-finance",
			}),
			why: "a system-tier row is the platform's own, where the column is not a customer scoping statement",
		},
		{
			name: "empty tenant",
			row: staticRow(t, "sys_empty", map[string]any{
				"tier": "tenant", "tenant_id": "", "org_id": "acme",
			}),
			why: "an empty tenant names nothing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Compile([]RawRow{tc.row}, testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rec := rep.Records[0]
			if r := reasonWithCode(rec, ReasonTenantColumnNotAPredicate); r != nil {
				t.Fatalf("reported the tenant column when %s: %q", tc.why, r.Detail)
			}
		})
	}
}

// TestTheDynamicTwinReportsItToo pins the second compiler.
//
// The two rows carry the same column with the same meaning, and the emitter is
// one shared function precisely so they cannot diverge - but a shared function
// called from one site and not the other is exactly the defect that reads as
// working. This is the call site, asserted.
func TestTheDynamicTwinReportsItToo(t *testing.T) {
	row := dynamicRow(t, "dyn_tenant_scoped", map[string]any{
		"tier": "tenant", "tenant_id": "team-finance", "org_id": "acme",
	})
	rep, err := Compile([]RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "dyn_tenant_scoped")
	if r := reasonWithCode(rec, ReasonTenantColumnNotAPredicate); r == nil {
		t.Fatalf("the dynamic compiler does not report the untranslated tenant column. Codes: %v", codesOf(rec))
	}
	for _, pr := range rec.Planes {
		for _, p := range pr.Policies {
			if !p.Scope.Organization {
				t.Fatalf("dynamic policy %q compiled to a narrower scope than organisation: %+v", p.ID, p.Scope)
			}
		}
	}
}

// TestTheRootDerivationIsSharedWithTheReason closes the gap the refactor
// opened.
//
// staticRootFor and dynamicRootFor exist so the reason and the compiled policy
// answer "is this row the platform's own" the same way. If they could disagree,
// the disagreement would be invisible in the ordinary case and would show up as
// a reason describing a row the policy had classified the other way.
func TestTheRootDerivationIsSharedWithTheReason(t *testing.T) {
	rows := map[string]RawRow{
		"tenant-owned": tenantScopedStaticRow(t, "sys_owned"),
		"system":       staticRow(t, "sys_platform", nil),
	}
	for name, row := range rows {
		t.Run(name, func(t *testing.T) {
			rep, err := Compile([]RawRow{row}, testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rec := rep.Records[0]
			reported := reasonWithCode(rec, ReasonTenantColumnNotAPredicate) != nil
			var compiledOrgRoot bool
			for _, pr := range rec.Planes {
				for _, p := range pr.Policies {
					if p.Root == pdp.RootOrganization {
						compiledOrgRoot = true
					}
				}
			}
			if reported && !compiledOrgRoot {
				t.Fatal("the reason says this row is the customer's and every compiled policy says it is the platform's")
			}
			if !reported && compiledOrgRoot && name == "tenant-owned" {
				t.Fatal("the policies compiled under the customer root and the reason was not reported")
			}
		})
	}
}

func codesOf(rec Record) []ReasonCode {
	out := make([]ReasonCode, 0, len(rec.Reasons))
	for _, r := range rec.Reasons {
		out = append(out, r.Code)
	}
	return out
}
