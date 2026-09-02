// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package deploymode

import (
	"reflect"
	"testing"
)

// TestAppliesEnterpriseSchemaPartition states, BY NAME, which deployment modes
// have the Enterprise schema.
//
// It is deliberately a hand-written expectation and NOT a loop over
// CanonicalModes checking `contains(categories, "enterprise")` — that would be
// a tautology, an assertion computed from the very map it claims to verify,
// which passes for any map at all. The point of writing the names out is that
// adding a mode, or moving one across the line, fails here and forces the
// decision to be made rather than inherited: the wrong answer on this table
// means a process either queries a table its deployment never created, or
// stops honouring per-organization records that exist.
func TestAppliesEnterpriseSchemaPartition(t *testing.T) {
	want := map[string]bool{
		// community-schema deployments: identity_org_settings CANNOT exist.
		"community":      false,
		"evaluation":     false,
		"community-saas": false,
		// enterprise-schema deployments: it can, and does.
		"in-vpc-enterprise": true,
		"in-vpc-healthcare": true,
		"in-vpc-banking":    true,
		"in-vpc-travel":     true,
		"saas":              true,
		// aliases resolve to their canonical mode's answer.
		"invpc":      true,
		"enterprise": true,
	}

	// Every recognised spelling must appear above. A mode added to the maps
	// and not to this table is the drift this test exists to catch, and a
	// table that merely happened to cover today's modes would not catch it.
	got := map[string]bool{}
	for _, mode := range RecognisedModes() {
		got[mode] = AppliesCategory(mode, CategoryEnterprise)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the enterprise-schema partition changed.\n got: %v\nwant: %v\n"+
			"If this is intended, update the table AND check every caller of "+
			"AppliesEnterpriseSchema: the wrong answer means a process reads a table "+
			"its deployment never created, or ignores records that exist.", got, want)
	}
}

// TestUnsetResolvesToTheCommunitySchema pins the one case an operator most
// often lands in by accident.
//
// Unset selects the `community` migration set, so identity_org_settings cannot
// exist — while the RUNTIME posture of an unset value is the enterprise one
// (isCommunityMode fails closed). That asymmetry is issue #3128 and is NOT
// resolved here; this package answers the schema question only, and answering
// it with the schema selector's own answer is the whole point.
func TestUnsetResolvesToTheCommunitySchema(t *testing.T) {
	mode, recognised := Resolve("")
	if !recognised || mode != Unset {
		t.Fatalf(`Resolve("") = (%q, %v), want (Unset, true)`, mode, recognised)
	}
	if Unset != "community" {
		t.Fatalf(`Unset = %q, want "community": the schema selector's default moved`, Unset)
	}
	if AppliesCategory("", CategoryEnterprise) {
		t.Fatal(`AppliesCategory("", "enterprise") = true; an unset DEPLOYMENT_MODE ` +
			`applies migrations/core/ only, so the Enterprise tables do not exist`)
	}
}

// TestUnrecognisedAnswersYes pins the direction of the fail-safe, and the
// reasoning behind it, so a later edit that flips it has to argue with this.
func TestUnrecognisedAnswersYes(t *testing.T) {
	if _, recognised := Resolve("enfore"); recognised {
		t.Fatal(`Resolve("enfore") reported the typo as recognised`)
	}
	if !AppliesCategory("enfore", CategoryEnterprise) {
		t.Fatal("an unrecognised mode must answer YES: the agent refuses to boot on one, " +
			"and for the orchestrator answering NO would silently stop honouring records " +
			"that may well exist, while YES restores the pre-#3602 behaviour — a read that " +
			"fails, is counted, and falls back to the process mode")
	}
}

// TestAppliesCategoryCoversTheOtherCategories checks the predicate is general
// rather than an enterprise special case, using categories the map actually
// declares.
func TestAppliesCategoryCoversTheOtherCategories(t *testing.T) {
	cases := []struct {
		mode, category string
		want           bool
	}{
		{"community", "core", true},
		{"community-saas", "community-saas", true},
		{"in-vpc-enterprise", "community-saas", false},
		{"saas", "industry/banking", true},
		{"in-vpc-enterprise", "industry/banking", false},
		{"community", "internal", false},
	}
	for _, c := range cases {
		if got := AppliesCategory(c.mode, c.category); got != c.want {
			t.Errorf("AppliesCategory(%q, %q) = %v, want %v", c.mode, c.category, got, c.want)
		}
	}
}

// TestAliasesResolveToCanonicalModes mirrors the invariant the agent's own
// migration tests hold: every alias names a canonical mode, and no alias is
// also a canonical name.
func TestAliasesResolveToCanonicalModes(t *testing.T) {
	for alias, canonical := range Aliases() {
		if _, ok := CanonicalModes()[canonical]; !ok {
			t.Errorf("alias %q resolves to %q, which is not a canonical mode", alias, canonical)
		}
		if _, ok := CanonicalModes()[alias]; ok {
			t.Errorf("%q is both an alias and a canonical mode", alias)
		}
	}
}

// TestCurrentReadsTheEnvironment covers the one env read in the package.
func TestCurrentReadsTheEnvironment(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	if got := Current(); got != "community-saas" {
		t.Fatalf("Current() = %q, want community-saas", got)
	}
	if AppliesEnterpriseSchema() {
		t.Fatal("AppliesEnterpriseSchema() = true under DEPLOYMENT_MODE=community-saas; " +
			"that is the exact live defect #3602 fixes — try.getaxonflow.com's agent wired " +
			`the store and logged 'relation "identity_org_settings" does not exist' per org per TTL window`)
	}
	t.Setenv("DEPLOYMENT_MODE", "saas")
	if !AppliesEnterpriseSchema() {
		t.Fatal("AppliesEnterpriseSchema() = false under DEPLOYMENT_MODE=saas; " +
			"production-us would stop honouring per-organization compat modes it has records for")
	}
}

// TestExportedMapsAreCopies pins that the shared definition cannot be mutated
// by a consumer.
//
// These maps were package-private to platform/agent before #3602 moved them
// here. Exporting the map OBJECT would have let any package in the tree edit
// the migration selector's input at runtime - and that selector decides which
// database schema a deployment applies. R3 round 1 flagged it; there were no
// writers, which is the point at which it is cheap to close.
func TestExportedMapsAreCopies(t *testing.T) {
	got := CanonicalModes()
	got["community"] = []string{"core", "enterprise"}
	delete(got, "saas")
	got["a-mode-nobody-declared"] = []string{"core"}

	if AppliesCategory("community", CategoryEnterprise) {
		t.Fatal("mutating the returned map changed the answer for community; " +
			"CanonicalModes returned the live map, not a copy")
	}
	if !AppliesCategory("saas", CategoryEnterprise) {
		t.Fatal("deleting from the returned map removed a mode from the real table")
	}
	if _, recognised := Resolve("a-mode-nobody-declared"); recognised {
		t.Fatal("adding to the returned map made an undeclared mode recognised")
	}

	// The nested slices are copies too: a shallow copy would share them, and
	// appending a category to one is the same defect one level down.
	got2 := CanonicalModes()
	got2["community"][0] = "enterprise"
	if !AppliesCategory("community", "core") || AppliesCategory("community", CategoryEnterprise) {
		t.Fatal("the category slices are shared; the copy is shallow")
	}

	al := Aliases()
	al["enterprise"] = "community"
	if mode, _ := Resolve("enterprise"); mode != "in-vpc-enterprise" {
		t.Fatalf("mutating the returned alias map changed Resolve: got %q", mode)
	}
}
