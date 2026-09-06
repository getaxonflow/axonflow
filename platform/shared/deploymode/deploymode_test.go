// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package deploymode

import (
	"reflect"
	"sort"
	"testing"
)

// axes is the answer BOTH axes give for one DEPLOYMENT_MODE spelling.
type axes struct {
	enterpriseSchema   bool
	communityPosture   bool
	enterpriseEntitled bool
}

// TestDeploymentModePartitions states, BY NAME, what every recognised
// DEPLOYMENT_MODE spelling means on BOTH axes this package owns.
//
// It is deliberately a hand-written expectation and NOT a loop over
// CanonicalModes checking `contains(categories, "enterprise")` - that would be
// a tautology, an assertion computed from the very map it claims to verify,
// which passes for any map at all. The point of writing the names out is that
// adding a mode, or moving one across either line, fails here and forces the
// decision to be made rather than inherited.
//
// # ALL THREE COLUMNS IN ONE TABLE IS THE POINT (#3713)
//
// The schema column was here before; the posture column had no home in the
// tree at all, so the three spellings where the two DISAGREE - unset,
// evaluation and community-saas - were a fact nobody could read off any single
// file. A second table in a second package would have been two things to keep
// in step, and the one that drifted would be the one fewer people read. This
// is the file that has to be edited when a mode is added, and it now refuses
// to let either answer be supplied by default.
//
// The ENTITLEMENT column arrived third, with the connector-limit classifier
// (#3713 again). It could have gone in a second table in this same package and
// deliberately did not, for the reason the paragraph above gives: a second
// table over the same mode list is two things to keep in step, and the one that
// drifts is the one fewer people read. It happens to AGREE with the schema
// column on every recognised spelling today - which is exactly why it needs to
// be visible here rather than derived from it, since deriving it would mean a
// mode gaining one Enterprise-only TABLE silently gains unlimited Enterprise
// LIMITS.
//
// The wrong answer in the schema column means a process queries a table its
// deployment never created, or stops honouring per-organization records that
// exist. The wrong answer in the posture column means authentication is off.
// The wrong answer in the entitlement column either hands a paid limit to a
// deployment that has bought nothing, or revokes one a customer is paying for.
func TestDeploymentModePartitions(t *testing.T) {
	want := map[string]axes{
		// community-schema deployments: identity_org_settings CANNOT exist.
		// Only ONE of them is also the Community runtime posture.
		"community":      {enterpriseSchema: false, communityPosture: true, enterpriseEntitled: false},
		"evaluation":     {enterpriseSchema: false, communityPosture: false, enterpriseEntitled: false},
		"community-saas": {enterpriseSchema: false, communityPosture: false, enterpriseEntitled: false},
		// enterprise-schema deployments: it can, and does. None is the
		// Community posture.
		"in-vpc-enterprise": {enterpriseSchema: true, communityPosture: false, enterpriseEntitled: true},
		"in-vpc-healthcare": {enterpriseSchema: true, communityPosture: false, enterpriseEntitled: true},
		"in-vpc-banking":    {enterpriseSchema: true, communityPosture: false, enterpriseEntitled: true},
		"in-vpc-travel":     {enterpriseSchema: true, communityPosture: false, enterpriseEntitled: true},
		"saas":              {enterpriseSchema: true, communityPosture: false, enterpriseEntitled: true},
		// aliases resolve to their canonical mode's SCHEMA answer. They do NOT
		// resolve for the posture answer - see IsCommunityPosture on why that
		// is exact-match rather than Resolve-based - which costs nothing today
		// because neither alias names community, and TestNoAliasSelectsAPosture
		// is what keeps that true.
		"invpc":      {enterpriseSchema: true, communityPosture: false, enterpriseEntitled: true},
		"enterprise": {enterpriseSchema: true, communityPosture: false, enterpriseEntitled: true},
	}

	// Every recognised spelling must appear above. A mode added to the maps
	// and not to this table is the drift this test exists to catch, and a
	// table that merely happened to cover today's modes would not catch it.
	got := map[string]axes{}
	for _, mode := range RecognisedModes() {
		got[mode] = axes{
			enterpriseSchema:   AppliesCategory(mode, CategoryEnterprise),
			communityPosture:   IsCommunityPosture(mode),
			enterpriseEntitled: IsEnterpriseEntitled(mode),
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the DEPLOYMENT_MODE partition changed.\n got: %+v\nwant: %+v\n"+
			"If this is intended, update the table AND check every caller of the axis that moved. "+
			"A wrong enterpriseSchema means a process reads a table its deployment never created, "+
			"or ignores records that exist. A wrong communityPosture means authentication is off.", got, want)
	}

	// ANTI-VACUITY. An empty RecognisedModes() makes both maps empty and
	// DeepEqual would then compare nothing against a table nobody could see was
	// unused - except that `want` is non-empty, so this cannot silently pass.
	// State it anyway, because the failure it guards against is the extraction
	// breaking rather than the code changing.
	if len(got) != len(want) {
		t.Fatalf("RecognisedModes() returned %d spellings; the table declares %d", len(got), len(want))
	}

	// THE DISAGREEMENT IS THE FINDING, so assert it exists rather than leaving
	// it as an emergent property of the table above. If a future edit ever made
	// the two columns identical, every argument for keeping them apart - and
	// #3128 - would be dead, and that should be noticed here rather than
	// inferred by the next reader.
	var disagreeing []string
	for mode, a := range got {
		// A community-SCHEMA mode that is not the community POSTURE.
		if !a.enterpriseSchema && !a.communityPosture {
			disagreeing = append(disagreeing, mode)
		}
	}
	sort.Strings(disagreeing)
	if len(disagreeing) == 0 {
		t.Error("no recognised mode has the community schema without the Community posture. " +
			"The two axes have become the same question, so they no longer need to be two - " +
			"or the posture predicate stopped answering. Either way #3128 needs revisiting.")
	}
	// The package doc names these two by name, and a doc that names a set is a
	// doc that goes wrong when the set changes.
	if want := []string{"community-saas", "evaluation"}; !reflect.DeepEqual(disagreeing, want) {
		t.Errorf("the recognised modes with a community schema and no Community posture are %v, "+
			"want %v. The package doc names them; update it, and check #3128 still reads correctly.",
			disagreeing, want)
	}
}

// TestUnsetDisagreesAcrossTheTwoAxes pins issue #3128 itself: the one input an
// operator lands in by accident, where this package's two answers are opposite.
//
// Unset is NOT a member of RecognisedModes() - it is handled by Resolve rather
// than declared as a mode - so the table above cannot cover it, and a reader
// who trusted that table alone would miss the row that matters most.
func TestUnsetDisagreesAcrossTheTwoAxes(t *testing.T) {
	if AppliesCategory("", CategoryEnterprise) {
		t.Error(`AppliesCategory("", CategoryEnterprise) = true; unset selects the community schema`)
	}
	if IsCommunityPosture("") {
		t.Error(`IsCommunityPosture("") = true; #3096 made unset fail CLOSED, because the ` +
			`Community posture disables authentication and must be asked for by name`)
	}
}

// TestNoAliasSelectsAPosture is the guard on the one way the two axes could
// come to disagree SILENTLY.
//
// IsCommunityPosture matches the raw value exactly and does not go through
// Resolve, on purpose: an alias is a schema convenience, and a widening of the
// posture set turns authentication off. Today no alias names a posture mode, so
// the two behave identically and nothing reveals the difference. The day an
// alias like "comm" -> "community" is declared, the schema half accepts it and
// the posture half does not, and that is a decision somebody must make rather
// than discover. This test fails on the commit that adds such an alias.
func TestNoAliasSelectsAPosture(t *testing.T) {
	for alias, canonical := range Aliases() {
		if IsCommunityPosture(canonical) {
			t.Errorf("alias %q resolves to %q, which selects the Community RUNTIME posture. "+
				"IsCommunityPosture matches the RAW value, so %q does NOT get that posture while "+
				"it DOES get %q's schema - the two axes now disagree for an input an operator can "+
				"write. Decide explicitly: either widen IsCommunityPosture (which turns "+
				"authentication off for a new spelling - see #3096) or document the split here.",
				alias, canonical, alias, canonical)
		}
		if IsCommunitySaasPosture(canonical) {
			t.Errorf("alias %q resolves to %q, which selects the community-SaaS posture; same "+
				"argument as the Community posture above", alias, canonical)
		}
	}
}

// TestPostureConstantsAreCanonicalModes pins the two spellings the posture
// predicates use against the schema selector's own map.
//
// ModeCommunity and ModeCommunitySaas are used as KEYS of canonicalModes, so a
// typo in either would move a mode rather than fail to compile - "communtiy"
// would simply become a canonical mode nobody deploys, while the posture
// predicate answered false for the real one. This is the assertion that a
// key-and-predicate pair cannot silently become a pair of orphans.
func TestPostureConstantsAreCanonicalModes(t *testing.T) {
	for _, mode := range []string{ModeCommunity, ModeCommunitySaas} {
		if _, ok := CanonicalModes()[mode]; !ok {
			t.Errorf("%q is used by a posture predicate but is not a canonical mode; the schema "+
				"half and the posture half are spelling the same mode differently", mode)
		}
	}
	if !IsCommunityPosture(ModeCommunity) || !IsCommunitySaasPosture(ModeCommunitySaas) {
		t.Error("a posture predicate does not accept its own constant")
	}
	// The two postures are distinct sets: csaas is deliberately NOT community.
	if IsCommunityPosture(ModeCommunitySaas) || IsCommunitySaasPosture(ModeCommunity) {
		t.Error("the Community and community-SaaS postures overlap; a csaas deployment is on the " +
			"public internet and must not get the posture that disables authentication")
	}
}

// TestPostureAcceptingSetIsExactlyOneToken pins the contract every one of the
// four pre-#3713 copies stated in prose and none of them tested: the set is the
// canonical token, not trimmed, not case-folded.
//
// The one site that DOES normalise - devTokenEndpointEnabled in
// platform/agent/dev_token_handler.go - is deliberate and stays; its own
// comment says why it must not take its accepting set from this predicate.
func TestPostureAcceptingSetIsExactlyOneToken(t *testing.T) {
	for _, raw := range []string{" community", "community ", "Community", "COMMUNITY", "\tcommunity", "communit", "communityx", ""} {
		if IsCommunityPosture(raw) {
			t.Errorf("IsCommunityPosture(%q) = true; every widening of this set DISABLES "+
				"authentication, so the accepting set is the canonical token and nothing else", raw)
		}
	}
	for _, raw := range []string{" community-saas", "Community-SaaS", "community_saas", "community", ""} {
		if IsCommunitySaasPosture(raw) {
			t.Errorf("IsCommunitySaasPosture(%q) = true; same argument", raw)
		}
	}
	if !IsCommunityPosture("community") || !IsCommunitySaasPosture("community-saas") {
		t.Fatal("the predicates reject their own canonical token; the loops above prove nothing")
	}
}

// TestCurrentPosturePredicatesReadTheEnvironment covers the env-reading forms,
// which are what every call site actually uses.
func TestCurrentPosturePredicatesReadTheEnvironment(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	if !CurrentIsCommunityPosture() || CurrentIsCommunitySaasPosture() {
		t.Error("DEPLOYMENT_MODE=community: want Community posture, not csaas")
	}
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	if CurrentIsCommunityPosture() || !CurrentIsCommunitySaasPosture() {
		t.Error("DEPLOYMENT_MODE=community-saas: want csaas posture, NOT the Community posture - " +
			"try.getaxonflow.com is on the public internet and the Community posture disables " +
			"authentication")
	}
	t.Setenv("DEPLOYMENT_MODE", "")
	if CurrentIsCommunityPosture() || CurrentIsCommunitySaasPosture() {
		t.Error("an unset DEPLOYMENT_MODE selected a posture; #3096 made unset fail closed")
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
