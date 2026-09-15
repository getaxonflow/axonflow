// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// THE #3878 COMPARISON CENSUS: every place in the tree where two identifiers
// are decided to be the same one, with the classification each site makes and
// the reason for it.
//
// # WHY A CENSUS RATHER THAN FIVE MORE FIXES
//
// The class is "an identity compared by a form that carries its
// CLASSIFICATION". Five instances were found across three subsystems before
// this one was written, so it is a class with a sixth on the way rather than a
// set of bugs - and the reason is structural: PrincipalID is a comparable
// struct whose `==` silently includes Type, and contract.ID's String() renders
// it, so the wrong semantics is what an author gets for free. Every one of the
// five looked exactly like correct code at review.
//
// So the durable half of #3878 is not the six-line comparison change. It is
// this: a new site is UNKNOWN until somebody classifies it and writes down
// why, and an unclassified site fails the build. The classification is the
// deliverable; the inventory below is the record of it.
//
// # THE FOUR CLASSES, AND WHAT DECIDES WHICH
//
// The question is never "which fields are in the struct". It is WHAT THE
// EQUALITY IS FOR:
//
//	classIdentity     the site asks WHO. The classification is asserted
//	                  independently by whatever produced each side - a token
//	                  on one side, a directory or a typed-in configuration on
//	                  the other - so including it turns one person into two.
//	classClassified   the site asks WHICH ENTRY in one classified structure
//	                  built from ONE source. The type is part of what the
//	                  structure records: a directory graph vertex, a catalog
//	                  key, a resource identifier whose type names its class.
//	                  Folding it there would merge two distinct things, which
//	                  is the same defect pointing the other way.
//	classOpen         a genuine instance of the class that this change does
//	                  NOT fix, with the issue that owns it. A row here is a
//	                  gap that stays visible in a guard rather than in prose.
//	classRuled        a genuine instance that was MEASURED and deliberately
//	                  not folded, with the measurement's premise carried by a
//	                  named guard rather than by this comment. It is what an
//	                  OPEN row becomes when somebody drives the reachability
//	                  question to an answer: the site is unchanged, but the
//	                  reason it is unchanged is now executable and fails on
//	                  the day it stops being true.
//
// The single fact that separates the first two is HOW MANY SOURCES supply the
// two sides' classifications. Two sources is where they diverge.
//
// classOpen and classRuled are separated by a different fact: whether anything
// FAILS when the gap becomes live. An open row is tracked by an issue somebody
// has to remember to re-read. A ruled row is tracked by a test.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil/gocensus"
)

// A site's classification.
const (
	classIdentity   = "identity"
	classClassified = "classified"
	classOpen       = "open"
	classRuled      = "ruled"
)

// ruledGuardRe matches the name of a Go test in a classRuled row's reason.
//
// It is deliberately a SHAPE and not a list: a list of the guards that exist
// today is a list that is one entry short the day a fourth is written, and the
// row it would reject is a correct one. Four characters after "Test" is enough
// to exclude the word "Test" appearing on its own in prose, which is the only
// false positive this needs to rule out.
var ruledGuardRe = regexp.MustCompile(`\bTest[A-Za-z0-9_]{4,}\b`)

// The reasons, named so a repeated one is one sentence rather than twenty
// copies that drift apart.
const (
	reasonIdentityRule = "the one place the identity rule is stated; it folds the classification on purpose, " +
		"and every caller inherits the choice from here rather than making it again (#3876, #3878)"

	reasonSelfExclusion = "self-exclusion asks WHO raised the request. The chain's classification comes from the " +
		"request's token and the pool's from configuration assembled out of several directories, so including it " +
		"left a requester eligible to approve their own escalation (#3878)"

	reasonChainRepeat = "\"no principal repeats\" asks whether a chain revisits a SUBJECT, so a hop that names one " +
		"already present is a repeat whatever principal type it declares (#3878)"

	reasonGraphNode = "a vertex in ONE directory snapshot from ONE source. The type is part of what the node IS - a " +
		"Group has members and a User does not - so folding it would let a group become its own parent and would " +
		"return a group's ancestors for a user with the same directory id. One source, so the two sides cannot " +
		"carry divergent classifications"

	reasonCatalogKey = "the rendered identifier IS the catalog key, and the values are Action, Tool and Resource " +
		"identifiers rather than principals. For a non-principal kind the type names the entity CLASS, so " +
		"JiraIssue::conn:ABC-1 and JiraProject::conn:ABC-1 are two resources; contract.IdentityKey keeps the type " +
		"for exactly these and this comparison already agrees with it"

	reasonRequestConsistency = "the chain root and the principal are two writes of ONE value by ONE producer, so this " +
		"asks whether the request is internally consistent. Widening it would let a request declare a principal its " +
		"own chain root classifies differently, which is the opposite of what the cycle check beside it needs"

	reasonEligibleSet = "an eligible set names GROUPS, and a Group and a User sharing a local part are two different " +
		"things to name - one is a set of subjects and the other is a subject. Folding the type would merge them"

	reasonRequestAttribute = "one side is already a STRING supplied as a request attribute (principal.groups), so the " +
		"rendered form is the only currency the two sides share. This mirrors the evaluator rather than deciding " +
		"anything of its own; the question of what currency THAT should be is " + openScopeIssue

	reasonScopeMirrorsEvaluator = "an authoring-time overlap and containment check over policy scopes, which must " +
		"agree with what the evaluator does. The PDP compiles scope principals into an equality of rendered forms, " +
		"so making authoring fold the type here would report overlaps the PDP does not have. It moves when " +
		"pdp.compileScope moves and not before, which is the ruling recorded on " + openScopeIssue + "; the same " +
		"three guards named in reasonScopeCurrencyRuled are what fail when that ruling stops holding, and " +
		"TestAScopePrincipalSelectsOnTheRenderedFormIncludingTheType is the behaviour both sides mirror"

	reasonScopeCurrencyRuled = "policy TARGETING compares a rendered principal, so a policy naming a subject does " +
		"not apply to that subject presented under another classification. MEASURED end to end against a real " +
		"signed bundle and the real evaluator, by " +
		"TestAScopePrincipalSelectsOnTheRenderedFormIncludingTheType: one spelling permits and every other " +
		"classification of the same subject in the same realm is not_applicable. NOT folded, because folding it " +
		"changes which policies apply in both directions at once and the hazard is not reachable - three " +
		"independent facts, each driven rather than reasoned, and each now a guard that fails when it stops " +
		"holding. No production compiler emits Scope.Principals at all " +
		"(shadow.TestNoCompiledDocumentSelectsOnNamedPrincipals). Every shipped realm accepts exactly the one " +
		"subject type its claim mapping mints, so Credential.SubjectType cannot widen and a subject does not " +
		"arrive spelled two ways (TestEveryShippedRealmAcceptsOnlyTheTypeItMints). And principal.id carries a " +
		"canonical rendered principal and nothing else " +
		"(shadow.TestNoLegacyConditionFieldOverwritesTheCanonicalPrincipal, which is the guard on the one live " +
		"currency defect this measurement found and fixed: legacy user.id was mapped onto principal.id and " +
		"overwrote it). The groups half of the same function makes the same choice through a slice of literals, " +
		"which this scanner does not record - see the boundary note on formConditionLiteral. Recorded on " +
		openScopeIssue

	reasonSelfConsistency = "a guard that the two answers being diffed are about the same principal. Both sides " +
		"derive from the ONE subject the caller passed - the projection's is copied from the closure's - so this is " +
		"a self-consistency assertion and widening it would weaken the only thing stopping Alice's legacy answer " +
		"being compared against Bob's projection"

	reasonProfileAction = "an Action identifier, not a principal. Its type names the action's class and is part of " +
		"the identifier"

	reasonExactDiagnostic = "an EXACTNESS test used to decide whether the two spellings differ, so that a diagnostic " +
		"names the matching chain hop only when naming it adds something. Folding it here would make the message " +
		"redundant on every ordinary exclusion"

	reasonPortalCostBound = "a cost bound on directory round trips. It keys on the identity because two spellings of " +
		"one person are one lookup; the entries themselves still reach provenance.approvers, which is " + openProvIssue

	openScopeIssue = "#3936"
	openProvIssue  = "#3939"
)

// censusRow is one classified site.
//
// Pkg is written without the module prefix that every one of them shares, for
// the same reason the reasons are constants: a column that is identical on
// sixty rows carries no information and hides the column that does.
type censusRow struct {
	Pkg   string
	Decl  string
	Form  string
	Expr  string
	Class string
	Why   string
}

// pkgPrefixes expands the abbreviated Pkg column back to an import path AND
// the module that owns it.
//
// THE MODULE IS RECORDED RATHER THAN DERIVED FROM THE IMPORT PATH. These
// module paths NEST - axonflow/platform/decision and
// axonflow/platform/customer-portal both live under axonflow/platform - so a
// longest-prefix guess would report the portal's package as present in a
// checkout that has only the platform module. That is precisely the community
// mirror, where ee/ does not exist, and the guess would red every portal row
// there as stale.
var pkgPrefixes = map[string]struct{ Module, Path string }{
	"identity":         {platformModule, "axonflow/platform/shared/identity"},
	"agent":            {platformModule, "axonflow/platform/agent"},
	"anchoredenforcer": {platformModule, "axonflow/platform/shared/anchoredenforcer"},
	"contract":         {decisionModule, "axonflow/platform/decision/contract"},
	"authoring":        {decisionModule, "axonflow/platform/decision/authoring"},
	"registry":         {decisionModule, "axonflow/platform/decision/registry"},
	"pdp":              {decisionModule, "axonflow/platform/decision/pdp"},
	"activation":       {decisionModule, "axonflow/platform/decision/activation"},
	"conformance":      {decisionModule, "axonflow/platform/decision/conformance"},
	"portal-api":       {"axonflow/platform/customer-portal", "axonflow/platform/customer-portal/api"},
}

// censusInventory is the classified set. Everything the scanner finds must be
// here, and everything here whose module is present in the checkout must be
// found.
func censusInventory() []censusRow {
	return []censusRow{
		// ---------------------------------------------------------------
		// classIdentity: the sites that ask WHO, and fold the classification.
		// ---------------------------------------------------------------
		{"contract", "SameEntity", formIdentity, "a.IdentityKey()", classIdentity, reasonIdentityRule},
		{"contract", "SameEntity", formIdentity, "b.IdentityKey()", classIdentity, reasonIdentityRule},
		{"authoring", "samePerson", formIdentity, "contract.SameEntity(a, b)", classIdentity,
			"the two-person rule for policy publication and for activation, delegating to the one rule rather than " +
				"restating it - a second spelling of \"are these the same person\" is two answers that agree until " +
				"one changes (#3876)"},
		{"portal-api", "(*TypedAuthoringHandler).checkApprovers", formIdentity, "ap.IdentityKey()", classIdentity,
			reasonPortalCostBound},
		{"contract", "(*Request).Validate", formIdentity, "a.ID.IdentityKey()", classIdentity, reasonChainRepeat},
		{"identity", "(PrincipalID).SameSubject", formIdentity, "p.SubjectKey()", classIdentity, reasonIdentityRule},
		{"identity", "(PrincipalID).SameSubject", formIdentity, "other.SubjectKey()", classIdentity, reasonIdentityRule},
		{"identity", "(ActorChain).ContainsSubject", formIdentity, "hop.SameSubject(p)", classIdentity, reasonSelfExclusion},
		{"identity", "EligibleApprovers", formIdentity, "m.SubjectKey()", classIdentity,
			"a quorum counts PEOPLE, so the eligible set holds one entry per subject. Nothing deduplicated it, and a " +
				"pool naming one person under two classifications - the same divergence self-exclusion had to be " +
				"corrected for - offered two approvers to a clause requiring two (#3878, found by the hostile review " +
				"of the exclusion fix)"},
		{"identity", "admitChain", formIdentity, "hop.SubjectKey()", classIdentity, reasonChainRepeat},
		{"identity", "matchedHopSuffix", formIdentity, "hop.SameSubject(member)", classIdentity, reasonSelfExclusion},

		// ---------------------------------------------------------------
		// classClassified: the sites that ask WHICH ENTRY, and must not fold.
		// ---------------------------------------------------------------

		// The request contract's own consistency check, deliberately NOT the
		// same answer as the cycle check three lines below it.
		{"contract", "(*Request).Validate", formCompare, "r.Context.ActorChain[0].ID != r.Principal", classClassified,
			reasonRequestConsistency},
		{"contract", "(ApprovalClause).canonical", formCompareRendered, "v.String() == prev", classClassified, reasonEligibleSet},

		// The action, tool and resource catalogs. The rendered identifier is
		// the key by design; none of these values is a principal.
		{"authoring", "(*Catalog).Validate", formCompareRendered, "entry.ID.String() != key", classClassified, reasonCatalogKey},
		{"authoring", "(*Catalog).actionsReached", formKeyRendered, "named[id.String()]", classClassified, reasonCatalogKey},
		{"authoring", "actionsCover", formKeyRendered, "set[e.ID.String()]", classClassified, reasonCatalogKey},
		{"authoring", "intersectActions", formKeyRendered, "set[e.ID.String()]", classClassified, reasonCatalogKey},
		{"authoring", "validatePolicyAgainstCatalog", formKeyRendered, "cat.Actions[id.String()]", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).Action", formKeyRendered, "c.actions[id.String()]", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).Posture", formKeyRendered, "c.actions[id.String()]", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).RegisterAction", formCompareRendered, "existing.String() != key", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).RegisterTool", formCompareRendered, "existing.String() != key", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).RegisterTool", formKeyRendered, "c.actions[t.Action.String()]", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).RequiredCapabilityCheck", formKeyRendered, "c.actions[action.String()]", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).ResolveTool", formKeyRendered, "c.actions[rec.Action.String()]", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).Tool", formKeyRendered, "c.tools[id.String()]", classClassified, reasonCatalogKey},
		{"registry", "(*Catalog).Validate", formKeyRendered, "c.actions[t.Action.String()]", classClassified, reasonCatalogKey},
		{"registry", "aliasCollisions", formKeyRendered, "records[target.String()]", classClassified, reasonCatalogKey},
		{"pdp", "(*Registry).Admit", formKeyRendered, "r.Actions[req.Action.String()]", classClassified, reasonCatalogKey},
		// The anchored enforcer finds the requested action's entry in the
		// activation's vocabulary, the same lookup pdp's admission makes one row
		// up, over the same one-source catalog (#3895 PR-A2). It moved from the
		// agent's seam to the enforcer every enforcing process shares.
		{"anchoredenforcer", "(*Enforcer).Evaluate", formKeyRendered, "act.Snapshot.Catalog.Actions[action.String()]", classClassified, reasonCatalogKey},
		// The action's display name, keyed exactly like Catalog.Actions in the
		// same one-source catalog, for the audit row's action_name (PRD v11 §1.14).
		{"activation", "(*Activation).ActionName", formKeyRendered, "a.Snapshot.Catalog.ActionLabels[action.String()]", classClassified, reasonCatalogKey},
		{"pdp", "isPierced", formKeyRendered, "allowed[r.String()]", classClassified, reasonCatalogKey},
		{"pdp", "(*CompatibilityProfile).Apply", formCompare, "e.Action != action", classClassified, reasonProfileAction},
		{"pdp", "compileActions", formConditionLiteral, "Compare(ActionIDPath, OpEq, id.String())", classClassified, reasonCatalogKey},
		{"conformance", "SystemDocument", formConditionLiteral,
			`pdp.Compare(PathResourceProject, pdp.OpEq, resource("Project", "QUARANTINE").String())`, classClassified,
			reasonCatalogKey},
		{"conformance", "SystemDocument", formConditionLiteral,
			`pdp.Intersects(PathPrincipalGroups, group("legal").String(), group("compliance").String())`, classClassified,
			reasonRequestAttribute},
		{"pdp", "witnessesFor", formKeyRendered, "member[g.String()]", classClassified, reasonRequestAttribute},
		{"pdp", "witnessesFor", formKeyRendered, "seen[g.String()]", classClassified, reasonRequestAttribute},

		// The normalized directory graph and its SCIM loader. One source, one
		// snapshot, and the type is part of the vertex.
		{"identity", "type DirectoryGraph", formMapKey, "map[PrincipalID]DirectoryEntity", classClassified, reasonGraphNode},
		{"identity", "type DirectoryGraph", formMapKey, "map[PrincipalID][]PrincipalID", classClassified, reasonGraphNode},
		{"identity", "type ClosureResult", formMapKey, "map[PrincipalID]WitnessPath", classClassified, reasonGraphNode},
		{"identity", "LoadDirectoryGraph", formMapKey, "map[PrincipalID]DirectoryEntity", classClassified, reasonGraphNode},
		{"identity", "LoadDirectoryGraph", formMapKey, "map[PrincipalID][]PrincipalID", classClassified, reasonGraphNode},
		{"identity", "NewAuthoritativeClosure", formMapKey, "map[PrincipalID]WitnessPath", classClassified, reasonGraphNode},
		{"identity", "NewTruncatedClosure", formMapKey, "map[PrincipalID]WitnessPath", classClassified, reasonGraphNode},
		{"identity", "(*DirectoryGraph).Closure", formMapKey, "map[PrincipalID]WitnessPath", classClassified, reasonGraphNode},
		{"identity", "(*DirectoryGraph).Closure", formMapKey, "map[PrincipalID]bool", classClassified, reasonGraphNode},
		{"identity", "(*DirectoryGraph).expandParents", formCompare, "parent == node", classClassified, reasonGraphNode},
		{"identity", "(*DirectoryGraph).membershipLoopsAmong", formCompare, "last == node", classClassified, reasonGraphNode},
		{"identity", "(*DirectoryGraph).membershipLoopsAmong", formMapKey, "map[PrincipalID]bool", classClassified, reasonGraphNode},
		{"identity", "(*DirectoryGraph).membershipLoopsAmong", formMapKey, "map[PrincipalID]int", classClassified, reasonGraphNode},
		{"identity", "loopWarning", formCompare, "parent == members[0]", classClassified, reasonGraphNode},
		{"identity", "dedupePrincipals", formCompare, "p != out[len(out)-1]", classClassified, reasonGraphNode},
		{"identity", "dedupeUnvisited", formMapKey, "map[PrincipalID]bool", classClassified, reasonGraphNode},
		{"identity", "dedupeUnvisited", formMapKey, "map[PrincipalID]struct{}", classClassified, reasonGraphNode},
		{"identity", "NormalizeSCIM", formMapKey, "map[PrincipalID]bool", classClassified, reasonGraphNode},
		{"identity", "NormalizeSCIM", formMapKey, "map[[2]PrincipalID]bool", classClassified, reasonGraphNode},
		{"identity", "scanMembershipDisagreements", formMapKey, "map[[2]PrincipalID]bool", classClassified, reasonGraphNode},
		{"identity", "scanMembershipDisagreements", formCompare, "out[i].Group != out[j].Group", classClassified, reasonGraphNode},
		{"identity", "scanMembershipDisagreements", formCompare, "out[i].Subject != out[j].Subject", classClassified, reasonGraphNode},

		// The shadow-mode diff's own precondition, and the #3878 diagnostic.
		{"identity", "matchedHopSuffix", formCompare, "hop == member", classClassified, reasonExactDiagnostic},

		// ---------------------------------------------------------------
		// classRuled: measured, deliberately not folded, tripwired.
		// ---------------------------------------------------------------
		{"pdp", "compileScope", formConditionLiteral, "Compare(PrincipalIDPath, OpEq, p.String())", classRuled,
			reasonScopeCurrencyRuled},
		{"authoring", "sharesID", formKeyRendered, "set[x.String()]", classRuled, reasonScopeMirrorsEvaluator},
		{"authoring", "sharesID", formKeyRendered, "set[y.String()]", classRuled, reasonScopeMirrorsEvaluator},
		{"authoring", "containsAllIDs", formKeyRendered, "set[x.String()]", classRuled, reasonScopeMirrorsEvaluator},
		{"authoring", "containsAllIDs", formKeyRendered, "set[y.String()]", classRuled, reasonScopeMirrorsEvaluator},
	}
}

// TestPrincipalComparisonCensus is the guard.
//
// FOUR ASSERTIONS, and each catches something the others cannot:
//
//  1. every site the scanner finds is classified. This is the one that fails
//     on a NEW bad comparison.
//  2. every classified row is still found, so the inventory cannot rot into a
//     description of a tree that has moved on. A count would not do: a count
//     ratchet cannot see a swap, and the row key includes the normalised
//     expression precisely so an operand change is visible.
//  3. the module domain is DERIVED and contains the two modules that define
//     the identifier types, so the census cannot be narrowed by a checkout
//     that happens to be missing something.
//  4. nothing failed to type-check outside the declared unscannable list, so
//     "no findings" cannot be produced by "no data".
func TestPrincipalComparisonCensus(t *testing.T) {
	root := gocensus.RepoRoot(t)
	modules := gocensus.DiscoverModules(t, root, platformModule, decisionModule)

	// (3) THE DOMAIN. Both defining modules must be present; a checkout
	// without them is one this census can say nothing about, and reporting a
	// clean tree there would be the vacuous pass this whole file exists to
	// prevent.
	for _, required := range []string{platformModule, decisionModule} {
		if _, ok := modules[required]; !ok {
			t.Fatalf("module %q was not discovered under %s; the census domain is derived from the module graph and "+
				"cannot be complete without the module that DEFINES one of the two identifier types", required, root)
		}
	}

	// THE EXPECTED SET OF BUILDABLE CONFIGURATIONS DEPENDS ON THE CHECKOUT.
	unscannable := gocensus.Unscannable(modules)
	shape := gocensus.CheckoutShape(modules)
	t.Logf("checkout shape: %s (%d module(s) in the census domain)", shape, len(modules))

	found := map[censusKey]comparisonSite{}
	scanned := 0
	// partial records modules for which some configuration could not be
	// scanned. Their rows are exempt from the staleness direction below,
	// because a row that was never looked for is indistinguishable from one
	// that has moved - and reporting the first as the second is the failure
	// this census is supposed to make impossible, not commit.
	partial := map[string]string{}
	scannedTags := map[string]int{}
	for _, modPath := range sortedKeys(modules) {
		dir := modules[modPath]
		for _, tags := range gocensus.TagSets {
			pair := modPath + "|" + tags
			sites, failures, err := scanModule(dir, tags)
			if err != nil {
				if reason, declared := unscannable[pair]; declared {
					t.Logf("not scanned: module %q under tags %q - %s", modPath, tags, reason)
					partial[modPath] = tags
					continue
				}
				t.Errorf("module %q could not be listed under tags %q, so its packages were not scanned and this "+
					"census says nothing about them. Either fix the module, or add the pair to the %s "+
					"unscannable list with a reason.\n%v", modPath, tags, shape, err)
				partial[modPath] = tags
				continue
			}
			if _, declared := unscannable[pair]; declared {
				t.Errorf("module %q now lists cleanly under tags %q in a %s checkout; its unscannable row is stale "+
					"and must be removed, or the census keeps skipping a configuration it can read", modPath, tags, shape)
			}
			// (4) A package that could not be type-checked is a hole, not a
			// clean result.
			for _, f := range failures {
				t.Errorf("module %q under tags %q: %s\nA package this census cannot type-check is a package it "+
					"reports as having no comparisons.", modPath, tags, f)
				partial[modPath] = tags
			}
			scanned++
			scannedTags[modPath]++
			for _, s := range sites {
				found[keyOf(s)] = s
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no module was scanned at all; every assertion below would pass vacuously")
	}
	// AND THE TWO MODULES THAT DEFINE THE TYPES MUST HAVE BEEN READ. `partial`
	// only suppresses the staleness direction; every undeclared failure above
	// is already an error. What that leaves uncovered is a module whose every
	// configuration is DECLARED unscannable - which for these two would mean
	// the census ran having read neither of the packages the class lives in,
	// and would still report a clean tree.
	for _, defining := range []string{platformModule, decisionModule} {
		if scannedTags[defining] == 0 {
			t.Fatalf("module %q was read under NO configuration, so nothing below is an assertion about the "+
				"package the identifier types live in", defining)
		}
	}

	classified := classifiedIndex(t)

	// (1) A NEW SITE IS UNKNOWN UNTIL SOMEBODY CLASSIFIES IT.
	unknown := unclassifiedSites(found, classified)
	if len(unknown) > 0 {
		t.Errorf(`%d comparison site(s) are not classified in censusInventory():

%s
Each one decides whether two identifiers are the same. Ask what the equality is
FOR, then add a row:

  - classIdentity   it asks WHO, and the two sides' classifications come from
                    different sources (a token and a directory, say). Use
                    PrincipalID.SameSubject or contract.SameEntity.
  - classClassified it asks WHICH ENTRY in one structure built from ONE source,
                    where the type is part of what the entry is.
  - classOpen       it is an instance of the class that is not being fixed, and
                    the reason names the issue that owns it.
  - classRuled      it is an instance that was MEASURED and deliberately not
                    folded, and the reason names both the issue that records
                    the ruling and the Test that fails when the measurement
                    stops holding.

Adding the row without answering that question is the mistake this census
exists to make expensive.`, len(unknown), strings.Join(unknown, "\n"))
	}

	// (2) AND THE INVENTORY CANNOT DESCRIBE A TREE THAT HAS MOVED ON.
	//
	// A row is EXEMPT when the module owning it is absent from this checkout
	// (the community mirror has no ee/ tree), or when a configuration of that
	// module could not be scanned - in which case a row that was not found may
	// simply never have been looked for, and reporting the first as the second
	// is the confusion this census exists to prevent rather than commit.
	stale := staleRows(found, classified, func(_ censusKey, row censusRow) bool {
		owner := pkgPrefixes[row.Pkg].Module
		if _, present := modules[owner]; !present {
			return false
		}
		_, incomplete := partial[owner]
		return !incomplete
	})
	if len(partial) > 0 {
		var skipped []string
		for m, tags := range partial {
			skipped = append(skipped, fmt.Sprintf("  %s under tags %q", m, tags))
		}
		sort.Strings(skipped)
		t.Logf(`the staleness direction did NOT run for %d module(s), because a configuration of each could not be scanned:

%s
Their rows are still held to the "every found site is classified" direction.`, len(partial), strings.Join(skipped, "\n"))
	}
	if len(stale) > 0 {
		t.Errorf(`%d classified site(s) were not found by the scan:

%s
Either the code moved, in which case re-anchor the row, or the site is gone, in
which case delete it. A row that matches nothing is a classification nobody is
holding anything to, and it looks exactly like a healthy one.`, len(stale), strings.Join(stale, "\n"))
	}
}

// classifiedIndex builds the inventory index and checks the inventory's own
// well-formedness: no site classified twice, every class a known one, every
// row carrying a reason, and every OPEN row naming the issue that owns it.
func classifiedIndex(t *testing.T) map[censusKey]censusRow {
	t.Helper()
	classified := map[censusKey]censusRow{}
	for _, row := range censusInventory() {
		where, ok := pkgPrefixes[row.Pkg]
		if !ok {
			t.Fatalf("inventory row %q names package abbreviation %q, which pkgPrefixes does not expand", row.Decl, row.Pkg)
		}
		key := censusKey{Pkg: where.Path, Decl: row.Decl, Form: row.Form, Expr: row.Expr}
		if prior, dup := classified[key]; dup {
			t.Errorf("the inventory classifies %s twice (%s and %s); one site, one classification",
				key, prior.Class, row.Class)
		}
		switch row.Class {
		case classIdentity, classClassified:
		case classOpen:
			// A DELIBERATE GAP NEEDS AN OWNER. Without this, "open" is a way
			// to classify a defect as acceptable and never look at it again.
			if !strings.Contains(row.Why, "#") {
				t.Errorf("%s is classified %q and its reason names no issue; an open instance of this class is "+
					"tracked or it is not open, it is forgotten", key, classOpen)
			}
		case classRuled:
			// A RULED GAP NEEDS AN OWNER AND A TRIPWIRE. The issue records
			// what was decided; the named test is what fails when the
			// measurement the decision rested on stops holding.
			//
			// This checks that the row NAMES one, and it cannot check that
			// the named test exists - it is in another module, and a
			// filesystem hunt from here would be one refactor away from
			// reporting a clean answer about a test it could not find. The
			// enforcement is the test itself, which carries the issue number
			// in its own failure message; this is the index into it.
			if !strings.Contains(row.Why, "#") {
				t.Errorf("%s is classified %q and its reason names no issue; a ruling nobody can look up "+
					"is a comment", key, classRuled)
			}
			if !ruledGuardRe.MatchString(row.Why) {
				t.Errorf("%s is classified %q and its reason names no guard. A ruled instance is one whose "+
					"premise FAILS somewhere when it stops holding; name the Test that does it, or the row "+
					"is an open one wearing a better word.", key, classRuled)
			}
		default:
			t.Errorf("%s carries unknown class %q", key, row.Class)
		}
		if strings.TrimSpace(row.Why) == "" {
			t.Errorf("%s carries no reason; the classification IS the deliverable", key)
		}
		classified[key] = row
	}
	return classified
}

// unclassifiedSites returns the found sites the inventory does not classify,
// rendered for a failure message and sorted.
//
// It is a function rather than an inline loop so the control can drive it with
// a planted site and prove the census's own reporting branch fires. Every
// mutant in this repository's gates removes a check; the branch that REPORTS
// is the one a mutation harness never reaches on its own.
func unclassifiedSites(found map[censusKey]comparisonSite, classified map[censusKey]censusRow) []string {
	var unknown []string
	for key, site := range found {
		if _, ok := classified[key]; !ok {
			unknown = append(unknown, fmt.Sprintf("  %s\n    type: %s", key, site.Type))
		}
	}
	sort.Strings(unknown)
	return unknown
}

// staleRows returns the classified rows the scan did not find, among those the
// caller says are in scope.
//
// Extracted for the same reason unclassifiedSites is: this is the census's
// second reporting branch, it never fires on a healthy tree, and a branch that
// never fires is one nothing proves can. TestTheCensusReportsAPlantedComparison
// drives it with a row deliberately withheld from the found set.
func staleRows(
	found map[censusKey]comparisonSite, classified map[censusKey]censusRow, inScope func(censusKey, censusRow) bool,
) []string {
	var stale []string
	for key, row := range classified {
		if _, ok := found[key]; ok {
			continue
		}
		if !inScope(key, row) {
			continue
		}
		stale = append(stale, fmt.Sprintf("  %s  [%s]", key, row.Class))
	}
	sort.Strings(stale)
	return stale
}

// censusKey is the identity of a site: package, enclosing declaration, form
// and normalised expression. Deliberately not a file or a line - see the note
// on comparisonSite.
type censusKey struct {
	Pkg  string
	Decl string
	Form string
	Expr string
}

func (k censusKey) String() string {
	return fmt.Sprintf("%s %s: %s  (%s)", k.Pkg, k.Decl, k.Expr, k.Form)
}

func keyOf(s comparisonSite) censusKey {
	return censusKey{Pkg: s.Pkg, Decl: s.Decl, Form: s.Form, Expr: s.Expr}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
