// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestEmbeddedRegistryIsValid is what makes the init-time panic in mustParse
// unreachable in a shipped binary.
func TestEmbeddedRegistryIsValid(t *testing.T) {
	if _, err := Parse(registryJSON); err != nil {
		t.Fatalf("the embedded registry does not validate: %v", err)
	}
	r := Load()
	if len(r.Entries) == 0 {
		t.Fatal("the embedded registry is empty")
	}
	if r.Schema != SchemaVersion {
		t.Fatalf("schema %q, want %q", r.Schema, SchemaVersion)
	}
}

// TestEveryOwnerAndImplementationPathExists is the tree-side half of
// validation: a registry can be internally perfect and still name files that
// are not there.
func TestEveryOwnerAndImplementationPathExists(t *testing.T) {
	root := repoRoot(t)
	if err := Load().ValidateAgainstTree(root); err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity. ValidateAgainstTree skips paths that the community mirror
	// legitimately strips, so on a mirror checkout it can have very little to
	// do. Prove it still checked something.
	var checkable int
	for _, e := range Load().Entries {
		if TreeIsCommunityMirror(root) && e.Sync != SyncMirrored {
			continue
		}
		checkable += 1 + len(e.Implementation)
	}
	if checkable < 50 {
		t.Fatalf("only %d path(s) were checkable, so this test proved almost nothing",
			checkable)
	}
}

// mutate parses the real registry, hands the decoded document to fn, and
// returns the error Parse gives for the result.
//
// The mutant is applied to the REAL document rather than to a fixture built for
// the purpose. A fixture is written by the same person as the check and tends
// to be exactly what the check can see; the shipped registry is not.
func mutate(t *testing.T, fn func(doc map[string]any)) error {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(registryJSON, &doc); err != nil {
		t.Fatalf("decoding the registry: %v", err)
	}
	fn(doc)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}
	_, perr := Parse(b)
	return perr
}

func caps(doc map[string]any) []any { return doc["capabilities"].([]any) }

func capByID(t *testing.T, doc map[string]any, id string) map[string]any {
	t.Helper()
	for _, c := range caps(doc) {
		m := c.(map[string]any)
		if m["id"] == id {
			return m
		}
	}
	t.Fatalf("no capability %q in the registry to mutate; this test's subject has been "+
		"renamed and the mutant is now aimed at nothing", id)
	return nil
}

// requireProblem asserts the mutant was caught AND that the message says what
// is wrong. A validator that fails with "invalid" teaches nobody anything, and
// a message that does not name the class cannot be distinguished from an
// unrelated failure that happened to fire.
func requireProblem(t *testing.T, err error, mutant string, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("MUTANT SURVIVED: %s, and the validator accepted the result", mutant)
	}
	msg := err.Error()
	for _, want := range wants {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure for %q does not mention %q.\nGot: %s", mutant, want, msg)
		}
	}
}

// --- failure class 1: duplicate IDs -----------------------------------------

func TestDuplicateCapabilityIDFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		list := caps(doc)
		first := list[0].(map[string]any)
		clone := map[string]any{}
		for k, v := range first {
			clone[k] = v
		}
		// A duplicate id with a DIFFERENT health name, so nothing but the id
		// check can catch it. A clone that duplicated the health name too would
		// be caught by the health-name check and this test would pass without
		// the id check existing at all.
		delete(clone, "health")
		delete(clone, "routes")
		delete(clone, "planes")
		clone["health_absent_reason"] = "a mutant"
		doc["capabilities"] = append(list, clone)
	})
	requireProblem(t, err, "the first capability is duplicated under the same id",
		"duplicate capability id")
}

// --- failure class 2: a missing owner ---------------------------------------

func TestMissingOwnerFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "governance.authzen")["owner"] = ""
	})
	requireProblem(t, err, "governance.authzen loses its owner", "owner is empty")
}

func TestAnOwnerThatIsNotATestFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		// The near-miss that would otherwise pass: an owner that exists and is
		// a real file, but is not a test, so nothing about the capability is
		// known to run.
		capByID(t, doc, "governance.authzen")["owner"] = "platform/agent/authzen_handler.go"
	})
	requireProblem(t, err, "an implementation file is named as the owner",
		"is neither a Go test file nor a shell suite")
}

// --- failure class 3: contradictory source classifications ------------------

// The four contradiction tests below each use a DIFFERENT entry.
//
// They all used `circuit.breaker` until round 2 asked twice. Four tests sharing
// one fixture red together whenever that fixture changes, which reads on a
// board as four independent checks failing and is one — and worse, a mutation
// that makes the shared fixture no longer contradict anything makes all four
// pass at once, for a reason that has nothing to do with the rules they name.
// contradictionSubjects records what each needs, and a control asserts the tree
// still supplies it.
var contradictionSubjects = map[string]Classification{
	"hitl.queue":         ClassEnterpriseImplementation,
	"compliance.rbi":     ClassEnterpriseImplementation,
	"circuit.breaker":    ClassEnterpriseImplementation,
	"governance.authzen": ClassCommunityCore,
}

func TestTheContradictionFixturesAreDistinctAndStillApt(t *testing.T) {
	seen := map[string]bool{}
	for id, want := range contradictionSubjects {
		if seen[id] {
			t.Errorf("%s is used as a fixture twice", id)
		}
		seen[id] = true
		e := Load().ByID(id)
		if e == nil {
			t.Errorf("%s is gone; a contradiction test is aimed at nothing", id)
			continue
		}
		if e.Classification != want {
			t.Errorf("%s is classified %q; its contradiction test needs %q, so the mutant "+
				"aimed at it no longer reaches the rule", id, e.Classification, want)
		}
	}
	if len(seen) < 4 {
		t.Errorf("only %d distinct fixtures for four contradiction rules", len(seen))
	}
}

func TestClassificationContradictingTheEditionFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "hitl.queue")["minimum_edition"] = "community"
	})
	requireProblem(t, err, "an enterprise_implementation is given a community minimum",
		"contradictory classification", "least edition that can run it")
}

func TestClassificationContradictingTheBuildTagFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "compliance.rbi")["build_tag"] = "none"
	})
	requireProblem(t, err, "an enterprise_implementation with no build constraint",
		"contradictory classification", "build_tag")
}

func TestClassificationContradictingTheSyncDispositionFails(t *testing.T) {
	for name, m := range map[string]func(map[string]any){
		"enterprise_implementation that reaches the mirror": func(doc map[string]any) {
			capByID(t, doc, "circuit.breaker")["sync"] = "mirrored"
		},
		"community_core that the mirror strips": func(doc map[string]any) {
			capByID(t, doc, "governance.authzen")["sync"] = "excluded"
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireProblem(t, mutate(t, m), name, "contradictory classification")
		})
	}
}

// --- failure class 4: an unknown edition ------------------------------------

func TestUnknownEditionFails(t *testing.T) {
	// The empty string and the plausible-looking placeholders are all here on
	// purpose: the thing a census actually grows is an encoding for "we have
	// not decided yet", and every one of these is what that looks like.
	for _, bad := range []string{"", "unknown", "tbd", "TBD", "Community", "professional", "none"} {
		t.Run("edition="+bad, func(t *testing.T) {
			err := mutate(t, func(doc map[string]any) {
				capByID(t, doc, "governance.authzen")["minimum_edition"] = bad
			})
			requireProblem(t, err, "minimum_edition set to "+bad, "unknown minimum_edition")
		})
	}
}

func TestUnknownClassificationFails(t *testing.T) {
	for _, bad := range []string{"", "unclassified", "enterprise", "community"} {
		t.Run("classification="+bad, func(t *testing.T) {
			err := mutate(t, func(doc map[string]any) {
				capByID(t, doc, "governance.authzen")["source_classification"] = bad
			})
			requireProblem(t, err, "source_classification set to "+bad,
				"unknown source_classification")
		})
	}
}

func TestUnknownVocabularyMembersFail(t *testing.T) {
	for field, want := range map[string]string{
		"build_tag": "unknown build_tag",
		"sync":      "unknown sync",
	} {
		t.Run(field, func(t *testing.T) {
			err := mutate(t, func(doc map[string]any) {
				capByID(t, doc, "governance.authzen")[field] = "maybe"
			})
			requireProblem(t, err, field+" set to a non-member", want)
		})
	}
}

// --- the /health guard ------------------------------------------------------

func TestAnEntryWithNeitherAHealthBlockNorAReasonFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		c := capByID(t, doc, "governance.decide")
		delete(c, "health_absent_reason")
	})
	requireProblem(t, err, "a capability is neither advertised nor explained",
		"health_absent_reason", "recorded decision rather than a default")
}

func TestAnEntryWithBothAHealthBlockAndAReasonFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "governance.authzen")["health_absent_reason"] = "both at once"
	})
	requireProblem(t, err, "a capability claims to be advertised and absent",
		"both a health block and a health_absent_reason")
}

func TestADuplicateHealthNameFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		c := capByID(t, doc, "governance.decide")
		delete(c, "health_absent_reason")
		c["health"] = map[string]any{
			"name": "authzen_evaluation", "since": "10.3.0",
			"description": "a mutant", "planes": []any{"agent"}, "order": 900,
		}
	})
	requireProblem(t, err, "two capabilities advertise the same /health name",
		"duplicate /health capability name")
}

func TestAClashingHealthOrderFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		c := capByID(t, doc, "governance.decide")
		delete(c, "health_absent_reason")
		c["health"] = map[string]any{
			"name": "a_mutant", "since": "10.4.0", "description": "a mutant",
			"planes": []any{"agent"}, "order": 0,
		}
	})
	requireProblem(t, err, "two entries claim the same position in the served list",
		"is claimed by both")
}

func TestAHealthEntryOnANonExistentPlaneFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		h := capByID(t, doc, "governance.authzen")["health"].(map[string]any)
		h["planes"] = []any{"customer-portal"}
	})
	requireProblem(t, err, "a capability is advertised on a plane that serves no /health",
		"served by")
}

// --- scoring ----------------------------------------------------------------

func TestAScoreWithNoBasisFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "governance.authzen")["score"].(map[string]any)["basis"] = ""
	})
	requireProblem(t, err, "a score with no basis", "unknown score.basis")
}

func TestAChosenScoreWithNoReasonFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		s := capByID(t, doc, "governance.authzen")["score"].(map[string]any)
		s["basis"] = "CHOSEN"
		delete(s, "reason")
	})
	requireProblem(t, err, "a CHOSEN score with no reason", "score.reason is empty")
}

func TestANonMonotonicScoreFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		s := capByID(t, doc, "governance.authzen")["score"].(map[string]any)
		s["enterprise"] = "none"
	})
	requireProblem(t, err, "Enterprise is given less than Community", "not monotonic")
}

func TestAScoreContradictingTheMinimumEditionFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		s := capByID(t, doc, "circuit.breaker")["score"].(map[string]any)
		s["community"] = "full"
		s["evaluation"] = "full"
	})
	requireProblem(t, err, "an enterprise-minimum capability scored full for Community",
		"minimum_edition")
}

func TestAnUnscorableEntryCarryingAnAvailabilityFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		s := capByID(t, doc, "identity.realms")["score"].(map[string]any)
		s["community"] = "none"
	})
	requireProblem(t, err, "an UNSCORABLE entry given an availability anyway", "UNSCORABLE")
}

func TestAnUnknownAvailabilityFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "governance.authzen")["score"].(map[string]any)["community"] = "partial"
	})
	requireProblem(t, err, "an availability outside the vocabulary", "unknown score.community")
}

// TestAnUnknownAvailabilityIsNotSilentlyWeightedZero is the mutation the map
// lookup invites. `availabilityWeight[a]` returns 0 for anything it does not
// know, which is indistinguishable from an honest "not available" — so every
// typo would quietly deflate the bands the census exists to derive.
func TestAnUnknownAvailabilityIsNotSilentlyWeightedZero(t *testing.T) {
	if _, ok := Availability("partial").Weight(); ok {
		t.Fatal("Weight reported an unknown availability as a member of the vocabulary")
	}
	for a, want := range map[Availability]float64{AvailFull: 1, AvailLimited: 0.5, AvailNone: 0} {
		got, ok := a.Weight()
		if !ok || got != want {
			t.Errorf("Weight(%s) = %v,%v want %v,true", a, got, ok, want)
		}
	}
}

// --- structure --------------------------------------------------------------

func TestAnIDNotMatchingItsFamilyFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "governance.authzen")["family"] = "policy"
	})
	requireProblem(t, err, "an id filed under a family it does not name",
		"does not start with its family")
}

func TestTwoEntriesClaimingTheSameRoutePrefixFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		c := capByID(t, doc, "governance.decide")
		c["routes"] = []any{"/api/v1/decide", "/api/v1/access/evaluation"}
	})
	requireProblem(t, err, "two capabilities claim one route prefix", "is claimed by both")
}

func TestARouteExemptionWithNoReasonFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		doc["route_exemptions"] = []any{map[string]any{"pattern": "x", "reason": "  "}}
	})
	requireProblem(t, err, "an exemption with a blank reason", "has no reason")
}

func TestAnUnknownFieldFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		capByID(t, doc, "governance.authzen")["minimum_editon"] = "enterprise"
	})
	requireProblem(t, err, "a misspelled field name", "unknown field")
}

func TestAMismatchedSchemaVersionFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) { doc["schema"] = "2.0" })
	requireProblem(t, err, "a document written for another schema", "this reader implements")
}

func TestAnEmptyRegistryFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		doc["capabilities"] = []any{}
	})
	requireProblem(t, err, "a registry with no capabilities", "pass vacuously")
}

func TestEmptyScanRootsFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) { doc["scan_roots"] = []any{} })
	requireProblem(t, err, "a registry that tells the derivation to walk nothing",
		"scan_roots is empty")
}

// TestTheMutantHarnessCanProduceAValidDocument is the survivor control.
//
// Every test above concludes something from Parse REJECTING a document. If the
// harness produced a document Parse would reject no matter what — a
// re-marshalling bug, say — every one of them would pass while proving nothing.
func TestTheMutantHarnessCanProduceAValidDocument(t *testing.T) {
	if err := mutate(t, func(map[string]any) {}); err != nil {
		t.Fatalf("the unmutated document does not survive a round trip through the "+
			"harness, so every mutant above is rejected for the wrong reason: %v", err)
	}
}

// TestRoutePrefixesDoNotSwallowSiblings pins the boundary rule directly, in
// both directions. `/api/v1/policies` must not own `/api/v1/policy-overrides`,
// and it must own `/api/v1/policies/export`.
func TestRoutePrefixesDoNotSwallowSiblings(t *testing.T) {
	for _, tc := range []struct {
		prefix, route string
		want          bool
	}{
		{"/api/v1/policies", "/api/v1/policies", true},
		{"/api/v1/policies", "/api/v1/policies/export", true},
		{"/api/v1/policies", "/api/v1/policy-overrides", false},
		{"/api/v1/policies", "/api/v1/policiesX", false},
		{"/api/v1/plan", "/api/v1/plans", false},
		{"/api/v1/plan", "/api/v1/plan/{id}", true},
		{"/api/v1/agents/", "/api/v1/agents/{id}", true},
	} {
		if got := routeCoveredBy(tc.prefix, tc.route); got != tc.want {
			t.Errorf("routeCoveredBy(%q, %q) = %v, want %v", tc.prefix, tc.route, got, tc.want)
		}
	}
}

// TestLongestPrefixWinsAttribution proves the nesting rule on the real
// registry, where /api/v1/plans and /api/v1/plans/approvals are both claimed.
func TestLongestPrefixWinsAttribution(t *testing.T) {
	r := Load()
	for route, wantID := range map[string]string{
		"/api/v1/plans":                      "map.planning",
		"/api/v1/plans/approvals/pending":    "hitl.map_approvals",
		"/api/v1/plans/estimate":             "map.plan_cost",
		"/api/v1/workflows/{id}/resume":      "wcp.workflows",
		"/api/v1/workflows/{id}/checkpoints": "wcp.checkpoints",
	} {
		got := r.CapabilityForRoute(route)
		if got == nil {
			t.Errorf("%s is attributed to nothing", route)
			continue
		}
		if got.ID != wantID {
			t.Errorf("%s is attributed to %s, want %s", route, got.ID, wantID)
		}
	}
	if r.CapabilityForRoute("/api/v1/not-a-real-route") != nil {
		t.Error("a route no entry claims was attributed to something")
	}
}

// TestValidateNeedsNoFilesystem proves Validate is safe to run inside a shipped
// binary, which is what lets the /health projection depend on it. A validator
// that read the repository would panic or hang in a container.
func TestValidateNeedsNoFilesystem(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if _, err := Parse(registryJSON); err != nil {
		t.Fatalf("Parse failed with no repository under the working directory: %v", err)
	}
}

func TestAnOutOfScopeMatrixSectionWithNoReasonFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		list := doc["matrix_sections_out_of_scope"].([]any)
		list[0].(map[string]any)["reason"] = "   "
	})
	requireProblem(t, err, "a matrix section excluded with a blank reason",
		"declared out of scope with no reason")
}

func TestADuplicateMatrixHeadingOnOneEntryFails(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		c := capByID(t, doc, "governance.authzen")
		c["matrix"] = []any{"Core Platform", "Core Platform"}
	})
	requireProblem(t, err, "one entry listing a matrix heading twice", "listed twice")
}

// TestValidationProblemsAreSorted pins the ordering in ONE run.
//
// The first version compared several runs and hoped the randomisation showed
// itself: with the sort deleted it reddened on run 6 of 10, which is a test
// that depends on luck to see its own subject. Asserting the property directly
// — the problems come out sorted — needs one run and cannot be lucky.
func TestValidationProblemsAreSorted(t *testing.T) {
	err := mutate(t, func(doc map[string]any) {
		// Several problems from checks with different iteration orders, at
		// least two from ONE map-iterating check (the availability loop), so
		// their relative order is randomised without the sort.
		c := capByID(t, doc, "governance.authzen")
		s := c["score"].(map[string]any)
		s["community"] = "partial"
		s["evaluation"] = "somewhat"
		c["title"] = ""
		c["summary"] = ""
	})
	if err == nil {
		t.Fatal("the multi-problem mutant was accepted")
	}
	problems, ok := err.(Problems)
	if !ok {
		t.Fatalf("Validate returned %T, not Problems, so its order cannot be checked", err)
	}
	if len(problems) < 4 {
		t.Fatalf("the mutant produced %d problems; too few to have an order worth pinning",
			len(problems))
	}
	if !sort.StringsAreSorted(problems) {
		t.Errorf("Validate returned its problems unsorted, so two runs over one broken file "+
			"print them differently and a CI failure cannot be diffed against the last "+
			"one:\n  %s", strings.Join(problems, "\n  "))
	}
	// Both halves of the availability loop must be present, or the sort is
	// being checked on problems that only ever come out in source order.
	var fromTheMapLoop int
	for _, p := range problems {
		if strings.Contains(p, "unknown score.") {
			fromTheMapLoop++
		}
	}
	if fromTheMapLoop < 2 {
		t.Fatalf("only %d problem(s) came from the map-iterating check; the sort is not "+
			"being tested against a randomised order", fromTheMapLoop)
	}
}

// TestARouteExemptionWithAHandWavingReasonFails is the second condition on
// accepting reported-not-resolved as the right answer for a helper-registered
// route: the exemption that answer forces must carry an argument, not a phrase.
//
// An empty reason is the easy case and is covered above. The shape this fails
// in is a reason that is PRESENT and says nothing, because that satisfies a
// presence check and survives review as a thing somebody wrote.
func TestARouteExemptionWithAHandWavingReasonFails(t *testing.T) {
	for _, bad := range []string{
		"n/a", "N/A", "TBD", "todo", "by design", "legacy", "known issue",
		"pre-existing", "see above", "obvious", "?", "for now",
		"table-driven",       // true, and not an argument
		"cannot be resolved", // restates the problem
		// R3's bypass: 66 characters of nothing, bought past a length floor by
		// PADDING WITH MORE NON-REASONS. The floor now applies to what is left
		// after the stock phrases are stripped, so concatenating them cannot
		// raise it.
		"by design, legacy, pre-existing, table-driven, nothing to add here",
		"n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a n/a",
		"tbd. todo. wip. for now. see above. see below. not applicable. obvious.",
	} {
		t.Run(bad, func(t *testing.T) {
			err := mutate(t, func(doc map[string]any) {
				doc["route_exemptions"] = []any{
					map[string]any{"pattern": "x.go:1 HandleFunc(p)", "reason": bad},
				}
			})
			requireProblem(t, err, "an exemption reasoned as "+bad, "route_exemption")
		})
	}
}

// TestTheRealExemptionsCarryAnArgument is the positive control on the rule
// above. If the shipped exemptions did not meet it, the rule would be
// unenforceable and the next person would weaken the rule rather than the
// exemption.
func TestTheRealExemptionsCarryAnArgument(t *testing.T) {
	if len(Load().RouteExemptions) == 0 {
		t.Skip("no route exemptions to check")
	}
	for _, x := range Load().RouteExemptions {
		if p := validateExemptionReason(x); len(p) > 0 {
			t.Errorf("a shipped exemption does not meet the rule: %v", p)
		}
		// And it must say something about COVERAGE, not only about the
		// scanner's limitation. "The scanner cannot read it" is the problem
		// restated, not the argument for allowing it.
		lower := strings.ToLower(x.Reason)
		if !strings.Contains(lower, "cover") && !strings.Contains(lower, "claims") {
			t.Errorf("exemption %q says what the scanner could not read but not why the URL "+
				"space is covered anyway: %q", x.Pattern, x.Reason)
		}
	}
}

// TestAnExemptionCannotCiteACapabilityThatDoesNotCoverIt pins the FIDELITY
// half of the exemption rule.
//
// The other half — the reason floor, and the requirement that the prose mention
// coverage at all — proves the sentence is an argument. It cannot prove the
// argument is TRUE. Writing seven exemptions by hand produced five capability
// ids that do not exist in this registry (platform.health_check,
// observability.metrics, gateway.request, tenancy.clients, policy.test); the
// only thing that stopped them shipping was looking each one up by hand.
//
// Probing for a guard afterwards found none. A fabricated id reddened exactly
// one test — the census golden file — and `UPDATE_CENSUS=1` made it pass. A
// regeneration gate proves the document matches the registry and never that
// the registry is true, which is the whole reason this test exists.
//
// The five real inventions are the table's first rows, so the fixture is the
// near-miss rather than a paraphrase of it.
func TestAnExemptionCannotCiteACapabilityThatDoesNotCoverIt(t *testing.T) {
	base := Load()
	// The path and the capability that really claims it, read from the
	// registry rather than written here: if platform.metrics ever stops
	// claiming /metrics, this test's CONTROL fails rather than its assertion.
	const path, realID = "/metrics", "platform.metrics"
	claimer := func() *Entry {
		for i := range base.Entries {
			if base.Entries[i].ID == realID {
				return &base.Entries[i]
			}
		}
		return nil
	}()
	if claimer == nil || !slices.Contains(claimer.Routes, path) {
		t.Fatalf("control: %s no longer claims %s, so every case below is about nothing",
			realID, path)
	}

	for name, tc := range map[string]struct {
		reason      string
		wantProblem bool
	}{
		// The real thing, which must pass. Without this the whole table is
		// satisfied by a guard that rejects every exemption ever written.
		"the capability that actually claims the path": {
			reason: "The scanner could not price the receiver. The path is " + path +
				", which " + realID + " claims, so the URL space is covered.",
			wantProblem: false},

		// RULE 1: a real family, an invented member. Two of the five real
		// inventions had this shape.
		"an invented member of a real family": {
			reason: "The scanner could not price the receiver. The path is " + path +
				", which observability.metrics claims, so the URL space is covered.",
			wantProblem: true},
		"a second invented member of a real family": {
			reason: "The scanner could not price the receiver. The path is /health" +
				", which platform.health_check claims, so the URL space is covered.",
			wantProblem: true},

		// RULE 2: the family does not exist either, so rule 1 is blind to it.
		// This is the shape rule 1 alone would have let through, and three of
		// the five real inventions had it.
		"an id whose family does not exist either": {
			reason: "The scanner could not price the receiver. The path is " + path +
				", which gateway.request claims, so the URL space is covered.",
			wantProblem: true},

		// RULE 1 ALONE. A real id that DOES claim the path, plus an invented
		// member of a real family. Rule 2 is satisfied, so only rule 1 can
		// fire — without this case, turning rule 1 off changes nothing that
		// any other row can see, because rule 2 catches those rows too.
		"an invented sibling beside the capability that does claim the path": {
			reason: "The scanner could not price the receiver. The path is " + path +
				", which " + realID + " claims alongside observability.metrics, so the " +
				"URL space is covered.",
			wantProblem: true},

		// RULE 2 again, and the sharpest case: every id named is REAL, and
		// none of them claims this path. A citation is not a coverage.
		"real capabilities that do not claim this path": {
			reason: "The scanner could not price the receiver. The path is " + path +
				", which policy.system and policy.tenant claim, so the URL space is covered.",
			wantProblem: true},

		// RULE 4: a path QUOTED IN THE PROSE that nothing claims. Rule 2
		// checks the key's path, so a wrong path here cannot cause a false
		// coverage claim — but these reasons are lifted into the census
		// verbatim, so a path nothing claims reads there as covered.
		"a fabricated path quoted in the prose": {
			reason: "The scanner could not price the receiver. The path is " + path +
				", which " + realID + " claims, and it also covers " +
				"/api/v1/totally-invented, so the URL space is covered.",
			wantProblem: true},

		// The control for rule 4, in the same table: a path the named
		// capability really does claim must NOT be flagged, or the rule
		// rejects every reason that mentions a sibling route.
		"a sibling path the named capability really claims": {
			reason: "The scanner could not price the receiver. The path is " + path +
				", which " + realID + " claims alongside /prometheus and " +
				"/api/v1/metrics, so the URL space is covered.",
			wantProblem: false},

		// And the degenerate one: an argument that names nothing at all.
		"no capability named at all": {
			reason: "The scanner could not price the receiver because it is assigned inside " +
				"a function body, and the path is a literal, so the URL space is covered.",
			wantProblem: true},
	} {
		t.Run(name, func(t *testing.T) {
			x := RouteExemption{
				Pattern: `platform/agent/run.go:1552 HandleFunc(<subrouter with an unresolved prefix>"` + path + `")`,
				Reason:  tc.reason,
			}
			// Only the citation rule is under test here; the reason floor has
			// its own cases elsewhere, and every reason above clears it.
			if p := validateExemptionReason(x); len(p) > 0 {
				t.Fatalf("fixture problem: this reason fails the FLOOR, so the citation "+
					"rule is not what is being measured: %v", p)
			}
			got := base.validateExemptionCitations(x)
			if tc.wantProblem && len(got) == 0 {
				t.Errorf("expected a problem and got none. An exemption is the one place " +
					"where prose stands in for a derivation, so an uncheckable claim there " +
					"is a silently uncovered URL space")
			}
			if !tc.wantProblem && len(got) > 0 {
				t.Errorf("expected no problem, got %v. A guard that rejects the TRUE "+
					"exemption rejects every exemption, and the next person weakens the "+
					"rule rather than the row", got)
			}
		})
	}
}

// TestAPathlessExemptionStillHasToNameARealCapability is R9-1, planted as the
// row that exercises it.
//
// The first version of the citation guard had two rules and a hole between
// them. Rule 2 needs a literal path in the exemption key, and returns early
// without one; rule 1 only fires when the invented id's FAMILY exists. The one
// shipped row with no path in its key — the `rt.suffix` range-variable site —
// sat in that gap, and replacing its `policy.system` with `gateway.request`,
// one of the five ids that were actually invented on this PR's first draft,
// passed the entire suite.
//
// So the guard's own subject defeated it, on a shipped row, inside the fix for
// exactly that class. Rule 3 is unconditional: name a real capability or the
// argument is prose.
func TestAPathlessExemptionStillHasToNameARealCapability(t *testing.T) {
	base := Load()
	const pathless = `platform/agent/static_policy_api_handlers.go:166 ` +
		`HandleFunc(<subrouter with an unresolved prefix>rt.suffix)`

	for name, tc := range map[string]struct {
		reason      string
		wantProblem bool
	}{
		"a real capability, on a key with no path": {
			reason: "The suffixes live in a struct slice and the receiver is a range " +
				"variable, so neither is a proven shape. policy.system claims both " +
				"prefixes it ranges over, so the URL space is covered.",
			wantProblem: false},

		// The exact edit that passed before rule 3 existed.
		"an invented id whose family does not exist either": {
			reason: "The suffixes live in a struct slice and the receiver is a range " +
				"variable, so neither is a proven shape. gateway.request claims both " +
				"prefixes it ranges over, so the URL space is covered.",
			wantProblem: true},

		"no capability named at all, on a key with no path": {
			reason: "The suffixes live in a struct slice and the receiver is a range " +
				"variable, so neither is a proven shape, and the URL space is covered by " +
				"the entries either side of it.",
			wantProblem: true},
	} {
		t.Run(name, func(t *testing.T) {
			x := RouteExemption{Pattern: pathless, Reason: tc.reason}
			if p := validateExemptionReason(x); len(p) > 0 {
				t.Fatalf("fixture problem: this reason fails the FLOOR, so the citation "+
					"rule is not what is being measured: %v", p)
			}
			// The fixture must really be pathless, or it is quietly testing
			// rule 2 and this whole test is about nothing.
			if quotedPathInPattern.MatchString(x.Pattern) {
				t.Fatalf("fixture problem: this key carries a literal path, so rule 2 " +
					"applies and the pathless gap is not being exercised")
			}
			got := base.validateExemptionCitations(x)
			if tc.wantProblem && len(got) == 0 {
				t.Errorf("expected a problem and got none. This is the shape that let a " +
					"fabricated id ride on a shipped row through an entire review round")
			}
			if !tc.wantProblem && len(got) > 0 {
				t.Errorf("expected no problem, got %v", got)
			}
		})
	}
}

// TestValidateReachesTheCitationRule pins the CALL SITE, not the predicate.
//
// Every case above calls validateExemptionCitations directly, so all of them
// pass with the rule written and never invoked. Deleting its one line in
// Validate reddened nothing: the rule was correct, complete, and unreachable —
// which is worse than not having written it, because the code reads as if the
// case is handled. Validate is what CI runs and what the embedded registry
// panics on at package init, so Validate is what has to be asserted.
func TestValidateReachesTheCitationRule(t *testing.T) {
	r := Load()
	bad := *r
	bad.RouteExemptions = append(append([]RouteExemption{}, r.RouteExemptions...), RouteExemption{
		Pattern: `platform/agent/run.go:9999 HandleFunc(<subrouter with an unresolved prefix>"/metrics")`,
		Reason: "The scanner could not price the receiver because it is assigned inside a " +
			"function body. The path is /metrics, which observability.metrics claims, so " +
			"the URL space is covered.",
	})
	err := bad.Validate()
	found := err != nil && strings.Contains(err.Error(), "observability.metrics")
	if !found {
		t.Errorf("Validate() did not report a fabricated capability id in an exemption. "+
			"The rule exists and is tested directly above; this asserts that the thing CI "+
			"actually runs calls it. Problems reported: %v", err)
	}
	// The control, in the same test: the UNMODIFIED registry must validate
	// clean, or "Validate reports a problem" is true of everything.
	if q := r.Validate(); q != nil {
		t.Errorf("control: the shipped registry does not validate clean, so the assertion "+
			"above cannot distinguish the planted row from the rest: %v", q)
	}
}

// TestTheShippedExemptionsAllCiteACapabilityThatCoversThem is the positive
// control on the rule above, applied to what actually ships. If the eight rows
// in registry.json did not meet it, the rule would be unenforceable and would
// be weakened rather than the rows corrected.
func TestTheShippedExemptionsAllCiteACapabilityThatCoversThem(t *testing.T) {
	r := Load()
	if len(r.RouteExemptions) == 0 {
		t.Skip("no route exemptions to check")
	}
	for _, x := range r.RouteExemptions {
		if p := r.validateExemptionCitations(x); len(p) > 0 {
			t.Errorf("a shipped exemption does not meet the citation rule: %v", p)
		}
	}
}

// TestEditionFactsMatchTheTree is the half of the classification check that
// cannot be satisfied by editing the registry.
//
// Every rule that reads only the document can be made true by rewriting the
// document. Master's laundering mutant proved it: turn `circuit.breaker` into
// `community_core` / `build_tag: none` / `sync: mirrored`, score it available
// to Community, and the file is internally consistent — every contradiction
// rule was keyed on the classification being enterprise_implementation, so an
// entry that stopped claiming to be one satisfied all of them by being none of
// them.
//
// The tree is what makes that row a lie. `circuit.breaker` names
// platform/agent/circuitbreaker/handler.go, which carries `//go:build
// enterprise`, and no edit to the registry changes what that file says.
func TestEditionFactsMatchTheTree(t *testing.T) {
	root := repoRoot(t)
	if TreeIsCommunityMirror(root) {
		t.Skip("community mirror: the enterprise halves are stripped here, so the tree " +
			"would report every capability as build_tag none — which is true OF THE MIRROR " +
			"and says nothing about what the entry should declare")
	}
	var checked, enterprise, split int
	for _, e := range Load().Entries {
		tag, sync, found, err := DeriveEditionFacts(root, e.Implementation)
		if err != nil {
			t.Errorf("%s: %v", e.ID, err)
			continue
		}
		if !found {
			t.Errorf("%s: none of its implementation paths holds a Go file, so its "+
				"build_tag and sync are unfalsifiable", e.ID)
			continue
		}
		checked++
		switch tag {
		case TagEnterprise:
			enterprise++
		case TagSplit:
			split++
		}
		if e.BuildTag != tag {
			t.Errorf("%s declares build_tag %q; its implementation files say %q. The tree "+
				"is the authority here — a row cannot edit what a build constraint says",
				e.ID, e.BuildTag, tag)
		}
		if e.Sync != sync {
			t.Errorf("%s declares sync %q; its implementation files say %q",
				e.ID, e.Sync, sync)
		}
	}
	// THE HALF THE ROW CANNOT CHOOSE.
	//
	// Everything above derives from the entry's own `implementation` list, so a
	// row can still launder itself by TRIMMING that list: master laundered
	// circuit.breaker and cut its implementation down to the !enterprise twin,
	// and this test passed. The derivation already knows the edition of every
	// file that REGISTERS A ROUTE, and an entry does not get to choose which
	// files register its routes.
	//
	// The rule is one-directional on purpose. A capability whose routes are
	// registered anywhere in enterprise-only source cannot be `build_tag:
	// none`, `sync: mirrored`, or available to Community — whatever its
	// implementation list says. The converse is NOT a rule: an entry may
	// legitimately name enterprise implementation beyond its route
	// registrations.
	d, err := Derive(root, Load().ScanRoots)
	if err != nil {
		t.Fatalf("deriving: %v", err)
	}
	registeredIn := map[string]map[string]bool{} // capability id -> editions
	for _, site := range d.Routes {
		if !site.Resolved {
			continue
		}
		owner := Load().CapabilityForRoute(site.Pattern)
		if owner == nil {
			continue
		}
		if registeredIn[owner.ID] == nil {
			registeredIn[owner.ID] = map[string]bool{}
		}
		registeredIn[owner.ID][site.Edition] = true
	}
	if len(registeredIn) < 20 {
		t.Fatalf("only %d capabilities have an attributed registration site; the "+
			"cross-check below would be about almost nothing", len(registeredIn))
	}
	var routeChecked, routeEnterprise int
	for _, e := range Load().Entries {
		editions := registeredIn[e.ID]
		if !editions["enterprise"] {
			continue
		}
		routeChecked++
		routeEnterprise++
		// A capability whose routes are registered in BOTH editions is split,
		// and Community legitimately reaches the community half — map.agents
		// serves its read routes everywhere and its write routes only under
		// the enterprise tag. So minimum_edition is checked only when the WHOLE
		// route surface is enterprise-only; the build tag and the sync
		// disposition are checked either way, because enterprise-only source
		// registering a route is enterprise-only source.
		wholeSurfaceEnterprise := !editions["community"]
		if wholeSurfaceEnterprise && e.MinimumEdition == EditionCommunity {
			t.Errorf("%s declares minimum_edition %q, but EVERY file registering its routes "+
				"is enterprise-only, so a Community build serves none of them",
				e.ID, e.MinimumEdition)
		}
		if e.BuildTag == TagNone {
			t.Errorf("%s declares build_tag %q, but a file that REGISTERS one of its routes "+
				"is enterprise-only. A row does not get to choose which files register its "+
				"routes", e.ID, e.BuildTag)
		}
		if e.Sync == SyncMirrored {
			t.Errorf("%s declares sync %q, but one of its routes is registered in "+
				"enterprise-only source", e.ID, e.Sync)
		}
	}
	if routeEnterprise == 0 {
		t.Fatal("no capability has a route registered in enterprise-only source, so the " +
			"route-side cross-check asserted nothing")
	}
	t.Logf("route-side cross-check: %d capabilities register a route in enterprise-only "+
		"source", routeChecked)

	// Anti-vacuity, and it is the assertion that makes the loop mean anything:
	// if the derivation found no enterprise-tagged and no split capability, it
	// is reading a tree with no enterprise source in it and every comparison
	// above passed on `none == none`.
	if checked < 50 {
		t.Fatalf("only %d entries were checkable", checked)
	}
	if enterprise == 0 || split == 0 {
		t.Fatalf("the tree derivation found %d enterprise-only and %d split capabilities; "+
			"with either at zero this test is comparing `none` against `none` for every row",
			enterprise, split)
	}
	t.Logf("checked %d entries against the tree: %d enterprise-only, %d split",
		checked, enterprise, split)
}

// TestTheReverseClassificationRulesEachFire pins M-3: the three rules that
// close the laundering direction inside the document.
//
// They had no test. Every contradiction test used `circuit.breaker` and mutated
// it INTO the community column, which the forward rules catch; nothing exercised
// the rules that fire when an entry declares `build_tag: enterprise` and then
// contradicts it. `if false &&` on any of the three would have survived.
//
// Each case uses a DIFFERENT entry, which round 1 asked for and round 2 asked
// for again: four tests sharing one fixture red together when that fixture
// changes, which reads as four independent checks and is one.
func TestTheReverseClassificationRulesEachFire(t *testing.T) {
	for name, tc := range map[string]struct {
		id     string
		mutate func(map[string]any)
		want   string
	}{
		"enterprise build tag reaching the mirror": {
			id:     "decision.proof_custody",
			mutate: func(c map[string]any) { c["sync"] = "mirrored" },
			want:   "not a state that can exist",
		},
		"enterprise build tag classified community_core": {
			id: "license.keygen",
			mutate: func(c map[string]any) {
				c["source_classification"] = "community_core"
				c["sync"] = "mirrored"
			},
			want: "may sync publicly",
		},
		"enterprise build tag available to Community": {
			id: "observability.client_version",
			mutate: func(c map[string]any) {
				c["minimum_edition"] = "community"
				c["score"].(map[string]any)["community"] = "full"
				c["score"].(map[string]any)["evaluation"] = "full"
			},
			want: "absent from a Community build",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := mutate(t, func(doc map[string]any) { tc.mutate(capByID(t, doc, tc.id)) })
			requireProblem(t, err, name, tc.want)
		})
	}
}

// TestTheReverseRuleSubjectsAreReallyEnterpriseTagged is the positive control
// on the test above. Every case needs an entry whose build_tag is already
// `enterprise`; if a future edit made those entries something else, all three
// mutants would stop reaching the rules and pass for the wrong reason.
func TestTheReverseRuleSubjectsAreReallyEnterpriseTagged(t *testing.T) {
	for _, id := range []string{"decision.proof_custody", "license.keygen", "observability.client_version"} {
		e := Load().ByID(id)
		if e == nil {
			t.Fatalf("%s is gone; the reverse-rule tests are aimed at nothing", id)
		}
		if e.BuildTag != TagEnterprise {
			t.Errorf("%s has build_tag %q; the reverse rules only fire on %q, so the mutant "+
				"aimed at it never reaches them", id, e.BuildTag, TagEnterprise)
		}
	}
}
