// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The (plane, phase) scope and the per-site admission it is derived from
// (#3564). The welds to the real Categories expressions live in platform/agent
// and platform/orchestrator; this file pins what the model says about itself.

// TestEveryStaticCallSiteDeclaresItsAdmissionAndNothingElseDoes holds
// siteAdmissions to the census in both directions: a static site nobody
// declared would leave its plane undeclared, and a declaration naming no site
// is a statement about code that does not reach the evaluator.
func TestEveryStaticCallSiteDeclaresItsAdmissionAndNothingElseDoes(t *testing.T) {
	sites, err := CallSites()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, s := range sites {
		if !s.StaticEvaluator() {
			if _, ok := SiteAdmission(s); ok {
				t.Errorf("%s evaluates the dynamic substrate and declares a category admission; no category filter narrows it", s.Key())
			}
			continue
		}
		if _, ok := SiteAdmission(s); !ok {
			t.Errorf("static call site %s declares no category admission in siteAdmissions", s.Key())
		}
		seen[s.Key()] = true
	}
	for key := range siteAdmissions {
		if !seen[key] {
			t.Errorf("siteAdmissions declares %s, which legacy_call_sites.tsv does not name as a static call site", key)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no static call site was read; the comparison above compared nothing")
	}
}

// TestAStaticPlanesPhasesAreItsCallSitesPhases: a scope is valid for a phase
// exactly when some site on the plane loads that phase, so the model's Phases
// and the census's evaluators must agree.
func TestAStaticPlanesPhasesAreItsCallSitesPhases(t *testing.T) {
	sites, err := CallSites()
	if err != nil {
		t.Fatal(err)
	}
	fromSites := map[Plane]map[Phase]bool{}
	for _, s := range sites {
		if !s.StaticEvaluator() {
			continue
		}
		if fromSites[s.Plane] == nil {
			fromSites[s.Plane] = map[Phase]bool{}
		}
		fromSites[s.Plane][s.Phase()] = true
	}
	for plane, phases := range fromSites {
		var got []string
		for ph := range phases {
			got = append(got, string(ph))
		}
		var want []string
		for _, ph := range MustSpecFor(plane).Phases {
			want = append(want, string(ph))
		}
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("plane %s: its static call sites load phases %v, and PlaneSpec.Phases declares %v", plane, got, want)
		}
	}
	if _, ok := fromSites[PlaneMCP]; !ok {
		t.Fatal("no static site for mcp was read, so the two-phase case was not compared")
	}
}

// TestAPlanesAdmissionIsTheUnionOfItsPhases: the derived plane admission and
// the per-phase admission are one statement read two ways.
func TestAPlanesAdmissionIsTheUnionOfItsPhases(t *testing.T) {
	for _, p := range AllPlanes() {
		spec := MustSpecFor(p)
		if !spec.Admission.Declared() {
			continue
		}
		var union CategoryAdmission
		for _, ph := range spec.Phases {
			a, err := AdmissionFor(p, ph)
			if err != nil {
				t.Fatalf("%s %s: %v", p, ph, err)
			}
			union = union.Union(a)
		}
		if !reflect.DeepEqual(union.Canonical(), spec.Admission.Canonical()) {
			t.Errorf("plane %s: the union of its per-phase admissions is {%v}, and PlaneSpec.Admission is {%v}", p, union, spec.Admission)
		}
	}
}

// TestTheMCPResponsePassAdmitsLessThanItsRequestPass is the fact that makes a
// phase a unit of enforcement: the two passes evaluate different categories, so
// a plane-wide admission is wrong for both.
func TestTheMCPResponsePassAdmitsLessThanItsRequestPass(t *testing.T) {
	req, err := AdmissionFor(PlaneMCP, PhaseRequest)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := AdmissionFor(PlaneMCP, PhaseResponse)
	if err != nil {
		t.Fatal(err)
	}
	if !req.Admits("security-sqli") {
		t.Fatalf("the MCP request pass %v does not admit security-sqli, which evaluateInputPolicies passes; this test's premise is gone", req)
	}
	if resp.Admits("security-sqli") {
		t.Fatalf("the MCP response pass %v admits security-sqli, which evaluateOutputPolicies does not pass", resp)
	}
	for _, c := range []string{"pii-us", "sensitive-data", "security-dangerous"} {
		if !resp.Admits(c) {
			t.Errorf("the MCP response pass %v does not admit %s", resp, c)
		}
		if !req.Admits(c) {
			t.Errorf("the MCP request pass %v does not admit %s", req, c)
		}
	}
}

func TestAdmissionForRefusesWhatItCannotDerive(t *testing.T) {
	for _, c := range []struct {
		plane Plane
		phase Phase
		want  string
	}{
		{PlaneDecide, PhaseResponse, "no static call site"},
		{PlaneWCP, PhaseRequest, "no static call site"},
		{PlaneWCP, "", "no static call site"},
	} {
		if _, err := AdmissionFor(c.plane, c.phase); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("AdmissionFor(%s, %q) returned %v; want a refusal naming %q", c.plane, c.phase, err, c.want)
		}
	}
}

// TestAnUndeclaredSiteLeavesItsPlaneUndeclaredNotNarrowed: a plane whose sites
// are only partly declared must not read as the declared part, because that is
// a narrower restriction nobody stated.
func TestAnUndeclaredSiteLeavesItsPlaneUndeclaredNotNarrowed(t *testing.T) {
	declared := CallSite{Plane: PlaneMCP, Evaluator: EvaluatorRequest, Function: "evaluateInputPolicies"}
	undeclared := CallSite{Plane: PlaneMCP, Evaluator: EvaluatorResponse, Function: "aSiteNobodyDeclared"}
	if got := planeAdmissionFromSites(PlaneMCP, []CallSite{declared}); !got.Declared() {
		t.Fatalf("CONTROL: a fully declared site set derived %v; the refusal below would prove nothing", got)
	}
	if got := planeAdmissionFromSites(PlaneMCP, []CallSite{declared, undeclared}); got.Declared() {
		t.Fatalf("a plane with an undeclared site derived admission %v; it must be undeclared, so activation refuses it by name", got)
	}
}

func TestScopeForAcceptsExactlyTheDeclaredScopes(t *testing.T) {
	for _, c := range []struct {
		plane Plane
		phase Phase
		want  string // canonical rendering, "" means refused
	}{
		{PlaneDecide, "", "decide"},
		{PlaneDecide, PhaseRequest, "decide"},
		{PlaneDecide, PhaseResponse, ""},
		{PlaneMCP, "", ""},
		{PlaneMCP, PhaseRequest, "mcp:request"},
		{PlaneMCP, PhaseResponse, "mcp:response"},
		{PlaneMCP, PhaseBoth, ""},
		{PlaneWCP, "", "wcp"},
		{PlaneWCP, PhaseRequest, ""},
		{"no-such-plane", "", ""},
	} {
		s, err := ScopeFor(c.plane, c.phase)
		switch {
		case c.want == "" && err == nil:
			t.Errorf("ScopeFor(%s, %q) accepted %v; want a refusal", c.plane, c.phase, s)
		case c.want != "" && err != nil:
			t.Errorf("ScopeFor(%s, %q) refused: %v", c.plane, c.phase, err)
		case c.want != "" && s.String() != c.want:
			t.Errorf("ScopeFor(%s, %q) renders %q; want %q", c.plane, c.phase, s.String(), c.want)
		}
	}
}

func TestAllScopesSplitsExactlyTheTwoPhasePlanes(t *testing.T) {
	var names []string
	for _, s := range AllScopes() {
		names = append(names, s.String())
		if _, err := ScopeFor(s.Plane, s.Phase); err != nil {
			t.Errorf("AllScopes returned %v, which ScopeFor refuses: %v", s, err)
		}
	}
	joined := "," + strings.Join(names, ",") + ","
	for _, want := range []string{",decide,", ",mcp:request,", ",mcp:response,", ",wcp,"} {
		if !strings.Contains(joined, want) {
			t.Errorf("AllScopes %v does not contain %s", names, strings.Trim(want, ","))
		}
	}
	if strings.Contains(joined, ",mcp,") {
		t.Errorf("AllScopes %v names mcp whole; a two-phase plane has no plane-wide scope", names)
	}
	// Every plane is covered exactly once per phase it is enforced in: named
	// alone when it has fewer than two phases, and once per phase otherwise.
	count := map[Plane]int{}
	for _, s := range AllScopes() {
		count[s.Plane]++
	}
	for _, p := range AllPlanes() {
		want := 1
		if n := len(MustSpecFor(p).Phases); n >= 2 {
			want = n
		}
		if count[p] != want {
			t.Errorf("plane %s appears in %d scopes; it evaluates phases %v, so want %d", p, count[p], MustSpecFor(p).Phases, want)
		}
	}
}
