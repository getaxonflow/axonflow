// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"reflect"
	"strings"
	"testing"
)

// The category-admission model (#3895 PR-A2). The WELDS to the real call
// sites live in platform/agent and platform/orchestrator, where those
// expressions are visible; this file pins what this package can see itself.

func TestCategoryAdmissionAlgebra(t *testing.T) {
	t.Run("Admits reads the three ways a site admits a category", func(t *testing.T) {
		a := CategoryAdmission{Categories: []string{"security-sqli"}, PIIFamily: true}
		for _, c := range []string{"security-sqli", "pii-global", "pii-a-category-seeded-tomorrow"} {
			if !a.Admits(c) {
				t.Errorf("%v does not admit %q", a, c)
			}
		}
		for _, c := range []string{"security-admin", "pii_detection", "sensitive-data", ""} {
			if a.Admits(c) {
				t.Errorf("%v admits %q, which it names neither directly nor by the pii-* family", a, c)
			}
		}
		if !(CategoryAdmission{Unfiltered: true}).Admits("anything-at-all") {
			t.Error("an unfiltered admission refused a category")
		}
		if (CategoryAdmission{}).Admits("security-sqli") {
			t.Error("the zero admission admitted a category; it must admit nothing, so a missing declaration cannot pass as one")
		}
	})

	t.Run("Canonical makes equal admissions compare equal", func(t *testing.T) {
		got := CategoryAdmission{Categories: []string{"b", "pii-us", "a", "b"}, PIIFamily: true}.Canonical()
		want := CategoryAdmission{Categories: []string{"a", "b"}, PIIFamily: true}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("canonical %+v, want %+v (sorted, de-duplicated, a name the family covers dropped)", got, want)
		}
		if got := (CategoryAdmission{Unfiltered: true, Categories: []string{"x"}, PIIFamily: true}).Canonical(); !reflect.DeepEqual(got, CategoryAdmission{Unfiltered: true}) {
			t.Errorf("an unfiltered admission canonicalised to %+v; unfiltered absorbs everything else", got)
		}
	})

	t.Run("Union admits what either site admits and nothing else", func(t *testing.T) {
		u := CategoryAdmission{Categories: []string{"a"}}.Union(CategoryAdmission{PIIFamily: true})
		for _, c := range []string{"a", "pii-eu"} {
			if !u.Admits(c) {
				t.Errorf("the union %v does not admit %q", u, c)
			}
		}
		if u.Admits("c") {
			t.Errorf("the union %v admits a category neither side names", u)
		}
	})
}

// TestEveryStaticPlaneDeclaresItsCategoryAdmission: a plane that evaluates the
// static substrate must say which categories its call sites evaluate, and a
// dynamic-only plane must say nothing - an admission there would be a claim
// about a filter that does not exist.
func TestEveryStaticPlaneDeclaresItsCategoryAdmission(t *testing.T) {
	for _, p := range AllPlanes() {
		spec := MustSpecFor(p)
		static := false
		for _, s := range spec.Substrates {
			if s == SubstrateStatic {
				static = true
			}
		}
		switch {
		case static && !spec.Admission.Declared():
			t.Errorf("%s evaluates the static substrate and declares no category admission", p)
		case !static && spec.Admission.Declared():
			t.Errorf("%s evaluates no static substrate yet declares admission %v", p, spec.Admission)
		}
	}
}

// TestTheCallSiteReaderReadsTheCensusTheWeldsKeyOn pins CallSites against the
// same file the plane model's census tests read, and states the property the
// two platform-side welds rely on: every static plane's static call sites sit
// in ONE binary, so exactly one weld can see all of them. A plane whose sites
// straddled both would be welded by neither.
func TestTheCallSiteReaderReadsTheCensusTheWeldsKeyOn(t *testing.T) {
	sites, err := CallSites()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) < 10 {
		t.Fatalf("CallSites returned %d rows; the census has far more, so the reader is not reading it", len(sites))
	}
	byPlane := map[Plane]map[string]bool{}
	for _, s := range sites {
		if !s.StaticEvaluator() {
			continue
		}
		var binary string
		switch {
		case strings.HasPrefix(s.File, "platform/agent/"):
			binary = "platform/agent"
		case strings.HasPrefix(s.File, "platform/orchestrator/"):
			binary = "platform/orchestrator"
		default:
			t.Errorf("static call site %s %s lives in %s, and no category-admission weld reads call sites there", s.Plane, s.Function, s.File)
			continue
		}
		if byPlane[s.Plane] == nil {
			byPlane[s.Plane] = map[string]bool{}
		}
		byPlane[s.Plane][binary] = true
	}
	for plane, binaries := range byPlane {
		if len(binaries) != 1 {
			t.Errorf("plane %s has static call sites in %d binaries (%v); neither weld sees the whole plane", plane, len(binaries), binaries)
		}
		if !MustSpecFor(plane).Admission.Declared() {
			t.Errorf("plane %s has static call sites and declares no admission", plane)
		}
	}
	// ANTI-VACUITY: decide must be among them, or this checked a census that
	// does not describe the tree.
	if _, ok := byPlane[PlaneDecide]; !ok {
		t.Fatal("no static call site for decide was read; the census and this reader disagree about the tree")
	}
}

// TestCategoryAdmissionStringIsCanonical: the rendering lands in a restriction
// reason and in the welds' failure messages, so two admissions that admit the
// same categories must render identically.
func TestCategoryAdmissionStringIsCanonical(t *testing.T) {
	for _, c := range []struct {
		a    CategoryAdmission
		want string
	}{
		{CategoryAdmission{Unfiltered: true, Categories: []string{"security-sqli"}}, "unfiltered"},
		{CategoryAdmission{}, "none"},
		{CategoryAdmission{Categories: []string{"b", "a", "b"}}, "a,b"},
		{CategoryAdmission{Categories: []string{"a", "b"}}, "a,b"},
		{CategoryAdmission{Categories: []string{"sensitive-data", "pii-us"}, PIIFamily: true}, "pii-*,sensitive-data"},
		{CategoryAdmission{PIIFamily: true}, "pii-*"},
	} {
		if got := c.a.String(); got != c.want {
			t.Errorf("%+v renders %q, want %q", c.a, got, c.want)
		}
	}
}

// TestTheCallSiteCensusReaderRefusesWhatItCannotParse holds the reader's
// refusals to firing, through parseCallSites: against the embedded census,
// which is well formed, none of them can.
func TestTheCallSiteCensusReaderRefusesWhatItCannotParse(t *testing.T) {
	header := strings.Join(callSiteColumns, "\t")
	row := func(fields ...string) string { return strings.Join(fields, "\t") }
	good := row(string(PlaneDecide), EvaluatorRequest, "platform/agent/mcp_handler.go", "evaluateInputPolicies", "yes", "community", "reachable", "-")

	for _, c := range []struct{ name, src, want string }{
		{"an empty census", "", "holds no call site"},
		{"a header with no rows", header + "\n", "holds no call site"},
		{"a reordered header", strings.Replace(header, "plane\tevaluator", "evaluator\tplane", 1) + "\n" + good, "header is"},
		{"a row missing fields", header + "\n" + row(string(PlaneDecide), EvaluatorRequest, "platform/agent/mcp_handler.go"), "has 3 fields, want 8"},
		{"an undeclared plane", header + "\n" + row("nowhere", EvaluatorRequest, "f.go", "fn", "yes", "community", "reachable", "-"), `names plane "nowhere"`},
		{"an undeclared evaluator", header + "\n" + row(string(PlaneDecide), "EvaluateSomehow", "f.go", "fn", "yes", "community", "reachable", "-"), `names evaluator "EvaluateSomehow"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			sites, err := parseCallSites(c.src)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("parseCallSites returned %d sites and error %v; want a refusal naming %q", len(sites), err, c.want)
			}
		})
	}

	t.Run("CONTROL: a well-formed census with a blank line parses", func(t *testing.T) {
		sites, err := parseCallSites(header + "\n" + good + "\n\n" + good + "\n")
		if err != nil || len(sites) != 2 || sites[0].Plane != PlaneDecide || sites[0].Function != "evaluateInputPolicies" {
			t.Fatalf("got %+v, %v; want the two rows, the blank line skipped", sites, err)
		}
	})
}
