package registry

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// shadowCensusPath is the shadow-diff harness's plane model, relative to this
// package. Both live in the platform/decision module.
const shadowCensusPath = "../legacycompile/plane.go"

// reviewedPlanes is the enforcement plane vocabulary this fixture declares.
//
// It is a SECOND statement of the set the checked-in table carries, and that is
// the point: two readers of one artifact, neither able to drift silently. An
// accidental edit to the table is caught by this list, and a deliberate one has
// to change both.
//
// The vocabulary itself is the shadow-diff harness's, and the second half of
// this test compares the two the moment that package exists in the tree. Until
// it does, this list is what holds the fixture, which is why it is a reviewed
// literal rather than something derived from the table it checks.
var reviewedPlanes = []string{
	"cowork_ingest",
	"decide",
	"gateway_request",
	"map",
	"mcp",
	"openai_compatible",
	"orchestrator_response",
	"policy_simulation",
	"policy_test",
	"proxy_request",
	"proxy_tier",
	"wcp",
}

// reviewedUnimplementedPlanes are planes ADR-065 Phase 4 names that have no
// legacy policy-evaluation call site, and which therefore must NOT appear as
// registered enforcement points.
//
// A plane in the fixture with no enforcement surface behind it would be
// registered, queried and counted, reading as coverage of something that does
// not exist.
var reviewedUnimplementedPlanes = []string{"connector_execution"}

// planeConstPattern matches the plane constant declarations in the shadow-diff
// harness's plane model, for example:
//
//	PlaneDecide Plane = "decide"
var planeConstPattern = regexp.MustCompile(`Plane[A-Za-z0-9_]*\s+Plane\s*=\s*"([a-z_]+)"`)

// TestLegacyPlaneFixtureAgreesWithTheShadowCensus is AXC-327.
func TestLegacyPlaneFixtureAgreesWithTheShadowCensus(t *testing.T) {
	MarkConformanceCase("AXC-327")

	rows, err := ParseLegacyPlanes(LegacyPlaneFile)
	if err != nil {
		t.Fatalf("parsing the legacy plane table: %v", err)
	}
	inTable := map[string]bool{}
	enterpriseRows := map[string]bool{}
	for _, r := range rows {
		inTable[r.Plane] = true
		if r.Edition == EditionEnterprise {
			enterpriseRows[r.Plane] = true
		}
	}

	// Every plane has an Enterprise row. Enterprise is the superset build, so a
	// plane present only on community would be a plane the fixture claims does
	// not exist in the build that has everything.
	for plane := range inTable {
		if !enterpriseRows[plane] {
			t.Errorf("plane %q has no Enterprise row", plane)
		}
	}

	assertSameSet(t, "the reviewed vocabulary", reviewedPlanes, "the checked-in table", keysOf(inTable))

	for _, plane := range reviewedUnimplementedPlanes {
		if inTable[plane] {
			t.Errorf("plane %q has no legacy policy-evaluation call site and must not be a registered enforcement point", plane)
		}
	}

	// The cross-check against the harness's own vocabulary. It runs the moment
	// that package lands and hard-fails on any disagreement; it is not a skip
	// dressed up, because the reviewed list above is asserted unconditionally
	// and is what this fixture is held to in the meantime.
	src, readErr := os.ReadFile(filepath.Clean(shadowCensusPath))
	if readErr != nil {
		t.Logf("the shadow-diff plane model is not in this tree (%s): the reviewed vocabulary above is what holds this fixture, "+
			"and the direct comparison starts running when that package lands", shadowCensusPath)
		return
	}
	text := string(src)
	var declared []string
	for _, m := range planeConstPattern.FindAllStringSubmatch(text, -1) {
		declared = append(declared, m[1])
	}
	if len(declared) == 0 {
		t.Fatalf("%s exists but no plane constant was found in it; the pattern is broken and the comparison below would pass vacuously",
			shadowCensusPath)
	}
	assertSameSet(t, "the shadow-diff plane model", declared, "the checked-in table", keysOf(inTable))
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// assertSameSet compares two sets in BOTH directions.
//
// One direction is the usual mistake: checking only that every entry in the
// table is declared would accept a table missing half the planes, and checking
// only the reverse would accept a table full of invented ones.
func assertSameSet(t *testing.T, leftName string, left []string, rightName string, right []string) {
	t.Helper()
	l, r := map[string]bool{}, map[string]bool{}
	for _, v := range left {
		l[v] = true
	}
	for _, v := range right {
		r[v] = true
	}
	var missing, extra []string
	for v := range l {
		if !r[v] {
			missing = append(missing, v)
		}
	}
	for v := range r {
		if !l[v] {
			extra = append(extra, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%s names %s, which %s does not", leftName, strings.Join(missing, ", "), rightName)
	}
	if len(extra) > 0 {
		t.Errorf("%s names %s, which %s does not", rightName, strings.Join(extra, ", "), leftName)
	}
}

// TestTheSetComparisonIsTwoSided proves the helper above catches a difference
// in either direction, which is the property a one-sided comparison silently
// loses.
func TestTheSetComparisonIsTwoSided(t *testing.T) {
	for name, tc := range map[string]struct{ left, right []string }{
		"the right side is missing one": {left: []string{"a", "b"}, right: []string{"a"}},
		"the right side has an extra":   {left: []string{"a"}, right: []string{"a", "b"}},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &testing.T{}
			assertSameSet(fake, "left", tc.left, "right", tc.right)
			if !fake.Failed() {
				t.Fatalf("the comparison accepted %s", name)
			}
		})
	}
	fake := &testing.T{}
	assertSameSet(fake, "left", []string{"a", "b"}, "right", []string{"b", "a"})
	if fake.Failed() {
		t.Fatalf("the comparison rejected two equal sets in different orders")
	}
}
