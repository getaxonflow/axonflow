// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestScopeActionsKeysAreCanonicalScopes: a key a document names in binds_on
// is compared as a string, so each must be the scope's own rendering. `mcp`
// alone is refused by ScopeFor (two phases), and a single-phase plane named
// with its phase renders without it.
func TestScopeActionsKeysAreCanonicalScopes(t *testing.T) {
	for key, actions := range scopeActions {
		plane, phase, _ := strings.Cut(key, ":")
		scope, err := ScopeFor(Plane(plane), Phase(phase))
		if err != nil {
			t.Errorf("scopeActions key %q is not a scope: %v", key, err)
			continue
		}
		if scope.String() != key {
			t.Errorf("scopeActions key %q renders as %q; binds_on compares the rendering", key, scope)
		}
		if len(actions) == 0 || !sort.StringsAreSorted(actions) {
			t.Errorf("scopeActions[%q] = %v: a scope presents at least one action, listed sorted", key, actions)
		}
	}
}

// TestScopeActionsKeysAreTheSeamsOfBothBinaries is the direction neither
// binary's own census can see: a scope stated here that NO seam in either
// binary decides on. Each binary's TestEverySeamPresentsWhatScopeActionsStates
// covers the seams it registers; this reads every seam scope DECLARED in the
// agent's and the orchestrator's sources and requires the key set to be
// exactly theirs.
func TestScopeActionsKeysAreTheSeamsOfBothBinaries(t *testing.T) {
	planes := map[string]Plane{}
	for _, p := range AllPlanes() {
		planes[planeConstName(p)] = p
	}
	phases := map[string]Phase{"PhaseRequest": PhaseRequest, "PhaseResponse": PhaseResponse}
	decl := regexp.MustCompile(`(?m)^var \w+ = legacycompile\.MustScopeFor\(legacycompile\.(Plane\w+), (?:""|legacycompile\.(Phase\w+))\)`)
	declared := map[string]bool{}
	for _, dir := range []string{"agent", "orchestrator"} {
		root := filepath.Join("..", "..", dir)
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range decl.FindAllStringSubmatch(string(raw), -1) {
				plane, ok := planes[m[1]]
				if !ok {
					t.Fatalf("%s/%s declares a seam scope on %s, which is not a plane constant", dir, e.Name(), m[1])
				}
				scope, err := ScopeFor(plane, phases[m[2]])
				if err != nil {
					t.Fatalf("%s/%s: %v", dir, e.Name(), err)
				}
				declared[scope.String()] = true
			}
		}
	}
	if len(declared) < 9 {
		t.Fatalf("read %d seam scope declarations; the census read nothing it can trust", len(declared))
	}
	var got []string
	for s := range declared {
		got = append(got, s)
	}
	sort.Strings(got)
	want := EnforcingScopes()
	// On a community-mirror checkout (no ee/ at the repository root) the sync
	// deletes every enterprise-tagged file, and a plane PlanesGatedByEdition
	// declares Enterprise-only has its seam in one: the community binaries
	// declare no scope for it, by design. So there the key set is compared
	// with those scopes removed, and the equality still requires that neither
	// community binary declares one (a declaration there would make the
	// edition gating stale). On the enterprise tree the full set is required.
	if _, err := os.Stat(filepath.Join("..", "..", "..", "ee")); os.IsNotExist(err) {
		var community, gated []string
		for _, s := range want {
			plane, _, _ := strings.Cut(s, ":")
			if _, isGated := PlanesGatedByEdition[Plane(plane)]; isGated {
				gated = append(gated, s)
				continue
			}
			community = append(community, s)
		}
		t.Logf("a community-mirror checkout: %v are on planes declared Enterprise-only and are held to their seams on the enterprise tree", gated)
		want = community
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the agent and orchestrator declare seam scopes %v and scopeActions states %v", got, want)
	}
}

// TestBindsOnAbsentIsEveryScope pins the default every document published
// before #4371 carries: absent binds everywhere, and a list binds exactly where
// it names. An empty list is never "everywhere".
func TestBindsOnAbsentIsEveryScope(t *testing.T) {
	for _, scope := range AllScopes() {
		if !BindsOn(nil, scope) {
			t.Errorf("an absent binds_on does not bind on %s", scope)
		}
		if BindsOn(&[]string{}, scope) {
			t.Errorf("an empty binds_on binds on %s", scope)
		}
	}
	wcp := MustScopeFor(PlaneWCP, "")
	mcpReq := MustScopeFor(PlaneMCP, PhaseRequest)
	if !BindsOn(&[]string{"wcp", "map"}, wcp) || BindsOn(&[]string{"wcp", "map"}, mcpReq) {
		t.Error("binds_on [wcp, map] must bind on wcp and not on mcp:request")
	}
	if BindsOn(&[]string{"mcp"}, mcpReq) {
		t.Error("binds_on [mcp] names no scope and must not bind on mcp:request")
	}
}

// planeConstName is the Go constant name the seams write for p.
func planeConstName(p Plane) string {
	var b strings.Builder
	b.WriteString("Plane")
	for _, part := range strings.Split(string(p), "_") {
		switch part {
		case "mcp", "map", "wcp":
			b.WriteString(strings.ToUpper(part))
		case "openai":
			b.WriteString("OpenAI")
		default:
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}
