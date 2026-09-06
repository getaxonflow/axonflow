// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package path_template

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestNormalize covers the three documented behaviors of the matcher:
// literal-vs-param specificity, trailing-{param} strip, and fail-closed
// fallback. Every example here ties back to an explicit case in the
// epic #2047 sub-task 2 spec.
func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "literal endpoint passes through unchanged",
			path: "/api/v1/static-policies",
			want: "/api/v1/static-policies",
		},
		{
			name: "trailing /{id} stripped",
			path: "/api/v1/static-policies/sp_abc123",
			want: "/api/v1/static-policies",
		},
		{
			name: "trailing-literal action keeps mid-path {id}",
			path: "/api/v1/static-policies/sp_abc/override",
			want: "/api/v1/static-policies/{id}/override",
		},
		{
			name: "trailing param after mid-path param strips only the last",
			path: "/api/v1/circuit-breaker/notifications/notif_99",
			want: "/api/v1/circuit-breaker/notifications",
		},
		{
			name: "deeply nested path with action keeps all params",
			path: "/api/v1/hitl/queue/hitl_42/override",
			want: "/api/v1/hitl/queue/{id}/override",
		},
		{
			name: "proxied euaiact action keeps mid-path param",
			path: "/api/v1/euaiact/conformity/asmt_42/submit",
			want: "/api/v1/euaiact/conformity/{assessment_id}/submit",
		},
		{
			name: "proxied euaiact trailing param stripped",
			path: "/api/v1/euaiact/export/exp_7",
			want: "/api/v1/euaiact/export",
		},
		{
			name: "two trailing params strips only ONE per epic decision",
			path: "/api/v1/connectors/refresh/cs_abc/sap-connector",
			want: "/api/v1/connectors/refresh/{tenant_id}",
		},
		{
			name: "unknown path returns as-is (fail-closed)",
			path: "/api/v1/unmapped/fancy-thing",
			want: "/api/v1/unmapped/fancy-thing",
		},
		{
			name: "completely unrelated path returns as-is",
			path: "/health",
			want: "/health",
		},
		{
			name: "query string defensively stripped",
			path: "/api/v1/static-policies/sp_abc?foo=bar",
			want: "/api/v1/static-policies",
		},
		{
			name: "empty path returns empty",
			path: "",
			want: "",
		},
	}

	m := NewMatcher(Templates)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Normalize(tc.path)
			if got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestNormalize_LiteralBeatsParam locks the specificity rule: when a
// literal template ("/api/v1/static-policies/effective") and a param
// template ("/api/v1/static-policies/{id}") both could match the same
// path, the literal wins. This is the "/me" preservation case from the
// epic spec's example list.
func TestNormalize_LiteralBeatsParam(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/static-policies/effective", "/api/v1/static-policies/effective"},
		{"/api/v1/static-policies/overrides", "/api/v1/static-policies/overrides"},
		{"/api/v1/static-policies/test", "/api/v1/static-policies/test"},
		// Non-literal sibling — should hit /{id} and strip.
		{"/api/v1/static-policies/sp_xyz789", "/api/v1/static-policies"},
	}

	m := NewMatcher(Templates)
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := m.Normalize(tc.path)
			if got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestNormalize_PackageLevelDelegates verifies the convenience
// Normalize() shadows the same algorithm via the package-level Default
// matcher. Production callers use the convenience; this test makes sure
// they see the same behavior as constructing their own Matcher.
func TestNormalize_PackageLevelDelegates(t *testing.T) {
	const path = "/api/v1/static-policies/sp_abc"
	const want = "/api/v1/static-policies"
	if got := Normalize(path); got != want {
		t.Errorf("package-level Normalize(%q) = %q, want %q", path, got, want)
	}
}

// TestStripTrailingParam isolates the trailing-/{param}-strip helper
// from matching, so a regression in the stripper alone surfaces with a
// pinpoint failure.
func TestStripTrailingParam(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/api/v1/users/{id}", "/api/v1/users"},
		{"/api/v1/users/me", "/api/v1/users/me"}, // literal trailing — not stripped
		{"/api/v1/conformity/assessments/{id}/start", "/api/v1/conformity/assessments/{id}/start"},
		{"/api/v1/conformity/assessments/{id}/checks/{checkId}", "/api/v1/conformity/assessments/{id}/checks"},
		{"", ""},
		{"/", "/"},
		{"{id}", "{id}"},       // no leading slash — degenerate but defined
		{"/{id}", "/{id}"},     // would strip to "" → returned unchanged
		{"/users/", "/users/"}, // trailing slash without {param} — unchanged
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := stripTrailingParam(tc.in); got != tc.want {
				t.Errorf("stripTrailingParam(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCompileTemplate ensures every entry in Templates compiles into a
// usable matcher. A regression here would silently skip a template at
// NewMatcher and downstream Normalize would fail-closed for that path.
func TestCompileTemplate_AllTemplatesCompile(t *testing.T) {
	for _, tmpl := range Templates {
		if _, err := compileTemplate(tmpl); err != nil {
			t.Errorf("compileTemplate(%q): %v", tmpl, err)
		}
	}
}

// TestCompileTemplate_Empty asserts the explicit empty-template error
// surfaces (vs panicking), so callers that pass garbage observe a
// recoverable error rather than a runtime crash.
func TestCompileTemplate_Empty(t *testing.T) {
	if _, err := compileTemplate(""); err == nil {
		t.Error("compileTemplate(\"\") expected error, got nil")
	}
}

// TestNewMatcher_SkipsBadTemplates verifies bad entries are dropped
// silently rather than panicking the constructor — keeps the package
// resilient against a malformed spec drift while still serving the
// other templates.
func TestNewMatcher_SkipsBadTemplates(t *testing.T) {
	m := NewMatcher([]string{"", "/api/v1/static-policies"})
	if got := m.Normalize("/api/v1/static-policies"); got != "/api/v1/static-policies" {
		t.Errorf("Normalize after bad-template skip = %q, want unchanged", got)
	}
}

// TestTemplatesAreSorted asserts the registered list stays alphabetical
// — keeps diffs against agent-api.yaml predictable and avoids gratuitous
// merge churn when two contributors add new endpoints in parallel.
func TestTemplatesAreSorted(t *testing.T) {
	sorted := append([]string(nil), Templates...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(sorted, Templates) {
		t.Errorf("Templates is not sorted alphabetically. Sort it; current order:\n%s", strings.Join(Templates, "\n"))
	}
}

// TestTemplatesMatchAgentAPISpec is the lockstep-with-OpenAPI check.
// Parses docs/api/agent-api.yaml from the repo root and asserts each
// `paths:`-section key has a corresponding entry in Templates (and vice
// versa). Drift is a CI-fail.
//
// IT FAILS, IT DOES NOT SKIP, WHEN IT CANNOT FIND ITS INPUT (#3639).
//
// Both the locate and the read used to `t.Skip`, so a moved, renamed or
// unreadable file made this test report PASS having compared nothing — and
// on a green board a skipped test and a passing test are indistinguishable.
// The tell that it was never a decision: this same function already treats an
// empty PARSE as fatal ("parser regression?") one step later, so the vacuity
// question was asked and answered differently for two adjacent failure modes.
//
// The skip's stated reason does not hold either, and was checked rather than
// argued with: "when this package is vendored into a separate Lambda's go.mod
// with replace directives". No go.mod in this repository references
// path_template — `grep -rn path_template $(find . -name go.mod)` returns
// nothing — and its only importer is platform/agent, in the same module. If a
// consumer outside this repository ever does vendor the package without the
// document, the honest answer is a build tag or a skip THAT CONSUMER opts into,
// not a check that silently stops guarding for everyone.
//
// The failure names every path searched, so "it cannot find the file" is
// actionable rather than a puzzle.
func TestTemplatesMatchAgentAPISpec(t *testing.T) {
	yamlPath, searched := locateAgentAPIYAML()
	if yamlPath == "" {
		t.Fatalf("docs/api/agent-api.yaml was not found, so the lockstep check compared NOTHING. "+
			"A guard that stops guarding when its input moves is indistinguishable from one that found no drift. "+
			"Searched:\n  %s", strings.Join(searched, "\n  "))
	}
	body, err := os.ReadFile(yamlPath) //nolint:gosec // a path resolved from this package's own source location
	if err != nil {
		t.Fatalf("reading %s: %v. The file was located and could not be read, so the lockstep check compared nothing.", yamlPath, err)
	}
	yamlPaths := extractAgentAPIPaths(string(body))
	if len(yamlPaths) == 0 {
		t.Fatalf("extractAgentAPIPaths returned empty — parser regression?")
	}

	registered := make(map[string]bool, len(Templates))
	for _, t := range Templates {
		registered[t] = true
	}

	yamlSet := make(map[string]bool, len(yamlPaths))
	for _, p := range yamlPaths {
		yamlSet[p] = true
	}

	var missing []string
	for _, p := range yamlPaths {
		if !registered[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		t.Errorf("agent-api.yaml has paths NOT registered in Templates:\n  %s\nAdd them to Templates (alphabetical) or remove from the YAML.", strings.Join(missing, "\n  "))
	}

	var extra []string
	for _, p := range Templates {
		if !yamlSet[p] {
			extra = append(extra, p)
		}
	}
	if len(extra) > 0 {
		t.Errorf("Templates has paths NOT present in agent-api.yaml:\n  %s\nRemove them or add to the YAML.", strings.Join(extra, "\n  "))
	}
}

// locateAgentAPIYAML walks upward from the package source directory looking for
// docs/api/agent-api.yaml.
//
// It returns the resolved path and EVERY candidate it tried. The candidate list
// is not decoration: the failure this function's caller now raises is "the file
// is not where I looked", and an operator or CI reader cannot act on that
// without knowing where that was. Returning it also makes the search itself
// testable, which is what TestTheSpecLocatorReportsWhereItLooked drives.
func locateAgentAPIYAML() (path string, searched []string) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", []string{"runtime.Caller(0) failed, so the package source directory is unknown"}
	}
	return walkUpFor(filepath.Dir(file), filepath.Join("docs", "api", "agent-api.yaml"))
}

// walkUpFor climbs from startDir looking for relPath, returning the resolved
// path and every candidate it tried.
//
// Split out from locateAgentAPIYAML so the NOT-FOUND branch is drivable. The
// caller above always finds the document in this repository, so a test of it
// exercises only the found case - and the found case never produces the failure
// message the candidate list exists to fill in. A guard whose message is only
// built on a path no test reaches is a guard whose message rots.
func walkUpFor(startDir, relPath string) (path string, searched []string) {
	dir := startDir
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, relPath)
		searched = append(searched, candidate)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, searched
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", searched
}

// TestTheSpecLocatorReportsWhereItLooked is the anti-vacuity half of the change
// above.
//
// Turning a skip into a failure is only an improvement if the failure is
// actionable, and the message is built from this list. Asserting the list is
// non-empty, ascending toward the repo root, and that it CONTAINS the path
// actually resolved, is what stops the message degrading into "not found"
// with nothing after it.
func TestTheSpecLocatorReportsWhereItLooked(t *testing.T) {
	path, searched := locateAgentAPIYAML()
	if len(searched) == 0 {
		t.Fatal("the locator reported no candidates, so the failure message it feeds would name nowhere")
	}
	if path == "" {
		t.Fatalf("the spec was not located from this checkout; searched:\n  %s", strings.Join(searched, "\n  "))
	}
	if searched[len(searched)-1] != path {
		t.Errorf("the resolved path %q is not the last candidate tried (%q); the search stops at the first hit, "+
			"so the two must agree", path, searched[len(searched)-1])
	}

	// THE NOT-FOUND CASE, which the call above can never reach because the
	// document is always there. This is the branch whose message the candidate
	// list exists for, so it is the branch that has to be driven.
	base := t.TempDir()
	deep := filepath.Join(base, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("building the synthetic tree: %v", err)
	}
	missing, tried := walkUpFor(deep, filepath.Join("docs", "api", "nothing-here.yaml"))
	if missing != "" {
		t.Fatalf("the locator resolved a document that does not exist: %q", missing)
	}
	if len(tried) == 0 {
		t.Fatal("the not-found case reported no candidates, so its failure message would name nowhere")
	}
	for i, c := range tried {
		if !strings.HasSuffix(filepath.ToSlash(c), "docs/api/nothing-here.yaml") {
			t.Errorf("candidate %d (%q) is not the document that was asked for", i, c)
		}
		if i > 0 && len(c) >= len(tried[i-1]) {
			t.Errorf("candidate %d (%q) is not shorter than candidate %d (%q); the walk is meant to climb toward the "+
				"repo root", i, c, i-1, tried[i-1])
		}
	}
	// It climbs from where it was asked to start, and it stops. Eight levels is
	// the bound; a walk that ran away would still "work" and would name paths
	// outside the checkout in its failure message.
	if !strings.HasPrefix(tried[0], deep) {
		t.Errorf("the first candidate %q is not under the directory the walk was given (%q)", tried[0], deep)
	}
	if len(tried) > 8 {
		t.Errorf("the walk tried %d candidates; it is bounded at 8", len(tried))
	}

	// And the FOUND case, driven the same way, so the two branches are proved by
	// the same function rather than one being inferred from the other.
	if err := os.MkdirAll(filepath.Join(base, "docs", "api"), 0o755); err != nil {
		t.Fatalf("building the synthetic spec: %v", err)
	}
	target := filepath.Join(base, "docs", "api", "nothing-here.yaml")
	if err := os.WriteFile(target, []byte("paths:\n"), 0o600); err != nil {
		t.Fatalf("writing the synthetic spec: %v", err)
	}
	found, tried := walkUpFor(deep, filepath.Join("docs", "api", "nothing-here.yaml"))
	if found != target {
		t.Errorf("the locator resolved %q, want %q", found, target)
	}
	if tried[len(tried)-1] != found {
		t.Errorf("the resolved path is not the last candidate tried")
	}
}

// extractAgentAPIPaths is a deliberately tiny "good enough" YAML parser
// for the specific shape of docs/api/agent-api.yaml. We don't import a
// full YAML library because (a) the file's `paths:` section follows a
// rigid two-space-indent OpenAPI 3.0 layout, (b) keeping the package
// dependency-light is worth more than a parser this shape does not need.
//
// It used to give a third reason - avoiding "import-path churn into every
// Lambda that pulls in path_template via replace directive". No such consumer
// exists: no go.mod in this repository references path_template, and a
// dependency module's _test.go is never compiled by a consumer anyway
// (`go mod vendor` omits test files). The claim was the same one that justified
// the lockstep check's fail-open, and it is removed here for the same reason.
//
// The parser walks the YAML line-by-line, finds the top-level `paths:`
// block, and collects path keys (lines indented exactly two spaces and
// ending with ":"). Anything outside the `paths:` block is ignored.
func extractAgentAPIPaths(yaml string) []string {
	var out []string
	inPaths := false
	for _, line := range strings.Split(yaml, "\n") {
		// Top-level keys land at column zero.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if strings.HasPrefix(line, "paths:") {
				inPaths = true
				continue
			}
			// Top-level non-paths key (info:, components:, etc.) closes
			// the paths block.
			if inPaths && strings.HasSuffix(strings.TrimSpace(line), ":") {
				inPaths = false
			}
			continue
		}
		if !inPaths {
			continue
		}
		// Path keys: exactly two-space indented, end with ":". Method
		// stanzas under each path are four-space indented and start with
		// get:/post:/etc., which we skip.
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}
		path := strings.TrimSuffix(trimmed, ":")
		if !strings.HasPrefix(path, "/") {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// TestAuditVerifyEndpointsRegistered is the regression guard for the 9.2.1 fix:
// the three audit-verification endpoints shipped in 9.2.0's OpenAPI spec must
// also be registered in Templates, so the spec/template consistency check holds
// and the paths normalize for telemetry roll-up. TestTemplatesMatchAgentAPISpec
// caught the original gap (and skips where the YAML is not locatable, e.g. the
// community checkout); this asserts the specific paths so the intent is explicit
// and edition-independent.
func TestAuditVerifyEndpointsRegistered(t *testing.T) {
	want := []string{
		"/api/v1/audit/chains/{chainID}/verify",
		"/api/v1/audit/records/{recordID}/verify",
		"/api/v1/audit/signing-key",
	}
	have := make(map[string]bool, len(Templates))
	for _, tmpl := range Templates {
		have[tmpl] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("audit-verify endpoint %q not registered in Templates (9.2.1 regression)", w)
		}
	}
}
