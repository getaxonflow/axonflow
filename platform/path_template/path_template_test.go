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
// Skipped if the YAML can't be located (e.g. when this package is
// vendored into a separate Lambda's go.mod with replace directives —
// the YAML doesn't ship with the Lambda zip). Locally and in main-repo
// CI, the file resolves.
func TestTemplatesMatchAgentAPISpec(t *testing.T) {
	yamlPath := locateAgentAPIYAML()
	if yamlPath == "" {
		t.Skip("docs/api/agent-api.yaml not located from this checkout — drift check skipped")
	}
	body, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Skipf("read %s: %v", yamlPath, err)
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

// locateAgentAPIYAML walks upward from the package source directory
// looking for docs/api/agent-api.yaml. Returns "" if not found.
func locateAgentAPIYAML() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "docs", "api", "agent-api.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// extractAgentAPIPaths is a deliberately tiny "good enough" YAML parser
// for the specific shape of docs/api/agent-api.yaml. We don't import a
// full YAML library because (a) the file's `paths:` section follows a
// rigid two-space-indent OpenAPI 3.0 layout, (b) keeping the package
// dependency-light avoids cascading import-path churn into every Lambda
// that pulls in path_template via replace directive.
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
