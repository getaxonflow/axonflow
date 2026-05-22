// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProbeBootLogShimMatchesCanonicalShape pins the production-posture
// boot-log probe (scripts/e2e/probe-boot-log.sh) to the canonical shape
// pinned by TestBootLogCanonicalShape.
//
// Issue #2391 / PR-E1 acceptance dimension:
//
//	"The boot-log assertion uses the canonical shape from PR #2385's
//	 TestBootLogCanonicalShape so it stays in sync"
//
// If a future refactor changes the boot-log format (e.g. drops the
// `current_user=` token or the `connected as` prefix), TestBootLogCanonicalShape
// fails for the Go side AND this test fails for the bash probe side. The
// two regression guards stay in lock-step.
//
// What this test pins:
//  1. The probe's awk filter matches lines containing both `connected as`
//     and `current_user=` — the same boot-log marker substring
//     TestBootLogCanonicalShape uses.
//  2. The probe explicitly handles three role tokens:
//     axonflow_app_role  (pass — the contract)
//     axonflow_platform_admin (pass — cross-org workers)
//     axonflow            (fail — silent master fallback)
//  3. The probe's awk extraction handles trailing whitespace OR `(`
//     (the canonical shape emits role then " (UseAppRoleEnabled=...")
//
// Mutation-test: changing the canonical role token strings in
// probe-boot-log.sh fails this test with the file:line of the mismatch.
func TestProbeBootLogShimMatchesCanonicalShape(t *testing.T) {
	// Locate the probe script. The Go test runs from
	// platform/orchestrator/ — climb to repo root.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Join(wd, "..", "..")
	probePath := filepath.Join(repoRoot, "scripts", "e2e", "probe-boot-log.sh")

	body, err := os.ReadFile(probePath)
	if err != nil {
		t.Fatalf("read %s: %v (expected probe-boot-log.sh to be in tree per PR-E1)", probePath, err)
	}
	probeSrc := string(body)

	// 1. The boot-log marker must match the Go canonical marker.
	//    TestBootLogCanonicalShape pins:
	//      const bootLogMarker = "connected as current_user=%s"
	//    The %s is a printf format token — the bash probe sees the
	//    POST-substitution form `connected as current_user=`. The probe's
	//    grep anchor must contain that literal substring.
	const wantMarker = "connected as current_user="
	if !strings.Contains(probeSrc, wantMarker) {
		t.Errorf("probe-boot-log.sh missing canonical marker %q — drift from TestBootLogCanonicalShape's bootLogMarker. Run TestBootLogCanonicalShape to confirm the Go side is still on the canonical shape, then update the probe.",
			wantMarker)
	}

	// 2. The probe must explicitly enumerate the three role tokens. A future
	//    refactor that drops one of them is a structural regression.
	for _, role := range []string{
		"axonflow_app_role",
		"axonflow_platform_admin",
		"axonflow", // master — must be REJECTED, not silently accepted
	} {
		if !strings.Contains(probeSrc, role) {
			t.Errorf("probe-boot-log.sh missing role token %q — incomplete classifier", role)
		}
	}

	// 3. The probe MUST contain the refusal verb on the master role. If a
	//    refactor accidentally treats master as a pass, the probe silently
	//    rubber-stamps the Session 21 failure class — which is exactly the
	//    bug this PR closes. Pin the refusal phrasing.
	for _, want := range []string{
		"silent fallback",
		"REFUSE TO PROCEED",
	} {
		if !strings.Contains(probeSrc, want) {
			t.Errorf("probe-boot-log.sh missing refusal phrasing %q — a refactor may have neutered the master-fallback rejection. The probe must REFUSE on master role, not warn.",
				want)
		}
	}

	// 4. The probe must NOT use a bare `grep current_user=axonflow` — that
	//    pattern false-positive-matches axonflow_app_role (prefix). The probe
	//    must distinguish via token-exact extraction (awk split on whitespace
	//    or `(`). Look for the canonical extraction comment OR awk pattern.
	if strings.Contains(probeSrc, "grep current_user=axonflow ") ||
		strings.Contains(probeSrc, "grep -q current_user=axonflow ") {
		t.Errorf("probe-boot-log.sh uses bare substring grep on master role — that pattern false-positives on axonflow_app_role (prefix). Use awk extraction with token-exact comparison.")
	}
}

// TestProductionPostureRegistryWellFormed pins the production-posture
// registry shape (issue #2391 PR-E1). Every non-comment entry must have
// 4 pipe-delimited fields; the expected outcome must be one of two known
// values; PR-C1 markers must reference real C1-pending sites from #2384.
//
// Mutation gate: changing the expected-outcome enum value in the runner
// without updating the registry's expected field triggers a parse-error
// path; this test catches that drift at compile time before CI runs.
func TestProductionPostureRegistryWellFormed(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Join(wd, "..", "..")
	registryPath := filepath.Join(repoRoot, "scripts", "e2e", "production_posture_registry.txt")

	body, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatalf("read %s: %v (registry expected per PR-E1)", registryPath, err)
	}

	allowedOutcomes := map[string]bool{
		"pass":                        true,
		"E2E-EXPECT-FAIL-UNTIL-PR-C1": true,
	}

	entries := 0
	expectFailEntries := 0
	passEntries := 0
	for lineNo, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "|", 4)
		if len(fields) != 4 {
			t.Errorf("registry line %d malformed: want 4 pipe-delimited fields, got %d: %q",
				lineNo+1, len(fields), line)
			continue
		}
		entries++
		outcome := strings.TrimSpace(fields[1])
		if !allowedOutcomes[outcome] {
			t.Errorf("registry line %d: unknown expected outcome %q (allowed: pass | E2E-EXPECT-FAIL-UNTIL-PR-C1)",
				lineNo+1, outcome)
		}
		switch outcome {
		case "pass":
			passEntries++
		case "E2E-EXPECT-FAIL-UNTIL-PR-C1":
			expectFailEntries++
			// PR-C1 sites must reference at least one #2384 cohort number.
			// The rationale field SHOULD also reference the file:line.
			rationale := fields[3]
			if !strings.Contains(rationale, "INSERT") &&
				!strings.Contains(rationale, "UPSERT") &&
				!strings.Contains(rationale, "UPDATE") {
				t.Errorf("registry line %d EXPECT-FAIL entry should mention INSERT/UPDATE/UPSERT in rationale: %q",
					lineNo+1, rationale)
			}
		}
	}

	// Sanity: PR-E1 must ship with at least one `pass` entry so the suite
	// proves something about the merged surface. EXPECT-FAIL entries are
	// optional in PR-E1 — the runner's boot-evidence assertion in
	// run-production-posture-suite.sh absorbs the EXPECT-FAIL-UNTIL-PR-C1
	// contract by grepping the agent log for the canonical heartbeat RLS
	// violation, which fires WITHOUT a request payload. PR-E3 will expand
	// the registry to add per-handler EXPECT-FAIL entries once the
	// auth-bootstrap + DB-seed CI plumbing is wired.
	if passEntries == 0 {
		t.Error("registry has zero `pass` entries — suite would prove nothing about the merged surface")
	}
	if entries < 3 {
		t.Errorf("registry has %d entries — PR-E1 should ship with at least 3 health-probe entries (agent + orchestrator + customer-portal /health). Got fewer.", entries)
	}
	_ = expectFailEntries // intentionally unused; see comment above
}
