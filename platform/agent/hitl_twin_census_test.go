// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Source-level guards for the #3509 grant path, covering the two things a
// normal `go test` cannot see: constants that only one BUILD TAG compiles, and
// the ee/ overlay copy that is what actually runs in the Enterprise image.

package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// hitlRepoRoot walks up from the test's working directory to the repo root.
func hitlRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "migrations", "core")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("repo root not found from the test working directory")
	return ""
}

func readRepoFile(t *testing.T, root, rel string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// funcBody returns the source of one function, from its signature to the next
// top-level declaration. Deliberately crude: it exists so a clause census
// cannot be satisfied by a DIFFERENT function in the same file, which is a
// specific hole a mutation run found, not a general parsing ambition.
func funcBody(t *testing.T, src, signature string) string {
	t.Helper()
	i := strings.Index(src, signature)
	if i < 0 {
		t.Fatalf("signature %q not found; the census would otherwise pass over nothing", signature)
	}
	rest := src[i+len(signature):]
	// The next line that starts a top-level declaration ends this body.
	for _, marker := range []string{"\nfunc ", "\ntype ", "\nvar ", "\nconst "} {
		if j := strings.Index(rest, marker); j >= 0 {
			rest = rest[:j]
		}
	}
	if strings.TrimSpace(rest) == "" {
		t.Fatalf("extracted an empty body for %q", signature)
	}
	return rest
}

// TestPolicyStepUpRequestTypeIsIdenticalInEveryBuild.
//
// The literal "policy_step_up" is declared in four places, because
// platform/agent imports platform/agent/hitl and the reverse edge would be a
// cycle, and because platform/agent/hitl has an enterprise variant, a
// community variant, and an ee/ overlay copy that replaces the whole directory
// in the Enterprise image.
//
// A compile-time equality check catches only the pair the CURRENT build tag
// happens to compile. That is not a guard: a drift in the other variant, or in
// the overlay, is invisible to it and would mean entries are written under one
// value and never matched by the consume predicate - every approval silently
// unspendable, which is the exact defect #3509 exists to remove, arriving
// under a different cause. This reads the SOURCE, so it sees all four
// regardless of tags.
func TestPolicyStepUpRequestTypeIsIdenticalInEveryBuild(t *testing.T) {
	root := hitlRepoRoot(t)
	const want = "policy_step_up"

	if HITLRequestTypePolicyStepUp != want {
		t.Fatalf("agent constant = %q, want %q", HITLRequestTypePolicyStepUp, want)
	}

	decl := regexp.MustCompile(`RequestTypePolicyStepUp\s*=\s*"([^"]*)"`)
	sites := []string{
		"platform/agent/hitl_policy_enqueue.go", // agent side (HITLRequestTypePolicyStepUp)
		"platform/agent/hitl/service.go",        // //go:build enterprise
		"platform/agent/hitl/hitl_community.go", // //go:build !enterprise
		"ee/platform/agent/hitl/service.go",     // the Docker overlay copy
	}
	seen := 0
	for _, rel := range sites {
		src, ok := readRepoFile(t, root, rel)
		if !ok {
			if strings.HasPrefix(rel, "ee/") {
				// The community mirror strips ee/; nothing to compare there.
				continue
			}
			t.Fatalf("%s not readable", rel)
		}
		m := decl.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s declares no RequestTypePolicyStepUp: a rename here is a silent drift, "+
				"because whichever build compiles the OTHER copy keeps working", rel)
		}
		if m[1] != want {
			t.Fatalf("%s declares %q, want %q: entries written under one value would never be "+
				"matched by the consume predicate, so every approval would be unspendable", rel, m[1], want)
		}
		seen++
	}
	// Anti-vacuity: a rename that made every path unreadable would otherwise
	// pass over nothing.
	if seen < 3 {
		t.Fatalf("only %d of the declaration sites were checked; this guard is not covering what it claims", seen)
	}
}

// TestConsumeGrantPredicateIsIdenticalInBothTwins.
//
// platform/agent/Dockerfile copies ee/platform/agent/hitl/* OVER
// platform/agent/hitl/ for EDITION=enterprise, so the ee/ copy is what runs in
// the shipped image while the platform/ copy is what the unit tests exercise.
// The repo's existing lockstep guard (platform/shared/egress/conformance_test.go
// TestEETwinsAreInLockstep) is explicitly scoped to the two egress-bearing
// files and its own comment says not to read it as covering the overlay.
//
// So a fix applied to one ConsumeGrant and not the other would pass every test
// and ship the unfixed predicate. This compares the security-bearing clauses
// of the two copies directly.
func TestConsumeGrantPredicateIsIdenticalInBothTwins(t *testing.T) {
	root := hitlRepoRoot(t)
	platformFile, ok := readRepoFile(t, root, "platform/agent/hitl/repository.go")
	if !ok {
		t.Fatal("platform/agent/hitl/repository.go not readable")
	}
	eeFile, ok := readRepoFile(t, root, "ee/platform/agent/hitl/repository.go")
	if !ok {
		t.Skip("ee/ not present in this checkout (community mirror strips it)")
	}
	// Scoped to ConsumeGrant's OWN body, not to the whole file.
	//
	// A whole-file substring check is satisfied by the clause appearing
	// ANYWHERE, and FindOpenPolicyStepUp in the same file matches on the same
	// dimensions - so deleting `AND client_id = ...` from the consume predicate
	// left the census green, because the sibling function still contained the
	// string. A mutation run caught it; a reviewer reading the test would not
	// have.
	platformSrc := funcBody(t, platformFile, "func (r *Repository) ConsumeGrant(")
	eeSrc := funcBody(t, eeFile, "func (r *Repository) ConsumeGrant(")

	// Every clause below is load-bearing: dropping any one of them widens the
	// match across users, across orgs, across planes, past the single-use
	// guard, or past the TTL.
	clauses := []string{
		"WHERE org_id = $1",
		"AND tenant_id = $2",
		"AND client_id = $3",
		"AND user_id = $4",
		"AND triggered_policy_id = $5",
		// A LITERAL, not a bound parameter: it has to match the partial index's
		// own literal predicate (migration 167) or the planner cannot use the
		// index under a generic plan.
		"AND request_type = 'policy_step_up'",
		"AND status = 'approved'",
		"AND consumed_at IS NULL",
		"AND reviewed_at IS NOT NULL",
		"AND reviewed_at > CURRENT_TIMESTAMP - $6::interval",
		// THE APPROVAL MUST NAME A PERSON. The HITL approve route has no role
		// gate, AND on the organization-license path client_id is an
		// unvalidated Basic-auth username - so a clause comparing only
		// reviewer_id to the caller's credential is defeated by re-presenting
		// the same licence under a different username. Only the role clause is
		// not defeatable that way.
		"AND reviewer_role IS NOT NULL",
		"AND reviewer_role <> 'service'",
		"AND reviewer_id IS NOT NULL",
		"AND reviewer_id <> $3",
		"AND reviewer_id <> $4",
		// The grant admits the request the reviewer SAW, not the next one the
		// same rule holds.
		"AND request_context->>'query_hash' = $7",
		"ORDER BY reviewed_at ASC",
		"FOR UPDATE SKIP LOCKED",
		"SET consumed_at = CURRENT_TIMESTAMP",
	}
	for _, c := range clauses {
		// Reported INDEPENDENTLY, not as a switch: if both twins lose the same
		// clause the ee/ message is the one that matters (that copy is what
		// ships), and a switch would print only the platform one and hide it.
		if !strings.Contains(platformSrc, c) {
			t.Errorf("platform/agent/hitl/repository.go is missing the clause %q", c)
		}
		if !strings.Contains(eeSrc, c) {
			t.Errorf("ee/platform/agent/hitl/repository.go is missing the clause %q; the ee/ copy is what "+
				"runs in the Enterprise image, so this ships the weaker predicate", c)
		}
	}

	// The guard clause on ConsumeGrant's own arguments must be present in both
	// too: without it a missing dimension matches across users or orgs.
	// Also body-scoped: FindOpenPolicyStepUp carries an identical guard, so a
	// whole-file check would be satisfied by the sibling.
	const failClosed = `if subj.OrgID == "" || subj.TenantID == "" || subj.ClientID == "" || subj.UserID == "" ||
		policyID == "" || queryHash == "" {`
	if !strings.Contains(platformSrc, failClosed) {
		t.Error("platform ConsumeGrant lost its fail-closed argument guard")
	}
	if !strings.Contains(eeSrc, failClosed) {
		t.Error("ee ConsumeGrant lost its fail-closed argument guard")
	}

	// The partial index the consume relies on must key on the same dimensions
	// the predicate matches, or the lookup falls back to scanning the org's
	// whole queue history on the latency path of a held decision.
	migration, ok := readRepoFile(t, root, "migrations/core/167_hitl_grant_consumption.sql")
	if !ok {
		t.Fatal("migration 167 not readable")
	}
	if !strings.Contains(migration, "(org_id, tenant_id, client_id, user_id, triggered_policy_id, reviewed_at DESC)") {
		t.Error("idx_hitl_unconsumed_grant does not cover the dimensions ConsumeGrant matches on")
	}
}

// TestMigration167DeclaresWhatTheCodeDependsOn.
//
// The consume predicate reads a column and writes a history action that must
// both exist, and the index it relies on is what keeps the lookup off a full
// scan of the org's queue history on the latency path of a held decision. A
// code change that outruns its migration fails at RUNTIME, on a governed
// decision, in production.
func TestMigration167DeclaresWhatTheCodeDependsOn(t *testing.T) {
	root := hitlRepoRoot(t)
	src, ok := readRepoFile(t, root, "migrations/core/167_hitl_grant_consumption.sql")
	if !ok {
		t.Fatal("migrations/core/167_hitl_grant_consumption.sql not readable")
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS consumed_at",
		"idx_hitl_unconsumed_grant",
		"'consumed'",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("migration 167 does not declare %q, but the code depends on it", want)
		}
	}
	// The widened CHECK must ADMIT the value the repository writes, not merely
	// mention it in a comment.
	if !strings.Contains(src, "CHECK (action IN ('created', 'approved', 'rejected', 'expired', 'overridden', 'escalated', 'consumed'))") {
		t.Error("migration 167 does not widen hitl_history_valid_action to admit 'consumed'; " +
			"every consumption history write would fail the CHECK")
	}
	// The dedup lookup asks the OPPOSITE question (pending, not approved) and
	// therefore cannot share an index with the consume. Without its own, it
	// scans every pending row in the org on the request-latency path.
	//
	// The name is matched with its line terminator, not as a bare substring: a
	// mutation run renamed the index to idx_hitl_open_policy_step_up_disabled
	// and a Contains check on the bare name passed, because any longer name
	// that STARTS with it satisfies it. Same class as an unanchored identifier
	// assertion matching a near-miss.
	if !strings.Contains(src, "CREATE INDEX IF NOT EXISTS idx_hitl_open_policy_step_up\n") {
		t.Error("migration 167 declares no index named exactly idx_hitl_open_policy_step_up for the retry-dedup lookup")
	}
	if !strings.Contains(src, "to_regclass('public.idx_hitl_open_policy_step_up') IS NULL") {
		t.Error("migration 167 does not VERIFY the dedup index was created; a silently skipped CREATE would pass")
	}
	if !strings.Contains(src, "WHERE status = 'pending'\n              AND request_type = 'policy_step_up'") {
		t.Error("idx_hitl_open_policy_step_up is not predicated on the rows the dedup lookup matches")
	}

	down, ok := readRepoFile(t, root, "migrations/core/167_hitl_grant_consumption_down.sql")
	if !ok {
		t.Fatal("migration 167 has no down migration")
	}
	if !strings.Contains(down, "DROP COLUMN IF EXISTS consumed_at") {
		t.Error("the down migration does not remove consumed_at")
	}
}

// TestEveryGrantLookupUsesTheSharedPolicyKey.
//
// TestApprovalPolicyKey_WriteAndReadAgree compares the two halves through the
// SAME function, so it agrees by construction and a mutation run showed it
// survives a change to the placeholder. The property that actually matters is
// structural: no plane may pass the RAW ApprovalPolicyID to the consume, or the
// write (which substitutes) and the read (which would not) key differently and
// every approval of an unattributed hold becomes unspendable.
//
// This reads the three call sites and requires the key to be wrapped at each.
func TestEveryGrantLookupUsesTheSharedPolicyKey(t *testing.T) {
	root := hitlRepoRoot(t)
	planes := []string{
		"platform/agent/decision_handler.go",
		"platform/agent/gateway_handlers.go",
		"platform/agent/run.go",
	}
	call := regexp.MustCompile(`consumeApprovalGrant\(`)
	raw := regexp.MustCompile(`consumeApprovalGrant\([\s\S]{0,400}?\}, policyResult\.ApprovalPolicyID,`)
	wrapped := regexp.MustCompile(`consumeApprovalGrant\([\s\S]{0,400}?\}, approvalPolicyKey\(policyResult\.ApprovalPolicyID\),`)

	total := 0
	for _, rel := range planes {
		src, ok := readRepoFile(t, root, rel)
		if !ok {
			t.Fatalf("%s not readable", rel)
		}
		n := len(call.FindAllString(src, -1))
		if n == 0 {
			t.Fatalf("%s no longer calls consumeApprovalGrant; this census would pass over nothing", rel)
		}
		total += n
		if raw.MatchString(src) {
			t.Errorf("%s passes the RAW ApprovalPolicyID to consumeApprovalGrant; the enqueue substitutes a "+
				"placeholder for an unattributed hold, so the two would key differently and every approval "+
				"of one would be unspendable", rel)
		}
		if len(wrapped.FindAllString(src, -1)) != n {
			t.Errorf("%s has %d consumeApprovalGrant call(s) but %d wrapped in approvalPolicyKey",
				rel, n, len(wrapped.FindAllString(src, -1)))
		}
	}
	// Anti-vacuity: all three planes must be present.
	if total != 3 {
		t.Fatalf("found %d consume call sites across the three planes, want 3", total)
	}
}
