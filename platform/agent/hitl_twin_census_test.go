// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Source-level guards for the #3509 grant path, covering the two things a
// normal `go test` cannot see: constants that only one BUILD TAG compiles, and
// the ee/ overlay copy that is what actually runs in the Enterprise image.

package agent

import (
	"io/fs"
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

// syncStrip names the mechanism by which .github/workflows/sync-community-repo.yml
// removes a file from the PUBLIC community mirror. It is the only reason a
// census site is ever allowed to be absent.
//
// The bug this type exists to prevent: the census used to treat an "ee/" path
// prefix as the definition of "not in the community build". The sync strips by
// TWO independent mechanisms, and the second one operates on files that live
// under platform/ and have no ee/ prefix at all, so the prefix test could not
// see them. platform/agent/hitl/{service,repository}.go are exactly that case,
// and the mirror's own unit-test job went red on them.
type syncStrip int

const (
	// stripNever: the file ships to BOTH editions. It is present in every
	// checkout, so absence is drift - a move or a rename - and must fail
	// wherever it is observed.
	stripNever syncStrip = iota
	// stripEEDir: removed by the sync's rsync --exclude='ee/'.
	stripEEDir
	// stripEnterpriseTag: removed by the sync's `^//go:build enterprise` scan
	// (#3270). NOTE these files live under platform/, not under ee/.
	stripEnterpriseTag
)

var enterpriseBuildTag = regexp.MustCompile(`(?m)^//go:build enterprise|^// \+build enterprise`)

// hitlSyncShape reports which of the community sync's strip mechanisms have
// ALREADY been applied to the tree the test is running against.
//
// Both fields are direct observations of the mechanism itself, not proxies for
// an edition name:
//
//   - ee/ exists if and only if the rsync exclusion has not run.
//   - an enterprise-tagged .go file exists if and only if the build-tag scan has
//     not run. The scan is backed by a fail-closed leak gate
//     (.github/scripts/check-enterprise-leak.sh) that aborts the sync if even one
//     such file survives, so "zero" is guaranteed on the mirror and never
//     accidental.
//
// So permission to be absent is only ever granted when the specific mechanism
// that would have removed that specific file is demonstrably in effect here.
// Nothing is inferred from an edition label or a build tag on the test binary.
type hitlSyncShape struct {
	eeStripped  bool
	tagStripped bool
}

// unsynced reports whether NOTHING has been stripped from this tree, which is
// the enterprise repo and is the only place a rename actually lands. On such a
// tree every census site must be present and the strict census is never
// relaxed.
func (s hitlSyncShape) unsynced() bool { return !s.eeStripped && !s.tagStripped }

func hitlDetectSyncShape(t *testing.T, root string) hitlSyncShape {
	t.Helper()
	shape := hitlSyncShape{}

	if fi, err := os.Stat(filepath.Join(root, "ee")); err != nil || !fi.IsDir() {
		shape.eeStripped = true
	}

	found := false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree must not be read as "no enterprise source
			// here": that would hand out an absence permission the tree has not
			// earned. Fail the walk instead.
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		// A build constraint must precede the package clause, so only that
		// prefix can carry one. Truncating there keeps a doc comment or a test
		// fixture further down the file from being mistaken for a real tag.
		src := string(b)
		if i := strings.Index(src, "\npackage "); i >= 0 {
			src = src[:i]
		}
		if enterpriseBuildTag.MatchString(src) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning %s for enterprise-tagged source: %v; the census cannot decide "+
			"which absences are legitimate without it", root, err)
	}
	shape.tagStripped = !found
	return shape
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
//
// This test is deliberately NOT build-tagged: two of its four sites (the
// agent-side constant and the //go:build !enterprise community stub) survive
// the community sync and remain a genuinely comparable pair there, so it does
// real work on the mirror. The two enterprise-only sites are classified by the
// mechanism that removes them and are permitted to be absent only on a tree
// where that mechanism has demonstrably run.
func TestPolicyStepUpRequestTypeIsIdenticalInEveryBuild(t *testing.T) {
	root := hitlRepoRoot(t)
	shape := hitlDetectSyncShape(t, root)
	const want = "policy_step_up"

	if HITLRequestTypePolicyStepUp != want {
		t.Fatalf("agent constant = %q, want %q", HITLRequestTypePolicyStepUp, want)
	}

	decl := regexp.MustCompile(`RequestTypePolicyStepUp\s*=\s*"([^"]*)"`)
	sites := []struct {
		rel   string
		strip syncStrip
	}{
		// Agent side (HITLRequestTypePolicyStepUp). Untagged: ships everywhere.
		{"platform/agent/hitl_policy_enqueue.go", stripNever},
		// //go:build enterprise, under platform/. The sync's build-tag scan
		// removes it. This is the site the old ee/-prefix test could not see.
		{"platform/agent/hitl/service.go", stripEnterpriseTag},
		// //go:build !enterprise. The sync KEEPS the community half of a tag
		// pair, so this one is present in every checkout.
		{"platform/agent/hitl/hitl_community.go", stripNever},
		// The Docker overlay copy, removed by rsync --exclude='ee/'.
		{"ee/platform/agent/hitl/service.go", stripEEDir},
	}

	seen, wantSeen := 0, 0
	for _, site := range sites {
		mayBeAbsent := (site.strip == stripEEDir && shape.eeStripped) ||
			(site.strip == stripEnterpriseTag && shape.tagStripped)
		if !mayBeAbsent {
			wantSeen++
		}

		src, ok := readRepoFile(t, root, site.rel)
		if !ok {
			if mayBeAbsent {
				continue
			}
			t.Fatalf("%s not readable, and this checkout still contains everything the community "+
				"sync would have stripped, so it was moved or renamed rather than excluded: a rename "+
				"in one twin while the other keeps working is exactly the silent drift this census exists "+
				"to catch", site.rel)
		}

		// Keep the classification honest. A file marked as removed-by-build-tag
		// that has LOST its tag now ships to the public mirror, so its absence
		// would no longer be legitimate and the row must be reclassified. Without
		// this the census could quietly hand out a permission the sync no longer
		// grants, which is the same class of stale assumption as the original bug.
		if site.strip == stripEnterpriseTag && !enterpriseBuildTag.MatchString(src) {
			t.Fatalf("%s is classified stripEnterpriseTag but no longer carries `//go:build enterprise`; "+
				"it now syncs to the public mirror, so its absence is no longer legitimate and this row "+
				"must be reclassified stripNever", site.rel)
		}

		m := decl.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s declares no RequestTypePolicyStepUp: a rename here is a silent drift, "+
				"because whichever build compiles the OTHER copy keeps working", site.rel)
		}
		if m[1] != want {
			t.Fatalf("%s declares %q, want %q: entries written under one value would never be "+
				"matched by the consume predicate, so every approval would be unspendable", site.rel, m[1], want)
		}
		seen++
	}

	// Anti-vacuity, keyed to the edition the census is actually running on. A
	// census that compared nothing has become a test that cannot fail.
	if shape.unsynced() {
		// Nothing has been stripped from this tree, so there is no legitimate
		// absence: the FULL census runs and a one-sided rename still fails hard.
		// This is the arm that runs in the enterprise repo, which is where every
		// rename lands, so the strict check is never lost - only relaxed on a
		// tree where it cannot apply.
		if seen != len(sites) {
			t.Fatalf("this checkout has nothing stripped (ee/ present, enterprise-tagged source present) "+
				"yet only %d of %d declaration sites were checked; the full census must run here", seen, len(sites))
		}
	} else if seen < 2 {
		// The two untagged sites always survive the sync, so a synced tree still
		// compares a real pair. Fewer than two means the census is measuring
		// nothing on this edition.
		t.Fatalf("this checkout is community-synced but only %d declaration site(s) were checked; "+
			"the agent-side constant and the //go:build !enterprise stub both survive the sync, so "+
			"at least 2 must be compared or this guard is vacuous here", seen)
	}
	if seen != wantSeen {
		t.Fatalf("checked %d declaration sites but %d are present-by-construction in this checkout shape "+
			"(ee stripped=%v, enterprise tag stripped=%v)", seen, wantSeen, shape.eeStripped, shape.tagStripped)
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

	// The partial index the consume relies on must key on the same dimensions
	// the predicate matches, or the lookup falls back to scanning the org's
	// whole queue history on the latency path of a held decision.
	//
	// This assertion used to live in TestConsumeGrantPredicateIsIdenticalInBothTwins,
	// which is now `//go:build enterprise` because both halves of the twin pair it
	// compares are enterprise-only. Its subject here is a migrations/core file,
	// which SHIPS to the community mirror and is applied by community deployments,
	// so it belongs on the untagged side or the coverage would simply be lost.
	if !strings.Contains(src, "(org_id, tenant_id, client_id, user_id, triggered_policy_id, reviewed_at DESC)") {
		t.Error("idx_hitl_unconsumed_grant does not cover the dimensions ConsumeGrant matches on")
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
