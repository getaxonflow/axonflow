// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// #3442 format pin for the control-plane workflow identifier.
//
// The identifier this package mints is the one an operator correlates a
// governed run by: the /api/v1/workflows/{id} path segment, the Approvals
// queue's approve/reject key, the workflows PRIMARY KEY, and the value stamped
// into audit_logs policy_details.workflow_id. It used to be
// `wf_<first 8 hex of a UUID>` - 32 bits - over a table nothing prunes.
//
// These tests pin the SHAPE (so the truncation cannot come back quietly) and,
// separately, pin BOTH minting paths, because there were two copies of the
// truncated expression and fixing one would have left the other unguarded.

const wantWorkflowIDLen = len("wf_") + 36 // "wf_" + a canonical RFC 4122 UUID

func TestNewWorkflowIDFormat(t *testing.T) {
	id := NewWorkflowID()

	if !strings.HasPrefix(id, WorkflowIDPrefix) {
		t.Fatalf("NewWorkflowID() = %q, want prefix %q", id, WorkflowIDPrefix)
	}

	// Length is asserted EXACTLY, not as a minimum. A minimum would have been
	// satisfied by the pre-fix `wf_` + 8 hex if the prefix ever grew, and the
	// entire defect is an identifier that is too short.
	if len(id) != wantWorkflowIDLen {
		t.Fatalf("NewWorkflowID() = %q (len %d), want len %d", id, len(id), wantWorkflowIDLen)
	}

	body := strings.TrimPrefix(id, WorkflowIDPrefix)
	parsed, err := uuid.Parse(body)
	if err != nil {
		t.Fatalf("NewWorkflowID() body %q does not parse as a UUID: %v", body, err)
	}

	// Version 4 + RFC 4122 variant is what carries the 122-bit claim in the
	// generator's comment. A v1 (time-based) or v5 (name-based) UUID would
	// parse and measure identically while carrying far less unpredictability,
	// so parsing alone is not the assertion.
	if parsed.Version() != 4 {
		t.Errorf("NewWorkflowID() body %q is UUID version %d, want 4 (random)", body, parsed.Version())
	}
	if parsed.Variant() != uuid.RFC4122 {
		t.Errorf("NewWorkflowID() body %q has variant %v, want RFC4122", body, parsed.Variant())
	}

	// The canonical hyphenated form is what makes a full UUID unmistakable
	// from a truncation on sight, on a screen and in a log line.
	if strings.Count(body, "-") != 4 {
		t.Errorf("NewWorkflowID() body %q is not the canonical hyphenated form", body)
	}
}

// TestNewWorkflowIDIsNotTheTruncatedShape states the regression directly. The
// format test above would also catch it, but a guard whose failure message
// names the actual defect is worth its two lines.
func TestNewWorkflowIDIsNotTheTruncatedShape(t *testing.T) {
	truncated := regexp.MustCompile(`^wf_[0-9a-f]{8}$`)
	for i := 0; i < 32; i++ {
		if id := NewWorkflowID(); truncated.MatchString(id) {
			t.Fatalf("NewWorkflowID() = %q - the 32-bit `uuid.New().String()[:8]` truncation is back (#3442)", id)
		}
	}
}

func TestNewWorkflowIDIsUnique(t *testing.T) {
	const n = 20000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := NewWorkflowID()
		if _, dup := seen[id]; dup {
			t.Fatalf("NewWorkflowID() produced a duplicate within %d draws: %q", n, id)
		}
		seen[id] = struct{}{}
	}
	// 20k draws is nothing against 122 bits, and it is deliberately MORE than
	// the ~9,300 at which the pre-fix 32-bit space reaches a 1% collision
	// probability - a run this size had a real chance of catching the old
	// generator red-handed, which is the point of choosing it.
}

// TestServiceCreateWorkflowMintsPinnedFormat pins the FIRST minting path:
// Service.CreateWorkflow. It runs against the in-memory mock repository, which
// only assigns an id of its own when the caller left one empty - so a pass
// here proves the service supplied the id, not the mock.
func TestServiceCreateWorkflowMintsPinnedFormat(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)

	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{
		WorkflowName: "3442 format pin",
	}, "tenant-3442", "org-3442", "user-3442", "client-3442")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	assertPinnedWorkflowID(t, "Service.CreateWorkflow", wf.WorkflowID)
	if strings.Contains(wf.WorkflowID, "mock") {
		t.Fatalf("workflow id %q came from the mock repository's fallback, so this test proves nothing about the service", wf.WorkflowID)
	}
}

// TestRepositoryCreateEmptyIDMintsPinnedFormat pins the SECOND minting path:
// PostgresRepository.Create's empty-id fallback. This is the copy the #3442
// issue text did not know about; a fix applied only to the service would have
// left it minting 32-bit ids with nothing red.
func TestRepositoryCreateEmptyIDMintsPinnedFormat(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO workflows").WillReturnResult(sqlmock.NewResult(1, 1))

	wf := &Workflow{WorkflowName: "3442 repository fallback"}
	if err := NewPostgresRepository(db).Create(context.Background(), wf); err != nil {
		t.Fatalf("Create: %v", err)
	}

	assertPinnedWorkflowID(t, "PostgresRepository.Create fallback", wf.WorkflowID)
}

func assertPinnedWorkflowID(t *testing.T, who, id string) {
	t.Helper()
	if !strings.HasPrefix(id, WorkflowIDPrefix) {
		t.Fatalf("%s minted %q, want prefix %q", who, id, WorkflowIDPrefix)
	}
	if len(id) != wantWorkflowIDLen {
		t.Fatalf("%s minted %q (len %d), want len %d - the 32-bit truncation is back", who, id, len(id), wantWorkflowIDLen)
	}
	if _, err := uuid.Parse(strings.TrimPrefix(id, WorkflowIDPrefix)); err != nil {
		t.Fatalf("%s minted %q, whose body is not a UUID: %v", who, id, err)
	}
}

// truncatedUUIDExpr matches a UUID string sliced to a prefix - the exact
// expression #3442 removed, in either of the spellings the codebase uses
// (uuid.New().String() and uuid.NewString()), with or without whitespace.
var truncatedUUIDExpr = regexp.MustCompile(`uuid\.(New\(\)\.String\(\)|NewString\(\))\s*\[\s*:\s*\d+\s*\]`)

// TestNoTruncatedUUIDInWorkflowControl is the extinction guard.
//
// Scoped to this package on purpose: a truncated UUID is a perfectly
// reasonable thing to put in a log line or a display label (several other
// packages do), and a tree-wide ban would be a guard nobody could keep. What
// must never happen again is a truncated UUID in the package that mints a
// database-wide PRIMARY KEY.
//
// The scanner self-tests against a decoy first. An extinction grep that cannot
// SEE the thing it claims is gone passes on an empty file list, a bad regex or
// a path that resolves nowhere, and reports that as success.
func TestNoTruncatedUUIDInWorkflowControl(t *testing.T) {
	decoys := []string{
		`x := fmt.Sprintf("wf_%s", uuid.New().String()[:8])`,
		`id = uuid.NewString()[:12]`,
		`id = uuid.New().String()[ : 8 ]`,
	}
	for _, d := range decoys {
		if !truncatedUUIDExpr.MatchString(d) {
			t.Fatalf("scanner self-test: decoy %q was NOT detected; the guard below cannot fail", d)
		}
	}
	if truncatedUUIDExpr.MatchString(`id = uuid.NewString()`) {
		t.Fatal("scanner self-test: an untruncated uuid.NewString() was flagged; the guard would fail on correct code")
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			// The generator's own doc comment quotes the removed expression;
			// a comment is not a mint.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if truncatedUUIDExpr.MatchString(line) {
				t.Errorf("%s:%d mints a TRUNCATED uuid: %s\n"+
					"    workflow_control mints workflows.workflow_id, a database-wide PRIMARY KEY.\n"+
					"    Use NewWorkflowID() (#3442).", name, i+1, strings.TrimSpace(line))
			}
		}
	}
	// Anti-vacuity: a walk that read no files reports "clean".
	if scanned < 5 {
		t.Fatalf("scanned only %d non-test .go files in workflow_control; the guard is not looking at the package", scanned)
	}
}
