// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

// TestResponsePlaneAuditRow_RealPostgres proves the #2626 fix end to end against
// a REAL Postgres with the REAL audit_logs schema (including the canonical
// decision_id + plane (mig 119) and correlation_id (mig 121) columns):
//
//   - a REDACTED response persists with policy_decision='redacted' (NOT
//     'allowed'), redacted_fields populated, and plane='llm' + a decision_id +
//     correlation_id — so the portal decisions/audit feed and the lineage
//     exporters classify it like every other plane;
//   - a WITHHELD (validation-denied) response persists with
//     policy_decision='blocked' (NOT 'allowed');
//   - rows are org-scoped: querying by org_id returns only that org's rows.
//
// This is the persistence half of the runtime-e2e proof; the unit tests cover
// the labeling logic deterministically. Gated on TEST_PG_INTEGRATION=1 + docker.
//
// Red-on-revert: reverting response_processor.go's verdict assignment or
// audit_logger.go's verdict precedence collapses the redacted/blocked rows back
// to 'allowed' and fails the policy_decision assertions below.
func TestResponsePlaneAuditRow_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = db.Close() }()

	// approletest.Setup runs migrations 1..111; apply the canonical-column
	// migrations the response-plane row depends on (119 decision_id+plane,
	// 121 correlation_id).
	for _, mig := range []string{
		"../../migrations/core/119_audit_logs_decision_id_plane.sql",
		"../../migrations/core/121_audit_logs_correlation_id.sql",
	} {
		b, err := os.ReadFile(mig)
		if err != nil {
			t.Fatalf("read %s: %v", mig, err)
		}
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatalf("apply %s: %v", mig, err)
		}
	}

	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	bw := NewBatchWriter(db, 1)

	const (
		orgA = "org-resp-a"
		orgB = "org-resp-b"
	)
	policyResult := &PolicyEvaluationResult{Allowed: true, AppliedPolicies: []string{"pii"}}
	providerInfo := &ProviderInfo{Provider: "openai", Model: "gpt-4"}

	mkReq := func(reqID, org string) OrchestratorRequest {
		return OrchestratorRequest{
			RequestID:   reqID,
			Query:       "q",
			RequestType: "test",
			User:        UserContext{ID: 1, Email: "u@example.com", Role: "user", TenantID: org},
			Client:      ClientContext{ID: "c", OrgID: org},
		}
	}

	// (1) Redacted response for orgA, with a propagated correlation_id.
	ctxA := context.WithValue(context.Background(), ctxKeyCorrelationID, "trace-aaaa")
	ctxA = context.WithValue(ctxA, ctxKeyRedactionInfo, &RedactionInfo{
		HasRedactions:  true,
		RedactedFields: []string{"nik", "email"},
		Verdict:        responseVerdictRedacted,
	})
	redEntry := logger.LogSuccessfulRequest(ctxA, mkReq("req-red-a", orgA), "masked", policyResult, providerInfo)

	// (2) Blocked (withheld) response for orgA.
	ctxBlocked := context.WithValue(context.Background(), ctxKeyCorrelationID, "trace-bbbb")
	blkEntry := logger.LogBlockedResponse(ctxBlocked, mkReq("req-blk-a", orgA), policyResult,
		&RedactionInfo{Verdict: responseVerdictBlocked, ValidationError: "no_empty_response: empty response"})

	// (3) Clean allowed response for orgB (used for org-scoping assertion).
	ctxB := context.WithValue(context.Background(), ctxKeyRedactionInfo,
		&RedactionInfo{Verdict: responseVerdictAllowed})
	allowEntry := logger.LogSuccessfulRequest(ctxB, mkReq("req-allow-b", orgB), "clean", policyResult, providerInfo)

	if err := bw.Write([]*AuditEntry{redEntry, blkEntry, allowEntry}); err != nil {
		t.Fatalf("persist audit rows: %v", err)
	}

	// --- assert the redacted row is canonical + NOT mislabeled allowed --------
	var (
		decision, plane    string
		decisionID         sql.NullString
		correlationID      sql.NullString
		redactedFieldsJSON []byte
	)
	err = db.QueryRow(`SELECT policy_decision, plane, decision_id, correlation_id, redacted_fields
	                   FROM audit_logs WHERE request_id = $1`, "req-red-a").
		Scan(&decision, &plane, &decisionID, &correlationID, &redactedFieldsJSON)
	if err != nil {
		t.Fatalf("query redacted row: %v", err)
	}
	if decision != "redacted" {
		t.Errorf("redacted response persisted as %q, want 'redacted' (NOT 'allowed')", decision)
	}
	if plane != "llm" {
		t.Errorf("redacted row plane = %q, want 'llm'", plane)
	}
	if !decisionID.Valid || decisionID.String == "" {
		t.Error("redacted row missing decision_id")
	}
	if !correlationID.Valid || correlationID.String != "trace-aaaa" {
		t.Errorf("redacted row correlation_id = %v, want 'trace-aaaa'", correlationID)
	}
	if string(redactedFieldsJSON) == "" || string(redactedFieldsJSON) == "null" {
		t.Errorf("redacted row redacted_fields empty: %s", redactedFieldsJSON)
	}

	// --- assert the withheld response is 'blocked' not 'allowed' --------------
	var blkDecision, blkPlane string
	if err := db.QueryRow(`SELECT policy_decision, plane FROM audit_logs WHERE request_id = $1`, "req-blk-a").
		Scan(&blkDecision, &blkPlane); err != nil {
		t.Fatalf("query blocked row: %v", err)
	}
	if blkDecision != "blocked" {
		t.Errorf("withheld response persisted as %q, want 'blocked' (NOT 'allowed')", blkDecision)
	}
	if blkPlane != "llm" {
		t.Errorf("blocked row plane = %q, want 'llm'", blkPlane)
	}

	// --- org scoping: querying orgA returns only orgA's rows ------------------
	var orgACount int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE org_id = $1`, orgA).Scan(&orgACount); err != nil {
		t.Fatalf("count orgA rows: %v", err)
	}
	if orgACount != 2 {
		t.Errorf("orgA should have exactly 2 response-plane rows, got %d", orgACount)
	}
	var leak int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE org_id = $1 AND request_id LIKE 'req-allow-b%'`, orgA).
		Scan(&leak); err != nil {
		t.Fatalf("cross-org leak check: %v", err)
	}
	if leak != 0 {
		t.Errorf("orgB's row leaked into an orgA-scoped query (%d rows)", leak)
	}
}
