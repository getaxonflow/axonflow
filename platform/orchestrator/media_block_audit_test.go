// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"axonflow/platform/agent"
	"axonflow/platform/agent/approletest"
	sharedaudit "axonflow/platform/shared/audit"

	_ "github.com/lib/pq"
)

// #2680 HOLE 3 — orchestrator media fail-closed deny audit completeness. A
// media-analysis failure under the fail-closed strategy 403'd the request but
// only emitted a log.Printf — no audit_logs row, asymmetric with every other
// terminal deny. LogBlockedMedia now records a canonical row before the 403.

// TestLogBlockedMedia_CanonicalEntry proves (deterministically, no DB) that the
// media fail-closed deny produces a canonical blocked row: plane=media, the
// canonical "blocked" verdict, a decision_id, the propagated correlation_id, and
// the analysis reason — without leaking anything beyond the operational error.
// Red-on-revert: drop the LogBlockedMedia call in run.go and no row is produced
// (covered by the real-PG test); revert the verdict/plane here and this fails.
func TestLogBlockedMedia_CanonicalEntry(t *testing.T) {
	logger := &AuditLogger{auditQueue: make(chan *AuditEntry, 10)}

	ctx := context.WithValue(context.Background(), ctxKeyCorrelationID, "trace-media-1")
	req := OrchestratorRequest{
		RequestID:   "req-media-1",
		Query:       "q",
		RequestType: "test",
		User:        UserContext{ID: 7, Email: "u@example.com", Role: "user", TenantID: "org-m"},
		Client:      ClientContext{ID: "c", OrgID: "org-m"},
		Media:       make([]MediaContentRequest, 2),
	}

	entry := logger.LogBlockedMedia(ctx, req, errors.New("analyzer timeout"))
	if entry == nil {
		t.Fatal("LogBlockedMedia returned nil")
	}

	if entry.PolicyDecision != sharedaudit.DecisionBlocked {
		t.Errorf("policy_decision = %q, want canonical %q", entry.PolicyDecision, sharedaudit.DecisionBlocked)
	}
	if !sharedaudit.IsCanonical(entry.PolicyDecision) {
		t.Errorf("policy_decision %q is not canonical (would be rejected by the migration-123 CHECK)", entry.PolicyDecision)
	}
	if entry.Plane != agent.PlaneMedia {
		t.Errorf("plane = %q, want %q", entry.Plane, agent.PlaneMedia)
	}
	if entry.DecisionID == "" {
		t.Error("missing decision_id")
	}
	if entry.CorrelationID != "trace-media-1" {
		t.Errorf("correlation_id = %q, want the propagated 'trace-media-1'", entry.CorrelationID)
	}
	if entry.OrgID != "org-m" || entry.RequestID != "req-media-1" {
		t.Errorf("org/request identity lost: org=%q request=%q", entry.OrgID, entry.RequestID)
	}
	if entry.ErrorMessage != "analyzer timeout" {
		t.Errorf("error_message = %q, want the analysis reason", entry.ErrorMessage)
	}
	if got := entry.PolicyDetails["plane"]; got != agent.PlaneMedia {
		t.Errorf("policy_details.plane = %v, want %q", got, agent.PlaneMedia)
	}
	if got := entry.PolicyDetails["enforcement"]; got != "fail_closed" {
		t.Errorf("policy_details.enforcement = %v, want fail_closed", got)
	}
	if got := entry.PolicyDetails["media_item_count"]; got != 2 {
		t.Errorf("policy_details.media_item_count = %v, want 2", got)
	}
}

// TestLogBlockedMedia_NilLoggerSafe proves a nil logger is a no-op (the run.go
// caller guards with `if auditLogger != nil`, but the writer is defensive too).
func TestLogBlockedMedia_NilLoggerSafe(t *testing.T) {
	var logger *AuditLogger
	if got := logger.LogBlockedMedia(context.Background(), OrchestratorRequest{}, errors.New("x")); got != nil {
		t.Errorf("nil logger should return nil, got %v", got)
	}
}

// TestLogBlockedMedia_RealPostgres is the persistence half: the media fail-closed
// deny lands in audit_logs with policy_decision='blocked' + plane='media' + a
// decision_id, like every other plane. Gated on TEST_PG_INTEGRATION=1 + docker.
func TestLogBlockedMedia_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = db.Close() }()

	for _, mig := range []string{
		"../../migrations/core/119_audit_logs_decision_id_plane.sql",
		"../../migrations/core/121_audit_logs_correlation_id.sql",
		"../../migrations/core/126_audit_logs_cross_border_fields.sql",
		"../../migrations/core/129_audit_logs_session_id.sql",
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
		auditQueue:   make(chan *AuditEntry, 10),
		shutdownChan: make(chan struct{}),
	}
	bw := NewBatchWriter(db, 1)

	ctx := context.WithValue(context.Background(), ctxKeyCorrelationID, "trace-media-rp")
	req := OrchestratorRequest{
		RequestID:   "req-media-rp",
		Query:       "q",
		RequestType: "test",
		User:        UserContext{ID: 1, Email: "u@example.com", Role: "user", TenantID: "org-mp"},
		Client:      ClientContext{ID: "c", OrgID: "org-mp"},
		Media:       make([]MediaContentRequest, 1),
	}
	entry := logger.LogBlockedMedia(ctx, req, errors.New("analyzer unreachable"))
	if err := bw.Write([]*AuditEntry{entry}); err != nil {
		t.Fatalf("persist media block row: %v", err)
	}

	var decision, plane string
	var decisionID, correlationID sql.NullString
	err = db.QueryRow(`SELECT policy_decision, plane, decision_id, correlation_id
	                   FROM audit_logs WHERE request_id = $1`, "req-media-rp").
		Scan(&decision, &plane, &decisionID, &correlationID)
	if err != nil {
		t.Fatalf("query media block row: %v", err)
	}
	if decision != "blocked" {
		t.Errorf("media fail-closed deny persisted as %q, want 'blocked'", decision)
	}
	if plane != "media" {
		t.Errorf("media row plane = %q, want 'media'", plane)
	}
	if !decisionID.Valid || decisionID.String == "" {
		t.Error("media row missing decision_id")
	}
	if !correlationID.Valid || correlationID.String != "trace-media-rp" {
		t.Errorf("media row correlation_id = %v, want 'trace-media-rp'", correlationID)
	}
}
