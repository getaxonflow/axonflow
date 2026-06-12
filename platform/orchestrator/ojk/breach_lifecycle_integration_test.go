//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

// requireBreachTable skips when migration 130 (ojk_breach_notifications) is not
// present in the test DB. CI applies migrations/enterprise/* so these run for
// real; local devs without migrations get a skip rather than a spurious failure.
func requireBreachTable(t *testing.T, db *sql.DB) {
	t.Helper()
	var exists bool
	if err := db.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ojk_breach_notifications')`,
	).Scan(&exists); err != nil || !exists {
		t.Skip("ojk_breach_notifications table not present (migration 130 not applied) — skipping")
	}
}

// freshBreachOrg creates a uniquely-named org per test run (nanosecond suffix)
// and registers row cleanup, so count/export assertions never accumulate across
// runs. Returns the org_id used by breach rows.
func freshBreachOrg(t *testing.T, db *sql.DB, base string) string {
	t.Helper()
	tenant := fmt.Sprintf("%s-%d", base, time.Now().UnixNano())
	createOJKTestOrg(t, db, tenant)
	org := "org-ojk-" + tenant
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM ojk_breach_notifications WHERE org_id = $1`, org) })
	return org
}

// seedBreachRow inserts a breach row directly (bypassing the service) so
// evaluator/reader behavior can be tested against arbitrary stored states. The
// id is org-prefixed (org is already nanosecond-unique) so the global primary
// key never collides across tests/runs. Returns the full id.
func seedBreachRow(t *testing.T, db *sql.DB, org, idSuffix, status string, discovery, deadline time.Time, submittedAt *time.Time) string {
	t.Helper()
	id := org + "-" + idSuffix
	_, err := db.Exec(
		`INSERT INTO ojk_breach_notifications
		   (id, org_id, tenant_id, incident_timestamp, discovery_time, notification_deadline,
		    data_subjects_affected, data_types_involved, description, remediation_steps,
		    notified_authority, status, submitted_at, created_at, updated_at)
		 VALUES ($1,$2,$2,$3,$3,$4,1,'nik','seed breach','rotate creds','MOCDA',$5,$6,NOW(),NOW())`,
		id, org, discovery, deadline, status, submittedAt,
	)
	if err != nil {
		t.Fatalf("seed breach row (%s,%s): %v", id, status, err)
	}
	return id
}

func TestBreachLifecycle_Integration_SubmitTimelyWritesSubmittedAt(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()
	requireBreachTable(t, db)

	org := freshBreachOrg(t, db, "breach-submit-timely")
	svc := NewOJKAuditExportService(db, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	resp, err := svc.SubmitBreachNotification(ctx, org, &OJKBreachNotification{
		IncidentTimestamp:    now.Add(-2 * time.Hour),
		DiscoveryTime:        now, // deadline = now+72h → submission is timely
		DataSubjectsAffected: 10,
		DataTypesInvolved:    []string{"nik", "npwp"},
		Description:          "timely breach",
		RemediationSteps:     []string{"rotate"},
	})
	if err != nil {
		t.Fatalf("SubmitBreachNotification: %v", err)
	}
	if resp.Status != string(BreachStatusSubmitted) {
		t.Errorf("effective status = %q, want submitted", resp.Status)
	}
	if resp.SubmittedAt == nil {
		t.Error("SubmittedAt not set on response")
	}

	var status string
	var submittedAt sql.NullTime
	if err := db.QueryRow(
		`SELECT status, submitted_at FROM ojk_breach_notifications WHERE id = $1`, resp.ID,
	).Scan(&status, &submittedAt); err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if status != "submitted" {
		t.Errorf("DB status = %q, want submitted (NOT a hard-coded value: result of the gated transition)", status)
	}
	if !submittedAt.Valid {
		t.Error("DB submitted_at is NULL — the 72h timeliness evidence was not recorded")
	}
}

func TestBreachLifecycle_Integration_LateSubmissionEffectiveOverdue(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()
	requireBreachTable(t, db)

	org := freshBreachOrg(t, db, "breach-late")
	svc := NewOJKAuditExportService(db, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	discovery := now.Add(-100 * time.Hour) // deadline = discovery+72h ≈ now-28h (already past)

	resp, err := svc.SubmitBreachNotification(ctx, org, &OJKBreachNotification{
		IncidentTimestamp:    discovery.Add(-1 * time.Hour),
		DiscoveryTime:        discovery,
		DataSubjectsAffected: 5,
		DataTypesInvolved:    []string{"nik"},
		Description:          "late breach",
		RemediationSteps:     []string{"notify"},
	})
	if err != nil {
		t.Fatalf("SubmitBreachNotification: %v", err)
	}
	if resp.Status != string(BreachStatusOverdue) {
		t.Errorf("effective status = %q, want overdue (filed after the 72h window)", resp.Status)
	}

	var stored string
	var submittedAt sql.NullTime
	var deadline time.Time
	if err := db.QueryRow(
		`SELECT status, submitted_at, notification_deadline FROM ojk_breach_notifications WHERE id = $1`, resp.ID,
	).Scan(&stored, &submittedAt, &deadline); err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if stored != "submitted" {
		t.Errorf("durable status = %q, want submitted (it WAS transmitted, just late)", stored)
	}
	if !submittedAt.Valid || !submittedAt.Time.After(deadline) {
		t.Errorf("submitted_at (%v) must be after the deadline (%v) for a late filing", submittedAt, deadline)
	}

	// Export must surface the effective overdue verdict + within_deadline=false.
	exp, err := svc.ExportAuditData(ctx, org, &OJKAuditExportRequest{
		StartDate: now.Add(-200 * time.Hour).Format("2006-01-02"),
		EndDate:   now.Add(48 * time.Hour).Format("2006-01-02"),
		DataTypes: []OJKAuditDataType{OJKDataTypeBreachNotify},
		Framework: OJKFrameworkUUPDP,
	})
	if err != nil {
		t.Fatalf("ExportAuditData: %v", err)
	}
	rec := findBreachRecord(exp, resp.ID)
	if rec == nil {
		t.Fatalf("breach %s missing from export: %+v", resp.ID, exp.Data)
	}
	if rec.Status != string(BreachStatusOverdue) {
		t.Errorf("export effective status = %q, want overdue", rec.Status)
	}
	if rec.StoredStatus != "submitted" {
		t.Errorf("export stored status = %q, want submitted", rec.StoredStatus)
	}
	if rec.WithinDeadline {
		t.Error("export within_deadline = true, want false for an overdue breach")
	}
}

func TestBreachLifecycle_Integration_EvaluateDeadlinesFlipsLapsedDrafts(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()
	requireBreachTable(t, db)

	org := freshBreachOrg(t, db, "breach-evaluate")
	svc := NewOJKAuditExportService(db, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	pastDeadline := now.Add(-1 * time.Hour)
	futureDeadline := now.Add(48 * time.Hour)
	timelySubmit := pastDeadline.Add(-2 * time.Hour)

	// Lapsed, never submitted → MUST flip to overdue.
	draftLapsed := seedBreachRow(t, db, org, "draft-lapsed", string(BreachStatusDraft), now.Add(-10*time.Hour), pastDeadline, nil)
	// Inside its window, never submitted → MUST NOT flip.
	draftWithin := seedBreachRow(t, db, org, "draft-within", string(BreachStatusDraft), now, futureDeadline, nil)
	// Submitted before its (past) deadline → MUST NOT flip (has submitted_at).
	submittedLapsed := seedBreachRow(t, db, org, "submitted-lapsed", string(BreachStatusSubmitted), now.Add(-10*time.Hour), pastDeadline, &timelySubmit)

	flipped, err := svc.EvaluateBreachDeadlines(ctx, org)
	if err != nil {
		t.Fatalf("EvaluateBreachDeadlines: %v", err)
	}
	if flipped != 1 {
		t.Errorf("flipped = %d, want 1 (only the lapsed never-submitted draft)", flipped)
	}

	assertStatus := func(id, want string) {
		var got string
		if err := db.QueryRow(`SELECT status FROM ojk_breach_notifications WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		if got != want {
			t.Errorf("%s status = %q, want %q", id, got, want)
		}
	}
	assertStatus(draftLapsed, string(BreachStatusOverdue))
	assertStatus(draftWithin, string(BreachStatusDraft))
	assertStatus(submittedLapsed, string(BreachStatusSubmitted))

	// Idempotent: a second sweep flips nothing.
	flipped2, err := svc.EvaluateBreachDeadlines(ctx, org)
	if err != nil {
		t.Fatalf("EvaluateBreachDeadlines (2nd): %v", err)
	}
	if flipped2 != 0 {
		t.Errorf("second sweep flipped = %d, want 0", flipped2)
	}
}

func TestBreachLifecycle_Integration_AcknowledgeAndGating(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()
	requireBreachTable(t, db)

	org := freshBreachOrg(t, db, "breach-ack")
	svc := NewOJKAuditExportService(db, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	resp, err := svc.SubmitBreachNotification(ctx, org, &OJKBreachNotification{
		IncidentTimestamp:    now.Add(-2 * time.Hour),
		DiscoveryTime:        now,
		DataSubjectsAffected: 3,
		DataTypesInvolved:    []string{"nik"},
		Description:          "ack breach",
		RemediationSteps:     []string{"rotate"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	ack, err := svc.AcknowledgeBreachNotification(ctx, org, resp.ID)
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if ack.Status != string(BreachStatusAcknowledged) {
		t.Errorf("ack status = %q, want acknowledged", ack.Status)
	}
	if ack.AcknowledgedAt == nil {
		t.Error("AcknowledgedAt not set on response")
	}

	var status string
	var ackAt sql.NullTime
	if err := db.QueryRow(
		`SELECT status, acknowledged_at FROM ojk_breach_notifications WHERE id = $1`, resp.ID,
	).Scan(&status, &ackAt); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != "acknowledged" || !ackAt.Valid {
		t.Errorf("DB status/acknowledged_at = %q/%v, want acknowledged/non-NULL", status, ackAt.Valid)
	}

	// Re-acknowledge a terminal row → invalid transition.
	if _, err := svc.AcknowledgeBreachNotification(ctx, org, resp.ID); !errors.Is(err, ErrInvalidBreachTransition) {
		t.Errorf("re-acknowledge err = %v, want ErrInvalidBreachTransition", err)
	}
	// Unknown id → not found.
	if _, err := svc.AcknowledgeBreachNotification(ctx, org, "no-such-id"); !errors.Is(err, ErrBreachNotFound) {
		t.Errorf("acknowledge unknown id err = %v, want ErrBreachNotFound", err)
	}
	// Empty id → guarded error (exercises the precondition the nil-DB unit test can't reach).
	if _, err := svc.AcknowledgeBreachNotification(ctx, org, ""); err == nil {
		t.Error("acknowledge empty id: expected error")
	}
	// Acknowledge a never-submitted draft → invalid transition.
	ackDraft := seedBreachRow(t, db, org, "ack-draft", string(BreachStatusDraft), now, now.Add(72*time.Hour), nil)
	if _, err := svc.AcknowledgeBreachNotification(ctx, org, ackDraft); !errors.Is(err, ErrInvalidBreachTransition) {
		t.Errorf("acknowledge draft err = %v, want ErrInvalidBreachTransition", err)
	}
}

func TestBreachLifecycle_Integration_DashboardCountsAndOrgIsolation(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()
	requireBreachTable(t, db)

	svc := NewOJKAuditExportService(db, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	orgA := freshBreachOrg(t, db, "breach-dash-a")
	orgB := freshBreachOrg(t, db, "breach-dash-b")

	// orgA: one timely submitted + one lapsed never-submitted draft (effectively overdue).
	if _, err := svc.SubmitBreachNotification(ctx, orgA, &OJKBreachNotification{
		IncidentTimestamp: now.Add(-time.Hour), DiscoveryTime: now,
		DataSubjectsAffected: 1, DataTypesInvolved: []string{"nik"},
		Description: "a-timely", RemediationSteps: []string{"x"},
	}); err != nil {
		t.Fatalf("orgA submit: %v", err)
	}
	seedBreachRow(t, db, orgA, "a-overdue", string(BreachStatusDraft), now.Add(-10*time.Hour), now.Add(-time.Hour), nil)

	// orgB: one timely submitted (must not leak into orgA counts).
	if _, err := svc.SubmitBreachNotification(ctx, orgB, &OJKBreachNotification{
		IncidentTimestamp: now.Add(-time.Hour), DiscoveryTime: now,
		DataSubjectsAffected: 1, DataTypesInvolved: []string{"npwp"},
		Description: "b-timely", RemediationSteps: []string{"y"},
	}); err != nil {
		t.Fatalf("orgB submit: %v", err)
	}

	dashA, err := svc.GetDashboard(ctx, orgA)
	if err != nil {
		t.Fatalf("dashboard A: %v", err)
	}
	if dashA.BreachNotifications != 2 {
		t.Errorf("orgA total breaches = %d, want 2", dashA.BreachNotifications)
	}
	if dashA.OverdueBreachNotifications != 1 {
		t.Errorf("orgA overdue breaches = %d, want 1", dashA.OverdueBreachNotifications)
	}

	dashB, err := svc.GetDashboard(ctx, orgB)
	if err != nil {
		t.Fatalf("dashboard B: %v", err)
	}
	if dashB.BreachNotifications != 1 {
		t.Errorf("orgB total breaches = %d, want 1 (org isolation)", dashB.BreachNotifications)
	}
	if dashB.OverdueBreachNotifications != 0 {
		t.Errorf("orgB overdue breaches = %d, want 0", dashB.OverdueBreachNotifications)
	}

	// Export org isolation: orgA export must not contain orgB's breach.
	expA, err := svc.ExportAuditData(ctx, orgA, &OJKAuditExportRequest{
		StartDate: now.Add(-200 * time.Hour).Format("2006-01-02"),
		EndDate:   now.Add(48 * time.Hour).Format("2006-01-02"),
		DataTypes: []OJKAuditDataType{OJKDataTypeBreachNotify},
	})
	if err != nil {
		t.Fatalf("export A: %v", err)
	}
	if got := len(expA.Data.BreachNotifications); got != 2 {
		t.Errorf("orgA export breach records = %d, want 2", got)
	}
	if expA.Summary.RecordsByType["breach_notifications"] != 2 {
		t.Errorf("orgA export records_by_type = %d, want 2", expA.Summary.RecordsByType["breach_notifications"])
	}
}

// TestBreachLifecycle_Integration_ExportAllIncludesBreaches proves the
// OJKDataTypeAll fan-out also surfaces breach notifications (the fallthrough
// chain wiring), not only an explicit breach_notifications request.
func TestBreachLifecycle_Integration_ExportAllIncludesBreaches(t *testing.T) {
	db := getOJKTestDB(t)
	defer db.Close()
	requireBreachTable(t, db)

	org := freshBreachOrg(t, db, "breach-export-all")
	svc := NewOJKAuditExportService(db, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	resp, err := svc.SubmitBreachNotification(ctx, org, &OJKBreachNotification{
		IncidentTimestamp: now.Add(-time.Hour), DiscoveryTime: now,
		DataSubjectsAffected: 7, DataTypesInvolved: []string{"nik"},
		Description: "all-export breach", RemediationSteps: []string{"rotate"},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	exp, err := svc.ExportAuditData(ctx, org, &OJKAuditExportRequest{
		StartDate: now.Add(-48 * time.Hour).Format("2006-01-02"),
		EndDate:   now.Add(48 * time.Hour).Format("2006-01-02"),
		DataTypes: []OJKAuditDataType{OJKDataTypeAll},
	})
	if err != nil {
		t.Fatalf("export all: %v", err)
	}
	if findBreachRecord(exp, resp.ID) == nil {
		t.Errorf("OJKDataTypeAll export omitted breach %s: %+v", resp.ID, exp.Data.BreachNotifications)
	}
}

func findBreachRecord(exp *OJKAuditExportResponse, id string) *OJKBreachNotificationRecord {
	if exp == nil || exp.Data == nil {
		return nil
	}
	for i := range exp.Data.BreachNotifications {
		if exp.Data.BreachNotifications[i].ID == id {
			return &exp.Data.BreachNotifications[i]
		}
	}
	return nil
}
