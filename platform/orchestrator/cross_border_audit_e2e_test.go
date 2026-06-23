//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// End-to-end (real Postgres) coverage of the UU PDP Pasal 56(b) auto-stamp
// (#2718). Gated on DATABASE_URL (skipped otherwise). This is the critical
// chain the master mandated: an auto-stamped cross-border decision row written
// through the real BatchWriter into audit_logs must round-trip, both fields
// intact, through the OJK cross-border export. It exercises the wired stamp
// hook (stampCrossBorderTransfer), the INSERT column wiring, and the repointed
// export query together, NOT sqlmock.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"axonflow/platform/orchestrator/ojk"

	_ "github.com/lib/pq"
)

func TestCrossBorderAutoStamp_EndToEnd(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping end-to-end test: DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}

	ctx := context.Background()
	tenantID := "org-e2e-cross-border-2718"
	auditID := "audit-e2e-2718"
	rowTS := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	// Operator declares the Pasal 56(b) basis via the global config knob.
	t.Cleanup(resetTransferBasisConfigForTest)
	setTransferBasisConfigForTest(&transferBasisConfig{
		defaultBasis: ojk.TransferBasisPasal56bDPA,
		orgOverrides: map[string]string{},
	})

	// Clean any prior row, and clean up afterwards.
	_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE id = $1`, auditID)
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE id = $1`, auditID) })

	// Build a canonical LLM-forward decision row and auto-stamp it through the
	// wired hook (anthropic → US), exactly as the forward path does.
	entry := &AuditEntry{
		ID: auditID, RequestID: "req-e2e-1", Timestamp: rowTS,
		UserID: 1, UserEmail: "auditor@example.com", UserRole: "admin",
		ClientID: "client-e2e", TenantID: tenantID, OrgID: tenantID,
		RequestType: "completion", Query: "hello", QueryHash: "h-e2e",
		PolicyDecision: "allowed",
	}
	req := OrchestratorRequest{Client: ClientContext{OrgID: tenantID}}
	if stampCrossBorderTransfer == nil {
		t.Fatal("stampCrossBorderTransfer hook not wired (enterprise init missing)")
	}
	stampCrossBorderTransfer(entry, req, &ProviderInfo{Provider: "anthropic", Model: "claude-opus-4-8"})
	if entry.TransferBasis != ojk.TransferBasisPasal56bDPA || entry.DataResidency != "US" {
		t.Fatalf("stamp did not populate fields: basis=%q residency=%q", entry.TransferBasis, entry.DataResidency)
	}

	// Write through the REAL BatchWriter into audit_logs.
	bw := &BatchWriter{db: db, batchSize: 1}
	if err := bw.Write([]*AuditEntry{entry}); err != nil {
		t.Fatalf("BatchWriter.Write (migration 126 applied?): %v", err)
	}

	// Verify the columns actually persisted (guards against a silently-failed
	// INSERT, which BatchWriter only logs).
	var gotBasis, gotResidency sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT transfer_basis, data_residency FROM audit_logs WHERE id = $1`, auditID,
	).Scan(&gotBasis, &gotResidency); err != nil {
		t.Fatalf("read back row (migration 126 applied?): %v", err)
	}
	if gotBasis.String != ojk.TransferBasisPasal56bDPA || gotResidency.String != "US" {
		t.Fatalf("persisted columns wrong: basis=%q residency=%q", gotBasis.String, gotResidency.String)
	}

	// Round-trip through the OJK cross-border export.
	svc := ojk.NewOJKAuditExportService(db, nil)
	resp, err := svc.ExportAuditData(ctx, tenantID, &ojk.OJKAuditExportRequest{
		StartDate: "2026-01-01",
		EndDate:   "2026-12-31",
		DataTypes: []ojk.OJKAuditDataType{ojk.OJKDataTypeCrossBorder},
		Framework: ojk.OJKFrameworkUUPDP,
	})
	if err != nil {
		t.Fatalf("ExportAuditData: %v", err)
	}
	if resp.Data == nil || len(resp.Data.CrossBorder) == 0 {
		t.Fatalf("expected at least one cross-border record, got %+v", resp.Data)
	}
	var found bool
	for _, rec := range resp.Data.CrossBorder {
		if rec.ID == auditID {
			found = true
			if rec.TransferBasis != ojk.TransferBasisPasal56bDPA {
				t.Errorf("exported transfer_basis = %q, want pasal_56b_dpa", rec.TransferBasis)
			}
			if rec.DataResidency != "US" || rec.DestinationCountry != "US" {
				t.Errorf("exported residency/destination = %q/%q, want US/US", rec.DataResidency, rec.DestinationCountry)
			}
		}
	}
	if !found {
		t.Fatalf("auto-stamped row %q did not round-trip through the OJK export: %+v", auditID, resp.Data.CrossBorder)
	}
}
