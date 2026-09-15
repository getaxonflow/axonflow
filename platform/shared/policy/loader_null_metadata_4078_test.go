// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestLoaderDropsARowWhoseMetadataIsNull pins the reader behaviour
// legacycompile's runtime scan-drop model now lists (#4078): policyRow.Metadata
// is a json.RawMessage, and database/sql scans a NULL only into *any, *[]byte
// and *sql.RawBytes, so a static_policies row whose metadata is NULL (the
// column is JSONB with a default and no NOT NULL, core/010) fails the scan, and
// loadFromDatabase logs it and moves on. The row is therefore enforced nowhere
// on the runtime path, which is what a scan-drop model entry claims.
//
// The control is the system row beside it, which carries a metadata and
// loads. So the missing row is missing because of its NULL, not because the
// pass returned nothing.
func TestLoaderDropsARowWhoseMetadataIsNull(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	global := systemRow(sqlmock.NewRows(loaderTestCols()), "sys_meta_present", 100)
	global.AddRow(
		"uuid-sys_meta_null", "sys_meta_null", "Policy sys_meta_null", "security-sqli", "system",
		`(?i)\bTRUNCATE\b`, "critical", nil, "request", "block", nil,
		true, 90, "global", nil, nil, time.Now().UTC(),
	)
	expectScopedLoadPass(mock, "tenant-1", sqlmock.NewRows(loaderTestCols()))
	expectScopedLoadPass(mock, "global", global)

	loader := NewPolicyLoader(db, NewPolicyCache(time.Minute, 10))
	policies, err := loader.GetPolicies(context.Background(), "tenant-1", nil, PhaseRequest)
	if err != nil {
		t.Fatalf("GetPolicies: %v", err)
	}
	var ids []string
	for _, p := range policies {
		ids = append(ids, p.PolicyID)
	}
	if len(policies) != 1 || policies[0].PolicyID != "sys_meta_present" {
		t.Fatalf("want only sys_meta_present loaded (the NULL-metadata row fails its scan), got %v", ids)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
