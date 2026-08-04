// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"database/sql"
	"strings"
	"testing"

	"axonflow/platform/agent/approletest"
)

// #3245: GET /api/v1/euaiact/export 500s on every deployment that does not run
// the TRAVEL industry migration pack.
//
// enterprise/116 creates euaiact_exports with no storage columns. Only
// migrations/industry/travel/201 adds download_url / storage_type /
// storage_key. But exportSelectColumns names all three on every read, and that
// reader is not travel-specific - so on in-vpc-enterprise, banking and
// healthcare the list and get endpoints fail with
//
//	ERROR: column "download_url" does not exist
//
// enterprise/138 moves the columns into the enterprise set. These tests drive
// the REAL repository against a database built the way those deployments build
// it: core + enterprise, and no industry pack.

// enterpriseOnlySchema builds core + enterprise/116 and returns the master
// handle. Deliberately does NOT apply any industry migration - that omission is
// the whole point of the fixture.
func enterpriseOnlySchema(t *testing.T) *sql.DB {
	t.Helper()
	approletest.SkipUnlessEnabled(t)

	env := approletest.Setup(t, "../../../migrations/core")
	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	applySQLFile(t, db, "../../../migrations/enterprise/116_euaiact_orchestrator_tables.sql")
	return db
}

// TestEUAIActExportReadIs500WithoutTheStorageColumns is the defect, reproduced.
//
// It runs the repository's own column list against the enterprise-only schema
// BEFORE 138 and requires the failure - so the fix below cannot pass vacuously
// against a schema that never had the problem.
func TestEUAIActExportReadIs500WithoutTheStorageColumns(t *testing.T) {
	db := enterpriseOnlySchema(t)

	_, err := db.Query(`SELECT `+exportSelectColumns+` FROM euaiact_exports WHERE org_id = $1`, "any-org")
	if err == nil {
		t.Fatal("the export read SUCCEEDED on a core+enterprise schema with no industry pack. " +
			"Either 116 now creates the storage columns (in which case 138 is redundant and this test " +
			"should be deleted with a note) or exportSelectColumns no longer names them.")
	}
	if !strings.Contains(err.Error(), "download_url") {
		t.Fatalf("expected a missing-column error naming download_url, got: %v", err)
	}
	t.Logf("reproduced #3245 on the enterprise-only schema: %v", err)
}

// TestEUAIActExportReadsWorkOnTheEnterpriseMigrationSetAlone is the fix.
func TestEUAIActExportReadsWorkOnTheEnterpriseMigrationSetAlone(t *testing.T) {
	db := enterpriseOnlySchema(t)
	applySQLFile(t, db, "../../../migrations/enterprise/138_euaiact_export_cloud_storage.sql")

	rows, err := db.Query(`SELECT `+exportSelectColumns+` FROM euaiact_exports WHERE org_id = $1`, "any-org")
	if err != nil {
		t.Fatalf("the export read still fails after enterprise/138: %v", err)
	}
	defer func() { _ = rows.Close() }()
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
}

// TestMigration138IsIdempotentOverTheTravelPack pins the upgrade path that
// actually exists in production: travel and saas deployments ALREADY ran
// industry/travel/201, so 138 must be a no-op there rather than an error.
//
// Both orders are exercised. 201-then-138 is the real upgrade; 138-then-201 is
// the deployment that adds the travel pack later, and it must not fail either.
func TestMigration138IsIdempotentOverTheTravelPack(t *testing.T) {
	for _, order := range [][]string{
		{"../../../migrations/industry/travel/201_euaiact_export_cloud_storage.sql",
			"../../../migrations/enterprise/138_euaiact_export_cloud_storage.sql"},
		{"../../../migrations/enterprise/138_euaiact_export_cloud_storage.sql",
			"../../../migrations/industry/travel/201_euaiact_export_cloud_storage.sql"},
	} {
		name := "travel-then-enterprise"
		if strings.Contains(order[0], "enterprise") {
			name = "enterprise-then-travel"
		}
		t.Run(name, func(t *testing.T) {
			db := enterpriseOnlySchema(t)
			for _, f := range order {
				applySQLFile(t, db, f)
			}

			rows, err := db.Query(`SELECT ` + exportSelectColumns + ` FROM euaiact_exports`)
			if err != nil {
				t.Fatalf("export read fails after applying both: %v", err)
			}
			_ = rows.Close()

			// The column definitions must be IDENTICAL whichever ran first, or a
			// travel deployment and an in-vpc one disagree about the schema they
			// claim to share.
			var typ, def sql.NullString
			if err := db.QueryRow(`
				SELECT format_type(a.atttypid, a.atttypmod),
				       pg_get_expr(d.adbin, d.adrelid)
				FROM pg_catalog.pg_attribute a
				JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
				LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
				WHERE c.relname = 'euaiact_exports' AND a.attname = 'storage_type'
				  AND a.attnum > 0 AND NOT a.attisdropped`).Scan(&typ, &def); err != nil {
				t.Fatalf("inspect storage_type: %v", err)
			}
			if typ.String != "text" {
				t.Errorf("storage_type is %q, want text", typ.String)
			}
			if !strings.Contains(def.String, "local") {
				t.Errorf("storage_type default is %q, want the 'local' default both migrations declare", def.String)
			}
		})
	}
}

// TestMigration138DownRetainsTheColumns pins the deliberate no-op rollback:
// storage_key is the only handle to a stored artifact, and on travel/saas the
// columns belong to industry/travel/201, not to 138.
func TestMigration138DownRetainsTheColumns(t *testing.T) {
	db := enterpriseOnlySchema(t)
	applySQLFile(t, db, "../../../migrations/enterprise/138_euaiact_export_cloud_storage.sql")
	applySQLFile(t, db, "../../../migrations/enterprise/138_euaiact_export_cloud_storage_down.sql")

	rows, err := db.Query(`SELECT ` + exportSelectColumns + ` FROM euaiact_exports`)
	if err != nil {
		t.Fatalf("the down migration removed columns it does not own: %v", err)
	}
	_ = rows.Close()
}
