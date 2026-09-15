// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"log"
)

// enforceLegacyPolicyReadOnly re-establishes the invariant migrations/core/174
// declares: no application role holds a write that reaches static_policies or
// dynamic_policies, by any route.
//
// WHY THE BOOT PATH AND NOT THE MIGRATION. 174 does run the same function, and
// on an upgrade that is sufficient. It is not sufficient on a fresh install,
// because the closure it has to bind is not complete when it runs:
//
//	migrations/core/       001-099    ← 174 lives here
//	migrations/enterprise/ 100-199
//	migrations/industry/   200+       ← four of the five views live here
//
// The 200+ numbering is deliberate (migration_helpers.go: "Industry migrations
// MUST use numbers >= 200 to ensure they run AFTER all core and enterprise
// migrations"), and core/098 arms ALTER DEFAULT PRIVILEGES so each of those
// views is granted INSERT/UPDATE/DELETE to both application roles at the moment
// it is created. A migration cannot bind a relation that does not exist yet.
// This is the first point in the process at which all DDL has run.
//
// WHY FATAL. The alternative is a warning, and a warning in a boot log is
// indistinguishable from success at the only time anyone reads it. The
// condition being reported is that an application role can reach another
// organization's policy rows through a view - the #3905 bypass, live.
//
// The one non-fatal case is the function being absent, which means the schema
// predates 174 - a deployment on which the closure was never bound at all.
//
// The boot path reaches it through RunMigrations, which returns the core's
// error to run.go (#3894); this wrapper keeps the direct callers' behaviour.
func enforceLegacyPolicyReadOnly(db *sql.DB) {
	if err := runLegacyPolicyReadOnlyEnforcer(db); err != nil {
		fatalMigrationError(err)
	}
}

// runLegacyPolicyReadOnlyEnforcer is enforceLegacyPolicyReadOnly with its
// failure returned rather than fatal, as a *MigrationError whose stage keeps the
// exact fatal message.
func runLegacyPolicyReadOnlyEnforcer(db *sql.DB) error {
	if db == nil {
		return nil
	}

	// to_regprocedure returns NULL rather than raising for an unknown name, so
	// this distinguishes "schema predates 174" from "the call failed" without
	// swallowing the second as the first.
	var present bool
	if err := db.QueryRow(
		`SELECT to_regprocedure('public.enforce_legacy_policy_read_only()') IS NOT NULL`,
	).Scan(&present); err != nil {
		return &MigrationError{stage: stageEnforcerCheck, Err: err}
	}
	if !present {
		log.Printf("ℹ️  Legacy-policy view-write enforcement skipped: schema predates migrations/core/174")
		return nil
	}

	var bound int
	if err := db.QueryRow(`SELECT enforce_legacy_policy_read_only()`).Scan(&bound); err != nil {
		return &MigrationError{stage: stageEnforce, Err: err}
	}
	log.Printf("✅ Legacy-policy read-only invariant enforced: %d (view, role) write grant(s) revoked", bound)
	return nil
}
