// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/decision/authoring"
)

// TestTheOverrideImportRecordsEachOrganizationOnce_RealPG runs the upgrade
// import against a migrated schema (PRD v11 §1.5, migrations/core/183): every
// organization with a policy_overrides row gets one record, the draft read back
// through JSONB still digests to the digest recorded beside it, a second boot
// writes nothing, and the portal's role reads only its own organization's
// record and may only dismiss it - after which boot still imports nothing.
func TestTheOverrideImportRecordsEachOrganizationOnce_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	ctx := context.Background()

	owner, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()

	idOf := func(query, policy string) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, query, policy).Scan(&id); err != nil {
			t.Fatalf("the shipped row %s: %v", policy, err)
		}
		return id
	}
	union := idOf(`SELECT id::text FROM static_policies WHERE policy_id = $1`, "sys_sqli_union_select")
	injection := idOf(`SELECT id::text FROM static_policies WHERE policy_id = $1`, "sys_dangerous_injection_override")
	dynamic := idOf(`SELECT id::text FROM dynamic_policies WHERE policy_id = $1`, "sys_dyn_expensive_query")

	override := func(org, policy, policyType string, tenant, action, enabled any) string {
		t.Helper()
		var id string
		if err := owner.QueryRowContext(ctx, `INSERT INTO policy_overrides
			(policy_id, policy_type, org_id, tenant_id, action_override, enabled_override, override_reason, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, 'realpg', 'realpg') RETURNING id::text`,
			policy, policyType, org, tenant, action, enabled).Scan(&id); err != nil {
			t.Fatalf("seeding an override for %s: %v", org, err)
		}
		return id
	}
	aUnion := override("org-a", union, "static", nil, "block", nil)
	aInjection := override("org-a", injection, "static", nil, nil, false)
	aTenant := override("org-a", union, "static", "tenant-1", "warn", nil)
	aDynamic := override("org-a", dynamic, "dynamic", nil, "block", nil)
	aBreakGlass := override("org-a", injection, "static", nil, "allow", nil)
	if _, err := owner.ExecContext(ctx, `UPDATE policy_overrides SET tool_signature = 'sig', expires_at = now() + interval '1 hour'
		WHERE id = $1::uuid`, aBreakGlass); err != nil {
		t.Fatal(err)
	}
	bTenant := override("org-b", union, "static", "tenant-9", "block", nil)

	now := time.Date(2026, 9, 13, 7, 0, 0, 0, time.UTC)
	written, recorded, err := runPolicyOverrideImport(ctx, owner, now)
	if err != nil || written != 2 || recorded != 0 {
		t.Fatalf("the first import wrote %d and found %d recorded (err %v); want 2 written, 0 recorded", written, recorded, err)
	}

	type record struct {
		sourceRows, imported int
		skipped              []importSkip
		draft, digest        sql.NullString
		importedAt           time.Time
		dismissed            sql.NullTime
	}
	read := func(db *sql.DB, org string) record {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_org_id', $1, true)`, org); err != nil {
			t.Fatal(err)
		}
		var r record
		var skipped string
		if err := tx.QueryRowContext(ctx, `SELECT source_row_count, imported_count, skipped::text, draft::text, draft_digest,
			imported_at, dismissed_at FROM typed_policy_import_drafts WHERE org_id = $1`, org).
			Scan(&r.sourceRows, &r.imported, &skipped, &r.draft, &r.digest, &r.importedAt, &r.dismissed); err != nil {
			t.Fatalf("reading %s's record: %v", org, err)
		}
		if err := json.Unmarshal([]byte(skipped), &r.skipped); err != nil {
			t.Fatal(err)
		}
		return r
	}

	a := read(owner, "org-a")
	if a.sourceRows != 5 || a.imported != 2 || !a.draft.Valid || !a.digest.Valid {
		t.Fatalf("org-a's record: %d rows, %d imported, draft %v, digest %v; want 5, 2, and a draft with its digest",
			a.sourceRows, a.imported, a.draft.Valid, a.digest.Valid)
	}
	// RULE 8, THROUGH THE COLUMN: JSONB reorders keys, and the digest is over
	// the parsed document, so the draft as stored still digests to it.
	var doc authoring.Document
	if err := json.Unmarshal([]byte(a.draft.String), &doc); err != nil {
		t.Fatalf("org-a's draft does not parse: %v", err)
	}
	if got, err := authoring.Digest(&doc); err != nil || got != a.digest.String {
		t.Fatalf("org-a's stored draft digests to %s (err %v); the record names %s", got, err, a.digest.String)
	}
	if len(doc.SystemControls) != 2 {
		t.Fatalf("org-a's draft carries %d system controls, want 2: %+v", len(doc.SystemControls), doc.SystemControls)
	}
	why := map[string]importSkip{}
	for _, s := range a.skipped {
		why[s.OverrideID] = s
	}
	if len(why) != 3 || !strings.HasPrefix(why[aTenant].Reason, "tenant-scoped") ||
		why[aDynamic].Code != "SYSTEM_CONTROL_NOT_REACTIONABLE" || !strings.HasPrefix(why[aBreakGlass].Reason, "break-glass") {
		t.Fatalf("org-a's skipped rows: %+v; want its tenant row, its dynamic re-action (SYSTEM_CONTROL_NOT_REACTIONABLE) and its break-glass row", a.skipped)
	}
	if _, carried := why[aUnion]; carried {
		t.Fatalf("the carried row %s is also listed as skipped", aUnion)
	}
	if _, carried := why[aInjection]; carried {
		t.Fatalf("the carried row %s is also listed as skipped", aInjection)
	}

	b := read(owner, "org-b")
	if b.sourceRows != 1 || b.imported != 0 || b.draft.Valid || b.digest.Valid || len(b.skipped) != 1 || b.skipped[0].OverrideID != bTenant {
		t.Fatalf("org-b's record: %+v; want one row, nothing imported, no draft, its tenant row skipped", b)
	}

	// ONCE: a second boot finds both records and writes nothing.
	written, recorded, err = runPolicyOverrideImport(ctx, owner, now.Add(time.Hour))
	if err != nil || written != 0 || recorded != 2 {
		t.Fatalf("the second import wrote %d and found %d recorded (err %v); want 0 and 2", written, recorded, err)
	}
	if again := read(owner, "org-a"); !again.importedAt.Equal(a.importedAt) {
		t.Fatalf("org-a's record moved from %s to %s on the second boot", a.importedAt, again.importedAt)
	}

	// THE PORTAL'S ROLE: its own organization only, and only a dismissal.
	app, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	approletest.AssertCurrentUser(t, app, "axonflow_app_role")
	asOrgA := func(stmt string) error {
		tx, err := app.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_org_id', 'org-a', true)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
		return tx.Commit()
	}
	var visible int
	if err := func() error {
		tx, err := app.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_org_id', 'org-a', true)`); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM typed_policy_import_drafts`).Scan(&visible)
	}(); err != nil || visible != 1 {
		t.Fatalf("the app role scoped to org-a sees %d record(s) (err %v); want its own one", visible, err)
	}
	if err := asOrgA(`UPDATE typed_policy_import_drafts SET dismissed_at = now() WHERE org_id = 'org-a'`); err != nil {
		t.Fatalf("the app role could not dismiss org-a's draft: %v", err)
	}
	if err := asOrgA(`UPDATE typed_policy_import_drafts SET draft = NULL WHERE org_id = 'org-a'`); err == nil {
		t.Fatal("the app role rewrote org-a's draft; it may only dismiss it")
	}
	if err := asOrgA(`UPDATE typed_policy_import_drafts SET dismissed_at = NULL WHERE org_id = 'org-a'`); err == nil {
		t.Fatal("the app role undid a dismissal; a draft is dismissed once")
	}
	if _, err := owner.ExecContext(ctx, `DELETE FROM typed_policy_import_drafts WHERE org_id = 'org-a'`); err == nil ||
		!strings.Contains(err.Error(), "records an import") {
		t.Fatalf("deleting org-a's record as the owner gave %v; want the record guard's refusal", err)
	}
	if d := read(owner, "org-a"); !d.dismissed.Valid {
		t.Fatal("org-a's dismissal did not stay")
	}

	// A DISMISSED DRAFT KEEPS ITS ROW, SO BOOT NEVER IMPORTS AGAIN.
	written, recorded, err = runPolicyOverrideImport(ctx, owner, now.Add(2*time.Hour))
	if err != nil || written != 0 || recorded != 2 {
		t.Fatalf("the import after a dismissal wrote %d and found %d recorded (err %v); want 0 and 2", written, recorded, err)
	}
}
