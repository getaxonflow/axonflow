// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/rls"
)

// losingSpellings are the obligation vocabulary terms retired by #3891. If any
// of them is in a stored row, a rename would be a MIGRATION and this lane
// would have to stop and ask for one.
var losingSpellings = []string{
	"field_redaction", "response_filtering", "schema_constrained_transform",
	"audit_notification", "at_least_once_durable",
}

// storedVocabularyQuery counts rows in every table that could carry an
// obligation spelling, as the APPLICATION ROLE sees them under an org scope.
//
// The three tables are the complete set:
//   - typed_policy_artifacts.artifact is the signed document, and
//     obligations[].type lives inside it;
//   - static_policies and dynamic_policies carry LEGACY action words
//     (`redact`, `log`), and their obligation types are derived by
//     legacycompile rather than stored - but they are queried anyway, because
//     "the column does not exist" is a claim about a schema I read and the
//     query is a claim about the bytes.
const storedVocabularyQuery = `
SELECT
  (SELECT count(*) FROM typed_policy_artifacts WHERE artifact::text LIKE $1) +
  (SELECT count(*) FROM static_policies       WHERE (COALESCE(action,'') || COALESCE(action_request,'') || COALESCE(action_response,'')) LIKE $1) +
  (SELECT count(*) FROM dynamic_policies      WHERE actions::text LIKE $1)`

// TestNoStoredRowCarriesARetiredObligationSpelling is the measured half of
// "#3891 needs no migration" (#3891). The structural half is in
// platform/decision/authoring: the only write path into typed_policy_artifacts
// runs Validate, which refuses an obligation type the canonical vocabulary
// does not declare. This is the same claim made against the BYTES.
//
// THREE THINGS MAKE THE ZERO MEAN SOMETHING, and each is the answer to a way
// this test could report a confident nothing:
//
//  1. THE ROLE IS ASSERTED. A superuser read is exempt from RLS, so a clean
//     result under the owner would say nothing about what the application can
//     reach. current_user is checked inside the same transaction that runs the
//     query, not once at setup.
//  2. THE ORG GUC IS SET. A query on an RLS-gated table with no
//     app.current_org_id returns ZERO ROWS FOR EVERY ORG, and zero reads as
//     clean. Every count below runs inside rls.WithOrgScope.
//  3. A POSITIVE IS PLANTED. Before the zero is believed, a row carrying
//     `field_redaction` is inserted for the scoped org and the same query must
//     FIND it. A query that matched nothing because its predicate was wrong
//     would pass every other check here.
func TestNoStoredRowCarriesARetiredObligationSpelling(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	countUnder := func(t *testing.T, org, spelling string) int {
		t.Helper()
		var n int
		err := rls.WithOrgScope(ctx, h.appRoleDB, org, func(tx *sql.Tx) error {
			// (1) The premise, inside the scoped transaction.
			var who string
			if err := tx.QueryRow(`SELECT current_user`).Scan(&who); err != nil {
				return err
			}
			if who != "axonflow_app_role" {
				return fmt.Errorf("current_user is %q, not axonflow_app_role; an exempt role's clean read is not evidence about what RLS hides", who)
			}
			// (2) And the GUC the scope set is really in force.
			var guc string
			if err := tx.QueryRow(`SELECT current_setting('app.current_org_id', true)`).Scan(&guc); err != nil {
				return err
			}
			if guc != org {
				return fmt.Errorf("app.current_org_id is %q, want %q; without it every count is zero for every org", guc, org)
			}
			return tx.QueryRow(storedVocabularyQuery, "%"+spelling+"%").Scan(&n)
		})
		if err != nil {
			t.Fatalf("scoped count for %q: %v", spelling, err)
		}
		return n
	}

	// (3) THE PLANTED POSITIVE, first, so a broken predicate cannot reach the
	// assertions below as a zero. Inserted through the OWNER connection
	// because the app role's grants are the thing under test elsewhere; the
	// READ that matters is the scoped app-role one.
	//
	// IT IS PLANTED IN ITS OWN ORGANIZATION AND NEVER REMOVED, because
	// typed_policy_artifacts is APPEND-ONLY BY TRIGGER and refuses DELETE even
	// to the table owner (`Table typed_policy_artifacts is append-only`,
	// #3776) - measured here, not assumed. A plant into orgA followed by a
	// cleanup would therefore leave the row behind and poison the very
	// assertion it exists to license. Planting into a third organization keeps
	// the claim's two organizations untouched and makes the removal
	// unnecessary; the database is a throwaway container in any case.
	const plantOrg = "org-planted-3891"
	const plantedDigest = "sha256:planted3891planted3891planted3891planted3891planted3891planted00"
	_, err := h.masterDB.ExecContext(ctx, `
		INSERT INTO typed_policy_artifacts
		  (org_id, root, digest, source_digest, document_id, document_version, key_id, artifact)
		VALUES ($1, 'organization', $2, $3, 'planted-3891', 1, 'planted-key', $4::jsonb)`,
		plantOrg, plantedDigest, plantedDigest,
		`{"root":"organization","version":1,"policies":[{"id":"p","obligations":[{"type":"field_redaction","mandatory":true,"source_policy":"p","schema_version":1}]}]}`)
	if err != nil {
		t.Fatalf("planting the positive: %v", err)
	}
	if got := countUnder(t, plantOrg, "field_redaction"); got != 1 {
		t.Fatalf("the planted row was NOT found (count=%d). The query below cannot be trusted to find a real one either.", got)
	}
	// The planted row is scoped: another organization's app-role read does not
	// see it, which is the same instrument reporting an honest zero.
	if got := countUnder(t, orgA, "field_redaction"); got != 0 {
		t.Fatalf("org %s sees org %s's planted row (count=%d); the scope is not in force", orgA, plantOrg, got)
	}

	// THE CLAIM. Every retired spelling, every table, both organizations -
	// neither of which the plant touched.
	for _, org := range []string{orgA, orgB} {
		for _, spelling := range losingSpellings {
			if got := countUnder(t, org, spelling); got != 0 {
				t.Errorf("org %s carries %d stored row(s) matching the retired spelling %q; renaming it would be a MIGRATION and this lane has none allocated",
					org, got, spelling)
			}
		}
	}
}

// TestTheStoredVocabularyQueryIsRunUnderTheRoleItClaims is the instrument's
// own control, kept separate so that a failure here reads as "the harness is
// wrong" rather than "the data is wrong".
func TestTheStoredVocabularyQueryIsRunUnderTheRoleItClaims(t *testing.T) {
	h := setup(t)
	approletest.AssertCurrentUser(t, h.appRoleDB, "axonflow_app_role")

	// An UNSCOPED read on the same connection is the failure mode item (2)
	// above names: no GUC, so RLS matches nothing and the count is zero for
	// every organization. Asserting it here is what makes the scoped zeros in
	// the test above a different fact from this one.
	var unscoped int
	if err := h.appRoleDB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM typed_policy_artifacts`).Scan(&unscoped); err != nil {
		t.Fatalf("unscoped count: %v", err)
	}
	if unscoped != 0 {
		t.Fatalf("an unscoped app-role read returned %d rows; this harness's assumption about RLS is wrong and every zero it reports is unexplained", unscoped)
	}
}
