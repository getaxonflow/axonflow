// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent"
	sharedidentity "axonflow/platform/shared/identity"
)

// OverrideView is THE element shape for `policy_overrides` on the orchestrator
// plane — one type behind its read views (#3944, #3897 §3).
//
// # What was wrong
//
// One table had four readers and four element shapes. The agent's parallel
// route over the SAME table (platform/agent/policy_types.go, PolicyOverride)
// returned `action_override` and `enabled_override`; the orchestrator's list,
// by-id and create views returned NEITHER. `action_override` is what an
// override DOES, so listing overrides through the orchestrator could not tell
// an operator what any of them was, and fetching one by id did not answer it
// either. The three also disagreed on the organisation key — `org_id` on the
// agent, `organization_id` on the by-id view, absent on the other two — and the
// create response did not echo `override_reason`, which is the mandatory
// ADR-044 justification the caller had just supplied.
//
// # Why ONE TYPE rather than three corrected structs
//
// Three structs that agree today are three structs that can drift tomorrow, and
// the drift is invisible: each one is locally correct. A single type makes the
// agreement STRUCTURAL — adding a member here adds it to both read views at
// once (the create response went with the session override write, #4252), and
// no future reviewer has to notice that another site exists. That is also what makes the DoD's "deserialise all four
// views with ONE client type" a property of the code rather than of a test.
//
// # The organisation key
//
// `org_id` is canonical: it is what the agent's view of this table emits, what
// the column is called, and what 64 of the 68 JSON tags in this tree spell it.
// `organization_id` is retained as a DEPRECATED ALIAS carrying the same value,
// not renamed away, because this is a published endpoint and a shipped client
// may read it — the `context_id` -> `decision_id` treatment from #3901, which
// is the model this follows.
//
// This is NOT a reversal of #3334, and the difference matters: that decision
// settled the wire name on the POLICY surface, where `organization_id` is
// current and deliberate and the document says so at the field. This is the
// OVERRIDES surface, whose own sibling view has always said `org_id`.
type OverrideView struct {
	ID         string `json:"id"`
	PolicyID   string `json:"policy_id"`
	PolicyType string `json:"policy_type"`

	// Scope. TenantID is nullable — a NULL tenant is what makes a row
	// org-scoped rather than tenant-scoped (see PolicyOverride).
	TenantID *string `json:"tenant_id,omitempty"`
	OrgID    string  `json:"org_id"`
	// OrganizationID is a deprecated alias of OrgID, always carrying the same
	// value. Read `org_id`.
	//
	// NO `omitempty`, and that is the whole point of the alias. With it, an
	// empty org made `org_id` present as "" (it has no omitempty) while
	// `organization_id` VANISHED - so the two diverged on exactly the row the
	// nullable-column handling was added for, and "always carrying the same
	// value" was false where it mattered most. R3 found it.
	OrganizationID string `json:"organization_id"`

	// What the override DOES. The reason this issue exists.
	ActionOverride  *string `json:"action_override,omitempty"`
	EnabledOverride *bool   `json:"enabled_override,omitempty"`

	// Governance.
	OverrideReason string     `json:"override_reason"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	ToolSignature  *string    `json:"tool_signature,omitempty"`

	// Audit trail.
	// No `omitempty`: the by-id view this replaces declared `json:"created_by"`
	// and emitted the key unconditionally, so omitting it for a row whose
	// created_by is empty would be SUBTRACTIVE on a published response.
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy *string    `json:"revoked_by,omitempty"`
}

// setOrg assigns both spellings from one value, so the alias cannot fall out of
// step with the canonical member by being set at only one of the call sites.
func (v *OverrideView) setOrg(org string) {
	v.OrgID = org
	v.OrganizationID = org
}

// overrideViewColumns is the SELECT list every view of this table uses, in the
// order scanOverrideView reads them. Sharing it is what stops a column being
// added to one query's projection and not another's — the shape of this issue.
const overrideViewColumns = `id, policy_id, policy_type, tenant_id, org_id,
	action_override, enabled_override, override_reason, expires_at,
	tool_signature, created_by, created_at, revoked_at, revoked_by`

// scanRow is the one-row abstraction shared by *sql.Row and *sql.Rows, so the
// by-id and list views scan through identical code.
type scanRow interface{ Scan(dest ...any) error }

// scanOverrideView reads one row of overrideViewColumns into the common shape.
func scanOverrideView(s scanRow) (OverrideView, error) {
	var v OverrideView
	// EVERY nullable column gets a Null* target, and the list is longer than it
	// looks. `policy_overrides` declares NOT NULL on almost nothing
	// (migrations/core/030_policy_tier_columns.sql): `created_by` is a bare
	// VARCHAR(255) and `created_at` only has a DEFAULT, which constrains what
	// this code writes and says nothing about what is already in the table.
	//
	// This matters more than it used to. Before #3944 the list query did not
	// project `created_by` at all, so a NULL there listed fine; projecting it
	// into a plain string fails the scan, and the same change makes a scan
	// failure a 500 for the WHOLE list rather than a silently dropped row. A row
	// with a NULL created_by is reachable - four fixtures in this repository
	// insert one - so that is a 200 -> 500 regression on every override in the
	// tenant, and sqlmock cannot see it because the fixture supplies the values.
	// TestOverrideViewScansANullCreatedBy drives it against a real Postgres.
	var org, action, createdBy sql.NullString
	var enabled sql.NullBool
	var createdAt sql.NullTime
	err := s.Scan(
		&v.ID, &v.PolicyID, &v.PolicyType, &v.TenantID, &org,
		&action, &enabled, &v.OverrideReason, &v.ExpiresAt,
		&v.ToolSignature, &createdBy, &createdAt, &v.RevokedAt, &v.RevokedBy,
	)
	if err != nil {
		return OverrideView{}, err
	}
	v.setOrg(org.String)
	v.CreatedBy = createdBy.String
	v.CreatedAt = createdAt.Time
	if action.Valid {
		a := action.String
		v.ActionOverride = &a
	}
	if enabled.Valid {
		e := enabled.Bool
		v.EnabledOverride = &e
	}
	return v, nil
}

// resolvePolicyUUID returns the canonical UUID id for a policy given the
// UUID, the static_policies slug, or the dynamic_policies name. Returns
// an empty string (no error) when no match is found.
func resolvePolicyUUID(ctx context.Context, db *sql.DB, tenantID, policyID string) (string, error) {
	if db == nil || policyID == "" {
		return "", nil
	}
	// A scoped two-pass with the tenancy predicate (#3039): visible under
	// app-role RLS, never a cross-tenant oracle on bypass pools.
	var uuid string
	lookup := func(scopeOrg string) error {
		return agent.WithOrgScope(ctx, db, scopeOrg, func(tx *sql.Tx) error {
			err := tx.QueryRowContext(ctx, `
				SELECT id::text FROM static_policies
				WHERE (id::text = $1 OR policy_id = $1)
				  AND (tenant_id = $2 OR tenant_id = 'global')
				LIMIT 1
			`, policyID, tenantID).Scan(&uuid)
			if err == nil || err != sql.ErrNoRows {
				return err
			}
			return tx.QueryRowContext(ctx, `
				SELECT id::text FROM dynamic_policies
				WHERE (id::text = $1 OR name = $1)
				  AND (tenant_id = $2 OR tenant_id = 'global')
				LIMIT 1
			`, policyID, tenantID).Scan(&uuid)
		})
	}
	err := lookup(tenantID)
	if err == sql.ErrNoRows && tenantID != GlobalTenantSentinel {
		err = lookup(GlobalTenantSentinel)
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return uuid, nil
}

// createOverrideHandler answers a session override create with the v11 freeze.
//
// ADR-044 session break-glass overrides are retired in v11 (PRD v11 §1.5,
// #4252): the workflow step gate no longer reads a session override, and the
// last deciding reader, the agent's tier pass, goes with #4281. The route stays
// registered so a caller is told where the write went, and the override reads
// (by id, and the list) are unchanged.
//
// The order is #4279's: the guards that authenticate the request answer first
// (overrideWriteGuards), then the freeze. The body is never read and no policy
// is looked up, so a malformed body and an unknown policy get the same 409 as a
// well-formed request for an overridable one.
func createOverrideHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := overrideWriteGuards(w, r, "OverrideCreate")
	if !ok {
		return
	}
	refuseSessionOverrideWrite(w, "create", tenantID)
}

// revokeOverrideHandler answers a session override revoke with the v11 freeze,
// in createOverrideHandler's order. The row is left as the record of what was
// granted.
func revokeOverrideHandler(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := overrideWriteGuards(w, r, "OverrideRevoke")
	if !ok {
		return
	}
	refuseSessionOverrideWrite(w, "revoke", tenantID)
}

// overrideWriteGuards runs the guards a session override write answers before
// the freeze, and returns the caller's tenant when every one passes:
//
//   - the agent gateway's proxy token (#2896 WS1b; #3076 for revoke), 403. The
//     per-user identity below is only trustworthy when the agent set it, and
//     Community mode with no configured secret is exempt inside
//     verifyAgentProxyAuth;
//   - a per-user identity (X-User-Email, else X-User-ID), 401 through
//     sendIdentityRequiredError, which names the identity-trust gate when that
//     is what removed the header (#3062);
//   - the tenant (X-Tenant-ID), 400.
func overrideWriteGuards(w http.ResponseWriter, r *http.Request, op string) (string, bool) {
	if ok, msg := verifyAgentProxyAuth(r, op); !ok {
		sendErrorResponse(w, msg, http.StatusForbidden)
		return "", false
	}
	userEmail := r.Header.Get("X-User-Email")
	if userEmail == "" {
		userEmail = r.Header.Get("X-User-ID")
	}
	if sharedidentity.CanonicalEmail(userEmail) == "" {
		sendIdentityRequiredError(w, r, "policy overrides")
		return "", false
	}
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		sendErrorResponse(w, "Tenant identity required (X-Tenant-ID header)", http.StatusBadRequest)
		return "", false
	}
	return tenantID, true
}

// getOverrideHandler handles GET /api/v1/overrides/:id.
// SECURITY: Scoped to the caller's tenant — does not leak override details
// across tenants.
func getOverrideHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	overrideID := vars["id"]
	if overrideID == "" {
		sendErrorResponse(w, "Override id required", http.StatusBadRequest)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		sendErrorResponse(w, "Tenant identity required (X-Tenant-ID header)", http.StatusBadRequest)
		return
	}

	// #3944: this was a local struct that omitted `action_override` and
	// `enabled_override` and spelled the organisation key `organization_id`
	// while reading the `org_id` column. It is now the shared OverrideView, so
	// this view and the list and create views cannot drift apart again.

	// #3060 (#2991 coverage gap): stamped before the lookup so the header goes
	// out on both 404s this handler can produce — the non-oracle body cannot
	// distinguish "no such override" from "not yours".
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)

	// #3048: org-scoped read — bare, this matched 0 rows under
	// axonflow_app_role (mig 110 RLS) and every override GET 404'd. Same
	// scope key convention as the retired override write (X-Org-ID falling
	// back to tenant).
	getScope := r.Header.Get("X-Org-ID")
	if getScope == "" {
		getScope = tenantID
	}
	var row OverrideView
	err := agent.WithOrgScope(r.Context(), usageDB, getScope, func(tx *sql.Tx) error {
		var scanErr error
		row, scanErr = scanOverrideView(tx.QueryRowContext(r.Context(),
			`SELECT `+overrideViewColumns+`
			 FROM policy_overrides WHERE id = $1 AND tenant_id = $2`,
			overrideID, tenantID))
		return scanErr
	})
	if err == sql.ErrNoRows {
		sendErrorResponse(w, "Override not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("override get: query failed: %v", err)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// #2922 role-scoped reads: a non-tenant-wide caller may fetch only
	// overrides they created. Same 404 as "no such id" — not 403 — so the
	// endpoint is not a cross-user existence oracle.
	if !scope.TenantWide {
		if scope.UserEmail == "" ||
			sharedidentity.CanonicalEmail(row.CreatedBy) != scope.UserEmail {
			sendErrorResponse(w, "Override not found", http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(row)
}

// listOverridesHandler handles GET /api/v1/overrides.
// Filters: policy_id (UUID or slug/name), tenant_id (header-driven),
// include_revoked (bool).
func listOverridesHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	policyIDParam := r.URL.Query().Get("policy_id")
	includeRevoked := r.URL.Query().Get("include_revoked") == "true"

	// Accept either the UUID or the human-readable slug/name on the filter,
	// matching the retired create path's semantic. Users who grab policy_id from
	// a block response's policy_matches[] should be able to pass that
	// straight through to listOverrides without a side-channel lookup.
	// On resolve error we fall back to the raw param so a transient DB hiccup
	// doesn't surface as "no overrides" to the caller — but log it so the
	// degradation is visible in the orchestrator logs.
	policyUUID := policyIDParam
	if policyIDParam != "" {
		if uuid, err := resolvePolicyUUID(r.Context(), usageDB, tenantID, policyIDParam); err != nil {
			log.Printf("override list: resolvePolicyUUID(%q) failed, using raw param: %v",
				policyIDParam, err)
		} else if uuid != "" {
			policyUUID = uuid
		}
	}

	if tenantID == "" {
		sendErrorResponse(w, "X-Tenant-ID header required", http.StatusBadRequest)
		return
	}

	// #2922 role-scoped reads: session overrides are per-user grants keyed to
	// created_by (ADR-044) — a non-tenant-wide caller lists only the overrides
	// THEY created; admin/owner list the tenant's. Empty identity ⇒ empty list
	// (fail-closed). Exact canonical match; the write path stores the same
	// identity this scope compares against.
	//
	// #3060 (#2991 coverage gap): stamp the scope so the empty list below is
	// self-diagnosing rather than a bare 200 {"overrides":[],"count":0}.
	scopeUserEmail := ""
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)
	if !scope.TenantWide {
		if scope.UserEmail == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"overrides": []struct{}{},
				"count":     0,
			})
			return
		}
		scopeUserEmail = scope.UserEmail
	}

	// Dynamic predicate builder (replaces the former 4-branch switch, which
	// would have needed 8 branches with the scope predicate).
	query := `
		SELECT ` + overrideViewColumns + `
		FROM policy_overrides WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if policyUUID != "" {
		args = append(args, policyUUID)
		query += fmt.Sprintf(" AND policy_id::text = $%d", len(args))
	}
	if scopeUserEmail != "" {
		args = append(args, strings.ToLower(scopeUserEmail))
		query += fmt.Sprintf(" AND LOWER(created_by) = $%d", len(args))
	}
	if !includeRevoked {
		query += " AND revoked_at IS NULL"
	}
	query += " ORDER BY created_at DESC LIMIT 100"

	// #3944 CLOSED THE PROJECTION GAP THAT WAS MARKED HERE. This view returned
	// eight members and omitted `org_id`, `tool_signature`, `created_by` and -
	// the two that matter - `action_override` and `enabled_override`, which are
	// what an override DOES. It is now the shared OverrideView, the same type
	// the by-id and create views return.
	//
	// #3048's THIRD SITE, and it is why the projection fix above would
	// otherwise have been invisible.
	//
	// This query was `usageDB.Query(...)` - bare, outside any org scope. But
	// `usageDB` is the axonflow_app_role pool (run.go: OpenAppRoleConnection),
	// which is NOT BYPASSRLS, and `policy_overrides` carries
	// `USING (org_id = current_setting('app.current_org_id', true))` from
	// migration 110. With the GUC unset that predicate is NULL for every row,
	// so this endpoint returned an EMPTY LIST for every organisation - a 200
	// with `{"overrides":[],"count":0}`, which reads to a caller as "this
	// tenant has no overrides" rather than as a failure.
	//
	// #3048 fixed exactly this on the by-id read and the revoke lookup - both
	// carry the comment "the bare read matched 0 rows under axonflow_app_role"
	// - and did not fix it here. Wrapping the list is the same one-line change
	// its two siblings already have, with the same scope key (X-Org-ID falling
	// back to the tenant), and it is what makes `action_override` observable on
	// the deployments this issue is about.
	listScope := r.Header.Get("X-Org-ID")
	if listScope == "" {
		listScope = tenantID
	}
	out := make([]OverrideView, 0, 32)
	if wrapErr := agent.WithOrgScope(r.Context(), usageDB, listScope, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(r.Context(), query, args...)
		if qErr != nil {
			return fmt.Errorf("query: %w", qErr)
		}
		defer rows.Close()
		for rows.Next() {
			v, scanErr := scanOverrideView(rows)
			if scanErr != nil {
				// A scan failure used to `continue`, which silently dropped the
				// row and returned a SHORT list with a `count` that matched it,
				// so the caller could not tell a filtered list from a broken
				// one. On a compliance surface that is the worse of the two
				// failures: an override that exists and is not shown reads as
				// an override that was never created.
				return fmt.Errorf("scan: %w", scanErr)
			}
			out = append(out, v)
		}
		return rows.Err()
	}); wrapErr != nil {
		log.Printf("override list: %v", wrapErr)
		sendErrorResponse(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"overrides": out,
		"count":     len(out),
	})
}

// nullableUUID was deleted here by #3334.
//
// It existed for ONE caller: the policy_overrides INSERT, whose
// organization_id column was typed uuid until migration core/133 retyped it
// to text. AxonFlow org ids are free-form strings from a signed licence
// ("local-dev-org"), so binding one into a uuid column threw
// `pq: invalid input syntax for type uuid` - shipped as a hard 500 in 9.3.0 -
// and this helper silently wrote NULL instead of erroring.
//
// That is a coping mechanism for a column with the wrong type, and it has an
// edge no reader would predict: an org id that HAPPENS to be UUID-shaped was
// stored, while every other org id became NULL, so the column's population
// depended on how a customer chose to name their organisation. Migration
// core/166 drops the column; the (now retired, #4252) INSERT wrote org_id,
// which has been VARCHAR since core/110 and needs no coercion.
//
// The unit tests that pinned its three branches went with it. They tested a
// helper, not a behaviour, and the behaviour they protected - a non-UUID org
// id must not 500 the override create path - is now a property of the schema
// rather than of a function that can be called from somewhere new.
