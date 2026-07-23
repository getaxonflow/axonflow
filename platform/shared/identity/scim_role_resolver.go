//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// scimRoleResolver resolves a validated identity's effective role from the
// server-side role directory: role_assignments (populated by SCIM group
// sync AND by manual admin assignment — both converge on the same table)
// joined to custom_roles.
//
// Deterministic effective-role rule (interim pending the #2921 role-model
// formalization; reconcile there at integration):
//
//  1. an assignment to a role NAMED "owner" → "owner". owner is the top tier
//     and OUTRANKS admin (#2993): the seeded owner role carries the "*" wildcard
//     (it is a true superset of admin), so this name check MUST precede the
//     wildcard→admin rule or a wildcard owner would collapse into admin.
//  2. otherwise any active assignment whose role grants the wildcard "*"
//     permission, or is named "admin" → "admin";
//  3. otherwise the highest-precedence KNOWN role name among the active
//     assignments: policy_admin > developer > viewer;
//  4. otherwise (no assignments, or only custom roles outside the known
//     set) → "" — unmapped, which every consumer must treat as
//     least-privilege. A custom role's read-scope semantics are #2921's to
//     define; guessing "custom probably means broad" here would be a
//     privilege escalation, so unknown ranks as unmapped.
type scimRoleResolver struct {
	db *sql.DB
}

// rolePrecedence orders the known non-admin role names, strongest first. It is
// exactly knownRoles minus "admin" (which is matched separately, by name or by
// the "*" wildcard permission). #2993 dropped "member" from the role model, so
// it is gone here too — the lockstep guard test asserts rolePrecedence ∪
// {"admin"} == knownRoles so this can never silently drift from the validator's
// vocabulary. A legacy assignment to a role named "member" now falls through to
// "" (least-privilege), matching NormalizeRole.
var rolePrecedence = []string{"owner", "policy_admin", "developer", "viewer"}

// NewSCIMRoleResolver builds a RoleResolver over the shared platform
// database. role_assignments is FORCE-RLS org-isolated (mig 111), so reads
// run inside an org-scoped transaction.
func NewSCIMRoleResolver(db *sql.DB) (RoleResolver, error) {
	if db == nil {
		return nil, fmt.Errorf("identity: nil db for SCIM role resolver")
	}
	return &scimRoleResolver{db: db}, nil
}

func (r *scimRoleResolver) ResolveRole(ctx context.Context, orgID, email string) (string, error) {
	if orgID == "" {
		return "", fmt.Errorf("identity: role resolution requires an org")
	}
	email = CanonicalEmail(email)
	if email == "" {
		return "", fmt.Errorf("identity: role resolution requires an email")
	}

	type assignment struct {
		name     string
		wildcard bool
	}
	var assignments []assignment
	var directoryDeactivated bool
	err := withOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, `
			SELECT cr.name, cr.permissions
			FROM role_assignments ra
			INNER JOIN custom_roles cr ON ra.role_id = cr.id
			WHERE ra.org_id = $1
			  AND lower(ra.user_email) = $2
			  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		`, orgID, email)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a assignment
			var permsJSON []byte // custom_roles.permissions is JSONB (mig 023)
			if scanErr := rows.Scan(&a.name, &permsJSON); scanErr != nil {
				return scanErr
			}
			var perms []string
			if len(permsJSON) > 0 {
				if uErr := json.Unmarshal(permsJSON, &perms); uErr != nil {
					return fmt.Errorf("role %q has malformed permissions JSON: %w", a.name, uErr)
				}
			}
			for _, p := range perms {
				if p == "*" {
					a.wildcard = true
					break
				}
			}
			assignments = append(assignments, a)
		}
		if rErr := rows.Err(); rErr != nil {
			return rErr
		}

		// #3030 defense-in-depth: never confer a role from a SCIM directory row
		// the IdP has DEACTIVATED. role_assignments has no FK to scim_users, so
		// a missed revoke on a deprovision (PATCH active=false) would otherwise
		// leave a stale grant conferring tenant-wide read authority until the
		// OIDC token TTL expires. This is a SECOND layer behind the service-side
		// revoke: it does not need to cover the DELETE case (a deleted user has
		// no directory row, indistinguishable from a manual principal), which
		// the actual role_assignments revoke handles.
		//
		// Scope of the refusal (deliberate, two-layer): while the directory says
		// inactive, NO role is conferred ON THE FLEET PLANE — including grants
		// whose source is 'manual' or 'system'. Those grants are preserved in
		// STORAGE (the service-side revoke only ever removes source='scim'
		// rows), they are just not CONFERRED here while the IdP says the human
		// must not act. The customer-portal plane does not use this resolver, so
		// a deactivated last-owner can still act in the portal — no org lockout.
		//
		// Runs inside the SAME org-scoped transaction as the assignments query
		// (m4): Path-B fleet resolution is a hot path, and a second BeginTx +
		// set_config round-trip per resolve is measurable; one tx also gives
		// both reads a consistent snapshot.
		if len(assignments) > 0 {
			if dErr := scimDirectoryDeactivatedTx(ctx, tx, orgID, email, &directoryDeactivated); dErr != nil {
				return fmt.Errorf("scim directory active-state check failed: %w", dErr)
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("identity: role directory lookup failed: %w", err)
	}
	if directoryDeactivated {
		return "", nil // directory says inactive → least-privilege at the consumer
	}

	names := make(map[string]bool, len(assignments))
	adminSignal := false
	for _, a := range assignments {
		names[a.name] = true
		if a.wildcard || a.name == "admin" {
			adminSignal = true
		}
	}
	// owner outranks admin (#2993): a role named "owner" resolves to owner even
	// though its seeded bundle carries "*", so owner can be a true superset of
	// admin without collapsing into it. Checked BEFORE the wildcard→admin rule.
	if names["owner"] {
		return "owner", nil
	}
	if adminSignal {
		return "admin", nil
	}
	for _, candidate := range rolePrecedence {
		if names[candidate] {
			return candidate, nil
		}
	}
	return "", nil // unmapped → least-privilege at the consumer
}

// scimDirectoryDeactivatedTx reports (into *deactivated) whether a SCIM
// directory row exists for this identity in the org's addressing tenant AND is
// marked inactive (#3030). Runs on the caller's already-org-scoped transaction
// (see the m4 note at the call site).
//
// Existence-guarded so the resolver still works where the SCIM provisioning
// schema (enterprise mig 117) was never applied — community builds and the
// minimal unit-test schemas have no scim_users table, and there is nothing to
// deactivate there. The table-presence probe and the EXISTS check are two
// statements precisely because a single statement referencing scim_users would
// fail at parse/analyze time (before any runtime short-circuit) when the table
// is absent. The unqualified to_regclass('scim_users') resolves via the
// connection's search_path — deliberately matching how the unqualified
// `FROM scim_users` in the EXISTS below (and every other query in this file)
// resolves, so the probe and the read can never disagree about which table
// they mean. The platform pins its schema via the connection's search_path
// (public on a stock install); a caller-supplied exotic search_path would
// redirect both statements together.
//
// scim_users is tenant-keyed (mig 117). In the single-tenant self-hosted
// posture tenant == org, so the org id is the addressing tenant; where
// tenant != org this simply finds no row (the defense is inert there, never
// over-restrictive — the service-side revoke remains the primary control).
func scimDirectoryDeactivatedTx(ctx context.Context, tx *sql.Tx, orgID, email string, deactivated *bool) error {
	var hasTable bool
	if e := tx.QueryRowContext(ctx, `SELECT to_regclass('scim_users') IS NOT NULL`).Scan(&hasTable); e != nil {
		return e
	}
	if !hasTable {
		return nil // no SCIM directory → nothing to deactivate
	}
	return tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM scim_users
			WHERE tenant_id = $1
			  AND lower(btrim(email)) = $2
			  AND active = false
		)`, orgID, email).Scan(deactivated)
}
