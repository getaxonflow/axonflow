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
		return rows.Err()
	})
	if err != nil {
		return "", fmt.Errorf("identity: role directory lookup failed: %w", err)
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
