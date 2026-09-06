// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package rls

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AssertBypassesRowSecurity refuses a pool whose connected role is subject to
// row-level security.
//
// # What it is for
//
// A cross-organization worker - a reaper, a sweep - runs ONE unqualified
// statement with no org predicate and no GUC set. Under FORCE ROW LEVEL
// SECURITY that statement's isolation predicate is
// `org_id = current_setting('app.current_org_id', true)`, which is NULL for
// every row when the GUC is unset, so a pool that does NOT bypass row security
// matches ZERO ROWS and the worker returns (0, nil).
//
// That is indistinguishable from "there was nothing to do". No error, no log,
// no metric: a misrouted DSN produces a reaper that reports success forever
// while releasing nothing, and for the reservation store that means an
// organization's budget stays pinned at its high-water mark and every
// subsequent admission is denied for capacity nobody is using.
//
// So the check belongs at CONSTRUCTION, where it is a boot failure with a named
// cause, rather than at the statement, where the only available signal is a
// zero that also means success. It is the same argument
// RequirePlatformAdminOrFatal already makes for the dynamic policy engine.
//
// # Why it asks about the PRIVILEGE, not the role name
//
// `SELECT current_user` answers "is this the role I expected to be", which is a
// different question and a weaker one: a deployment may legitimately name its
// admin role something else, and a role called `axonflow_platform_admin` that
// has lost BYPASSRLS passes a name check while failing at exactly the thing the
// name was standing in for. The privilege is what the statement depends on, so
// the privilege is what is asserted.
//
// BOTH ATTRIBUTES ARE READ. `rolbypassrls` alone is not the question:
// `ALTER ROLE x SUPERUSER` leaves `rolbypassrls` false while still bypassing
// every policy, so a `rolbypassrls`-only check reports a superuser as blind.
// runtime-e2e/3133_masfeat_app_role_rls records the same pair for the same
// reason.
//
// # Why it lives here
//
// This is the leaf package that exists so a store anywhere in the import graph
// can reach an RLS helper without importing the rest of platform/agent - and
// importing platform/agent from a store is not merely heavy, it is a CYCLE the
// moment run.go wires the store up.
func AssertBypassesRowSecurity(ctx context.Context, db *sql.DB, who string) error {
	if db == nil {
		return fmt.Errorf("%s: no pool was supplied, so nothing can be asserted about the role it connects as", who)
	}
	// Bounded, because this runs at boot and a hung probe would hang the
	// process rather than fail it. Two seconds matches assertConnectedRole.
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var role string
	var bypass, super bool
	err := db.QueryRowContext(checkCtx,
		`SELECT current_user, rolbypassrls, rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user`,
	).Scan(&role, &bypass, &super)
	if err != nil {
		// NOT tolerated. A probe that cannot answer leaves the caller with the
		// same unknown it was built to resolve, and the failure direction that
		// matters here is the silent one.
		return fmt.Errorf("%s: could not read the connected role's row-security attributes: %w", who, err)
	}
	if bypass || super {
		return nil
	}
	return fmt.Errorf(
		"%s: the connected role %q is subject to row-level security (rolbypassrls=false, rolsuper=false). "+
			"A cross-organization statement runs with no org predicate and no app.current_org_id set, so under "+
			"FORCE ROW LEVEL SECURITY its isolation predicate is NULL for every row and it would match NOTHING - "+
			"returning success having done nothing, which no caller can tell from an idle run. "+
			"Point this pool at the admin role (AXONFLOW_DB_PLATFORM_ADMIN_URL), or grant it BYPASSRLS",
		who, role)
}
