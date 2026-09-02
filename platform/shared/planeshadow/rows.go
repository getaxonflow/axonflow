// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/agent/rls"
	"axonflow/platform/decision/legacycompile"
)

// globalOrgScope is the org_id wildcard system-seeded policies carry
// (migration core/010's DEFAULT, backfilled onto org_id by core/153).
//
// It is duplicated from platform/shared/policy's globalTenantSentinel rather
// than imported because that constant is unexported and this package must not
// import the policy package - the policy package imports THIS one, and a cycle
// would be the result. The duplication is pinned by
// TestGlobalScopeMatchesTheLoader, which reads the loader's own source.
const globalOrgScope = "global"

// RowSource reads the raw legacy policy rows for one organization scope.
//
// It is an interface so the bundle cache can be exercised without a database,
// and so the SQL lives in exactly one place.
type RowSource interface {
	// RawRows returns every static_policies and dynamic_policies row visible
	// in orgScope, plus the 'global' scope's rows relabelled into orgScope.
	RawRows(ctx context.Context, orgScope string) ([]legacycompile.RawRow, error)
}

// dbRowSource reads both legacy policy tables under row-level security.
type dbRowSource struct{ db *sql.DB }

// NewDBRowSource builds the production row source.
func NewDBRowSource(db *sql.DB) (RowSource, error) {
	if db == nil {
		return nil, fmt.Errorf("planeshadow: nil db for the policy row source")
	}
	return &dbRowSource{db: db}, nil
}

// legacyTables are the two substrates, in a stable order.
var legacyTables = []string{"static_policies", "dynamic_policies"}

// RawRows performs the SAME two-pass read the runtime loader performs.
//
// # WHY TWO PASSES AND NOT ONE PREDICATE
//
// Both tables carry RLS keyed on org_id (migrations/core/018,
// `org_id = get_current_org_id()`), and a single GUC unlocks exactly one org's
// rows at a time. `WHERE org_id = $1 OR org_id = 'global'` therefore returns
// only the first half under the app role: the global baseline disappears while
// the read still looks successful. loadFromDatabase issues two disjoint scoped
// passes for exactly that reason (#3048, observed live: check-input with a
// DROP TABLE payload returned allowed with policies_evaluated=0), and a shadow
// that read once would compile a policy set the plane does not have and then
// report the difference as a migration finding.
//
// # WHY THE GLOBAL ROWS ARE RELABELLED
//
// legacycompile keys a row's identity on its OrgScope and builds one document
// set per org, because the runtime reads under strict-equality RLS and one
// org's policies never reach another's (ADR-065 invariant 1). But the runtime
// MERGES the two passes before evaluating, so the policy set that decided a
// request in org X is (X's rows + the global rows). Relabelling the global
// rows into X reproduces exactly that set, per org, without merging two orgs'
// rows into one document - which is the isolation failure the per-org
// compilation exists to prevent.
//
// A caller with no org scope degrades to the global baseline alone rather than
// issuing an unscoped read, which is what the loader does (rls.WithOrgScope
// rejects an empty scope).
func (s *dbRowSource) RawRows(ctx context.Context, orgScope string) ([]legacycompile.RawRow, error) {
	orgScope = strings.TrimSpace(orgScope)
	var out []legacycompile.RawRow

	scopes := []string{globalOrgScope}
	if orgScope != "" && orgScope != globalOrgScope {
		scopes = append([]string{orgScope}, scopes...)
	}
	// The label every row is compiled under: the requesting org when there is
	// one, and the global scope when the caller is unbound.
	label := orgScope
	if label == "" {
		label = globalOrgScope
	}

	seen := map[string]string{}
	for _, scope := range scopes {
		for _, table := range legacyTables {
			rows, err := s.readScope(ctx, table, scope, label)
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				// A physical row is visible in exactly ONE scoped pass under
				// strict-equality RLS, so the same (table, policy_id) arriving
				// twice means the two passes were not disjoint - RLS not
				// enforcing, or an org literally named "global". Compile
				// REFUSES a duplicate identifier late and without naming the
				// read as the cause, so it is named here instead.
				id := table + "|" + policyIDOf(r)
				if prev, dup := seen[id]; dup {
					return nil, fmt.Errorf(
						"planeshadow: row %s appeared in both the %q and %q scoped passes; the two passes must be disjoint under row-level security, so either RLS is not enforcing on %s or this organization is literally named %q",
						id, prev, scope, table, globalOrgScope)
				}
				seen[id] = scope
				out = append(out, r)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return policyIDOf(out[i]) < policyIDOf(out[j])
	})
	return out, nil
}

// readScope reads one table inside one org's RLS scope.
//
// row_to_json is what makes the capture lossless: every column arrives keyed
// by name, so a column a later migration adds reaches the compiler without
// anybody remembering to add it, and a NULL arrives as a JSON null rather than
// as a zero value indistinguishable from a stored one. It is the same shape
// scripts/legacy-policy-capture.sh produces, deliberately, so the offline and
// the runtime paths compile from identical inputs.
func (s *dbRowSource) readScope(ctx context.Context, table, scope, label string) ([]legacycompile.RawRow, error) {
	var out []legacycompile.RawRow
	err := rls.WithOrgScope(ctx, s.db, scope, func(tx *sql.Tx) error {
		// #nosec G202 -- table is one of the two constants in legacyTables and
		// never reaches here from a caller; there is no interpolation of any
		// value.
		q := "SELECT row_to_json(t) FROM " + table + " t WHERE t.org_id = $1"
		rows, err := tx.QueryContext(ctx, q, scope)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			cols := map[string]json.RawMessage{}
			if err := json.Unmarshal(raw, &cols); err != nil {
				return fmt.Errorf("decoding a %s row: %w", table, err)
			}
			out = append(out, legacycompile.RawRow{
				Table: table, OrgScope: label, Columns: cols,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("planeshadow: reading %s in org scope %q: %w", table, scope, err)
	}
	return out, nil
}

// policyIDOf reads a raw row's policy_id for duplicate detection and ordering.
// A row without one is ordered under the empty string and is reported by the
// compiler as the capture defect it is, rather than being dropped here.
func policyIDOf(r legacycompile.RawRow) string {
	raw, ok := r.Columns["policy_id"]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return strings.Trim(string(raw), `"`)
	}
	return s
}

// updatedAtOf renders a raw row's updated_at the same way the engines render
// theirs, so the two halves of a snapshot key can be compared at all.
//
// It returns the value VERBATIM from the JSON encoding rather than parsing and
// reformatting it: the engines stamp what the driver gave them, and a
// reformatting step on one side only is how two identical timestamps stop
// comparing equal. Normalization happens in exactly one place, normalizeStamp,
// which both sides call.
func updatedAtOf(r legacycompile.RawRow) string {
	raw, ok := r.Columns["updated_at"]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return normalizeStamp(strings.Trim(string(raw), `"`))
	}
	return normalizeStamp(s)
}

// normalizeStamp is the ONE rendering both sides of a snapshot key use.
//
// Postgres renders a timestamptz through row_to_json as RFC3339 with a numeric
// offset, while database/sql hands a Go caller a time.Time the engines format
// themselves. Two spellings of one instant must produce one key or every
// comparison is not-comparable forever - which is a green-looking gate over an
// empty denominator, the exact failure this package exists to prevent. So both
// sides funnel through here and the test asserts the two spellings agree.
func normalizeStamp(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range stampLayouts {
		if t, err := parseStamp(layout, s); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
		}
	}
	// An unparseable stamp is returned as-is rather than dropped: it still
	// distinguishes two versions of a row, and dropping it would make an
	// edited row compare equal to its previous version.
	return s
}
