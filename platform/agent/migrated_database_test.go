// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// THE MIGRATED DATABASE A HANDLER TEST RUNS AGAINST.
//
// Every agent process has a shared policy engine loaded with every enabled
// shipped row of the 'global' scope - the system rows, and the organization
// template's tenant-tier rows the core migrations seed there: a migrated
// database carries them and cannot lose them
// (#3048 item 10 fails a load that returns none), and boot refuses the
// narrowing that would skip them (PRD v11 §1.7). The anchored engine reads those
// detectors' facts, so an engine without the shipped rows hands it every
// detector ABSENT - a process that cannot exist.
//
// The rows are derived from the census. Each carries a pattern that never
// matches, so content a test sends matches none of them unless the test plants
// a row of its own: the equivalent of a request that trips no shipped control.
// A row the corpus SPLIT by scope stores the action decide is bound to as its
// request-phase action and the action the MCP response pass is bound to as its
// response-phase action, as production stores it (the real-Postgres oracle in
// TestSystemPolicyCount_MigrationsAreSingleSourceOfTruth holds that equality).

// shippedGlobalRow is one enabled row of the 'global' scope as the loader reads
// it: a shipped system control, or one of the organization template's
// tenant-tier rows.
type shippedGlobalRow struct {
	tier, policyID, category, severity, requestAction string
	// responseAction is the stored response-phase action, empty for a row the
	// corpus did not split, which stores none.
	responseAction string
}

// shippedGlobalRows is every row a migrated database carries in the 'global'
// scope: each enabled system row the census carries, and the tenant-tier rows
// whose detectors the organization template reads, which the core migrations
// seed there too - while no document is active the implicit bundle decides on
// them.
func shippedGlobalRows() ([]shippedGlobalRow, error) {
	census, err := registry.ShippedCensus()
	if err != nil {
		return nil, err
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	templatePaths := map[string]bool{}
	for _, p := range template.Policies {
		for _, path := range p.ReferencedPaths() {
			templatePaths[path] = true
		}
	}
	requestActions, err := phaseActions(decideSeamScope)
	if err != nil {
		return nil, err
	}
	responseActions, err := phaseActions(mcpResponseSeamScope)
	if err != nil {
		return nil, err
	}
	var out []shippedGlobalRow
	templateRows := 0
	for _, r := range census {
		template := r.Tier != "system" && templatePaths[registry.DetectorID(r.PolicyID).SignalPath()]
		if (r.Tier != "system" && !template) || !r.Enabled {
			continue
		}
		if template {
			templateRows++
		}
		action := r.LegacyAction
		if requested, split := requestActions[r.PolicyID]; split {
			action = requested
		}
		if action == "" {
			action = "warn"
		}
		severity := r.Severity
		if severity == "" {
			severity = "medium"
		}
		out = append(out, shippedGlobalRow{
			tier: r.Tier, policyID: r.PolicyID, category: r.Category, severity: severity,
			requestAction: action, responseAction: responseActions[r.PolicyID],
		})
	}
	if len(out) == 0 {
		return nil, errors.New("the census carries no enabled system row")
	}
	// One row per template CONTROL: a template redaction ships as two policies
	// bound by discharge (#4131), both reading the row's one detector.
	controls := map[string]bool{}
	for _, p := range template.Policies {
		control, _, _ := legacycompile.CorpusControlOf(p.ID)
		controls[control] = true
	}
	if templateRows != len(controls) {
		return nil, fmt.Errorf("the census carries %d enabled rows the organization template reads, and the template has %d controls; "+
			"a template control reading an unserved detector would be UNKNOWN on every request", templateRows, len(controls))
	}
	return out, nil
}

// values is the row in LoaderCols order: never matching unless pattern is set,
// and storing responseAction when it is not empty.
func (r shippedGlobalRow) values(n int, pattern, responseAction string) []driver.Value {
	if pattern == "" {
		pattern = "ZZ_NEVER_MATCHES_" + r.policyID
	}
	var stored interface{}
	if responseAction != "" {
		stored = responseAction
	}
	return policytest.GlobalPolicyValues(r.tier, fmt.Sprintf("00000000-0000-0000-0000-%012d", n), r.policyID, r.category, pattern, r.severity, "both", r.requestAction, stored, 100)
}

// scopeControls pairs every policy the scope's restriction keeps with the census
// row of the detector it reads, in the restriction's order. A policy reading no
// censused detector is left out.
func scopeControls(scope legacycompile.EnforcementScope) ([]enfScopeControl, error) {
	doc, _, err := activation.RestrictToScope(scope)
	if err != nil {
		return nil, err
	}
	return controlsOver(doc)
}

// templateControls is scopeControls over the organization template the scope
// binds (activation.OrganizationTemplateForScope): the controls the implicit
// bundle adds while an organization has published nothing.
func templateControls(scope legacycompile.EnforcementScope) ([]enfScopeControl, error) {
	doc, err := activation.OrganizationTemplateForScope(scope)
	if err != nil {
		return nil, err
	}
	return controlsOver(doc)
}

// controlsOver pairs each policy of doc with the census row of the detector it
// reads, in the document's order.
func controlsOver(doc *pdp.Document) ([]enfScopeControl, error) {
	rows, err := registry.ShippedCensus()
	if err != nil {
		return nil, err
	}
	byPath := map[string]registry.CensusRow{}
	for _, r := range rows {
		byPath[registry.DetectorID(r.PolicyID).SignalPath()] = r
	}
	var out []enfScopeControl
	for _, p := range doc.Policies {
		for _, path := range p.ReferencedPaths() {
			if r, ok := byPath[path]; ok {
				out = append(out, enfScopeControl{policy: p, row: r})
				break
			}
		}
	}
	return out, nil
}

// phaseActions reads, from the restriction of a scope that evaluates one phase,
// the action each row the corpus SPLIT by scope is bound to there. A row is split
// because its planes enforce different actions, which production stores in the
// row's own phase columns; the restriction is the committed record of the one
// each scope enforces. A row the corpus did not split is absent.
func phaseActions(scope legacycompile.EnforcementScope) (map[string]string, error) {
	controls, err := scopeControls(scope)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, c := range controls {
		if _, action, _ := legacycompile.CorpusControlOf(c.policy.ID); action != "" {
			out[c.row.PolicyID] = action
		}
	}
	return out, nil
}

// appendShippedGlobalRows appends every shipped global row to a fixture's
// loader rows: never matching, except a row named in probes, which matches its
// probe; storing the phase actions the corpus binds, except where
// responseActions names a row's response-phase action. A fixture that plants
// rows of its own passes nil for both.
func appendShippedGlobalRows(t *testing.T, rows *sqlmock.Rows, probes, responseActions map[string]string) *sqlmock.Rows {
	t.Helper()
	shipped, err := shippedGlobalRows()
	if err != nil {
		t.Fatal(err)
	}
	for n, r := range shipped {
		responseAction := r.responseAction
		if override, ok := responseActions[r.policyID]; ok {
			responseAction = override
		}
		rows = rows.AddRow(r.values(n+1, probes[r.policyID], responseAction)...)
	}
	return rows
}

// migratedDatabaseDriver names the driver the package default engine reads.
const migratedDatabaseDriver = "agent-test-migrated-database"

// migratedDatabase is a database/sql driver serving the two reads the shared
// engine's evaluation path issues against a deployment in which no organization
// has authored a static policy: the 'global' scope holds the shipped global
// rows, and every organization scope holds none. Any other statement is refused
// by name, so a path this double does not model fails loudly rather than
// reading an empty table.
type migratedDatabase struct{ rows [][]driver.Value }

func newMigratedDatabase() (*migratedDatabase, error) {
	shipped, err := shippedGlobalRows()
	if err != nil {
		return nil, err
	}
	db := &migratedDatabase{}
	for n, r := range shipped {
		db.rows = append(db.rows, r.values(n+1, "", r.responseAction))
	}
	return db, nil
}

func (d *migratedDatabase) Open(string) (driver.Conn, error) { return migratedConn{db: d}, nil }

type migratedConn struct{ db *migratedDatabase }

func (c migratedConn) Prepare(query string) (driver.Stmt, error) {
	return nil, fmt.Errorf("the test's migrated database prepares no statement: %q", query)
}

func (migratedConn) Close() error { return nil }

func (migratedConn) Begin() (driver.Tx, error) { return migratedTx{}, nil }

func (migratedConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return migratedTx{}, nil
}

// ExecContext accepts the org-scope setting every RLS transaction opens with.
func (migratedConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "set_config('app.current_org_id'") {
		return driver.RowsAffected(0), nil
	}
	return nil, fmt.Errorf("the test's migrated database executes no %q", query)
}

// QueryContext answers the loader's scoped read and its system-tier read.
func (c migratedConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "FROM static_policies") {
		return nil, fmt.Errorf("the test's migrated database answers only the loader's static_policies reads, not %q", query)
	}
	switch {
	case strings.Contains(query, "tier = 'system'"):
		return &migratedRows{rows: c.db.rows}, nil
	case strings.Contains(query, "org_id = $1") && len(args) == 1:
		if scope, _ := args[0].Value.(string); scope == "global" {
			return &migratedRows{rows: c.db.rows}, nil
		}
		return &migratedRows{}, nil
	}
	return nil, fmt.Errorf("the test's migrated database does not model the static_policies read %q", query)
}

type migratedTx struct{}

func (migratedTx) Commit() error   { return nil }
func (migratedTx) Rollback() error { return nil }

type migratedRows struct {
	rows [][]driver.Value
	next int
}

func (*migratedRows) Columns() []string { return policytest.LoaderCols() }
func (*migratedRows) Close() error      { return nil }

func (r *migratedRows) Next(dest []driver.Value) error {
	if r.next >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.next])
	r.next++
	return nil
}

// installDefaultTestEngine installs the package default shared engine over the
// migrated database.
func installDefaultTestEngine() error {
	db, err := newMigratedDatabase()
	if err != nil {
		return err
	}
	sql.Register(migratedDatabaseDriver, db)
	conn, err := sql.Open(migratedDatabaseDriver, "")
	if err != nil {
		return err
	}
	sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(conn, sharedpolicy.EngineConfig{CacheTTL: time.Hour}, nil))
	return nil
}
