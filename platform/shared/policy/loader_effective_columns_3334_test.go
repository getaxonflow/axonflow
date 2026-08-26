// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #3334. ScanEffectivePolicyRows reads static_policies POSITIONALLY: the Nth
// scan target takes whatever the Nth column of effectivePolicyColumns is. The
// two halves are separate declarations with nothing tying them together, so
// editing one and not the other is silent - and both readers of this query
// swallow the resulting scan error (this one logs and `continue`s,
// StaticPolicyRepository's list path `continue`s without even logging), which
// turns the mismatch into "zero policies" rather than an error.
//
// That is how #3334 shipped a break: retiring the legacy organization_id
// column from the SELECT left a fixture still naming it at index 11, so the
// scan read a NULL organization_id into TenantID (a value-typed string) and
// every row was dropped with
//
//	sql: Scan error on column index 11, name "organization_id":
//	converting NULL to string is unsupported
//
// These tests pin the SELECT-to-scan correspondence by NAME, not by count. A
// count check cannot see a swap, and a swap between two same-typed columns is
// the variant that reaches production silently.

// effectiveColumnProbe is one column of effectivePolicyColumns paired with a
// value that names it and the EffectivePolicyRow field that value must reach.
// Every value is distinguishable, so a scan list reading the columns in the
// wrong order lands a recognisably wrong value rather than a plausible one.
type effectiveColumnProbe struct {
	column string
	value  driver.Value
	got    func(EffectivePolicyRow) interface{}
}

var effectiveProbeTime = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func effectiveColumnProbes() []effectiveColumnProbe {
	return []effectiveColumnProbe{
		{"id", "val-id", func(r EffectivePolicyRow) interface{} { return r.ID }},
		{"policy_id", "val-policy_id", func(r EffectivePolicyRow) interface{} { return r.PolicyID }},
		{"name", "val-name", func(r EffectivePolicyRow) interface{} { return r.Name }},
		{"category", "val-category", func(r EffectivePolicyRow) interface{} { return r.Category }},
		{"pattern", "val-pattern", func(r EffectivePolicyRow) interface{} { return r.Pattern }},
		{"severity", "val-severity", func(r EffectivePolicyRow) interface{} { return r.Severity }},
		{"description", "val-description", func(r EffectivePolicyRow) interface{} { return r.Description.String }},
		{"action", "val-action", func(r EffectivePolicyRow) interface{} { return r.Action }},
		{"tier", "val-tier", func(r EffectivePolicyRow) interface{} { return r.Tier }},
		{"priority", int64(4242), func(r EffectivePolicyRow) interface{} { return int64(r.Priority) }},
		{"enabled", true, func(r EffectivePolicyRow) interface{} { return r.Enabled }},
		{"tenant_id", "val-tenant_id", func(r EffectivePolicyRow) interface{} { return r.TenantID }},
		{"org_id", "val-org_id", func(r EffectivePolicyRow) interface{} { return r.OrgID.String }},
		{"segment_id", "val-segment_id", func(r EffectivePolicyRow) interface{} { return r.SegmentID.String }},
		{"tags", "val-tags", func(r EffectivePolicyRow) interface{} { return r.Tags.String }},
		{"metadata", "val-metadata", func(r EffectivePolicyRow) interface{} { return r.Metadata.String }},
		{"version", int64(77), func(r EffectivePolicyRow) interface{} { return int64(r.Version) }},
		{"created_at", effectiveProbeTime, func(r EffectivePolicyRow) interface{} { return r.CreatedAt }},
		{"updated_at", effectiveProbeTime.Add(time.Hour), func(r EffectivePolicyRow) interface{} { return r.UpdatedAt }},
		{"created_by", "val-created_by", func(r EffectivePolicyRow) interface{} { return r.CreatedBy.String }},
		{"updated_by", "val-updated_by", func(r EffectivePolicyRow) interface{} { return r.UpdatedBy.String }},
	}
}

func probeColumns(p []effectiveColumnProbe) []string {
	out := make([]string, len(p))
	for i := range p {
		out[i] = p[i].column
	}
	return out
}

// newEffectiveRows builds a sqlmock result whose columns are the probe table's,
// with `override` replacing individual values by column name.
func newEffectiveRows(probes []effectiveColumnProbe, override map[string]driver.Value) *sqlmock.Rows {
	cols := probeColumns(probes)
	vals := make([]driver.Value, len(probes))
	for i, p := range probes {
		vals[i] = p.value
		if v, ok := override[p.column]; ok {
			vals[i] = v
		}
	}
	return sqlmock.NewRows(cols).AddRow(vals...)
}

// TestEffectivePolicyColumnsMatchTheProbeTable is the guard on the guard. The
// probe table is a hand-written mirror of effectivePolicyColumns; if the SELECT
// gains, loses or reorders a column and the table is not updated, every
// positional assertion below would be checking the wrong thing. This fails
// first and says so.
func TestEffectivePolicyColumnsMatchTheProbeTable(t *testing.T) {
	want := EffectivePolicyColumnNames()
	probes := effectiveColumnProbes()

	if len(want) == 0 {
		t.Fatal("EffectivePolicyColumnNames() is empty - it no longer parses effectivePolicyColumns, " +
			"so every assertion in this file is vacuous")
	}
	if len(probes) != len(want) {
		t.Fatalf("probe table has %d columns, effectivePolicyColumns has %d\n probes: %v\n select: %v",
			len(probes), len(want), probeColumns(probes), want)
	}
	for i := range want {
		if probes[i].column != want[i] {
			t.Errorf("column %d: probe table says %q, effectivePolicyColumns says %q - update the "+
				"probe table, and check ScanEffectivePolicyRows' scan list moved with it",
				i, probes[i].column, want[i])
		}
	}
}

// TestScanEffectivePolicyRowsIsPositionallyAligned drives ScanEffectivePolicyRows
// over a row whose every column carries a value naming that column, and asserts
// each value arrived in the field belonging to it. This is the assertion that
// fails on a reorder.
func TestScanEffectivePolicyRowsIsPositionallyAligned(t *testing.T) {
	probes := effectiveColumnProbes()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT.*FROM static_policies`).
		WillReturnRows(newEffectiveRows(probes, nil))
	mock.ExpectCommit()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rows, err := ScanEffectivePolicyRows(context.Background(), tx, "sp.tier = 'system'")
	if err != nil {
		t.Fatalf("ScanEffectivePolicyRows: %v", err)
	}
	_ = tx.Commit()

	// Positive control. A misalignment presents as an EMPTY slice, not an
	// error, because the scan error is logged and the row skipped - and a
	// per-column loop over an empty slice passes. This is what says so.
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 - ScanEffectivePolicyRows dropped the row, which is exactly "+
			"what a column-list/scan-list misalignment looks like. Every per-column assertion "+
			"below would be vacuous.", len(rows))
	}

	for i, p := range probes {
		got, want := p.got(rows[0]), interface{}(p.value)
		if !equalProbe(got, want) {
			t.Errorf("column %d (%s): scanned %#v, want %#v - the SELECT column list and "+
				"ScanEffectivePolicyRows' scan list disagree at this position",
				i, p.column, got, want)
		}
	}
}

// TestScanEffectivePolicyRowsDropsRowsSilentlyOnScanError pins the exact shape
// #3334 shipped: a NULL arriving at a value-typed field. TenantID is a bare
// string, so a NULL there cannot be scanned, the row is dropped, and the caller
// sees an empty result rather than an error.
//
// Asserting the silent drop is what makes the alignment test above meaningful:
// it proves the failure mode really is "zero rows", so that is the symptom
// worth guarding. If TenantID ever becomes nullable this test fails, which is
// the correct signal - the hazard has moved and the guard needs re-aiming.
func TestScanEffectivePolicyRowsDropsRowsSilentlyOnScanError(t *testing.T) {
	probes := effectiveColumnProbes()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT.*FROM static_policies`).
		WillReturnRows(newEffectiveRows(probes, map[string]driver.Value{"tenant_id": nil}))
	mock.ExpectCommit()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rows, err := ScanEffectivePolicyRows(context.Background(), tx, "sp.tier = 'system'")
	if err != nil {
		t.Fatalf("ScanEffectivePolicyRows returned an error (%v); the documented behaviour is to "+
			"log and continue, which is why this class of defect is silent", err)
	}
	_ = tx.Commit()

	if len(rows) != 0 {
		t.Fatalf("got %d rows, want 0 - a NULL in the value-typed TenantID field must fail to "+
			"scan; if it now succeeds the field's type changed and the silent-drop hazard this "+
			"file guards has moved", len(rows))
	}
}

func equalProbe(got, want interface{}) bool {
	gt, gok := got.(time.Time)
	wt, wok := want.(time.Time)
	if gok && wok {
		return gt.Equal(wt)
	}
	return got == want
}
