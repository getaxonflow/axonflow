// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProviderRequest is the scope + window a provider is asked to report on.
//
// It carries BOTH tenancy keys because the regulatory modules disagree about
// which one they scope on: euaiact / rbi / masfeat take an orgID, sebi / ojk
// take a tenantID. Under a single enterprise license those are different values
// (#3071), so guessing one from the other is exactly the class tenantscope.go
// documents. Each adapter passes the key its own module actually keys on, and
// says so in a comment at the call site.
//
// # WHAT THIS MEANS FOR THE CONTENT OF A REPORT (M2, #3241 round 2)
//
// The split is not cosmetic - it changes what a report CONTAINS, and it is
// stated here because nothing about the API surface reveals it:
//
//	euaiact, rbi, masfeat   ->  ORGANIZATION-WIDE. On an org with several
//	                            tenancies, a report requested while acting as
//	                            tenancy A includes rows belonging to tenancies
//	                            B and C.
//	sebi, ojk               ->  TENANCY-SCOPED. The same request returns only
//	                            the requesting tenancy's rows.
//
// This is NOT a defect introduced here and it is deliberately not "fixed" here.
// It is the scoping each module has always applied on its own endpoints; the
// facade reads those modules read-only and cannot narrow euaiact/rbi/masfeat
// without either re-implementing their queries or filtering their results
// post-fetch - and post-fetch authorization filtering is the #1623 class this
// codebase has been burned by before. Unifying it means changing the modules,
// which is a change to five live endpoint families and belongs in its own
// piece of work.
//
// Two things follow that a caller should know:
//
//  1. On a SINGLE-tenancy organization - which is every deployment except a
//     multi-tenancy enterprise licence - org-wide and tenancy-scoped are the
//     same set of rows, and the distinction is invisible.
//  2. Generating a report is gated on ADMIN AUTHORITY over the tenant
//     (read_scope.go, enforceTenantWideAuditExport), so the caller who can
//     obtain an org-wide euaiact report is an administrator, not an arbitrary
//     viewer.
//
// The one place this leaks below the admin gate is RecordCount: the STATUS
// POLL is deliberately reachable by a non-admin (the D4 viewing half), and it
// returns record_count. So on a multi-tenancy org a viewer in tenancy A can
// learn the SIZE of the org-wide euaiact/rbi/masfeat result set - a single
// integer, no rows, no identifiers. Recorded rather than closed: removing it
// would leave a viewer unable to tell a finished empty report from a finished
// populated one, which is the poll's whole job.
type ProviderRequest struct {
	OrgID       string
	TenantID    string
	Framework   Framework
	PeriodStart time.Time
	PeriodEnd   time.Time
}

// ProviderResult is what a provider returns for one report.
type ProviderResult struct {
	// State is the authoritative three-state answer for this org + period.
	State ReportState
	// Sections are rendered in slice order.
	Sections []Section
	// RecordCount is the number of underlying data rows the report represents.
	RecordCount int
}

// DataProvider adapts one regulatory module to the report facade. Providers are
// READ-ONLY: they call existing module services and never write.
type DataProvider interface {
	// Regulator identifies which regulator this provider serves.
	Regulator() Regulator

	// Available reports whether the regulator's module is wired in this
	// deployment. It is called BEFORE a job is persisted, so an unwired module
	// produces an honest immediate refusal instead of a job that can never
	// succeed.
	//
	// It answers the DEPLOYMENT question only, never the data question.
	// Deciding empty-vs-populated up front would mean running the report's
	// queries twice - and for the modules whose only cheap count is all-time
	// rather than period-scoped, it would mean guessing. The data state is
	// determined once, by Fetch, and is what the terminal job carries.
	Available(ctx context.Context, req ProviderRequest) (bool, error)

	// Fetch builds the full report. Its State is authoritative and may differ
	// from Probe's (rows can be written or a module can fall over in between).
	Fetch(ctx context.Context, req ProviderRequest) (*ProviderResult, error)
}

// Registry maps regulators to providers.
//
// A regulator with NO registered provider is ReportStateNotAvailable, which is
// how a community build and a deployment whose module failed to initialize both
// answer without a special case.
type Registry struct {
	providers map[Regulator]DataProvider
}

// NewRegistry builds a registry from the given providers. A nil provider, or one
// whose Regulator() is unknown, is skipped — wiring code passes whatever
// modules initialized, and a half-initialized deployment must degrade to
// "not_available" for that regulator rather than panicking at request time.
func NewRegistry(providers ...DataProvider) *Registry {
	reg := &Registry{providers: make(map[Regulator]DataProvider, len(providers))}
	for _, p := range providers {
		if p == nil {
			continue
		}
		r := p.Regulator()
		if !r.Valid() {
			continue
		}
		reg.providers[r] = p
	}
	return reg
}

// Get returns the provider for a regulator, or nil.
func (reg *Registry) Get(r Regulator) DataProvider {
	if reg == nil {
		return nil
	}
	return reg.providers[r]
}

// Available reports the regulators that have a provider, in canonical order.
func (reg *Registry) Available() []Regulator {
	out := make([]Regulator, 0, len(AllRegulators()))
	for _, r := range AllRegulators() {
		if reg.Get(r) != nil {
			out = append(out, r)
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Shared helpers for the per-module adapters
// -----------------------------------------------------------------------------

// maxSectionRows caps any one section. A five-year OJK window over a busy
// tenant's audit_logs is millions of rows; a PDF nobody can open is not a
// compliance artifact. The cap is stated ON the section (see truncationNote) so
// the reader is never silently shown a subset — a silent cap reads as
// "this is everything", which is the one thing a regulatory artifact must not
// claim falsely.
const maxSectionRows = 5000

// capRows truncates rows to maxSectionRows and returns the rows plus the note
// to append (empty when nothing was dropped).
func capRows(rows [][]string) ([][]string, string) {
	if len(rows) <= maxSectionRows {
		return rows, ""
	}
	dropped := len(rows) - maxSectionRows
	return rows[:maxSectionRows], fmt.Sprintf(
		"TRUNCATED: showing the first %d of %d rows (%d not shown). Narrow the reporting period, or use the JSON format with a shorter window, to obtain the full set.",
		maxSectionRows, len(rows), dropped)
}

// finishSection applies the row cap and the empty-state note in one place, so
// every provider gets identical semantics.
//
// A section is ALWAYS emitted even when it has no rows: dropping it would make
// "we have no HITL oversight records" indistinguishable from "this report does
// not cover HITL oversight", which on a regulatory artifact is a different
// claim entirely.
func finishSection(s Section, emptyReason string) Section {
	if len(s.Rows) == 0 {
		s.Rows = nil
		s.Notes = append(s.Notes, emptyReason)
		return s
	}
	rows, note := capRows(s.Rows)
	s.Rows = rows
	if note != "" {
		s.Notes = append(s.Notes, note)
	}
	return s
}

// stabilizeTiesByID makes a section's row order TOTAL without changing it.
//
// # What this is not
//
// An earlier revision sorted these sections outright, on the stated premise
// that "the regulator modules' list APIs issue SQL with no ORDER BY". That
// premise was wrong for every section it touched - rbi/boardreport_repository.go
// orders by generated_at DESC, rbi/incident_repository.go by detected_at DESC,
// masfeat/assessment_repository.go by created_at DESC, and so on - so the sort
// replaced a deliberate newest-first order with an opaque id order. Reverted.
//
// # What remains
//
// Several of those ORDER BY clauses are not TOTAL: `ORDER BY created_at DESC`
// with no unique tie-break lets two rows written in the same instant come back
// in either order, run to run. That is the same checksum instability, just
// narrower: two runs of one report emit the tied rows in a different order and
// produce different SHA-256s, and the auditor comparing two copies concludes
// the artifact was altered.
//
// This helper reproduces the module's own ordering and breaks only the ties:
// rows are compared on keyCol in the SQL's direction, and rows that compare
// equal there fall back to idCol. Rows the database already ordered keep their
// order exactly.
//
// It is applied ONLY where the module's ORDER BY is genuinely non-total; each
// call site cites the exact query it mirrors. Where the query already ends in a
// unique column (euaiact's `... ASC, id ASC`) nothing is done, because there is
// nothing to break.
func stabilizeTiesByID(rows [][]string, keyCol, idCol int, descending bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := cell(rows[i], keyCol), cell(rows[j], keyCol)
		if a != b {
			if descending {
				return a > b
			}
			return a < b
		}
		return cell(rows[i], idCol) < cell(rows[j], idCol)
	})
}

// cell reads a column defensively: a provider that emits a short row must not
// panic the sort.
func cell(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return row[i]
}

// stateFromCount is the single place the populated/empty distinction is made,
// so no provider can accidentally report "populated" for a zero-row report.
func stateFromCount(n int) ReportState {
	if n > 0 {
		return ReportStatePopulated
	}
	return ReportStateEnabledEmpty
}

// fmtTime renders a timestamp in the one format every artifact uses. UTC so a
// report generated on two hosts in different zones reads identically.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// fmtTimePtr renders an optional timestamp, empty when absent.
func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtTime(*t)
}

// fmtDate renders a date-only value.
func fmtDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}

// fmtDatePtr renders an optional date-only value.
func fmtDatePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtDate(*t)
}

func fmtInt(n int) string     { return strconv.Itoa(n) }
func fmtInt64(n int64) string { return strconv.FormatInt(n, 10) }
func fmtBool(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// fmtFloat renders a float with fixed precision. Fixed, not %v: %v's shortest
// representation makes 0.1 and 0.10 render differently depending on how the
// value was computed, which is a determinism hazard in a golden file.
func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }

// fmtFloatPtr renders an optional float.
func fmtFloatPtr(f *float64) string {
	if f == nil {
		return ""
	}
	return fmtFloat(*f)
}

// fmtStrings joins a string slice for a single cell.
func fmtStrings(ss []string) string { return strings.Join(ss, "; ") }

// withinPeriod reports whether t falls inside [start, end]. Providers use it to
// filter module APIs that have no date-range parameter of their own; doing it
// here rather than per-provider keeps the boundary semantics (inclusive on both
// ends) identical across regulators.
func withinPeriod(t time.Time, start, end time.Time) bool {
	if t.IsZero() {
		return false
	}
	return !t.Before(start) && !t.After(end)
}
