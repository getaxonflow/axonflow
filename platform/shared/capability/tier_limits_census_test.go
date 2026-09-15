// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"strconv"
	"strings"
	"testing"
)

// matrixRowCell finds a row by its LABEL in any of the matrix's tables and
// returns its cells.
//
// The two reconciliations that already exist read the licensing table by tier
// row (`| **Community** |`) and the scale-boundaries table by resource row.
// The tables this census reads are keyed the same way - by the label in the
// first cell - but they are NOT the same tables, so this cannot reuse
// matrixLimitRow, which only matches `| **<tier>**`.
func matrixRowCell(src, label string) ([]string, bool) {
	for _, line := range strings.Split(src, "\n") {
		if !strings.HasPrefix(line, "| "+label+" |") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		return cells, true
	}
	return nil, false
}

// normaliseSuffixedLimit reads a cell whose number carries a unit suffix with
// no space, such as `5/tenant`.
//
// It is a SIBLING of normaliseLimit rather than a widening of it. That helper
// has two callers, both of which treat an unreadable cell as an error, and both
// of their tables are already green; widening a shared parser under two passing
// tests to admit a third table's spelling risks changing what THEY accept, and
// the failure would look like a docs edit rather than a parser change. This one
// is used only here.
func normaliseSuffixedLimit(cell string) (int, bool) {
	c := strings.ToLower(strings.TrimSpace(cell))
	if c == "unlimited" {
		return -1, true
	}
	digits := c
	if i := strings.IndexFunc(c, func(r rune) bool { return r < '0' || r > '9' }); i > 0 {
		digits = c[:i]
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
}

// publication is one place the matrix publishes a limit: a row label, and which
// cell index carries which tier. A tier absent from a table is -1.
type publication struct {
	label      string
	community  int
	evaluation int
	enterprise int
	// suffixed says the cells carry a unit suffix (`5/tenant`) that
	// normaliseLimit cannot read.
	suffixed bool
}

// reconciled maps a TierLimits field to every place the matrix publishes it.
//
// A field listed here is compared against the docs; a field in `unpublished`
// below is declared, with a reason, as not published as a per-tier limit. Every
// field of the struct must appear in exactly one of the two, which is what
// makes this a census rather than a spot check.
var reconciled = map[string][]publication{
	// Published TWICE, in two tables with different shapes, and neither
	// carries an Evaluation column - see unpublishedTiers below.
	"MaxSSEConnections": {
		// ### Community Numeric Limits: | Resource | Community Limit | Enterprise |
		{label: "SSE connections per tenant", community: 1, evaluation: -1, enterprise: 2},
		// ### Real-time Streaming (SSE): | Feature | Community | Enterprise | Notes |
		{label: "Concurrent SSE connections", community: 1, evaluation: -1, enterprise: 2, suffixed: true},
	},
}

// unpublishedTiers records, for a field that IS reconciled, the tiers whose
// value the matrix does not publish anywhere. Stating it is the point: the
// alternative is a census that silently compares two of three tiers and reports
// the field as covered.
var unpublishedTiers = map[string]string{
	"MaxSSEConnections": "Evaluation (25) is published nowhere. The Community Numeric Limits table has " +
		"only Resource/Community/Enterprise columns, the Real-time Streaming table only " +
		"Feature/Community/Enterprise/Notes, and no row carrying 25 mentions SSE, connections or " +
		"streaming. Adding a cell is a docs decision, not a test's to make",
}

// unpublished declares every TierLimits field the feature matrix does not
// publish as a per-tier limit, with the reason.
//
// A reason is required because "not in the docs" has two very different causes:
// a limit nobody wrote down, and a value that is not a published commercial
// boundary at all. The first is a docs gap; the second is correct.
//
// MEASURED, not assumed: two independent searches over the matrix agree. A
// keyword search finds no limit row for these; a value search - both tier
// values present in one row - finds only coincidences, where a row's OTHER
// columns happen to carry the same digits. A value appearing in a row is not a
// column meaning, so those were discarded.
var unpublished = map[string]string{
	"TenantPolicies":           "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"OrgPolicies":              "reconciled by the licensing and scale-boundaries tests",
	"CustomPolicyConnectors":   "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"AuditRetentionDays":       "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"MaxLLMProviders":          "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"MaxExecutionHistory":      "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"MaxConcurrentExec":        "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"MaxPlans":                 "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"MaxVersionsPerPlan":       "reconciled by TestTheMatrixLicensingTableAgreesWithTheExecutableLimits",
	"MaxHumanPrincipals":       "reconciled by TestTheMatrixScaleBoundariesAgreeWithTheExecutableLimits",
	"MaxServicePrincipals":     "reconciled by TestTheMatrixScaleBoundariesAgreeWithTheExecutableLimits",
	"MaxNodes":                 "reconciled by TestTheMatrixScaleBoundariesAgreeWithTheExecutableLimits",
	"MaxCostEstimatesPerDay":   "not published: the matrix has no cost-estimate limit row (zero matching lines for `cost estimate`)",
	"MaxPendingApprovals":      "not published as a NUMBER: the only approvals rows are capability rows (`Pending Approvals API` is ❌/Resolve-only/✅), which state reachability rather than a count",
	"MediaGovernanceEnabled":   "a boolean entitlement, not a scale limit; the matrix states media governance as a capability tick",
	"DailyEventQuota":          "-1 on every self-hosted tier: it is a SaaS Plugin tier quota and not a self-hosted boundary, so there is nothing to publish",
	"MaxActiveCustomPolicies":  "-1 on every self-hosted tier; the SaaS Plugin tier carries the real value",
	"MaxHITLApprovalsPerWeek":  "-1 on every self-hosted tier; the SaaS Plugin tier carries the real value",
	"DecisionListWindowHours":  "not published: the matrix has no decision-list row (zero matching lines for `decision list`)",
	"DecisionListMaxPage":      "not published: the matrix has no decision-list row. A value search appeared to hit, but the matching row was the licensing table, whose other columns carry the same digits",
	"HITLApprovalEnabled":      "a boolean entitlement; published as the WCP capability rows (❌ / Resolve-only / ✅) rather than as a number",
	"HITLExpiryHours":          "not published: zero matching lines for `expiry`",
	"PolicySimulationEnabled":  "a boolean entitlement; the matrix carries one prose mention of simulation and no limit row",
	"MaxSimulationsPerDay":     "not published: no simulation limit row",
	"MaxImpactReportInputs":    "not published: zero matching lines for `impact`",
	"EvidenceExportEnabled":    "a boolean entitlement; the evidence rows in the matrix are compliance-package capability rows",
	"MaxEvidenceExportRecords": "not published: no evidence-export limit row",
	"MaxEvidenceWindowDays":    "not published: no evidence-window row",
	"MaxEvidenceExportsPerDay": "not published: no evidence-exports-per-day row",
}

// TestEveryTierLimitIsReconciledOrDeclaredUnpublished is the census #3593 asks
// for: the limit values are single-sourced, and a field that is NOT published
// says so with a reason rather than being silently outside the guard.
//
// # THE POPULATION IS THE STRUCT, NOT THE LITERALS
//
// tierLimits() parses the three composite literals and returns 26 of the 30
// fields: intValue accepts only token.INT, so the four bool entitlements
// (MediaGovernanceEnabled, HITLApprovalEnabled, PolicySimulationEnabled,
// EvidenceExportEnabled) are absent from it. A census built on that map would
// classify 26 fields and look complete. tierLimitsStructFields() reads the
// struct declaration, so a field added to TierLimits is unclassified here and
// reds - which is the property that makes this a census.
//
// # WHAT IT DOES NOT RE-ASSERT
//
// The platform/ee copies of tier_limits.go are held identical apart from the
// build constraint by tests/regression-test-required/license_pair_byte_identity_test.sh,
// which keys on the marker "identical apart from its build constraint between"
// carried in both files. This does not add a sixth assertion of that property.
func TestEveryTierLimitIsReconciledOrDeclaredUnpublished(t *testing.T) {
	fields := tierLimitsStructFields(t)
	if len(fields) < 25 {
		t.Fatalf("TierLimits has %d fields; the population collapsed and this census would "+
			"assert about almost nothing", len(fields))
	}

	var classified, both int
	for _, f := range fields {
		_, isReconciled := reconciled[f]
		reason, isUnpublished := unpublished[f]
		switch {
		case isReconciled && isUnpublished:
			both++
			t.Errorf("%s is both reconciled and declared unpublished; one of the two entries is wrong", f)
		case !isReconciled && !isUnpublished:
			t.Errorf("TierLimits.%s is classified by neither table in this census. Add it to "+
				"`reconciled` with the matrix row that publishes it, or to `unpublished` with the "+
				"reason it is not a published per-tier limit. A field outside both is a limit no "+
				"guard is watching", f)
		default:
			classified++
			if isUnpublished && strings.TrimSpace(reason) == "" {
				t.Errorf("%s is declared unpublished with an empty reason", f)
			}
		}
	}
	if both > 0 {
		t.Fatalf("%d field(s) appear in both tables", both)
	}
	if classified != len(fields) {
		t.Fatalf("classified %d of %d fields", classified, len(fields))
	}

	// Every declared entry must name a REAL field, or the tables rot into
	// statements about names that no longer exist.
	known := map[string]bool{}
	for _, f := range fields {
		known[f] = true
	}
	for f := range reconciled {
		if !known[f] {
			t.Errorf("`reconciled` names %q, which is not a TierLimits field; the entry is stale", f)
		}
	}
	for f := range unpublished {
		if !known[f] {
			t.Errorf("`unpublished` names %q, which is not a TierLimits field; the entry is stale", f)
		}
	}
	for f := range unpublishedTiers {
		if _, ok := reconciled[f]; !ok {
			t.Errorf("unpublishedTiers names %q, which this census does not reconcile", f)
		}
	}
	// REPORT THE SPLIT, not just the totals. "29 declared unpublished" and "17
	// genuinely unpublished" are both true and count different things: twelve of
	// the twenty-nine are reconciled by the two tests that already exist, and
	// their entries say so. A single total invites a reader to reconcile two
	// true numbers by hand.
	var citedToExistingTests int
	for _, reason := range unpublished {
		if strings.HasPrefix(reason, "reconciled by") {
			citedToExistingTests++
		}
	}
	t.Logf("census: %d TierLimits fields = %d reconciled here + %d already reconciled by the "+
		"licensing/scale-boundaries tests + %d genuinely unpublished with a reason",
		len(fields), len(reconciled), citedToExistingTests, len(unpublished)-citedToExistingTests)
}

// TestTheReconciledLimitsAgreeWithEveryMatrixPublication compares each
// reconciled field against EVERY row that publishes it.
//
// Reconciling one publication and not the other leaves the second free to
// drift, which is the drift this work exists to stop: MaxSSEConnections is
// published in two tables, with different shapes and different spellings of the
// same number.
func TestTheReconciledLimitsAgreeWithEveryMatrixPublication(t *testing.T) {
	src := readMatrix(t)
	limits := tierLimits(t)

	var compared int
	for field, pubs := range reconciled {
		if len(pubs) == 0 {
			t.Errorf("%s is listed as reconciled but names no publication", field)
			continue
		}
		for _, p := range pubs {
			cells, ok := matrixRowCell(src, p.label)
			if !ok {
				t.Errorf("MATRIX ROW MISSING - %s: no row labelled %q. Either the row was removed, "+
					"in which case this field is no longer published and belongs in `unpublished` "+
					"with that reason, or it was renamed and this entry is stale", field, p.label)
				continue
			}
			for _, tier := range []struct {
				name string
				idx  int
				v    string
			}{
				{"Community", p.community, "CommunityLimits"},
				{"Evaluation", p.evaluation, "EvaluationLimits"},
				{"Enterprise", p.enterprise, "EnterpriseLimits"},
			} {
				if tier.idx < 0 {
					continue // this table has no column for that tier
				}
				if tier.idx >= len(cells) {
					t.Errorf("%s %s: row %q has %d cells, so column %d is missing",
						tier.name, field, p.label, len(cells), tier.idx)
					continue
				}
				want, ok := limits[tier.v][field]
				if !ok {
					t.Errorf("%s: %s declares no %s", tier.name, tierLimitsPath, field)
					continue
				}
				var got int
				var readable bool
				if p.suffixed {
					got, readable = normaliseSuffixedLimit(cells[tier.idx])
				} else {
					got, readable = normaliseLimit(cells[tier.idx])
				}
				if !readable {
					t.Errorf("%s %s: cannot read matrix cell %q in row %q",
						tier.name, field, cells[tier.idx], p.label)
					continue
				}
				compared++
				if got != want {
					t.Errorf("MATRIX/CODE DISAGREEMENT - %s %s: the matrix row %q says %q, %s says %d",
						tier.name, field, p.label, cells[tier.idx], tierLimitsPath, want)
				}
			}
		}
	}

	// ANTI-VACUITY FLOOR. MaxSSEConnections publishes two rows x two tiers with
	// a column (Evaluation is absent from both tables), so four comparisons are
	// the whole of what is reconcilable today. A floor beneath that still reds
	// if a publication silently stops being read.
	if compared < 4 {
		t.Fatalf("compared %d matrix cell(s) (floor 4); a publication stopped being read and this "+
			"test is asserting about almost nothing", compared)
	}
	t.Logf("reconciled %d cell(s) across %d field(s) and their publications", compared, len(reconciled))
}

// TestTheSiblingNormaliserReadsWhatTheSharedOneCannot pins why
// normaliseSuffixedLimit exists rather than a change to normaliseLimit, and
// pins that the shared helper still REJECTS what its two callers rely on it
// rejecting.
func TestTheSiblingNormaliserReadsWhatTheSharedOneCannot(t *testing.T) {
	if n, ok := normaliseLimit("5/tenant"); ok {
		t.Errorf("normaliseLimit now reads %q as %d; it did not before, and its two callers treat "+
			"an unreadable cell as an error. Widening it changes what THEY accept", "5/tenant", n)
	}
	if n, ok := normaliseSuffixedLimit("5/tenant"); !ok || n != 5 {
		t.Errorf("normaliseSuffixedLimit(%q) = %d, %v; want 5, true", "5/tenant", n, ok)
	}
	for cell, want := range map[string]int{"5": 5, "Unlimited": -1, "25/tenant": 25} {
		got, ok := normaliseSuffixedLimit(cell)
		if !ok || got != want {
			t.Errorf("normaliseSuffixedLimit(%q) = %d, %v; want %d, true", cell, got, ok, want)
		}
	}
	if _, ok := normaliseSuffixedLimit("n/a"); ok {
		t.Error("normaliseSuffixedLimit read a non-numeric cell; a cell it cannot read must be an error")
	}
}

// TestEveryUnpublishedTierIsRecordedForAReconciledField keeps the partial
// reconciliation honest: MaxSSEConnections is compared for two tiers and its
// third is published nowhere, and that gap is stated rather than inferred from
// a comparison count.
func TestEveryUnpublishedTierIsRecordedForAReconciledField(t *testing.T) {
	limits := tierLimits(t)
	for field, pubs := range reconciled {
		var covered [3]bool
		for _, p := range pubs {
			for i, idx := range []int{p.community, p.evaluation, p.enterprise} {
				if idx >= 0 {
					covered[i] = true
				}
			}
		}
		for i, tier := range []string{"CommunityLimits", "EvaluationLimits", "EnterpriseLimits"} {
			if covered[i] {
				continue
			}
			if _, declared := unpublishedTiers[field]; !declared {
				t.Errorf("%s is reconciled but no publication carries its %s column, and "+
					"unpublishedTiers records no reason. A tier compared by nothing must be "+
					"declared, or the field reads as covered when it is not", field, tier)
			}
			if _, ok := limits[tier][field]; !ok {
				t.Errorf("%s: %s declares no %s, so the gap cannot even be stated",
					field, tierLimitsPath, tier)
			}
		}
	}
}
