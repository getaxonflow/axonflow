// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3529 (epic #3528 Phase 1): the guard that keeps the US regulator-keyed
// retention presets honest.
//
// Migration enterprise/139 seeds five rows into audit_retention_defaults naming
// regulatory record classes and the period each must be kept for: Reg B
// adverse-action records (25 months), SAR supporting documentation (5 years),
// the two NYDFS 23 NYCRR 500.06 classes (5 and 3 years), and SEC 17a-4
// broker-dealer records (6 years).
//
// Those are REQUIREMENT vocabulary, not a pruning schedule, and the difference
// is the whole safety argument. AxonFlow does not store "adverse-action
// records" as a table of its own, and it must never start deleting a bank's
// records on a clock it inferred from a seeded row. The property that makes
// that true is structural rather than incidental: CleanupRetentionGovernedAudits
// iterates retentionGovernedTables - a fixed six-entry map in audit_cleanup.go -
// and NOT the rows of audit_retention_defaults, so a preset naming a data type
// absent from that map can never reach a DELETE.
//
// This test lives here, in the package that owns retentionGovernedTables, so it
// reads the REAL map. Mirroring the executor's data types into the agent
// package's migration test would have been a hand-maintained copy that drifts
// silently - the same defect class the migration's own comments are about.
//
// If someone later adds one of these data types to the executor's map, this
// test fails. That is intended: beginning to delete records on a regulatory
// clock is a decision that must be made deliberately and reviewed on its own
// merits, never acquired as a side effect of seeding a preset.

import "testing"

// usRetentionPresetDataTypes are the data_type keys seeded by
// migrations/enterprise/139_us_compliance_templates.sql. Written as literals:
// this test's job is to compare the migration against the executor, so taking
// either side from the other would make it agree with itself.
var usRetentionPresetDataTypes = []string{
	"reg_b_adverse_action_records",
	"sar_supporting_documentation",
	"nydfs_transaction_reconstruction",
	"nydfs_cybersecurity_audit_trail",
	"sec_broker_dealer_records",
}

func TestUSRetentionPresetsAreNotGovernedByTheRetentionExecutor(t *testing.T) {
	governed := make(map[string]bool, len(retentionGovernedTables))
	for _, g := range retentionGovernedTables {
		governed[g.dataType] = true
	}

	// Anti-vacuity, both directions. An empty governed set, or one whose keys
	// are not the data types this comparison assumes, would make the loop
	// below pass while comparing nothing.
	if len(governed) == 0 {
		t.Fatal("retentionGovernedTables is empty - this guard would be vacuous")
	}
	if !governed["decision_chain"] {
		t.Fatalf("retentionGovernedTables does not contain 'decision_chain' (got %d entries) - the field being read is not the executor's data_type key, so the check below compares nothing", len(governed))
	}

	for _, preset := range usRetentionPresetDataTypes {
		if governed[preset] {
			t.Errorf("retention preset %q is governed by the retention executor. AxonFlow would begin DELETING records on a regulatory clock inferred from a seeded row. If that is genuinely intended it needs its own review - it must not be acquired as a side effect of adding a preset to audit_retention_defaults (#3529)", preset)
		}
	}
}

// TestRetentionExecutorStillGovernsExactlyTheKnownTables pins the executor's
// map itself.
//
// Without this, the guard above could be satisfied by the map being emptied or
// rewritten - a change that would stop ALL retention pruning while leaving the
// preset guard green. The six entries below are the documented governed set
// (audit_cleanup.go); policy_violations and audit_logs are deliberately absent
// there and remain so.
func TestRetentionExecutorStillGovernsExactlyTheKnownTables(t *testing.T) {
	want := map[string]bool{
		"agent_audit_logs":        true,
		"orchestrator_audit_logs": true,
		"llm_call_audits":         true,
		"gateway_contexts":        true,
		"decision_chain":          true,
		"hitl_oversight":          true,
	}

	got := make(map[string]bool, len(retentionGovernedTables))
	for _, g := range retentionGovernedTables {
		got[g.dataType] = true
	}

	for dataType := range want {
		if !got[dataType] {
			t.Errorf("retentionGovernedTables no longer governs %q - retention pruning silently stopped for it", dataType)
		}
	}
	for dataType := range got {
		if !want[dataType] {
			t.Errorf("retentionGovernedTables gained %q. If this is a US retention preset, AxonFlow has started deleting records on a regulatory clock; if it is a new AxonFlow table, add it to this list deliberately (#3529)", dataType)
		}
	}
}
