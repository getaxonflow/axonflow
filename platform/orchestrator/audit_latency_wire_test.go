// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3424 round-2 BLOCKER: the read path used to re-manufacture the fabricated
// zero the write path had just stopped storing.
//
// AuditEntry.ResponseTime was a non-pointer int64 with no omitempty, so
// /api/v1/audit/search emitted `"response_time_ms": 0` for every row whose
// writer measured nothing. The portal's `??` does not catch 0, so the Latency
// column rendered "0ms" one panel below an Avg Latency tile that had just been
// taught to say N/A for the very same rows.
//
// The field is now *int64 with omitempty, so an unmeasured row OMITS the key.
// That is deliberately not an explicit null: AuditLogEntry declares no
// `required` list, so the field was already optional in the published contract
// and an absent key breaks nothing, while `nullable: true` would have been a
// real contract change on the four highest-traffic audit endpoints. `??` then
// does the right thing for free, which it never did for a literal 0.
//
// These tests pin the WIRE, which is the contract the portal reads.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditEntryJSON_UnmeasuredLatencyKeyIsAbsent(t *testing.T) {
	// A row from any of the seven AuditEntry producers that measure nothing
	// (blocked request / response / media, failed request, workflow, plan,
	// tool-call), or from any writer whose column is SQL NULL.
	body, err := json.Marshal(&AuditEntry{ID: "audit-1", PolicyDecision: "blocked"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(body)
	if strings.Contains(got, `"response_time_ms"`) {
		t.Fatalf("unmeasured row must OMIT response_time_ms entirely, not carry it: %s\n"+
			"An explicit null would work for the portal but is a contract CHANGE on four audit "+
			"endpoints; an absent key is not, because the schema declares no `required` list.", got)
	}
	if strings.Contains(got, `"response_time_ms":0`) {
		t.Fatalf("THE BLOCKER: an unmeasured row still claims a measured zero on the wire; got %s", got)
	}
}

func TestAuditEntryJSON_MeasuredZeroIsZero(t *testing.T) {
	// The other half: a decision the platform genuinely timed at under the
	// column's 1ms resolution is a SAMPLE, and must reach the portal as one so
	// it can render "<1ms" rather than silently dropping it.
	zero := int64(0)
	body, err := json.Marshal(&AuditEntry{ID: "audit-2", ResponseTime: &zero})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The trap omitempty sets for a value type: `int64` + omitempty would drop
	// exactly this sample, which is 19 of 20 ordinary allow decisions. On a
	// POINTER omitempty drops only nil.
	if !strings.Contains(string(body), `"response_time_ms":0`) {
		t.Fatalf("a measured sub-millisecond row must serialize as 0, not be omitted; got %s", body)
	}
}

func TestAuditEntryJSON_MeasuredLatencySurvives(t *testing.T) {
	ms := int64(137)
	body, err := json.Marshal(&AuditEntry{ID: "audit-3", ResponseTime: &ms})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"response_time_ms":137`) {
		t.Fatalf("measured latency lost on the wire; got %s", body)
	}
}

// TestCSVLatencyCell is the export's half of the same rule. A "0" in a
// spreadsheet column is worse than on screen: the operator will AVERAGE it, and
// every unmeasured row would vote that average towards zero with nothing to
// signal it was never a measurement. An empty cell is skipped by AVERAGE() in
// Excel and Sheets alike, which is the same treatment the server's own
// predicate gives the row.
func TestCSVLatencyCell(t *testing.T) {
	if got := csvLatencyCell(nil); got != "" {
		t.Fatalf("csvLatencyCell(nil) = %q, want an EMPTY cell (not %q, which a spreadsheet averages)", got, "0")
	}
	zero := int64(0)
	if got := csvLatencyCell(&zero); got != "0" {
		t.Fatalf("csvLatencyCell(&0) = %q, want \"0\": a measured sub-millisecond decision is a real sample", got)
	}
	ms := int64(42)
	if got := csvLatencyCell(&ms); got != "42" {
		t.Fatalf("csvLatencyCell(&42) = %q, want \"42\"", got)
	}
}
