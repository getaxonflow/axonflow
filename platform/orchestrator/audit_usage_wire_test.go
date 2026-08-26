// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3427 sub-finding M19: the token and cost twins of the #3424 latency wire
// contract, on the two columns that issue did not cover.
//
// LogSuccessfulRequest is the only AuditEntry producer that RECORDS a token
// count or a cost. That is not the same as "the only producer with a
// ProviderInfo": LogBlockedResponse is handed one too, on a post-forward path
// where the round trip really happened, and records none of it - so its rows
// join the no-usage population for a different reason, and the wire says only
// "not recorded" rather than "no provider was called". While the fields were
// plain value types, every such producer's zero VALUE was bound into the
// INSERT as a literal 0, and all three read paths scanned the columns into
// sql.Null* and then took .Int64 / .Float64 without checking .Valid. A governed
// BLOCK therefore left the orchestrator as `"tokens_used": 0, "cost": 0`, and
// the portal's expanded detail panel - whose `!= null` guards exist precisely
// for the absent case, and were therefore unreachable - rendered "Tokens 0" and
// "Cost $0.0000" under a row that recorded no provider usage.
//
// These tests pin the WIRE, which is the contract the portal reads, and the
// scan, which is where the absence was being thrown away.

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditEntryJSON_NoProviderRoundTripOmitsUsage(t *testing.T) {
	// A row from any producer that recorded no provider usage.
	body, err := json.Marshal(&AuditEntry{ID: "audit-1", PolicyDecision: "blocked"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(body)
	for _, key := range []string{`"tokens_used"`, `"cost"`} {
		if strings.Contains(got, key) {
			t.Fatalf("a row with no recorded provider usage must OMIT %s entirely; got %s\n"+
				"An absent key is not a contract change (AuditLogEntry declares no `required` "+
				"list), while a 0 is a claim about usage nothing measured.", key, got)
		}
	}
}

func TestAuditEntryJSON_MeasuredZeroCostSurvives(t *testing.T) {
	// The mirror-image failure. A locally hosted or free-tier model genuinely
	// costs 0.0000, and a provider can report 0 tokens; rendering either as
	// "not recorded" would be the same lie in the other direction. This is why
	// absence is expressed by OMITTING the key rather than by a zero, and why
	// the fields are pointers rather than value types with omitempty - a
	// value-typed omitempty would swallow exactly this row.
	tokens, cost := 0, 0.0
	body, err := json.Marshal(&AuditEntry{
		ID: "audit-2", Provider: "ollama", Model: "llama-3.1",
		TokensUsed: &tokens, Cost: &cost,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, `"tokens_used":0`) {
		t.Fatalf("a reported zero token count must serialize as 0, not be omitted; got %s", got)
	}
	if !strings.Contains(got, `"cost":0`) {
		t.Fatalf("a genuine zero-cost round trip must serialize as 0, not be omitted; got %s", got)
	}
}

func TestAuditEntryJSON_MeasuredUsageSurvives(t *testing.T) {
	tokens, cost := 2412, 0.0184
	body, err := json.Marshal(&AuditEntry{ID: "audit-3", TokensUsed: &tokens, Cost: &cost})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, `"tokens_used":2412`) || !strings.Contains(got, `"cost":0.0184`) {
		t.Fatalf("measured usage lost on the wire; got %s", got)
	}
}

// The scan half. This is where the absence was actually destroyed: the column
// really is NULL for every non-provider row (and the cowork writer has always
// nulled its own zeros), and `int(tokensUsed.Int64)` on an invalid NullInt64
// silently produces the 0 the wire then published.
func TestNullUsagePtrs_DistinguishAbsentFromZero(t *testing.T) {
	if got := nullTokensPtr(sql.NullInt64{}); got != nil {
		t.Fatalf("a SQL NULL token count must become nil, got %d - the value a "+
			".Valid-less scan produced, and the one the panel rendered as \"Tokens 0\"", *got)
	}
	if got := nullCostPtr(sql.NullFloat64{}); got != nil {
		t.Fatalf("a SQL NULL cost must become nil, got %v", *got)
	}
	if got := nullTokensPtr(sql.NullInt64{Int64: 0, Valid: true}); got == nil || *got != 0 {
		t.Fatalf("a stored 0 is a REPORTED zero and must survive as 0, got %v", got)
	}
	if got := nullCostPtr(sql.NullFloat64{Float64: 0, Valid: true}); got == nil || *got != 0 {
		t.Fatalf("a stored 0.0 cost is a real free-tier measurement and must survive, got %v", got)
	}
	if got := nullTokensPtr(sql.NullInt64{Int64: 512, Valid: true}); got == nil || *got != 512 {
		t.Fatalf("a measured token count was lost, got %v", got)
	}
	if got := nullCostPtr(sql.NullFloat64{Float64: 1.25, Valid: true}); got == nil || *got != 1.25 {
		t.Fatalf("a measured cost was lost, got %v", got)
	}
}

// The export's half of the same rule, and the reason it is not simply
// strconv.Itoa: a "0" in a numeric spreadsheet column is worse than on screen,
// because an analyst filtering the export to governed BLOCKS would be averaging
// or summing a column in which every one of those rows claims a real
// zero-token model call.
func TestCSVTokensCell(t *testing.T) {
	if got := csvTokensCell(nil); got != "" {
		t.Fatalf("csvTokensCell(nil) = %q, want an EMPTY cell - a spreadsheet counts a 0 as a sample", got)
	}
	zero := 0
	if got := csvTokensCell(&zero); got != "0" {
		t.Fatalf("csvTokensCell(&0) = %q, want \"0\": a provider that reported zero tokens reported something", got)
	}
	n := 2412
	if got := csvTokensCell(&n); got != "2412" {
		t.Fatalf("csvTokensCell(&2412) = %q, want \"2412\"", got)
	}
}
