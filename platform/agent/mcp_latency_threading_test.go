// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3424 round 2: the MCP plane's exclusion from the Avg Latency tile was by
// VERDICT, not by plane, and the excluded half was the enforcement verdicts.
//
// An MCP allow routes through recordDecideDecision and carried a measurement.
// The static blocks (writeExplainableAuditLog) and the redactions
// (writeMCPDecisionAudit) beside it could not: their writers had no latency
// parameter at all. Those are the SLOWER paths -- they run the richer-context
// build, the override lookup and the policy-name resolution the allow path
// skips -- so the tile lost the plane's slow half while the rows still inflated
// the denominator it was shown against.
//
// These tests pin the two halves of the fix as VALUES, not as sqlmock.AnyArg:
// a measured call binds an int64, and the one call site that deliberately stays
// unmeasured binds SQL NULL.

import (
	"context"
	"database/sql/driver"
	"testing"

	sharedaudit "axonflow/platform/shared/audit"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// latencyArg matches the response_time_ms bind and records what it saw, so the
// assertion is on the VALUE rather than on sqlmock.AnyArg -- which would match
// a NULL and a measurement identically, i.e. would pass against the bug.
type latencyArg struct{ got *interface{} }

func (a latencyArg) Match(v driver.Value) bool {
	*a.got = v
	return true
}

func TestWriteMCPDecisionAudit_BindsMeasuredLatency(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var bound interface{}
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			latencyArg{got: &bound}, // response_time_ms
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeMCPDecisionAudit(context.Background(), db,
		"dec-lat-1", "req-lat-1",
		"tenant-1", "org-1", "client-1", "u@e.com",
		"0", "service",
		"mcp_check_output", "mcp check-output: postgres", "",
		mcpVerdictRedacted,
		[]string{"pii-us-ssn"}, []string{"response PII redacted"}, []string{"nik"},
		"", nil,
		13)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	v, ok := bound.(int64)
	if !ok || v != 13 {
		t.Fatalf("response_time_ms bound as %v (%T), want int64(13).\n"+
			"A redaction on the MCP plane is enforcement work and must contribute a sample; "+
			"before #3424 round 2 this writer had no latency parameter at all.", bound, bound)
	}
}

func TestWriteMCPDecisionAudit_BindsNullForTheConnectorExecClosure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var bound interface{} = "unset"
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			latencyArg{got: &bound},
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// This is what mcpQueryHandler / mcpExecuteHandler pass: their one
	// emitDecisionAudit closure is shared between verdicts reached before
	// connector.Query/Execute and verdicts reached after it, so a single
	// elapsed value would be two different quantities.
	writeMCPDecisionAudit(context.Background(), db,
		"dec-lat-2", "req-lat-2",
		"tenant-1", "org-1", "client-1", "u@e.com",
		"0", "service",
		"mcp_resources_query", "mcp resources/query: postgres", "",
		mcpVerdictBlocked,
		[]string{"p"}, []string{"r"}, nil,
		"", nil,
		sharedaudit.LatencyUnmeasured)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	if bound != nil {
		t.Fatalf("response_time_ms bound as %v (%T), want SQL NULL. A 0 here would be read back "+
			"as a measured sub-millisecond decision now that the reader admits zeros.", bound, bound)
	}
}

func TestWriteExplainableAuditLog_BindsMeasuredLatency(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var bound interface{}
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			latencyArg{got: &bound},
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// A check-input STATIC BLOCK: the verdict the reviewer measured as
	// structurally unmeasurable, on the slower of the two paths.
	writeExplainableAuditLog(context.Background(), db,
		"dec-lat-3", "req-lat-3",
		"t1", "o1", "c1", "u@e.com",
		"", "user",
		"mcp_check_input", "SELECT 1", "h1",
		"blocked", "high",
		[]RicherPolicyMatch{{PolicyID: "p1", PolicyName: "Name"}},
		"",
		21)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	v, ok := bound.(int64)
	if !ok || v != 21 {
		t.Fatalf("response_time_ms bound as %v (%T), want int64(21)", bound, bound)
	}
}

// TestMCPWritersKeepAMeasuredZero is the other direction, and it is the one a
// careless "guard against 0" would break: a check-input block that completes in
// under a millisecond is a sample, not an absence.
func TestMCPWritersKeepAMeasuredZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var bound interface{} = "unset"
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			latencyArg{got: &bound},
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeMCPDecisionAudit(context.Background(), db,
		"dec-lat-4", "req-lat-4",
		"tenant-1", "org-1", "client-1", "u@e.com",
		"0", "service",
		"mcp_check_input", "mcp check-input: postgres", "",
		mcpVerdictBlocked,
		[]string{"p"}, []string{"r"}, nil,
		"", nil,
		0)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	v, ok := bound.(int64)
	if !ok || v != 0 {
		t.Fatalf("response_time_ms bound as %v (%T), want int64(0). A decision faster than the "+
			"column's 1ms resolution is measured, and dropping it is how 19 of 20 ALLOW decisions "+
			"came to record no sample.", bound, bound)
	}
}
