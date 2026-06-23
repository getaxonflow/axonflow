// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/lib/pq"

	"axonflow/platform/connectors/base"
)

// Integration tests for the read-only posture backstop (#2733).
//
// These prove that, under MCP_READ_ONLY (base.Query.ReadOnly == true), the
// PostgreSQL connector runs the read inside a "BEGIN READ ONLY" transaction so
// the database itself rejects any write smuggled past the gate's verb parser,
// while leaving posture-off behavior byte-identical.

// connectReadOnlyTestDB connects a fresh connector and returns it with a
// cleanup that disconnects. Each test uses an isolated table name.
func connectReadOnlyTestDB(t *testing.T, name string) (*PostgresConnector, context.Context) {
	t.Helper()
	dbURL := getTestDBURL(t)

	conn := NewPostgresConnector()
	ctx := context.Background()

	config := &base.ConnectorConfig{
		Name:          name,
		Type:          "postgres",
		ConnectionURL: dbURL,
		TenantID:      "test_tenant",
		Timeout:       30 * time.Second,
	}
	if err := conn.Connect(ctx, config); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	t.Cleanup(func() { _ = conn.Disconnect(ctx) })
	return conn, ctx
}

// seedTable creates a single-row table out-of-band (posture off) so each
// read-only test starts from a known, present row.
func seedTable(t *testing.T, conn *PostgresConnector, ctx context.Context, tableName string) {
	t.Helper()
	create := &base.Command{
		Action:    "CREATE",
		Statement: `CREATE TABLE ` + tableName + ` (id INT PRIMARY KEY, name VARCHAR(255))`,
	}
	if _, err := conn.Execute(ctx, create); err != nil {
		t.Fatalf("seed CREATE failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Execute(ctx, &base.Command{
			Action:    "DROP",
			Statement: "DROP TABLE IF EXISTS " + tableName,
		})
	})
	insert := &base.Command{
		Action:    "INSERT",
		Statement: `INSERT INTO ` + tableName + ` (id, name) VALUES (1, 'seed_row')`,
	}
	if _, err := conn.Execute(ctx, insert); err != nil {
		t.Fatalf("seed INSERT failed: %v", err)
	}
}

// rowCount returns the number of rows in the table via a posture-off query.
func rowCount(t *testing.T, conn *PostgresConnector, ctx context.Context, tableName string) int {
	t.Helper()
	res, err := conn.Query(ctx, &base.Query{
		Statement: `SELECT id FROM ` + tableName,
	})
	if err != nil {
		t.Fatalf("rowCount query failed: %v", err)
	}
	return res.RowCount
}

// TestPostgresConnector_Integration_ReadOnly_RejectsStackedWrite is the core
// case: a write stacked behind a SELECT (the exact shape a verb-path parser can
// miss) must be rejected by the database under read-only posture, and the row
// must remain present.
func TestPostgresConnector_Integration_ReadOnly_RejectsStackedWrite(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_stacked")
	tableName := "test_ro_stacked_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	// Smuggled write: SELECT passes the verb gate, the trailing DELETE does not.
	// No parameters -> lib/pq uses the simple-query protocol, which executes the
	// full multi-statement batch, so the DELETE actually reaches the server.
	stacked := &base.Query{
		Statement: `SELECT 1; DELETE FROM ` + tableName,
		ReadOnly:  true,
	}
	_, err := conn.Query(ctx, stacked)
	if err == nil {
		t.Fatalf("expected stacked write to be rejected under read-only posture, got nil error")
	}

	// The seed row must still be there: the DELETE was rejected, not silently
	// applied.
	if got := rowCount(t, conn, ctx, tableName); got != 1 {
		t.Errorf("expected row to survive rejected write, rowCount=%d want 1", got)
	}
}

// TestPostgresConnector_Integration_ReadOnly_RejectsDirectWrite covers a bare
// write submitted on the read path under posture.
func TestPostgresConnector_Integration_ReadOnly_RejectsDirectWrite(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_direct")
	tableName := "test_ro_direct_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	_, err := conn.Query(ctx, &base.Query{
		Statement: `DELETE FROM ` + tableName + ` WHERE id = 1`,
		ReadOnly:  true,
	})
	if err == nil {
		t.Fatalf("expected direct write to be rejected under read-only posture, got nil error")
	}
	if got := rowCount(t, conn, ctx, tableName); got != 1 {
		t.Errorf("expected row to survive rejected write, rowCount=%d want 1", got)
	}
}

// TestPostgresConnector_Integration_ReadOnly_AllowsSelect proves a legitimate
// read still succeeds and returns correct results under read-only posture.
func TestPostgresConnector_Integration_ReadOnly_AllowsSelect(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_select")
	tableName := "test_ro_select_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	res, err := conn.Query(ctx, &base.Query{
		Statement: `SELECT id, name FROM ` + tableName + ` WHERE id = 1`,
		ReadOnly:  true,
	})
	if err != nil {
		t.Fatalf("read-only SELECT failed: %v", err)
	}
	if res.RowCount != 1 {
		t.Fatalf("expected 1 row, got %d", res.RowCount)
	}
	if res.Rows[0]["name"] != "seed_row" {
		t.Errorf("expected name='seed_row', got %v", res.Rows[0]["name"])
	}
}

// TestPostgresConnector_Integration_ReadOnly_AllowsParameterizedSelect ensures
// the read-only path also works through the prepared-statement (extended)
// protocol that lib/pq uses when parameters are present.
func TestPostgresConnector_Integration_ReadOnly_AllowsParameterizedSelect(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_param")
	tableName := "test_ro_param_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	res, err := conn.Query(ctx, &base.Query{
		Statement:  `SELECT name FROM ` + tableName + ` WHERE id = $1`,
		Parameters: map[string]interface{}{"1": 1},
		ReadOnly:   true,
	})
	if err != nil {
		t.Fatalf("parameterized read-only SELECT failed: %v", err)
	}
	if res.RowCount != 1 || res.Rows[0]["name"] != "seed_row" {
		t.Errorf("unexpected result: count=%d rows=%v", res.RowCount, res.Rows)
	}
}

// TestPostgresConnector_Integration_PostureOff_AllowsStackedWrite is the
// regression guard: with ReadOnly unset (default), behavior is unchanged and a
// write still lands normally. This proves the backstop is inert when posture is
// off.
func TestPostgresConnector_Integration_PostureOff_AllowsStackedWrite(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_off_stacked")
	tableName := "test_off_stacked_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	// Identical statement, posture OFF: the DELETE must succeed and remove the
	// row, exactly as on the legacy read path.
	_, err := conn.Query(ctx, &base.Query{
		Statement: `SELECT 1; DELETE FROM ` + tableName,
		// ReadOnly: false (default)
	})
	if err != nil {
		t.Fatalf("posture-off stacked query failed: %v", err)
	}
	if got := rowCount(t, conn, ctx, tableName); got != 0 {
		t.Errorf("expected row to be deleted with posture off, rowCount=%d want 0", got)
	}
}

// TestPostgresConnector_Integration_ReadOnly_NoConnectionLeak runs many
// read-only queries, including rejected writes, and asserts the pool returns to
// zero in-use connections. A leaked transaction (commit/rollback missed on any
// path) would pin a connection and fail this.
func TestPostgresConnector_Integration_ReadOnly_NoConnectionLeak(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_leak")
	tableName := "test_ro_leak_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	for i := 0; i < 25; i++ {
		// Alternate success and rejected-write paths to exercise both the
		// commit branch and the early-return rollback branch.
		if i%2 == 0 {
			_, _ = conn.Query(ctx, &base.Query{
				Statement: `SELECT id FROM ` + tableName,
				ReadOnly:  true,
			})
		} else {
			_, _ = conn.Query(ctx, &base.Query{
				Statement: `DELETE FROM ` + tableName,
				ReadOnly:  true,
			})
		}
	}

	// Allow the pool a brief moment to settle released connections, then assert
	// nothing is still checked out.
	status, err := conn.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
	inUse, err := strconv.Atoi(status.Details["in_use"])
	if err != nil {
		t.Fatalf("could not parse in_use=%q: %v", status.Details["in_use"], err)
	}
	if inUse != 0 {
		t.Errorf("expected 0 in-use connections after read-only queries, got %d (transaction/connection leak)", inUse)
	}

	// And the row must still be present: every DELETE above was under read-only
	// posture and must have been rejected.
	if got := rowCount(t, conn, ctx, tableName); got != 1 {
		t.Errorf("expected seed row intact after read-only DELETE attempts, rowCount=%d want 1", got)
	}
}

// assertReadOnlyRejectedWith25006 runs statement under read-only posture and
// asserts it is rejected by PostgreSQL with SQLSTATE 25006
// (read_only_sql_transaction). It unwraps the connector error chain to the
// underlying *pq.Error so the assertion is on the real database error code, not
// a substring of a message.
func assertReadOnlyRejectedWith25006(t *testing.T, conn *PostgresConnector, ctx context.Context, statement string) {
	t.Helper()
	_, err := conn.Query(ctx, &base.Query{
		Statement: statement,
		ReadOnly:  true,
	})
	if err == nil {
		t.Fatalf("expected statement to be rejected under read-only posture, got nil error\n  statement: %s", statement)
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		t.Fatalf("expected a *pq.Error in the chain, got %T: %v\n  statement: %s", err, err, statement)
	}
	if string(pqErr.Code) != "25006" {
		t.Errorf("expected SQLSTATE 25006 (read_only_sql_transaction), got %s (%s): %v\n  statement: %s",
			pqErr.Code, pqErr.Code.Name(), err, statement)
	}
}

// TestPostgresConnector_Integration_ReadOnly_RejectsExplainAnalyzeDelete proves
// a write hidden inside EXPLAIN ANALYZE is rejected: EXPLAIN ANALYZE actually
// executes the wrapped DELETE, so the read-only transaction blocks it (25006).
func TestPostgresConnector_Integration_ReadOnly_RejectsExplainAnalyzeDelete(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_explain")
	tableName := "test_ro_explain_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	assertReadOnlyRejectedWith25006(t, conn, ctx, `EXPLAIN ANALYZE DELETE FROM `+tableName)

	if got := rowCount(t, conn, ctx, tableName); got != 1 {
		t.Errorf("expected row to survive rejected EXPLAIN ANALYZE DELETE, rowCount=%d want 1", got)
	}
}

// TestPostgresConnector_Integration_ReadOnly_RejectsSelectInto proves a
// data-definition write expressed as SELECT ... INTO (which creates a new
// table) is rejected under the read-only transaction (25006).
func TestPostgresConnector_Integration_ReadOnly_RejectsSelectInto(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_into")
	tableName := "test_ro_into_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)
	intoTable := tableName + "_copy"

	assertReadOnlyRejectedWith25006(t, conn, ctx,
		`SELECT id, name INTO `+intoTable+` FROM `+tableName)

	// The target table must not have been created under read-only posture.
	res, err := conn.Query(ctx, &base.Query{
		Statement: `SELECT to_regclass('` + intoTable + `') AS rel`,
	})
	if err != nil {
		t.Fatalf("existence check query failed: %v", err)
	}
	if rel := res.Rows[0]["rel"]; rel != nil {
		t.Errorf("expected SELECT INTO target table NOT to exist, but to_regclass returned %v", rel)
	}
}

// TestPostgresConnector_Integration_ReadOnly_RejectsWriteCTE proves a
// data-modifying common table expression (WITH x AS (DELETE ... RETURNING ...))
// is rejected under the read-only transaction (25006). This is a single
// statement whose top level is a SELECT, so a naive verb parser would pass it;
// the database backstop catches the embedded write.
func TestPostgresConnector_Integration_ReadOnly_RejectsWriteCTE(t *testing.T) {
	conn, ctx := connectReadOnlyTestDB(t, "test_ro_cte")
	tableName := "test_ro_cte_" + time.Now().Format("20060102150405")
	seedTable(t, conn, ctx, tableName)

	assertReadOnlyRejectedWith25006(t, conn, ctx,
		`WITH deleted AS (DELETE FROM `+tableName+` RETURNING id) SELECT id FROM deleted`)

	if got := rowCount(t, conn, ctx, tableName); got != 1 {
		t.Errorf("expected row to survive rejected write-CTE, rowCount=%d want 1", got)
	}
}
