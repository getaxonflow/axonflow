// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package usage

import (
	"context"
	"database/sql/driver"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

// ---- normalizeOTELDelta (pure) ---------------------------------------------

func TestNormalizeOTELDelta_DeltaTemporalityPassthrough(t *testing.T) {
	ev := OTELMetricEvent{Temporality: TemporalityDelta, Value: 42}
	if got := normalizeOTELDelta(ev, otelSeriesState{known: true, raw: 999}); got != 42 {
		t.Errorf("delta temporality must ignore prior state: got %v want 42", got)
	}
}

func TestNormalizeOTELDelta_CumulativeFirstObservation(t *testing.T) {
	ev := OTELMetricEvent{Temporality: TemporalityCumulative, Value: 1500}
	if got := normalizeOTELDelta(ev, otelSeriesState{}); got != 1500 {
		t.Errorf("first cumulative observation IS the usage to date: got %v want 1500", got)
	}
}

func TestNormalizeOTELDelta_CumulativeIncrement(t *testing.T) {
	start := time.Unix(1000, 0)
	ev := OTELMetricEvent{Temporality: TemporalityCumulative, Value: 1500, StartTime: start}
	prev := otelSeriesState{known: true, raw: 1100, start: start}
	if got := normalizeOTELDelta(ev, prev); got != 400 {
		t.Errorf("cumulative increment: got %v want 400", got)
	}
}

func TestNormalizeOTELDelta_CounterResetByValueDrop(t *testing.T) {
	start := time.Unix(1000, 0)
	ev := OTELMetricEvent{Temporality: TemporalityCumulative, Value: 90, StartTime: start}
	prev := otelSeriesState{known: true, raw: 1100, start: start}
	if got := normalizeOTELDelta(ev, prev); got != 90 {
		t.Errorf("value drop = counter reset, exported value IS the delta: got %v want 90", got)
	}
}

func TestNormalizeOTELDelta_CounterResetByStartTimeChange(t *testing.T) {
	// A restarted counter that already exceeded the old total is only
	// detectable via the changed start time.
	ev := OTELMetricEvent{Temporality: TemporalityCumulative, Value: 2000, StartTime: time.Unix(5000, 0)}
	prev := otelSeriesState{known: true, raw: 1100, start: time.Unix(1000, 0)}
	if got := normalizeOTELDelta(ev, prev); got != 2000 {
		t.Errorf("start-time change = counter reset: got %v want 2000", got)
	}
}

func TestNormalizeOTELDelta_CumulativeResendNoChange(t *testing.T) {
	start := time.Unix(1000, 0)
	ev := OTELMetricEvent{Temporality: TemporalityCumulative, Value: 1100, StartTime: start}
	prev := otelSeriesState{known: true, raw: 1100, start: start}
	if got := normalizeOTELDelta(ev, prev); got != 0 {
		t.Errorf("unchanged cumulative resend carries no usage: got %v want 0", got)
	}
}

// ---- RecordOTELMetrics (sqlmock) --------------------------------------------

func otelTestEvent(over func(*OTELMetricEvent)) OTELMetricEvent {
	ev := OTELMetricEvent{
		ClientID:     "client-1",
		InstanceID:   "agent-1",
		InstanceType: "agent",
		SessionID:    "sess-1",
		UserEmail:    "dev@example.com",
		MetricName:   "claude_code.token.usage",
		Value:        250,
		Temporality:  TemporalityDelta,
		SeriesKey:    "abc123",
		Attributes:   map[string]string{"type": "input", "model": "claude-sonnet-5"},
		Time:         time.Unix(1700000000, 0).UTC(),
		CountsTokens: true,
		TokenType:    "input",
	}
	if over != nil {
		over(&ev)
	}
	return ev
}

func TestRecordOTELMetrics_DeltaInsert(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs("org-1", sqlmock.AnyArg(), "agent-1", "agent",
			sqlmock.AnyArg(), sqlmock.AnyArg(), "claude_code.token.usage",
			float64(250), float64(250), TemporalityDelta, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			250, 0, 250, 0). // prompt=250 (input), completion=0, total=250, cents=0
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{otelTestEvent(nil)})
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 1 {
		t.Errorf("inserted: got %d want 1", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestRecordOTELMetrics_CostMirroredToCents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT COALESCE\\(SUM\\(metric_value").
		WithArgs("org-1", "abc123").
		WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(0.0))
	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs("org-1", sqlmock.AnyArg(), "agent-1", "agent",
			sqlmock.AnyArg(), sqlmock.AnyArg(), "claude_code.cost.usage",
			0.0742, 0.0742, TemporalityDelta, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			0, 0, 0, 7). // $0.0742 → 7 cents (rounded); exact value stays in metric_value
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	ev := otelTestEvent(func(e *OTELMetricEvent) {
		e.MetricName = "claude_code.cost.usage"
		e.Value = 0.0742
		e.CountsTokens = false
		e.TokenType = ""
		e.CountsCostUSD = true
	})
	if _, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{ev}); err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// A cumulative datapoint with a prior row in the table is stored as the DELTA
// against that row — the core over-count guard for cumulative exporters.
func TestRecordOTELMetrics_CumulativeDeltaAgainstStoredRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	start := time.Unix(1700000000, 0).UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT metric_raw_value, metric_start_time").
		WithArgs("org-1", "series-x").
		WillReturnRows(sqlmock.NewRows([]string{"metric_raw_value", "metric_start_time"}).AddRow(1100.0, start))
	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs("org-1", sqlmock.AnyArg(), "agent-1", "agent",
			sqlmock.AnyArg(), sqlmock.AnyArg(), "claude_code.token.usage",
			float64(400), float64(1500), TemporalityCumulative, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			400, 0, 400, 0).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	ev := otelTestEvent(func(e *OTELMetricEvent) {
		e.Temporality = TemporalityCumulative
		e.Value = 1500
		e.SeriesKey = "series-x"
		e.StartTime = start
	})
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{ev})
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 1 {
		t.Errorf("inserted: got %d want 1", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// Two cumulative datapoints of the SAME series in one batch: the second deltas
// against the FIRST (batch cache), with only one table lookup.
func TestRecordOTELMetrics_CumulativeBatchCache(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	start := time.Unix(1700000000, 0).UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	// ONE lookup (no prior row), then two inserts: 1000, then 1300-1000=300.
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT metric_raw_value, metric_start_time").
		WithArgs("org-1", "series-y").
		WillReturnRows(sqlmock.NewRows([]string{"metric_raw_value", "metric_start_time"}))
	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs("org-1", sqlmock.AnyArg(), "agent-1", "agent",
			sqlmock.AnyArg(), sqlmock.AnyArg(), "claude_code.token.usage",
			float64(1000), float64(1000), TemporalityCumulative, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), 1000, 0, 1000, 0).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs("org-1", sqlmock.AnyArg(), "agent-1", "agent",
			sqlmock.AnyArg(), sqlmock.AnyArg(), "claude_code.token.usage",
			float64(300), float64(1300), TemporalityCumulative, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), 300, 0, 300, 0).
		WillReturnResult(sqlmock.NewResult(2, 1))
	mock.ExpectCommit()

	mk := func(v float64) OTELMetricEvent {
		return otelTestEvent(func(e *OTELMetricEvent) {
			e.Temporality = TemporalityCumulative
			e.Value = v
			e.SeriesKey = "series-y"
			e.StartTime = start
		})
	}
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{mk(1000), mk(1300)})
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 2 {
		t.Errorf("inserted: got %d want 2", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// A zero-delta datapoint (cumulative resend, no change) is elided — no row.
func TestRecordOTELMetrics_ZeroDeltaElided(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	start := time.Unix(1700000000, 0).UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT metric_raw_value, metric_start_time").
		WithArgs("org-1", "series-z").
		WillReturnRows(sqlmock.NewRows([]string{"metric_raw_value", "metric_start_time"}).AddRow(500.0, start))
	// No INSERT expected.
	mock.ExpectCommit()

	ev := otelTestEvent(func(e *OTELMetricEvent) {
		e.Temporality = TemporalityCumulative
		e.Value = 500
		e.SeriesKey = "series-z"
		e.StartTime = start
	})
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{ev})
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 0 {
		t.Errorf("inserted: got %d want 0 (zero-delta elided)", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// Empty org is a LOUD error (usage_events RLS rejects it), never a NULL-bucket row.
func TestRecordOTELMetrics_EmptyOrgRejected(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	// No expectations: nothing may touch the DB.

	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "", []OTELMetricEvent{otelTestEvent(nil)})
	if err == nil {
		t.Fatal("empty org must error")
	}
	if n != 0 {
		t.Errorf("inserted: got %d want 0", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no DB call expected: %v", err)
	}
}

// A negative value (invalid for a monotonic counter) is skipped defensively.
func TestRecordOTELMetrics_NegativeValueSkipped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	ev := otelTestEvent(func(e *OTELMetricEvent) { e.Value = -5 })
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{ev})
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 0 {
		t.Errorf("inserted: got %d want 0", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// R3 HIGH: a non-finite value must never reach the table (NaN would poison
// every SUM(metric_value)). Recorder-side backstop for the ingest guard.
func TestRecordOTELMetrics_NonFiniteSkipped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	events := []OTELMetricEvent{
		otelTestEvent(func(e *OTELMetricEvent) { e.Value = math.NaN() }),
		otelTestEvent(func(e *OTELMetricEvent) { e.Value = math.Inf(1) }),
	}
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", events)
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 0 {
		t.Errorf("inserted: got %d want 0 (non-finite values must be skipped)", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no INSERT expected: %v", err)
	}
}

// R3 HIGH: a client retry of an already-committed export (same series + same
// datapoint time) hits ON CONFLICT DO NOTHING → zero rows, no double count.
func TestRecordOTELMetrics_DuplicateRetryElided(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO usage_events").
		WillReturnResult(sqlmock.NewResult(0, 0)) // conflict → 0 rows affected
	mock.ExpectCommit()

	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{otelTestEvent(nil)})
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 0 {
		t.Errorf("inserted: got %d want 0 (duplicate retry must not double-count)", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// R3 round 2: sub-half-cent deltas must not round to zero forever — the cents
// mirror telescopes against the series' running total, so consecutive $0.004
// deltas yield cents rows that sum to the true total within one cent.
func TestRecordOTELMetrics_CostCentsTelescope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	// One SUM lookup (batch cache covers the rest); stored total so far $0.008.
	mock.ExpectQuery("SELECT COALESCE\\(SUM\\(metric_value").
		WithArgs("org-1", "cost-series").
		WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(0.008))
	// Row 1: sum 0.008 → 0.012: round(1.2) - round(0.8) = 1 - 1 = 0 cents.
	a1 := make([]driver.Value, 18)
	for i := range a1 {
		a1[i] = sqlmock.AnyArg()
	}
	a1[17] = 0
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a1...).WillReturnResult(sqlmock.NewResult(1, 1))
	// Row 2: sum 0.012 → 0.016: round(1.6) - round(1.2) = 2 - 1 = 1 cent.
	a2 := make([]driver.Value, 18)
	for i := range a2 {
		a2[i] = sqlmock.AnyArg()
	}
	a2[17] = 1
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a2...).WillReturnResult(sqlmock.NewResult(2, 1))
	mock.ExpectCommit()

	mk := func(v float64, tm time.Time) OTELMetricEvent {
		return otelTestEvent(func(e *OTELMetricEvent) {
			e.MetricName = "claude_code.cost.usage"
			e.Value = v
			e.CountsTokens = false
			e.TokenType = ""
			e.CountsCostUSD = true
			e.SeriesKey = "cost-series"
			e.Time = tm
		})
	}
	events := []OTELMetricEvent{
		mk(0.004, time.Unix(1700000060, 0).UTC()),
		mk(0.004, time.Unix(1700000120, 0).UTC()),
	}
	if _, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", events); err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// R3 round 2 HIGH: a SQLSTATE class-23 (integrity) failure — e.g. the org has
// no organizations row, so the usage_events FK rejects every insert — must be
// classified PERMANENT so the ingest answers 4xx instead of trapping the
// exporter in an identical-payload 503 retry loop.
func TestRecordOTELMetrics_IntegrityErrorClassifiedPermanent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO usage_events").
		WillReturnError(&pq.Error{Code: "23503", Message: "violates foreign key constraint \"fk_usage_org\""})
	mock.ExpectRollback()

	_, err = NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{otelTestEvent(nil)})
	if !errors.Is(err, ErrOTELMetricsPermanent) {
		t.Fatalf("FK violation must classify as ErrOTELMetricsPermanent, got: %v", err)
	}
}

func TestClassifyOTELStorageError(t *testing.T) {
	if err := classifyOTELStorageError(&pq.Error{Code: "22003"}); !errors.Is(err, ErrOTELMetricsPermanent) {
		t.Error("class 22 must be permanent")
	}
	transient := &pq.Error{Code: "40001"} // serialization failure — retryable
	if err := classifyOTELStorageError(transient); errors.Is(err, ErrOTELMetricsPermanent) {
		t.Error("class 40 must stay retryable")
	}
	if err := classifyOTELStorageError(context.DeadlineExceeded); errors.Is(err, ErrOTELMetricsPermanent) {
		t.Error("non-pq errors must stay retryable")
	}
}

func TestClampToInt32(t *testing.T) {
	if got := clampToInt32(5e9); got != math.MaxInt32 {
		t.Errorf("overflow clamp: got %d", got)
	}
	if got := clampToInt32(-3); got != 0 {
		t.Errorf("negative clamp: got %d", got)
	}
	if got := clampToInt32(1234); got != 1234 {
		t.Errorf("passthrough: got %d", got)
	}
}

// Empty batch and nil DB are no-ops.
func TestRecordOTELMetrics_EmptyAndNilDB(t *testing.T) {
	if n, err := NewUsageRecorder(nil).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{otelTestEvent(nil)}); n != 0 || err != nil {
		t.Errorf("nil db: got n=%d err=%v", n, err)
	}
	db, _, _ := sqlmock.New()
	defer db.Close()
	if n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", nil); n != 0 || err != nil {
		t.Errorf("empty batch: got n=%d err=%v", n, err)
	}
}

// R3 M2 pin: cache-token types (cacheRead / cacheCreation) must NOT mirror
// into the legacy prompt/completion/total token columns — on a real Claude
// Code session they dwarf real tokens by orders of magnitude and would
// inflate the shared rollups. The delta still lands in metric_value.
func TestRecordOTELMetrics_CacheTokensNotMirrored(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs("org-1", sqlmock.AnyArg(), "agent-1", "agent",
			sqlmock.AnyArg(), sqlmock.AnyArg(), "claude_code.token.usage",
			float64(20058), float64(20058), TemporalityDelta, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			0, 0, 0, 0). // NO token mirror for cacheRead
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	ev := otelTestEvent(func(e *OTELMetricEvent) {
		e.Value = 20058 // real-capture cache_read magnitude
		e.TokenType = "cacheRead"
		e.Attributes = map[string]string{"type": "cacheRead", "model": "claude-sonnet-5"}
	})
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", []OTELMetricEvent{ev})
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 1 {
		t.Errorf("inserted: got %d want 1", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("cache tokens leaked into the token mirror: %v", err)
	}
}

// #2840 LOW: out-of-order same-series datapoints in one export must not trip
// the counter-reset heuristic (value drop misread as reset → full value
// re-counted). sortOTELSeriesPoints time-orders each series in place.
func TestSortOTELSeriesPoints_FixesInBatchInversion(t *testing.T) {
	mk := func(key string, v float64, sec int64) OTELMetricEvent {
		return OTELMetricEvent{SeriesKey: key, Value: v, Time: time.Unix(sec, 0),
			Temporality: TemporalityCumulative}
	}
	// Series A arrives inverted (t2 before t1); series B sits between them.
	events := []OTELMetricEvent{
		mk("A", 1500, 200), // later point first
		mk("B", 7, 150),
		mk("A", 1000, 100),
	}
	sortOTELSeriesPoints(events)
	if events[0].Value != 1000 || events[2].Value != 1500 {
		t.Errorf("series A not time-ordered in place: got [%v %v %v]", events[0].Value, events[1].Value, events[2].Value)
	}
	if events[1].SeriesKey != "B" || events[1].Value != 7 {
		t.Errorf("cross-series slot must be untouched: got %+v", events[1])
	}
	// Folding the ordered series yields 1000 + 500, not 1000 + 1500 (reset misread).
	prev := otelSeriesState{}
	total := 0.0
	for _, ev := range events {
		if ev.SeriesKey != "A" {
			continue
		}
		d := normalizeOTELDelta(ev, prev)
		prev = otelSeriesState{raw: ev.Value, start: ev.StartTime, known: true}
		total += d
	}
	if total != 1500 {
		t.Errorf("in-batch inversion over-counted: total delta %v want 1500", total)
	}
}

// R3 MED-1 pin: the sort must be WIRED into RecordOTELMetrics, not just exist.
// An inverted two-point cumulative series in one batch stores 1000 then a 500
// delta (total 1500); deleting the sortOTELSeriesPoints call re-counts the
// full 1500 on the inverted point (reset misdetection) and goes red here.
func TestRecordOTELMetrics_InBatchInversionSortedBeforeFold(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	start := time.Unix(1700000000, 0).UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT metric_raw_value, metric_start_time").
		WithArgs("org-1", "series-inv").
		WillReturnRows(sqlmock.NewRows([]string{"metric_raw_value", "metric_start_time"}))
	// Earlier point (1000) first, then the 500 delta — NOT 1500 then 1000.
	a1 := make([]driver.Value, 18)
	for i := range a1 {
		a1[i] = sqlmock.AnyArg()
	}
	a1[7] = float64(1000) // metric_value
	a1[8] = float64(1000) // metric_raw_value
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a1...).WillReturnResult(sqlmock.NewResult(1, 1))
	a2 := make([]driver.Value, 18)
	for i := range a2 {
		a2[i] = sqlmock.AnyArg()
	}
	a2[7] = float64(500)  // delta after sort
	a2[8] = float64(1500) // raw
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a2...).WillReturnResult(sqlmock.NewResult(2, 1))
	mock.ExpectCommit()

	mk := func(v float64, sec int64) OTELMetricEvent {
		return otelTestEvent(func(e *OTELMetricEvent) {
			e.Temporality = TemporalityCumulative
			e.Value = v
			e.SeriesKey = "series-inv"
			e.StartTime = start
			e.Time = time.Unix(sec, 0).UTC()
		})
	}
	// Wire order INVERTED: the later (1500 @ t+120) point arrives first.
	events := []OTELMetricEvent{mk(1500, 1700000120), mk(1000, 1700000060)}
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", events)
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 2 {
		t.Errorf("inserted: got %d want 2", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("inverted batch must fold time-ordered (1000 then delta 500): %v", err)
	}
}

// R3 #2843 L1 pin: a duplicate-(series,time) point dropped by ON CONFLICT
// (n=0) must NOT advance the series-state cache. P1{100,T1}, P2{50,T1}
// (duplicate time, inverted value → reset-detected delta 50, dropped by the
// dedup index), P3{120,T2}: stored metric_value must sum to 120 (100 + 20),
// not 170 (100 + 70 deltaed against P2's never-stored raw).
func TestRecordOTELMetrics_DroppedDuplicateDoesNotAdvanceSeriesState(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	start := time.Unix(1700000000, 0).UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WithArgs("org-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET LOCAL lock_timeout").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT metric_raw_value, metric_start_time").
		WithArgs("org-1", "series-dup").
		WillReturnRows(sqlmock.NewRows([]string{"metric_raw_value", "metric_start_time"}))
	// P1: delta 100, stored.
	a1 := make([]driver.Value, 18)
	for i := range a1 {
		a1[i] = sqlmock.AnyArg()
	}
	a1[7] = float64(100)
	a1[8] = float64(100)
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a1...).WillReturnResult(sqlmock.NewResult(1, 1))
	// P2: value drop at the SAME timestamp → reset-detected delta 50, but the
	// dedup index drops it (0 rows affected).
	a2 := make([]driver.Value, 18)
	for i := range a2 {
		a2[i] = sqlmock.AnyArg()
	}
	a2[7] = float64(50)
	a2[8] = float64(50)
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a2...).WillReturnResult(sqlmock.NewResult(0, 0))
	// P3: MUST delta against P1's STORED raw (120-100=20), not P2's
	// never-stored 50 (which would give 70 → stored total 170 vs true 120).
	a3 := make([]driver.Value, 18)
	for i := range a3 {
		a3[i] = sqlmock.AnyArg()
	}
	a3[7] = float64(20)
	a3[8] = float64(120)
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a3...).WillReturnResult(sqlmock.NewResult(2, 1))
	mock.ExpectCommit()

	mk := func(v float64, sec int64) OTELMetricEvent {
		return otelTestEvent(func(e *OTELMetricEvent) {
			e.Temporality = TemporalityCumulative
			e.Value = v
			e.SeriesKey = "series-dup"
			e.StartTime = start
			e.Time = time.Unix(sec, 0).UTC()
		})
	}
	events := []OTELMetricEvent{
		mk(100, 1700000060), // P1
		mk(50, 1700000060),  // P2 — duplicate time, inverted value
		mk(120, 1700000120), // P3
	}
	n, err := NewUsageRecorder(db).RecordOTELMetrics(context.Background(), "org-1", events)
	if err != nil {
		t.Fatalf("RecordOTELMetrics: %v", err)
	}
	if n != 2 {
		t.Errorf("inserted: got %d want 2 (P2 dropped by dedup)", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("dropped duplicate must not poison the next delta: %v", err)
	}
}
