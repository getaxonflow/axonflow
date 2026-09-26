// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #4249 row 5705939628: nothing the audit queue cannot keep is dropped
// silently, and a shared-engine evaluation lands as policy_metrics rows. Every
// drop site has a cell reading its counter; the cells never start the queue's
// workers, so what reaches a channel is read straight off it.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/testutil"

	sharedpolicy "axonflow/platform/shared/policy"
)

func droppedAt(site string) float64 {
	return testutil.ToFloat64(auditEntriesDroppedTotal.WithLabelValues(site))
}

// unstartedQueue is an AuditQueue whose workers and batcher never run, so a
// test reads its channels directly.
func unstartedQueue(t *testing.T, mode AuditMode, metricsSlots int) *AuditQueue {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fallback-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	aq := &AuditQueue{
		mode:         mode,
		queue:        make(chan AuditEntry, 10),
		metricsBatch: make(chan AuditEntry, metricsSlots),
		fallbackFile: f,
	}
	return aq
}

func drainMetrics(aq *AuditQueue) []AuditEntry {
	var out []AuditEntry
	for {
		select {
		case e := <-aq.metricsBatch:
			out = append(out, e)
		default:
			return out
		}
	}
}

// AN EVALUATION IS ONE METRICS ENTRY PER MATCHED POLICY, under its
// organization, with that policy's own block flag.
func TestAnEvaluationBecomesOneMetricsEntryPerMatchedPolicy(t *testing.T) {
	aq := unstartedQueue(t, AuditModePerformance, 100)
	adapter := &SharedPolicyAuditAdapter{queue: aq}
	err := adapter.LogPolicyEvaluation(sharedpolicy.PolicyEvaluationEntry{
		Type:            "response",
		TenantID:        "tenant-a",
		OrgID:           "org-a",
		UserID:          "user-a",
		MatchedPolicies: []string{"pii_ssn", "pii_email", "pii_ssn", ""},
		BlockedPolicies: []string{"pii_ssn"},
		Blocked:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := drainMetrics(aq)
	if len(got) != 2 {
		t.Fatalf("got %d metrics entries, want 2 (one per distinct matched policy): %+v", len(got), got)
	}
	want := map[string]bool{"pii_ssn": true, "pii_email": false}
	for _, e := range got {
		id, _ := e.Details["policy_id"].(string)
		blocked, ok := want[id]
		if !ok {
			t.Errorf("unexpected policy_id %q", id)
			continue
		}
		if e.Details["blocked"] != blocked {
			t.Errorf("%s: blocked = %v, want %v", id, e.Details["blocked"], blocked)
		}
		if e.OrgID != "org-a" || e.TenantID != "tenant-a" || e.Type != AuditTypeMetric {
			t.Errorf("%s: org %q tenant %q type %q, want org-a, tenant-a, metric", id, e.OrgID, e.TenantID, e.Type)
		}
	}

	t.Run("an evaluation that matched nothing writes nothing", func(t *testing.T) {
		if err := adapter.LogPolicyEvaluation(sharedpolicy.PolicyEvaluationEntry{Type: "request", OrgID: "org-a"}); err != nil {
			t.Fatal(err)
		}
		if n := len(drainMetrics(aq)); n != 0 {
			t.Fatalf("got %d entries for an evaluation with no match", n)
		}
	})
}

// A FLUSH IS ONE UPSERT PER ORGANIZATION, aggregated by policy, keyed on the
// partial unique index core/186 creates: (org_id, policy_id, date) WHERE
// policy_id IS NOT NULL.
func TestAMetricsFlushIsOneAggregatedUpsertPerOrganization(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	aq := unstartedQueue(t, AuditModePerformance, 10)
	aq.db = db
	conflict := regexp.QuoteMeta("ON CONFLICT (org_id, policy_id, date) WHERE policy_id IS NOT NULL DO UPDATE SET")
	// org-a: sys_pii_email once (not blocked), sys_pii_ssn twice (one blocked).
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(conflict).WithArgs("org-a", "sys_pii_email", 1, 0, "sys_pii_ssn", 2, 1).WillReturnResult(sqlmock.NewResult(2, 2))
	mock.ExpectCommit()
	// org-b: sys_pii_ssn once, blocked.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).WithArgs("org-b").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(conflict).WithArgs("org-b", "sys_pii_ssn", 1, 1).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	aq.flushMetricsBatch([]AuditEntry{
		{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": true}},
		{OrgID: "org-b", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": true}},
		{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_email", "blocked": false}},
		{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "sys_pii_ssn", "blocked": false}},
	})
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEveryAuditDropSiteIsCounted(t *testing.T) {
	t.Run("the metrics channel is full", func(t *testing.T) {
		aq := unstartedQueue(t, AuditModePerformance, 1)
		before := droppedAt(auditDropMetricsQueueFull)
		_ = aq.LogMetric(AuditEntry{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "p1"}})
		_ = aq.LogMetric(AuditEntry{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "p2"}})
		if got := droppedAt(auditDropMetricsQueueFull) - before; got != 1 {
			t.Fatalf("metrics_queue_full moved by %v, want 1", got)
		}
	})

	t.Run("a metrics entry with no organization", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		aq := unstartedQueue(t, AuditModePerformance, 10)
		aq.db = db
		before := droppedAt(auditDropMetricsNoOrg)
		aq.flushMetricsBatch([]AuditEntry{{Details: map[string]interface{}{"policy_id": "p1"}}})
		if got := droppedAt(auditDropMetricsNoOrg) - before; got != 1 {
			t.Fatalf("metrics_no_org moved by %v, want 1", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("an entry with no organization reached the database: %v", err)
		}
	})

	t.Run("the metrics write fails permanently: one attempt, every entry counted", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		aq := unstartedQueue(t, AuditModePerformance, 10)
		aq.db = db
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO policy_metrics").WillReturnError(&pq.Error{Code: "42P10", Message: "there is no unique or exclusion constraint matching the ON CONFLICT specification"})
		mock.ExpectRollback()
		// A retry would consume this; a permanent failure must leave it.
		mock.ExpectBegin()
		before := droppedAt(auditDropMetricsWriteFailed)
		aq.flushMetricsBatch([]AuditEntry{
			{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "p1"}},
			{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "p2"}},
		})
		if got := droppedAt(auditDropMetricsWriteFailed) - before; got != 2 {
			t.Fatalf("metrics_write_failed moved by %v, want 2 (both entries)", got)
		}
		if err := mock.ExpectationsWereMet(); err == nil {
			t.Fatal("a permanent failure was retried: the second attempt's BEGIN was consumed")
		}
	})

	t.Run("the metrics write fails transiently: tried three times, then counted", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		aq := unstartedQueue(t, AuditModePerformance, 10)
		aq.db = db
		for i := 0; i < 3; i++ {
			mock.ExpectBegin().WillReturnError(errors.New("dial tcp 10.0.0.1:5432: connect: connection refused"))
		}
		before := droppedAt(auditDropMetricsWriteFailed)
		aq.flushMetricsBatch([]AuditEntry{{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "p1"}}})
		if got := droppedAt(auditDropMetricsWriteFailed) - before; got != 1 {
			t.Fatalf("metrics_write_failed moved by %v, want 1", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("a transient failure was not retried three times: %v", err)
		}
	})

	t.Run("a violation that cannot be written (compliance mode, no organization)", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		aq := unstartedQueue(t, AuditModeCompliance, 10)
		aq.db = db
		adapter := &SharedPolicyAuditAdapter{queue: aq}
		before := droppedAt(auditDropViolationWriteFailed)
		err = adapter.LogViolation(sharedpolicy.AuditEntry{
			Type:    "violation",
			Details: map[string]interface{}{"policy_id": "p1", "policy_name": "P1"},
		})
		if err == nil {
			t.Fatal("PREMISE: a violation with no organization was written")
		}
		if got := droppedAt(auditDropViolationWriteFailed) - before; got != 1 {
			t.Fatalf("violation_write_failed moved by %v, want 1", got)
		}
	})

	t.Run("a queued entry whose database and fallback writes both fail", func(t *testing.T) {
		aq := unstartedQueue(t, AuditModePerformance, 10)
		_ = aq.fallbackFile.Close() // the fallback write now fails
		aq.queue <- AuditEntry{Type: AuditTypeViolation, Details: map[string]interface{}{"policy_name": "P1"}}
		close(aq.queue)
		before := droppedAt(auditDropFallbackWriteFailed)
		aq.wg.Add(1)
		aq.worker(0) // aq.db is nil: every write fails
		if got := droppedAt(auditDropFallbackWriteFailed) - before; got != 1 {
			t.Fatalf("fallback_write_failed moved by %v, want 1", got)
		}
	})
}

// A FALLBACK ENTRY THAT CAN NEVER BE WRITTEN IS NOT RE-PENDED FOREVER, AND IS
// NOT DELETED EITHER: it is retried on maxFallbackRecoveryAttempts startups,
// then moved, byte for byte, to the dead-letter file beside the fallback file
// (same mode), and counted. Before #4249 it stayed pending forever; the first
// cut of this change deleted it, which round 2 of the hostile review caught.
func TestAnExhaustedFallbackEntryMovesToTheDeadLetterFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fallback.jsonl")
	entry := AuditEntry{Type: AuditTypeViolation, Details: map[string]interface{}{"policy_name": "P1"}} // no OrgID: never writable
	raw, _ := json.Marshal(entry)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	aq := unstartedQueue(t, AuditModeCompliance, 10)
	aq.db = db

	before := droppedAt(auditDropRecoveryExhausted)
	for attempt := 1; attempt < maxFallbackRecoveryAttempts; attempt++ {
		if _, err := aq.RecoverFromFallback(path); err != nil {
			t.Fatal(err)
		}
		pending := readFallback(t, path)
		if len(pending) != 1 || pending[0].RecoveryAttempts != attempt {
			t.Fatalf("after startup %d the fallback holds %+v, want the entry with recovery_attempts %d", attempt, pending, attempt)
		}
		if droppedAt(auditDropRecoveryExhausted) != before {
			t.Fatalf("the entry was dropped after %d attempts, before the bound %d", attempt, maxFallbackRecoveryAttempts)
		}
	}
	lastLine, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aq.RecoverFromFallback(path); err != nil {
		t.Fatal(err)
	}
	if got := droppedAt(auditDropRecoveryExhausted) - before; got != 1 {
		t.Fatalf("recovery_exhausted moved by %v after attempt %d, want 1", got, maxFallbackRecoveryAttempts)
	}
	if pending := readFallback(t, path); len(pending) != 0 {
		t.Fatalf("the exhausted entry is still pending: %+v", pending)
	}
	dead, err := os.ReadFile(path + ".dead.jsonl")
	if err != nil {
		t.Fatalf("the exhausted entry was not kept in the dead-letter file: %v", err)
	}
	if string(dead) != string(lastLine) {
		t.Fatalf("the dead-letter file holds %q, want the fallback line byte for byte: %q", dead, lastLine)
	}
	info, err := os.Stat(path + ".dead.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("the dead-letter file's mode is %o, want the fallback file's 600", mode)
	}
}

func readFallback(t *testing.T, path string) []AuditEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []AuditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// A DROP IS LOGGED AT MOST ONCE A MINUTE PER SITE, and the next line says how
// many it did not log.
func TestADropSiteLogsAtABoundedRate(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	auditDropLogMu.Lock()
	prevNow, prevLogf := auditDropNow, auditDropLogf
	auditDropNow = func() time.Time { return now }
	auditDropLogf = func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	delete(auditDropLog, "test_site")
	auditDropLogMu.Unlock()
	t.Cleanup(func() {
		auditDropLogMu.Lock()
		auditDropNow, auditDropLogf = prevNow, prevLogf
		auditDropLogMu.Unlock()
	})

	before := droppedAt("test_site")
	for i := 0; i < 5; i++ {
		recordAuditDrop("test_site", "entry %d", i)
	}
	auditDropLogMu.Lock()
	now = now.Add(auditDropLogInterval)
	auditDropLogMu.Unlock()
	recordAuditDrop("test_site", "entry 5")

	if got := droppedAt("test_site") - before; got != 6 {
		t.Fatalf("the counter moved by %v, want 6: every drop is counted", got)
	}
	if len(lines) != 2 {
		t.Fatalf("logged %d lines, want 2 (the first, then one after the interval): %q", len(lines), lines)
	}
	if !strings.Contains(lines[1], "and 4 more since the last line") {
		t.Fatalf("the second line does not count the suppressed drops: %q", lines[1])
	}
}

// A COMPLIANCE-MODE VIOLATION WHOSE WRITE A RETRY CAN CURE IS KEPT, in the
// fallback file, as performance mode keeps it; one that can never be written is
// returned (and counted by the adapter).
func TestAComplianceModeViolationIsKeptWhenItsWriteFailsTransiently(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	aq := unstartedQueue(t, AuditModeCompliance, 10)
	aq.db = db
	for i := 0; i < 3; i++ {
		mock.ExpectBegin().WillReturnError(errors.New("dial tcp 10.0.0.1:5432: connect: connection refused"))
	}
	entry := AuditEntry{OrgID: "org-a", Severity: "high", Details: map[string]interface{}{"policy_name": "P1", "policy_id": "p1"}}
	if err := aq.LogViolation(entry); err != nil {
		t.Fatalf("a transient failure was returned (%v); want the entry kept", err)
	}
	pending := readFallback(t, aq.fallbackFile.Name())
	if len(pending) != 1 || pending[0].OrgID != "org-a" || pending[0].Type != AuditTypeViolation {
		t.Fatalf("the fallback file holds %+v, want the violation", pending)
	}

	t.Run("a permanent failure is returned, not kept", func(t *testing.T) {
		aq := unstartedQueue(t, AuditModeCompliance, 10)
		aq.db = db
		if err := aq.LogViolation(AuditEntry{Details: map[string]interface{}{"policy_name": "P1"}}); err == nil {
			t.Fatal("a violation with no organization was accepted")
		}
		if pending := readFallback(t, aq.fallbackFile.Name()); len(pending) != 0 {
			t.Fatalf("a never-writable violation was kept: %+v", pending)
		}
	})
}

// A TRANSIENT RECOVERY FAILURE SPENDS NO ATTEMPT, so a database that is
// reachable but failing over for five startups does not drop compliance rows.
func TestATransientRecoveryFailureSpendsNoAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fallback.jsonl")
	raw, _ := json.Marshal(AuditEntry{Type: AuditTypeViolation, OrgID: "org-a", Details: map[string]interface{}{"policy_name": "P1"}})
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	mock.MatchExpectationsInOrder(false)
	for i := 0; i < 3*(maxFallbackRecoveryAttempts+1); i++ {
		mock.ExpectBegin().WillReturnError(errors.New("dial tcp 10.0.0.1:5432: connect: connection refused"))
	}
	aq := unstartedQueue(t, AuditModeCompliance, 10)
	aq.db = db
	before := droppedAt(auditDropRecoveryExhausted)
	for i := 0; i < maxFallbackRecoveryAttempts+1; i++ {
		if _, err := aq.RecoverFromFallback(path); err != nil {
			t.Fatal(err)
		}
	}
	pending := readFallback(t, path)
	if len(pending) != 1 || pending[0].RecoveryAttempts != 0 {
		t.Fatalf("after %d transient failures the fallback holds %+v, want the entry with no attempt spent", maxFallbackRecoveryAttempts+1, pending)
	}
	if droppedAt(auditDropRecoveryExhausted) != before {
		t.Fatal("a transiently failing entry was dropped")
	}
}

// THE REWRITE REOPENS THE QUEUE'S FALLBACK FILE. Recovery replaces the file by
// rename; the queue's open descriptor would otherwise keep appending to the
// replaced file, and every later fallback write would be lost.
func TestAFallbackWriteAfterRecoveryLandsInTheLiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fallback.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(AuditEntry{Type: AuditTypeViolation, Details: map[string]interface{}{"policy_name": "never"}}) // no OrgID
	if _, err := f.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	aq := &AuditQueue{mode: AuditModeCompliance, queue: make(chan AuditEntry, 1), metricsBatch: make(chan AuditEntry, 1), fallbackFile: f, db: db}
	t.Cleanup(func() { _ = aq.fallbackFile.Close() })
	if _, err := aq.RecoverFromFallback(path); err != nil {
		t.Fatal(err)
	}
	aq.mu.Lock()
	if err := aq.writeToFallback(AuditEntry{Type: AuditTypeViolation, OrgID: "org-a", Details: map[string]interface{}{"policy_name": "after"}}); err != nil {
		aq.mu.Unlock()
		t.Fatal(err)
	}
	aq.mu.Unlock()
	pending := readFallback(t, path)
	if len(pending) != 2 || pending[1].Details["policy_name"] != "after" {
		t.Fatalf("the live fallback file holds %+v, want the re-pended entry and the one written after recovery", pending)
	}
}

func TestAnUnparseableFallbackLineAndAMetricAfterShutdownAreCounted(t *testing.T) {
	t.Run("an unparseable line", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fallback.jsonl")
		if err := os.WriteFile(path, []byte("{not json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		aq := unstartedQueue(t, AuditModeCompliance, 10)
		before := droppedAt(auditDropFallbackUnparseable)
		if _, err := aq.RecoverFromFallback(path); err != nil {
			t.Fatal(err)
		}
		if got := droppedAt(auditDropFallbackUnparseable) - before; got != 1 {
			t.Fatalf("fallback_unparseable moved by %v, want 1", got)
		}
	})
	t.Run("a metric after shutdown", func(t *testing.T) {
		aq := unstartedQueue(t, AuditModePerformance, 10)
		aq.closed.Store(true)
		close(aq.metricsBatch)
		before := droppedAt(auditDropMetricsAfterShutdown)
		if err := aq.LogMetric(AuditEntry{OrgID: "org-a", Details: map[string]interface{}{"policy_id": "p1"}}); err != nil {
			t.Fatal(err)
		}
		if got := droppedAt(auditDropMetricsAfterShutdown) - before; got != 1 {
			t.Fatalf("metrics_after_shutdown moved by %v, want 1 (and no panic)", got)
		}
	})
}

// A REOPEN THAT FAILS AFTER THE REWRITE IS COUNTED, not reported as a rewrite
// that did not happen.
func TestAFallbackReopenThatFailsAfterTheRewriteIsCounted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fallback.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(AuditEntry{Type: AuditTypeViolation, OrgID: "org-a", Details: map[string]interface{}{"policy_name": "pending"}})
	if _, err := f.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	aq := &AuditQueue{mode: AuditModeCompliance, queue: make(chan AuditEntry, 1), metricsBatch: make(chan AuditEntry, 1), fallbackFile: f} // no db: the entry fails transiently and stays pending
	t.Cleanup(func() { _ = aq.fallbackFile.Close() })
	prev := auditFallbackOpen
	auditFallbackOpen = func(string) (*os.File, error) { return nil, errors.New("planted reopen failure") }
	t.Cleanup(func() { auditFallbackOpen = prev })

	before := droppedAt(auditDropFallbackReopenFailed)
	if _, err := aq.RecoverFromFallback(path); err != nil {
		t.Fatal(err)
	}
	if got := droppedAt(auditDropFallbackReopenFailed) - before; got != 1 {
		t.Fatalf("fallback_reopen_failed moved by %v, want 1", got)
	}
	if pending := readFallback(t, path); len(pending) != 1 {
		t.Fatalf("the rewrite did not happen: the fallback holds %+v", pending)
	}
}

// NO SEND LANDS ON A CLOSED CHANNEL. Metrics are recorded on goroutines, so a
// LogMetric or a queued entry can race Shutdown; sendMu makes the closed check
// and the send one step against the close. Run under -race.
func TestConcurrentSendsDuringShutdownNeverPanic(t *testing.T) {
	aq := unstartedQueue(t, AuditModePerformance, 4)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				_ = aq.LogMetric(AuditEntry{OrgID: "org-a", Details: map[string]interface{}{"policy_id": fmt.Sprintf("p%d", i)}})
				_ = aq.queueEntry(AuditEntry{Type: AuditTypeViolation, OrgID: "org-a", Details: map[string]interface{}{"policy_name": "P"}})
			}
		}(i)
	}
	close(start)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = aq.Shutdown(ctx)
	wg.Wait()
}

// AN EXHAUSTED ENTRY WHOSE DEAD-LETTER WRITE FAILS STAYS PENDING: it is not
// counted as set aside, and its spent attempts are kept on disk.
func TestAnExhaustedEntryWhoseDeadLetterWriteFailsStaysPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fallback.jsonl")
	entry := AuditEntry{Type: AuditTypeViolation, Details: map[string]interface{}{"policy_name": "P1"}, RecoveryAttempts: maxFallbackRecoveryAttempts - 1} // no OrgID: never writable
	raw, _ := json.Marshal(entry)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory where the dead-letter file would go: the append fails.
	if err := os.Mkdir(path+".dead.jsonl", 0o700); err != nil {
		t.Fatal(err)
	}
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	aq := unstartedQueue(t, AuditModeCompliance, 10)
	aq.db = db

	before := droppedAt(auditDropRecoveryExhausted)
	if _, err := aq.RecoverFromFallback(path); err != nil {
		t.Fatal(err)
	}
	if got := droppedAt(auditDropRecoveryExhausted) - before; got != 0 {
		t.Fatalf("recovery_exhausted moved by %v although nothing was set aside", got)
	}
	pending := readFallback(t, path)
	if len(pending) != 1 || pending[0].RecoveryAttempts != maxFallbackRecoveryAttempts {
		t.Fatalf("the fallback holds %+v, want the entry still pending with recovery_attempts %d", pending, maxFallbackRecoveryAttempts)
	}
}

// A COMPLIANCE-MODE VIOLATION WHOSE WRITE FAILS WITH A POSTGRES-PERMANENT CLASS
// IS KEPT, not returned: a revoked grant (42501) is fixable, and recovery's
// bound sets an entry that never succeeds aside instead of deleting it.
func TestAComplianceModeViolationWithAPermanentPostgresFailureIsKept(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	aq := unstartedQueue(t, AuditModeCompliance, 10)
	aq.db = db
	for i := 0; i < 3; i++ {
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO policy_violations").WillReturnError(&pq.Error{Code: "42501", Message: "permission denied for table policy_violations"})
		mock.ExpectRollback()
	}
	entry := AuditEntry{OrgID: "org-a", Severity: "high", Details: map[string]interface{}{"policy_name": "P1", "policy_id": "p1"}}
	if err := aq.LogViolation(entry); err != nil {
		t.Fatalf("a 42501 was returned (%v); want the entry kept in the fallback", err)
	}
	pending := readFallback(t, aq.fallbackFile.Name())
	if len(pending) != 1 || pending[0].OrgID != "org-a" || pending[0].Details["policy_name"] != "P1" {
		t.Fatalf("the fallback file holds %+v, want the violation", pending)
	}
}
