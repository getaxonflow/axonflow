//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// #2840 — client NUL / control bytes on the OTLP ingest planes.
//
// Postgres rejects 0x00 in text/varchar/jsonb, and strings.ToValidUTF8
// PRESERVES U+0000 (it is a valid code point), so before this fix one NUL in
// any client-supplied field lost the audit row on the logs plane and
// wholesale-400'd the entire batch on the metrics plane. These tests pin the
// fix: NUL and the other C0/DEL controls are stripped BEFORE any INSERT, the
// row LANDS sanitized (the audit store captures the event instead of dropping
// it), the persist-then-sign contract holds, and sibling datapoints survive.

package agent

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

// Pin the root cause so nobody "simplifies" the sanitizer back to ToValidUTF8:
// U+0000 IS valid UTF-8 and survives ToValidUTF8 unchanged.
func TestSanitizeOTELText_ToValidUTF8AloneIsNotEnough(t *testing.T) {
	if got := strings.ToValidUTF8("x\x00y", ""); !strings.Contains(got, "\x00") {
		t.Fatal("premise broken: strings.ToValidUTF8 no longer preserves NUL — revisit sanitizeOTELText")
	}
}

func TestSanitizeOTELText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"x\x00y", "xy"},                                   // NUL stripped
		{"a\x01\x02\x08b", "ab"},                           // C0 controls stripped
		{"del\x7fchar", "delchar"},                         // DEL stripped
		{"line1\nline2\ttab\rcr", "line1\nline2\ttab\rcr"}, // prose whitespace survives
		{"caf\xc3\xa9", "café"},                            // valid multibyte untouched
		{"bad\xff\xfeutf8", "badutf8"},                     // invalid UTF-8 repaired
		{"", ""},
	}
	for _, c := range cases {
		if got := sanitizeOTELText(c.in); got != c.want {
			t.Errorf("sanitizeOTELText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// truncateOTELString composes slice + sanitize (mid-rune cut repaired, NUL gone).
	if got := truncateOTELString("ab\x00cd", 10); got != "abcd" {
		t.Errorf("truncateOTELString NUL: got %q", got)
	}
}

// Logs plane: a user_prompt whose content, user.email, and session.id all carry
// NUL/control bytes LANDS as a sanitized canonical row (not lost), and the
// persist-then-sign contract completes — the chain entry exists and verifies.
func TestCoworkOTEL_NULInClientFields_SanitizedRowLandsAndSigned(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact)
	tr := withMemoryChainTracker(t)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	var emailCap, queryCap, sessCap, decisionIDCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[4] = capStr{&emailCap}       // user_email
	args[10] = capStr{&queryCap}      // query
	args[19] = capStr{&decisionIDCap} // decision_id
	args[23] = capStr{&sessCap}       // session_id
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "claude-code")},
		"claude_code.user_prompt",
		[]*commonpb.KeyValue{
			strAttr("prompt", "first line\x00\x01 second\nline"),
			strAttr("user.email", "andi\x00@acme-eval.example"),
			strAttr("session.id", "sess-\x00nul-1"),
			strAttr("prompt.id", "prompt-nul-1"),
		},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the sanitized row must LAND (not be dropped): %v", err)
	}

	for name, v := range map[string]string{"user_email": emailCap, "query": queryCap, "session_id": sessCap} {
		if strings.ContainsAny(v, "\x00\x01") {
			t.Errorf("%s reached the INSERT with control bytes: %q", name, v)
		}
	}
	if emailCap != "andi@acme-eval.example" {
		t.Errorf("user_email: got %q want NUL stripped in place", emailCap)
	}
	if !strings.Contains(queryCap, "second\nline") {
		t.Errorf("prose newline must survive sanitization, got %q", queryCap)
	}

	// Persist succeeded → the signed chain entry must exist AND verify (no
	// dangling entry, no missing entry).
	res, found, verr := tr.VerifyChain(context.Background(), "org-auth", decisionIDCap)
	if verr != nil || !found {
		t.Fatalf("chain entry for persisted row: found=%v err=%v", found, verr)
	}
	if !res.Valid {
		t.Fatalf("chain entry does not verify: %q", res.BreakReason)
	}
}

// R3 MED-2 pin: NUL in the tool_name / decision descriptor identifiers of a
// tool_decision event must be sanitized — a blocked tool decision is exactly
// the row a hostile client wants lost (audit-evasion class). Reverting the
// truncateOTELString on either identifier goes red here.
func TestCoworkOTEL_NULInToolDescriptor_SanitizedRowLands(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	var queryCap, verdictCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[10] = capStr{&queryCap}   // query (descriptor)
	args[12] = capStr{&verdictCap} // policy_decision
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.tool_decision",
		[]*commonpb.KeyValue{
			strAttr("tool_name", "delete\x00_files"),
			strAttr("decision", "reject\x00ed"),
		},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "c1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the sanitized tool_decision row must LAND: %v", err)
	}
	if strings.Contains(queryCap, "\x00") {
		t.Fatalf("descriptor reached the INSERT with NUL: %q", queryCap)
	}
	if !strings.Contains(queryCap, "delete_files") || !strings.Contains(queryCap, "rejected") {
		t.Errorf("descriptor identifiers should be NUL-stripped in place, got %q", queryCap)
	}
	if verdictCap != "blocked" {
		t.Errorf("verdict: got %q want blocked (isRejectDecision must see the sanitized value)", verdictCap)
	}
}

// R3 L1 pin: an all-control record-level identity value must NOT shadow a
// valid resource-level fallback — sanitize each candidate, then pick.
func TestCoworkOTEL_AllControlIdentity_FallsBackToResource(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	var emailCap, sessCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[4] = capStr{&emailCap}
	args[23] = capStr{&sessCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{
			strAttr("service.name", "claude-code"),
			strAttr("session.id", "sess-resource-1"),
			strAttr("user.email", "resource@acme-eval.example"),
		},
		"claude_code.user_prompt",
		[]*commonpb.KeyValue{
			strAttr("prompt", "hello"),
			strAttr("user.email", "\x00"), // all-control record-level value
			strAttr("session.id", "\x00\x01"),
		},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "c1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	if emailCap != "resource@acme-eval.example" {
		t.Errorf("user_email: got %q want the resource-level fallback (all-control record value must not shadow it)", emailCap)
	}
	if sessCap != "sess-resource-1" {
		t.Errorf("session_id: got %q want the resource-level fallback", sessCap)
	}
}

// Metrics plane: a datapoint whose session.id / user.email / allowlisted attr
// values carry NUL is stored SANITIZED, and the clean sibling datapoint in the
// same batch is untouched — the batch is NOT wholesale-400'd.
func TestCoworkOTELMetrics_NULInClientFields_SanitizedNotWholesaleRejected(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	expectMetricsUsageTx(mock, "org-auth")

	// Row 1: the NUL-carrying datapoint, sanitized.
	var sessCap, emailCap string
	var attrsCap []byte
	a1 := metricInsertArgs()
	a1[4] = capStr{&sessCap}
	a1[5] = capStr{&emailCap}
	a1[11] = capBytes{&attrsCap}
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a1...).WillReturnResult(sqlmock.NewResult(1, 1))
	// Row 2: the clean sibling survives.
	a2 := metricInsertArgs()
	a2[7] = float64(300)
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a2...).WillReturnResult(sqlmock.NewResult(2, 1))
	mock.ExpectCommit()

	req := coworkMetricsReq(
		[]*commonpb.KeyValue{
			strAttr("service.name", "claude-code"),
			strAttr("session.id", "sess-\x00metrics"),
			strAttr("user.email", "dev\x00@acme-eval.example"),
		},
		sumMetric(metricFixture{
			name: "claude_code.token.usage", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points: []*metricspb.NumberDataPoint{
				dpInt(1200, strAttr("type", "input"), strAttr("model", "claude\x00-sonnet-5")),
				dpInt(300, strAttr("type", "output"), strAttr("model", "claude-sonnet-5")),
			},
		}),
	)

	rr := postCoworkMetrics(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (batch must not be wholesale-rejected), body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("both rows must land: %v", err)
	}
	resp := decodeMetricsResponse(t, rr, contentTypeProtobuf)
	if got := resp.GetPartialSuccess().GetRejectedDataPoints(); got != 0 {
		t.Errorf("rejected: got %d want 0 (sanitize, don't reject)", got)
	}
	if strings.Contains(sessCap, "\x00") || strings.Contains(emailCap, "\x00") {
		t.Errorf("identity columns reached the INSERT with NUL: sess=%q email=%q", sessCap, emailCap)
	}
	var storedAttrs map[string]string
	if err := json.Unmarshal(attrsCap, &storedAttrs); err != nil {
		t.Fatalf("metric_attributes not JSON: %v", err)
	}
	if strings.Contains(storedAttrs["model"], "\x00") {
		t.Errorf("allowlisted attr value reached JSONB with NUL: %q", storedAttrs["model"])
	}
	if storedAttrs["model"] != "claude-sonnet-5" {
		t.Errorf("model attr: got %q want NUL stripped in place", storedAttrs["model"])
	}
}

// Real-Postgres regression for #2840, both planes: Postgres genuinely rejects
// 0x00 (the failure class this fix prevents), so prove against a LIVE database
// that (a) a NUL-carrying logs record LANDS as a sanitized audit row, (b) a
// NUL-carrying metrics batch stores BOTH the sanitized and the clean sibling
// datapoint at HTTP 200 (no wholesale-400), and that Postgres would indeed have
// rejected the raw value (premise pin).
//
// Gated on TEST_PG_INTEGRATION=1 + docker, same as the sibling realpg tests.
func TestOTELIngest_NUL_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres integration test")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	withCoworkRedactor(t, DetectionActionRedact)

	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	for _, kv := range []struct{ key, val string }{
		{"app.db_password", "testpass"},
		{"app.deployment_org_id", "local-dev-org"},
		{"app.deployment_kind", "dev"},
		{"app.current_org_id", "nul-org"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", kv.key, kv.val); err != nil {
			t.Fatalf("set_config %s: %v", kv.key, err)
		}
	}
	applyAllCoreMigrations(t, db, "../../migrations/core")

	// Premise pin: Postgres rejects a raw NUL — this is the exact failure the
	// sanitizer prevents from ever reaching an INSERT.
	if _, err := db.Exec(`SELECT $1::text`, "x\x00y"); err == nil {
		t.Fatal("premise broken: Postgres accepted a NUL in text — revisit whether sanitization is still needed")
	}

	// audit_logs may or may not be created by the core chain depending on the
	// migration set; ensure the columns the writer targets exist (same shape
	// the sibling realpg test uses — the 059+119+121+129 union).
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_logs (
			id               VARCHAR(255) PRIMARY KEY,
			request_id       VARCHAR(255),
			timestamp        TIMESTAMPTZ,
			user_id          INTEGER,
			user_email       VARCHAR(255),
			user_role        VARCHAR(255),
			client_id        VARCHAR(255),
			tenant_id        VARCHAR(255),
			org_id           VARCHAR(255),
			request_type     VARCHAR(255),
			query            TEXT,
			query_hash       VARCHAR(255),
			policy_decision  VARCHAR(50) NOT NULL,
			policy_details   JSONB,
			provider         VARCHAR(50),
			model            VARCHAR(100),
			response_time_ms BIGINT,
			tokens_used      INTEGER,
			cost             DECIMAL(10,6),
			decision_id      VARCHAR(255),
			plane            VARCHAR(50),
			correlation_id   VARCHAR(255),
			redacted_fields  JSONB,
			session_id       VARCHAR(255)
		)`); err != nil {
		t.Fatalf("create audit_logs: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO organizations (org_id, name, license_key, tier)
		VALUES ('nul-org', 'nul-org', 'lic-nul', 'ENTERPRISE') ON CONFLICT (org_id) DO NOTHING
	`); err != nil {
		t.Fatalf("seed organizations: %v", err)
	}

	origDB := usageDB
	usageDB = db
	t.Cleanup(func() { usageDB = origDB })

	// --- Leg 1: logs plane -------------------------------------------------
	logsReq := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "claude-code")},
		"claude_code.user_prompt",
		[]*commonpb.KeyValue{
			strAttr("prompt", "hostile\x00prompt with\nnewline"),
			strAttr("user.email", "andi\x00@acme-eval.example"),
			strAttr("session.id", "sess-nul-pg-1"),
		},
	)
	rr := postCoworkLogs(t, authCtx("nul-org", "tenant-nul", "client-1"), contentTypeProtobuf, logsReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("logs ingest status %d body %s", rr.Code, rr.Body.String())
	}
	var query, email string
	if err := db.QueryRow(`
		SELECT query, user_email FROM audit_logs WHERE session_id='sess-nul-pg-1'
	`).Scan(&query, &email); err != nil {
		t.Fatalf("the NUL-carrying record must LAND as a sanitized audit row: %v", err)
	}
	if strings.Contains(query, "\x00") || strings.Contains(email, "\x00") {
		t.Fatalf("NUL persisted: query=%q email=%q", query, email)
	}
	if email != "andi@acme-eval.example" {
		t.Errorf("user_email: got %q want NUL stripped in place", email)
	}
	if !strings.Contains(query, "with\nnewline") {
		t.Errorf("prose newline must survive: %q", query)
	}

	// --- Leg 2: metrics plane ----------------------------------------------
	metricsReq := coworkMetricsReq(
		[]*commonpb.KeyValue{
			strAttr("service.name", "claude-code"),
			strAttr("session.id", "sess-nul-pg-m"),
			strAttr("user.email", "dev\x00@acme-eval.example"),
		},
		sumMetric(metricFixture{
			name: "claude_code.token.usage", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points: []*metricspb.NumberDataPoint{
				dpInt(1200, strAttr("type", "input"), strAttr("model", "claude\x00-sonnet-5")),
				dpInt(300, strAttr("type", "output"), strAttr("model", "claude-sonnet-5")),
			},
		}),
	)
	rrM := postCoworkMetrics(t, authCtx("nul-org", "tenant-nul", "client-1"), contentTypeProtobuf, metricsReq)
	if rrM.Code != http.StatusOK {
		t.Fatalf("metrics ingest status %d (must NOT wholesale-reject) body %s", rrM.Code, rrM.Body.String())
	}
	var rows int
	if err := db.QueryRow(`
		SELECT count(*) FROM usage_events WHERE session_id='sess-nul-pg-m' AND event_type='claude_code_metric'
	`).Scan(&rows); err != nil {
		t.Fatalf("count metric rows: %v", err)
	}
	if rows != 2 {
		t.Fatalf("metric rows: got %d want 2 (NUL datapoint sanitized AND clean sibling stored)", rows)
	}
	var email2, model2 string
	if err := db.QueryRow(`
		SELECT user_email, COALESCE(metric_attributes->>'model','')
		  FROM usage_events WHERE session_id='sess-nul-pg-m' ORDER BY id LIMIT 1
	`).Scan(&email2, &model2); err != nil {
		t.Fatalf("read metric row: %v", err)
	}
	if email2 != "dev@acme-eval.example" {
		t.Errorf("metric user_email: got %q want NUL stripped in place", email2)
	}
	if model2 != "claude-sonnet-5" {
		t.Errorf("allowlisted attr through JSONB: got %q want NUL stripped in place", model2)
	}
}
