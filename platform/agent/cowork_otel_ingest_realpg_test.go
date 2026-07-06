//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres E2E for WS-6 (#2760): a faithful OTLP fixture (a Cowork
// user_prompt carrying a NIK + an api_request) is POSTed through the REAL
// coworkOTELLogsHandler over a LIVE Postgres (no sqlmock). It asserts the events
// land as CANONICAL audit_logs rows — redacted at the collector, tenant-tagged
// from auth, keyed by session_id/prompt.id — and are QUERYABLE BY SESSION + USER
// (the read the unified session-summary #2759 performs). The raw NIK must appear
// nowhere in the table.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (testcontainers postgres), same as the
// other *_realpg_test.go integration tests. Runs in the enterprise-realpg CI job.

import (
	"context"
	"os"
	"strings"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	sharedaudit "axonflow/platform/shared/audit"
	"axonflow/platform/testutil"
)

// coworkEventFixture is a (name, attrs) pair for building a multi-record OTLP
// req (consumed by coworkLogsReqRealShaped in cowork_otel_ingest_test.go, which
// builds the REAL wire shape: eventName absent, prefixed body, identity per
// record — #2838).
type coworkEventFixture struct {
	name  string
	attrs []*commonpb.KeyValue
}

func TestCoworkOTEL_RealPostgres_RedactedQueryableBySession(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres integration test")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	withCoworkRedactor(t, DetectionActionRedact) // detection ON + non-nil engine (passes fail-closed gate)

	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	db := pg.DB

	// audit_logs shaped as the union of migrations 059 + 119 + 121 + 129
	// (session_id) — the exact columns writeCoworkAuditLog's INSERT targets.
	if _, err := db.Exec(`
		CREATE TABLE audit_logs (
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

	origDB := usageDB
	usageDB = db
	t.Cleanup(func() { usageDB = origDB })

	const sessionID = "sess-e2e-1"
	const userEmail = "andi@acme-eval.example"
	const nik = coworkValidNIK

	// REAL attribute placement (#2838): identity/session per LOG RECORD (with a
	// telemetry-spoofed organization.id that must NOT become org_id), resource
	// block identity-free, top-level eventName ABSENT (prefixed name in body,
	// unprefixed in the event.name attribute) — the shape a real captured
	// Claude Code / Cowork export has on the wire.
	identity := func() []*commonpb.KeyValue {
		return append(realShapedIdentityAttrs(userEmail, sessionID),
			strAttr("organization.id", "org-SPOOFED"))
	}
	req := coworkLogsReqRealShaped("cowork",
		[]coworkEventFixture{
			{name: "cowork.user_prompt", attrs: append(identity(),
				strAttr("prompt", "Cek pelanggan NIK "+nik),
				strAttr("prompt.id", "prompt-e2e-1"),
			)},
			{name: "cowork.api_request", attrs: append(identity(),
				strAttr("model", "claude-sonnet-4-6"),
				intAttr("input_tokens", 90),
				intAttr("output_tokens", 50),
				dblAttr("cost_usd", 0.02),
				strAttr("prompt.id", "prompt-e2e-1"),
			)},
			{name: "cowork.assistant_response", attrs: append(identity(),
				strAttr("response", "Ditemukan: NIK "+nik+" atas nama pelanggan"),
				strAttr("model", "claude-sonnet-4-6"),
				strAttr("prompt.id", "prompt-e2e-1"),
			)},
		},
	)

	ctx := context.WithValue(context.Background(), ContextKeyOrgID, "org-auth")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "tenant-dp")
	ctx = context.WithValue(ctx, ContextKeyClientID, "client-1")
	rr := postCoworkLogs(t, ctx, contentTypeProtobuf, req)
	if rr.Code != 200 {
		t.Fatalf("ingest status %d body %s", rr.Code, rr.Body.String())
	}

	// --- queryable BY SESSION + USER (the session-summary read) ---------------
	var total int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE session_id=$1 AND user_email=$2`,
		sessionID, userEmail).Scan(&total); err != nil {
		t.Fatalf("count by session/user: %v", err)
	}
	if total != 3 {
		t.Fatalf("rows queryable by session+user: got %d want 3 (identity travels on the LOG RECORDS — #2838)", total)
	}

	// --- the user_prompt row: redacted, canonical, correlated -----------------
	var verdict, query, plane, corr, redFields string
	if err := db.QueryRow(`
		SELECT policy_decision, query, plane, COALESCE(correlation_id,''), COALESCE(redacted_fields::text,'')
		  FROM audit_logs WHERE session_id=$1 AND request_type='cowork_user_prompt'`,
		sessionID).Scan(&verdict, &query, &plane, &corr, &redFields); err != nil {
		t.Fatalf("read user_prompt row: %v", err)
	}
	if verdict != sharedaudit.DecisionRedacted {
		t.Errorf("user_prompt verdict: got %q want redacted", verdict)
	}
	if plane != PlaneCowork {
		t.Errorf("plane: got %q want cowork", plane)
	}
	if corr != "prompt-e2e-1" {
		t.Errorf("correlation_id: got %q want prompt-e2e-1", corr)
	}
	if !strings.Contains(redFields, "nik") {
		t.Errorf("redacted_fields should list nik, got %q", redFields)
	}
	if strings.Contains(query, nik) {
		t.Fatalf("REDACTION LEAK: raw NIK in user_prompt query: %q", query)
	}

	// --- the api_request row: usage populated ---------------------------------
	var model string
	var tokens int
	var cost float64
	if err := db.QueryRow(`
		SELECT COALESCE(model,''), COALESCE(tokens_used,0), COALESCE(cost,0)
		  FROM audit_logs WHERE session_id=$1 AND request_type='cowork_api_request'`,
		sessionID).Scan(&model, &tokens, &cost); err != nil {
		t.Fatalf("read api_request row: %v", err)
	}
	if model != "claude-sonnet-4-6" || tokens != 140 {
		t.Errorf("usage: model=%q tokens=%d want claude-sonnet-4-6/140", model, tokens)
	}
	if cost < 0.0199 || cost > 0.0201 {
		t.Errorf("cost: got %v want ~0.02", cost)
	}

	// --- the assistant_response row: reply text landed, redacted (#2838) -------
	var arVerdict, arQuery string
	if err := db.QueryRow(`
		SELECT policy_decision, query
		  FROM audit_logs WHERE session_id=$1 AND request_type='cowork_assistant_response'`,
		sessionID).Scan(&arVerdict, &arQuery); err != nil {
		t.Fatalf("read assistant_response row: %v", err)
	}
	if arVerdict != sharedaudit.DecisionRedacted {
		t.Errorf("assistant_response verdict: got %q want redacted", arVerdict)
	}
	if strings.Contains(arQuery, nik) {
		t.Fatalf("REDACTION LEAK: raw NIK in assistant_response query: %q", arQuery)
	}

	// --- the raw NIK must appear NOWHERE (redact-before-persist) ---------------
	var leak int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE query LIKE '%' || $1 || '%'`, nik).Scan(&leak); err != nil {
		t.Fatalf("scan for NIK leak: %v", err)
	}
	if leak != 0 {
		t.Fatalf("REDACTION LEAK: raw NIK %s found in %d audit_logs row(s)", nik, leak)
	}

	// --- org came from AUTH, not the spoofed telemetry attr -------------------
	var spoof int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE org_id='org-SPOOFED'`).Scan(&spoof); err != nil {
		t.Fatalf("scan spoof: %v", err)
	}
	if spoof != 0 {
		t.Errorf("telemetry-supplied org spoof leaked into %d row(s); org must come from auth", spoof)
	}
}
