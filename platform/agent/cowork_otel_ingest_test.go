//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	sharedaudit "axonflow/platform/shared/audit"
	sharedpolicy "axonflow/platform/shared/policy"
)

// validNIK is a checksum-valid Indonesian NIK (shared with the Indonesia detector
// tests). The Indonesia response detector masks it to 31**********0001.
const coworkValidNIK = "3174042506780001"

// ---- capture matchers (record the INSERT arg at a position, always match) ----

type capStr struct{ dst *string }

func (c capStr) Match(v driver.Value) bool {
	switch t := v.(type) {
	case string:
		*c.dst = t
	case []byte:
		*c.dst = string(t)
	case nil:
		*c.dst = ""
	default:
		*c.dst = fmt.Sprintf("%v", v)
	}
	return true
}

type capBytes struct{ dst *[]byte }

func (c capBytes) Match(v driver.Value) bool {
	switch t := v.(type) {
	case []byte:
		*c.dst = append([]byte(nil), t...)
	case string:
		*c.dst = []byte(t)
	default:
		*c.dst = nil
	}
	return true
}

// ---- OTLP builders ----

func strAttr(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}
func intAttr(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}
func dblAttr(k string, v float64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: v}}}
}

func coworkLogsReq(resAttrs []*commonpb.KeyValue, eventName string, recAttrs []*commonpb.KeyValue) *collectorlogs.ExportLogsServiceRequest {
	return &collectorlogs.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{Attributes: resAttrs},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					EventName:  eventName,
					Attributes: recAttrs,
				}},
			}},
		}},
	}
}

// authCtx stamps the four-key auth identity apiAuthMiddleware would set.
func authCtx(orgID, tenantID, clientID string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyOrgID, orgID)
	ctx = context.WithValue(ctx, ContextKeyTenantID, tenantID)
	ctx = context.WithValue(ctx, ContextKeyClientID, clientID)
	return ctx
}

func postCoworkLogs(t *testing.T, ctx context.Context, contentType string, reqPB *collectorlogs.ExportLogsServiceRequest) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	var err error
	if strings.Contains(contentType, "json") {
		body, err = protojson.Marshal(reqPB)
	} else {
		body, err = proto.Marshal(reqPB)
	}
	if err != nil {
		t.Fatalf("marshal OTLP req: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, coworkOTELLogsPath, bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	coworkOTELLogsHandler(rr, r)
	return rr
}

// withRedactionDisabled turns OFF every redactor (static engine nil + MCP
// detection disabled) so the fail-closed path (withhold raw content) is exercised.
func withRedactionDisabled(t *testing.T) {
	t.Helper()
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: false}
	detectionConfigMu.Unlock()
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
		sharedpolicy.SetGlobalEngine(origEngine)
	})
}

// withCoworkRedactor installs a NON-nil static engine (empty policies) AND enables
// MCP detection at the given action, so coworkRedactDefault passes the fail-closed
// gate (detection-on + engine-present) and the engine-independent Indonesia
// checksum masker runs. The static engine has no seeded policies here, so
// generic-PII masking is a no-op in these tests — the Indonesia (NIK) path is what
// they exercise; generic-PII force-redaction is proven at the engine layer
// (shared/policy TestUnifiedPolicyEngine_EvaluateResponse_Redact) + runtime-e2e.
func withCoworkRedactor(t *testing.T, action DetectionAction) {
	t.Helper()
	installSharedEngineWithMockDB(t) // non-nil global engine (+ its own cleanup)
	detectionConfigMu.Lock()
	orig := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: action}
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = orig
		detectionConfigMu.Unlock()
	})
}

// =============================================================================
// Flagship: a Cowork user_prompt containing a NIK is redacted BEFORE it lands in
// a CANONICAL audit_logs row (plane=cowork), org/tenant come from AUTH (not the
// spoofed telemetry resource attr), and the row is signed into the verifiable
// decision chain. This single test pins redaction + single-audit-source + tenant
// tagging + signing together.
// =============================================================================
func TestCoworkOTEL_UserPrompt_RedactedTaggedSigned(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact) // detection ON + non-nil engine (passes fail-closed gate)
	tr := withMemoryChainTracker(t)              // real sealEntry signing, synchronous, verifiable

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)

	var orgCap, queryCap, verdictCap, decisionIDCap, planeCap, corrCap, sessCap, userEmailCap string
	var redBytes []byte
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[4] = capStr{&userEmailCap}   // user_email
	args[8] = capStr{&orgCap}         // org_id
	args[10] = capStr{&queryCap}      // query
	args[12] = capStr{&verdictCap}    // policy_decision
	args[19] = capStr{&decisionIDCap} // decision_id
	args[20] = capStr{&planeCap}      // plane
	args[21] = capStr{&corrCap}       // correlation_id
	args[22] = capBytes{&redBytes}    // redacted_fields
	args[23] = capStr{&sessCap}       // session_id
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{
			strAttr("service.name", "cowork"),
			strAttr("session.id", "sess-123"),
			strAttr("user.email", "dev@design-partner.example"),
			strAttr("organization.id", "org-SPOOFED-FROM-TELEMETRY"),
		},
		"cowork.user_prompt",
		[]*commonpb.KeyValue{
			strAttr("prompt", "Pelanggan NIK "+coworkValidNIK+" terdaftar"),
			strAttr("prompt.id", "prompt-abc"),
		},
	)

	ctx := authCtx("org-auth", "tenant-dp", "client-1")
	rr := postCoworkLogs(t, ctx, contentTypeProtobuf, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("audit INSERT not executed as expected: %v", err)
	}

	// Redaction: the raw NIK MUST NOT be persisted; a mask MUST be.
	if strings.Contains(queryCap, coworkValidNIK) {
		t.Fatalf("raw NIK leaked into audit_logs.query: %q", queryCap)
	}
	if !strings.Contains(queryCap, "31**********0001") {
		t.Errorf("expected masked NIK in query, got %q", queryCap)
	}
	if verdictCap != sharedaudit.DecisionRedacted {
		t.Errorf("policy_decision: got %q want %q", verdictCap, sharedaudit.DecisionRedacted)
	}
	if len(redBytes) == 0 || !strings.Contains(string(redBytes), "nik") {
		t.Errorf("redacted_fields should list nik, got %q", string(redBytes))
	}
	// Single audit source: canonical plane + correlation + session on the row.
	if planeCap != PlaneCowork {
		t.Errorf("plane: got %q want %q", planeCap, PlaneCowork)
	}
	if corrCap != "prompt-abc" {
		t.Errorf("correlation_id (=prompt.id): got %q want prompt-abc", corrCap)
	}
	if sessCap != "sess-123" {
		t.Errorf("session_id: got %q want sess-123", sessCap)
	}
	// Tenant/org tagging: from AUTH, never the spoofed telemetry attr.
	if orgCap != "org-auth" {
		t.Errorf("org_id must come from auth, got %q (telemetry tried to spoof org-SPOOFED-FROM-TELEMETRY)", orgCap)
	}
	if userEmailCap != "dev@design-partner.example" {
		t.Errorf("user_email (attribution) should come from telemetry, got %q", userEmailCap)
	}

	// Signing: the canonical decision was signed + chained and verifies.
	if decisionIDCap == "" {
		t.Fatal("decision_id was not captured")
	}
	res, found, verr := tr.VerifyChain(context.Background(), "org-auth", decisionIDCap)
	if verr != nil || !found {
		t.Fatalf("VerifyChain found=%v err=%v", found, verr)
	}
	if !res.Valid || !res.AuthorshipProven {
		t.Fatalf("cowork audit row not signed/verified: valid=%v authorship=%v break=%q",
			res.Valid, res.AuthorshipProven, res.BreakReason)
	}
}

// Red-on-revert for the R3 round-2 HIGH: under the DEFAULT PII_ACTION=warn
// (detection enabled, detect-don't-modify on the live plane) the collector must
// STILL mask a NIK before storing it — the store must never hold raw PII
// regardless of the deployment's enforcement action. (Reverting the force-redact
// to evaluateOutputPolicies stores the raw NIK under warn and fails this test.)
func TestCoworkOTEL_UserPrompt_MaskedUnderWarnAction(t *testing.T) {
	withCoworkRedactor(t, DetectionActionWarn) // enabled + warn (default class) + non-nil engine

	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)

	var queryCap, verdictCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[10] = capStr{&queryCap}
	args[12] = capStr{&verdictCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.user_prompt",
		[]*commonpb.KeyValue{strAttr("prompt", "Pelanggan NIK "+coworkValidNIK+" terdaftar")},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "c1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	if strings.Contains(queryCap, coworkValidNIK) {
		t.Fatalf("FAIL-OPEN (warn): raw NIK persisted under PII_ACTION=warn: %q", queryCap)
	}
	if !strings.Contains(queryCap, "31**********0001") {
		t.Errorf("NIK should be masked under warn, got %q", queryCap)
	}
	if verdictCap != sharedaudit.DecisionRedacted {
		t.Errorf("verdict: got %q want redacted", verdictCap)
	}
}

// api_request carries the OTEL usage triple onto the canonical row (model /
// tokens / cost already exist on audit_logs since migration 059 — no detail table).
func TestCoworkOTEL_APIRequest_PopulatesUsage(t *testing.T) {
	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)

	var modelCap, verdictCap, planeCap string
	var tokensCap, costCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[12] = capStr{&verdictCap} // policy_decision
	args[15] = capStr{&modelCap}   // model
	args[17] = capStr{&tokensCap}  // tokens_used
	args[18] = capStr{&costCap}    // cost
	args[20] = capStr{&planeCap}   // plane
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "claude-code")},
		"claude_code.api_request",
		[]*commonpb.KeyValue{
			strAttr("model", "claude-sonnet-4-6"),
			intAttr("input_tokens", 100),
			intAttr("output_tokens", 40),
			dblAttr("cost_usd", 0.0123),
		},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT expectation: %v", err)
	}
	if modelCap != "claude-sonnet-4-6" {
		t.Errorf("model: got %q", modelCap)
	}
	if tokensCap != "140" {
		t.Errorf("tokens_used: got %q want 140", tokensCap)
	}
	if costCap != "0.0123" {
		t.Errorf("cost: got %q want 0.0123", costCap)
	}
	if planeCap != PlaneClaudeCode {
		t.Errorf("plane: got %q want %q", planeCap, PlaneClaudeCode)
	}
	if verdictCap != sharedaudit.DecisionAllowed {
		t.Errorf("verdict: got %q want allowed", verdictCap)
	}
}

// A tool_decision "reject" maps to the canonical blocked verdict.
func TestCoworkOTEL_ToolDecisionReject_Blocked(t *testing.T) {
	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)

	var verdictCap, queryCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[10] = capStr{&queryCap}
	args[12] = capStr{&verdictCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.tool_decision",
		[]*commonpb.KeyValue{
			strAttr("tool_name", "delete_files"),
			strAttr("decision", "reject"),
		},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "c1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	if verdictCap != sharedaudit.DecisionBlocked {
		t.Errorf("verdict: got %q want blocked", verdictCap)
	}
	if !strings.Contains(queryCap, "reject") {
		t.Errorf("descriptor should mention reject, got %q", queryCap)
	}
}

// Fail-closed: with NO redactor active, raw prompt content is WITHHELD (never
// persisted in the clear) and the verdict is error.
func TestCoworkOTEL_FailClosed_WithholdsContent(t *testing.T) {
	withRedactionDisabled(t)

	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)

	var queryCap, verdictCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[10] = capStr{&queryCap}
	args[12] = capStr{&verdictCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.user_prompt",
		[]*commonpb.KeyValue{strAttr("prompt", "Pelanggan NIK "+coworkValidNIK)},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "c1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	if strings.Contains(queryCap, coworkValidNIK) {
		t.Fatalf("FAIL-CLOSED VIOLATION: raw NIK persisted when redactor unavailable: %q", queryCap)
	}
	if !strings.Contains(queryCap, "withheld") {
		t.Errorf("expected withheld placeholder, got %q", queryCap)
	}
	if verdictCap != sharedaudit.DecisionError {
		t.Errorf("verdict: got %q want error", verdictCap)
	}
}

// Red-on-revert for the R3 HIGH fail-open: a LOADED static engine must NOT be
// treated as "redaction available" — only mcpDetectionCfg.Enabled drives
// redaction (evaluateOutputPolicies gates every pass on it). With detection OFF
// but an engine loaded, content must STILL be withheld, never stored raw.
func TestCoworkOTEL_FailClosed_EngineOnDetectionOff(t *testing.T) {
	installSharedEngineWithMockDB(t) // non-nil global engine
	detectionConfigMu.Lock()
	orig := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: false}
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = orig
		detectionConfigMu.Unlock()
	})

	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)

	var queryCap, verdictCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[10] = capStr{&queryCap}
	args[12] = capStr{&verdictCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.user_prompt",
		[]*commonpb.KeyValue{strAttr("prompt", "Pelanggan NIK "+coworkValidNIK)},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "c1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	if strings.Contains(queryCap, coworkValidNIK) {
		t.Fatalf("FAIL-OPEN: raw NIK persisted with engine-on/detection-off: %q", queryCap)
	}
	if verdictCap != sharedaudit.DecisionError {
		t.Errorf("verdict: got %q want error (content withheld)", verdictCap)
	}
}

// Red-on-revert for the round-2 engine-nil residual: detection ENABLED but the
// static engine nil → GENERIC content (an email, no Indonesia PII) must be
// WITHHELD (verdict error), never stored raw. Removing the engine-nil gate lets
// the raw email land and fails this test.
func TestCoworkOTEL_FailClosed_EngineNilGenericWithheld(t *testing.T) {
	detectionConfigMu.Lock()
	orig := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: DetectionActionRedact}
	detectionConfigMu.Unlock()
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = orig
		detectionConfigMu.Unlock()
		sharedpolicy.SetGlobalEngine(origEngine)
	})

	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)

	var queryCap, verdictCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[10] = capStr{&queryCap}
	args[12] = capStr{&verdictCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.user_prompt",
		[]*commonpb.KeyValue{strAttr("prompt", "Email saya andi@example.com mohon dicek")},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "c1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
	if strings.Contains(queryCap, "andi@example.com") {
		t.Fatalf("FAIL-OPEN: raw email persisted with engine nil: %q", queryCap)
	}
	if verdictCap != sharedaudit.DecisionError {
		t.Errorf("verdict: got %q want error (content withheld)", verdictCap)
	}
}

// Non-community deployment with no authenticated org → 401, and NO row written
// (closes the unauthenticated-ingest hole).
func TestCoworkOTEL_Unauthenticated_Rejected(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")

	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	// No ExpectExec → any INSERT is an unexpected-call failure.

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.user_prompt",
		[]*commonpb.KeyValue{strAttr("prompt", "hello")},
	)
	rr := postCoworkLogs(t, authCtx("", "", ""), contentTypeProtobuf, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no INSERT should have run: %v", err)
	}
}

// JSON (OTLP/HTTP application/json) is accepted as well as protobuf.
func TestCoworkOTEL_JSONContentType(t *testing.T) {
	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false)
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.api_request",
		[]*commonpb.KeyValue{strAttr("model", "claude-opus-4-8")},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "t", "c"), contentTypeJSON, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("INSERT: %v", err)
	}
}

// Unsupported content-type → 415.
func TestCoworkOTEL_UnsupportedContentType(t *testing.T) {
	req := coworkLogsReq(nil, "cowork.api_request", nil)
	rr := postCoworkLogs(t, authCtx("org-auth", "t", "c"), "text/csv", req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status: got %d want 415", rr.Code)
	}
}

// Unrecognized event names are skipped (partial success), not fabricated.
func TestCoworkOTEL_UnknownEventSkipped(t *testing.T) {
	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	// No ExpectExec.

	req := coworkLogsReq(
		[]*commonpb.KeyValue{strAttr("service.name", "cowork")},
		"cowork.some_future_event",
		[]*commonpb.KeyValue{strAttr("x", "y")},
	)
	rr := postCoworkLogs(t, authCtx("org-auth", "t", "c"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no INSERT should have run for unknown event: %v", err)
	}
}

// ---- helper unit tests (coverage of the pure mappers) ----

func TestNormalizeEventName(t *testing.T) {
	cases := map[string]string{
		"claude_code.user_prompt":  evUserPrompt,
		"cowork.tool_result":       evToolResult,
		"TOOL_DECISION":            evToolDecision,
		"claude_desktop.api_error": evAPIError,
	}
	for in, want := range cases {
		if got := normalizeEventName(in); got != want {
			t.Errorf("normalizeEventName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPlaneFromService(t *testing.T) {
	cases := map[string]string{
		"cowork":         PlaneCowork,
		"claude-code":    PlaneClaudeCode,
		"claude_code":    PlaneClaudeCode,
		"claude-desktop": PlaneCowork,
		"":               PlaneCowork,
		"something-else": PlaneCowork,
	}
	for in, want := range cases {
		if got := planeFromService(in); got != want {
			t.Errorf("planeFromService(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseCoworkOTLPLogs_Errors(t *testing.T) {
	if _, err := parseCoworkOTLPLogs("text/csv", []byte("x")); err == nil {
		t.Error("expected unsupported content-type error")
	}
	if _, err := parseCoworkOTLPLogs(contentTypeJSON, []byte("{not json")); err == nil {
		t.Error("expected json parse error")
	}
}

func TestReadLimited_TooLarge(t *testing.T) {
	_, err := readLimited(bytes.NewReader(make([]byte, 100)), 10)
	if err == nil {
		t.Error("expected too-large error")
	}
}

func TestRegisterCoworkOTELIngest_RouteMounted(t *testing.T) {
	r := mux.NewRouter()
	registerCoworkOTELIngest(r)
	req := httptest.NewRequest(http.MethodPost, coworkOTELLogsPath, nil)
	var match mux.RouteMatch
	if !r.Match(req, &match) {
		t.Fatalf("POST %s was not routed after registration", coworkOTELLogsPath)
	}
}

func TestIsRejectDecision(t *testing.T) {
	for _, d := range []string{"reject", "REJECTED", "deny", "user_abort"} {
		if !isRejectDecision(d) {
			t.Errorf("%q should be a reject", d)
		}
	}
	for _, d := range []string{"accept", "allow", ""} {
		if isRejectDecision(d) {
			t.Errorf("%q should NOT be a reject", d)
		}
	}
}

// =============================================================================
// #2838 — REAL attribute placement. Real Claude Code / Cowork exporters carry
// user.email / session.id / user.account_uuid on EVERY LOG RECORD and leave the
// resource block identity-free (only service.*/os.*/host.arch); the top-level
// OTLP eventName field is ABSENT (the prefixed name rides in body.stringValue,
// the unprefixed one in the event.name record attribute). These fixtures mirror
// a real captured export byte-for-byte in SHAPE (values genericized: this file
// syncs to the public mirror).
// =============================================================================

// realShapedResourceAttrs is the COMPLETE resource attribute set a real
// exporter sends — no identity, no session.
func realShapedResourceAttrs(serviceName string) []*commonpb.KeyValue {
	return []*commonpb.KeyValue{
		strAttr("host.arch", "arm64"),
		strAttr("os.type", "darwin"),
		strAttr("os.version", "25.3.0"),
		strAttr("service.name", serviceName),
		strAttr("service.version", "2.1.201"),
	}
}

// realShapedIdentityAttrs is the per-record identity block every real log
// record carries.
func realShapedIdentityAttrs(email, sessionID string) []*commonpb.KeyValue {
	return []*commonpb.KeyValue{
		strAttr("user.id", "1111111111111111111111111111111111111111111111111111111111111111"),
		strAttr("session.id", sessionID),
		strAttr("organization.id", "0000000e-0000-4000-8000-00000000e001"),
		strAttr("user.email", email),
		strAttr("user.account_uuid", "0000000a-0000-4000-8000-00000000a001"),
		strAttr("user.account_id", "user_01AcmeEvalAccountId0000"),
		strAttr("terminal.type", "Apple_Terminal"),
	}
}

// coworkLogsReqRealShaped builds an ExportLogsServiceRequest the way a real
// exporter does: EventName field EMPTY, Body = prefixed event name, unprefixed
// event.name record attribute, identity per record.
func coworkLogsReqRealShaped(serviceName string, events []coworkEventFixture) *collectorlogs.ExportLogsServiceRequest {
	records := make([]*logspb.LogRecord, 0, len(events))
	for _, ev := range events {
		base := normalizeEventName(ev.name)
		attrs := append([]*commonpb.KeyValue{}, ev.attrs...)
		attrs = append(attrs, strAttr("event.name", base))
		records = append(records, &logspb.LogRecord{
			Body:       &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: ev.name}},
			Attributes: attrs,
		})
	}
	return &collectorlogs.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{Attributes: realShapedResourceAttrs(serviceName)},
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope:      &commonpb.InstrumentationScope{Name: "com.anthropic.claude_code.events", Version: "2.1.201"},
				LogRecords: records,
			}},
		}},
	}
}

// Flagship for #2838: with identity ONLY at record level (the real placement),
// user_email + session_id populate on the canonical row, and the Anthropic
// account identifiers land in policy_details. Red on the pre-#2838 code, which
// read identity from resource attributes only (user_email defaulted to
// unknown@axonflow.local, session_id NULL).
func TestCoworkOTEL_RecordLevelIdentity_RealPlacement(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	var emailCap, sessCap, detailsCap, corrCap, rtCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[4] = capStr{&emailCap}    // user_email
	args[9] = capStr{&rtCap}       // request_type
	args[13] = capStr{&detailsCap} // policy_details
	args[21] = capStr{&corrCap}    // correlation_id
	args[23] = capStr{&sessCap}    // session_id
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReqRealShaped("claude-code", []coworkEventFixture{
		{name: "claude_code.user_prompt", attrs: append(
			realShapedIdentityAttrs("andi@acme-eval.example", "00000005-0000-4000-8000-000000005001"),
			strAttr("prompt", "list open tickets"),
			strAttr("prompt.id", "0000000b-0000-4000-8000-00000000b001"),
			strAttr("prompt_length", "17"), // real exporters string-type this
		)},
	})

	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("audit INSERT not executed: %v", err)
	}
	if emailCap != "andi@acme-eval.example" {
		t.Errorf("user_email must come from RECORD attrs, got %q", emailCap)
	}
	if sessCap != "00000005-0000-4000-8000-000000005001" {
		t.Errorf("session_id must come from RECORD attrs, got %q", sessCap)
	}
	if corrCap != "0000000b-0000-4000-8000-00000000b001" {
		t.Errorf("correlation_id (prompt.id): got %q", corrCap)
	}
	if rtCap != "claude_code_user_prompt" {
		t.Errorf("request_type: got %q want claude_code_user_prompt", rtCap)
	}
	if !strings.Contains(detailsCap, `"user_account_uuid":"0000000a-0000-4000-8000-00000000a001"`) {
		t.Errorf("policy_details must carry user_account_uuid (Compliance API join key), got %s", detailsCap)
	}
	if !strings.Contains(detailsCap, `"user_account_id":"user_01AcmeEvalAccountId0000"`) {
		t.Errorf("policy_details must carry user_account_id, got %s", detailsCap)
	}
}

// Record-level identity WINS over resource-level (record attrs are more
// specific; a collector may promote stale values to the resource).
func TestCoworkOTEL_RecordLevelIdentity_WinsOverResource(t *testing.T) {
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
			strAttr("service.name", "cowork"),
			strAttr("session.id", "sess-resource-STALE"),
			strAttr("user.email", "resource-stale@acme-eval.example"),
		},
		"cowork.user_prompt",
		[]*commonpb.KeyValue{
			strAttr("prompt", "halo"),
			strAttr("session.id", "sess-record-FRESH"),
			strAttr("user.email", "record-fresh@acme-eval.example"),
		},
	)

	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("audit INSERT not executed: %v", err)
	}
	if emailCap != "record-fresh@acme-eval.example" {
		t.Errorf("record-level user.email must win, got %q", emailCap)
	}
	if sessCap != "sess-record-FRESH" {
		t.Errorf("record-level session.id must win, got %q", sessCap)
	}
}

// assistant_response (#2838): model reply text IS in the OTEL stream (Cowork
// ≥1.17377 / Claude Code) — it must land as a canonical row, force-redacted
// like every other content field. Red on the pre-#2838 code (event rejected).
func TestCoworkOTEL_AssistantResponse_RedactedAndLanded(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	var queryCap, verdictCap, rtCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[9] = capStr{&rtCap}
	args[10] = capStr{&queryCap}
	args[12] = capStr{&verdictCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReqRealShaped("claude-code", []coworkEventFixture{
		{name: "claude_code.assistant_response", attrs: append(
			realShapedIdentityAttrs("andi@acme-eval.example", "sess-ar-1"),
			strAttr("response", "Data pelanggan: NIK "+coworkValidNIK),
			strAttr("prompt.id", "prompt-ar-1"),
			strAttr("model", "claude-sonnet-4-6"),
		)},
	})

	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("assistant_response did not land a canonical row: %v", err)
	}
	if rtCap != "claude_code_assistant_response" {
		t.Errorf("request_type: got %q", rtCap)
	}
	if strings.Contains(queryCap, coworkValidNIK) {
		t.Fatalf("raw NIK leaked into stored assistant response: %q", queryCap)
	}
	if !strings.Contains(queryCap, "31**********0001") {
		t.Errorf("expected masked NIK in stored response, got %q", queryCap)
	}
	if verdictCap != sharedaudit.DecisionRedacted {
		t.Errorf("policy_decision: got %q want %q", verdictCap, sharedaudit.DecisionRedacted)
	}
}

// assistant_response with content capture OFF (no response attribute): the
// event still lands (audit completeness) with a descriptor, verdict allowed.
func TestCoworkOTEL_AssistantResponse_ContentCaptureOff(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact)

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
	args[10] = capStr{&queryCap}
	args[12] = capStr{&verdictCap}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	req := coworkLogsReqRealShaped("cowork", []coworkEventFixture{
		{name: "cowork.assistant_response", attrs: append(
			realShapedIdentityAttrs("andi@acme-eval.example", "sess-ar-2"),
			strAttr("model", "claude-sonnet-4-6"),
			intAttr("response_length", 2048),
		)},
	})

	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("row not landed: %v", err)
	}
	if queryCap != "(cowork assistant response: content capture off)" {
		t.Errorf("query descriptor: got %q", queryCap)
	}
	if verdictCap != sharedaudit.DecisionAllowed {
		t.Errorf("verdict: got %q want %q", verdictCap, sharedaudit.DecisionAllowed)
	}
}

// realCapturedExportJSON mirrors a REAL captured Claude Code OTLP/HTTP JSON
// export (OTel-OTLP-Exporter-JavaScript) record-for-record and type-for-type:
// camelCase protojson keys, ABSENT top-level eventName, prefixed body, string-
// typed numerics where the real exporter string-types them, identity per
// record, operational events interleaved. Values genericized (public mirror);
// structure verbatim from the 2026-07-05 capture (#2838).
const realCapturedExportJSON = `{
  "resourceLogs": [{
    "resource": {"attributes": [
      {"key": "host.arch", "value": {"stringValue": "arm64"}},
      {"key": "os.type", "value": {"stringValue": "darwin"}},
      {"key": "os.version", "value": {"stringValue": "25.3.0"}},
      {"key": "service.name", "value": {"stringValue": "claude-code"}},
      {"key": "service.version", "value": {"stringValue": "2.1.201"}}
    ]},
    "scopeLogs": [{
      "scope": {"name": "com.anthropic.claude_code.events", "version": "2.1.201"},
      "logRecords": [
        {
          "timeUnixNano": "1783253696411000000",
          "observedTimeUnixNano": "1783253696411000000",
          "body": {"stringValue": "claude_code.user_prompt"},
          "attributes": [
            {"key": "user.id", "value": {"stringValue": "1111111111111111111111111111111111111111111111111111111111111111"}},
            {"key": "session.id", "value": {"stringValue": "00000005-0000-4000-8000-000000005001"}},
            {"key": "organization.id", "value": {"stringValue": "0000000e-0000-4000-8000-00000000e001"}},
            {"key": "user.email", "value": {"stringValue": "andi@acme-eval.example"}},
            {"key": "user.account_uuid", "value": {"stringValue": "0000000a-0000-4000-8000-00000000a001"}},
            {"key": "user.account_id", "value": {"stringValue": "user_01AcmeEvalAccountId0000"}},
            {"key": "terminal.type", "value": {"stringValue": "Apple_Terminal"}},
            {"key": "event.name", "value": {"stringValue": "user_prompt"}},
            {"key": "event.timestamp", "value": {"stringValue": "2026-07-05T12:14:56.411Z"}},
            {"key": "event.sequence", "value": {"intValue": 11}},
            {"key": "prompt.id", "value": {"stringValue": "0000000b-0000-4000-8000-00000000b001"}},
            {"key": "prompt_length", "value": {"stringValue": "22"}},
            {"key": "prompt", "value": {"stringValue": "Reply with exactly: ok"}}
          ]
        },
        {
          "timeUnixNano": "1783253697458000000",
          "observedTimeUnixNano": "1783253697458000000",
          "body": {"stringValue": "claude_code.api_request"},
          "attributes": [
            {"key": "user.id", "value": {"stringValue": "1111111111111111111111111111111111111111111111111111111111111111"}},
            {"key": "session.id", "value": {"stringValue": "00000005-0000-4000-8000-000000005001"}},
            {"key": "organization.id", "value": {"stringValue": "0000000e-0000-4000-8000-00000000e001"}},
            {"key": "user.email", "value": {"stringValue": "andi@acme-eval.example"}},
            {"key": "user.account_uuid", "value": {"stringValue": "0000000a-0000-4000-8000-00000000a001"}},
            {"key": "user.account_id", "value": {"stringValue": "user_01AcmeEvalAccountId0000"}},
            {"key": "terminal.type", "value": {"stringValue": "Apple_Terminal"}},
            {"key": "event.name", "value": {"stringValue": "api_request"}},
            {"key": "event.timestamp", "value": {"stringValue": "2026-07-05T12:14:57.458Z"}},
            {"key": "event.sequence", "value": {"intValue": 12}},
            {"key": "prompt.id", "value": {"stringValue": "0000000b-0000-4000-8000-00000000b001"}},
            {"key": "model", "value": {"stringValue": "claude-haiku-4-5-20251001"}},
            {"key": "input_tokens", "value": {"intValue": 10}},
            {"key": "output_tokens", "value": {"intValue": 39}},
            {"key": "cache_read_tokens", "value": {"intValue": 20058}},
            {"key": "cache_creation_tokens", "value": {"intValue": 3485}},
            {"key": "cost_usd", "value": {"doubleValue": 0.0091808}},
            {"key": "cost_usd_micros", "value": {"intValue": 9181}},
            {"key": "duration_ms", "value": {"intValue": 1032}},
            {"key": "request_id", "value": {"stringValue": "req_011AcmeEvalRequestId000"}},
            {"key": "speed", "value": {"stringValue": "normal"}},
            {"key": "query_source", "value": {"stringValue": "sdk"}}
          ]
        },
        {
          "timeUnixNano": "1783253697458000000",
          "observedTimeUnixNano": "1783253697458000000",
          "body": {"stringValue": "claude_code.assistant_response"},
          "attributes": [
            {"key": "user.id", "value": {"stringValue": "1111111111111111111111111111111111111111111111111111111111111111"}},
            {"key": "session.id", "value": {"stringValue": "00000005-0000-4000-8000-000000005001"}},
            {"key": "organization.id", "value": {"stringValue": "0000000e-0000-4000-8000-00000000e001"}},
            {"key": "user.email", "value": {"stringValue": "andi@acme-eval.example"}},
            {"key": "user.account_uuid", "value": {"stringValue": "0000000a-0000-4000-8000-00000000a001"}},
            {"key": "user.account_id", "value": {"stringValue": "user_01AcmeEvalAccountId0000"}},
            {"key": "terminal.type", "value": {"stringValue": "Apple_Terminal"}},
            {"key": "event.name", "value": {"stringValue": "assistant_response"}},
            {"key": "event.timestamp", "value": {"stringValue": "2026-07-05T12:14:57.458Z"}},
            {"key": "event.sequence", "value": {"intValue": 13}},
            {"key": "prompt.id", "value": {"stringValue": "0000000b-0000-4000-8000-00000000b001"}},
            {"key": "response_length", "value": {"intValue": 2}},
            {"key": "response", "value": {"stringValue": "ok"}},
            {"key": "request_id", "value": {"stringValue": "req_011AcmeEvalRequestId000"}},
            {"key": "model", "value": {"stringValue": "claude-haiku-4-5-20251001"}},
            {"key": "query_source", "value": {"stringValue": "sdk"}}
          ]
        },
        {
          "timeUnixNano": "1783253697461000000",
          "observedTimeUnixNano": "1783253697461000000",
          "body": {"stringValue": "claude_code.mcp_server_connection"},
          "attributes": [
            {"key": "user.id", "value": {"stringValue": "1111111111111111111111111111111111111111111111111111111111111111"}},
            {"key": "session.id", "value": {"stringValue": "00000005-0000-4000-8000-000000005001"}},
            {"key": "user.email", "value": {"stringValue": "andi@acme-eval.example"}},
            {"key": "event.name", "value": {"stringValue": "mcp_server_connection"}},
            {"key": "event.sequence", "value": {"intValue": 14}},
            {"key": "status", "value": {"stringValue": "disconnected"}},
            {"key": "transport_type", "value": {"stringValue": "claudeai-proxy"}},
            {"key": "duration_ms", "value": {"stringValue": "1502"}}
          ]
        },
        {
          "timeUnixNano": "1783253695722000000",
          "observedTimeUnixNano": "1783253695722000000",
          "body": {"stringValue": "claude_code.hook_execution_start"},
          "attributes": [
            {"key": "user.email", "value": {"stringValue": "andi@acme-eval.example"}},
            {"key": "session.id", "value": {"stringValue": "00000005-0000-4000-8000-000000005001"}},
            {"key": "event.name", "value": {"stringValue": "hook_execution_start"}},
            {"key": "event.sequence", "value": {"intValue": 0}},
            {"key": "hook_event", "value": {"stringValue": "SessionStart"}}
          ]
        }
      ]
    }]
  }]
}`

// The verbatim real-capture shape parses end-to-end: three content/usage rows
// land (user_prompt, api_request, assistant_response) with record-level
// identity + usage populated; the two operational records are counted rejected
// via partial_success. This is the in-tree pin of the REAL wire contract —
// [[feedback_dod_real_client_and_unhappy_path_not_synthetic]].
func TestCoworkOTEL_RealCapturedPayloadJSON(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	// Rows INSERT in record order: user_prompt, api_request, assistant_response.
	type rowCaps struct{ email, sess, rt, query, model string; tokens, cost driver.Value }
	caps := make([]rowCaps, 3)
	for i := range caps {
		args := make([]driver.Value, 24)
		for j := range args {
			args[j] = sqlmock.AnyArg()
		}
		args[4] = capStr{&caps[i].email}
		args[9] = capStr{&caps[i].rt}
		args[10] = capStr{&caps[i].query}
		args[23] = capStr{&caps[i].sess}
		mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))
	}

	r := httptest.NewRequest(http.MethodPost, coworkOTELLogsPath,
		strings.NewReader(realCapturedExportJSON)).WithContext(authCtx("org-auth", "tenant-dp", "client-1"))
	r.Header.Set("Content-Type", contentTypeJSON)
	rr := httptest.NewRecorder()
	coworkOTELLogsHandler(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected 3 canonical rows from the real-shaped export: %v", err)
	}
	wantRT := []string{"claude_code_user_prompt", "claude_code_api_request", "claude_code_assistant_response"}
	for i, c := range caps {
		if c.rt != wantRT[i] {
			t.Errorf("row %d request_type: got %q want %q", i, c.rt, wantRT[i])
		}
		if c.email != "andi@acme-eval.example" {
			t.Errorf("row %d user_email: got %q (record-level identity must populate)", i, c.email)
		}
		if c.sess != "00000005-0000-4000-8000-000000005001" {
			t.Errorf("row %d session_id: got %q", i, c.sess)
		}
	}
	// Operational records (mcp_server_connection, hook_execution_start) are
	// intentionally unmapped → partial_success reports exactly 2 rejected.
	if !strings.Contains(rr.Body.String(), "partialSuccess") || !strings.Contains(rr.Body.String(), `"2"`) {
		t.Errorf("expected partial_success with 2 rejected operational records, got %s", rr.Body.String())
	}
}

// R3 H1 pin: a failed audit INSERT must be counted REJECTED (partial_success),
// not ACKed — and must NOT leave a signed chain entry referencing a row that
// does not exist. Red on the pre-fix code (write was fire-and-forget, record
// counted accepted, chain entry always written).
func TestCoworkOTEL_InsertFailure_CountedRejectedNotSigned(t *testing.T) {
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
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnError(errors.New("value too long for type character varying"))

	req := coworkLogsReqRealShaped("claude-code", []coworkEventFixture{
		{name: "claude_code.user_prompt", attrs: append(
			realShapedIdentityAttrs("andi@acme-eval.example", "sess-h1"),
			strAttr("prompt", "hello"),
		)},
	})

	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeJSON, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "partialSuccess") {
		t.Errorf("failed persist must surface as partial_success rejected, got body %s", rr.Body.String())
	}
	tr.mu.RLock()
	chains := len(tr.memoryStore)
	tr.mu.RUnlock()
	if chains != 0 {
		t.Errorf("no chain entry may reference an unstored row; found %d chain(s)", chains)
	}
}

// R3 H1 pin: every client-supplied value bound for a bounded audit_logs column
// is truncated/clamped — an oversized model / prompt.id / token count / cost
// must not be able to fail the INSERT (audit-evasion channel).
func TestCoworkOTEL_OversizedClientValues_ClampedNotFailed(t *testing.T) {
	withCoworkRedactor(t, DetectionActionRedact)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	var modelCap, corrCap, detailsCap string
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13] = capStr{&detailsCap} // policy_details
	args[15] = capStr{&modelCap}   // model
	args[21] = capStr{&corrCap}    // correlation_id
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))

	big := strings.Repeat("x", 5000)
	req := coworkLogsReqRealShaped("claude-code", []coworkEventFixture{
		{name: "claude_code.api_request", attrs: []*commonpb.KeyValue{
			strAttr("user.email", "andi@acme-eval.example"),
			strAttr("session.id", "sess-clamp"),
			strAttr("user.account_uuid", big),
			strAttr("user.account_id", big),
			strAttr("model", big),
			strAttr("prompt.id", big),
			intAttr("input_tokens", int64(1)<<40),
			intAttr("output_tokens", int64(1)<<40),
			dblAttr("cost_usd", 1e12),
		}},
	})

	rr := postCoworkLogs(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("oversized values must clamp, not fail the INSERT: %v", err)
	}
	if len(modelCap) != maxCoworkModelLen {
		t.Errorf("model truncated to %d, want %d", len(modelCap), maxCoworkModelLen)
	}
	if len(corrCap) != maxCoworkCorrelationIDLen {
		t.Errorf("correlation_id truncated to %d, want %d", len(corrCap), maxCoworkCorrelationIDLen)
	}
	if strings.Contains(detailsCap, big) {
		t.Errorf("account identifiers must be length-capped in policy_details")
	}
}

// R3 clamp-helper pins.
func TestClampCoworkTokensAndCost(t *testing.T) {
	if got := clampCoworkTokens(10, 39); got != 49 {
		t.Errorf("normal sum: got %d", got)
	}
	if got := clampCoworkTokens(int64(1)<<40, int64(1)<<40); got != math.MaxInt32 {
		t.Errorf("overflow must clamp to MaxInt32, got %d", got)
	}
	if got := clampCoworkTokens(math.MaxInt64, math.MaxInt64); got != math.MaxInt32 {
		t.Errorf("int64 wrap must clamp to MaxInt32, got %d", got)
	}
	if got := clampCoworkTokens(-5, 2); got != 0 {
		t.Errorf("negative sum clamps to 0, got %d", got)
	}
	if got := clampCoworkCost(1e12); got != maxCoworkCost {
		t.Errorf("cost overflow must clamp, got %v", got)
	}
	if got := clampCoworkCost(math.NaN()); got != 0 {
		t.Errorf("NaN cost clamps to 0, got %v", got)
	}
}
