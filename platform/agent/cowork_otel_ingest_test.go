//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql/driver"
	"fmt"
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
