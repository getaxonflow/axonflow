// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"axonflow/platform/orchestrator/cost"
	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/serviceauth"
	"github.com/google/uuid"
)

type governedModelCostRepository struct {
	*mockCostRepository
	mu         sync.Mutex
	records    []cost.UsageRecord
	saveErr    error
	budgetErr  error
	attempts   map[string]cost.GovernedModelAttempt
	journalErr error
}

func (repo *governedModelCostRepository) GetBudgetsForScope(ctx context.Context, scope cost.BudgetScope, scopeID, orgID, tenantID string) ([]cost.Budget, error) {
	if repo.budgetErr != nil {
		return nil, repo.budgetErr
	}
	return repo.mockCostRepository.GetBudgetsForScope(ctx, scope, scopeID, orgID, tenantID)
}

func newGovernedModelCostRepository() *governedModelCostRepository {
	return &governedModelCostRepository{mockCostRepository: &mockCostRepository{
		budgets: map[string]*cost.Budget{}, usageSum: map[string]float64{},
	}, attempts: map[string]cost.GovernedModelAttempt{}}
}

func (repo *governedModelCostRepository) BeginGovernedModelAttempt(_ context.Context, attempt *cost.GovernedModelAttempt) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.journalErr != nil {
		return repo.journalErr
	}
	copy := *attempt
	copy.Status = "forwarding"
	repo.attempts[attempt.RequestID] = copy
	return nil
}

func (repo *governedModelCostRepository) FinishGovernedModelAttempt(_ context.Context, attempt *cost.GovernedModelAttempt) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.journalErr != nil {
		return repo.journalErr
	}
	if _, ok := repo.attempts[attempt.RequestID]; !ok {
		return errors.New("missing intent")
	}
	repo.attempts[attempt.RequestID] = *attempt
	return nil
}

func (repo *governedModelCostRepository) GetGovernedModelAttempt(_ context.Context, orgID, tenantID, requestID string,
	_ time.Duration) (*cost.GovernedModelAttempt, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	attempt, ok := repo.attempts[requestID]
	if !ok || attempt.OrgID != orgID || attempt.TenantID != tenantID {
		return nil, sql.ErrNoRows
	}
	copy := attempt
	return &copy, nil
}

func (repo *governedModelCostRepository) CheckGovernedModelAttemptJournal(_ context.Context, orgID, tenantID string) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.journalErr != nil {
		return repo.journalErr
	}
	if orgID == "" || tenantID == "" {
		return errors.New("missing tenant scope")
	}
	return nil
}

func (repo *governedModelCostRepository) SaveUsage(_ context.Context, record *cost.UsageRecord) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.saveErr != nil {
		return repo.saveErr
	}
	repo.records = append(repo.records, *record)
	return nil
}

func (repo *governedModelCostRepository) saved() []cost.UsageRecord {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	return append([]cost.UsageRecord(nil), repo.records...)
}

type governedModelFixture struct {
	repo           *governedModelCostRepository
	orchestrations atomic.Int64
	secret         string
	org            string
	tenant         string
}

type governedModelRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn governedModelRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func setupGovernedModelFixture(t *testing.T, response func(*http.Request) map[string]any) *governedModelFixture {
	t.Helper()
	enfSetup(t)
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{}
	}
	fixture := &governedModelFixture{
		repo: newGovernedModelCostRepository(), secret: "governed-model-secret-at-least-32-bytes", org: enfOrgImplicit, tenant: "model-tenant-a",
	}

	previousCost, previousURL, previousValidator := costService, orchestratorURL, internalTokenValidator
	previousHTTPClient := http.DefaultClient
	previousUsageDB, previousAuthDB := usageDB, authDB
	costService = cost.NewService(fixture.repo, nil)
	internalTokenValidator = serviceauth.NewTokenValidator(fixture.secret, nil, 0)
	usageDB, authDB = nil, nil
	http.DefaultClient = &http.Client{Transport: governedModelRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		fixture.orchestrations.Add(1)
		encoded, err := json.Marshal(response(request))
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(encoded)),
			Request:    request,
		}, nil
	})}
	orchestratorURL = "http://governed-model-orchestrator.invalid"
	t.Cleanup(func() {
		costService, orchestratorURL, internalTokenValidator = previousCost, previousURL, previousValidator
		http.DefaultClient = previousHTTPClient
		usageDB, authDB = previousUsageDB, previousAuthDB
	})
	return fixture
}

func (fixture *governedModelFixture) request(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if json.Unmarshal(encoded, &envelope) == nil {
		if value, exists := envelope["correlation"]; !exists || value == nil {
			envelope["correlation"] = testGovernedModelCorrelation()
			encoded, err = json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return fixture.requestBytes(t, encoded)
}

func testGovernedModelCorrelation() GovernedModelCorrelation {
	return GovernedModelCorrelation{RequestID: uuid.NewString(), TraceID: strings.Repeat("c", 32),
		Module: "payment_exception", CaseID: "case-test", EvidenceVersion: strings.Repeat("a", 64),
		InvestigationKey: strings.Repeat("b", 64)}
}

func (fixture *governedModelFixture) requestBytes(t *testing.T, encoded []byte) *httptest.ResponseRecorder {
	t.Helper()
	subject := hostedOutcomeSubject(t, fixture.org, fixture.tenant)
	token, err := serviceauth.NewTokenGenerator(fixture.secret, nil).GenerateTokenForSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/governed/model", bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(serviceauth.SubjectHeader, subject)
	request.Header.Set(serviceauth.ServiceIDHeader, serviceauth.ClientID)
	request.Header.Set(serviceauth.ServiceTokenHeader, token)
	request.Header.Set("X-Org-ID", "attacker-org")
	request.Header.Set("X-Tenant-ID", "attacker-tenant")
	recorder := httptest.NewRecorder()
	governedModelRequestHandler(recorder, request)
	return recorder
}

func (fixture *governedModelFixture) statusRequest(t *testing.T, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	subject := hostedOutcomeSubject(t, fixture.org, fixture.tenant)
	token, err := serviceauth.NewTokenGenerator(fixture.secret, nil).GenerateTokenForSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/governed/model/status?request_id="+requestID, nil)
	request.Header.Set(serviceauth.SubjectHeader, subject)
	request.Header.Set(serviceauth.ServiceIDHeader, serviceauth.ClientID)
	request.Header.Set(serviceauth.ServiceTokenHeader, token)
	recorder := httptest.NewRecorder()
	governedModelStatusHandler(recorder, request)
	return recorder
}

func (fixture *governedModelFixture) readinessRequest(t *testing.T, module string) *httptest.ResponseRecorder {
	t.Helper()
	subject := hostedOutcomeSubject(t, fixture.org, fixture.tenant)
	token, err := serviceauth.NewTokenGenerator(fixture.secret, nil).GenerateTokenForSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"/api/v1/governed/model/readiness?module="+module, nil)
	request.Header.Set(serviceauth.SubjectHeader, subject)
	request.Header.Set(serviceauth.ServiceIDHeader, serviceauth.ClientID)
	request.Header.Set(serviceauth.ServiceTokenHeader, token)
	recorder := httptest.NewRecorder()
	governedModelReadinessHandler(recorder, request)
	return recorder
}

func decodeGovernedModelResponse(t *testing.T, recorder *httptest.ResponseRecorder) ClientResponse {
	t.Helper()
	var response ClientResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not ClientResponse JSON: %v\n%s", err, recorder.Body.String())
	}
	return response
}

// orchestratorEnvelope is the real Orchestrator ProcessResponse wrapper
// (enrichResponse): the answer under "data" beside "metadata". The Agent passes
// it through unchanged, exactly as /api/request does.
func orchestratorEnvelope(answer any) map[string]any {
	return map[string]any{"data": answer, "metadata": map[string]any{"processed_at": "2026-01-01T00:00:00Z"}}
}

func modelAttempt(success bool) map[string]any {
	return map[string]any{
		"success": success,
		"data":    orchestratorEnvelope("bounded recommendation"),
		"provider_info": map[string]any{
			"provider": "ollama", "model": "llama3.2", "tokens_used": 19, "cost": 0.002,
		},
	}
}

func TestGovernedModelStatusIsDurableAndTenantScoped(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("model status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	status := fixture.statusRequest(t, response.RequestID)
	if status.Code != http.StatusOK {
		t.Fatalf("status lookup=%d body=%s", status.Code, status.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(status.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["request_id"] != response.RequestID || body["status"] != "completed" {
		t.Fatalf("unexpected durable status: %#v", body)
	}
	fixture.tenant = "model-tenant-b"
	if cross := fixture.statusRequest(t, response.RequestID); cross.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant status=%d want 404 body=%s", cross.Code, cross.Body.String())
	}
}

func TestGovernedModelRejectsCallerIdentityMetadata(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	recorder := fixture.request(t, map[string]any{
		"query": "investigate", "context": map[string]any{"metadata": map[string]any{"tenantId": "victim"}},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("orchestrator calls=%d want 0", got)
	}
}

func TestGovernedModelRejectsMissingCorrelationBeforeOrchestration(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	recorder := fixture.requestBytes(t, []byte(`{"query":"investigate","context":{}}`))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "correlation is required") {
		t.Fatalf("status=%d want 400 missing-correlation refusal; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("orchestrator calls=%d want 0", got)
	}
	if len(fixture.repo.attempts) != 0 || len(fixture.repo.saved()) != 0 {
		t.Fatal("missing correlation created a durable attempt or usage row")
	}
}

func TestGovernedModelReadinessIsAuthenticatedDurableAndNonSpending(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	for _, module := range []string{"payment_exception", "support_refund"} {
		recorder := fixture.readinessRequest(t, module)
		if recorder.Code != http.StatusOK {
			t.Fatalf("module=%s status=%d body=%s", module, recorder.Code, recorder.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		principal, _ := body["authenticated_principal"].(map[string]any)
		if body["operational"] != true || body["spending"] != false || body["journal_ready"] != true ||
			body["module"] != module || principal["organization_id"] != fixture.org ||
			principal["tenant_id"] != fixture.tenant || principal["principal_id"] != "hosted-outcome-service" {
			t.Fatalf("invalid readiness receipt: %#v", body)
		}
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("readiness made %d orchestrator/provider calls", got)
	}
	if len(fixture.repo.attempts) != 0 || len(fixture.repo.saved()) != 0 {
		t.Fatal("readiness created a durable attempt or usage row")
	}
	// The same request after the logical process state is cleared remains valid
	// because readiness is derived from authenticated scope and the durable journal.
	fixture.repo.attempts = map[string]cost.GovernedModelAttempt{}
	if recorder := fixture.readinessRequest(t, "payment_exception"); recorder.Code != http.StatusOK {
		t.Fatalf("restart readiness status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGovernedModelReadinessFailsClosedWhenJournalUnavailable(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	fixture.repo.journalErr = errors.New("journal unavailable")
	if recorder := fixture.readinessRequest(t, "payment_exception"); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("failed readiness made %d orchestrator/provider calls", got)
	}
}

func TestHostedFreshStartUsesRealAgentReadinessWithoutSpend(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	python := `
import json
import os
from hosted_governance import HostedModelClientFactory
from workflow import Principal

principal = Principal(os.environ["READINESS_ORG"], os.environ["READINESS_TENANT"], "hosted-outcome-readiness")
factory = HostedModelClientFactory(
    os.environ["READINESS_AGENT_URL"], os.environ["READINESS_SECRET"].encode(),
    frozenset({"payment_exception", "support_refund"}), timeout=2)
factory.wait_until_ready(principal, 2)
print(json.dumps(factory.health(), sort_keys=True))
`
	runFreshProcess := func() map[string]any {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(governedModelReadinessHandler))
		defer server.Close()
		command := exec.Command("python3", "-c", python)
		command.Dir = "../../ee/examples/payment-exception-shadow"
		command.Env = append(os.Environ(),
			"READINESS_AGENT_URL="+server.URL,
			"READINESS_SECRET="+fixture.secret,
			"READINESS_ORG="+fixture.org,
			"READINESS_TENANT="+fixture.tenant,
		)
		output, err := command.Output()
		if err != nil {
			t.Fatalf("Hosted startup readiness failed: %v", err)
		}
		var health map[string]any
		if err := json.Unmarshal(output, &health); err != nil {
			t.Fatalf("decode Hosted health: %v: %s", err, output)
		}
		return health
	}
	for run := 0; run < 2; run++ {
		health := runFreshProcess()
		if health["operational"] != true {
			t.Fatalf("run %d health=%#v", run, health)
		}
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("fresh start/restart made %d orchestrator/provider calls", got)
	}
	if len(fixture.repo.attempts) != 0 || len(fixture.repo.saved()) != 0 {
		t.Fatal("fresh start/restart created an attempt or usage row")
	}
}

func TestGovernedModelRejectsCallerPolicyRoutingEffects(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	recorder := fixture.request(t, map[string]any{
		"query": "investigate", "context": map[string]any{"policy_preferred_provider": "attacker-provider"},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("orchestrator calls=%d want 0", got)
	}
}

func TestGovernedModelHonorsDocumentedCharacterLimit(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	recorder := fixture.request(t, GovernedModelRequest{Query: strings.Repeat("é", governedModelQueryLimit)})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 for %d-character query; body=%s", recorder.Code, governedModelQueryLimit, recorder.Body.String())
	}
	recorder = fixture.request(t, GovernedModelRequest{Query: strings.Repeat("x", governedModelQueryLimit+1)})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 above character limit; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGovernedModelRejectsOversizedEncodedBodyBeforeOrchestration(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	correlation, err := json.Marshal(testGovernedModelCorrelation())
	if err != nil {
		t.Fatal(err)
	}
	prefix := []byte(`{"query":"investigate","correlation":` + string(correlation) + `,"context":{"padding":"`)
	suffix := []byte(`"}}`)
	exact := append(append(append([]byte{}, prefix...), bytes.Repeat([]byte("x"), governedModelBodyLimit-len(prefix)-len(suffix))...), suffix...)
	if len(exact) != governedModelBodyLimit {
		t.Fatalf("test body bytes=%d want %d", len(exact), governedModelBodyLimit)
	}
	recorder := fixture.requestBytes(t, exact)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 at exact %d-byte boundary; body=%s", recorder.Code, governedModelBodyLimit, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 1 {
		t.Fatalf("orchestrator calls=%d want 1 at exact boundary", got)
	}

	oversized := append(append([]byte{}, exact...), ' ')
	recorder = fixture.requestBytes(t, oversized)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413 at %d bytes; body=%s", recorder.Code, governedModelBodyLimit+1, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 1 {
		t.Fatalf("orchestrator calls=%d want unchanged 1 after oversized body", got)
	}
}

func TestGovernedModelOpenAPIReservedKeysAndBodyLimitMatchCode(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/agent-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(raw)
	start := strings.Index(spec, "  /api/v1/governed/model:")
	end := strings.Index(spec[start+1:], "\n  /api/")
	if start < 0 || end < 0 {
		t.Fatal("governed model OpenAPI operation not found")
	}
	operation := spec[start : start+1+end]
	for _, key := range governedModelReservedPlatformContextKeys {
		if !strings.Contains(operation, "`"+key+"`") {
			t.Errorf("OpenAPI governed-model contract omits reserved context key %q", key)
		}
	}
	if !strings.Contains(operation, "1,000,000 bytes") || !strings.Contains(operation, "        '413':") {
		t.Errorf("OpenAPI governed-model contract omits %d-byte body limit or 413 response", governedModelBodyLimit)
	}
}

func TestGovernedModelOpenAPIDocumentsNonSpendingReadiness(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/agent-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(raw)
	start := strings.Index(spec, "  /api/v1/governed/model/readiness:")
	end := strings.Index(spec[start+1:], "\n  /api/")
	if start < 0 || end < 0 {
		t.Fatal("governed model readiness OpenAPI operation not found")
	}
	operation := spec[start : start+1+end]
	for _, contract := range []string{"spending", "enum: [false]", "journal_ready", "payment_exception", "support_refund"} {
		if !strings.Contains(operation, contract) {
			t.Errorf("readiness contract omits %q", contract)
		}
	}
}

func TestGovernedModelBudgetDenyMakesNoProviderCall(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	now := time.Now().UTC()
	fixture.repo.budgets["org-limit"] = &cost.Budget{
		ID: "org-limit", Name: "Model spend", Scope: cost.ScopeOrganization, ScopeID: fixture.org,
		LimitUSD: 1, Period: cost.PeriodMonthly, OnExceed: cost.OnExceedBlock, Enabled: true,
		OrgID: fixture.org, TenantID: fixture.tenant, CreatedAt: now, UpdatedAt: now,
	}
	fixture.repo.usageSum[string(cost.ScopeOrganization)+":"+fixture.org] = 1
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusPaymentRequired {
		t.Fatalf("status=%d want 402; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("orchestrator calls=%d want 0", got)
	}
}

func TestGovernedModelBudgetStoreFailureMakesNoProviderCall(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	fixture.repo.budgetErr = errors.New("budget store unavailable")
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("orchestrator calls=%d want 0", got)
	}
}

func TestGovernedModelBindsPrincipalAndUsageToAuthenticatedTenant(t *testing.T) {
	const tenant = "model-tenant-a"
	fixture := setupGovernedModelFixture(t, func(request *http.Request) map[string]any {
		var forwarded map[string]any
		if err := json.NewDecoder(request.Body).Decode(&forwarded); err != nil {
			t.Errorf("decode forwarded request: %v", err)
		}
		if got := request.Header.Get("X-Org-ID"); got != enfOrgImplicit {
			t.Errorf("forwarded org=%q want %q", got, enfOrgImplicit)
		}
		if got := request.Header.Get("X-Tenant-ID"); got != tenant {
			t.Errorf("forwarded tenant=%q want %q", got, tenant)
		}
		if got := request.Header.Get("X-Client-ID"); got != "hosted-outcome-service" {
			t.Errorf("forwarded authenticated service principal=%q", got)
		}
		contextValue, _ := forwarded["context"].(map[string]any)
		if _, callerControlled := contextValue[governedModelDisableFailoverContextKey]; callerControlled {
			t.Errorf("platform failover control leaked into caller JSON: %#v", contextValue)
		}
		if got := request.Header.Get(sharedidentity.HeaderDisableLLMFailover); got != sharedidentity.DisableLLMFailoverAsserted {
			t.Errorf("trusted failover assertion=%q want %q", got, sharedidentity.DisableLLMFailoverAsserted)
		}
		return modelAttempt(true)
	})
	recorder := fixture.request(t, map[string]any{"query": "investigate", "context": map[string]any{"case_id": "case-1"}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.AuthenticatedPrincipal == nil || response.AuthenticatedPrincipal.PrincipalID != "hosted-outcome-service" ||
		response.AuthenticatedPrincipal.OrganizationID != fixture.org || response.AuthenticatedPrincipal.TenantID != fixture.tenant {
		t.Fatalf("principal=%+v", response.AuthenticatedPrincipal)
	}
	if response.RequestID == "" || response.UsageReceipt == nil || !response.UsageReceipt.Recorded || response.UsageReceipt.RequestID != response.RequestID || response.UsageReceipt.Status != "recorded" {
		t.Fatalf("request/usage receipt not bound: request_id=%q receipt=%+v", response.RequestID, response.UsageReceipt)
	}
	records := fixture.repo.saved()
	if len(records) != 1 || records[0].RequestID != response.RequestID || records[0].OrgID != fixture.org || records[0].TenantID != fixture.tenant {
		t.Fatalf("canonical usage=%+v", records)
	}
}

func TestGovernedModelPreservesUsageForPostProviderFailure(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any {
		result := modelAttempt(false)
		result["error"] = "provider result failed schema validation"
		return result
	})
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.UsageReceipt == nil || !response.UsageReceipt.Attempted || !response.UsageReceipt.Recorded || response.UsageReceipt.Status != "recorded" || response.ProviderInfo == nil {
		t.Fatalf("post-provider receipt was lost: %+v", response)
	}
	if response.Data != nil {
		t.Fatalf("failed provider result was released: %+v", response.Data)
	}
	if records := fixture.repo.saved(); len(records) != 1 {
		t.Fatalf("usage rows=%d want 1", len(records))
	}
}

func TestGovernedModelCommitsUsageBeforeConsumerParsesMalformedResult(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any {
		result := modelAttempt(true)
		result["data"] = orchestratorEnvelope("not valid structured JSON")
		return result
	})
	recorder := fixture.request(t, GovernedModelRequest{Query: "return a structured recommendation"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.UsageReceipt == nil || !response.UsageReceipt.Recorded || response.UsageReceipt.Status != "recorded" || response.ProviderInfo == nil {
		t.Fatalf("consumer parse failure would lose attempt evidence: %+v", response)
	}
	if records := fixture.repo.saved(); len(records) != 1 {
		t.Fatalf("usage rows=%d want 1", len(records))
	}
}

func TestGovernedModelUsageIsTenantIsolatedAcrossSubjectBoundCalls(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	first := fixture.request(t, GovernedModelRequest{Query: "first tenant"})
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	fixture.tenant = "model-tenant-b"
	second := fixture.request(t, GovernedModelRequest{Query: "second tenant"})
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	records := fixture.repo.saved()
	if len(records) != 2 || records[0].TenantID != "model-tenant-a" || records[1].TenantID != "model-tenant-b" {
		t.Fatalf("cross-tenant usage attribution: %+v", records)
	}
}

func TestGovernedModelRejectsSuccessWithoutProviderAttemptMetadata(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any {
		return map[string]any{"success": true, "data": orchestratorEnvelope("unattributed")}
	})
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.Success || !response.Blocked || response.Data != nil || response.UsageReceipt == nil || response.UsageReceipt.Attempted || response.UsageReceipt.Status != "not_attempted" {
		t.Fatalf("unattributed success was released: %+v", response)
	}
}

func TestGovernedModelDoesNotInventAttemptForNullProviderInfo(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any {
		return map[string]any{"success": false, "error": "request refused before provider", "provider_info": nil}
	})
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.UsageReceipt == nil || response.UsageReceipt.Attempted || response.UsageReceipt.Recorded || response.UsageReceipt.Status != "not_attempted" {
		t.Fatalf("pre-provider refusal was mislabeled as an attempt: %+v", response)
	}
	if records := fixture.repo.saved(); len(records) != 0 {
		t.Fatalf("pre-provider refusal wrote %d usage rows", len(records))
	}
}

func TestGovernedModelFailsClosedWhenUsageCannotBeCommitted(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	fixture.repo.saveErr = errors.New("usage store unavailable")
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.Success || !response.Blocked || response.Data != nil || response.ProviderInfo == nil || response.UsageReceipt == nil || response.UsageReceipt.Recorded {
		t.Fatalf("failed usage commit did not preserve attempt evidence: %+v", response)
	}
	if !response.UsageReceipt.Attempted || response.UsageReceipt.Status != "record_failed" {
		t.Fatalf("failed usage commit receipt status=%+v want record_failed", response.UsageReceipt)
	}
}

func TestGovernedModelLabelsIncompleteProviderAttemptAsUnrecorded(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any {
		result := modelAttempt(true)
		result["provider_info"] = map[string]any{
			"attempted": true, "provider": "ollama", "tokens_used": 19, "cost": 0.002,
		}
		return result
	})
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.UsageReceipt == nil || !response.UsageReceipt.Attempted || response.UsageReceipt.Recorded ||
		response.UsageReceipt.Status != "attempted_unrecorded" {
		t.Fatalf("incomplete provider attempt receipt=%+v want attempted_unrecorded", response.UsageReceipt)
	}
	if records := fixture.repo.saved(); len(records) != 0 {
		t.Fatalf("incomplete provider attempt wrote %d usage rows", len(records))
	}
}

func TestGovernedModelDoesNotForwardWithoutDurableAttemptIntent(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	fixture.repo.journalErr = errors.New("journal unavailable")
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.UsageReceipt == nil || response.UsageReceipt.Attempted || response.UsageReceipt.Recorded ||
		response.UsageReceipt.Status != "not_attempted" {
		t.Fatalf("journal refusal receipt=%+v want not_attempted", response.UsageReceipt)
	}
	if got := fixture.orchestrations.Load(); got != 0 {
		t.Fatalf("orchestrator calls=%d want 0", got)
	}
}

func TestGovernedModelTruncatedOrchestratorResponseKeepsUnknownAttemptReceipt(t *testing.T) {
	fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any { return modelAttempt(true) })
	http.DefaultClient = &http.Client{Transport: governedModelRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		fixture.orchestrations.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"success":true,"provider_info":`)), Request: request}, nil
	})}
	recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	response := decodeGovernedModelResponse(t, recorder)
	if response.UsageReceipt == nil || !response.UsageReceipt.Attempted || response.UsageReceipt.Recorded ||
		response.UsageReceipt.RequestID == "" || response.UsageReceipt.Status != "outcome_unknown" {
		t.Fatalf("unknown provider outcome lost durable attempt receipt: %+v", response)
	}
	fixture.repo.mu.Lock()
	attempt := fixture.repo.attempts[response.RequestID]
	fixture.repo.mu.Unlock()
	if attempt.Status != "outcome_unknown" {
		t.Fatalf("attempt status=%q want outcome_unknown", attempt.Status)
	}
}

func TestGovernedModelRequiresSubjectBoundCredential(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/governed/model", bytes.NewBufferString(`{"query":"investigate"}`))
	governedModelRequestHandler(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGovernedModelPassesThroughOrchestratorEnvelope(t *testing.T) {
	for name, answer := range map[string]any{
		"string": "bounded recommendation",
		"object": map[string]any{"verdict": "approve", "score": float64(3)},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := setupGovernedModelFixture(t, func(*http.Request) map[string]any {
				result := modelAttempt(true)
				result["data"] = orchestratorEnvelope(answer)
				return result
			})
			recorder := fixture.request(t, GovernedModelRequest{Query: "investigate"})
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d want 200; body=%s", recorder.Code, recorder.Body.String())
			}
			var raw map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			if want := any(orchestratorEnvelope(answer)); !reflect.DeepEqual(raw["data"], want) {
				t.Fatalf("data=%#v want %#v", raw["data"], want)
			}
		})
	}
}
