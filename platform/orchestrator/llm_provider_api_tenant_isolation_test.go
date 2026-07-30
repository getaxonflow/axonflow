// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Cross-tenant isolation of the LLM provider HTTP API (#3067 S-2 / S-3).
//
// The write handlers (PUT/DELETE) already compared config.TenantID since
// #2384. The read/test/routing handlers never got that check, so:
//
//   - GET  /api/v1/llm-providers            listed every tenant's providers
//   - GET  /api/v1/llm-providers/{name}     returned another tenant's config
//   - GET  /api/v1/llm-providers/status     health-checked everyone's
//   - PUT  /api/v1/llm-providers/routing    wrote onto another tenant's row
//   - POST /api/v1/llm-providers/{name}/test  SPENT another tenant's API key
//
// Vacuity: against the pre-fix code the handlers resolved by name only, so
// tenant A's request for tenant B's provider returned 200 and — for /test —
// incremented the victim provider's completion counter. Every assertion below
// would fail.

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"axonflow/platform/orchestrator/llm"
)

// billableProvider counts completions so a test can prove the refusal path
// never reaches the upstream API.
type billableProvider struct {
	mu        sync.Mutex
	completes int
	owner     string
}

func (p *billableProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	p.mu.Lock()
	p.completes++
	p.mu.Unlock()
	return &llm.CompletionResponse{Content: "billed to " + p.owner, Model: "m"}, nil
}

func (p *billableProvider) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
	return &llm.HealthCheckResult{Status: llm.HealthStatusHealthy, LastChecked: time.Now()}, nil
}

func (p *billableProvider) Type() llm.ProviderType  { return llm.ProviderTypeOpenAI }
func (p *billableProvider) Name() string            { return p.owner }
func (p *billableProvider) SupportsStreaming() bool { return false }
func (p *billableProvider) Capabilities() []llm.Capability {
	return []llm.Capability{llm.CapabilityCompletion}
}
func (p *billableProvider) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate { return nil }

func (p *billableProvider) completions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.completes
}

// victimAPIFixture builds a handler whose registry holds ONE provider, owned
// by "org-victim".
func victimAPIFixture(t *testing.T) (*LLMProviderAPIHandler, *billableProvider) {
	t.Helper()

	registry := llm.NewRegistry()
	victim := &billableProvider{owner: "org-victim"}
	if err := registry.RegisterProvider("victim-gpt", victim, &llm.ProviderConfig{
		Name:     "victim-gpt",
		Type:     llm.ProviderTypeOpenAI,
		APIKey:   "victim-api-key",
		Endpoint: "https://victim.internal/v1",
		TenantID: "org-victim",
		Enabled:  true,
		Weight:   10,
	}); err != nil {
		t.Fatalf("register victim provider: %v", err)
	}
	return NewLLMProviderAPIHandler(registry, nil), victim
}

// TestLLMProviderAPI_TestEndpointDeniesBeforeSpendingAnotherTenantsKey is the
// S-2 CRITICAL case.
func TestLLMProviderAPI_TestEndpointDeniesBeforeSpendingAnotherTenantsKey(t *testing.T) {
	handler, victim := victimAPIFixture(t)
	router := createTestRouter(handler)

	body, _ := json.Marshal(map[string]string{"prompt": "drain their quota"})
	req := withTenant(httptest.NewRequest(http.MethodPost,
		"/api/v1/llm-providers/victim-gpt/test", bytes.NewReader(body)), "org-attacker")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for a cross-tenant test, got %d: %s", w.Code, w.Body.String())
	}
	// The load-bearing assertion: no upstream call, so no key was spent.
	if got := victim.completions(); got != 0 {
		t.Fatalf("victim provider was invoked %d time(s) by another tenant", got)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("billed to")) {
		t.Fatal("the attacker received the victim's completion")
	}

	// Positive control: the OWNER can still test its own provider.
	body, _ = json.Marshal(map[string]string{"prompt": "hello"})
	req = withTenant(httptest.NewRequest(http.MethodPost,
		"/api/v1/llm-providers/victim-gpt/test", bytes.NewReader(body)), "org-victim")
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("positive control: owner must be able to test its provider, got %d: %s", w.Code, w.Body.String())
	}
	if got := victim.completions(); got != 1 {
		t.Fatalf("positive control: expected exactly 1 completion, got %d", got)
	}
}

// TestLLMProviderAPI_TestEndpointRequiresTenantIdentity: no asserted tenancy
// must not fall back to a deployment-wide view.
func TestLLMProviderAPI_TestEndpointRequiresTenantIdentity(t *testing.T) {
	handler, victim := victimAPIFixture(t)
	router := createTestRouter(handler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/llm-providers/victim-gpt/test", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally no X-Tenant-ID / X-Org-ID.
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 without an asserted tenancy, got %d: %s", w.Code, w.Body.String())
	}
	if got := victim.completions(); got != 0 {
		t.Fatalf("an unidentified caller spent the provider's key %d time(s)", got)
	}
}

// TestLLMProviderAPI_TestEndpointRefusesTheDeploymentProvider (R3): read
// access to the deployment's own providers is deliberate — they are the pool
// the router already uses for everyone's traffic. SPENDING is not. Without an
// ownership gate on /test, any tenant could run arbitrary prompts through the
// operator's bootstrap provider: an ungoverned LLM egress path on the
// deployment's key, with no check-input/check-output in front of it.
func TestLLMProviderAPI_TestEndpointRefusesTheDeploymentProvider(t *testing.T) {
	registry := llm.NewRegistry()
	deployment := &billableProvider{owner: "deployment"}
	if err := registry.RegisterProvider("bootstrap-gpt", deployment, &llm.ProviderConfig{
		Name: "bootstrap-gpt", Type: llm.ProviderTypeOpenAI, APIKey: "operator-key", Enabled: true,
	}); err != nil {
		t.Fatalf("register deployment provider: %v", err)
	}
	handler := NewLLMProviderAPIHandler(registry, nil)
	router := createTestRouter(handler)

	body, _ := json.Marshal(map[string]string{"prompt": "burn the operator's quota"})
	req := withTenant(httptest.NewRequest(http.MethodPost,
		"/api/v1/llm-providers/bootstrap-gpt/test", bytes.NewReader(body)), "org-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for a tenant testing the deployment provider, got %d: %s", w.Code, w.Body.String())
	}
	if got := deployment.completions(); got != 0 {
		t.Fatalf("SECURITY: a tenant spent the operator's key %d time(s) via /test", got)
	}

	// Positive control: reading it is still allowed — the deployment's
	// providers are visible, just not spendable or mutable by a tenant.
	req = withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/bootstrap-gpt", nil), "org-tenant")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("positive control: a tenant should still be able to READ the deployment provider, got %d", w.Code)
	}
}

// TestLLMProviderAPI_RoutingGetAndPutAgree (R3): a client that reads the
// routing config and writes it straight back must not get a 400. Listing
// deployment providers in GET while gating PUT on ownership broke
// read-modify-write for every UI and client.
func TestLLMProviderAPI_RoutingGetAndPutAgree(t *testing.T) {
	registry := llm.NewRegistry()
	if err := registry.RegisterProvider("bootstrap-gpt", &billableProvider{owner: "deployment"}, &llm.ProviderConfig{
		Name: "bootstrap-gpt", Type: llm.ProviderTypeOpenAI, Enabled: true, Weight: 5,
	}); err != nil {
		t.Fatalf("register deployment provider: %v", err)
	}
	if err := registry.RegisterProvider("own-gpt", &billableProvider{owner: "org-tenant"}, &llm.ProviderConfig{
		Name: "own-gpt", Type: llm.ProviderTypeOpenAI, APIKey: "tenant-key", TenantID: "org-tenant", Enabled: true, Weight: 7,
	}); err != nil {
		t.Fatalf("register tenant provider: %v", err)
	}
	handler := NewLLMProviderAPIHandler(registry, nil)
	router := createTestRouter(handler)

	req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/routing", nil), "org-tenant")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var cfg LLMRoutingConfigResponse
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, leaked := cfg.Weights["bootstrap-gpt"]; leaked {
		t.Error("routing GET listed a provider the tenant cannot write")
	}
	if cfg.Weights["own-gpt"] != 7 {
		t.Fatalf("positive control: the tenant's own weight is missing from routing GET: %+v", cfg.Weights)
	}

	// Echo exactly what was read back — this must succeed.
	body, _ := json.Marshal(UpdateLLMRoutingRequest{Weights: cfg.Weights})
	req = withTenant(httptest.NewRequest(http.MethodPut, "/api/v1/llm-providers/routing", bytes.NewReader(body)), "org-tenant")
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("read-modify-write broken: PUT of the exact GET payload returned %d: %s", w.Code, w.Body.String())
	}
}

func TestLLMProviderAPI_ReadSurfaceIsTenantScoped(t *testing.T) {
	handler, _ := victimAPIFixture(t)
	router := createTestRouter(handler)

	t.Run("list excludes other tenants' providers", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil), "org-attacker")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp LLMProviderListResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Providers) != 0 {
			t.Fatalf("attacker saw %d provider(s) belonging to another tenant: %+v", len(resp.Providers), resp.Providers)
		}
	})

	t.Run("list still returns the caller's own providers", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers", nil), "org-victim")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var resp LLMProviderListResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Providers) != 1 || resp.Providers[0].Name != "victim-gpt" {
			t.Fatalf("positive control: owner must see its own provider, got %+v", resp.Providers)
		}
		if resp.Providers[0].Endpoint != "https://victim.internal/v1" {
			t.Errorf("owner should see its own endpoint, got %q", resp.Providers[0].Endpoint)
		}
	})

	t.Run("get by name is 404 across tenants", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/victim-gpt", nil), "org-attacker")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
		}
		if bytes.Contains(w.Body.Bytes(), []byte("victim.internal")) {
			t.Fatal("the refusal disclosed the victim's endpoint")
		}
	})

	t.Run("health by name is 404 across tenants", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/victim-gpt/health", nil), "org-attacker")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("status excludes other tenants' providers", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/status", nil), "org-attacker")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp LLMProviderHealthAllResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, leaked := resp.Providers["victim-gpt"]; leaked {
			t.Fatal("status disclosed another tenant's provider")
		}
	})

	t.Run("routing GET excludes other tenants' weights", func(t *testing.T) {
		req := withTenant(httptest.NewRequest(http.MethodGet, "/api/v1/llm-providers/routing", nil), "org-attacker")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var resp LLMRoutingConfigResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, leaked := resp.Weights["victim-gpt"]; leaked {
			t.Fatal("routing config disclosed another tenant's provider weight")
		}
	})
}

// TestLLMProviderAPI_RoutingPutCannotWriteAnotherTenantsProvider is the S-3
// write half: PUT /routing persisted straight onto the victim's row.
func TestLLMProviderAPI_RoutingPutCannotWriteAnotherTenantsProvider(t *testing.T) {
	handler, _ := victimAPIFixture(t)
	router := createTestRouter(handler)

	body, _ := json.Marshal(UpdateLLMRoutingRequest{Weights: map[string]int{"victim-gpt": 0}})
	req := withTenant(httptest.NewRequest(http.MethodPut,
		"/api/v1/llm-providers/routing", bytes.NewReader(body)), "org-attacker")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("cross-tenant routing write must be refused, got 200: %s", w.Body.String())
	}

	// The victim's weight must be untouched.
	cfg, err := handler.registry.GetConfig("org-victim", "victim-gpt")
	if err != nil {
		t.Fatalf("victim provider config must still exist: %v", err)
	}
	if cfg.Weight != 10 {
		t.Fatalf("victim's routing weight was mutated cross-tenant: %d", cfg.Weight)
	}

	// Positive control: the owner CAN change its own weight.
	body, _ = json.Marshal(UpdateLLMRoutingRequest{Weights: map[string]int{"victim-gpt": 77}})
	req = withTenant(httptest.NewRequest(http.MethodPut,
		"/api/v1/llm-providers/routing", bytes.NewReader(body)), "org-victim")
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("positive control: owner routing write must succeed, got %d: %s", w.Code, w.Body.String())
	}
	cfg, _ = handler.registry.GetConfig("org-victim", "victim-gpt")
	if cfg.Weight != 77 {
		t.Fatalf("positive control: owner's weight update did not apply, got %d", cfg.Weight)
	}
}

// TestLLMProviderAPI_CreateConflictIsNotACrossTenantOracle: a 409 must mean
// "you already have one", not "somebody else does".
func TestLLMProviderAPI_CreateConflictIsNotACrossTenantOracle(t *testing.T) {
	handler, _ := victimAPIFixture(t)
	router := createTestRouter(handler)

	body, _ := json.Marshal(CreateLLMProviderRequest{
		Name:   "victim-gpt",
		Type:   "openai",
		APIKey: "attacker-key",
	})
	req := withTenant(httptest.NewRequest(http.MethodPost,
		"/api/v1/llm-providers", bytes.NewReader(body)), "org-attacker")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code == http.StatusConflict {
		t.Fatal("a name taken by ANOTHER tenant must not produce a 409 (existence oracle)")
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// And the victim's provider is untouched.
	cfg, err := handler.registry.GetConfig("org-victim", "victim-gpt")
	if err != nil {
		t.Fatalf("victim provider must survive: %v", err)
	}
	if cfg.APIKey != "victim-api-key" {
		t.Fatalf("victim's API key was overwritten: %q", cfg.APIKey)
	}
}
