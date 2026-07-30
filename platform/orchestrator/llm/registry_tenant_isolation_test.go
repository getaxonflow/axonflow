// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Cross-tenant isolation of the LLM provider registry (#3067 S-2 / S-3).
//
// ProviderConfig.TenantID always existed but was not the map key, so the
// read/test/routing surface resolved any tenant's provider by name. Most
// severely, POST /api/v1/llm-providers/{name}/test ran a completion through
// another tenant's provider — spending and billing their API key.
//
// Vacuity: against the pre-fix code the maps were keyed by name alone, so
// `Get(ctx, tenantB, name)` (which did not exist — it was `Get(ctx, name)`)
// resolved tenant A's provider. Every refusal assertion below would fail.

package llm

import (
	"context"
	"sync"
	"testing"
	"time"
)

// spendingProvider records every completion so a test can prove that a
// refused request never reached the upstream API — i.e. never spent the key.
type spendingProvider struct {
	mu        sync.Mutex
	completes int
	healths   int
	name      string
}

func (p *spendingProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	p.mu.Lock()
	p.completes++
	p.mu.Unlock()
	return &CompletionResponse{Content: "billed to " + p.name, Model: "m"}, nil
}

func (p *spendingProvider) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	p.mu.Lock()
	p.healths++
	p.mu.Unlock()
	return &HealthCheckResult{Status: HealthStatusHealthy, LastChecked: time.Now()}, nil
}

func (p *spendingProvider) Type() ProviderType      { return ProviderTypeOpenAI }
func (p *spendingProvider) Name() string            { return p.name }
func (p *spendingProvider) SupportsStreaming() bool { return false }
func (p *spendingProvider) Capabilities() []Capability {
	return []Capability{CapabilityCompletion}
}
func (p *spendingProvider) EstimateCost(req CompletionRequest) *CostEstimate { return nil }

func (p *spendingProvider) completions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.completes
}

func (p *spendingProvider) healthChecks() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.healths
}

const (
	llmTenantA = "org-alpha"
	llmTenantB = "org-beta"
)

func twoTenantLLMRegistry(t *testing.T) (*Registry, *spendingProvider, *spendingProvider) {
	t.Helper()

	r := NewRegistry()
	provA := &spendingProvider{name: "alpha"}
	provB := &spendingProvider{name: "beta"}

	if err := r.RegisterProvider("gpt", provA, &ProviderConfig{
		Name: "gpt", Type: ProviderTypeOpenAI, APIKey: "alpha-key", TenantID: llmTenantA, Enabled: true, Weight: 10,
	}); err != nil {
		t.Fatalf("register A: %v", err)
	}
	if err := r.RegisterProvider("gpt", provB, &ProviderConfig{
		Name: "gpt", Type: ProviderTypeOpenAI, APIKey: "beta-key", TenantID: llmTenantB, Enabled: true, Weight: 20,
	}); err != nil {
		t.Fatalf("register B: %v", err)
	}
	return r, provA, provB
}

func TestLLMRegistry_TenantsCannotResolveEachOthersProviders(t *testing.T) {
	r, provA, provB := twoTenantLLMRegistry(t)
	ctx := context.Background()

	// Positive controls.
	gotA, err := r.Get(ctx, llmTenantA, "gpt")
	if err != nil {
		t.Fatalf("tenant A must resolve its own provider: %v", err)
	}
	if gotA != Provider(provA) {
		t.Error("tenant A resolved the wrong provider instance")
	}
	gotB, err := r.Get(ctx, llmTenantB, "gpt")
	if err != nil {
		t.Fatalf("tenant B must resolve its own provider: %v", err)
	}
	if gotB != Provider(provB) {
		t.Error("tenant B resolved the wrong provider instance")
	}

	// Refusal: a third tenant naming the provider gets nothing, and NOTHING
	// upstream was called.
	if _, err := r.Get(ctx, "org-gamma", "gpt"); err == nil {
		t.Fatal("an unrelated tenant must not resolve a provider by name")
	}
	if provA.completions() != 0 || provB.completions() != 0 {
		t.Fatal("a refused resolution must never touch a provider")
	}
}

func TestLLMRegistry_ConfigDisclosureIsTenantScoped(t *testing.T) {
	r, _, _ := twoTenantLLMRegistry(t)

	cfgA, err := r.GetConfig(llmTenantA, "gpt")
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if cfgA.APIKey != "alpha-key" {
		t.Fatalf("tenant A read the wrong config (%q)", cfgA.APIKey)
	}
	cfgB, err := r.GetConfig(llmTenantB, "gpt")
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if cfgB.APIKey == "alpha-key" {
		t.Fatal("tenant B read tenant A's API key")
	}

	if _, err := r.GetConfig("org-gamma", "gpt"); err == nil {
		t.Fatal("an unrelated tenant must not read either config")
	}
	if r.Has("org-gamma", "gpt") {
		t.Fatal("Has must not disclose another tenant's provider")
	}
	if !r.Has(llmTenantA, "gpt") {
		t.Fatal("positive control: Has must find the caller's own provider")
	}
}

func TestLLMRegistry_ListAndHealthAreTenantScoped(t *testing.T) {
	r := NewRegistry()
	provA := &spendingProvider{name: "alpha"}
	provB := &spendingProvider{name: "beta"}

	if err := r.RegisterProvider("alpha-gpt", provA, &ProviderConfig{
		Name: "alpha-gpt", Type: ProviderTypeOpenAI, TenantID: llmTenantA, Enabled: true,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.RegisterProvider("beta-gpt", provB, &ProviderConfig{
		Name: "beta-gpt", Type: ProviderTypeOpenAI, TenantID: llmTenantB, Enabled: true,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	namesA := r.List(llmTenantA)
	if len(namesA) != 1 || namesA[0] != "alpha-gpt" {
		t.Fatalf("tenant A must see only its own provider, got %v", namesA)
	}
	if enabled := r.ListEnabled(llmTenantA); len(enabled) != 1 || enabled[0] != "alpha-gpt" {
		t.Fatalf("ListEnabled leaked across tenants: %v", enabled)
	}
	if byType := r.ListByType(llmTenantA, ProviderTypeOpenAI); len(byType) != 1 {
		t.Fatalf("ListByType leaked across tenants: %v", byType)
	}
	if got := r.Count(llmTenantA); got != 1 {
		t.Fatalf("Count must be tenant-scoped, got %d", got)
	}

	// A health sweep must not open a connection for a foreign provider.
	results := r.HealthCheck(context.Background(), llmTenantA)
	if _, ok := results["alpha-gpt"]; !ok {
		t.Error("positive control: tenant A must get its own health result")
	}
	if _, ok := results["beta-gpt"]; ok {
		t.Fatal("tenant A's health sweep reached tenant B's provider")
	}
	if provB.healthChecks() != 0 {
		t.Fatal("tenant B's provider was health-checked on tenant A's request")
	}
	if provA.healthChecks() != 1 {
		t.Fatalf("positive control: tenant A's provider should be checked once, got %d", provA.healthChecks())
	}

	if r.GetHealthResult(llmTenantA, "beta-gpt") != nil {
		t.Fatal("cached health results must be tenant-scoped")
	}
	if healthy := r.GetHealthyProviders(llmTenantA); len(healthy) != 1 || healthy[0] != "alpha-gpt" {
		t.Fatalf("GetHealthyProviders leaked across tenants: %v", healthy)
	}
}

// TestLLMRegistry_MutationsRequireOwnership is the S-3 write half: PUT
// /routing used to persist a weight onto ANOTHER tenant's row, silently
// disabling their LLM routing. Ownership is now the resolution rule for
// every mutation, and deployment-level providers are equally off-limits.
func TestLLMRegistry_MutationsRequireOwnership(t *testing.T) {
	r, _, _ := twoTenantLLMRegistry(t)
	ctx := context.Background()

	if err := r.RegisterProvider("deployment-gpt", &spendingProvider{name: "deployment"}, &ProviderConfig{
		Name: "deployment-gpt", Type: ProviderTypeOpenAI, Enabled: true,
	}); err != nil {
		t.Fatalf("register deployment provider: %v", err)
	}

	if !r.OwnsProvider(llmTenantA, "gpt") {
		t.Fatal("positive control: tenant A owns its own provider")
	}
	if r.OwnsProvider(llmTenantA, "deployment-gpt") {
		t.Fatal("a tenant must not own a deployment-level provider")
	}
	if r.OwnsProvider("org-gamma", "gpt") {
		t.Fatal("an unrelated tenant must not own another tenant's provider")
	}

	// Update targeting B's provider under A's tenancy must not find anything.
	err := r.Update(ctx, &ProviderConfig{
		Name: "gpt", Type: ProviderTypeOpenAI, APIKey: "hijacked", TenantID: "org-gamma", Weight: 999,
	})
	if err == nil {
		t.Fatal("update under a tenancy that owns nothing must fail")
	}
	cfgB, getErr := r.GetConfig(llmTenantB, "gpt")
	if getErr != nil {
		t.Fatalf("tenant B config must still be readable: %v", getErr)
	}
	if cfgB.Weight != 20 || cfgB.APIKey != "beta-key" {
		t.Fatalf("tenant B's provider was mutated cross-tenant: %+v", cfgB)
	}

	// Positive control: the owner CAN update.
	if err := r.Update(ctx, &ProviderConfig{
		Name: "gpt", Type: ProviderTypeOpenAI, APIKey: "beta-key", TenantID: llmTenantB, Weight: 55,
	}); err != nil {
		t.Fatalf("positive control: owner update must succeed: %v", err)
	}
	cfgB, _ = r.GetConfig(llmTenantB, "gpt")
	if cfgB.Weight != 55 {
		t.Fatalf("owner update did not take effect: %+v", cfgB)
	}

	// Unregister / Enable / Disable are likewise ownership-scoped.
	if err := r.Unregister(ctx, "org-gamma", "gpt"); err == nil {
		t.Fatal("cross-tenant unregister must fail")
	}
	if !r.Has(llmTenantA, "gpt") {
		t.Fatal("cross-tenant unregister removed the provider anyway")
	}
	if err := r.Enable("org-gamma", "gpt"); err == nil {
		t.Fatal("cross-tenant enable must fail")
	}
	if err := r.Disable("org-gamma", "gpt"); err == nil {
		t.Fatal("cross-tenant disable must fail")
	}
	if err := r.Disable(llmTenantA, "gpt"); err != nil {
		t.Fatalf("positive control: owner disable must succeed: %v", err)
	}
}

// TestLLMRegistry_DeploymentProvidersRemainRoutable proves the fix did not
// break enforcement: the bootstrap's system providers (no TenantID) still
// live in the pool the deployment router selects from.
func TestLLMRegistry_DeploymentProvidersRemainRoutable(t *testing.T) {
	r := NewRegistry()
	sys := &spendingProvider{name: "system"}
	if err := r.RegisterProvider("system-gpt", sys, &ProviderConfig{
		Name: "system-gpt", Type: ProviderTypeOpenAI, Enabled: true,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	if !r.Has(GlobalTenant, "system-gpt") {
		t.Fatal("the router's global scope must still see bootstrap providers")
	}
	if names := r.ListEnabled(GlobalTenant); len(names) != 1 || names[0] != "system-gpt" {
		t.Fatalf("global ListEnabled must include the bootstrap provider, got %v", names)
	}
	if _, err := r.Get(context.Background(), GlobalTenant, "system-gpt"); err != nil {
		t.Fatalf("global Get must resolve the bootstrap provider: %v", err)
	}

	// And a tenant may READ (and therefore route through) the deployment's
	// own providers — they are the deployment's, not another customer's.
	if !r.Has(llmTenantA, "system-gpt") {
		t.Fatal("a tenant must still see the deployment's providers")
	}
	// ...but must not be able to mutate them.
	if r.OwnsProvider(llmTenantA, "system-gpt") {
		t.Fatal("a tenant must not own a deployment provider")
	}
}

// TestLLMRegistry_DuplicateIsNotACrossTenantOracle: two tenants may each
// register `gpt`; a 409 no longer tells a caller that some other tenant took
// the name.
func TestLLMRegistry_DuplicateIsNotACrossTenantOracle(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	mk := func(tenant string) *ProviderConfig {
		return &ProviderConfig{Name: "gpt", Type: ProviderTypeOpenAI, APIKey: "k", TenantID: tenant}
	}
	if err := r.Register(ctx, mk(llmTenantA)); err != nil {
		t.Fatalf("A register: %v", err)
	}
	if err := r.Register(ctx, mk(llmTenantB)); err != nil {
		t.Fatalf("B must be able to use the same provider name: %v", err)
	}
	if err := r.Register(ctx, mk(llmTenantA)); err == nil {
		t.Fatal("a duplicate WITHIN a tenancy must still be rejected")
	}
}

func TestLLMRegistry_CraftedNameCannotCrossTenancies(t *testing.T) {
	r, _, _ := twoTenantLLMRegistry(t)
	ctx := context.Background()

	for _, crafted := range []string{
		llmTenantA + ":gpt",
		llmTenantA + "/gpt",
		llmTenantA + "\x00gpt",
	} {
		if _, err := r.Get(ctx, llmTenantB, crafted); err == nil {
			t.Errorf("crafted name %q resolved across tenancies", crafted)
		}
	}
}
