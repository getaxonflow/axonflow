// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"context"
	"testing"
)

// testAnalyzerType is the custom type used across registry tests.
const testAnalyzerType MediaAnalyzerType = "test-registry-analyzer"

// mockValidator implements AnalyzerLicenseValidator for registry tests.
type mockValidator struct {
	allowed     bool
	max         int
	enforcement EnforcementStrategy
}

func (v *mockValidator) IsAnalyzerAllowed(_ context.Context, _ MediaAnalyzerType) bool {
	return v.allowed
}

func (v *mockValidator) GetMaxAnalyzers(_ context.Context) int {
	return v.max
}

func (v *mockValidator) GetEnforcementStrategy(_ context.Context) EnforcementStrategy {
	return v.enforcement
}

// stubAnalyzer is a minimal MediaAnalyzer for registry tests.
type stubAnalyzer struct {
	name         string
	analyzerType MediaAnalyzerType
	healthy      bool
}

func (a *stubAnalyzer) Name() string                         { return a.name }
func (a *stubAnalyzer) Type() MediaAnalyzerType              { return a.analyzerType }
func (a *stubAnalyzer) Capabilities() []MediaAnalyzerCapability { return nil }

func (a *stubAnalyzer) Analyze(_ context.Context, _ MediaContent) (*MediaAnalysisResult, error) {
	return &MediaAnalysisResult{AnalyzerName: a.name, AnalyzerType: a.analyzerType}, nil
}

func (a *stubAnalyzer) HealthCheck(_ context.Context) error {
	if !a.healthy {
		return &MediaError{Code: ErrMediaAnalysisFailed, Message: "unhealthy"}
	}
	return nil
}

func newStubAnalyzer(name string) *stubAnalyzer {
	return &stubAnalyzer{name: name, analyzerType: testAnalyzerType, healthy: true}
}

// registerTestFactory registers a factory for testAnalyzerType in the global
// registry and returns a cleanup function that unregisters it.
func registerTestFactory(t *testing.T) {
	t.Helper()
	RegisterAnalyzerFactory(testAnalyzerType, func(cfg AnalyzerConfig) (MediaAnalyzer, error) {
		return newStubAnalyzer(cfg.Name), nil
	})
	t.Cleanup(func() {
		UnregisterAnalyzerFactory(testAnalyzerType)
	})
}

// allowAllValidator returns a mockValidator that allows everything.
func allowAllValidator() *mockValidator {
	return &mockValidator{allowed: true, max: -1, enforcement: EnforcementFailOpen}
}

// --- NewRegistry -----------------------------------------------------------

func TestNewRegistry_Defaults(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.factory == nil {
		t.Error("expected non-nil factory manager")
	}
	if r.validator == nil {
		t.Error("expected non-nil validator")
	}
	if r.Count() != 0 {
		t.Errorf("expected 0 analyzers, got %d", r.Count())
	}
}

func TestNewRegistry_WithMaxAnalyzers(t *testing.T) {
	r := NewRegistry(WithMaxAnalyzers(3))
	if r.maxAnalyzers != 3 {
		t.Errorf("expected maxAnalyzers=3, got %d", r.maxAnalyzers)
	}
}

func TestNewRegistry_WithRegistryLicenseValidator(t *testing.T) {
	v := allowAllValidator()
	r := NewRegistry(WithRegistryLicenseValidator(v))
	if r.validator != v {
		t.Error("expected custom validator to be set")
	}
}

// --- Register (config-based) -----------------------------------------------

func TestRegister_ValidConfig(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))

	err := r.Register(context.Background(), &AnalyzerConfig{
		Name:    "test-1",
		Type:    testAnalyzerType,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if !r.Has("test-1") {
		t.Error("expected registry to contain test-1")
	}
}

func TestRegister_NilConfig(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	err := r.Register(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryInvalidConfig {
		t.Errorf("expected code %s, got %s", ErrRegistryInvalidConfig, re.Code)
	}
}

func TestRegister_EmptyName(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	err := r.Register(context.Background(), &AnalyzerConfig{
		Name: "",
		Type: testAnalyzerType,
	})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryInvalidConfig {
		t.Errorf("expected code %s, got %s", ErrRegistryInvalidConfig, re.Code)
	}
}

func TestRegister_EmptyType(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	err := r.Register(context.Background(), &AnalyzerConfig{
		Name: "no-type",
		Type: "",
	})
	if err == nil {
		t.Fatal("expected error for empty type")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryInvalidConfig {
		t.Errorf("expected code %s, got %s", ErrRegistryInvalidConfig, re.Code)
	}
}

func TestRegister_Duplicate(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{Name: "dup", Type: testAnalyzerType, Enabled: true})

	err := r.Register(ctx, &AnalyzerConfig{Name: "dup", Type: testAnalyzerType, Enabled: true})
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryDuplicate {
		t.Errorf("expected code %s, got %s", ErrRegistryDuplicate, re.Code)
	}
}

func TestRegister_LicenseNotAllowed(t *testing.T) {
	v := &mockValidator{allowed: false, max: -1, enforcement: EnforcementFailOpen}
	r := NewRegistry(WithRegistryLicenseValidator(v))

	err := r.Register(context.Background(), &AnalyzerConfig{
		Name: "blocked",
		Type: testAnalyzerType,
	})
	if err == nil {
		t.Fatal("expected error when license disallows analyzer type")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryLicenseRequired {
		t.Errorf("expected code %s, got %s", ErrRegistryLicenseRequired, re.Code)
	}
}

func TestRegister_AnalyzerLimitReached(t *testing.T) {
	registerTestFactory(t)
	v := &mockValidator{allowed: true, max: 1, enforcement: EnforcementFailOpen}
	r := NewRegistry(WithRegistryLicenseValidator(v), WithMaxAnalyzers(1))
	ctx := context.Background()

	// First registration should succeed.
	err := r.Register(ctx, &AnalyzerConfig{Name: "first", Type: testAnalyzerType, Enabled: true})
	if err != nil {
		t.Fatalf("first Register failed: %v", err)
	}

	// Second should hit the limit.
	err = r.Register(ctx, &AnalyzerConfig{Name: "second", Type: testAnalyzerType, Enabled: true})
	if err == nil {
		t.Fatal("expected error when analyzer limit reached")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryAnalyzerLimit {
		t.Errorf("expected code %s, got %s", ErrRegistryAnalyzerLimit, re.Code)
	}
}

// --- RegisterAnalyzer (instance-based) -------------------------------------

func TestRegisterAnalyzer_Valid(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	a := newStubAnalyzer("inst-1")

	err := r.RegisterAnalyzer("inst-1", a)
	if err != nil {
		t.Fatalf("RegisterAnalyzer returned error: %v", err)
	}
	if !r.Has("inst-1") {
		t.Error("expected registry to contain inst-1")
	}
}

func TestRegisterAnalyzer_NilAnalyzer(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	err := r.RegisterAnalyzer("nil-analyzer", nil)
	if err == nil {
		t.Fatal("expected error for nil analyzer")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryInvalidConfig {
		t.Errorf("expected code %s, got %s", ErrRegistryInvalidConfig, re.Code)
	}
}

func TestRegisterAnalyzer_EmptyName(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	err := r.RegisterAnalyzer("", newStubAnalyzer("x"))
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryInvalidConfig {
		t.Errorf("expected code %s, got %s", ErrRegistryInvalidConfig, re.Code)
	}
}

func TestRegisterAnalyzer_Duplicate(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	_ = r.RegisterAnalyzer("dup-inst", newStubAnalyzer("dup-inst"))

	err := r.RegisterAnalyzer("dup-inst", newStubAnalyzer("dup-inst"))
	if err == nil {
		t.Fatal("expected error for duplicate instance")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryDuplicate {
		t.Errorf("expected code %s, got %s", ErrRegistryDuplicate, re.Code)
	}
}

// --- Get -------------------------------------------------------------------

func TestGet_ExistingInstance(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	a := newStubAnalyzer("existing")
	_ = r.RegisterAnalyzer("existing", a)

	got, err := r.Get(context.Background(), "existing")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if got != a {
		t.Error("Get did not return the registered analyzer instance")
	}
}

func TestGet_LazyInstantiation(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{
		Name:    "lazy-one",
		Type:    testAnalyzerType,
		Enabled: true,
	})

	got, err := r.Get(ctx, "lazy-one")
	if err != nil {
		t.Fatalf("Get (lazy) returned error: %v", err)
	}
	if got == nil {
		t.Fatal("Get (lazy) returned nil analyzer")
	}
	if got.Name() != "lazy-one" {
		t.Errorf("expected name lazy-one, got %s", got.Name())
	}
}

func TestGet_NotFound(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	_, err := r.Get(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing analyzer")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryNotFound {
		t.Errorf("expected code %s, got %s", ErrRegistryNotFound, re.Code)
	}
}

// --- List / ListEnabled / Count / Has --------------------------------------

func TestList(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{Name: "cfg-a", Type: testAnalyzerType, Enabled: true})
	_ = r.RegisterAnalyzer("inst-b", newStubAnalyzer("inst-b"))

	names := r.List()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d: %v", len(names), names)
	}
	// List returns sorted names.
	if names[0] != "cfg-a" || names[1] != "inst-b" {
		t.Errorf("unexpected names: %v", names)
	}
}

func TestListEnabled(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{Name: "enabled-1", Type: testAnalyzerType, Enabled: true})
	_ = r.Register(ctx, &AnalyzerConfig{Name: "disabled-1", Type: testAnalyzerType, Enabled: false})
	_ = r.RegisterAnalyzer("inst-always", newStubAnalyzer("inst-always"))

	enabled := r.ListEnabled()
	if len(enabled) != 2 {
		t.Fatalf("expected 2 enabled, got %d: %v", len(enabled), enabled)
	}
	// Should contain enabled-1 and inst-always but not disabled-1.
	found := make(map[string]bool)
	for _, n := range enabled {
		found[n] = true
	}
	if !found["enabled-1"] {
		t.Error("expected enabled-1 in ListEnabled")
	}
	if !found["inst-always"] {
		t.Error("expected inst-always in ListEnabled")
	}
	if found["disabled-1"] {
		t.Error("disabled-1 should not appear in ListEnabled")
	}
}

func TestCount(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	if r.Count() != 0 {
		t.Fatalf("expected 0, got %d", r.Count())
	}

	_ = r.Register(ctx, &AnalyzerConfig{Name: "c1", Type: testAnalyzerType, Enabled: true})
	_ = r.RegisterAnalyzer("c2", newStubAnalyzer("c2"))

	if r.Count() != 2 {
		t.Errorf("expected 2, got %d", r.Count())
	}
}

func TestHas(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{Name: "h1", Type: testAnalyzerType, Enabled: true})

	if !r.Has("h1") {
		t.Error("expected Has(h1) == true")
	}
	if r.Has("h2") {
		t.Error("expected Has(h2) == false")
	}
}

// --- Unregister ------------------------------------------------------------

func TestUnregister_Existing(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{Name: "rem", Type: testAnalyzerType, Enabled: true})
	if !r.Has("rem") {
		t.Fatal("precondition: rem should exist")
	}

	err := r.Unregister("rem")
	if err != nil {
		t.Fatalf("Unregister returned error: %v", err)
	}
	if r.Has("rem") {
		t.Error("expected rem to be removed")
	}
}

func TestUnregister_NotFound(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	err := r.Unregister("ghost")
	if err == nil {
		t.Fatal("expected error for unregistering non-existent analyzer")
	}
	re, ok := err.(*RegistryError)
	if !ok {
		t.Fatalf("expected *RegistryError, got %T", err)
	}
	if re.Code != ErrRegistryNotFound {
		t.Errorf("expected code %s, got %s", ErrRegistryNotFound, re.Code)
	}
}

// --- HealthCheck -----------------------------------------------------------

func TestHealthCheck(t *testing.T) {
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))

	healthy := newStubAnalyzer("ok")
	healthy.healthy = true

	unhealthy := newStubAnalyzer("bad")
	unhealthy.healthy = false

	_ = r.RegisterAnalyzer("ok", healthy)
	_ = r.RegisterAnalyzer("bad", unhealthy)

	results := r.HealthCheck(context.Background())
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results["ok"] != nil {
		t.Error("expected ok analyzer to be healthy")
	}
	if results["bad"] == nil {
		t.Error("expected bad analyzer to report error")
	}
}

// --- GetAllAnalyzers -------------------------------------------------------

func TestGetAllAnalyzers(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{Name: "all-1", Type: testAnalyzerType, Enabled: true})
	_ = r.RegisterAnalyzer("all-2", newStubAnalyzer("all-2"))

	analyzers, err := r.GetAllAnalyzers(ctx)
	if err != nil {
		t.Fatalf("GetAllAnalyzers returned error: %v", err)
	}
	if len(analyzers) != 2 {
		t.Errorf("expected 2 analyzers, got %d", len(analyzers))
	}
}

// --- Close -----------------------------------------------------------------

func TestClose(t *testing.T) {
	registerTestFactory(t)
	r := NewRegistry(WithRegistryLicenseValidator(allowAllValidator()))
	ctx := context.Background()

	_ = r.Register(ctx, &AnalyzerConfig{Name: "cl-1", Type: testAnalyzerType, Enabled: true})
	_ = r.RegisterAnalyzer("cl-2", newStubAnalyzer("cl-2"))

	err := r.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if r.Count() != 0 {
		t.Errorf("expected 0 analyzers after Close, got %d", r.Count())
	}
	if r.Has("cl-1") || r.Has("cl-2") {
		t.Error("expected all analyzers removed after Close")
	}
}
