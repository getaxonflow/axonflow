// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// testBase64Data is a valid base64-encoded payload used across pipeline tests.
var testBase64Data = base64.StdEncoding.EncodeToString([]byte("test-image-data"))

// mockPipelineValidator implements AnalyzerLicenseValidator for pipeline tests.
type mockPipelineValidator struct {
	enforcement EnforcementStrategy
}

func (v *mockPipelineValidator) IsAnalyzerAllowed(_ context.Context, _ MediaAnalyzerType) bool {
	return true
}

func (v *mockPipelineValidator) GetMaxAnalyzers(_ context.Context) int { return -1 }

func (v *mockPipelineValidator) GetEnforcementStrategy(_ context.Context) EnforcementStrategy {
	return v.enforcement
}

// mockPipelineAnalyzer is a configurable MediaAnalyzer for pipeline tests.
type mockPipelineAnalyzer struct {
	name   string
	result *MediaAnalysisResult
	err    error
}

func (a *mockPipelineAnalyzer) Name() string            { return a.name }
func (a *mockPipelineAnalyzer) Type() MediaAnalyzerType  { return MediaAnalyzerType("mock-pipeline") }
func (a *mockPipelineAnalyzer) Capabilities() []MediaAnalyzerCapability { return nil }
func (a *mockPipelineAnalyzer) HealthCheck(_ context.Context) error     { return nil }

func (a *mockPipelineAnalyzer) Analyze(_ context.Context, _ MediaContent) (*MediaAnalysisResult, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.result, nil
}

// validTestMedia returns a single-element slice with valid base64 media for tests.
func validTestMedia() []MediaContent {
	return []MediaContent{
		{
			Source:     MediaSourceBase64,
			Base64Data: testBase64Data,
			MIMEType:   "image/png",
		},
	}
}

// buildTestPipeline creates a pipeline with a registry containing the given analyzers.
func buildTestPipeline(t *testing.T, enforcement EnforcementStrategy, analyzers ...MediaAnalyzer) *Pipeline {
	t.Helper()
	v := &mockPipelineValidator{enforcement: enforcement}
	reg := NewRegistry(WithRegistryLicenseValidator(v))

	for _, a := range analyzers {
		if err := reg.RegisterAnalyzer(a.Name(), a); err != nil {
			t.Fatalf("failed to register analyzer %s: %v", a.Name(), err)
		}
	}

	return NewPipeline(
		WithPipelineRegistry(reg),
		WithPipelineValidator(v),
	)
}

// --- AnalyzeMedia: nil / empty media ---------------------------------------

func TestAnalyzeMedia_NilMedia(t *testing.T) {
	p := NewPipeline()
	results, err := p.AnalyzeMedia(context.Background(), "req-nil", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for nil media, got %v", results)
	}
}

func TestAnalyzeMedia_EmptyMedia(t *testing.T) {
	p := NewPipeline()
	results, err := p.AnalyzeMedia(context.Background(), "req-empty", []MediaContent{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for empty media, got %v", results)
	}
}

// --- AnalyzeMedia: invalid media -------------------------------------------

func TestAnalyzeMedia_InvalidMedia(t *testing.T) {
	p := NewPipeline()
	invalid := []MediaContent{
		{Source: "", MIMEType: "image/png", Base64Data: testBase64Data},
	}

	_, err := p.AnalyzeMedia(context.Background(), "req-invalid", invalid)
	if err == nil {
		t.Fatal("expected validation error for media with empty source")
	}
}

// --- AnalyzeMedia: no registry (empty results with warnings) ---------------

func TestAnalyzeMedia_NoRegistry(t *testing.T) {
	v := &mockPipelineValidator{enforcement: EnforcementFailOpen}
	p := NewPipeline(WithPipelineValidator(v))

	results, err := p.AnalyzeMedia(context.Background(), "req-noreg", validTestMedia())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].Warnings) == 0 {
		t.Error("expected warnings in result when no analyzers available")
	}
	if !results[0].ContentSafe {
		t.Error("expected ContentSafe=true for empty result")
	}
}

// --- AnalyzeMedia: mock analyzer (verify aggregation) ----------------------

func TestAnalyzeMedia_WithMockAnalyzer(t *testing.T) {
	analyzer := &mockPipelineAnalyzer{
		name: "mock-1",
		result: &MediaAnalysisResult{
			AnalyzerName:    "mock-1",
			AnalyzerType:    MediaAnalyzerType("mock-pipeline"),
			ExtractedText:   "hello world",
			EstimatedCostUSD: 0.01,
		},
	}

	p := buildTestPipeline(t, EnforcementFailOpen, analyzer)
	results, err := p.AnalyzeMedia(context.Background(), "req-mock", validTestMedia())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if len(r.AnalyzerResults) != 1 {
		t.Fatalf("expected 1 analyzer result, got %d", len(r.AnalyzerResults))
	}
	if r.AnalyzerResults[0].AnalyzerName != "mock-1" {
		t.Errorf("expected analyzer name mock-1, got %s", r.AnalyzerResults[0].AnalyzerName)
	}
	if r.ExtractedText != "hello world" {
		t.Errorf("expected extracted text 'hello world', got %q", r.ExtractedText)
	}
	if r.EstimatedCostUSD != 0.01 {
		t.Errorf("expected cost 0.01, got %f", r.EstimatedCostUSD)
	}
}

// --- AnalyzeMedia: analyzer error in fail-open mode ------------------------

func TestAnalyzeMedia_AnalyzerError_FailOpen(t *testing.T) {
	failing := &mockPipelineAnalyzer{
		name: "failing",
		err:  errors.New("analysis boom"),
	}

	p := buildTestPipeline(t, EnforcementFailOpen, failing)
	results, err := p.AnalyzeMedia(context.Background(), "req-fail-open", validTestMedia())
	if err != nil {
		t.Fatalf("expected no error in fail-open mode, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if len(r.Warnings) == 0 {
		t.Error("expected at least one warning from failing analyzer")
	}
	// The analyzer error should be captured as a warning, not block the pipeline.
	foundWarning := false
	for _, w := range r.Warnings {
		if len(w) > 0 {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expected a non-empty warning string")
	}
}

// --- aggregateSignals via AnalyzeMedia: faces, PII, content safety merged --

func TestAnalyzeMedia_AggregateSignals(t *testing.T) {
	faceAnalyzer := &mockPipelineAnalyzer{
		name: "face-detector",
		result: &MediaAnalysisResult{
			AnalyzerName: "face-detector",
			AnalyzerType: MediaAnalyzerType("mock-pipeline"),
			Faces: []FaceDetection{
				{Confidence: 0.99, IsBiometric: true},
				{Confidence: 0.85, IsBiometric: false},
			},
		},
	}

	piiAnalyzer := &mockPipelineAnalyzer{
		name: "pii-scanner",
		result: &MediaAnalysisResult{
			AnalyzerName: "pii-scanner",
			AnalyzerType: MediaAnalyzerType("mock-pipeline"),
			PIIFindings: []PIIFinding{
				{Type: "ssn", Confidence: 0.95, StartIndex: 0, EndIndex: 11},
				{Type: "email", Confidence: 0.90, StartIndex: 20, EndIndex: 40},
			},
			ExtractedText: "123-45-6789 test@example.com",
		},
	}

	safetyAnalyzer := &mockPipelineAnalyzer{
		name: "safety-check",
		result: &MediaAnalysisResult{
			AnalyzerName: "safety-check",
			AnalyzerType: MediaAnalyzerType("mock-pipeline"),
			ContentSafety: &ContentSafetyResult{
				NSFWScore:     0.15,
				ViolenceScore: 0.30,
				IsSafe:        false,
			},
		},
	}

	p := buildTestPipeline(t, EnforcementFailOpen, faceAnalyzer, piiAnalyzer, safetyAnalyzer)
	results, err := p.AnalyzeMedia(context.Background(), "req-agg", validTestMedia())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]

	// Verify face aggregation.
	if !r.HasFaces {
		t.Error("expected HasFaces=true")
	}
	if r.FaceCount != 2 {
		t.Errorf("expected FaceCount=2, got %d", r.FaceCount)
	}
	if !r.HasBiometricData {
		t.Error("expected HasBiometricData=true")
	}

	// Verify PII aggregation.
	if !r.HasPII {
		t.Error("expected HasPII=true")
	}
	if len(r.PIITypes) != 2 {
		t.Errorf("expected 2 PII types, got %d: %v", len(r.PIITypes), r.PIITypes)
	}
	piiTypeSet := make(map[string]bool)
	for _, pt := range r.PIITypes {
		piiTypeSet[pt] = true
	}
	if !piiTypeSet["ssn"] {
		t.Error("expected ssn in PIITypes")
	}
	if !piiTypeSet["email"] {
		t.Error("expected email in PIITypes")
	}

	// Verify content safety aggregation.
	if r.NSFWScore != 0.15 {
		t.Errorf("expected NSFWScore=0.15, got %f", r.NSFWScore)
	}
	if r.ViolenceScore != 0.30 {
		t.Errorf("expected ViolenceScore=0.30, got %f", r.ViolenceScore)
	}
	if r.ContentSafe {
		t.Error("expected ContentSafe=false when IsSafe=false in safety result")
	}

	// Verify extracted text aggregation.
	if r.ExtractedText == "" {
		t.Error("expected non-empty extracted text")
	}

	// Verify all three analyzer results present.
	if len(r.AnalyzerResults) != 3 {
		t.Errorf("expected 3 analyzer results, got %d", len(r.AnalyzerResults))
	}
}

// --- Concurrency cap ---

// slowAnalyzer tracks peak concurrency during analysis.
type slowAnalyzer struct {
	name    string
	delay   time.Duration
	peak    *atomic.Int32
	current *atomic.Int32
}

func (a *slowAnalyzer) Name() string                                { return a.name }
func (a *slowAnalyzer) Type() MediaAnalyzerType                     { return MediaAnalyzerType("slow") }
func (a *slowAnalyzer) Capabilities() []MediaAnalyzerCapability     { return nil }
func (a *slowAnalyzer) HealthCheck(_ context.Context) error         { return nil }
func (a *slowAnalyzer) Analyze(_ context.Context, _ MediaContent) (*MediaAnalysisResult, error) {
	n := a.current.Add(1)
	for {
		old := a.peak.Load()
		if n <= old || a.peak.CompareAndSwap(old, n) {
			break
		}
	}
	time.Sleep(a.delay)
	a.current.Add(-1)
	return &MediaAnalysisResult{AnalyzerName: a.name, AnalyzerType: MediaAnalyzerType("slow")}, nil
}

func TestPipeline_ConcurrencyCap(t *testing.T) {
	peak := &atomic.Int32{}
	current := &atomic.Int32{}

	// Create 5 slow analyzers, cap at 2
	var analyzers []MediaAnalyzer
	for i := 0; i < 5; i++ {
		analyzers = append(analyzers, &slowAnalyzer{
			name:    "slow-" + string(rune('a'+i)),
			delay:   50 * time.Millisecond,
			peak:    peak,
			current: current,
		})
	}

	v := &mockPipelineValidator{enforcement: EnforcementFailOpen}
	reg := NewRegistry(WithRegistryLicenseValidator(v))
	for _, a := range analyzers {
		if err := reg.RegisterAnalyzer(a.Name(), a); err != nil {
			t.Fatalf("failed to register analyzer: %v", err)
		}
	}

	p := NewPipeline(
		WithPipelineRegistry(reg),
		WithPipelineValidator(v),
		WithMaxConcurrentAnalyzers(2),
	)

	results, err := p.AnalyzeMedia(context.Background(), "req-concurrency", validTestMedia())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if len(results[0].AnalyzerResults) != 5 {
		t.Errorf("expected 5 analyzer results, got %d", len(results[0].AnalyzerResults))
	}
	if peak.Load() > 2 {
		t.Errorf("expected peak concurrency <= 2, got %d", peak.Load())
	}
}

// --- Context cancellation ---

func TestAnalyzeMedia_ContextCancelled_FailOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	blockingAnalyzer := &mockPipelineAnalyzer{
		name: "blocking",
		result: &MediaAnalysisResult{
			AnalyzerName: "blocking",
			AnalyzerType: MediaAnalyzerType("mock-pipeline"),
		},
	}
	// We'll cancel after a short delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	// Use a slow analyzer that takes longer than the cancel
	slowA := &slowAnalyzer{
		name:    "very-slow",
		delay:   500 * time.Millisecond,
		peak:    &atomic.Int32{},
		current: &atomic.Int32{},
	}

	v := &mockPipelineValidator{enforcement: EnforcementFailOpen}
	reg := NewRegistry(WithRegistryLicenseValidator(v))
	_ = reg.RegisterAnalyzer(blockingAnalyzer.Name(), blockingAnalyzer)
	_ = reg.RegisterAnalyzer(slowA.Name(), slowA)

	p := NewPipeline(
		WithPipelineRegistry(reg),
		WithPipelineValidator(v),
	)

	results, err := p.AnalyzeMedia(ctx, "req-cancel-open", validTestMedia())
	if err != nil {
		t.Fatalf("expected no error in fail-open mode with cancelled context, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// Should have a partial results warning
	foundPartialWarning := false
	for _, sw := range results[0].StructuredWarnings {
		if sw.Code == WarnMediaPartialResults {
			foundPartialWarning = true
		}
	}
	if !foundPartialWarning {
		t.Error("expected WarnMediaPartialResults warning")
	}
}

func TestAnalyzeMedia_ContextCancelled_FailClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	slowA := &slowAnalyzer{
		name:    "very-slow",
		delay:   500 * time.Millisecond,
		peak:    &atomic.Int32{},
		current: &atomic.Int32{},
	}

	v := &mockPipelineValidator{enforcement: EnforcementFailClosed}
	reg := NewRegistry(WithRegistryLicenseValidator(v))
	_ = reg.RegisterAnalyzer(slowA.Name(), slowA)

	p := NewPipeline(
		WithPipelineRegistry(reg),
		WithPipelineValidator(v),
	)

	_, err := p.AnalyzeMedia(ctx, "req-cancel-closed", validTestMedia())
	if err == nil {
		t.Fatal("expected error in fail-closed mode with cancelled context")
	}
}

// --- Deterministic order ---

func TestAnalyzeMedia_DeterministicOrder(t *testing.T) {
	// Create analyzers with names that would sort differently than insertion order
	analyzerZ := &mockPipelineAnalyzer{
		name:   "z-analyzer",
		result: &MediaAnalysisResult{AnalyzerName: "z-analyzer", AnalyzerType: MediaAnalyzerType("mock-pipeline")},
	}
	analyzerA := &mockPipelineAnalyzer{
		name:   "a-analyzer",
		result: &MediaAnalysisResult{AnalyzerName: "a-analyzer", AnalyzerType: MediaAnalyzerType("mock-pipeline")},
	}
	analyzerM := &mockPipelineAnalyzer{
		name:   "m-analyzer",
		result: &MediaAnalysisResult{AnalyzerName: "m-analyzer", AnalyzerType: MediaAnalyzerType("mock-pipeline")},
	}

	p := buildTestPipeline(t, EnforcementFailOpen, analyzerZ, analyzerA, analyzerM)

	// Run multiple times to verify deterministic ordering
	for i := 0; i < 5; i++ {
		results, err := p.AnalyzeMedia(context.Background(), "req-order", validTestMedia())
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if len(results) != 1 {
			t.Fatalf("iteration %d: expected 1 result, got %d", i, len(results))
		}
		r := results[0]
		if len(r.AnalyzerResults) != 3 {
			t.Fatalf("iteration %d: expected 3 analyzer results, got %d", i, len(r.AnalyzerResults))
		}
		expected := []string{"a-analyzer", "m-analyzer", "z-analyzer"}
		for j, ar := range r.AnalyzerResults {
			if ar.AnalyzerName != expected[j] {
				t.Errorf("iteration %d: position %d: expected %s, got %s", i, j, expected[j], ar.AnalyzerName)
			}
		}
	}
}

// --- No analyzers: fail-closed vs fail-open ---

func TestAnalyzeMedia_NoAnalyzers_FailClosed(t *testing.T) {
	v := &mockPipelineValidator{enforcement: EnforcementFailClosed}
	reg := NewRegistry(WithRegistryLicenseValidator(v))

	p := NewPipeline(
		WithPipelineRegistry(reg),
		WithPipelineValidator(v),
	)

	_, err := p.AnalyzeMedia(context.Background(), "req-no-analyzers-closed", validTestMedia())
	if err == nil {
		t.Fatal("expected error when no analyzers and fail-closed")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaAnalysisFailed {
		t.Errorf("expected code %s, got %s", ErrMediaAnalysisFailed, me.Code)
	}
}

func TestAnalyzeMedia_NoAnalyzers_FailOpen(t *testing.T) {
	v := &mockPipelineValidator{enforcement: EnforcementFailOpen}
	reg := NewRegistry(WithRegistryLicenseValidator(v))

	p := NewPipeline(
		WithPipelineRegistry(reg),
		WithPipelineValidator(v),
	)

	results, err := p.AnalyzeMedia(context.Background(), "req-no-analyzers-open", validTestMedia())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// Should have structured warning
	foundWarning := false
	for _, sw := range results[0].StructuredWarnings {
		if sw.Code == WarnMediaNoAnalyzers {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("expected WarnMediaNoAnalyzers structured warning")
	}
}

// --- Pipeline.GetEnforcementStrategy ---

func TestPipeline_GetEnforcementStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy EnforcementStrategy
	}{
		{"fail-open", EnforcementFailOpen},
		{"fail-closed", EnforcementFailClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := buildTestPipeline(t, tt.strategy)
			got := p.GetEnforcementStrategy(context.Background())
			if got != tt.strategy {
				t.Errorf("GetEnforcementStrategy() = %v, want %v", got, tt.strategy)
			}
		})
	}
}

// --- Pipeline option coverage ---

func TestWithPipelineAuditLogger(t *testing.T) {
	al := &AuditLogger{}
	p := NewPipeline(
		WithPipelineValidator(&mockPipelineValidator{enforcement: EnforcementFailOpen}),
		WithPipelineAuditLogger(al),
	)
	if p.auditLogger != al {
		t.Error("expected auditLogger to be set")
	}
}

func TestWithPipelineLogger(t *testing.T) {
	l := log.New(os.Stderr, "test", 0)
	p := NewPipeline(
		WithPipelineValidator(&mockPipelineValidator{enforcement: EnforcementFailOpen}),
		WithPipelineLogger(l),
	)
	if p.logger != l {
		t.Error("expected logger to be set")
	}
}

func TestWithMaxConcurrentAnalyzers(t *testing.T) {
	p := NewPipeline(
		WithPipelineValidator(&mockPipelineValidator{enforcement: EnforcementFailOpen}),
		WithMaxConcurrentAnalyzers(5),
	)
	if p.maxConcurrentAnalyzers != 5 {
		t.Errorf("maxConcurrentAnalyzers = %d, want 5", p.maxConcurrentAnalyzers)
	}
}

func TestWithMaxConcurrentAnalyzers_ZeroIgnored(t *testing.T) {
	p := NewPipeline(
		WithPipelineValidator(&mockPipelineValidator{enforcement: EnforcementFailOpen}),
		WithMaxConcurrentAnalyzers(0),
	)
	if p.maxConcurrentAnalyzers != DefaultMaxConcurrentAnalyzers {
		t.Errorf("maxConcurrentAnalyzers = %d, want default %d", p.maxConcurrentAnalyzers, DefaultMaxConcurrentAnalyzers)
	}
}

// --- Structured warnings in analyzer error ---

func TestAnalyzeMedia_AnalyzerError_HasStructuredWarning(t *testing.T) {
	failing := &mockPipelineAnalyzer{
		name: "failing-analyzer",
		err:  errors.New("analysis boom"),
	}

	p := buildTestPipeline(t, EnforcementFailOpen, failing)
	results, err := p.AnalyzeMedia(context.Background(), "req-structured-warn", validTestMedia())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	foundWarning := false
	for _, sw := range r.StructuredWarnings {
		if sw.Code == WarnMediaAnalyzerError {
			foundWarning = true
			if sw.Message == "" {
				t.Error("expected non-empty warning message")
			}
		}
	}
	if !foundWarning {
		t.Error("expected WarnMediaAnalyzerError structured warning")
	}
}
