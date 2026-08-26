// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeSegmentGateResolver is a minimal IdentityAttributeResolver double for
// exercising ResolveUserSegments directly, independent of either
// service's own resolver wiring.
type fakeSegmentGateResolver struct {
	resolved ResolvedIdentity
	err      error
}

func (f *fakeSegmentGateResolver) Resolve(_ context.Context, _, _ string) (ResolvedIdentity, error) {
	if f.err != nil {
		return ResolvedIdentity{}, f.err
	}
	return f.resolved, nil
}

func (f *fakeSegmentGateResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

// fakeSegmentPolicyMetrics records every call made through the
// SegmentPolicyMetrics interface so a test can assert exactly what
// ResolveUserSegments reported.
type fakeSegmentPolicyMetrics struct {
	results        []string
	durations      []float64
	failClosedInc  int
	loggedErrors   int
	loggedSuccess  int
	lastSuccessIDs []string
}

func (m *fakeSegmentPolicyMetrics) ObserveResolutionResult(result string) {
	m.results = append(m.results, result)
}

func (m *fakeSegmentPolicyMetrics) ObserveResolutionDuration(seconds float64) {
	m.durations = append(m.durations, seconds)
}

func (m *fakeSegmentPolicyMetrics) IncFailClosed() {
	m.failClosedInc++
}

func (m *fakeSegmentPolicyMetrics) LogResolutionError(string, time.Duration, error) {
	m.loggedErrors++
}

func (m *fakeSegmentPolicyMetrics) LogResolutionSuccess(_ string, _ time.Duration, segmentIDs []string) {
	m.loggedSuccess++
	m.lastSuccessIDs = segmentIDs
}

func TestResolveUserSegments_NilResolver_OrgOnlyNotFailure(t *testing.T) {
	metrics := &fakeSegmentPolicyMetrics{}
	ids, ok := ResolveUserSegments(context.Background(), "org-a", "a@example.com", nil, metrics)
	if !ok {
		t.Fatal("no resolver wired (community / no SCIM) must NOT be treated as a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set, got %v", ids)
	}
	if len(metrics.results) != 0 {
		t.Fatalf("expected no metrics observed when resolver is nil, got %v", metrics.results)
	}
	if metrics.loggedErrors != 0 || metrics.loggedSuccess != 0 {
		t.Fatalf("expected neither log hook called when resolver is nil, got errors=%d success=%d", metrics.loggedErrors, metrics.loggedSuccess)
	}
}

func TestResolveUserSegments_EmptyOrgOrEmail_OrgOnlyNotFailure(t *testing.T) {
	resolver := &fakeSegmentGateResolver{resolved: ResolvedIdentity{Segments: []Segment{{ID: "grp-finance"}}}}
	metrics := &fakeSegmentPolicyMetrics{}

	for _, tc := range []struct{ org, email string }{
		{"", "a@example.com"},
		{"org-a", ""},
		{"", ""},
	} {
		ids, ok := ResolveUserSegments(context.Background(), tc.org, tc.email, resolver, metrics)
		if !ok {
			t.Fatalf("org=%q email=%q: no verified identity to resolve against must not be a failure", tc.org, tc.email)
		}
		if ids != nil {
			t.Fatalf("org=%q email=%q: expected nil segment set, got %v", tc.org, tc.email, ids)
		}
	}
	if len(metrics.results) != 0 {
		t.Fatalf("resolver must not be consulted when org or email is empty, got metrics %v", metrics.results)
	}
}

func TestResolveUserSegments_EmptySet_OrgOnly(t *testing.T) {
	resolver := &fakeSegmentGateResolver{resolved: ResolvedIdentity{Segments: []Segment{}}}
	metrics := &fakeSegmentPolicyMetrics{}
	ids, ok := ResolveUserSegments(context.Background(), "org-a", "a@example.com", resolver, metrics)
	if !ok {
		t.Fatal("zero group memberships is a legitimate success, not a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set for zero memberships, got %v", ids)
	}
	if len(metrics.results) != 1 || metrics.results[0] != "empty" {
		t.Fatalf("expected a single 'empty' observation, got %v", metrics.results)
	}
	if metrics.loggedSuccess != 1 || metrics.lastSuccessIDs != nil {
		t.Fatalf("expected LogResolutionSuccess called once with nil ids, got count=%d ids=%v", metrics.loggedSuccess, metrics.lastSuccessIDs)
	}
	if metrics.loggedErrors != 0 {
		t.Fatalf("a success must never call LogResolutionError, got %d", metrics.loggedErrors)
	}
}

// TestResolveUserSegments_Error_FailsClosed pins the ADR-060
// §Fail-closed contract: a genuine resolver ERROR must deny (ok=false) —
// unconditionally, on both planes, after #3239 round 2's convergence.
func TestResolveUserSegments_Error_FailsClosed(t *testing.T) {
	resolver := &fakeSegmentGateResolver{err: errors.New("segment query failed")}
	metrics := &fakeSegmentPolicyMetrics{}
	ids, ok := ResolveUserSegments(context.Background(), "org-a", "a@example.com", resolver, metrics)
	if ok {
		t.Fatal("a genuine segment resolution error must DENY (ok=false), never fall back to org-only")
	}
	if ids != nil {
		t.Fatalf("expected nil ids on failure, got %v", ids)
	}
	if metrics.failClosedInc != 1 {
		t.Fatalf("expected IncFailClosed to be called once, got %d", metrics.failClosedInc)
	}
	if len(metrics.results) != 1 || metrics.results[0] != "error" {
		t.Fatalf("expected a single 'error' observation, got %v", metrics.results)
	}
	if metrics.loggedErrors != 1 {
		t.Fatalf("expected LogResolutionError to be called once, got %d", metrics.loggedErrors)
	}
	if metrics.loggedSuccess != 0 {
		t.Fatalf("an error must never call LogResolutionSuccess, got %d", metrics.loggedSuccess)
	}
}

func TestResolveUserSegments_Success_ReturnsIDs(t *testing.T) {
	want := []Segment{{ID: "grp-finance", DisplayName: "finance"}, {ID: "grp-ml", DisplayName: "ml-platform"}}
	resolver := &fakeSegmentGateResolver{resolved: ResolvedIdentity{Segments: want}}
	metrics := &fakeSegmentPolicyMetrics{}
	ids, ok := ResolveUserSegments(context.Background(), "org-a", "a@example.com", resolver, metrics)
	if !ok {
		t.Fatal("a successful resolution must never fail closed")
	}
	if len(ids) != 2 || ids[0] != "grp-finance" || ids[1] != "grp-ml" {
		t.Fatalf("ResolveUserSegments ids = %v, want [grp-finance grp-ml]", ids)
	}
	if len(metrics.results) != 1 || metrics.results[0] != "resolved" {
		t.Fatalf("expected a single 'resolved' observation, got %v", metrics.results)
	}
	if len(metrics.durations) != 1 {
		t.Fatalf("expected one duration observation, got %v", metrics.durations)
	}
	if metrics.loggedSuccess != 1 || len(metrics.lastSuccessIDs) != 2 {
		t.Fatalf("expected LogResolutionSuccess called once with the resolved ids, got count=%d ids=%v", metrics.loggedSuccess, metrics.lastSuccessIDs)
	}
}

func TestNormalizeSegmentIDs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"all empty strings", []string{"", ""}, nil},
		{"dedupes and sorts", []string{"b", "a", "b", ""}, []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeSegmentIDs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("NormalizeSegmentIDs(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("NormalizeSegmentIDs(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestSegmentSetContains(t *testing.T) {
	set := []string{"a", "b", "c"}
	if !SegmentSetContains(set, "b") {
		t.Error("expected b to be found")
	}
	if SegmentSetContains(set, "z") {
		t.Error("expected z not to be found")
	}
	if SegmentSetContains(nil, "a") {
		t.Error("expected nil set to contain nothing")
	}
}
