// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// fakeOrchestratorSegmentResolver is a call-counting
// sharedidentity.IdentityAttributeResolver double, mirroring
// platform/agent/mcp_identity_test.go's fakeSegmentResolver — injected via
// setOrchestratorSegmentResolver so a test can assert WHETHER and HOW
// segment resolution ran without a real SCIM-backed database.
type fakeOrchestratorSegmentResolver struct {
	mu       sync.Mutex
	calls    int
	resolved sharedidentity.ResolvedIdentity
	err      error
}

func (f *fakeOrchestratorSegmentResolver) Resolve(_ context.Context, _, _ string) (sharedidentity.ResolvedIdentity, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return sharedidentity.ResolvedIdentity{}, f.err
	}
	return f.resolved, nil
}

func (f *fakeOrchestratorSegmentResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (f *fakeOrchestratorSegmentResolver) InvalidateUserSegments(_, _ string) {}

func (f *fakeOrchestratorSegmentResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// withOrchestratorSegmentResolver wires r as the process-wide orchestrator
// segment resolver for the test's lifetime.
func withOrchestratorSegmentResolver(t *testing.T, r sharedidentity.IdentityAttributeResolver) {
	t.Helper()
	setOrchestratorSegmentResolver(r)
	t.Cleanup(ResetOrchestratorSegmentResolverForTest)
}

func TestResolveSegmentsForPolicy_NilResolver_OrgOnlyNotFailure(t *testing.T) {
	ResetOrchestratorSegmentResolverForTest()
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com")
	if !ok {
		t.Fatal("no resolver wired (community / no SCIM) must NOT be treated as a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set, got %v", ids)
	}
}

func TestResolveSegmentsForPolicy_EmptyOrgOrEmail_OrgOnlyNotFailure(t *testing.T) {
	fake := &fakeOrchestratorSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "grp-finance"}},
	}}
	withOrchestratorSegmentResolver(t, fake)

	for _, tc := range []struct{ org, email string }{
		{"", "a@example.com"},
		{"org-a", ""},
		{"", ""},
	} {
		ids, ok := resolveSegmentsForPolicy(context.Background(), tc.org, tc.email)
		if !ok {
			t.Fatalf("org=%q email=%q: no verified identity to resolve against must not be a failure", tc.org, tc.email)
		}
		if ids != nil {
			t.Fatalf("org=%q email=%q: expected nil segment set, got %v", tc.org, tc.email, ids)
		}
	}
	if fake.callCount() != 0 {
		t.Fatalf("resolver must not be called when org or email is empty, got %d calls", fake.callCount())
	}
}

func TestResolveSegmentsForPolicy_EmptySet_OrgOnly(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{
		resolved: sharedidentity.ResolvedIdentity{Segments: []sharedidentity.Segment{}},
	})
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com")
	if !ok {
		t.Fatal("zero group memberships is a legitimate success, not a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set for zero memberships, got %v", ids)
	}
}

// TestResolveSegmentsForPolicy_Error_FailsClosed is the ADR-060 §Fail-closed
// contract, unconditional on this plane (the orchestrator's dynamic-policy
// enforcement path has no read-only-simulator carve-out): a genuine
// resolver ERROR must deny (ok=false).
func TestResolveSegmentsForPolicy_Error_FailsClosed(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{err: errors.New("segment query failed")})
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com")
	if ok {
		t.Fatal("a genuine segment resolution error must DENY (ok=false), never fall back to org-only")
	}
	if ids != nil {
		t.Fatalf("expected nil ids on failure, got %v", ids)
	}
}

func TestResolveSegmentsForPolicy_Success_ReturnsIDs(t *testing.T) {
	want := []sharedidentity.Segment{{ID: "grp-finance", DisplayName: "finance"}, {ID: "grp-ml", DisplayName: "ml-platform"}}
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: want}})
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com")
	if !ok {
		t.Fatal("a successful resolution must never fail closed")
	}
	if len(ids) != 2 || ids[0] != "grp-finance" || ids[1] != "grp-ml" {
		t.Fatalf("resolveSegmentsForPolicy ids = %v, want [grp-finance grp-ml]", ids)
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
			got := normalizeSegmentIDs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeSegmentIDs(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeSegmentIDs(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

func TestSegmentSetContains(t *testing.T) {
	set := []string{"a", "b", "c"}
	if !segmentSetContains(set, "b") {
		t.Error("expected b to be found")
	}
	if segmentSetContains(set, "z") {
		t.Error("expected z not to be found")
	}
	if segmentSetContains(nil, "a") {
		t.Error("expected nil set to contain nothing")
	}
}
