// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// captureLog redirects the standard logger into a buffer for the duration of
// the test so log emission can be asserted, mirroring
// platform/agent/identity_trust_test.go's helper of the same name (same
// technique, not shared across packages).
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

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

// resolverReturning builds a fakeOrchestratorSegmentResolver that resolves
// to exactly the given segment ids.
//
// #3319: relocated from verdict_cache_segment_3052_test.go, which was
// deleted along with the retired in-memory DynamicPolicyEngine's per-request
// verdict cache (the tests in that file existed solely to pin that cache's
// segment-collision behavior, which has no equivalent on the surviving
// DatabaseDynamicPolicyEngine — it carries no per-request verdict cache).
// This helper itself is not cache-specific — db_dynamic_policies_segment_3052_test.go
// depends on it too — so it moved here, alongside its sibling segment-resolver
// test doubles, rather than being deleted with the rest of that file.
func resolverReturning(ids ...string) *fakeOrchestratorSegmentResolver {
	segs := make([]sharedidentity.Segment, len(ids))
	for i, id := range ids {
		segs[i] = sharedidentity.Segment{ID: sharedidentity.SegmentID(id)}
	}
	return &fakeOrchestratorSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: segs}}
}

func TestResolveUserSegments_NilResolver_OrgOnlyNotFailure(t *testing.T) {
	ResetOrchestratorSegmentResolverForTest()
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com")
	if !ok {
		t.Fatal("no resolver wired (community / no SCIM) must NOT be treated as a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set, got %v", ids)
	}
}

func TestResolveUserSegments_EmptyOrgOrEmail_OrgOnlyNotFailure(t *testing.T) {
	fake := &fakeOrchestratorSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "grp-finance"}},
	}}
	withOrchestratorSegmentResolver(t, fake)

	for _, tc := range []struct{ org, email string }{
		{"", "a@example.com"},
		{"org-a", ""},
		{"", ""},
	} {
		ids, ok := resolveUserSegments(context.Background(), tc.org, tc.email)
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

func TestResolveUserSegments_EmptySet_OrgOnly(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{
		resolved: sharedidentity.ResolvedIdentity{Segments: []sharedidentity.Segment{}},
	})
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com")
	if !ok {
		t.Fatal("zero group memberships is a legitimate success, not a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set for zero memberships, got %v", ids)
	}
}

// TestResolveUserSegments_Error_FailsClosed is the ADR-060 §Fail-closed
// contract, unconditional on this plane (the orchestrator's dynamic-policy
// enforcement path has no read-only-simulator carve-out): a genuine
// resolver ERROR must deny (ok=false).
func TestResolveUserSegments_Error_FailsClosed(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{err: errors.New("segment query failed")})
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com")
	if ok {
		t.Fatal("a genuine segment resolution error must DENY (ok=false), never fall back to org-only")
	}
	if ids != nil {
		t.Fatalf("expected nil ids on failure, got %v", ids)
	}
}

// TestResolveUserSegments_ErrorLogsDenying is the orchestrator mirror of
// platform/agent/segment_policy_gate_test.go's
// TestResolveUserSegments_EnforcementPhase_ErrorLogsDenying: existing tests
// here exercise LogResolutionError but nothing previously asserted its TEXT.
// Unlike the agent, the orchestrator has no session-auth phase — every call
// site is policy-affecting (see this file's and segment_policy_gate.go's
// doc) — so "DENYING" is unconditionally the correct claim here, with no
// phase gate to pin.
func TestResolveUserSegments_ErrorLogsDenying(t *testing.T) {
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{err: errors.New("segment query failed")})
	buf := captureLog(t)

	resolveUserSegments(context.Background(), "org-a", "a@example.com")

	out := buf.String()
	if !strings.Contains(out, `[Policy] DENYING (fail-closed, ADR-060 #2989): segment resolution failed org="org-a"`) {
		t.Fatalf("expected the unconditional DENYING line, got: %s", out)
	}
}

func TestResolveUserSegments_Success_ReturnsIDs(t *testing.T) {
	want := []sharedidentity.Segment{{ID: "grp-finance", DisplayName: "finance"}, {ID: "grp-ml", DisplayName: "ml-platform"}}
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: want}})
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com")
	if !ok {
		t.Fatal("a successful resolution must never fail closed")
	}
	if len(ids) != 2 || ids[0] != "grp-finance" || ids[1] != "grp-ml" {
		t.Fatalf("resolveUserSegments ids = %v, want [grp-finance grp-ml]", ids)
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
