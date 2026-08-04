// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// resolveSegmentsForPolicy is the P3 (#3051) promotion of segment
// resolution from observability-only (mcp_identity.go's resolveUserSegments,
// P2) to POLICY-AFFECTING — the two functions have deliberately OPPOSITE
// error contracts, so these tests pin resolveSegmentsForPolicy's contract
// independently, reusing the fakeSegmentResolver/withFleetSegmentResolver
// test doubles already established for the P2 tests in mcp_identity_test.go
// (same package, same fixtures — no duplicate fakes).

func TestResolveSegmentsForPolicy_NilResolver_OrgOnlyNotFailure(t *testing.T) {
	ResetFleetSegmentResolverForTest()
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com", true)
	if !ok {
		t.Fatal("no resolver wired (community / no SCIM) must NOT be treated as a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set, got %v", ids)
	}
}

func TestResolveSegmentsForPolicy_EmptySet_OrgOnly(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: []sharedidentity.Segment{}}})
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com", true)
	if !ok {
		t.Fatal("zero group memberships is a legitimate success, not a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set for zero memberships, got %v", ids)
	}
}

// TestResolveSegmentsForPolicy_Error_FailsClosed is the ADR-060
// §Fail-closed contract this file exists to implement: a genuine resolver
// ERROR must deny (ok=false), in stark contrast to resolveUserSegments
// (P2), which treats the identical error as "nil, proceed" (observability
// only). Getting this backwards — silently proceeding org-only on error —
// is exactly the fail-open regression R3 is told to hunt for.
func TestResolveSegmentsForPolicy_Error_FailsClosed(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed")})
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com", true)
	if ok {
		t.Fatal("a genuine segment resolution error must DENY (ok=false), never fall back to org-only")
	}
	if ids != nil {
		t.Fatalf("expected nil ids on failure, got %v", ids)
	}
}

func TestResolveSegmentsForPolicy_Success_ReturnsIDs(t *testing.T) {
	want := []sharedidentity.Segment{{ID: "grp-finance", DisplayName: "finance"}, {ID: "grp-ml", DisplayName: "ml-platform"}}
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: want}})
	ids, ok := resolveSegmentsForPolicy(context.Background(), "org-a", "a@example.com", true)
	if !ok {
		t.Fatal("a successful resolution must never fail closed")
	}
	if len(ids) != 2 || ids[0] != "grp-finance" || ids[1] != "grp-ml" {
		t.Fatalf("resolveSegmentsForPolicy ids = %v, want [grp-finance grp-ml]", ids)
	}
}
