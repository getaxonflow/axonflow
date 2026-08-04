// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3255 - the policy-test preview must resolve identity attributes under the
// org the DEPLOYMENT authenticated, never under the tenant string the caller
// influences.
//
// On the enterprise service-license path the two are not the same value:
// TenantID is the HTTP Basic-Auth username (db_auth.go, "From Basic auth
// username"), which any holder of a valid license may choose freely, while
// OrgID comes from the validated license itself (auth.go, "From license
// validation"). apiAuthMiddleware stamps both into the request context.
//
// policyTestHandler passes an org straight to the segment resolver, whose
// lookup is scoped by exactly that argument (both the SQL predicate and the
// RLS GUC). Sourcing it from the tenant string therefore lets the caller
// choose whose directory the preview reads, and the answer is observable in
// the response. Sourcing it from the authenticated context does not.
//
// The same binding is also a correctness fix: in any deployment where the
// license org and the Basic-Auth username differ (the normal enterprise
// shape), the tenant-sourced value read the wrong org, matched nothing, and
// silently returned a preview with no segment-scoped policies applied.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// orgCapturingSegmentResolver records the org every Resolve call is scoped
// to. The org argument is the whole point of the assertion, so unlike
// fakeSegmentResolver (which ignores it) this double keeps it.
type orgCapturingSegmentResolver struct {
	mu       sync.Mutex
	orgs     []string
	resolved sharedidentity.ResolvedIdentity
}

func (f *orgCapturingSegmentResolver) Resolve(_ context.Context, orgID, _ string) (sharedidentity.ResolvedIdentity, error) {
	f.mu.Lock()
	f.orgs = append(f.orgs, orgID)
	f.mu.Unlock()
	return f.resolved, nil
}

func (f *orgCapturingSegmentResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}
func (f *orgCapturingSegmentResolver) InvalidateUserSegments(_, _ string) {}

func (f *orgCapturingSegmentResolver) capturedOrgs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.orgs...)
}

// TestPolicyTestHandler_ResolvesSegmentsUnderAuthenticatedOrg is the #3255
// regression test. It drives policyTestHandler with an authenticated context
// whose tenant and org DISAGREE - the shape the enterprise license path
// actually produces - and asserts the segment lookup ran under the
// authenticated org.
//
// It fails on pre-fix code: the handler set OrgID from the tenant string, so
// the resolver was called with the caller-chosen value.
func TestPolicyTestHandler_ResolvesSegmentsUnderAuthenticatedOrg(t *testing.T) {
	const (
		authenticatedOrg = "org-from-license"
		callerTenant     = "some-other-org"
	)

	originalEngine := tierAwarePolicyEngine
	t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
	// A nil-DB engine is sufficient: the segment resolution under test runs
	// BEFORE EvaluatePolicy, and the handler tolerates the engine erroring.
	tierAwarePolicyEngine = NewTierAwarePolicyEngine(nil, nil)

	resolver := &orgCapturingSegmentResolver{}
	setFleetSegmentResolver(resolver)
	t.Cleanup(ResetFleetSegmentResolverForTest)

	body, _ := json.Marshal(map[string]interface{}{
		"query":      "quarterly ledger export",
		"user_email": "victim@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/policies/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Exactly what apiAuthMiddleware stamps: tenant from the Basic-Auth
	// username, org from the validated license. They differ here.
	ctx := context.WithValue(req.Context(), ContextKeyTenantID, callerTenant)
	ctx = context.WithValue(ctx, ContextKeyOrgID, authenticatedOrg)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	policyTestHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	orgs := resolver.capturedOrgs()
	if len(orgs) == 0 {
		t.Fatal("vacuity control failed: the segment resolver was never called, so this test asserts nothing about which org it was scoped to")
	}
	for _, got := range orgs {
		if got == callerTenant {
			t.Errorf("segment resolution ran under the caller-influenced tenant string %q; a caller who names another org's identifier as its Basic-Auth username would read that org's directory through this preview", callerTenant)
		}
		if got != authenticatedOrg {
			t.Errorf("segment resolution ran under org %q, want the authenticated %q", got, authenticatedOrg)
		}
	}
}

// TestPolicyTestHandler_FallsBackToTenantWhenNoAuthenticatedOrg pins the
// community shape, where the deployment has no distinct org identity and the
// tenant string is not caller-influenced. The handler must still resolve
// under something rather than silently querying an empty org, so an absent
// context org falls back to the tenant exactly as before this fix.
func TestPolicyTestHandler_FallsBackToTenantWhenNoAuthenticatedOrg(t *testing.T) {
	originalEngine := tierAwarePolicyEngine
	t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
	tierAwarePolicyEngine = NewTierAwarePolicyEngine(nil, nil)

	resolver := &orgCapturingSegmentResolver{}
	setFleetSegmentResolver(resolver)
	t.Cleanup(ResetFleetSegmentResolverForTest)

	body, _ := json.Marshal(map[string]interface{}{
		"query":      "quarterly ledger export",
		"user_email": "someone@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/policies/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Tenant stamped, org absent - no ContextKeyOrgID at all.
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyTenantID, "tenant-only"))

	w := httptest.NewRecorder()
	policyTestHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	orgs := resolver.capturedOrgs()
	if len(orgs) == 0 {
		t.Fatal("vacuity control failed: the segment resolver was never called")
	}
	for _, got := range orgs {
		if got != "tenant-only" {
			t.Errorf("with no authenticated org in context the handler must fall back to the tenant, got %q", got)
		}
	}
}
