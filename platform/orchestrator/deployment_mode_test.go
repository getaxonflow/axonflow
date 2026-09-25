// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestMain declares the deployment posture this package's unit tests run under.
//
// #3096 changed isCommunityMode() so that an UNSET DEPLOYMENT_MODE no longer
// means community. That is the right production default — community bypasses
// authority checks, so it must be asked for by name — but it exposed a large
// implicit assumption in this test suite: ~68 tests drive handlers DIRECTLY,
// bypassing requireInternalProxyAuth, and depend on the community posture for
// read authority (resolveCallerReadScope grants {TenantWide, AdminAuthority}
// unconditionally in community mode; under the enterprise posture a caller with
// no identity is scoped down to zero rows and those tests see empty result sets).
//
// That assumption is stated ONCE here rather than pasted into every test,
// because it is a property of the harness — "these are handler unit tests, not
// authority tests" — not of any individual case.
//
// This does NOT weaken the fix. The production predicate still fails closed;
// what this sets is the baseline for tests that are about something else. Two
// things keep it honest:
//
//   - Every test that IS about the posture sets DEPLOYMENT_MODE itself with
//     t.Setenv, which overrides this default for the duration of that test and
//     restores it afterwards. All 84 pre-existing DEPLOYMENT_MODE uses in this
//     package already do exactly that.
//   - TestIsCommunityMode_UnsetFailsClosed below pins the new contract by
//     explicitly clearing the variable, so re-introducing the fail-open default
//     still fails the suite.
func TestMain(m *testing.M) {
	// Set unconditionally rather than only-if-absent: a deterministic baseline
	// is worth more here than the ability to run the suite under an injected
	// mode, and an ambient DEPLOYMENT_MODE from the developer's shell silently
	// changing which branch 68 tests take is precisely the class of surprise
	// #3096 exists to remove.
	if err := os.Setenv("DEPLOYMENT_MODE", "community"); err != nil {
		panic("orchestrator TestMain: cannot set DEPLOYMENT_MODE: " + err.Error())
	}
	// #4249 row 5701303521: every LLM call takes the organization's route rows,
	// and with no route source wired it is refused fail-closed. A test that
	// reaches an LLM call without declaring a source (withLLMCallRouteSource)
	// reads "no route rows" here, deterministically, rather than whatever an
	// earlier test left cached (row 5774257842). A test of the production
	// factory calls productionRouteRequestFactProducer.
	newRouteRequestFactProducer = func() (routeFactSource, error) { return noRouteRows{}, nil }
	// The policy summary reads the agent's installed-pack count (#4249). No
	// test reaches a real agent: by default the read fails at once, as an
	// unreachable agent does, and a test of the read installs its own agent
	// (withSummaryAgent).
	typedAuthoringAgentSummary = unreachableSummaryAgent
	os.Exit(m.Run())
}

// TestIsCommunityMode_UnsetFailsClosed pins the #3096 contract for the
// orchestrator's copy of the helper.
//
// It matters more here than on the agent: resolveCallerReadScope
// (read_scope.go) returns {TenantWide: true, AdminAuthority: true}
// unconditionally for community mode, BEFORE any token or role check. While
// unset meant community, an orchestrator whose operator simply never set
// DEPLOYMENT_MODE handed tenant-wide read authority — and whole-tenant
// compliance exports — to every caller that reached it.
func TestIsCommunityMode_UnsetFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want bool
	}{
		{"explicit community", "community", true},
		{"unset fails closed", "", false},
		{"enterprise", "enterprise", false},
		{"community-saas is its own mode", "community-saas", false},
		{"in-vpc-enterprise", "in-vpc-enterprise", false},
		{"evaluation", "evaluation", false},
		{"typo fails closed", "communtiy", false},
		// Deliberately neither trimmed nor case-folded: every widening of this
		// predicate hands out tenant-wide read authority.
		{"padded fails closed", " community ", false},
		{"capitalised fails closed", "Community", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", c.mode)
			if got := isCommunityMode(); got != c.want {
				t.Errorf("isCommunityMode() = %v, want %v for DEPLOYMENT_MODE=%q", got, c.want, c.mode)
			}
		})
	}
}

// TestResolveCallerReadScope_UnsetModeDoesNotGrantTenantWide is the assertion
// that actually matters: the #3096 defect was not the predicate in isolation,
// it was the authority the predicate conferred. An unset mode must not produce
// a tenant-wide, admin-authority read scope for a caller that presented no
// identity at all.
func TestResolveCallerReadScope_UnsetModeDoesNotGrantTenantWide(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "")

	// No identity headers, no per-user token, no proxy auth — the shape a
	// caller that simply reached the port presents.
	req := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	req.Header.Set("X-Tenant-ID", "acme")
	scope := resolveCallerReadScope(req)

	if scope.TenantWide {
		t.Error("unset DEPLOYMENT_MODE granted TenantWide read authority to an unidentified caller (#3096)")
	}
	if scope.AdminAuthority {
		t.Error("unset DEPLOYMENT_MODE granted AdminAuthority to an unidentified caller (#3096)")
	}
}

// noRouteRows is a route fact source with no rows: no facts, no route effects.
type noRouteRows struct{}

func (noRouteRows) Produce(context.Context, OrchestratorRequest) (contract.AttributeSet, routeEffects, error) {
	return contract.AttributeSet{}, routeEffects{}, nil
}
