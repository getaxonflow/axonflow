// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	sharedidentity "axonflow/platform/shared/identity"
)

// resolveUserSegments (#3473) is the fleet/MCP-server plane's one
// user->segments lookup, collapsed from what used to be two functions with
// opposite error contracts: mcp_identity.go's P2-era resolveUserSegments
// (fail-open, observability-only) and this file's P3 (#3051)
// resolveSegmentsForPolicy (fail-closed, policy-affecting). These tests pin
// the merged function's ONE contract — unconditionally fail-closed — reusing
// the fakeSegmentResolver/withFleetSegmentResolver test doubles already
// established in mcp_identity_test.go (same package, same fixtures — no
// duplicate fakes).

func TestResolveUserSegments_NilResolver_OrgOnlyNotFailure(t *testing.T) {
	ResetFleetSegmentResolverForTest()
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseEnforcement)
	if !ok {
		t.Fatal("no resolver wired (community / no SCIM) must NOT be treated as a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set, got %v", ids)
	}
}

// TestResolveUserSegments_EmptyOrgOrEmail_OrgOnlyNotFailure pins the M1
// early-return (#3239 round 2): an absent identity (no email supplied on a
// preview, or a service-to-service caller with no per-user email) must
// resolve org-only, NEVER deny. This is load-bearing under fail-closed
// convergence — without it, dropping the fail-open carve-out would have
// turned a routine no-email preview into a wrongful DENY, since it would
// otherwise reach the resolver with an empty email and (depending on the
// resolver's own validation) surface as an error. Mirrors
// platform/orchestrator/segment_policy_gate_test.go's test of the same name
// — both planes share this guard via the shared/identity implementation.
func TestResolveUserSegments_EmptyOrgOrEmail_OrgOnlyNotFailure(t *testing.T) {
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "grp-finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	for _, tc := range []struct{ org, email string }{
		{"", "a@example.com"},
		{"org-a", ""},
		{"", ""},
	} {
		ids, ok := resolveUserSegments(context.Background(), tc.org, tc.email, segmentResolutionPhaseEnforcement)
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
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: []sharedidentity.Segment{}}})
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseEnforcement)
	if !ok {
		t.Fatal("zero group memberships is a legitimate success, not a failure")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set for zero memberships, got %v", ids)
	}
}

// TestResolveUserSegments_Error_FailsClosed is the ADR-060 §Fail-closed
// contract this file exists to implement: a genuine resolver ERROR must deny
// (ok=false) on the enforcement phase. After #3239 round 2 this holds
// UNCONDITIONALLY for every enforcement-phase caller — there is no longer a
// second, fail-open contract for policyTestHandler's preview call. (The
// session-auth phase gets the identical `ok=false` return too — see
// TestResolveUserSegments_SessionAuthPhase_ErrorNeverCountsAsFailClosed
// below for what makes it observably distinct: nothing acts on it.)
func TestResolveUserSegments_Error_FailsClosed(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed")})
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseEnforcement)
	if ok {
		t.Fatal("a genuine segment resolution error must DENY (ok=false), never fall back to org-only")
	}
	if ids != nil {
		t.Fatalf("expected nil ids on failure, got %v", ids)
	}
}

// TestResolveUserSegments_EmptyEmail_OrgOnly_NeverCallsResolver pins the
// #travel-us outage fix: a request with NO per-user email (a legitimate
// TENANT-kind user_token on the agent static plane, which carries no email
// claim) must proceed org-only, NOT fail closed. The real resolver's
// ResolveRole returns "requires an email" for "", which failClosed would
// otherwise turn into a hard DENY of every tenant-token request. The resolver
// must not even be consulted — there is no user to resolve segments for — so
// this also asserts callCount()==0. Note the resolver is deliberately wired to
// ERROR: without the empty-email short-circuit this would deny (ok=false),
// so the test would fail; it can only pass because email=="" is handled first.
func TestResolveUserSegments_EmptyEmail_OrgOnly_NeverCallsResolver(t *testing.T) {
	fake := &fakeSegmentResolver{err: errors.New("segment query failed")}
	withFleetSegmentResolver(t, fake)
	ids, ok := resolveUserSegments(context.Background(), "org-a", "", segmentResolutionPhaseEnforcement)
	if !ok {
		t.Fatal("an absent per-user email (tenant-kind token) must proceed org-only, never fail closed")
	}
	if ids != nil {
		t.Fatalf("expected nil segment set for an identity-less request, got %v", ids)
	}
	if c := fake.callCount(); c != 0 {
		t.Fatalf("resolver must not be consulted when there is no user email; callCount=%d", c)
	}
}

// TestResolveUserSegments_NonEmptyEmailError_StillFailsClosed guards that
// the empty-email short-circuit did NOT weaken the ADR-060 §Fail-closed
// contract for the genuine threat: a NON-empty email whose lookup errors must
// still DENY.
func TestResolveUserSegments_NonEmptyEmailError_StillFailsClosed(t *testing.T) {
	fake := &fakeSegmentResolver{err: errors.New("segment query failed")}
	withFleetSegmentResolver(t, fake)
	_, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseEnforcement)
	if ok {
		t.Fatal("a genuine resolver error on a real per-user identity must still fail closed")
	}
	if c := fake.callCount(); c != 1 {
		t.Fatalf("resolver must be consulted for a non-empty email; callCount=%d", c)
	}
}

func TestResolveUserSegments_Success_ReturnsIDs(t *testing.T) {
	want := []sharedidentity.Segment{{ID: "grp-finance", DisplayName: "finance"}, {ID: "grp-ml", DisplayName: "ml-platform"}}
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: want}})
	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseEnforcement)
	if !ok {
		t.Fatal("a successful resolution must never fail closed")
	}
	if len(ids) != 2 || ids[0] != "grp-finance" || ids[1] != "grp-ml" {
		t.Fatalf("resolveUserSegments ids = %v, want [grp-finance grp-ml]", ids)
	}
}

// --- #3473 item 5: phase-label / segmentPolicyFailClosedTotal isolation ---

// counterValue reads a CounterVec's current value for one label combination,
// or 0 if it has never been observed. Avoids depending on Prometheus's text
// exposition format (unlike the runtime-e2e harness's /prometheus scrape).
func counterValue(t *testing.T, c *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m, err := c.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%v): %v", labels, err)
	}
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatalf("Write metric: %v", err)
	}
	return out.GetCounter().GetValue()
}

// TestResolveUserSegments_SessionAuthPhase_ErrorNeverCountsAsFailClosed is
// the behavioral-parity guard for collapsing the session-auth call site
// onto this fail-closed function (#3473 item 2): before the collapse, a
// session-auth resolution error never touched
// segmentPolicyFailClosedTotal at all (that counter didn't exist on the P2
// call path). After the collapse, the SAME shared implementation
// (sharedidentity.ResolveUserSegments) calls metrics.IncFailClosed() on every
// error regardless of phase — so agentSegmentPolicyMetrics.IncFailClosed
// must no-op for segmentResolutionPhaseSessionAuth, or a session-auth
// failure (which denies nothing — mcp_server_handler.go discards `ok`)
// would misreport as a "request denied" in a counter whose Help text says
// exactly that.
func TestResolveUserSegments_SessionAuthPhase_ErrorNeverCountsAsFailClosed(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed")})
	before := counterValue(t, segmentResolutionTotal, "error", "session_auth")
	failClosedBefore := readFailClosedTotal(t)

	ids, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseSessionAuth)
	if ok {
		t.Fatal("a genuine resolver error must still report ok=false even on the session-auth phase (the caller just discards it)")
	}
	if ids != nil {
		t.Fatalf("expected nil ids on failure, got %v", ids)
	}

	after := counterValue(t, segmentResolutionTotal, "error", "session_auth")
	if after != before+1 {
		t.Fatalf("segmentResolutionTotal{result=error,phase=session_auth} = %v, want %v", after, before+1)
	}
	if failClosedAfter := readFailClosedTotal(t); failClosedAfter != failClosedBefore {
		t.Fatalf("segmentPolicyFailClosedTotal must NOT increment for the session_auth phase (it denies nothing): before=%v after=%v", failClosedBefore, failClosedAfter)
	}
}

// TestResolveUserSegments_EnforcementPhase_ErrorCountsAsFailClosed is the
// enforcement-side twin of the test above: an enforcement-phase error DOES
// increment segmentPolicyFailClosedTotal, unchanged from pre-#3473 behavior.
func TestResolveUserSegments_EnforcementPhase_ErrorCountsAsFailClosed(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed")})
	failClosedBefore := readFailClosedTotal(t)

	if _, ok := resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseEnforcement); ok {
		t.Fatal("enforcement-phase resolver error must fail closed")
	}

	if failClosedAfter := readFailClosedTotal(t); failClosedAfter != failClosedBefore+1 {
		t.Fatalf("segmentPolicyFailClosedTotal = %v, want %v", failClosedAfter, failClosedBefore+1)
	}
}

// readFailClosedTotal reads segmentPolicyFailClosedTotal's current value (a
// plain Counter, not a Vec).
func readFailClosedTotal(t *testing.T) float64 {
	t.Helper()
	var out dto.Metric
	if err := segmentPolicyFailClosedTotal.Write(&out); err != nil {
		t.Fatalf("Write segmentPolicyFailClosedTotal: %v", err)
	}
	return out.GetCounter().GetValue()
}

// --- R3 round 2 (PR #3479): the phase-gated log content itself, not just
// the metrics it accompanies. Reuses captureLog (identity_trust_test.go,
// same package) to redirect the standard logger
// agentSegmentPolicyMetrics.LogResolutionError/LogResolutionSuccess write
// through (log.Printf) so a test can assert on exactly what was emitted.

// TestResolveUserSegments_SessionAuthPhase_ErrorLogsWarningNeverDenying is
// the MEDIUM-1 fix: a session-auth-phase resolver error must NEVER log
// "DENYING" (it denies nothing — the request is served 200 regardless), and
// must instead reproduce the pre-#3473 P2-era WARNING-level line so the
// failure stays observable in logs without the false claim.
func TestResolveUserSegments_SessionAuthPhase_ErrorLogsWarningNeverDenying(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed")})
	buf := captureLog(t)

	resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseSessionAuth)

	out := buf.String()
	if strings.Contains(out, "DENYING") {
		t.Fatalf("session-auth phase must NEVER log DENYING (it denies nothing; the request is served 200), got: %s", out)
	}
	if !strings.Contains(out, `[Identity] WARNING: #2989 segment resolution failed org="org-a"`) {
		t.Fatalf("expected the restored WARNING-level line naming the org, got: %s", out)
	}
}

// TestResolveUserSegments_EnforcementPhase_ErrorLogsDenying pins the
// unchanged enforcement-phase behavior: byte-for-byte the pre-#3473 log line.
func TestResolveUserSegments_EnforcementPhase_ErrorLogsDenying(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment query failed")})
	buf := captureLog(t)

	resolveUserSegments(context.Background(), "org-a", "a@example.com", segmentResolutionPhaseEnforcement)

	out := buf.String()
	if !strings.Contains(out, `[Policy] DENYING (fail-closed, ADR-060 #2989): segment resolution failed org="org-a"`) {
		t.Fatalf("expected the unchanged enforcement-phase DENYING line, got: %s", out)
	}
}

// TestResolveUserSegments_SessionAuthPhase_SuccessLogsOrgCountAndGroupIDs is
// the HIGH-1/HIGH-2 fix: the session-auth phase restores the specific-entity
// signal (org, cardinality, resolved group ids) the runtime-e2e suite's
// deleted grep used to pin, moved onto the phase-gated metrics adapter
// instead of firing unconditionally inside the shared lookup.
func TestResolveUserSegments_SessionAuthPhase_SuccessLogsOrgCountAndGroupIDs(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "grp-finance-real-id", DisplayName: "finance"}},
	}})
	buf := captureLog(t)

	ids, ok := resolveUserSegments(context.Background(), "org-a", "alice@example.com", segmentResolutionPhaseSessionAuth)
	if !ok || len(ids) != 1 {
		t.Fatalf("precondition: resolveUserSegments = (%v, %v)", ids, ok)
	}

	out := buf.String()
	if !strings.Contains(out, `#2989 segments resolved org="org-a" count=1`) {
		t.Fatalf("expected the restored success line naming org and count=1, got: %s", out)
	}
	if !strings.Contains(out, "grp-finance-real-id") {
		t.Fatalf("expected the restored success line to name the resolved group id, got: %s", out)
	}
}

// TestResolveUserSegments_SessionAuthPhase_ZeroGroupsLogsCountZero is the
// zero-groups-is-success twin: distinct from an error, still logged.
func TestResolveUserSegments_SessionAuthPhase_ZeroGroupsLogsCountZero(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: []sharedidentity.Segment{}}})
	buf := captureLog(t)

	resolveUserSegments(context.Background(), "org-a", "noone@example.com", segmentResolutionPhaseSessionAuth)

	out := buf.String()
	if !strings.Contains(out, `#2989 segments resolved org="org-a" count=0`) {
		t.Fatalf("expected the restored zero-groups success line, got: %s", out)
	}
}

// TestResolveUserSegments_EnforcementPhase_SuccessLogsNothing guards the
// other half of the trade the original R3 round-1 finding surfaced: the
// enforcement phase runs on every policy-affecting request, so it must NOT
// gain a per-call log line (that would flood the log for no benefit
// segmentResolutionTotal doesn't already provide).
func TestResolveUserSegments_EnforcementPhase_SuccessLogsNothing(t *testing.T) {
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "grp-finance"}},
	}})
	buf := captureLog(t)

	resolveUserSegments(context.Background(), "org-a", "alice@example.com", segmentResolutionPhaseEnforcement)

	if buf.Len() != 0 {
		t.Fatalf("enforcement-phase success must not log, got: %s", buf.String())
	}
}

// =============================================================================
// The resolution PHASE must be pinned per call site.
//
// The phase used to be a positional enum argument, so it was entirely
// caller-supplied and nothing anywhere pinned it: flipping every enforcement
// call site to the observability phase compiled and passed the whole suite. In
// production that flatlines axonflow_segment_policy_fail_closed_total through
// a live segment-store outage while requests ARE being denied, replaces each
// "DENYING" line with a WARNING, and starts logging a success line per request
// on the hot path — the exact flood the phase gate exists to prevent. The
// denial itself still happens, so it is audit and observability integrity
// rather than authorization, which is precisely why no behavioural test caught
// it.
//
// The wrappers make the phase structural: a call site picks a differently
// named function rather than a differently valued argument. This census pins
// which wrapper each production site uses, so a future edit that reaches for
// the raw form or the wrong wrapper fails here rather than silently.
func TestSegmentResolutionPhaseIsPinnedPerCallSite(t *testing.T) {
	// Production call sites, by file, with the wrapper each MUST use.
	want := map[string]string{
		"run.go":                "resolveUserSegmentsForEnforcement",
		"gateway_handlers.go":   "resolveUserSegmentsForEnforcement",
		"mcp_identity.go":       "resolveUserSegmentsForEnforcement",
		"mcp_server_handler.go": "resolveUserSegmentsForObservability",
	}
	// run.go additionally holds the ONE preview call site (policyTestHandler).
	extra := map[string][]string{
		"run.go": {"resolveUserSegmentsForPreview"},
	}

	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	agentPkg, ok := pkg["agent"]
	if !ok {
		t.Fatal("agent package not found")
	}

	seen := map[string]map[string]bool{}
	for name, f := range agentPkg.Files {
		base := filepath.Base(name)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || !strings.HasPrefix(id.Name, "resolveUserSegments") {
				return true
			}
			// The wrappers' own bodies call the raw form; skip the defining file.
			if base == "segment_policy_gate.go" {
				return true
			}
			if seen[base] == nil {
				seen[base] = map[string]bool{}
			}
			seen[base][id.Name] = true
			return true
		})
	}

	for file, wrapper := range want {
		got := seen[file]
		if got == nil {
			t.Errorf("%s no longer resolves segments at all — if the call site moved, move this pin with it", file)
			continue
		}
		if !got[wrapper] {
			t.Errorf("%s must resolve via %s; found %v. Picking a different wrapper silently changes "+
				"which phase the metric and the DENYING log are attributed to.", file, wrapper, keysOf(got))
		}
		if got["resolveUserSegments"] {
			t.Errorf("%s calls the raw phase-taking form. Use a named wrapper — a positional enum is "+
				"caller-supplied and is exactly what went unpinned before.", file)
		}
	}
	for file, wrappers := range extra {
		for _, wrapper := range wrappers {
			if !seen[file][wrapper] {
				t.Errorf("%s must retain a %s call site (policyTestHandler simulates a verdict and "+
					"returns 200, so its failures must not reach the denial counter)", file, wrapper)
			}
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
