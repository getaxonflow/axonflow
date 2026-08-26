// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// #3430 (ADR-060 P3 fleet-plane promotion): the MCP-server JSON-RPC plane's
// check_policy/check_output tools now resolve the caller's governance-segment
// set FAIL-CLOSED (resolveMCPServerSegmentsForPolicy, mcp_identity.go) and
// thread it into the shared engine via evaluateInputPolicies /
// evaluateOutputPolicies (mcp_handler.go), replacing the hardcoded
// Segments: nil that left a verified MCP-server human actor's segment-scoped
// policies unenforced (#3430 brief, correcting #3280's "no human-actor half"
// claim for this plane).
//
// R3 BLOCKER 1 (round 2) closed the OTHER half of the same bypass: round 1
// returned org-only for any session with no validated per-user token, so the
// same human could turn every segment-scoped policy off for themselves by
// simply OMITTING X-User-Token (ResolveToken returns (nil, nil) for an empty
// token, so the request is still served on the pseudo-identity path). An
// indeterminate segment set now DENIES whenever segment-scoped policies
// actually exist for the (tenant, org, phase) under evaluation, and proceeds
// org-only when none do. The tests below pin BOTH halves, and pin that the
// conditional really is conditional.
//
// This plane resolves identity BEFORE the tool call runs, at session-create
// time (authenticateMCPSession) - unlike the gateway pre-check surface
// (#3312, gateway_precheck_segment_enforcement_test.go), there is no
// HTTP/JWT layer to drive here: mcpToolCheckPolicy/mcpToolCheckOutput take
// an already-built *mcpSession directly, so these tests set its
// identityInputs.tokenResolvedIdentity / orgID / userEmail fields directly
// to stand in for a validated (or non-validated) per-user-token session.

const (
	// segTestMarker matches ONLY the segment-scoped fixture policy.
	segTestMarker = "confidential_ledger"
	// orgTestMarker matches ONLY the org-tier (non-segment-scoped) control.
	orgTestMarker = "org_wide_secret"
	// segRespMarker matches ONLY the segment-scoped RESPONSE-phase fixture.
	segRespMarker = "confidential_ledger_response"
)

// --- fixtures ---

// installSharedEngineWithOrgTierPolicyOnly seeds a policy set with NO
// segment-scoped row at all: one org-tier (segment_id IS NULL) BLOCK control
// plus the mandatory system row. It is the control fixture for the #3430 R3
// conditional - a deployment that has never adopted segment targeting must
// see EXACTLY its pre-#3430 behavior, including for a caller with no
// per-user token.
func installSharedEngineWithOrgTierPolicyOnly(t *testing.T, tenantID, orgPattern string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)

	for i := 0; i < 12; i++ {
		rows := orgTierControlPolicyRow(sqlmock.NewRows(policytest.LoaderCols()),
			"org-policy-1", "org_control_block", tenantID,
			"compliance-rbi", orgPattern, "critical", "both", "block", 90)
		rows = policytest.SystemPolicyRow(rows,
			"sys-never-matches", "sys_test_never_matches",
			"security-sqli", "ZZ_NEVER_MATCHES_ZZ", "low", "request", "block", 1)
		mockSQL.ExpectQuery("SELECT").WillReturnRows(rows)
	}
	policytest.ScopedTxPlumbing(mockSQL, 12)

	installGlobalEngine(t, mockDB)
}

// installSharedEngineWithSegmentScopedResponsePolicy seeds a segment-scoped
// SENSITIVE-DATA policy carrying an explicit action_response, so it can
// actually BLOCK on the response phase.
//
// Category choice is load-bearing: evaluateOutputPolicies' static pass
// enumerates only the PII / sensitive-data / security-dangerous categories
// (Enabled*Categories), so a compliance-rbi row - the category the
// request-phase fixtures use - is never evaluated on the response phase at
// all and could not prove anything there. The caller must also set
// SENSITIVE_DATA_ACTION=block (see withSensitiveDataBlockPosture), because
// ModeDetectionConfig.BuildActionOverrides rewrites this category's action to
// the deployment posture, whose default is warn.
func installSharedEngineWithSegmentScopedResponsePolicy(t *testing.T, segmentID, tenantID string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)

	for i := 0; i < 12; i++ {
		rows := sqlmock.NewRows(policytest.LoaderCols()).AddRow(
			"seg-resp-policy-1", "seg_finance_response_block", "Test policy seg_finance_response_block",
			"sensitive-data", "tenant", segRespMarker, "critical",
			nil, "both", "block", "block",
			true, 100, tenantID, segmentID, []byte(`{}`),
			time.Now().UTC(),
		)
		rows = policytest.SystemPolicyRow(rows,
			"sys-never-matches", "sys_test_never_matches",
			"security-sqli", "ZZ_NEVER_MATCHES_ZZ", "low", "request", "block", 1)
		mockSQL.ExpectQuery("SELECT").WillReturnRows(rows)
	}
	policytest.ScopedTxPlumbing(mockSQL, 12)

	installGlobalEngine(t, mockDB)
}

// installGlobalEngine swaps in a UnifiedPolicyEngine over db for the test's
// lifetime. Shared by the fixtures above so they cannot drift on engine
// config.
func installGlobalEngine(t *testing.T, db *sql.DB) {
	t.Helper()
	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(db, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
}

// withSensitiveDataBlockPosture forces SENSITIVE_DATA_ACTION=block for the
// test's lifetime so a seeded sensitive-data policy's stored 'block' survives
// BuildActionOverrides instead of being rewritten to the default warn.
func withSensitiveDataBlockPosture(t *testing.T) {
	t.Helper()
	t.Setenv(EnvSensitiveDataAction, "block")
	ResetDetectionConfigCache()
	t.Cleanup(ResetDetectionConfigCache)
}

// withDetectionDisabled turns the static detection pass off for the test's
// lifetime, the deployment shape in which no static policy - segment-scoped
// or not - can fire.
func withDetectionDisabled(t *testing.T) {
	t.Helper()
	// MCP_STATIC_POLICIES_ENABLED, not the gateway lever: both tools under
	// test resolve their posture through ResolveMCPDetectionConfig.
	t.Setenv(EnvMCPStaticPoliciesEnabled, "false")
	ResetDetectionConfigCache()
	t.Cleanup(ResetDetectionConfigCache)
}

// --- resolveMCPServerSegmentsForPolicy: the gate contract ---

// TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_SegmentScopedPolicyPresent_Denies
// is the R3 BLOCKER 1 unit proof: a session with no validated per-user token
// and segment-scoped policies in scope is DENIED, not silently evaluated
// against a narrowed policy set. The resolver is still never consulted -
// there is no per-user principal to resolve against - so this is a refusal,
// not a widening of enforcement onto an unverified identity.
func TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_SegmentScopedPolicyPresent_Denies(t *testing.T) {
	const tenantID, orgID = "gate-notoken-tenant", "gate-notoken-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	// identityInputs.tokenResolvedIdentity left at its zero value (false) -
	// exactly what omitting X-User-Token produces.
	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: mcpClientPseudoIdentityPrefix + "legacy-client"}

	ids, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateDenyIdentityUnresolved {
		t.Fatalf("outcome = %v, want mcpSegmentGateDenyIdentityUnresolved - a caller who simply omits X-User-Token must not get segment enforcement switched off", outcome)
	}
	if ids != nil {
		t.Fatalf("a denied gate must return no segment set, got %v", ids)
	}
	if c := fake.callCount(); c != 0 {
		t.Fatalf("resolver must NOT be consulted for a session with no per-user principal; callCount=%d", c)
	}
}

// TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_NoSegmentScopedPolicy_Proceeds
// is the other half of the same conditional and the compatibility proof: with
// no segment-scoped row in scope, the verdict cannot depend on segments, so
// the identical token-less caller proceeds org-only exactly as before #3430.
func TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_NoSegmentScopedPolicy_Proceeds(t *testing.T) {
	const tenantID, orgID = "gate-notoken-clean-tenant", "gate-notoken-clean-org"
	installSharedEngineWithOrgTierPolicyOnly(t, tenantID, orgTestMarker)
	withFleetSegmentResolver(t, &fakeSegmentResolver{})

	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: mcpClientPseudoIdentityPrefix + "legacy-client"}

	ids, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateProceed {
		t.Fatalf("outcome = %v, want mcpSegmentGateProceed - a deployment with no segment-scoped policy must be completely unaffected by #3430", outcome)
	}
	if ids != nil {
		t.Fatalf("expected a nil (org-only) segment set, got %v", ids)
	}
}

// TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_StaticEvaluationOff_Proceeds
// pins that the refusal is scoped to requests whose static pass actually
// runs: with detection disabled no static policy can fire, so an
// indeterminate segment set cannot change any verdict and must not deny.
func TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_StaticEvaluationOff_Proceeds(t *testing.T) {
	const tenantID, orgID = "gate-nostatic-tenant", "gate-nostatic-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)
	withFleetSegmentResolver(t, &fakeSegmentResolver{})

	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: mcpClientPseudoIdentityPrefix + "legacy-client"}

	_, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, false)
	if outcome != mcpSegmentGateProceed {
		t.Fatalf("outcome = %v, want mcpSegmentGateProceed when the static pass will not run", outcome)
	}
}

// TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_PolicySetUnreadable_Denies
// pins the fail-closed answer to "could not tell": the canary engine has ZERO
// query expectations, so HasSegmentScopedPolicies cannot load and returns
// ok == false. An unknown answer must deny, never proceed.
func TestResolveMCPServerSegmentsForPolicy_NoPerUserToken_PolicySetUnreadable_Denies(t *testing.T) {
	installCanarySharedEngine(t)
	withFleetSegmentResolver(t, &fakeSegmentResolver{})

	session := &mcpSession{tenantID: "gate-unreadable-tenant", orgID: "gate-unreadable-org", userEmail: mcpClientPseudoIdentityPrefix + "legacy-client"}

	_, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateDenyIdentityUnresolved {
		t.Fatalf("outcome = %v, want a deny when the policy set cannot be read", outcome)
	}
}

// TestResolveMCPServerSegmentsForPolicy_TrustedHeaderIdentity_IsNotAPerUserPrincipal
// is the anti-sibling-bypass pin. A trust-gated X-User-Email produces a
// perfectly real-looking session.userEmail with tokenResolvedIdentity FALSE.
// Accepting it as a segment-resolution key would let the same human shed
// their segments by naming a non-member colleague - the reported bypass
// recreated through a different header. The gate must treat it as
// indeterminate and refuse, and must never call the resolver with it.
func TestResolveMCPServerSegmentsForPolicy_TrustedHeaderIdentity_IsNotAPerUserPrincipal(t *testing.T) {
	const tenantID, orgID = "gate-header-tenant", "gate-header-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	// A header-supplied identity: a real address, but nothing validated it.
	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: "not-really-carol@corp.example"}

	_, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateDenyIdentityUnresolved {
		t.Fatalf("outcome = %v, want a deny - a caller-supplied header must never decide which segment-scoped policies apply", outcome)
	}
	if c := fake.callCount(); c != 0 {
		t.Fatalf("the resolver must never be keyed on a caller-supplied identity; callCount=%d", c)
	}
}

// TestResolveMCPServerSegmentsForPolicy_SharedSyntheticTokenSubject_Denies:
// a token can VALIDATE while naming one of the platform's shared synthetics
// (mint() checks only for an "@", ResolveToken censuses nothing - see
// authenticateMCPSession's #3077 R3 comment). Resolving segments for such an
// address returns zero memberships and reads as "this person is in no
// segment", which is the same bypass with a mintable token instead of a
// dropped header. IsSharedSyntheticIdentity is consulted, so the gate refuses.
func TestResolveMCPServerSegmentsForPolicy_SharedSyntheticTokenSubject_Denies(t *testing.T) {
	const tenantID, orgID = "gate-synth-tenant", "gate-synth-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)

	fake := &fakeSegmentResolver{}
	withFleetSegmentResolver(t, fake)

	for _, subject := range []string{
		"svc@axonflow.local",
		"orchestrator@axonflow.internal",
		mcpClientPseudoIdentityPrefix + "some-client",
	} {
		session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: subject}
		session.identityInputs.tokenResolvedIdentity = true

		_, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
		if outcome != mcpSegmentGateDenyIdentityUnresolved {
			t.Fatalf("subject %q: outcome = %v, want a deny - a validated token naming a SHARED synthetic is not a per-user principal", subject, outcome)
		}
	}
	if c := fake.callCount(); c != 0 {
		t.Fatalf("resolver must not be consulted for a shared-synthetic subject; callCount=%d", c)
	}
}

// TestResolveMCPServerSegmentsForPolicy_NilSession_Denies: a gate must not
// answer "proceed" for an absent principal. Unreachable from a served
// request (requireMCPAuth refuses first), pinned so it stays that way.
func TestResolveMCPServerSegmentsForPolicy_NilSession_Denies(t *testing.T) {
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	ids, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), nil, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateDenyIdentityUnresolved {
		t.Fatalf("nil session must deny, got outcome=%v ids=%v", outcome, ids)
	}
	if c := fake.callCount(); c != 0 {
		t.Fatalf("resolver must not be consulted for a nil session; callCount=%d", c)
	}
}

func TestResolveMCPServerSegmentsForPolicy_ValidatedToken_Success(t *testing.T) {
	want := []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}}
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: want}}
	withFleetSegmentResolver(t, fake)

	session := &mcpSession{orgID: "org-a", userEmail: "carol@example.com"}
	session.identityInputs.tokenResolvedIdentity = true

	ids, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateProceed {
		t.Fatalf("a successful resolution must proceed, got %v", outcome)
	}
	if len(ids) != 1 || ids[0] != "finance" {
		t.Fatalf("ids = %v, want [finance]", ids)
	}
	if c := fake.callCount(); c != 1 {
		t.Fatalf("resolver must be consulted exactly once for a validated session; callCount=%d", c)
	}
}

func TestResolveMCPServerSegmentsForPolicy_ValidatedToken_ResolverError_FailsClosed(t *testing.T) {
	fake := &fakeSegmentResolver{err: errors.New("segment query failed")}
	withFleetSegmentResolver(t, fake)

	session := &mcpSession{orgID: "org-a", userEmail: "carol@example.com"}
	session.identityInputs.tokenResolvedIdentity = true

	ids, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateDenyResolutionFailed {
		t.Fatalf("a genuine resolver error on a validated per-user identity must fail closed as a RESOLUTION failure, got %v", outcome)
	}
	if ids != nil {
		t.Fatalf("expected nil ids on failure, got %v", ids)
	}
}

// TestResolveMCPServerSegmentsForPolicy_NoResolverWired_Proceeds pins the
// "capability absent" arm, deliberately shared with the two already-merged
// planes (#3051 run.go, #3312 gateway): with no identity-attribute resolver
// constructed at all there is no segment layer in this deployment, so BOTH a
// validated and a token-less caller proceed org-only. Denying here alone
// would make this plane refuse traffic its two siblings serve.
func TestResolveMCPServerSegmentsForPolicy_NoResolverWired_Proceeds(t *testing.T) {
	ResetFleetSegmentResolverForTest()
	const tenantID, orgID = "gate-noresolver-tenant", "gate-noresolver-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)

	t.Run("validated session", func(t *testing.T) {
		session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: "carol@corp.example"}
		session.identityInputs.tokenResolvedIdentity = true
		ids, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
		if outcome != mcpSegmentGateProceed || ids != nil {
			t.Fatalf("no resolver wired must proceed org-only, got ids=%v outcome=%v", ids, outcome)
		}
	})

	t.Run("token-less session", func(t *testing.T) {
		session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: mcpClientPseudoIdentityPrefix + "legacy-client"}
		ids, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
		if outcome != mcpSegmentGateProceed || ids != nil {
			t.Fatalf("no resolver wired must proceed org-only for a token-less caller too, got ids=%v outcome=%v", ids, outcome)
		}
	})
}

// --- mcpToolCheckPolicy (request phase): end-to-end enforcement ---

// setupMCPSegmentEnforcementTest disables the dynamic-policy evaluator (so
// only static/segment evaluation is under test) and nils usageDB (every
// audit writer these tests exercise on the ALLOW/redact paths nil-guards on
// db == nil, per writeMCPDecisionAudit / writeExplainableAuditLog /
// buildRicherCheckInputBlock) - tests that need to assert an audit row wire
// their own sqlmock DB instead.
func setupMCPSegmentEnforcementTest(t *testing.T) {
	t.Helper()
	origUsageDB := usageDB
	usageDB = nil
	t.Cleanup(func() { usageDB = origUsageDB })

	origDynEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origDynEval) })
}

// checkPolicyArgs is the minimal tools/call argument map for check_policy.
func checkPolicyArgs(statement string) map[string]interface{} {
	return map[string]interface{}{"connector_type": "postgres", "statement": statement}
}

// toolRespMap normalizes a tool result into a map, failing the test on any
// error or unexpected shape.
func toolRespMap(t *testing.T, resp interface{}, err error) map[string]interface{} {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("resp not a map: %T", resp)
	}
	return m
}

// runCheckPolicy / runCheckOutput drive one tool call and return its response
// map. Separate helpers (rather than one that takes the tool's two return
// values) because Go forbids mixing a multi-value call with other arguments.
func runCheckPolicy(t *testing.T, session *mcpSession, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	resp, err := mcpToolCheckPolicy(context.Background(), session, args)
	return toolRespMap(t, resp, err)
}

func runCheckOutput(t *testing.T, session *mcpSession, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	resp, err := mcpToolCheckOutput(context.Background(), session, args)
	return toolRespMap(t, resp, err)
}

// TestMCPToolCheckPolicy_SegmentMember_PolicyEnforced is the headline #3430
// proof for the request phase: a member of the policy's segment is BLOCKED
// by check_policy - before this fix, Segments: nil excluded this row for
// every MCP-server caller including a member, so a finance-segment member
// blocked on /api/request could re-issue the identical statement through an
// MCP tool call unblocked.
func TestMCPToolCheckPolicy_SegmentMember_PolicyEnforced(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)

	const tenantID, orgID, email = "mcp-seg-mem-tenant", "mcp-seg-mem-org", "carol@corp.example"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, "ZZ_ORG_CONTROL_NEVER_MATCHES_ZZ")

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: email, userID: email, userRole: "developer", clientID: "seg-mcp-client"}
	session.identityInputs.tokenResolvedIdentity = true

	m := runCheckPolicy(t, session, checkPolicyArgs("please read the "+segTestMarker+" for Q3"))
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("#3430: expected a segment MEMBER to be blocked by the segment-scoped policy, got %+v", m)
	}
	if got, _ := m["blocked_by"].(string); got != "seg_finance_ledger_block" {
		t.Fatalf("expected the block attributed to the segment-scoped policy, got blocked_by=%q resp=%+v", got, m)
	}
	if c := fake.callCount(); c != 1 {
		t.Fatalf("expected the segment resolver to be called exactly once, got %d", c)
	}
}

// TestMCPToolCheckPolicy_SegmentNonMember_NotBlocked is the #3266
// restriction-only regression proof carried into #3430: a caller who
// resolves to a DIFFERENT segment must NOT be blocked by the segment-scoped
// policy on the MCP-server plane either.
func TestMCPToolCheckPolicy_SegmentNonMember_NotBlocked(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)

	const tenantID, orgID, email = "mcp-seg-nonmem-tenant", "mcp-seg-nonmem-org", "dave@corp.example"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, "ZZ_ORG_CONTROL_NEVER_MATCHES_ZZ")

	// Caller resolves to segment "engineering" - NOT a member of "finance".
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "engineering", DisplayName: "Engineering"}},
	}}
	withFleetSegmentResolver(t, fake)

	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: email, userID: email, userRole: "developer", clientID: "seg-mcp-client"}
	session.identityInputs.tokenResolvedIdentity = true

	m := runCheckPolicy(t, session, checkPolicyArgs("please read the "+segTestMarker+" for Q3"))
	if allowed, _ := m["allowed"].(bool); !allowed {
		t.Fatalf("#3266/#3430: expected a non-member NOT to be blocked by a segment-scoped policy outside their segment, got %+v", m)
	}

	// #3266 disclosure half at the evaluation layer (mcpToolCheckPolicy's own
	// response carries no policy list on a clean allow, so the ABSENCE claim
	// is asserted directly against evaluateInputPolicies' outcome, the same
	// function mcpToolCheckPolicy delegates to): the segment-scoped policy
	// must not appear in MatchedPolicies for a non-member even though its
	// pattern is present in the statement - it must be excluded from
	// evaluation entirely, not merely fail to fire.
	mcpDetectionCfg := ResolveMCPDetectionConfig(context.Background(), orgID)
	outcome := evaluateInputPolicies(context.Background(),
		tenantID, orgID, email, "developer", "postgres", "",
		"execute", "please read the "+segTestMarker+" for Q3", nil,
		mcpDetectionCfg, false, []string{"engineering"})
	if outcome.StaticResult == nil {
		t.Fatal("expected a static result")
	}
	for _, mp := range outcome.StaticResult.MatchedPolicies {
		if mp.PolicyID == "seg_finance_ledger_block" {
			t.Fatalf("segment-scoped policy leaked into a non-member's MatchedPolicies: %+v", outcome.StaticResult.MatchedPolicies)
		}
	}
}

// TestMCPToolCheckPolicy_SegmentResolutionError_FailsClosedAndAudited pins
// the #3293 locked invariant on the MCP-server plane: a genuine resolver
// error must deny the WHOLE tool call before evaluateInputPolicies (and
// therefore the shared engine) ever runs, and that deny must be observable
// via the canonical audit_logs row. installCanarySharedEngine has ZERO query
// expectations registered - if evaluation ran anyway it would hit an
// unexpected-query error, so a clean allowed=false response with the
// resolution-site reason proves the deny happened at the resolution site.
func TestMCPToolCheckPolicy_SegmentResolutionError_FailsClosedAndAudited(t *testing.T) {
	installCanarySharedEngine(t)

	fake := &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}
	withFleetSegmentResolver(t, fake)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	origUsageDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origUsageDB })
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	session := &mcpSession{tenantID: "seg-fc-tenant", orgID: "seg-fc-org", userEmail: "erin@corp.example", userID: "erin@corp.example", userRole: "developer", clientID: "seg-mcp-client"}
	session.identityInputs.tokenResolvedIdentity = true

	m := runCheckPolicy(t, session, checkPolicyArgs("hello, totally benign query"))
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("#3293: a segment-resolution failure must deny the whole tool call, got %+v", m)
	}
	const wantReason = "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"
	if got, _ := m["block_reason"].(string); got != wantReason {
		t.Fatalf("block_reason = %q, want the resolution-site reason %q - a different reason means the deny came from somewhere else, meaning the failure reached evaluation instead of being denied at the source", got, wantReason)
	}
	if got, _ := m["blocked_by"].(string); got != mcpSegmentResolutionFailedPolicyID {
		t.Fatalf("blocked_by = %q, want %q", got, mcpSegmentResolutionFailedPolicyID)
	}
	if c := fake.callCount(); c != 1 {
		t.Fatalf("expected the segment resolver to be called exactly once, got %d", c)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("fail-closed deny did not emit the canonical audit_logs row: %v", err)
	}
}

// TestMCPToolCheckPolicy_SameHumanDropsToken_DeniedAndAudited is the R3
// BLOCKER 1 end-to-end proof, and it is deliberately the SAME principal as
// TestMCPToolCheckPolicy_SegmentMember_PolicyEnforced above: same tenant,
// same org, same statement, same resolver returning finance membership. The
// ONLY difference is that no per-user token was presented, which on this
// plane is not an error (ResolveToken returns (nil, nil) for an empty token)
// and downgrades the session to the client-scoped pseudo-identity.
//
// Round 1 of this PR answered allowed=true here. That was the bypass: one
// omitted header, at zero cost, turned every segment-scoped policy off for a
// caller who is otherwise identical to the blocked member above.
func TestMCPToolCheckPolicy_SameHumanDropsToken_DeniedAndAudited(t *testing.T) {
	const tenantID, orgID = "mcp-seg-mem-tenant", "mcp-seg-mem-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)

	origDynEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(origDynEval) })

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	origUsageDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origUsageDB })
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	// The identity the plane mints when X-User-Token is omitted.
	session := &mcpSession{
		tenantID: tenantID, orgID: orgID,
		userEmail: mcpClientPseudoIdentityPrefix + "seg-mcp-client",
		userID:    mcpClientPseudoIdentityPrefix + "seg-mcp-client",
		clientID:  "seg-mcp-client",
	}

	m := runCheckPolicy(t, session, checkPolicyArgs("please read the "+segTestMarker+" for Q3"))
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("R3 BLOCKER 1: dropping X-User-Token must NOT switch segment enforcement off, got %+v", m)
	}
	if got, _ := m["blocked_by"].(string); got != mcpSegmentIdentityUnresolvedPolicyID {
		t.Fatalf("blocked_by = %q, want %q", got, mcpSegmentIdentityUnresolvedPolicyID)
	}
	const wantReason = "segment membership indeterminate for a caller with no validated per-user token - request denied (fail-closed, ADR-060 #3430)"
	if got, _ := m["block_reason"].(string); got != wantReason {
		t.Fatalf("block_reason = %q, want %q", got, wantReason)
	}
	if c := fake.callCount(); c != 0 {
		t.Fatalf("the refusal must not consult the resolver on an unverified principal; callCount=%d", c)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the identity-unresolved deny did not emit the canonical audit_logs row: %v", err)
	}
}

// TestMCPToolCheckPolicy_NoPerUserToken_NoSegmentScopedPolicy_Unaffected is
// the compatibility control for the refusal above, and it is what keeps the
// new deny proportionate: the identical token-less caller in a deployment
// that has no segment-scoped policy is served exactly as before #3430,
// INCLUDING having the org-tier control policy still enforce.
func TestMCPToolCheckPolicy_NoPerUserToken_NoSegmentScopedPolicy_Unaffected(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)

	const tenantID, orgID = "mcp-seg-notoken-clean-tenant", "mcp-seg-notoken-clean-org"
	installSharedEngineWithOrgTierPolicyOnly(t, tenantID, orgTestMarker)

	fake := &fakeSegmentResolver{}
	withFleetSegmentResolver(t, fake)

	session := &mcpSession{
		tenantID: tenantID, orgID: orgID,
		userEmail: mcpClientPseudoIdentityPrefix + "legacy-client",
		userID:    mcpClientPseudoIdentityPrefix + "legacy-client",
		clientID:  "legacy-client",
	}

	t.Run("benign query is allowed", func(t *testing.T) {
		m := runCheckPolicy(t, session, checkPolicyArgs("what is the weather forecast"))
		if allowed, _ := m["allowed"].(bool); !allowed {
			t.Fatalf("a deployment with no segment-scoped policy must be unaffected by #3430, got %+v", m)
		}
	})

	t.Run("org-tier control policy still enforces", func(t *testing.T) {
		m := runCheckPolicy(t, session, checkPolicyArgs("this query contains "+orgTestMarker+" data"))
		if allowed, _ := m["allowed"].(bool); allowed {
			t.Fatalf("regression: a non-segment-scoped org-tier policy must still enforce for a token-less caller, got %+v", m)
		}
	})

	if c := fake.callCount(); c != 0 {
		t.Fatalf("resolver must never be consulted for a session with no per-user principal; callCount=%d", c)
	}
}

// TestMCPToolCheckPolicy_DetectionDisabled_IndeterminateIdentityAllowed pins
// the pairing between mcpToolCheckPolicy's staticEvaluationWillRun expression
// and evaluateInputPolicies' own static-pass gate. With detection off no
// static policy can fire, so the segment-scoped row in scope must NOT produce
// a refusal - otherwise the gate would deny traffic on a verdict that could
// never have differed.
func TestMCPToolCheckPolicy_DetectionDisabled_IndeterminateIdentityAllowed(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)
	withDetectionDisabled(t)

	const tenantID, orgID = "mcp-seg-nodetect-tenant", "mcp-seg-nodetect-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)
	withFleetSegmentResolver(t, &fakeSegmentResolver{})

	session := &mcpSession{
		tenantID: tenantID, orgID: orgID,
		userEmail: mcpClientPseudoIdentityPrefix + "legacy-client",
		clientID:  "legacy-client",
	}

	m := runCheckPolicy(t, session, checkPolicyArgs("please read the "+segTestMarker+" for Q3"))
	if allowed, _ := m["allowed"].(bool); !allowed {
		t.Fatalf("with static detection disabled no segment-scoped row can fire, so the gate must not deny; got %+v", m)
	}
}

// TestMCPToolCheckPolicy_NilResolver_OrgOnlyDoesNotSuppressOrgTierPolicy
// covers the nil-resolver / no-SCIM-configured case for a VALIDATED session:
// resolution must legitimately proceed org-only (never a failure), the
// segment-scoped policy must NOT enforce, and - the over-enforcement
// regression R3 is told to hunt for - a NON-segment-scoped (org-tier,
// segment_id IS NULL) policy must still enforce normally.
func TestMCPToolCheckPolicy_NilResolver_OrgOnlyDoesNotSuppressOrgTierPolicy(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)
	ResetFleetSegmentResolverForTest()

	const tenantID, orgID, email = "mcp-seg-orgonly-tenant", "mcp-seg-orgonly-org", "frank@corp.example"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)

	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: email, userID: email, userRole: "developer", clientID: "seg-mcp-client"}
	session.identityInputs.tokenResolvedIdentity = true

	t.Run("segment-scoped policy does not enforce (no resolver)", func(t *testing.T) {
		m := runCheckPolicy(t, session, checkPolicyArgs("please read the "+segTestMarker+" for Q3"))
		if allowed, _ := m["allowed"].(bool); !allowed {
			t.Fatalf("expected org-only (no resolver) NOT to enforce a segment-scoped policy, got %+v", m)
		}
	})

	t.Run("org-tier control policy still enforces", func(t *testing.T) {
		m := runCheckPolicy(t, session, checkPolicyArgs("this query contains "+orgTestMarker+" data"))
		if allowed, _ := m["allowed"].(bool); allowed {
			t.Fatalf("over-enforcement regression: a non-segment-scoped org-tier policy must still enforce when Segments is nil, got %+v", m)
		}
	})
}

// --- mcpToolCheckOutput (response phase): executed enforcement ---
//
// R3 BLOCKER 2: before this round the response half had ZERO executed proof
// that its segmentIDs argument reached evaluation - mutating it to nil at the
// evaluateOutputPolicies call compiled and left the whole platform/agent
// suite green, because the only coverage was fail-closed paths that return
// BEFORE the evaluator. The member/non-member pair below is the mutation
// target: nil-ing that argument makes the member case allow, so the pair goes
// red.

// checkOutputArgs is the minimal tools/call argument map for check_output.
func checkOutputArgs(message string) map[string]interface{} {
	return map[string]interface{}{"connector_type": "postgres", "message": message}
}

// TestMCPToolCheckOutput_SegmentMemberAndNonMember_ResponsePolicyEnforced is
// the executed proof for the response phase: one segment-scoped
// response-phase policy, two callers, opposite verdicts, with the ONLY
// difference being the resolved segment set that mcpToolCheckOutput passes
// into evaluateOutputPolicies.
func TestMCPToolCheckOutput_SegmentMemberAndNonMember_ResponsePolicyEnforced(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)
	withSensitiveDataBlockPosture(t)

	const tenantID, orgID = "mcp-out-seg-tenant", "mcp-out-seg-org"
	installSharedEngineWithSegmentScopedResponsePolicy(t, "finance", tenantID)

	newSession := func(email string) *mcpSession {
		s := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: email, userID: email, userRole: "developer", clientID: "seg-mcp-client"}
		s.identityInputs.tokenResolvedIdentity = true
		return s
	}

	t.Run("member is blocked by the segment-scoped response policy", func(t *testing.T) {
		withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
			Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
		}})
		m := runCheckOutput(t, newSession("carol@corp.example"), checkOutputArgs("here is the "+segRespMarker+" extract you asked for"))
		if allowed, _ := m["allowed"].(bool); allowed {
			t.Fatalf("#3430 response phase: expected a segment MEMBER's response to be withheld, got %+v", m)
		}
	})

	t.Run("non-member is not blocked by it", func(t *testing.T) {
		withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
			Segments: []sharedidentity.Segment{{ID: "engineering", DisplayName: "Engineering"}},
		}})
		m := runCheckOutput(t, newSession("dave@corp.example"), checkOutputArgs("here is the "+segRespMarker+" extract you asked for"))
		if allowed, _ := m["allowed"].(bool); !allowed {
			t.Fatalf("#3266/#3430 response phase: a member of a DIFFERENT segment must not be blocked, got %+v", m)
		}
	})
}

// TestMCPToolCheckOutput_SegmentResolutionError_FailsClosedAndAudited mirrors
// the request-phase fail-closed proof for check_output: a resolver error
// must withhold the response before evaluateOutputPolicies ever runs, and
// must be audited.
func TestMCPToolCheckOutput_SegmentResolutionError_FailsClosedAndAudited(t *testing.T) {
	fake := &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}
	withFleetSegmentResolver(t, fake)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	origUsageDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origUsageDB })
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	session := &mcpSession{tenantID: "seg-fc-tenant", orgID: "seg-fc-org", userEmail: "erin@corp.example", userID: "erin@corp.example", userRole: "developer", clientID: "seg-mcp-client"}
	session.identityInputs.tokenResolvedIdentity = true

	m := runCheckOutput(t, session, checkOutputArgs("totally benign output"))
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("#3293: a segment-resolution failure must withhold the response, got %+v", m)
	}
	const wantReason = "segment resolution unavailable - response withheld (fail-closed, ADR-060 #2989)"
	if got, _ := m["block_reason"].(string); got != wantReason {
		t.Fatalf("block_reason = %q, want %q", got, wantReason)
	}
	if got, _ := m["blocked_by"].(string); got != mcpSegmentResolutionFailedPolicyID {
		t.Fatalf("blocked_by = %q, want %q", got, mcpSegmentResolutionFailedPolicyID)
	}
	if c := fake.callCount(); c != 1 {
		t.Fatalf("expected the segment resolver to be called exactly once, got %d", c)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("fail-closed withhold did not emit the canonical audit_logs row: %v", err)
	}
}

// TestMCPToolCheckOutput_SameHumanDropsToken_Denied is the response-phase
// twin of the R3 BLOCKER 1 proof: the response half must not be evadable by
// omitting the same header either.
func TestMCPToolCheckOutput_SameHumanDropsToken_Denied(t *testing.T) {
	withSensitiveDataBlockPosture(t)

	const tenantID, orgID = "mcp-out-notoken-tenant", "mcp-out-notoken-org"
	installSharedEngineWithSegmentScopedResponsePolicy(t, "finance", tenantID)
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance"}},
	}})

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()
	origUsageDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origUsageDB })
	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	session := &mcpSession{
		tenantID: tenantID, orgID: orgID,
		userEmail: mcpClientPseudoIdentityPrefix + "legacy-client",
		clientID:  "legacy-client",
	}

	m := runCheckOutput(t, session, checkOutputArgs("here is the "+segRespMarker+" extract"))
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Fatalf("R3 BLOCKER 1 (response phase): dropping X-User-Token must not switch segment enforcement off, got %+v", m)
	}
	if got, _ := m["blocked_by"].(string); got != mcpSegmentIdentityUnresolvedPolicyID {
		t.Fatalf("blocked_by = %q, want %q", got, mcpSegmentIdentityUnresolvedPolicyID)
	}
	const wantReason = "segment membership indeterminate for a caller with no validated per-user token - response withheld (fail-closed, ADR-060 #3430)"
	if got, _ := m["block_reason"].(string); got != wantReason {
		t.Fatalf("block_reason = %q, want %q", got, wantReason)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the identity-unresolved withhold did not emit the canonical audit_logs row: %v", err)
	}
}

// TestMCPToolCheckOutput_NoPerUserToken_NoSegmentScopedPolicy_Unaffected is
// the response-phase compatibility control.
func TestMCPToolCheckOutput_NoPerUserToken_NoSegmentScopedPolicy_Unaffected(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)

	const tenantID, orgID = "mcp-out-clean-tenant", "mcp-out-clean-org"
	installSharedEngineWithOrgTierPolicyOnly(t, tenantID, orgTestMarker)
	fake := &fakeSegmentResolver{}
	withFleetSegmentResolver(t, fake)

	session := &mcpSession{
		tenantID: tenantID, orgID: orgID,
		userEmail: mcpClientPseudoIdentityPrefix + "legacy-client",
		clientID:  "legacy-client",
	}

	m := runCheckOutput(t, session, checkOutputArgs("some benign output"))
	if allowed, _ := m["allowed"].(bool); !allowed {
		t.Fatalf("expected allow with no segment-scoped policy in scope, got %+v", m)
	}
	if c := fake.callCount(); c != 0 {
		t.Fatalf("resolver must never be consulted for a session with no per-user principal; callCount=%d", c)
	}
}

// TestMCPToolCheckOutput_DetectionDisabled_IndeterminateIdentityAllowed pins
// the pairing between mcpToolCheckOutput's own detection-gate expression and
// evaluateOutputPolicies' detectionGate for an isGateway caller.
func TestMCPToolCheckOutput_DetectionDisabled_IndeterminateIdentityAllowed(t *testing.T) {
	setupMCPSegmentEnforcementTest(t)
	withDetectionDisabled(t)

	const tenantID, orgID = "mcp-out-nodetect-tenant", "mcp-out-nodetect-org"
	installSharedEngineWithSegmentScopedResponsePolicy(t, "finance", tenantID)
	withFleetSegmentResolver(t, &fakeSegmentResolver{})

	session := &mcpSession{
		tenantID: tenantID, orgID: orgID,
		userEmail: mcpClientPseudoIdentityPrefix + "legacy-client",
		clientID:  "legacy-client",
	}

	m := runCheckOutput(t, session, checkOutputArgs("here is the "+segRespMarker+" extract"))
	if allowed, _ := m["allowed"].(bool); !allowed {
		t.Fatalf("with static detection disabled no segment-scoped row can fire, so the gate must not deny; got %+v", m)
	}
}

// --- refusal-text contract ---

// TestMCPSegmentGateRefusal_RequestDenyMatchesTheOtherPlanes pins THIS plane's
// half of a three-plane contract: mcpSegmentGateRefusal's request-phase
// resolution-failure message must equal the literal below, em dash included,
// so the repo's no-dash-on-added-lines sweep cannot quietly reword this
// plane's copy of one operator-facing message.
//
// What it does NOT do: it never reads run.go or gateway_handlers.go. The
// constant below is a local copy of the string, not a reference to either
// site, so drifting run.go's literal leaves this test GREEN (verified by
// mutation). Cross-plane parity is enforced TRANSITIVELY, each plane pinning
// its own copy against a byte-identical literal:
//
//	run.go clientRequestHandler       -> run_shared_engine_segment_gate_test.go
//	gateway_handlers.go pre-check     -> gateway_precheck_segment_enforcement_test.go
//	mcp_identity.go (this plane)      -> this test
//
// A drift on any one plane is caught by that plane's own test. Nothing in the
// repo compares the three sites to each other directly.
func TestMCPSegmentGateRefusal_RequestDenyMatchesTheOtherPlanes(t *testing.T) {
	// Byte-identical to platform/agent/run.go's clientRequestHandler deny and
	// platform/agent/gateway_handlers.go's pre-check deny.
	const crossPlaneReason = "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"

	id, reason := mcpSegmentGateRefusal(mcpSegmentGateDenyResolutionFailed, mcpSegmentPhaseRequest)
	if reason != crossPlaneReason {
		t.Fatalf("request-phase resolution-failure reason = %q, want the cross-plane literal %q", reason, crossPlaneReason)
	}
	if id != mcpSegmentResolutionFailedPolicyID {
		t.Fatalf("guard id = %q, want %q", id, mcpSegmentResolutionFailedPolicyID)
	}

	// The response-phase text deliberately DIVERGES: check_output withholds a
	// response, it does not deny a request. Pinned so the divergence stays a
	// decision rather than a drift.
	_, respReason := mcpSegmentGateRefusal(mcpSegmentGateDenyResolutionFailed, mcpSegmentPhaseResponse)
	if respReason == crossPlaneReason {
		t.Fatal("the response-phase refusal must not claim a request was denied")
	}
}

// TestMCPSegmentGateRefusal_EveryDenyOutcomeHasAKnownGuardID: a blocked audit
// row whose policy id is unknown to the builtin guard table renders as a bare
// identifier in the portal and the compliance exports. Every id this gate can
// stamp must resolve to a display name.
func TestMCPSegmentGateRefusal_EveryDenyOutcomeHasAKnownGuardID(t *testing.T) {
	for _, outcome := range []mcpSegmentGateOutcome{
		mcpSegmentGateDenyResolutionFailed,
		mcpSegmentGateDenyIdentityUnresolved,
	} {
		for _, phase := range []mcpSegmentPhaseLabel{mcpSegmentPhaseRequest, mcpSegmentPhaseResponse} {
			id, reason := mcpSegmentGateRefusal(outcome, phase)
			if id == "" || reason == "" {
				t.Fatalf("outcome %v phase %v produced an empty id/reason", outcome, phase)
			}
			if _, known := builtinPolicyDisplayNames[id]; !known {
				t.Fatalf("guard id %q is not in builtinPolicyDisplayNames - its blocked rows would render unnamed", id)
			}
		}
	}
}

// TestZeroRegisteredValidators_TokenBearingCallerIsNotSilentlyServed is the
// defensive coverage for R3 BLOCKER 1's SECOND inertness path.
//
// The named risk: sharedidentity.ResolveToken returns (nil, nil) when the
// registry is empty, so a caller PRESENTING a valid token reaches
// authenticateMCPSession's header/pseudo-identity fallback with
// tokenResolvedIdentity false - identical to a caller who presented nothing.
// If the gate treated that as "proceed org-only", the whole fix would be
// inert for every caller in such a deployment.
//
// Measured rather than assumed, the deployment state itself turns out to be
// unreachable in an enterprise build: registerFleetValidators also registers
// the Path B OIDC verifier, whose two dependencies (NewDBOIDCConfigProvider,
// NewIdentityAttributeResolver) fail only on a nil db, so the registry is
// never empty; a presented token that no registered validator accepts takes
// ResolveToken's ERROR arm and authenticateMCPSession refuses with 401.
// runtime-e2e/3430_mcp_human_segment [26] drives exactly that on a live agent
// booted without a JWT secret and observes the 401. In a community build every
// constructor is Enterprise-only and the registry IS empty, but community
// callers never enter the AuthKindEnterprise branch that calls ResolveToken.
//
// This test therefore pins the two facts directly, without depending on a
// deployment able to produce them together: (1) an empty registry really does
// make ResolveToken swallow a presented token into (nil, nil), and (2) the
// session shape that produces is DENIED by the segment gate rather than served.
func TestZeroRegisteredValidators_TokenBearingCallerIsNotSilentlyServed(t *testing.T) {
	sharedidentity.ResetRegistryForTest()
	t.Cleanup(sharedidentity.ResetRegistryForTest)

	vid, err := sharedidentity.ResolveToken(context.Background(), "gate-novalidator-org", "a.presented.per-user.token")
	if err != nil {
		t.Fatalf("precondition changed: ResolveToken with an empty registry returned an error (%v); if this is now a refusal, the inertness path is closed upstream and this test should assert that instead", err)
	}
	if vid != nil {
		t.Fatalf("precondition changed: ResolveToken with an empty registry produced an identity: %+v", vid)
	}

	// The session authenticateMCPSession builds from that outcome: no
	// validated identity, so the client-scoped pseudo-identity and
	// tokenResolvedIdentity left false.
	const tenantID, orgID = "gate-novalidator-tenant", "gate-novalidator-org"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, segTestMarker, orgTestMarker)
	withFleetSegmentResolver(t, &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance"}},
	}})

	session := &mcpSession{tenantID: tenantID, orgID: orgID, userEmail: mcpClientPseudoIdentityPrefix + "fleet-client"}

	_, outcome := resolveMCPServerSegmentsForPolicy(context.Background(), session, sharedpolicy.PhaseRequest, true)
	if outcome != mcpSegmentGateDenyIdentityUnresolved {
		t.Fatalf("outcome = %v, want a deny - a token-bearing caller in a validator-less process must not be served with segment enforcement silently off", outcome)
	}
}
