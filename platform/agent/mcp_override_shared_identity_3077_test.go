// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3077 — the MCP-server plane's override refusal must name only causes it can
// observe, and must not suggest a remedy that cannot help the caller.
//
// The refusal itself is correct and stays: a session attributed to the
// client-shared pseudo-identity has no person behind it, and an ADR-044
// override held by it would flip a deny for every caller on that credential
// (#2896). What was wrong was the sentence. It told EVERY caller to
// "set AXONFLOW_TRUST_IDENTITY_HEADERS=true", including the deployment that had
// already set it — for whom flipping an already-true flag changes nothing. That
// is the same confidently-wrong-diagnosis defect R3 caught on #3062/#3069, one
// plane over, and acting on the advice is a security-posture relaxation that
// fixes nothing.
//
// EVERY TEST IN THIS FILE ENTERS AT THE REAL ENTRY POINT. The session is built
// by resolveMCPSession from a real *http.Request with real headers, then handed
// to the real tool handler, because the fact under test — "what did the caller
// present?" — is decided during session resolution and is exactly the thing a
// hand-constructed mcpSession would let a test assert into existence. This file
// deliberately compiles against the PRE-FIX tree too, so its failures are
// assertion failures rather than a build error, which is what makes the
// before/after pair meaningful.

import (
	"net/http/httptest"
	"strings"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// sharedIdentitySessionFromRequest resolves a session the way production does
// and asserts the precondition every test here depends on: the identity really
// is a shared synthetic, so the refusal under test is the one being exercised.
func sharedIdentitySessionFromRequest(t *testing.T, headers map[string]string) *mcpSession {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	session := resolveMCPSession(r)
	if session == nil {
		t.Fatal("resolveMCPSession returned nil — community auth should succeed")
	}
	if !isClientSharedPseudoIdentity(session.userEmail) {
		t.Fatalf("precondition failed: session identity %q is not a shared synthetic, so this test would pass vacuously", session.userEmail)
	}
	return session
}

// validCreateArgs are complete on purpose: mcpToolCreateOverride validates its
// arguments BEFORE the identity guard, so incomplete args would short-circuit
// on "policy_id ... required" and never reach the branch under test.
func validCreateArgs() map[string]interface{} {
	return map[string]interface{}{
		"policy_id":       "pol-1",
		"policy_type":     "static",
		"override_reason": "debugging a false positive",
	}
}

func refuse(t *testing.T, session *mcpSession) string {
	t.Helper()
	result, err := mcpToolCreateOverride(session, validCreateArgs())
	if err == nil {
		t.Fatalf("create override must be refused for a shared identity; got result %+v", result)
	}
	return err.Error()
}

// THE #3077 CASE. The gate is ON and the caller presented no identity header,
// so the session still falls back to the shared pseudo-identity. Telling this
// caller to set AXONFLOW_TRUST_IDENTITY_HEADERS=true is advice that provably
// cannot help: it is already true. The message must say so and point at the
// thing that WOULD help.
//
// Pre-fix this fails: the old message ends with
// "...set AXONFLOW_TRUST_IDENTITY_HEADERS=true on the agent if your identity
// source is trusted" unconditionally.
func TestCreateOverride_SharedIdentity_GateAlreadyOn_DoesNotAdviseFlippingIt(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	msg := refuse(t, sharedIdentitySessionFromRequest(t, nil))

	if strings.Contains(msg, sharedidentity.EnvVar+"=true") {
		t.Errorf("the gate is already ON — the refusal must not tell the caller to set it; got: %s", msg)
	}
	// And it must positively say the setting is not the problem, or the reader
	// will try it anyway: it is the remedy every sibling message names.
	if !strings.Contains(msg, "will not help") {
		t.Errorf("refusal must state that changing the trust gate will not help here; got: %s", msg)
	}
	// The remedy that DOES apply on this plane.
	if !strings.Contains(msg, "X-User-Email") {
		t.Errorf("refusal must name the remedy that applies (send X-User-Email); got: %s", msg)
	}
}

// The gate is OFF and the caller DID present an identity header, so this agent
// is demonstrably the thing that dropped it. Here naming the gate is a
// diagnosis, not a guess, and the message must keep doing it.
func TestCreateOverride_SharedIdentity_GateOffWithHeader_DiagnosesTheGate(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)

	msg := refuse(t, sharedIdentitySessionFromRequest(t, map[string]string{
		identityHeaderUserEmail: "dev@corp.example",
	}))

	if !strings.Contains(msg, sharedidentity.EnvVar) {
		t.Errorf("gate off + header presented: refusal must name the gate; got: %s", msg)
	}
	if !strings.Contains(msg, "DID present") {
		t.Errorf("gate off + header presented: refusal must state the header was presented and removed; got: %s", msg)
	}
	if strings.Contains(msg, "will not help") {
		t.Errorf("gate off: setting the gate DOES help here — the refusal must not say otherwise; got: %s", msg)
	}
}

// Gate off and nothing presented: both changes are required, and naming only
// one sends the reader away half-fixed. Verified against the resolution path
// below by TestSharedIdentity_TheStatedRemedyActuallyWorks.
func TestCreateOverride_SharedIdentity_GateOffNoHeader_NamesBothHalves(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)

	msg := refuse(t, sharedIdentitySessionFromRequest(t, nil))

	for _, want := range []string{sharedidentity.EnvVar, "X-User-Email", "neither alone is enough"} {
		if !strings.Contains(msg, want) {
			t.Errorf("gate off + nothing presented: refusal must mention %q; got: %s", want, msg)
		}
	}
}

// The identity is decided when the session is CREATED and is immutable
// afterwards, so a caller who starts sending X-User-Email on a later call gets
// nothing. That trap is invisible from the client side, so the refusal has to
// name it.
func TestCreateOverride_SharedIdentity_SaysTheIdentityIsFixedAtSessionCreate(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	msg := refuse(t, sharedIdentitySessionFromRequest(t, nil))
	if !strings.Contains(msg, "OPENS the session") {
		t.Errorf("refusal must say the identity is fixed at session create; got: %s", msg)
	}
}

// The caller presented a value that IS one of the platform's reserved shared
// spellings, under a gate that is on. No configuration change fixes that, and
// "your header was dropped" would be false — it was honored, and it named a
// credential rather than a person.
func TestCreateOverride_SharedIdentity_PresentedReservedSpelling_SaysSo(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	msg := refuse(t, sharedIdentitySessionFromRequest(t, map[string]string{
		identityHeaderUserEmail: "svc-bot@axonflow.local",
	}))

	if !strings.Contains(msg, "reserved") {
		t.Errorf("a presented reserved spelling must be named as the cause; got: %s", msg)
	}
	if strings.Contains(msg, "did not survive sanitization") {
		t.Errorf("the value survived sanitization — the refusal must not claim otherwise; got: %s", msg)
	}
}

// Gate on, a header presented, nothing reserved, and still no identity: the one
// remaining observable explanation is that the value did not survive the
// agent's printable-only, length-bounded sanitizer.
func TestCreateOverride_SharedIdentity_UnsanitizableValue_NamesSanitization(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	msg := refuse(t, sharedIdentitySessionFromRequest(t, map[string]string{
		identityHeaderUserEmail: "\x01\x02\x03",
	}))

	if !strings.Contains(msg, "sanitization") {
		t.Errorf("an unusable presented value must be named as the cause; got: %s", msg)
	}
}

// REVOKE MUST NOT BE SHORT-CIRCUITED HERE. R3 finding, and this test is the
// tripwire for re-adding the guard.
//
// The obvious symmetry — "create refuses for a shared identity, so revoke
// should too" — is wrong, and wrong in the direction that breaks working
// deployments. resolveCallerReadScope (orchestrator read_scope.go) returns
// {TenantWide, AdminAuthority} as its FIRST statement in community mode, and
// {TenantWide} for community-saas over a validated proxy token, which
// mcpProxyToOrchestrator always presents alongside a non-blank X-Tenant-ID.
// With TenantWide set, revokeOverrideHandler SKIPS the ownership check and the
// revoke succeeds. A local guard would therefore delete a working capability —
// and since create is already refused in those modes, revoke is the only half
// of the lifecycle that works there at all.
//
// So the refusal must NOT fire locally: the tool has to reach the proxy and let
// the orchestrator decide under its own scope rules. Here that means a
// transport error (no orchestrator in a unit test), which is exactly the point —
// it got past the identity check.
func TestDeleteOverride_SharedIdentity_IsNotRefusedLocally(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	session := sharedIdentitySessionFromRequest(t, nil)
	_, err := mcpToolDeleteOverride(session, map[string]interface{}{"override_id": "ovr-1"})

	// It may fail downstream; what it must NOT do is refuse on identity grounds.
	if err != nil && strings.Contains(err.Error(), "scoped to an individual user") {
		t.Errorf("revoke must not short-circuit on a shared identity — community and community-saas grant tenant-wide scope and the orchestrator would have allowed it: %v", err)
	}
}

// The create/revoke asymmetry is deliberate and must stay legible: create
// refuses locally, revoke does not. If a future edit makes them symmetric in
// either direction, one of these two halves turns red.
func TestOverrideLifecycle_SharedIdentity_CreateRefusesRevokeProxies(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)

	session := sharedIdentitySessionFromRequest(t, nil)

	_, createErr := mcpToolCreateOverride(session, validCreateArgs())
	if createErr == nil || !strings.Contains(createErr.Error(), "scoped to an individual user") {
		t.Errorf("create must refuse locally for a shared identity: %v", createErr)
	}

	_, revokeErr := mcpToolDeleteOverride(session, map[string]interface{}{"override_id": "ovr-1"})
	if revokeErr != nil && strings.Contains(revokeErr.Error(), "scoped to an individual user") {
		t.Errorf("revoke must NOT refuse locally: %v", revokeErr)
	}
}

// R3 finding: presentedIsReserved was computed on the RAW header while the
// identity resolves from the SANITIZED one, so a value that survived
// sanitization into a reserved spelling was reported as one that did not
// survive it — a false sentence, which is the single outcome this whole change
// exists to prevent.
//
// "mcp\x7f-client:acme" loses the DEL rune to boundedAuditString and resolves to
// the reserved "mcp-client:acme". Pre-fix the message said "did not survive
// sanitization"; it must name the reserved spelling instead.
func TestCreateOverride_SharedIdentity_SanitizerReconstitutesAReservedSpelling(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	session := sharedIdentitySessionFromRequest(t, map[string]string{
		identityHeaderUserEmail: "mcp\x7f-client:acme",
	})
	if session.userEmail != "mcp-client:acme" {
		t.Fatalf("precondition: expected the sanitizer to yield the reserved spelling, got %q", session.userEmail)
	}

	msg := refuse(t, session)
	if strings.Contains(msg, "did not survive sanitization") {
		t.Errorf("the value DID survive sanitization — into a reserved spelling; the refusal must not claim otherwise: %s", msg)
	}
	if !strings.Contains(msg, "reserved") {
		t.Errorf("refusal must name the reserved spelling as the cause: %s", msg)
	}
}

// The same trap via the X-User-ID fallback: X-User-Email sanitizes away, so the
// identity resolves from X-User-ID. The census must follow the resolver's
// fall-back, not just look at the first header.
func TestCreateOverride_SharedIdentity_ReservedSpellingArrivesViaUserIDFallback(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	session := sharedIdentitySessionFromRequest(t, map[string]string{
		identityHeaderUserEmail: "\x01\x02",
		identityHeaderUserID:    "svc-bot@axonflow.local",
	})
	msg := refuse(t, session)
	if !strings.Contains(msg, "reserved") {
		t.Errorf("the identity resolved from X-User-ID, which IS reserved — the refusal must say so: %s", msg)
	}
}

// The FIRST of the two layers that keep a hostile identity out of a plugin's
// terminal: the agent's own sanitizer drops every non-printable rune before the
// value ever becomes session.userEmail.
//
// Scoped and named for what it actually proves. An earlier version claimed to
// assert the %q layer "which is what holds if the first ever changes" — it did
// not: boundedAuditString strips the ESC on the way in, so the assertion was
// true with or without %q and survived a %q→%s mutation. The %q layer is pinned
// where it can actually be exercised, in platform/shared/identity
// TestSharedIdentityRefusal_EscapesHostileIdentity, which feeds the builder
// directly.
func TestSharedIdentityRefusal_AgentSanitizerStripsControlRunesBeforeAttribution(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	session := sharedIdentitySessionFromRequest(t, map[string]string{
		identityHeaderUserEmail: "a\x1b[31mb@axonflow.local",
	})
	if strings.ContainsRune(session.userEmail, '\x1b') {
		t.Errorf("the agent attributed an identity containing a raw ESC: %q", session.userEmail)
	}
	if strings.ContainsRune(refuse(t, session), '\x1b') {
		t.Errorf("refusal emitted a raw ESC byte")
	}
}

// THE CACHED-SESSION PATH. handleMCPInitialize is the only site that produces a
// session reused across requests — the entire reason the identity-resolution
// inputs are captured at create rather than read at refusal time. Every other
// test here drives resolveMCPSession's cache-MISS branch, where the resolving
// request and the refusing request are the same one, so none of them can tell a
// correct implementation from one that captures nothing.
//
// R3 caught that: deleting `identityInputs: captureMCPIdentityInputs(r)` from
// handleMCPInitialize left the whole suite green. This test is the mutant's
// tripwire — with zero-valued inputs the message reports the gate as OFF while
// this deployment has it ON, and recommends setting it. That is the #3077 defect
// itself, emitted by the fix for it.
func TestCreateOverride_CachedSession_ReportsTheInputsCapturedAtInitialize(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	// initialize presenting NOTHING — this is the request that decides the
	// identity for the life of the session.
	initReq := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	rec := httptest.NewRecorder()
	handleMCPInitialize(rec, initReq, &jsonRPCRequest{ID: 1, Method: "initialize"})
	sessionID := rec.Header().Get(mcpSessionHeaderKey)
	if sessionID == "" {
		t.Fatalf("initialize returned no session id; body: %s", rec.Body.String())
	}

	// A LATER request on that session, now presenting an identity. It arrives
	// too late to matter, and the message must describe the initialize request.
	callReq := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	callReq.Header.Set(mcpSessionHeaderKey, sessionID)
	callReq.Header.Set(identityHeaderUserEmail, "dev@corp.example")
	session := resolveMCPSession(callReq)
	if session == nil {
		t.Fatal("resolveMCPSession did not return the cached session")
	}
	if !isClientSharedPseudoIdentity(session.userEmail) {
		t.Fatalf("precondition: the cached identity must still be the shared synthetic, got %q", session.userEmail)
	}

	msg := refuse(t, session)
	if !strings.Contains(msg, "presented no per-user identity header") {
		t.Errorf("the refusal must describe the request that RESOLVED the identity, not the later call: %s", msg)
	}
	// The discriminator. Inputs that were never captured are zero-valued, so a
	// gate-ON deployment would be reported as gate-OFF and told to set the flag.
	if strings.Contains(msg, sharedidentity.EnvVar+"=true") {
		t.Errorf("the gate is ON for this deployment — recommending it means the cached session carried no captured inputs: %s", msg)
	}
	if strings.Contains(msg, "dev@corp.example") {
		t.Errorf("the refusal echoed an identity that never influenced the session: %s", msg)
	}
}

// THE CONTROL. Every message above claims that presenting X-User-Email under an
// ON gate produces a real per-user identity on this plane. #3077 recorded that
// as UNVERIFIED and warned it might not hold, because the plane's fallback
// identity is the pseudo-identity itself. Assert it by execution: without this,
// the whole diagnostic could be confidently recommending something that does
// not work, which is the exact defect it is fixing.
func TestSharedIdentity_TheStatedRemedyActuallyWorks(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "true")
	resetIdentityWarnLatches(t)

	r := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	r.Header.Set(identityHeaderUserEmail, "dev@corp.example")
	session := resolveMCPSession(r)
	if session == nil {
		t.Fatal("resolveMCPSession returned nil")
	}
	if session.userEmail != "dev@corp.example" {
		t.Fatalf("gate on + X-User-Email must yield a per-user identity, got %q", session.userEmail)
	}
	if isClientSharedPseudoIdentity(session.userEmail) {
		t.Fatalf("the remedy the refusal recommends does not clear the refusal: %q still censuses as shared", session.userEmail)
	}
	// And the tool no longer refuses on identity grounds. It may still fail
	// downstream (no orchestrator in a unit test) — what must be gone is the
	// identity refusal.
	_, err := mcpToolCreateOverride(session, validCreateArgs())
	if err != nil && strings.Contains(err.Error(), "scoped to an individual user") {
		t.Errorf("the recommended remedy still hits the identity refusal: %v", err)
	}
}

// Wiring: X-User-Token is a remedy only where it can be resolved.
// authenticateMCPServerRequest runs token resolution under AuthKindEnterprise
// exclusively, so a community / community-saas / internal-service session must
// not be told to present one — that is the advice-that-cannot-help class again,
// just aimed at a different flag.
//
// The community half runs through the real resolution path. The enterprise half
// cannot (it needs a signed license), so it pins the field mapping on a session
// built by hand; the message content it produces is covered exhaustively by
// platform/shared/identity TestSharedIdentityRefusal_OffersTokenOnlyWhereItIsResolvable.
// The env gate is set to match the hand-built session's zero-valued inputs, so
// the assertion is not reading a message assembled from contradictory facts.
func TestSharedIdentityRefusal_TokenOfferedOnlyForEnterpriseSessions(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)

	community := refuse(t, sharedIdentitySessionFromRequest(t, nil))
	if strings.Contains(community, "Alternatively, present a validated per-user token") {
		t.Errorf("a community session cannot resolve a per-user token — it must not be offered one; got: %s", community)
	}

	enterprise := refuse(t, &mcpSession{
		userEmail: "mcp-client:acme",
		clientID:  "acme",
		authKind:  AuthKindEnterprise,
	})
	if !strings.Contains(enterprise, "Alternatively, present a validated per-user token") {
		t.Errorf("an enterprise session CAN resolve a per-user token — it must be offered; got: %s", enterprise)
	}
}

// --- The per-user TOKEN route (R3 round 3) -----------------------------------
//
// authenticateMCPSession resolves a validated per-user token under
// AuthKindEnterprise and RETURNS from that branch before it reads X-User-Email /
// X-User-ID at all. Nothing on the path censuses the token's subject — the
// portal mint() checks only that the address contains "@", and ResolveToken
// checks nothing — so a token minted for a reserved spelling validates and
// resolves to a SHARED synthetic that trips this refusal.
//
// Before the tokenResolvedIdentity capture, the switch then routed that caller
// on header state that had no bearing on the identity, producing the two
// messages below — both of which name a cause that did not apply, and one of
// which sends an operator to relax the identity-trust posture on every proxied
// route for a call that still fails. That is #3062, inside the change that
// closes #3062's class.
//
// These enter at the REAL entry point: a whitelisted enterprise Basic
// credential, a real per-user token, a validator registered through the shared
// seam, and resolveMCPSession doing the resolution.

// tokenSharedIdentitySession resolves a session whose identity came from a
// validated per-user token carrying a reserved spelling, and asserts that
// precondition so the test cannot pass vacuously.
func tokenSharedIdentitySession(t *testing.T, headers map[string]string) *mcpSession {
	t.Helper()
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		// A mintable, resolvable, SHARED subject: user_tokens.go mint()
		// validates only `email != "" && strings.Contains(email, "@")`.
		id: &sharedidentity.ValidatedIdentity{
			Email:     "svc@axonflow.local",
			Role:      "member",
			Validated: true,
			Source:    sharedidentity.ValidatorNameHS256,
		},
	})
	resetIdentityWarnLatches(t)

	r := enterpriseTokenRequest(t, "tok")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	session := resolveMCPSession(r)
	if session == nil {
		t.Fatal("resolveMCPSession returned nil — the enterprise whitelist credential should authenticate")
	}
	if session.userEmail != "svc@axonflow.local" {
		t.Fatalf("precondition: the TOKEN must have supplied the identity, got %q", session.userEmail)
	}
	if !isClientSharedPseudoIdentity(session.userEmail) {
		t.Fatalf("precondition: %q must census as a shared synthetic or this test is vacuous", session.userEmail)
	}
	return session
}

// tokenRefusalCommonAssertions holds for BOTH misrouted cases: the gate is never
// offered as an action (flipping it cannot change a decision the gate was never
// consulted for), the token is named as the cause, and the token is not offered
// back to the caller as an alternative — they presented one, and it is why they
// are here.
func tokenRefusalCommonAssertions(t *testing.T, msg string) {
	t.Helper()
	if strings.Contains(msg, sharedidentity.EnvVar+"=true") {
		t.Errorf("the identity came from a token — the gate was never consulted, so setting it cannot help and must not be advised; got: %s", msg)
	}
	if !strings.Contains(msg, "supplied by a validated per-user token") {
		t.Errorf("the refusal must name the token as the cause; got: %s", msg)
	}
	if strings.Contains(msg, "Alternatively, present a validated per-user token") {
		t.Errorf("the caller already presented a token and it is the cause — it must not be offered as the remedy; got: %s", msg)
	}
	if !strings.Contains(msg, "reserved") {
		t.Errorf("the refusal must say the token's own subject is a reserved spelling; got: %s", msg)
	}
}

// MISROUTED CASE 1. Gate OFF and a perfectly good X-User-Email presented. The
// agent removed nothing that mattered — the token won before the header was
// read — yet the pre-fix message said "this agent removed it ... Set
// AXONFLOW_TRUST_IDENTITY_HEADERS=true ... and open a new session". Acting on it
// relaxes the identity-trust posture on every proxied route and the call still
// fails.
func TestCreateOverride_TokenResolvedSharedIdentity_GateOffWithHeader_BlamesTheTokenNotTheGate(t *testing.T) {
	t.Setenv(sharedidentity.EnvVar, "false")
	session := tokenSharedIdentitySession(t, map[string]string{
		identityHeaderUserEmail: "dev@corp.example",
	})

	msg := refuse(t, session)
	tokenRefusalCommonAssertions(t, msg)
	if strings.Contains(msg, "DID present a usable per-user identity header") {
		t.Errorf("the header had no bearing on the identity — the refusal must not diagnose it as the cause; got: %s", msg)
	}
	if strings.Contains(msg, "this agent removed it") {
		t.Errorf("the agent removed nothing that mattered: the token was resolved before the header was read; got: %s", msg)
	}
}

// MISROUTED CASE 2. Gate ON and no header at all. The pre-fix message said
// "send X-User-Email on the request that OPENS the session" — the token
// overrides the header entirely, so doing that changes nothing.
func TestCreateOverride_TokenResolvedSharedIdentity_GateOnNoHeader_DoesNotPrescribeAHeader(t *testing.T) {
	t.Setenv(sharedidentity.EnvVar, "true")
	session := tokenSharedIdentitySession(t, nil)

	msg := refuse(t, session)
	tokenRefusalCommonAssertions(t, msg)
	if strings.Contains(msg, "send X-User-Email") {
		t.Errorf("a per-user token overrides the header, so sending one cannot help; got: %s", msg)
	}
	if strings.Contains(msg, "presented no per-user identity header") {
		t.Errorf("whether a header was presented is irrelevant here and must not be reported as the cause; got: %s", msg)
	}
}

// THE CONTROL for the branch above, in both directions. The token route is not
// refused per se — it is refused because THIS token's subject is shared. A token
// naming a real person must clear the refusal, or the remedy the new branch
// prescribes ("issue a per-user token whose subject is a real user address")
// would be the very advice-that-cannot-help this file forbids.
func TestCreateOverride_TokenResolvedRealIdentity_IsNotRefused(t *testing.T) {
	t.Setenv(sharedidentity.EnvVar, "false")
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id: &sharedidentity.ValidatedIdentity{
			Email: "alice@corp.example", Role: "member", Validated: true,
		},
	})
	resetIdentityWarnLatches(t)

	session := resolveMCPSession(enterpriseTokenRequest(t, "tok"))
	if session == nil {
		t.Fatal("resolveMCPSession returned nil")
	}
	if session.userEmail != "alice@corp.example" {
		t.Fatalf("the token must supply the identity, got %q", session.userEmail)
	}
	if _, err := mcpToolCreateOverride(session, validCreateArgs()); err != nil &&
		strings.Contains(err.Error(), "scoped to an individual user") {
		t.Errorf("a token naming a real person must clear the identity refusal: %v", err)
	}
}

// A HEADER-resolved session must NOT be described as token-resolved. Without
// this, "always set tokenResolvedIdentity" would pass every assertion above
// while silently deleting the four header diagnoses.
func TestCreateOverride_HeaderResolvedIdentity_IsNotReportedAsTokenResolved(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)

	session := sharedIdentitySessionFromRequest(t, map[string]string{
		identityHeaderUserEmail: "dev@corp.example",
	})
	msg := refuse(t, session)
	if strings.Contains(msg, "supplied by a validated per-user token") {
		t.Errorf("this identity came from the header route; the refusal must not blame a token: %s", msg)
	}
	if !strings.Contains(msg, sharedidentity.EnvVar+"=true") {
		t.Errorf("gate off + a usable header IS the gate's doing — the remedy must still be offered: %s", msg)
	}
}

// The other half of the same control: with the gate OFF the same header is
// dropped and the refusal is correct to fire. Without this pair, a message
// change could be "verified" against a code path that never refuses.
func TestSharedIdentity_GateOff_SameHeaderStillRefuses(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(sharedidentity.EnvVar, "false")
	resetIdentityWarnLatches(t)

	r := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	r.Header.Set(identityHeaderUserEmail, "dev@corp.example")
	session := resolveMCPSession(r)
	if session == nil {
		t.Fatal("resolveMCPSession returned nil")
	}
	if !isClientSharedPseudoIdentity(session.userEmail) {
		t.Fatalf("gate off must drop the header, got %q", session.userEmail)
	}
	if _, err := mcpToolCreateOverride(session, validCreateArgs()); err == nil {
		t.Fatal("gate off: the override must still be refused")
	}
}
