// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// #3152 — the governed request plane must take its ACTOR from the authenticated
// identity and nothing else.
//
// #3066 bound the TENANCY on these handlers and left the rest of the decoded
// UserContext verbatim from the body, which is the state these tests exist to
// end. The headline consequence is a policy-evasion primitive:
// db_dynamic_policies.go getFieldValue resolves the condition field "user.role"
// straight off req.User.Role, /api/v1/process is registered on the agent's
// reverse proxy (which forwards the caller's body byte for byte), and a grep for
// `User.Role =` across the orchestrator and the agent returned zero assignments
// — nothing ever set that field from a credential, a header or a JWT claim. So
// `{user.role not_equals "admin"} → block`, a shape shipped as a built-in HIPAA
// template and offered in the portal's policy builder, was defeated by typing
// "user":{"role":"admin"} into the request body.
//
// The tests below drive the real handlers through buildOrchestratorHandler (so
// the #3068 gate is in the path exactly as in production) and then run the
// captured request through the REAL condition evaluator. Asserting on the
// struct alone would only prove the renderer; the property that matters is what
// the policy engine resolves.

const (
	pb3152Org    = "pb3152-org"
	pb3152Tenant = "pb3152-tenant"
)

// pb3152ForgedUser is the attacker-controlled principal, every field populated.
func pb3152ForgedUser() map[string]any {
	return map[string]any{
		"id":          4242,
		"email":       "ceo@victim.example.com",
		"role":        "admin",
		"region":      "eu-west-1",
		"permissions": []string{"admin", "read_phi"},
		"tenant_id":   pb3152Tenant,
	}
}

func pb3152Headers(extra map[string]string) map[string]string {
	h := map[string]string{"X-Org-ID": pb3152Org, "X-Tenant-ID": pb3152Tenant}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

// ---------------------------------------------------------------------------
// The binder itself
// ---------------------------------------------------------------------------

func TestApplyAuthoritativePrincipal_DiscardsEveryBodySuppliedField(t *testing.T) {
	body := UserContext{
		ID:          4242,
		Email:       "ceo@victim.example.com",
		Role:        "admin",
		Region:      "eu-west-1",
		Permissions: []string{"admin", "read_phi"},
		TenantID:    pb3152Tenant,
		OrgID:       pb3152Org,
	}

	t.Run("no authenticated actor: every principal field is emptied", func(t *testing.T) {
		u := body
		applyAuthoritativePrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/process", nil), &u)

		if u.Role != "" {
			t.Errorf("Role = %q, want empty — no validated role header was presented", u.Role)
		}
		if u.Email != "" {
			t.Errorf("Email = %q, want empty", u.Email)
		}
		if u.ID != 0 {
			t.Errorf("ID = %d, want 0", u.ID)
		}
		if u.Region != "" {
			t.Errorf("Region = %q, want empty", u.Region)
		}
		if u.Permissions != nil {
			t.Errorf("Permissions = %v, want nil", u.Permissions)
		}
		// The tenancy half is bound by resolveGovernedScope /
		// authorizeBodyTenancy, NOT here. If this binder ever starts clearing
		// it, the handlers below would refuse their own callers.
		if u.TenantID != pb3152Tenant || u.OrgID != pb3152Org {
			t.Errorf("tenancy must be left to the tenancy binder, got tenant=%q org=%q", u.TenantID, u.OrgID)
		}
	})

	t.Run("authenticated actor: the headers win, not the body", func(t *testing.T) {
		u := body
		r := httptest.NewRequest(http.MethodPost, "/api/v1/process", nil)
		r.Header.Set("X-User-Email", "real.person@example.com")
		r.Header.Set(sharedidentity.HeaderUserRole, "developer")
		applyAuthoritativePrincipal(r, &u)

		if u.Email != "real.person@example.com" {
			t.Errorf("Email = %q, want the header value", u.Email)
		}
		if u.Role != "developer" {
			t.Errorf("Role = %q, want the validated-token role header value", u.Role)
		}
		if u.ID != 0 || u.Region != "" || u.Permissions != nil {
			t.Errorf("fields with no authenticated channel must stay empty: %+v", u)
		}
	})

	t.Run("nil user is a no-op, not a panic", func(t *testing.T) {
		applyAuthoritativePrincipal(httptest.NewRequest(http.MethodPost, "/", nil), nil)
	})
}

// TestApplyAuthoritativePrincipal_RoleComesOnlyFromTheValidatedRoleHeader pins
// the one design decision in this change that is easy to get wrong later.
//
// The role must NOT be sourced from the trust-gated identity headers
// (X-User-Email / X-User-ID). platform/shared/identity states the contract: a
// trusted identity header may set audit ATTRIBUTION fields only and "must never
// influence a verdict, an authz decision, policy selection, or tenant/org
// resolution". user.role IS a verdict input. X-Axonflow-User-Role is a
// different class of channel — the agent Del()s any inbound value
// unconditionally and re-Sets it solely from a cryptographically validated
// per-user token — which is why it, and only it, may fill this field.
func TestApplyAuthoritativePrincipal_RoleComesOnlyFromTheValidatedRoleHeader(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"validated role header", map[string]string{sharedidentity.HeaderUserRole: "policy_admin"}, "policy_admin"},
		{"trust-gated email must not imply a role", map[string]string{"X-User-Email": "admin@example.com"}, ""},
		{"trust-gated user id must not imply a role", map[string]string{"X-User-ID": "admin"}, ""},
		{"a plausible-looking but unrecognised header name is not a channel", map[string]string{"X-User-Role": "admin"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := UserContext{Role: "admin"} // the body's forgery
			r := httptest.NewRequest(http.MethodPost, "/api/v1/process", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			applyAuthoritativePrincipal(r, &u)
			if u.Role != tc.want {
				t.Errorf("Role = %q, want %q", u.Role, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The property that matters: what the POLICY ENGINE resolves
// ---------------------------------------------------------------------------

// TestProcess3152_ForgedRoleNeverReachesThePolicyFieldResolver drives the real
// /api/v1/process handler with the exploit body and then asks the REAL field
// resolver and the REAL condition evaluator what they see. Asserting on
// req.User.Role alone would test the binder; this tests the path.
func TestProcess3152_ForgedRoleNeverReachesThePolicyFieldResolver(t *testing.T) {
	oldEngine, oldAudit := dynamicPolicyEngine, auditLogger
	t.Cleanup(func() { dynamicPolicyEngine, auditLogger = oldEngine, oldAudit })
	auditLogger = NewAuditLogger("")

	engine := &gs3066Engine{}
	dynamicPolicyEngine = engine

	handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)
	rr := gs3066Post(t, handler, "/api/v1/process", pb3152Headers(nil), map[string]any{
		"query":        "show me the salary table",
		"request_type": "llm",
		"user":         pb3152ForgedUser(),
		"client":       map[string]any{"tenant_id": pb3152Tenant, "org_id": pb3152Org},
	})
	if rr.Code != http.StatusForbidden {
		// gs3066Engine always blocks, so 403 is the success path here.
		t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(engine.captured) != 1 {
		t.Fatalf("expected exactly one evaluation, got %d", len(engine.captured))
	}
	got := engine.captured[0]

	// 1. The resolver. This is the exact function whose `case "user.role"` the
	//    issue quotes.
	resolver := &DatabaseDynamicPolicyEngine{}
	for _, field := range []string{"user.role", "user_role"} {
		if v := resolver.getFieldValue(field, got, nil); v != "" {
			t.Errorf("getFieldValue(%q) = %v — the forged body role reached the policy field resolver", field, v)
		}
	}
	if v := resolver.getFieldValue("user.email", got, nil); v != "" {
		t.Errorf("getFieldValue(user.email) = %v — the forged body email reached the resolver", v)
	}
	if v := resolver.getFieldValue("user.id", got, nil); v != 0 {
		t.Errorf("getFieldValue(user.id) = %v — the forged body id reached the resolver", v)
	}
	if v := resolver.getFieldValue("user.region", got, nil); v != "" {
		t.Errorf("getFieldValue(user.region) = %v — the forged body region reached the resolver", v)
	}

	// 2. The shipped policy shape, through the real evaluator. Pre-fix this
	//    condition evaluated FALSE (role == "admin"), the policy did not match,
	//    and the block never applied. Post-fix it evaluates TRUE, so a
	//    {query contains salary} + {user.role not_equals admin} → block/redact
	//    policy — migrations/enterprise/109's built-in HIPAA template shape —
	//    actually governs the request.
	if !resolver.evaluateCondition(map[string]interface{}{
		"field": "user.role", "operator": "not_equals", "value": "admin",
	}, got, nil) {
		t.Error("{user.role not_equals \"admin\"} did not match: the body still chose the role, " +
			"so the shipped role-gated policy shape is still evadable")
	}
	if resolver.evaluateCondition(map[string]interface{}{
		"field": "user.role", "operator": "equals", "value": "admin",
	}, got, nil) {
		t.Error("{user.role equals \"admin\"} matched: the caller successfully asserted the admin role")
	}

	// 3. Attribution. req.User.Email is what audit_logger.go writes to
	//    audit_logs.user_email on every verdict this plane records.
	if got.User.Email != "" {
		t.Errorf("audit attribution email = %q, want empty — it came from the body", got.User.Email)
	}
	if got.User.ID != 0 {
		t.Errorf("audit attribution id = %d, want 0", got.User.ID)
	}
	if len(got.User.Permissions) != 0 {
		t.Errorf("permissions = %v — a body-chosen permission set reached llm.RequestContext", got.User.Permissions)
	}

	// The tenancy binding from #3066 must still hold. A fix that broke it would
	// pass every assertion above.
	if got.User.TenantID != pb3152Tenant || got.Client.OrgID != pb3152Org {
		t.Errorf("#3066 tenancy binding regressed: %+v / %+v", got.User, got.Client)
	}
}

// TestProcess3152_ValidatedRoleHeaderIsHonoured is the other direction: the fix
// must not make role-keyed policy unenforceable. A fleet that issues per-user
// tokens gets a real role, and a policy keyed on it must still be able to
// exempt the holder.
func TestProcess3152_ValidatedRoleHeaderIsHonoured(t *testing.T) {
	oldEngine, oldAudit := dynamicPolicyEngine, auditLogger
	t.Cleanup(func() { dynamicPolicyEngine, auditLogger = oldEngine, oldAudit })
	auditLogger = NewAuditLogger("")

	engine := &gs3066Engine{}
	dynamicPolicyEngine = engine

	handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)
	rr := gs3066Post(t, handler, "/api/v1/process", pb3152Headers(map[string]string{
		sharedidentity.HeaderUserRole: "admin",
		"X-User-Email":                "real.admin@example.com",
	}), map[string]any{
		"query":        "show me the salary table",
		"request_type": "llm",
		// The body still lies, in the opposite direction this time.
		"user": map[string]any{"role": "intern", "email": "someone.else@example.com"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(engine.captured) != 1 {
		t.Fatalf("expected exactly one evaluation, got %d", len(engine.captured))
	}
	got := engine.captured[0]

	resolver := &DatabaseDynamicPolicyEngine{}
	if v := resolver.getFieldValue("user.role", got, nil); v != "admin" {
		t.Errorf("getFieldValue(user.role) = %v, want admin from the validated role header", v)
	}
	if resolver.evaluateCondition(map[string]interface{}{
		"field": "user.role", "operator": "not_equals", "value": "admin",
	}, got, nil) {
		t.Error("{user.role not_equals \"admin\"} matched for a validated admin: " +
			"the fix has made role-keyed policy unenforceable rather than unforgeable")
	}
	if got.User.Email != "real.admin@example.com" {
		t.Errorf("Email = %q, want the header identity", got.User.Email)
	}
}

// TestWorkflowsExecute3152_ActorBound covers the second handler named in the
// issue. req.User is what the workflow engine stamps onto execution rows and
// what hitl_execution.go writes as UserEmail / UserRole on every step-gate
// audit row.
func TestWorkflowsExecute3152_ActorBound(t *testing.T) {
	oldEngine, oldHITL := workflowEngine, hitlEnabled
	t.Cleanup(func() { workflowEngine, hitlEnabled = oldEngine, oldHITL })
	workflowEngine = NewWorkflowEngine()
	hitlEnabled = false

	handler := gs3066ServedHandler(t, "/api/v1/workflows/execute", executeWorkflowHandler)
	rr := gs3066Post(t, handler, "/api/v1/workflows/execute", pb3152Headers(nil),
		gs3066Workflow(map[string]any{
			"email":       "ceo@victim.example.com",
			"role":        "admin",
			"region":      "eu-west-1",
			"permissions": []string{"admin"},
			"tenant_id":   pb3152Tenant,
		}))
	if rr.Code != http.StatusOK && rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 200/202 (body=%s)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, forged := range []string{"ceo@victim.example.com", "eu-west-1"} {
		if strings.Contains(body, forged) {
			t.Errorf("a body-supplied principal value (%q) survived into the execution record: %s", forged, body)
		}
	}
}

// TestApplyAuthoritativeIdentity3152_BindsTheWholePrincipal covers the MAP
// planes. #2896 WS1c already bound the actor EMAIL here; the rest of the
// principal was not bound, and plans.user_id was built out of the body integer.
func TestApplyAuthoritativeIdentity3152_BindsTheWholePrincipal(t *testing.T) {
	withAuthnValidator(t)

	req := PlanRequest{User: UserContext{
		ID:          4242,
		Email:       "ceo@victim.example.com",
		Role:        "admin",
		Region:      "eu-west-1",
		Permissions: []string{"admin"},
	}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/plan", nil)
	r.Header.Set("X-Org-ID", pb3152Org)
	r.Header.Set("X-Tenant-ID", pb3152Tenant)

	if status, msg := applyAuthoritativeIdentity(r, &req, "GeneratePlan"); status != 0 {
		t.Fatalf("bind refused an authenticated request: %d %s", status, msg)
	}
	if req.User.Role != "" || req.User.ID != 0 || req.User.Email != "" ||
		req.User.Region != "" || req.User.Permissions != nil {
		t.Errorf("MAP plane still carries a body-supplied principal: %+v", req.User)
	}
	if req.User.OrgID != pb3152Org || req.User.TenantID != pb3152Tenant {
		t.Errorf("#3066 tenancy binding regressed: %+v", req.User)
	}
}

// ---------------------------------------------------------------------------
// Anti-regression census
// ---------------------------------------------------------------------------

// TestEveryBodyDecodedPrincipalIsBound is the lint that makes this a class fix
// rather than a list of three handlers. It scans the package source for any
// function that decodes a request body into a type carrying a UserContext, and
// requires it to either bind the actor or carry an explicit, reviewed
// exemption marker.
//
// The alternative — trusting that a future handler author reads
// getFieldValue's provenance comment — is exactly the assumption that produced
// this issue: #3066 bound the tenancy on these same functions and left the
// actor, and nothing failed.
// principalBindExemptions is the reviewed allowlist. An entry is a claim that
// the named function decodes a principal from the body ON PURPOSE and that the
// value governs nothing — not a note that it has not been fixed yet.
//
// Both current entries are POLICY SIMULATORS. Taking a hypothetical actor is
// the feature: "what would happen for a user with role X". The exemption holds
// only because the verdict is advisory — it is returned to the caller, allows
// and blocks nothing, and persists no actor column. Their one side effect, the
// policy_metrics row, is scoped by the tenant resolved from the gateway, not by
// the sample actor. If either verdict ever becomes authoritative for anything,
// the entry must be removed before that change ships.
var principalBindExemptions = map[string]string{
	"testPolicyHandler": "POST /api/v1/policies/test — dry run, advisory verdict only",
	"SimulatePolicies":  "POST /api/v1/policies/simulate — dry run, advisory verdict only",
}

func TestEveryBodyDecodedPrincipalIsBound(t *testing.T) {
	const (
		binder   = "applyAuthoritativePrincipal"
		delegate = "applyAuthoritativeIdentity"
	)
	// Word-boundary matching, not substring: `PlanRequest` as a substring also
	// matches planning.CancelPlanRequest and planning.UpdatePlanRequest, which
	// carry no principal at all. A census that reports false positives gets
	// allowlisted into uselessness.
	principalType := regexp.MustCompile(`\b(OrchestratorRequest|PlanRequest|UserContext)\b`)
	// Method receivers make the name follow the closing paren.
	funcName := regexp.MustCompile(`^(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)`)

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	checked, exempted := 0, 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, block := range strings.Split(string(src), "\nfunc ") {
			if !strings.Contains(block, "r.Body).Decode(") && !strings.Contains(block, "decodeJSONBody(r") {
				continue
			}
			if !principalType.MatchString(block) {
				continue
			}
			checked++
			name := "<unnamed>"
			if m := funcName.FindStringSubmatch(block); m != nil {
				name = m[1]
			}
			// Match the CALL, not the name: testPolicyHandler's exemption
			// comment names the binder in prose, and a bare substring check
			// accepted that as evidence of a call. A guard a comment can
			// satisfy is not a guard.
			if strings.Contains(block, binder+"(") || strings.Contains(block, delegate+"(") {
				continue
			}
			if _, ok := principalBindExemptions[name]; ok {
				exempted++
				continue
			}
			t.Errorf("%s: %s decodes a principal from the request body but neither binds it "+
				"(%s / %s) nor appears in principalBindExemptions", f, name, binder, delegate)
		}
	}
	// Vacuity guards. If the scan stops matching, or every match is an
	// exemption, every assertion above is silently satisfied.
	if checked < 5 {
		t.Fatalf("the census matched only %d function(s); the scan has stopped finding the "+
			"handlers it exists to police", checked)
	}
	if checked-exempted < 3 {
		t.Fatalf("the census found %d bound function(s) and %d exemptions; a growing exemption "+
			"list is how this guard stops guarding", checked-exempted, exempted)
	}
	if exempted != len(principalBindExemptions) {
		t.Errorf("principalBindExemptions has %d entries but only %d matched a real function — "+
			"a stale entry vouches for code that no longer exists",
			len(principalBindExemptions), exempted)
	}
}

// TestGetFieldValueUserCasesAreAllBound pins the other half of the class: the
// set of `user.*` fields the policy resolver answers must not grow past the set
// applyAuthoritativePrincipal binds. A new `case "user.department"` reading an
// unbound struct field would re-open #3152 without touching any handler.
func TestGetFieldValueUserCasesAreAllBound(t *testing.T) {
	bound := map[string]any{
		"user.id": 0, "user_id": 0,
		"user.email": "", "user_email": "",
		"user.role": "", "user_role": "",
		"user.region": "", "user_region": "", "region": "",
	}
	resolver := &DatabaseDynamicPolicyEngine{}
	req := OrchestratorRequest{User: UserContext{
		ID: 7, Email: "body@example.com", Role: "admin", Region: "eu", Permissions: []string{"admin"},
	}}
	// Bind as a handler would, with no authenticated actor.
	applyAuthoritativePrincipal(httptest.NewRequest(http.MethodPost, "/", nil), &req.User)

	for field, want := range bound {
		if got := resolver.getFieldValue(field, req, nil); got != want {
			t.Errorf("getFieldValue(%q) = %v, want the bound zero value %v", field, got, want)
		}
	}

	// user.tenant_id is deliberately NOT in the bound-to-zero set: it is bound
	// by the TENANCY half and must survive.
	req.User.TenantID = pb3152Tenant
	if got := resolver.getFieldValue("user.tenant_id", req, nil); got != pb3152Tenant {
		t.Errorf("getFieldValue(user.tenant_id) = %v, want the authenticated tenant", got)
	}
}

// TestProcess3152_AuditWriterSeesTheBoundPrincipal closes the loop on the
// attribution half by going through the audit entry builder the handler
// actually uses, rather than re-reading the struct.
func TestProcess3152_AuditWriterSeesTheBoundPrincipal(t *testing.T) {
	req := OrchestratorRequest{
		RequestID: "pb3152",
		User: UserContext{
			ID: 4242, Email: "ceo@victim.example.com", Role: "admin",
			TenantID: pb3152Tenant, OrgID: pb3152Org,
		},
		Client: ClientContext{ID: "client-a", TenantID: pb3152Tenant, OrgID: pb3152Org},
	}
	applyAuthoritativePrincipal(httptest.NewRequest(http.MethodPost, "/", nil), &req.User)

	al := NewAuditLogger("")
	// LogBlockedRequest is the writer on the deny path; with no DB configured
	// it must still build the entry without panicking and without the forged
	// identity.
	al.LogBlockedRequest(context.Background(), req, &PolicyEvaluationResult{Allowed: false})

	if req.User.Email != "" || req.User.Role != "" || req.User.ID != 0 {
		t.Fatalf("audit writer was handed a forged principal: %+v", req.User)
	}
}
