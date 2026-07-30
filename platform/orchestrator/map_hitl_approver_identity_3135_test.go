// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3135 — the MAP HITL approve/reject handlers took the approver from the
// REQUEST BODY, with the identity header as a mere fallback:
//
//	approvedBy := body.ApprovedBy                    // body wins
//	if approvedBy == "" { approvedBy = r.Header.Get("X-User-ID") }
//	if approvedBy == "" { approvedBy = "system" }
//
// That value is written to workflow_steps.approved_by and, through
// WorkflowAuditEntry.UserEmail, to audit_logs.user_email. An already
// authenticated caller could therefore name any approver they liked and that
// name is what the HITL trail recorded. It is an attribution / non-repudiation
// defect (ADR-044's subject), not an access-control one: the cross-tenant
// binding is separately covered by map_hitl_tenant_isolation_test.go (#3067)
// and by workflowBelongsTo on the WCP path.
//
// The assertions below are deliberately made at the STORAGE boundary, not on
// the JSON response: workflow_control.MockRepository.UpdateStepApproval writes
// exactly the field the Postgres repository writes to workflow_steps
// (`db:"approved_by"`), and the stubbed WorkflowAuditLogger receives exactly
// the entry the audit writer maps into audit_logs.user_email. Asserting the
// response body alone would prove only that the projector echoed something.
//
// Vacuity: restore either pre-fix line in map_hitl_adapter.go
// (`approvedBy := body.ApprovedBy` / `rejectedBy := body.RejectedBy`, with the
// header demoted to a fallback) and every "forged" case here fails, because
// the forged body name reaches the step row and the audit entry.

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/serviceauth"

	"github.com/gorilla/mux"
)

// mapHITLTestProxyToken mints an internal-service token that validates against
// the validator installProxyTokenValidator(t, proxyGuardTestSecret) installs.
// It takes no *testing.T so request builders that predate this change (e.g.
// approveRequest in map_hitl_tenant_isolation_test.go) can use it unchanged.
func mapHITLTestProxyToken() string {
	return serviceauth.GetInternalServiceToken(serviceauth.NewTokenGenerator(proxyGuardTestSecret, nil))
}

// recordingWorkflowAuditLogger captures the audit entries the WCP service emits
// so the audit_logs.user_email half of the defect is asserted, not assumed.
type recordingWorkflowAuditLogger struct {
	entries []*workflow_control.WorkflowAuditEntry
}

func (l *recordingWorkflowAuditLogger) LogWorkflowOperation(_ context.Context, entry *workflow_control.WorkflowAuditEntry) {
	l.entries = append(l.entries, entry)
}

func (l *recordingWorkflowAuditLogger) userEmailFor(op string) (string, bool) {
	for _, e := range l.entries {
		if e.Operation == op {
			return e.UserEmail, true
		}
	}
	return "", false
}

// mapApproverEnv is a WCP-backed MAP plan whose single step is pending
// approval — the path that actually writes workflow_steps.
type mapApproverEnv struct {
	repo    *workflow_control.MockRepository
	audit   *recordingWorkflowAuditLogger
	planID  string
	wfID    string
	stepID  string
	cleanup func()
}

func setupMAPApproverEnv(t *testing.T, caseName string) *mapApproverEnv {
	t.Helper()

	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origWCP := workflowControlService
	origEngine := hitlWorkflowEngine
	origEnabled := hitlEnabled
	origExecutor := mapWCPExecutor
	origPlanSvc := planService

	repo := workflow_control.NewMockRepository()
	audit := &recordingWorkflowAuditLogger{}
	svc := workflow_control.NewService(repo, &wcpParityPolicyEvaluator{}, nil)
	svc.SetAuditLogger(audit)

	workflowControlService = svc
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	planRepo := planning.NewMockRepository()
	planSvc := planning.NewService(planRepo)
	planService = planSvc
	mapWCPExecutor = NewMAPWCPExecutor(svc, planSvc)

	planID := "plan-" + caseName
	wfID := "wf-" + caseName
	stepID := "step-" + caseName

	metadataJSON, _ := json.Marshal(map[string]interface{}{
		"plan_id":        planID,
		"execution_mode": "confirm",
	})
	wf := &workflow_control.Workflow{
		WorkflowID:   wfID,
		WorkflowName: "map-confirm-" + planID,
		Source:       workflow_control.WorkflowSource("map"),
		Status:       workflow_control.WorkflowStatusInProgress,
		TenantID:     "tenant-1",
		OrgID:        "org-1",
		UserID:       "user-1",
		ClientID:     "client-1",
		Metadata:     metadataJSON,
	}
	if err := repo.Create(context.Background(), wf); err != nil {
		t.Fatalf("repo.Create: %v", err)
	}

	requireApproval := workflow_control.GateDecisionRequireApproval
	if _, err := svc.StepGate(context.Background(), wfID, stepID, &workflow_control.StepGateRequest{
		StepName:       "step-name",
		StepType:       workflow_control.StepTypeToolCall,
		IdempotencyKey: "idem-" + caseName,
		GateOverride:   &requireApproval,
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("svc.StepGate: %v", err)
	}

	return &mapApproverEnv{
		repo:   repo,
		audit:  audit,
		planID: planID,
		wfID:   wfID,
		stepID: stepID,
		cleanup: func() {
			workflowControlService = origWCP
			hitlEnabled = origEnabled
			hitlWorkflowEngine = origEngine
			mapWCPExecutor = origExecutor
			planService = origPlanSvc
		},
	}
}

// mapHITLRequest builds an authenticated (proxy-auth bearing) MAP approve or
// reject request. headers are applied last so a case can add or omit identity.
func mapHITLRequest(verb, planID, stepID, body string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/"+planID+"/steps/"+stepID+"/"+verb,
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": planID, "step_id": stepID})
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestMAPApprove_ForgedApprovedByNeverReachesWorkflowSteps is the headline
// assertion of #3135: the body names one person, the authenticated hop names
// another, and the STEP ROW must carry the authenticated one.
func TestMAPApprove_ForgedApprovedByNeverReachesWorkflowSteps(t *testing.T) {
	env := setupMAPApproverEnv(t, "forged_approve")
	defer env.cleanup()

	const forged = "cfo@victim.example"
	const real = "reviewer@example.com"

	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, mapHITLRequest("approve", env.planID, env.stepID,
		`{"approved_by":"`+forged+`","comment":"Approved after full audit review"}`,
		map[string]string{"X-User-ID": real}))

	if rr.Code != http.StatusOK {
		t.Fatalf("approve status = %d body=%s", rr.Code, rr.Body.String())
	}

	step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if step.ApprovedBy == forged {
		t.Fatalf("workflow_steps.approved_by = %q — the request BODY forged the approver", step.ApprovedBy)
	}
	if step.ApprovedBy != real {
		t.Fatalf("workflow_steps.approved_by = %q, want %q (the authenticated identity)", step.ApprovedBy, real)
	}

	email, ok := env.audit.userEmailFor("step_approved")
	if !ok {
		t.Fatal("no step_approved audit entry was emitted — the audit_logs half is unasserted")
	}
	if email == forged {
		t.Fatalf("audit_logs.user_email = %q — the request BODY forged the audited approver", email)
	}
	if email != real {
		t.Fatalf("audit_logs.user_email = %q, want %q", email, real)
	}

	// The wire response must agree with the row; a projector that echoed the
	// body while the row held the header would be its own defect.
	var resp workflow_control.StepGateHTTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	if resp.ApprovedBy != real {
		t.Fatalf("response approved_by = %q, want %q", resp.ApprovedBy, real)
	}
}

// TestMAPReject_ForgedRejectedByNeverReachesWorkflowSteps is the reject twin.
// The rejector lands in the same workflow_steps.approved_by column (the WCP
// service passes rejectedBy through UpdateStepApproval).
func TestMAPReject_ForgedRejectedByNeverReachesWorkflowSteps(t *testing.T) {
	env := setupMAPApproverEnv(t, "forged_reject")
	defer env.cleanup()

	const forged = "cfo@victim.example"
	const real = "reviewer@example.com"

	rr := httptest.NewRecorder()
	mapStepRejectHandler(rr, mapHITLRequest("reject", env.planID, env.stepID,
		`{"rejected_by":"`+forged+`","reason":"Rejected after full audit review"}`,
		map[string]string{"X-User-ID": real}))

	if rr.Code != http.StatusOK {
		t.Fatalf("reject status = %d body=%s", rr.Code, rr.Body.String())
	}

	step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if step.ApprovedBy == forged {
		t.Fatalf("workflow_steps.approved_by = %q — the request BODY forged the rejector", step.ApprovedBy)
	}
	if step.ApprovedBy != real {
		t.Fatalf("workflow_steps.approved_by = %q, want %q (the authenticated identity)", step.ApprovedBy, real)
	}

	email, ok := env.audit.userEmailFor("step_rejected")
	if !ok {
		t.Fatal("no step_rejected audit entry was emitted — the audit_logs half is unasserted")
	}
	if email != real {
		t.Fatalf("audit_logs.user_email = %q, want %q", email, real)
	}
}

// TestMAPApprove_BodyOnlyIdentityRecordsSystem covers the case with no header
// at all. Pre-fix the body name was adopted wholesale; the honest record of an
// unattributable approval is "system", and "system" is what an identity
// classifier can recognise as synthetic.
func TestMAPApprove_BodyOnlyIdentityRecordsSystem(t *testing.T) {
	env := setupMAPApproverEnv(t, "body_only")
	defer env.cleanup()

	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, mapHITLRequest("approve", env.planID, env.stepID,
		`{"approved_by":"ghost@attacker.example","comment":"Approved after full audit review"}`,
		nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("approve status = %d body=%s", rr.Code, rr.Body.String())
	}

	step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if step.ApprovedBy != "system" {
		t.Fatalf("workflow_steps.approved_by = %q, want \"system\" — an unattributable approval must not adopt a body-supplied name", step.ApprovedBy)
	}
}

// TestMAPApprove_FallsBackToUserEmailHeader pins the second header, matching
// workflow_control.Handler.getUserID. The portal proxy sets X-User-Email on
// every hop and X-User-ID only in its synthetic-identity fallback, so a plane
// that read X-User-ID alone would record "system" for real SSO users.
func TestMAPApprove_FallsBackToUserEmailHeader(t *testing.T) {
	env := setupMAPApproverEnv(t, "email_header")
	defer env.cleanup()

	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, mapHITLRequest("approve", env.planID, env.stepID,
		`{"comment":"Approved after full audit review"}`,
		map[string]string{"X-User-Email": "sso.user@example.com"}))

	if rr.Code != http.StatusOK {
		t.Fatalf("approve status = %d body=%s", rr.Code, rr.Body.String())
	}

	step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if step.ApprovedBy != "sso.user@example.com" {
		t.Fatalf("workflow_steps.approved_by = %q, want sso.user@example.com (X-User-Email fallback)", step.ApprovedBy)
	}
}

// TestMAPApprove_XUserIDOutranksXUserEmail pins the precedence against
// getUserID so the two planes cannot drift into stamping different strings for
// the same human.
func TestMAPApprove_XUserIDOutranksXUserEmail(t *testing.T) {
	env := setupMAPApproverEnv(t, "precedence")
	defer env.cleanup()

	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, mapHITLRequest("approve", env.planID, env.stepID,
		`{"comment":"Approved after full audit review"}`,
		map[string]string{
			"X-User-ID":    "primary@example.com",
			"X-User-Email": "secondary@example.com",
		}))

	if rr.Code != http.StatusOK {
		t.Fatalf("approve status = %d body=%s", rr.Code, rr.Body.String())
	}

	step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
	if err != nil {
		t.Fatalf("GetStep: %v", err)
	}
	if step.ApprovedBy != "primary@example.com" {
		t.Fatalf("workflow_steps.approved_by = %q, want primary@example.com (X-User-ID outranks X-User-Email, matching getUserID)", step.ApprovedBy)
	}
}

// TestMAPHITLActorIdentity_NeverParsesABody is the direct unit contract on the
// resolver: it is handed a request whose body names an approver and must still
// answer from the headers alone.
func TestMAPHITLActorIdentity_NeverParsesABody(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"no identity at all", nil, ""},
		{"user id", map[string]string{"X-User-ID": "a@example.com"}, "a@example.com"},
		{"user email only", map[string]string{"X-User-Email": "b@example.com"}, "b@example.com"},
		{"user id wins", map[string]string{"X-User-ID": "a@example.com", "X-User-Email": "b@example.com"}, "a@example.com"},
		{"whitespace-only header is no identity", map[string]string{"X-User-ID": "   "}, ""},
		{"whitespace user id falls through to email", map[string]string{"X-User-ID": "  ", "X-User-Email": "b@example.com"}, "b@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/plans/p/steps/s/approve",
				bytes.NewBufferString(`{"approved_by":"forged@attacker.example","rejected_by":"forged@attacker.example"}`))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := mapHITLActorIdentity(req); got != tc.want {
				t.Fatalf("mapHITLActorIdentity = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMAPHITL_ThroughTheServedHandlerStack drives the routes the way run.go
// serves them — gorilla/mux with the two routes registered as at run.go:652-653,
// wrapped in requireInternalProxyAuth (#3068) exactly as buildOrchestratorHandler
// does — rather than calling the handler function directly. Without this, both
// gates could be individually correct while the composition was not, and the
// handler's own gate could be mistaken for the only thing standing between the
// internet and an approval.
func TestMAPHITL_ThroughTheServedHandlerStack(t *testing.T) {
	newStack := func() http.Handler {
		r := mux.NewRouter()
		r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/approve", mapStepApproveHandler).Methods("POST")
		r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/reject", mapStepRejectHandler).Methods("POST")
		return requireInternalProxyAuth(r)
	}

	t.Run("unauthenticated approve is refused and writes nothing", func(t *testing.T) {
		env := setupMAPApproverEnv(t, "stack_unauth")
		defer env.cleanup()

		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/plans/"+env.planID+"/steps/"+env.stepID+"/approve",
			bytes.NewBufferString(`{"approved_by":"cfo@victim.example","comment":"Approved after full audit review"}`))
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		newStack().ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
		}
		step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
		if err != nil {
			t.Fatalf("GetStep: %v", err)
		}
		if step.ApprovedBy != "" {
			t.Fatalf("refused request wrote workflow_steps.approved_by = %q", step.ApprovedBy)
		}
	})

	t.Run("authenticated approve records the header identity", func(t *testing.T) {
		env := setupMAPApproverEnv(t, "stack_auth")
		defer env.cleanup()

		req := mapHITLRequest("approve", env.planID, env.stepID,
			`{"approved_by":"cfo@victim.example","comment":"Approved after full audit review"}`,
			map[string]string{"X-User-ID": "reviewer@example.com"})
		// Routed for real, so drop the mux.SetURLVars the direct-call helper
		// applied — the router must extract {id}/{step_id} itself.
		routed := httptest.NewRequest(http.MethodPost, req.URL.String(), req.Body)
		routed.Header = req.Header

		rr := httptest.NewRecorder()
		newStack().ServeHTTP(rr, routed)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
		if err != nil {
			t.Fatalf("GetStep: %v", err)
		}
		if step.ApprovedBy != "reviewer@example.com" {
			t.Fatalf("workflow_steps.approved_by = %q, want reviewer@example.com", step.ApprovedBy)
		}
	})
}

// TestMAPHITLHandlers_RequireAgentProxyAuth pins the gate itself. These are
// negative-auth cases: they must NOT carry a token, and the surrounding suites
// must not "helpfully" add one.
func TestMAPHITLHandlers_RequireAgentProxyAuth(t *testing.T) {
	verbs := []struct {
		verb    string
		handler func(http.ResponseWriter, *http.Request)
		body    string
	}{
		{"approve", mapStepApproveHandler, `{"comment":"Approved after full audit review"}`},
		{"reject", mapStepRejectHandler, `{"reason":"Rejected after full audit review"}`},
	}

	for _, v := range verbs {
		t.Run(v.verb+"/no token is refused", func(t *testing.T) {
			env := setupMAPApproverEnv(t, "gate_missing_"+v.verb)
			defer env.cleanup()

			req := mapHITLRequest(v.verb, env.planID, env.stepID, v.body, nil)
			req.Header.Del("X-Axonflow-Proxy-Auth") // the property under test

			rr := httptest.NewRecorder()
			v.handler(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("direct-to-orchestrator %s without proxy auth: status %d, want 403; body=%s",
					v.verb, rr.Code, rr.Body.String())
			}

			// And it was refused BEFORE touching the step.
			step, err := env.repo.GetStep(context.Background(), env.wfID, env.stepID)
			if err != nil {
				t.Fatalf("GetStep: %v", err)
			}
			if step.ApprovedBy != "" {
				t.Fatalf("refused request still wrote workflow_steps.approved_by = %q", step.ApprovedBy)
			}
		})

		t.Run(v.verb+"/forged token is refused", func(t *testing.T) {
			env := setupMAPApproverEnv(t, "gate_forged_"+v.verb)
			defer env.cleanup()

			req := mapHITLRequest(v.verb, env.planID, env.stepID, v.body, nil)
			req.Header.Set("X-Axonflow-Proxy-Auth",
				serviceauth.GetInternalServiceToken(serviceauth.NewTokenGenerator("a-different-secret-32-bytes-long!!", nil)))

			rr := httptest.NewRecorder()
			v.handler(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s with a token minted from the wrong secret: status %d, want 403; body=%s",
					v.verb, rr.Code, rr.Body.String())
			}
		})

		t.Run(v.verb+"/valid token proceeds", func(t *testing.T) {
			// Positive control: without this, the two cases above would pass
			// against a handler that 403s unconditionally.
			env := setupMAPApproverEnv(t, "gate_valid_"+v.verb)
			defer env.cleanup()

			rr := httptest.NewRecorder()
			v.handler(rr, mapHITLRequest(v.verb, env.planID, env.stepID, v.body,
				map[string]string{"X-User-ID": "reviewer@example.com"}))

			if rr.Code != http.StatusOK {
				t.Fatalf("%s with a valid proxy token: status %d, want 200; body=%s",
					v.verb, rr.Code, rr.Body.String())
			}
		})
	}
}
