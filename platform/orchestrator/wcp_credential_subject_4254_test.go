// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// ONE CREDENTIAL SUBJECT FOR BOTH PLANES (#4254, R3 A-H1).
//
// The workflow step gate decides for the organization and client the agent
// authenticated: X-Org-ID and X-Client-ID, installed on the request context at
// the orchestrator's HTTP boundary, which is where the multi-agent plane reads
// them too. It used to decide for the step context's client id, which every
// caller filled from X-Tenant-ID; on the agent's internal-service hop that is the
// value the upstream service sent.

// agentCredentialHeaders is what the agent's proxy authentication sets.
func agentCredentialHeaders(orgID, tenantID, clientID string) http.Header {
	h := http.Header{}
	h.Set("X-Org-ID", orgID)
	h.Set("X-Tenant-ID", tenantID)
	h.Set("X-Client-ID", clientID)
	return h
}

// wcpSubjectContext is a request context carrying the credential subject the
// orchestrator's HTTP boundary installs, for seamStepContext's organization and
// client.
func wcpSubjectContext() context.Context {
	return withWCPPlaneSubject(context.Background(), headerCredentialSubject(agentCredentialHeaders("org-seam", "tenant-seam", "client-seam")))
}

// subjectOf evaluates a call's subject at now.
func subjectOf(t *testing.T, call anchoredenforcer.Call, now time.Time) anchoredenforcer.Subject {
	t.Helper()
	if call.Subject == nil {
		t.Fatal("the call carries no subject builder")
	}
	subject, ok := call.Subject(now)
	if !ok {
		t.Fatal("the call's subject could not be built")
	}
	return subject
}

func TestTheStepGateDecidesForTheClientHeaderNotTheTenant(t *testing.T) {
	d := withStepGateEngine(t, allowedStepVerdict())
	step := seamStepContext()
	step.ClientID = "tenant-seam" // what every caller filled from X-Tenant-ID
	ctx := withWCPPlaneSubject(context.Background(), headerCredentialSubject(agentCredentialHeaders("org-seam", "tenant-seam", "client-seam")))

	NewWCPPolicyAdapter().EvaluateStepGate(ctx, step)

	now := time.Now()
	subject := subjectOf(t, d.lastCall(t), now)
	want, err := credentialPrincipal("org-seam", "client-seam", now)
	if err != nil {
		t.Fatalf("credentialPrincipal: %v", err)
	}
	if !subject.Credential || !reflect.DeepEqual(subject.Principal, want) {
		t.Errorf("subject = %+v, want the X-Client-ID credential %+v", subject, want)
	}
	if tenant, _ := credentialPrincipal("org-seam", "tenant-seam", now); reflect.DeepEqual(subject.Principal, tenant) {
		t.Error("the step gate decided for the tenant id, not for the client the agent authenticated")
	}
}

// With no subject installed the step is refused as subject_unverifiable and
// never decided, exactly as the multi-agent plane refuses it.
func TestAStepWithNoCredentialSubjectIsRefusedAndNeverDecided(t *testing.T) {
	d := withStepGateEngine(t, allowedStepVerdict())

	ev := NewWCPPolicyAdapter().EvaluateStepGate(context.Background(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q with no subject, want block", ev.Decision)
	}
	if want := []string{anchoredenforcer.CauseSubjectUnverifiable}; !reflect.DeepEqual(ev.PolicyIDs, want) {
		t.Errorf("policy ids = %v, want %v", ev.PolicyIDs, want)
	}
	if !strings.HasPrefix(ev.Reason, anchoredenforcer.CauseSubjectUnverifiable+": ") {
		t.Errorf("reason = %q, want it to lead with %s", ev.Reason, anchoredenforcer.CauseSubjectUnverifiable)
	}
	if n := d.callCount(); n != 0 {
		t.Errorf("the enforcer was called %d times for a step with no subject, want never", n)
	}
}

// The orchestrator's HTTP boundary installs the subject from the headers the
// agent set.
func TestTheHTTPBoundaryInstallsTheCredentialSubject(t *testing.T) {
	var got func(now time.Time) (anchoredenforcer.Subject, bool)
	r := mux.NewRouter()
	r.Use(installWCPPlaneSubject)
	r.HandleFunc("/probe", func(_ http.ResponseWriter, req *http.Request) { got = wcpPlaneSubjectFrom(req.Context()) })

	req := httptest.NewRequest(http.MethodPost, "/probe", nil)
	req.Header = agentCredentialHeaders("org-edge", "tenant-edge", "client-edge")
	r.ServeHTTP(httptest.NewRecorder(), req)

	if got == nil {
		t.Fatal("no credential subject was installed on the request context")
	}
	now := time.Now()
	subject, ok := got(now)
	want, _ := credentialPrincipal("org-edge", "client-edge", now)
	if !ok || !reflect.DeepEqual(subject.Principal, want) {
		t.Errorf("installed subject = (%+v, %v), want the X-Client-ID credential", subject, ok)
	}
}

// resumeEnv is a workflow gated once for client-original in org-a, served
// through the orchestrator's HTTP boundary.
type resumeEnv struct {
	router   *mux.Router
	engine   *stepGateEnforcerDouble
	rows     *AuditLogger
	workflow string
}

func newResumeEnv(t *testing.T) resumeEnv {
	t.Helper()
	d := withStepGateEngine(t, allowedStepVerdict())
	svc := workflow_control.NewService(workflow_control.NewMockRepository(), NewWCPPolicyAdapter(), nil)
	rows := responsePlaneLogger()
	svc.SetAuditLogger(NewWCPAuditAdapter(rows))

	original := withWCPPlaneSubject(context.Background(), headerCredentialSubject(agentCredentialHeaders("org-a", "tenant-a", "client-original")))
	wf, err := svc.CreateWorkflow(original, &workflow_control.CreateWorkflowRequest{WorkflowName: "resume-subject"},
		"tenant-a", "org-a", "user-a", "client-original")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	if _, err := svc.StepGate(original, wf.WorkflowID, "step-1",
		&workflow_control.StepGateRequest{StepName: "step-1", StepType: workflow_control.StepTypeToolCall},
		"tenant-a", "org-a", "user-a", "client-original"); err != nil {
		t.Fatalf("StepGate: %v", err)
	}
	auditRowsWhere(rows, anyRow) // the create and first gate rows

	r := mux.NewRouter()
	r.Use(installWCPPlaneSubject)
	workflow_control.NewHandler(svc).RegisterEvaluationRoutes(r)
	return resumeEnv{router: r, engine: d, rows: rows, workflow: wf.WorkflowID}
}

func (e resumeEnv) resume(h http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+e.workflow+"/checkpoints/resume", nil)
	req.Header = h
	rr := httptest.NewRecorder()
	e.router.ServeHTTP(rr, req)
	return rr
}

// A checkpoint resume is decided for the RESUMING credential, the same rule as
// the gate route, and its row keeps the checkpoint's client as the actor.
func TestACheckpointResumeIsDecidedForTheResumingCredential(t *testing.T) {
	env := newResumeEnv(t)
	before := env.engine.callCount()

	rr := env.resume(agentCredentialHeaders("org-a", "tenant-a", "client-resumer"))

	if rr.Code != http.StatusOK {
		t.Fatalf("resume status = %d, body = %s; want 200", rr.Code, rr.Body.String())
	}
	if n := env.engine.callCount() - before; n != 1 {
		t.Fatalf("PREMISE: the resume decided %d times, want once", n)
	}
	now := time.Now()
	subject := subjectOf(t, env.engine.lastCall(t), now)
	want, _ := credentialPrincipal("org-a", "client-resumer", now)
	if !reflect.DeepEqual(subject.Principal, want) {
		t.Errorf("the resume was decided for %+v, want the resuming client %+v", subject.Principal, want)
	}
	row := oneAuditRowWhere(t, env.rows, "the resume's step_gate", func(e *AuditEntry) bool { return e.RequestType == "workflow_step_gate" })
	if row.ClientID != "client-original" {
		t.Errorf("the resume's row names actor client %q, want the checkpoint's client-original", row.ClientID)
	}
}

// The ownership check refuses a resume from another organization before any
// decision is made (workflow_control Service.ResumeFromLastCheckpoint,
// workflowBelongsTo).
func TestACheckpointResumeFromAnotherOrganizationIsRefusedBeforeAnyDecision(t *testing.T) {
	env := newResumeEnv(t)
	before := env.engine.callCount()

	rr := env.resume(agentCredentialHeaders("org-b", "tenant-b", "client-original"))

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, body = %s; want 404", rr.Code, rr.Body.String())
	}
	if n := env.engine.callCount() - before; n != 0 {
		t.Errorf("a foreign-organization resume was decided %d times, want never", n)
	}
}
