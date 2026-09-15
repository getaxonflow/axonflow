// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
	sharedidentity "axonflow/platform/shared/identity"
)

// EVERY ANCHORED SEAM RECORDS THE DECISION IT MADE (PRD v11 §5.7).
//
// The WCP step gate's row, the multi-agent plane's step row (an allow included,
// one row per decision) and the blocked rows of /api/v1/process and plan execute
// carry the plane's own label and the engine's decision id as columns, and the
// engine, the subject type, the policy bundle and the decision id in
// policy_details, as the response plane's rows do. The step gate's answer carries
// the engine, the subject type and the bundle, and the plan-execute 403 carries
// the members /api/v1/process carries. Each member is asserted on its own.

// anchoredStampVerdict is v with every member the stamp records set.
func anchoredStampVerdict(v anchoredenforcer.Verdict, decisionID string) anchoredenforcer.Verdict {
	v.SubjectType = "Client"
	v.Act = &activation.Activation{PolicyBundle: "sha256:stamp-bundle"}
	if v.Decision != nil {
		v.Decision.DecisionID = decisionID
	}
	return v
}

// auditRowsWhere returns every row l queued that match selects, waiting briefly
// for at least one.
func auditRowsWhere(l *AuditLogger, match func(*AuditEntry) bool) []*AuditEntry {
	var found []*AuditEntry
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case e := <-l.auditQueue:
			if match(e) {
				found = append(found, e)
			}
			continue
		default:
		}
		if len(found) > 0 || time.Now().After(deadline) {
			return found
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func oneAuditRowWhere(t *testing.T, l *AuditLogger, what string, match func(*AuditEntry) bool) *AuditEntry {
	t.Helper()
	rows := auditRowsWhere(l, match)
	if len(rows) != 1 {
		t.Fatalf("%s rows = %d, want exactly one", what, len(rows))
	}
	return rows[0]
}

func anyRow(*AuditEntry) bool { return true }

var anchoredDetailMembers = []string{"engine", "subject_type", "policy_bundle", "decision_id"}

// assertAnchoredRow asserts the row records d, member by member.
func assertAnchoredRow(t *testing.T, what string, row *AuditEntry, d anchoredDecision) {
	t.Helper()
	if row.Plane != d.Plane {
		t.Errorf("%s: the plane column = %q, want %q", what, row.Plane, d.Plane)
	}
	if row.DecisionID != d.DecisionID {
		t.Errorf("%s: the decision_id column = %q, want the engine's %q", what, row.DecisionID, d.DecisionID)
	}
	want := map[string]string{"engine": d.Engine, "subject_type": d.SubjectType, "policy_bundle": d.PolicyBundle, "decision_id": d.DecisionID}
	for _, member := range anchoredDetailMembers {
		got, ok := row.PolicyDetails[member]
		if want[member] == "" {
			if ok {
				t.Errorf("%s: policy_details %s = %v, want it omitted", what, member, got)
			}
			continue
		}
		if !ok || got != want[member] {
			t.Errorf("%s: policy_details %s = %v (present %v), want %q", what, member, got, ok, want[member])
		}
	}
}

type anchoredRowWriter struct {
	name  string
	plane string
	write func(l *AuditLogger, d *anchoredDecision)
}

func anchoredRowWriters() []anchoredRowWriter {
	return []anchoredRowWriter{
		{name: "the wcp step_gate row", plane: "wcp", write: func(l *AuditLogger, d *anchoredDecision) {
			entry := &WorkflowAuditEntry{WorkflowID: "wf-stamp", WorkflowName: "stamp", Operation: "step_gate", Decision: "allow"}
			if d != nil {
				entry.Plane, entry.Engine, entry.SubjectType, entry.PolicyBundle, entry.EngineDecisionID = d.Plane, d.Engine, d.SubjectType, d.PolicyBundle, d.DecisionID
			}
			l.LogWorkflowOperation(context.Background(), entry)
		}},
		{name: "the map step_gate row", plane: "map", write: func(l *AuditLogger, d *anchoredDecision) {
			e := &HITLWorkflowEngine{}
			e.SetAuditLogger(l)
			e.auditStepGate(context.Background(), &HITLWorkflowExecution{WorkflowExecution: &WorkflowExecution{ID: "exec-stamp"}},
				"stamp", WorkflowStep{Name: "s", Type: "llm-call"}, &PolicyCheckResult{Allowed: true, Action: "allow", decided: d}, UserContext{OrgID: "org-stamp"})
		}},
		{name: "a route's blocked row", plane: "wcp", write: func(l *AuditLogger, d *anchoredDecision) {
			l.LogBlockedRequest(context.Background(), OrchestratorRequest{RequestID: "req-stamp", RequestType: "llm", Client: ClientContext{OrgID: "org-stamp"}},
				&PolicyEvaluationResult{Allowed: false}, d)
		}},
	}
}

func TestEveryAnchoredSeamRowCarriesThePlaneAndTheDecision(t *testing.T) {
	for _, w := range anchoredRowWriters() {
		t.Run(w.name, func(t *testing.T) {
			full := anchoredDecision{Plane: w.plane, Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client", PolicyBundle: "sha256:stamp", DecisionID: "dec-stamp"}

			l := responsePlaneLogger()
			d := full
			w.write(l, &d)
			assertAnchoredRow(t, "SET", oneAuditRowWhere(t, l, w.name, anyRow), full)

			// ABSENT: a decision no anchored seam recorded writes none of it.
			l = responsePlaneLogger()
			w.write(l, nil)
			assertAnchoredRow(t, "ABSENT", oneAuditRowWhere(t, l, w.name, anyRow), anchoredDecision{})

			// SET BUT EMPTY: each member left empty is omitted, and the others stay.
			for _, member := range []string{"plane", "engine", "subject_type", "policy_bundle", "decision_id"} {
				empty := full
				switch member {
				case "plane":
					empty.Plane = ""
				case "engine":
					empty.Engine = ""
				case "subject_type":
					empty.SubjectType = ""
				case "policy_bundle":
					empty.PolicyBundle = ""
				case "decision_id":
					empty.DecisionID = ""
				}
				l = responsePlaneLogger()
				d := empty
				w.write(l, &d)
				assertAnchoredRow(t, "EMPTY "+member, oneAuditRowWhere(t, l, w.name, anyRow), empty)
			}
		})
	}
}

// The step gate stamps its evaluation on every path: what the engine produced
// when it answered, and only the plane and the engine when the plane failed
// closed before it could.
func TestTheStepGateSeamRecordsTheAnchoredDecisionOnEveryPath(t *testing.T) {
	plain := anchoredDecision{Plane: "wcp", Engine: anchoredenforcer.EngineAnchored}
	decided := func(id string) anchoredDecision {
		return anchoredDecision{Plane: "wcp", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client", PolicyBundle: "sha256:stamp-bundle", DecisionID: id}
	}
	cases := []struct {
		name    string
		install func(t *testing.T)
		want    anchoredDecision
	}{
		{"an allow", func(t *testing.T) { withStepGateEngine(t, anchoredStampVerdict(allowedStepVerdict(), "dec-allow")) }, decided("dec-allow")},
		{"a hold", func(t *testing.T) { withStepGateEngine(t, anchoredStampVerdict(heldStepVerdict(), "dec-hold")) }, decided("dec-hold")},
		{"a deny", func(t *testing.T) {
			withStepGateEngine(t, anchoredStampVerdict(stepGateVerdict(contract.StateDeny, contract.ReasonExplicitConstraint,
				contract.Determining{MatchedConstraints: []string{"pol-a"}}), "dec-deny"))
		}, decided("dec-deny")},
		{"an unavailable verdict", func(t *testing.T) {
			withStepGateEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseActivation, SubjectType: "Client"})
		}, anchoredDecision{Plane: "wcp", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client"}},
		{"a refused subject", func(t *testing.T) {
			withStepGateEngine(t, anchoredenforcer.Verdict{Refusal: &sharedidentity.Admission{
				State: sharedidentity.AdmissionDeny, Reason: sharedidentity.ReasonUnknownRealm, Detail: "no realm admits this credential",
			}})
		}, plain},
		{"no enforcer", func(t *testing.T) {
			withStepGateEngine(t, anchoredStampVerdict(allowedStepVerdict(), "dec-unseen"))
			orchestratorEnforcerInstance.Store(nil)
		}, plain},
		{"a segment resolution outage", func(t *testing.T) {
			withStepGateEngine(t, anchoredStampVerdict(allowedStepVerdict(), "dec-unseen"))
			withStepGateFacts(t, false)
		}, plain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.install(t)
			ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())
			got := anchoredDecision{Plane: ev.Plane, Engine: ev.Engine, SubjectType: ev.SubjectType, PolicyBundle: ev.PolicyBundle, DecisionID: ev.EngineDecisionID}
			for member, pair := range map[string][2]string{
				"plane": {got.Plane, c.want.Plane}, "engine": {got.Engine, c.want.Engine}, "subject_type": {got.SubjectType, c.want.SubjectType},
				"policy_bundle": {got.PolicyBundle, c.want.PolicyBundle}, "engine decision id": {got.DecisionID, c.want.DecisionID},
			} {
				if pair[0] != pair[1] {
					t.Errorf("the evaluation's %s = %q, want %q", member, pair[0], pair[1])
				}
			}
		})
	}
}

// The adapter that hands the workflow service's rows to the audit logger copies
// every member of the anchored decision.
func TestTheWCPAuditAdapterCarriesTheAnchoredDecision(t *testing.T) {
	l := responsePlaneLogger()
	NewWCPAuditAdapter(l).LogWorkflowOperation(context.Background(), &workflow_control.WorkflowAuditEntry{
		WorkflowID: "wf-adapter", WorkflowName: "adapter", Operation: "step_gate", Decision: "allow",
		Plane: "wcp", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client", PolicyBundle: "sha256:adapter", EngineDecisionID: "dec-adapter",
	})
	row := oneAuditRowWhere(t, l, "the adapter's step_gate", anyRow)
	assertAnchoredRow(t, "adapter", row, anchoredDecision{Plane: "wcp", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client", PolicyBundle: "sha256:adapter", DecisionID: "dec-adapter"})
}

func isMAPStepGateRow(e *AuditEntry) bool { return e.RequestType == "workflow_step_gate" }

// An allowed multi-agent step writes one row, recorded allowed with its
// anchored decision under plane "map", and then runs.
func TestAnAllowedMAPStepIsRecordedOnceAndRuns(t *testing.T) {
	withMAPEngine(t, anchoredStampVerdict(allowedStepVerdict(), "dec-map-allow"))
	l := responsePlaneLogger()
	hitl, processor := mapHITLEngine(&recordingApprovalService{})
	hitl.SetAuditLogger(l)

	if _, err := hitl.ExecuteWithHITL(mapSubjectContext(), oneStepWorkflow(), map[string]interface{}{}, UserContext{OrgID: "org-map"}); err != nil {
		t.Fatalf("ExecuteWithHITL: %v", err)
	}
	if processor.ran != 1 {
		t.Errorf("the allowed step ran %d times, want once", processor.ran)
	}
	row := oneAuditRowWhere(t, l, "the allowed map step_gate", isMAPStepGateRow)
	if row.PolicyDecision != "allowed" {
		t.Errorf("policy_decision = %q, want allowed", row.PolicyDecision)
	}
	assertAnchoredRow(t, "allowed map step", row, anchoredDecision{Plane: "map", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client", PolicyBundle: "sha256:stamp-bundle", DecisionID: "dec-map-allow"})
}

// A withheld multi-agent step's row carries the plane and what the engine gave.
func TestAWithheldMAPStepRowCarriesTheMapPlane(t *testing.T) {
	withMAPEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseActivation, SubjectType: "Client"})
	l := responsePlaneLogger()
	hitl, processor := mapHITLEngine(&recordingApprovalService{})
	hitl.SetAuditLogger(l)

	_, _ = hitl.ExecuteWithHITL(mapSubjectContext(), oneStepWorkflow(), map[string]interface{}{}, UserContext{OrgID: "org-map"})
	if processor.ran != 0 {
		t.Errorf("the withheld step ran %d times, want never", processor.ran)
	}
	row := oneAuditRowWhere(t, l, "the withheld map step_gate", isMAPStepGateRow)
	if row.PolicyDecision != "blocked" {
		t.Errorf("policy_decision = %q, want blocked", row.PolicyDecision)
	}
	assertAnchoredRow(t, "withheld map step", row, anchoredDecision{Plane: "map", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client"})
}

// A route decision keeps the engine's decision id, and an unavailable verdict
// carries none.
func TestARouteDecisionCarriesTheEnginesDecisionID(t *testing.T) {
	withRouteRequestEngine(t, anchoredStampVerdict(routeDenyVerdict("pol-a"), "dec-route"))
	decision := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{Client: ClientContext{OrgID: "o"}}, processRouteAction)
	if decision.decisionID != "dec-route" {
		t.Errorf("decision id = %q, want the engine's dec-route", decision.decisionID)
	}
	got := *decision.anchoredDecision()
	want := anchoredDecision{Plane: "wcp", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client", PolicyBundle: "sha256:stamp-bundle", DecisionID: "dec-route"}
	if got != want {
		t.Errorf("the route's record = %+v, want %+v", got, want)
	}

	withRouteRequestEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseActivation})
	if id := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{Client: ClientContext{OrgID: "o"}}, processRouteAction).decisionID; id != "" {
		t.Errorf("an unavailable verdict carries decision id %q, want none", id)
	}
}

func isBlockedRow(e *AuditEntry) bool { return e.PolicyDecision == "blocked" }

// A refused plan's 403 carries the engine envelope /api/v1/process carries, and
// both routes' blocked rows record the anchored decision under plane "wcp".
func TestARouteRefusalCarriesTheEngineEnvelopeOnTheAnswerAndTheRow(t *testing.T) {
	want := anchoredDecision{Plane: "wcp", Engine: anchoredenforcer.EngineAnchored, SubjectType: "Client", PolicyBundle: "sha256:stamp-bundle"}

	t.Run("plan execute", func(t *testing.T) {
		previousPlans, previousWorkflow, previousAudit := planService, workflowEngine, auditLogger
		t.Cleanup(func() { planService, workflowEngine, auditLogger = previousPlans, previousWorkflow, previousAudit })
		repo := planning.NewMockRepository()
		if err := repo.SavePlan(context.Background(), &planning.Plan{
			TenantID: "tenant_1", PlanID: "plan_stamp_4254", Status: planning.PlanStatusPending, StepCount: 1,
			Query: "transfer the funds", Domain: "generic", OrgID: "org_1",
			WorkflowDefinition: json.RawMessage(`{"metadata":{"name":"test"},"spec":{"steps":[]}}`),
			ExpiresAt:          time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("save plan: %v", err)
		}
		planService = planning.NewService(repo)
		workflowEngine = NewWorkflowEngine()
		l := responsePlaneLogger()
		auditLogger = l
		withRouteRequestEngine(t, anchoredStampVerdict(heldStepVerdict(), "dec-plan"))
		withRecordingHITL(t)

		body, _ := json.Marshal(PlanRequest{Query: "run it", User: UserContext{ID: 1, Email: "user@example.com"}, Context: map[string]interface{}{"plan_id": "plan_stamp_4254"}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/execute", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org_1")
		req.Header.Set("X-Tenant-ID", "tenant_1")
		w := httptest.NewRecorder()
		executePlanHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
		}
		var wire map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &wire); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for member, value := range map[string]string{"engine": want.Engine, "subject_type": want.SubjectType, "policy_bundle": want.PolicyBundle, "verdict": routeRequestVerdictBlocked} {
			if got, ok := wire[member]; !ok || got != value {
				t.Errorf("the plan-execute 403's %s = %v (present %v), want %q", member, got, ok, value)
			}
		}
		planWant := want
		planWant.DecisionID = "dec-plan"
		assertAnchoredRow(t, "plan execute's blocked row", oneAuditRowWhere(t, l, "plan execute's blocked", isBlockedRow), planWant)
	})

	t.Run("process", func(t *testing.T) {
		previousAudit := auditLogger
		t.Cleanup(func() { auditLogger = previousAudit })
		l := responsePlaneLogger()
		auditLogger = l
		withRouteRequestEngine(t, anchoredStampVerdict(heldStepVerdict(), "dec-process"))
		withRecordingHITL(t)

		handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)
		rr := gs3066Post(t, handler, "/api/v1/process",
			map[string]string{"X-Org-ID": gs3066AttackerOrg, "X-Tenant-ID": gs3066AttackerTenat},
			map[string]any{"query": "move the funds", "request_type": "llm"})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
		}
		processWant := want
		processWant.DecisionID = "dec-process"
		assertAnchoredRow(t, "/api/v1/process's blocked row", oneAuditRowWhere(t, l, "/api/v1/process's blocked", isBlockedRow), processWant)
	})
}
