// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4249 row 5697957634, ADR-067 Decision 4 step 1b, the orchestrator half.
// requireInternalProxyAuth is the ONE place the agent's X-Axonflow-Identity-Source
// marker is read, after the proxy token validated; it stamps the answer on the
// request context, and the dynamic fact producer is its only reader. These
// tests pin the stamp, the refusal it names on the route-request plane, and the
// two non-obvious context hops by which it reaches the producer: the WCP
// checkpoint resume's re-gate and plan execute's MAP steps.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"axonflow/platform/orchestrator/planning"
	sharedidentity "axonflow/platform/shared/identity"
)

// The stamp, per cell: only a valid proxy token beside the exact value
// validated_token establishes; every other value is not established; a missing
// or invalid token never reaches the handler; an exempt path is served without a
// stamp whatever it carries. Every DEPLOYMENT_MODE answers the same.
func TestTheProxyAuthGateStampsIdentityEstablishedOnlyBehindAValidToken(t *testing.T) {
	type cell struct {
		name        string
		path        string
		token       func() string
		marker      string
		wantReached bool
		wantStamp   bool
	}
	cells := []cell{
		{"valid token, validated_token", "/api/v1/process", validAuthnToken, sharedidentity.IdentitySourceValidatedToken, true, true},
		{"valid token, no marker", "/api/v1/process", validAuthnToken, "", true, false},
		{"valid token, header", "/api/v1/process", validAuthnToken, "header", true, false},
		{"valid token, unknown value", "/api/v1/process", validAuthnToken, "verified", true, false},
		{"valid token, other case", "/api/v1/process", validAuthnToken, "VALIDATED_TOKEN", true, false},
		{"no token, validated_token", "/api/v1/process", func() string { return "" }, sharedidentity.IdentitySourceValidatedToken, false, false},
		{"invalid token, validated_token", "/api/v1/process", func() string { return tamperLastChar(validAuthnToken()) }, sharedidentity.IdentitySourceValidatedToken, false, false},
		{"exempt path, validated_token", "/health", func() string { return "" }, sharedidentity.IdentitySourceValidatedToken, true, false},
	}
	for _, mode := range []string{"", "community", "community-saas", "in-vpc-enterprise", "saas"} {
		for _, c := range cells {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				t.Setenv("DEPLOYMENT_MODE", mode)
				withAuthnValidator(t)
				reached, stamped, sawStamp := false, false, false
				r := mux.NewRouter()
				r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					reached = true
					_, sawStamp = req.Context().Value(identityEstablishedKey{}).(bool)
					stamped = identityEstablishedFrom(req.Context())
					w.WriteHeader(http.StatusOK)
				})
				req := httptest.NewRequest(http.MethodPost, c.path, nil)
				if tok := c.token(); tok != "" {
					req.Header.Set("X-Axonflow-Proxy-Auth", tok)
				}
				if c.marker != "" {
					req.Header.Set(sharedidentity.HeaderIdentitySource, c.marker)
				}
				rr := httptest.NewRecorder()
				requireInternalProxyAuth(r).ServeHTTP(rr, req)

				if reached != c.wantReached {
					t.Fatalf("reached = %v (status %d), want %v", reached, rr.Code, c.wantReached)
				}
				if !c.wantReached && rr.Code != http.StatusForbidden {
					t.Errorf("status = %d, want 403", rr.Code)
				}
				if stamped != c.wantStamp {
					t.Errorf("identity established = %v, want %v", stamped, c.wantStamp)
				}
				if c.path == "/health" && sawStamp {
					t.Error("an exempt path carried an identity stamp; it never passed proxy auth")
				}
			})
		}
	}
}

func TestSegmentMembershipEstablishedIsTheEmptyEmailOrTheStamp(t *testing.T) {
	withEmail := OrchestratorRequest{User: UserContext{Email: "alice@example.com"}}
	noEmail := OrchestratorRequest{}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		req  OrchestratorRequest
		want bool
	}{
		{"email, stamped established", withIdentityEstablished(context.Background(), true), withEmail, true},
		{"email, stamped not established", withIdentityEstablished(context.Background(), false), withEmail, false},
		{"email, no stamp", context.Background(), withEmail, false},
		{"email, nil context", nil, withEmail, false},
		{"no email, no stamp", context.Background(), noEmail, true},
		{"no email, stamped not established", withIdentityEstablished(context.Background(), false), noEmail, true},
	} {
		if got := segmentMembershipEstablished(tc.ctx, tc.req); got != tc.want {
			t.Errorf("%s: established = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// On the route-request plane an allow whose restrictions permit nothing is named
// by the producer's stated cause: segment_not_established only when the segment
// rows applied to a not-established caller took the last provider away, and
// no_compliant_provider otherwise, whatever the request's identity.
func TestANothingPermittedRefusalIsNamedByTheProducersCause(t *testing.T) {
	req := OrchestratorRequest{Client: ClientContext{OrgID: "o"}, User: UserContext{OrgID: "o", Email: "alice@example.com"}}
	for _, tc := range []struct {
		name   string
		routes routeEffects
		ctx    context.Context
		reason string
	}{
		{"segment rows took it away", routeEffects{Restricted: true, AllowedProviders: []string{}, SegmentNotEstablished: true}, context.Background(), reasonSegmentNotEstablished},
		{"nothing permitted regardless, header identity", routeEffects{Restricted: true, AllowedProviders: []string{}}, context.Background(), reasonNoCompliantProvider},
		{"nothing permitted regardless, validated token", routeEffects{Restricted: true, AllowedProviders: []string{}}, withIdentityEstablished(context.Background(), true), reasonNoCompliantProvider},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, src := withRouteRequestEngine(t, allowedStepVerdict())
			src.routes = tc.routes
			result := decideRouteRequest(tc.ctx, http.Header{}, req, processRouteAction).result
			if result.Allowed || !reflect.DeepEqual(result.RequiredActions, []string{"blocked: " + tc.reason}) ||
				!reflect.DeepEqual(result.AppliedPolicies, []string{tc.reason}) || result.BlockedBy != blockedByRouteLayer {
				t.Errorf("result = %+v, want refused naming %s by the route layer", result, tc.reason)
			}
		})
	}
}

// Plan execute decides through the same seam (run.go, planExecuteRouteAction),
// so a plan whose route restrictions permit nothing is refused there too, by
// the route layer, named by the producer's cause.
func TestPlanExecuteRefusesRouteRestrictionsThatPermitNothing(t *testing.T) {
	req := OrchestratorRequest{Client: ClientContext{OrgID: "o"}, User: UserContext{OrgID: "o"}}
	for _, tc := range []struct {
		routes routeEffects
		reason string
	}{
		{routeEffects{Restricted: true, AllowedProviders: []string{}}, reasonNoCompliantProvider},
		{routeEffects{Restricted: true, AllowedProviders: []string{}, SegmentNotEstablished: true}, reasonSegmentNotEstablished},
	} {
		_, src := withRouteRequestEngine(t, allowedStepVerdict())
		src.routes = tc.routes
		result := decideRouteRequest(context.Background(), http.Header{}, req, planExecuteRouteAction).result
		if result.Allowed || !reflect.DeepEqual(result.AppliedPolicies, []string{tc.reason}) || result.BlockedBy != blockedByRouteLayer {
			t.Errorf("plan execute over %+v: result = %+v, want refused naming %s by the route layer", tc.routes, result, tc.reason)
		}
	}
	_, src := withRouteRequestEngine(t, allowedStepVerdict())
	src.routes = routeEffects{Restricted: true, AllowedProviders: []string{"ollama"}}
	if result := decideRouteRequest(context.Background(), http.Header{}, req, planExecuteRouteAction).result; !result.Allowed {
		t.Errorf("CONTROL: plan execute over a restriction permitting ollama = %+v, want admitted", result)
	}
}

// resolvingProbe is a segmentRowsProbe installed behind a producer whose segment
// resolution answers seg-finance for every email, so the hop tests can read
// which list a plane's rows were selected from.
func installResolvingProbe(t *testing.T, factory *func() (*dynamicFactProducer, error), reset func(), probe *segmentRowsProbe, presentsNoContent bool) {
	t.Helper()
	previous := *factory
	*factory = func() (*dynamicFactProducer, error) {
		p, err := newDynamicFactProducer(probe)
		if err != nil {
			return nil, err
		}
		p.segments = func(_ context.Context, _, email string) ([]string, bool) {
			if email == "" {
				return nil, true
			}
			return []string{"seg-finance"}, true
		}
		p.presentsNoContent = presentsNoContent
		return p, nil
	}
	reset()
	t.Cleanup(func() {
		*factory = previous
		reset()
	})
}

// HOP 1, the WCP checkpoint resume. Served through buildOrchestratorHandler, so
// the stamp is the real gate's. The resume re-gates the checkpoint's step with
// the resuming request's context: a validated-token caller stays established
// (rows by its resolved segment), and the same email without the marker selects
// every segment's rows.
func TestACheckpointResumeCarriesTheIdentityStampToTheReGate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		marker    string
		wantEvery bool
	}{
		{"validated token", sharedidentity.IdentitySourceValidatedToken, false},
		{"header identity", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newResumeEnv(t)
			probe := &segmentRowsProbe{}
			installResolvingProbe(t, &newWCPFactProducer, resetWCPFacts, probe, true)
			withAuthnValidator(t)
			handler := buildOrchestratorHandler(cors.New(cors.Options{AllowedOrigins: []string{"*"}}), env.router)

			h := agentCredentialHeaders("org-a", "tenant-a", "client-resumer")
			h.Set("X-Axonflow-Proxy-Auth", validAuthnToken())
			h.Set("X-User-Email", "alice@example.com")
			if tc.marker != "" {
				h.Set(sharedidentity.HeaderIdentitySource, tc.marker)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+env.workflow+"/checkpoints/resume", nil)
			req.Header = h
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("resume status = %d, body = %s; want 200", rr.Code, rr.Body.String())
			}
			if probe.calls == 0 {
				t.Fatal("PREMISE: the re-gate never selected dynamic rows")
			}
			if probe.everySegment != tc.wantEvery {
				t.Errorf("every segment = %v, want %v", probe.everySegment, tc.wantEvery)
			}
			if !tc.wantEvery && !reflect.DeepEqual(probe.segments, []string{"seg-finance"}) {
				t.Errorf("established rows selected with segments %v, want [seg-finance]", probe.segments)
			}
		})
	}
}

// HOP 2, plan execute's MAP steps: executePlanHandler derives the execution's
// context from the request's (context.WithTimeout, then withMAPPlaneSubject),
// and every step's MAP decision hands it to the producer.
func TestPlanExecuteCarriesTheIdentityStampToTheMAPSteps(t *testing.T) {
	for _, tc := range []struct {
		name      string
		marker    string
		wantEvery bool
	}{
		{"validated token", sharedidentity.IdentitySourceValidatedToken, false},
		{"header identity", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousPlans, previousWorkflow, previousAudit := planService, workflowEngine, auditLogger
			t.Cleanup(func() { planService, workflowEngine, auditLogger = previousPlans, previousWorkflow, previousAudit })
			repo := planning.NewMockRepository()
			if err := repo.SavePlan(context.Background(), &planning.Plan{
				TenantID:           "tenant_1",
				PlanID:             "plan_identity_1b",
				Status:             planning.PlanStatusPending,
				StepCount:          1,
				Query:              "draft it",
				Domain:             "generic",
				OrgID:              "org_1",
				WorkflowDefinition: json.RawMessage(`{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"identity"},"spec":{"steps":[{"name":"draft","type":"llm-call"}]}}`),
				ExpiresAt:          time.Now().Add(time.Hour),
				CreatedAt:          time.Now(),
			}); err != nil {
				t.Fatalf("save plan: %v", err)
			}
			planService = planning.NewService(repo)
			auditLogger = responsePlaneLogger()
			// #4382: the plan's steps are decided on the declarative engine's step
			// gate, through the plane's own checker.
			workflowEngine = NewWorkflowEngine()
			workflowEngine.SetStepGate(&MAPHITLPolicyChecker{}, auditLogger)
			withRecordingRouteFacts(t, allowedStepVerdict())
			withHITLFlag(t, true)
			probe := &segmentRowsProbe{}
			installResolvingProbe(t, &newMAPFactProducer, resetMAPFacts, probe, true)

			handler := gs3066ServedHandler(t, "/api/v1/plan/execute", executePlanHandler)
			body, _ := json.Marshal(PlanRequest{Query: "run it", Context: map[string]interface{}{"plan_id": "plan_identity_1b"}})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/execute", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Axonflow-Proxy-Auth", validAuthnToken())
			req.Header.Set("X-Org-ID", "org_1")
			req.Header.Set("X-Tenant-ID", "tenant_1")
			req.Header.Set("X-Client-ID", "client_1")
			req.Header.Set("X-User-Email", "alice@example.com")
			if tc.marker != "" {
				req.Header.Set(sharedidentity.HeaderIdentitySource, tc.marker)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if probe.calls == 0 {
				t.Fatalf("PREMISE: no MAP step selected dynamic rows (status %d, body %s)", rr.Code, rr.Body.String())
			}
			if probe.everySegment != tc.wantEvery {
				t.Errorf("every segment = %v, want %v", probe.everySegment, tc.wantEvery)
			}
			if !tc.wantEvery && !reflect.DeepEqual(probe.segments, []string{"seg-finance"}) {
				t.Errorf("established rows selected with segments %v, want [seg-finance]", probe.segments)
			}
		})
	}
}

// For an ESTABLISHED caller the WCP and MAP seams state exactly the facts they
// stated before 1b: the facts over the rows the established list selects, which
// is the list both seams read before. For a NOT-established caller they state
// the facts of every segment's rows; the verdict is the engine's either way.
func TestWCPAndMAPFactsForAnEstablishedCallerAreTheSegmentSelectedRowsFacts(t *testing.T) {
	financeRow := DynamicPolicy{ID: "finance-row", Conditions: []PolicyCondition{{Field: "user.role", Operator: "equals", Value: "analyst"}}}
	engRow := DynamicPolicy{ID: "eng-row", Conditions: []PolicyCondition{{Field: "risk_score", Operator: "greater_than", Value: 0.5}}}
	src := &splitRows{bySegment: []DynamicPolicy{financeRow}, every: []DynamicPolicy{financeRow, engRow}}
	req := stepFactRequest("", nil)
	req.User.Email = "alice@example.com"
	for _, plane := range []string{"wcp", "map"} {
		t.Run(plane, func(t *testing.T) {
			p := testFactProducerOver(t, src)
			p.presentsNoContent = true
			before := testFactProducerOver(t, fixedFactRows(src.bySegment))
			before.presentsNoContent = true

			established, _, err := p.Produce(withIdentityEstablished(context.Background(), true), req)
			if err != nil {
				t.Fatal(err)
			}
			want, _, _ := before.Produce(withIdentityEstablished(context.Background(), true), req)
			if !reflect.DeepEqual(established, want) {
				t.Errorf("established facts %v, want the segment-selected rows' %v", established, want)
			}
			notEstablished, _, err := p.Produce(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			everyFacts, _, _ := testFactProducerOver(t, fixedFactRows(src.every)).Produce(context.Background(), req)
			if !reflect.DeepEqual(notEstablished, everyFacts) || reflect.DeepEqual(notEstablished, established) {
				t.Errorf("not-established facts %v, want every segment's rows' %v (and different from established %v)", notEstablished, everyFacts, established)
			}
		})
	}
}

// splitRows answers the established list and the every-segment list with
// different rows.
type splitRows struct {
	bySegment, every []DynamicPolicy
}

func (s *splitRows) ListActivePoliciesForTenant(string, []string) []DynamicPolicy { return s.bySegment }

func (s *splitRows) ListActivePoliciesForOrgInEverySegment(string) []DynamicPolicy { return s.every }
