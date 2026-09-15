// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/agent/license/admission"
	sharedidentity "axonflow/platform/shared/identity"
)

// /api/request IS ONE ANCHORED PASS (#4253, PRD v11 §1 item 1). Its second
// pass - the tier-aware engine over the stored action column and the
// organization's legacy per-policy overrides - is gone with the proxy_tier
// plane, and so is the segment gate that fed it. The policy-test preview
// previews that one pass. Every test below names the engine or the record it
// reads, and carries the control that makes its answer mean something.

// labelledSeries sums a vector's series by one label's value, over the series
// whose other labels match want. A series set other tests in the package
// created is included: the property is "no such series exists", not "this test
// did not create one".
func labelledSeries(t *testing.T, c prometheus.Collector, by string, want map[string]string) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1024)
	go func() { c.Collect(ch); close(ch) }()
	out := map[string]float64{}
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("reading a series: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range d.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		match := true
		for k, v := range want {
			if labels[k] != v {
				match = false
			}
		}
		if match {
			out[labels[by]] += d.GetCounter().GetValue()
		}
	}
	return out
}

// TestAPIRequestRecordsOnlyTheAnchoredEngine: every verdict /api/request
// counts is the anchored engine's. The CONTROL is that the series exist at
// all - an allow and two refusals were counted - so "no other engine" is not
// the answer of a counter nothing writes.
func TestAPIRequestRecordsOnlyTheAnchoredEngine(t *testing.T) {
	enfProxySetup(t)
	alice := enfMintUserToken(t, enfOrgPublished, enfUser)
	if r := enfProxy(t, enfOrgPublished, alice, "SELECT id FROM products"); r.code != http.StatusOK || r.str(t, "engine") != decisionEngineAnchored {
		t.Fatalf("PREMISE: the allow is the anchored engine's: HTTP %d engine=%q", r.code, r.str(t, "engine"))
	}
	if r := enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfBob), "SELECT id FROM products"); r.code != http.StatusForbidden {
		t.Fatalf("PREMISE: bob is refused: HTTP %d", r.code)
	}
	if r := enfProxy(t, enfOrgPublished, alice, "please run "+enfConstraintProbe+" now"); r.code != http.StatusForbidden {
		t.Fatalf("PREMISE: the probe is refused: HTTP %d", r.code)
	}

	engines := labelledSeries(t, anchoredEnforceDecisions, "engine", map[string]string{"plane": proxyRequestSeamScope.String()})
	if engines[decisionEngineAnchored] < 3 {
		t.Fatalf("CONTROL: the anchored engine's proxy_request series sum to %v; the three requests above were not counted", engines[decisionEngineAnchored])
	}
	for engine, n := range engines {
		if engine != decisionEngineAnchored && n > 0 {
			t.Errorf("proxy_request counted %v verdicts under engine=%q; since #4253 the anchored engine is this route's only author", n, engine)
		}
	}
}

// TestAPIRequestResolvesNoSegments is the segment gate's retirement, driven.
// Before #4253 /api/request resolved the caller's governance segments before
// any policy ran and refused the request, 403 segment_resolution_failed, when
// the resolution failed. Now nothing on the route resolves: with a resolver
// installed that fails every lookup, a verified user's request is decided by
// the anchored engine, and the resolution counter does not move.
func TestAPIRequestResolvesNoSegments(t *testing.T) {
	enfProxySetup(t)
	withFleetSegmentResolver(t, &fakeSegmentResolver{err: errors.New("segment store unavailable")})
	before := labelledSeries(t, segmentResolutionTotal, "phase", nil)

	r := enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "SELECT id FROM products")
	if r.code != http.StatusOK || r.blocked(t) || r.str(t, "engine") != decisionEngineAnchored {
		t.Fatalf("HTTP %d blocked=%v engine=%q; a failing segment store must decide nothing on /api/request. body=%s",
			r.code, r.blocked(t), r.str(t, "engine"), r.raw)
	}
	if strings.Contains(string(r.raw), "segment_resolution_failed") {
		t.Fatalf("the retired segment guard is named on the wire: %s", r.raw)
	}
	after := labelledSeries(t, segmentResolutionTotal, "phase", nil)
	for phase, n := range after {
		if n != before[phase] {
			t.Errorf("segment resolutions (phase %q) moved %v -> %v across one /api/request; the route resolves none", phase, before[phase], n)
		}
	}
}

// TestTheEffectivePolicyReadHasOneProductionCaller: the read that applied an
// organization's legacy per-policy override to a static row -
// StaticPolicyRepository.GetEffective - serves only the deprecated effective
// route now (PRD v11 §1.11). The tier engine was its other caller, and a
// second caller is that engine, or a new consumer of legacy overrides, coming
// back to a request path. Read from the source, so no build tag hides one.
func TestTheEffectivePolicyReadHasOneProductionCaller(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	agentPkg, ok := pkgs["agent"]
	if !ok {
		t.Fatal("agent package not found")
	}
	var callers []string
	for name, f := range agentPkg.Files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "GetEffective" {
					callers = append(callers, filepath.Base(name)+" "+fn.Name.Name)
				}
				return true
			})
		}
	}
	want := "static_policy_api_handlers.go HandleGetEffectivePolicies"
	if len(callers) != 1 || callers[0] != want {
		t.Fatalf("GetEffective is called from %v; want exactly [%s]", callers, want)
	}
}

// --- The policy-test preview: the dry run of the one pass ---

// enfPreview drives one policy-test preview through apiAuthMiddleware,
// authenticated as the organization's credential, with the body given.
func enfPreview(t *testing.T, org string, body map[string]string) enfResponse {
	t.Helper()
	clientID := enfProxyClientFor(org)
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/", bytes.NewReader(raw)) // neither the middleware nor the handler reads a path
	req.Header.Set("Content-Type", "application/json")
	setOAuth2BasicAuth(req, clientID, knownClients[clientID].LicenseKey)
	rr := httptest.NewRecorder()
	apiAuthMiddleware(http.HandlerFunc(policyTestHandler)).ServeHTTP(rr, req)
	out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
	if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("the preview is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return out
}

// stringArray reads a JSON string array member, failing when it is absent or null.
func (r enfResponse) stringArray(t *testing.T, member string) []string {
	t.Helper()
	v, ok := r.body[member]
	if !ok || string(v) == "null" {
		t.Fatalf("member %s is absent or null; want an array: %s", member, r.raw)
	}
	var out []string
	if err := json.Unmarshal(v, &out); err != nil {
		t.Fatalf("member %s is not a string array: %s", member, v)
	}
	return out
}

// enfCommunityOrg decides the rest of the test as a community deployment whose
// organization is org: the credential is the principal (PRD v11 §1.6), as the
// seam's own community case does (TestProxyRequestEnforcingSeam).
func enfCommunityOrg(t *testing.T, org string) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ORG_ID", org)
}

// TestPolicyTestPreviewAnswersWhatTheRouteAnswers: the preview IS the route's
// pass. For a request the organization's document allows and one a shipped
// constraint refuses, the preview and /api/request agree on the verdict, the
// determining policy, the engine, the principal and the policy bundle.
func TestPolicyTestPreviewAnswersWhatTheRouteAnswers(t *testing.T) {
	enfProxySetup(t)
	enfCommunityOrg(t, enfOrgPublished)
	constraintPolicy := enfProxyConstraintPolicy(t)

	for _, tc := range []struct {
		name, query string
		refused     bool
	}{
		{"allowed", "SELECT id FROM products", false},
		{"refused by a shipped constraint", "please run " + enfConstraintProbe + " now", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := enfProxy(t, enfOrgPublished, "", tc.query)
			preview := enfPreview(t, enfOrgPublished, map[string]string{"query": tc.query, "request_type": "sql"})
			if preview.code != http.StatusOK {
				t.Fatalf("the preview answered HTTP %d: %s", preview.code, preview.raw)
			}
			if route.blocked(t) != tc.refused || preview.blocked(t) != tc.refused {
				t.Fatalf("blocked: route=%v preview=%v, want %v. route=%s preview=%s", route.blocked(t), preview.blocked(t), tc.refused, route.raw, preview.raw)
			}
			for _, member := range []string{"engine", "subject_type", "policy_bundle"} {
				if route.str(t, member) != preview.str(t, member) || preview.str(t, member) == "" {
					t.Errorf("%s: route=%q preview=%q; the preview must be the route's pass", member, route.str(t, member), preview.str(t, member))
				}
			}
			if preview.str(t, "engine") != decisionEngineAnchored || preview.str(t, "subject_type") != string(sharedidentity.SubjectClient) {
				t.Fatalf("engine=%q subject_type=%q; want anchored for the credential", preview.str(t, "engine"), preview.str(t, "subject_type"))
			}
			triggered := preview.stringArray(t, "triggered_policies")
			matched := enfProxyMatchedPolicies(t, route)
			if tc.refused {
				if len(triggered) == 0 || triggered[0] != constraintPolicy || len(matched) == 0 || matched[0] != constraintPolicy {
					t.Fatalf("the determining policy: preview %v, route %v; want %s first in both", triggered, matched, constraintPolicy)
				}
				if preview.str(t, "reason") == "" {
					t.Fatal("a refused preview names no reason")
				}
			}
		})
	}
}

// TestPolicyTestPreviewRecordsNothing: the preview decides and writes no
// record of a decision. The CONTROL is the same refusal through /api/request,
// which writes its audit row and moves the enforce-decision counter; the
// preview of it does neither.
func TestPolicyTestPreviewRecordsNothing(t *testing.T) {
	enfProxySetup(t)
	enfCommunityOrg(t, enfOrgPublished)
	query := "please run " + enfConstraintProbe + " now"
	// Every series the enforce-decision counter keeps on proxy_request, whatever
	// the reason, so the dry run is held to moving none of them.
	proxyDecisions := func() float64 {
		total := 0.0
		for _, v := range labelledSeries(t, anchoredEnforceDecisions, "reason", map[string]string{"plane": proxyRequestSeamScope.String()}) {
			total += v
		}
		return total
	}

	expectAuditInsert := func() sqlmock.Sqlmock {
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
		return mock
	}

	control := expectAuditInsert()
	before := proxyDecisions()
	if r := enfProxy(t, enfOrgPublished, "", query); r.code != http.StatusForbidden {
		t.Fatalf("CONTROL: the route refuses the probe: HTTP %d", r.code)
	}
	if err := control.ExpectationsWereMet(); err != nil {
		t.Fatalf("CONTROL: the route's refusal wrote no audit row, so the preview's absence would mean nothing: %v", err)
	}
	if after := proxyDecisions(); after != before+1 {
		t.Fatalf("CONTROL: the route's refusal moved the counter %v -> %v; want +1", before, after)
	}

	mock := expectAuditInsert()
	before = proxyDecisions()
	preview := enfPreview(t, enfOrgPublished, map[string]string{"query": query})
	if preview.code != http.StatusOK || !preview.blocked(t) {
		t.Fatalf("PREMISE: the preview reports the refusal: HTTP %d blocked=%v", preview.code, preview.blocked(t))
	}
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Fatal("the preview wrote an audit row; a dry run records nothing")
	}
	if after := proxyDecisions(); after != before {
		t.Fatalf("the preview moved the enforce-decision counter %v -> %v; a dry run counts nothing", before, after)
	}
}

// servicePrincipalAdmissions is every counted outcome of a service-principal
// admission while no admitter is wired (admitPrincipal).
func servicePrincipalAdmissions(t *testing.T) float64 {
	t.Helper()
	dim := string(admission.ServicePrincipal)
	return testutil.ToFloat64(admissionUnwiredTotal.WithLabelValues(dim)) +
		testutil.ToFloat64(admissionSkippedTotal.WithLabelValues(dim, "org")) +
		testutil.ToFloat64(admissionSkippedTotal.WithLabelValues(dim, "principal"))
}

// TestPolicyTestPreviewAdmitsThePrincipalOnce: the preview reads the
// authentication result apiAuthMiddleware stored. Authenticating again would
// run admitPrincipal a second time, so one preview must admit exactly once.
func TestPolicyTestPreviewAdmitsThePrincipalOnce(t *testing.T) {
	enfProxySetup(t)
	enfCommunityOrg(t, enfOrgPublished)
	prev := tierAdmitter.Load()
	tierAdmitter.Store(nil)
	t.Cleanup(func() { tierAdmitter.Store(prev) })

	before := servicePrincipalAdmissions(t)
	if r := enfPreview(t, enfOrgPublished, map[string]string{"query": "SELECT id FROM products"}); r.code != http.StatusOK {
		t.Fatalf("PREMISE: the preview answers: HTTP %d %s", r.code, r.raw)
	}
	if after := servicePrincipalAdmissions(t); after != before+1 {
		t.Fatalf("one preview admitted the service principal %v times; want exactly 1 (the middleware's)", after-before)
	}
}

// TestPolicyTestPreviewWireShape holds each member of the preview's body, and
// the one it no longer carries.
func TestPolicyTestPreviewWireShape(t *testing.T) {
	enfProxySetup(t)
	enfCommunityOrg(t, enfOrgPublished)

	// bob is a principal the published document refuses by name; named in the
	// body he is still not the principal, so the credential is decided and the
	// preview allows.
	r := enfPreview(t, enfOrgPublished, map[string]string{"query": "SELECT id FROM products", "user_email": enfBob})
	if r.code != http.StatusOK || r.blocked(t) {
		t.Fatalf("HTTP %d blocked=%v; a body email is not a principal. body=%s", r.code, r.blocked(t), r.raw)
	}
	if _, present := r.body["segments_resolved"]; present {
		t.Fatalf("segments_resolved is still on the wire; nothing resolves segments since #4253: %s", r.raw)
	}
	if got := r.stringArray(t, "triggered_policies"); got == nil {
		t.Fatal("triggered_policies must be an array, empty when nothing triggered")
	}
	r.stringArray(t, "checks_performed")
	if _, ok := r.body["processing_time_ms"]; !ok {
		t.Fatalf("processing_time_ms is absent: %s", r.raw)
	}
	if reason, ok := r.body["reason"]; !ok || string(reason) != `""` {
		t.Fatalf("an allow carries an empty reason; got %s", reason)
	}
	if r.str(t, "engine") != decisionEngineAnchored || r.str(t, "subject_type") != string(sharedidentity.SubjectClient) || r.str(t, "policy_bundle") == "" {
		t.Fatalf("engine=%q subject_type=%q policy_bundle=%q; want anchored, Client and the bundle that decided", r.str(t, "engine"), r.str(t, "subject_type"), r.str(t, "policy_bundle"))
	}
}

// TestPolicyTestPreviewFailsClosedWithoutAnEnforcer: where the route answers
// 503 without a verdict, so does its preview.
func TestPolicyTestPreviewFailsClosedWithoutAnEnforcer(t *testing.T) {
	enfProxySetup(t)
	enfCommunityOrg(t, enfOrgPublished)
	prev := anchoredEnforcerInstance.Load()
	anchoredEnforcerInstance.Store(nil)
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })

	r := enfPreview(t, enfOrgPublished, map[string]string{"query": "SELECT id FROM products"})
	if r.code != http.StatusServiceUnavailable || !r.blocked(t) {
		t.Fatalf("HTTP %d blocked=%v; want a 503 refusal. body=%s", r.code, r.blocked(t), r.raw)
	}
	if got := r.stringArray(t, "triggered_policies"); len(got) != 1 || got[0] != "decision_enforcement_unavailable" {
		t.Fatalf("triggered_policies %v; want [decision_enforcement_unavailable]", got)
	}
	if r.str(t, "engine") != decisionEngineAnchored {
		t.Fatalf("engine=%q; want anchored", r.str(t, "engine"))
	}
}

// TestPolicyTestPreviewRefusesWhatItCannotDecide: a body that is not JSON is a
// 400, and a request apiAuthMiddleware did not authenticate is a 401 - the
// handler never authenticates on its own.
func TestPolicyTestPreviewRefusesWhatItCannotDecide(t *testing.T) {
	rr := httptest.NewRecorder()
	policyTestHandler(rr, httptest.NewRequest("POST", "/", strings.NewReader("{not json")))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("a body that is not JSON answered %d; want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	policyTestHandler(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"query":"SELECT 1"}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated preview answered %d; want 401", rr.Code)
	}
}
