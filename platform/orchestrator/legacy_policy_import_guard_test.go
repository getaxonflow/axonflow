// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/legacyfreeze"
)

// #4237. The legacy policy write routes - bulk import, create and update, on
// both handler types - answer the core/172 freeze BEFORE they read a body, on a
// deployment whose connection may not write the legacy tables, and answer as
// before on one that may (an owner-role deployment still writes: PRD v11 §5
// item 5). A %w-wrapped *ValidationError is a 400, not a 500, on every legacy
// write that still validates.
//
// The agent's POST /api/v1/policies[/import] has no handler of its own: the
// agent proxies the /api/v1/policies prefix here (proxy.go), so the
// orchestrator routes below are what it answers. Real-revoke coverage is
// TestLegacyImportAgainstTheRealRevoke_RealPG; the customer path is
// runtime-e2e/3039_rls_blind_reads.

// guardStub is a PolicyServicer whose privilege probe and write outcome a test
// sets, and whose calls it counts.
type guardStub struct {
	freezeStubService
	may      bool
	probeErr error
	writeErr error
	probes   int
	imports  int
	writes   int
	gets     int
}

func (s *guardStub) MayWriteLegacyPolicies(context.Context) (bool, error) {
	s.probes++
	return s.may, s.probeErr
}

func (s *guardStub) ImportPolicies(context.Context, string, string, *ImportPoliciesRequest, string) (*ImportPoliciesResponse, error) {
	s.imports++
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	return &ImportPoliciesResponse{Created: 1}, nil
}

func (s *guardStub) CreatePolicy(context.Context, string, string, *CreatePolicyRequest, string) (*PolicyResource, error) {
	s.writes++
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	return &PolicyResource{ID: "p1", Name: "created", Category: "dynamic-compliance"}, nil
}

func (s *guardStub) UpdatePolicy(context.Context, string, string, string, *UpdatePolicyRequest, string) (*PolicyResource, error) {
	s.writes++
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	return &PolicyResource{ID: "p1", Name: "updated", Category: "dynamic-compliance"}, nil
}

// GetPolicy returns a DYNAMIC row: the deprecated family's update refuses a
// non-dynamic one with 404 before it reads the body, which would satisfy a
// "not 500" assertion for a reason that has nothing to do with the error type.
func (s *guardStub) GetPolicy(context.Context, string, string, string) (*PolicyResource, error) {
	s.gets++
	return &PolicyResource{ID: "p1", Name: "existing", Category: "dynamic-compliance"}, nil
}

// readCounter records whether anything read the request body.
type readCounter struct {
	r     io.Reader
	reads int
}

func (b *readCounter) Read(p []byte) (int, error) {
	b.reads++
	return b.r.Read(p)
}

// legacyImportRouter is the registrar run.go calls, over svc, with both handler
// types the legacy routes delegate to: the path production takes, the
// deprecation stamp included.
func legacyImportRouter(t *testing.T, svc PolicyServicer) *mux.Router {
	t.Helper()
	prev := policyAPIHandler
	policyAPIHandler = NewPolicyAPIHandler(svc)
	t.Cleanup(func() { policyAPIHandler = prev })
	router := mux.NewRouter()
	registerLegacyPolicyRoutes(router, NewDynamicPolicyAPIHandler(svc), nil)
	return router
}

func legacyImport(t *testing.T, router *mux.Router, method, path, body string, headers map[string]string) (*httptest.ResponseRecorder, *readCounter) {
	t.Helper()
	rc := &readCounter{r: strings.NewReader(body)}
	r := httptest.NewRequest(method, path, rc)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, r)
	return rr, rc
}

// codedError reads both envelopes: PolicyAPIError and the deprecated family's
// untyped map carry the same two keys.
type codedError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeCoded(t *testing.T, rr *httptest.ResponseRecorder) codedError {
	t.Helper()
	var out codedError
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rr.Body.String())
	}
	return out
}

// assertTheFreeze asserts the whole refusal: the status, the code, the one
// message and the route it names, and the deprecation stamp.
func assertTheFreeze(t *testing.T, path string, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409 - a revoked deployment can write nothing here, whatever the body. body=%s",
			rr.Code, rr.Body.String())
	}
	out := decodeCoded(t, rr)
	if out.Error.Code != legacyfreeze.ErrCode {
		t.Fatalf("code=%q, want %q", out.Error.Code, legacyfreeze.ErrCode)
	}
	if out.Error.Message != legacyfreeze.Message {
		t.Fatalf("message=%q, want legacyfreeze.Message - no second freeze text", out.Error.Message)
	}
	if !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
		t.Fatalf("the refusal does not name the typed authoring route this binary serves: %q", out.Error.Message)
	}
	assertDeprecationSignal(t, path, rr.Header())
}

var (
	legacyImportRoutes = []string{
		"/api/v1/policies/import",
		"/api/v1/dynamic-policies/import",
		"/api/v1/tenant-policies/import",
	}
	tenantAndOrg = map[string]string{"X-Tenant-ID": "tenant-a", "X-Org-ID": "org-a"}

	// realisticRow is a well-formed dynamic row: the shape 3039's FREEZE_BODY
	// sends, which passes validation and reaches the write.
	realisticRow = `{"name":"w3x-4237-realistic","type":"content","category":"dynamic-compliance",` +
		`"conditions":[{"field":"query","operator":"contains","value":"x"}],"actions":[{"type":"block"}],"priority":10,"enabled":true}`
	// malformedRow is the row #4237 measured on the orchestrator routes:
	// `policy_type` where the request field is `type`, so validation fails.
	malformedRow = `{"name":"w3x-4237-malformed","policy_type":"content","category":"dynamic-compliance",` +
		`"conditions":[{"field":"query","operator":"contains","value":"x"}],"actions":[{"type":"block"}],"priority":10,"enabled":true}`
	// staticShapedRow is the row #4237 measured on the agent route: a static
	// policy's fields, none of a dynamic row's.
	staticShapedRow = `{"name":"w3x-4237-static","pattern":"x","category":"security-sqli","action":"block",` +
		`"severity":"high","tier":"tenant","enabled":true}`

	realisticImport    = `{"policies":[` + realisticRow + `]}`
	malformedImport    = `{"policies":[` + malformedRow + `]}`
	staticShapedImport = `{"policies":[` + staticShapedRow + `]}`

	importBodies = []struct{ name, body string }{
		{"a realistic row", realisticImport},
		{"a malformed row", malformedImport},
		{"a static-shaped row", staticShapedImport},
		{"an empty body", ""},
		{"invalid JSON", "{"},
		{"an empty policy list", `{"policies":[]}`},
	}

	// legacyWriteRoutes are the create and update routes of both handler
	// types, and the successor spelling, each with the body a real caller
	// sends and one that fails validation (the name must be 3-100 characters,
	// the priority 0-1000).
	legacyWriteRoutes = []struct{ name, method, path, realistic, malformed string }{
		{"policies create", http.MethodPost, "/api/v1/policies", realisticRow, malformedRow},
		{"policies update", http.MethodPut, "/api/v1/policies/p1", `{"name":"w3x-4237-renamed"}`, `{"name":"x","priority":-1}`},
		{"dynamic create", http.MethodPost, "/api/v1/dynamic-policies", realisticRow, malformedRow},
		{"dynamic update", http.MethodPut, "/api/v1/dynamic-policies/p1", `{"name":"w3x-4237-renamed"}`, `{"name":"x","priority":-1}`},
		{"tenant create", http.MethodPost, "/api/v1/tenant-policies", realisticRow, malformedRow},
		{"tenant update", http.MethodPut, "/api/v1/tenant-policies/p1", `{"name":"w3x-4237-renamed"}`, `{"name":"x","priority":-1}`},
	}

	wrappedValidation = fmt.Errorf("policy 0 validation failed: %w",
		&ValidationError{Errors: []PolicyFieldError{{Field: "type", Message: "Type is required"}}})
)

// TestLegacyImportIsRefusedBeforeItsBodyIsReadWhereTheWriteIsRevoked is the
// guard's contract on a deployment whose connection may not write: every body
// class, on all three import routes, is the freeze - and the body is never
// read, so no class of body can reach a validation answer first.
func TestLegacyImportIsRefusedBeforeItsBodyIsReadWhereTheWriteIsRevoked(t *testing.T) {
	for _, path := range legacyImportRoutes {
		for _, b := range importBodies {
			t.Run(path+" "+b.name, func(t *testing.T) {
				svc := &guardStub{may: false}
				rr, rc := legacyImport(t, legacyImportRouter(t, svc), http.MethodPost, path, b.body, tenantAndOrg)
				assertTheFreeze(t, path, rr)
				if rc.reads != 0 {
					t.Fatalf("the body was read %d time(s) before the refusal; the guard must run before decode", rc.reads)
				}
				if svc.imports != 0 || svc.probes != 1 {
					t.Fatalf("probes=%d imports=%d, want one probe and no import", svc.probes, svc.imports)
				}
			})
		}
	}
}

// TestLegacyCreateAndUpdateAreRefusedBeforeTheBodyIsReadWhereTheWriteIsRevoked
// is the same contract on create and update (R3 round 1, M1): a body that
// failed validation was answered 400 there, never the freeze. The update on the
// deprecated family is refused before its existence lookup too.
func TestLegacyCreateAndUpdateAreRefusedBeforeTheBodyIsReadWhereTheWriteIsRevoked(t *testing.T) {
	for _, rt := range legacyWriteRoutes {
		for _, b := range []struct{ name, body string }{
			{"a realistic body", rt.realistic},
			{"a body that fails validation", rt.malformed},
			{"an empty body", ""},
			{"invalid JSON", "{"},
		} {
			t.Run(rt.name+" "+b.name, func(t *testing.T) {
				svc := &guardStub{may: false}
				rr, rc := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, b.body, tenantAndOrg)
				assertTheFreeze(t, rt.path, rr)
				if rc.reads != 0 {
					t.Fatalf("the body was read %d time(s) before the refusal; the guard must run before decode", rc.reads)
				}
				if svc.writes != 0 || svc.gets != 0 || svc.probes != 1 {
					t.Fatalf("probes=%d writes=%d gets=%d, want one probe and no write or lookup", svc.probes, svc.writes, svc.gets)
				}
			})
		}
	}
}

// TestLegacyCreateAndUpdateStillWriteOnAnOwnerPool is the twin: where the
// connection may write, create and update proceed as before.
func TestLegacyCreateAndUpdateStillWriteOnAnOwnerPool(t *testing.T) {
	for _, rt := range legacyWriteRoutes {
		t.Run(rt.name, func(t *testing.T) {
			svc := &guardStub{may: true}
			rr, rc := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, rt.realistic, tenantAndOrg)
			want := http.StatusOK
			if rt.method == http.MethodPost {
				want = http.StatusCreated
			}
			if rr.Code != want {
				t.Fatalf("status=%d, want %d - an owner-role deployment still writes. body=%s", rr.Code, want, rr.Body.String())
			}
			if svc.probes != 1 || svc.writes != 1 || rc.reads == 0 {
				t.Fatalf("probes=%d writes=%d reads=%d, want one probe, one write and a read body", svc.probes, svc.writes, rc.reads)
			}
		})
	}
}

// TestLegacyImportAnswersAuthenticationBeforeTheFreeze fixes the order: a
// caller the route does not accept is told so, and the database is not asked.
// Each refusal is paired with the legitimate caller in the SAME revoked state,
// who gets the freeze - so the 401 is about the headers and not a route that
// refuses everyone.
func TestLegacyImportAnswersAuthenticationBeforeTheFreeze(t *testing.T) {
	cases := []struct {
		name     string
		headers  map[string]string
		wantCode string
	}{
		{"no tenant and no organization", map[string]string{}, "UNAUTHORIZED"},
		{"a tenant but no organization", map[string]string{"X-Tenant-ID": "tenant-a"}, "ORG_REQUIRED"},
	}
	for _, path := range legacyImportRoutes {
		for _, c := range cases {
			t.Run(path+" "+c.name, func(t *testing.T) {
				svc := &guardStub{may: false}
				rr, rc := legacyImport(t, legacyImportRouter(t, svc), http.MethodPost, path, realisticImport, c.headers)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("status=%d, want 401. body=%s", rr.Code, rr.Body.String())
				}
				if got := decodeCoded(t, rr).Error.Code; got != c.wantCode {
					t.Fatalf("code=%q, want %q", got, c.wantCode)
				}
				if svc.probes != 0 || rc.reads != 0 {
					t.Fatalf("probes=%d reads=%d, want neither before authentication", svc.probes, rc.reads)
				}
			})
		}
		t.Run(path+" the legitimate caller in the same state gets the freeze", func(t *testing.T) {
			svc := &guardStub{may: false}
			rr, _ := legacyImport(t, legacyImportRouter(t, svc), http.MethodPost, path, realisticImport, tenantAndOrg)
			assertTheFreeze(t, path, rr)
		})
	}
	// CREATE AND UPDATE REQUIRE ONLY THE TENANT, as they always have: a caller
	// with a tenant and no organization reaches the guard, and on a revoked
	// pool that is the freeze (through the agent the organization is always
	// set from the credential). Pinned so the order is stated, not assumed.
	for _, rt := range legacyWriteRoutes {
		t.Run(rt.name+" a tenant but no organization reaches the guard", func(t *testing.T) {
			svc := &guardStub{may: false}
			rr, rc := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, rt.malformed, map[string]string{"X-Tenant-ID": "tenant-a"})
			assertTheFreeze(t, rt.path, rr)
			if svc.probes != 1 || rc.reads != 0 || svc.writes != 0 {
				t.Fatalf("probes=%d reads=%d writes=%d, want one probe, no read and no write", svc.probes, rc.reads, svc.writes)
			}
		})
	}
	for _, rt := range legacyWriteRoutes {
		t.Run(rt.name+" no tenant and no organization", func(t *testing.T) {
			svc := &guardStub{may: false}
			rr, rc := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, rt.realistic, map[string]string{})
			if rr.Code != http.StatusUnauthorized || decodeCoded(t, rr).Error.Code != "UNAUTHORIZED" {
				t.Fatalf("status=%d body=%s, want 401 UNAUTHORIZED", rr.Code, rr.Body.String())
			}
			if svc.probes != 0 || rc.reads != 0 {
				t.Fatalf("probes=%d reads=%d, want neither before authentication", svc.probes, rc.reads)
			}
		})
	}
}

// TestAnOwnerPoolStillImportsAndAMalformedRowIsA400 is the other half of PRD v11
// §5 item 5: where the connection may write, the import proceeds as before,
// and a row that fails validation is the caller's 400 - the answer the
// concrete type assertion used to miss, answering 500.
func TestAnOwnerPoolStillImportsAndAMalformedRowIsA400(t *testing.T) {
	for _, path := range legacyImportRoutes {
		t.Run(path+" a realistic row is imported", func(t *testing.T) {
			svc := &guardStub{may: true}
			rr, rc := legacyImport(t, legacyImportRouter(t, svc), http.MethodPost, path, realisticImport, tenantAndOrg)
			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200 - an owner-role deployment still imports. body=%s", rr.Code, rr.Body.String())
			}
			if svc.probes != 1 || svc.imports != 1 || rc.reads == 0 {
				t.Fatalf("probes=%d imports=%d reads=%d, want one probe, one import and a read body", svc.probes, svc.imports, rc.reads)
			}
		})
		t.Run(path+" a malformed row is a 400, not a 500", func(t *testing.T) {
			svc := &guardStub{may: true, writeErr: wrappedValidation}
			rr, _ := legacyImport(t, legacyImportRouter(t, svc), http.MethodPost, path, malformedImport, tenantAndOrg)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400 for a wrapped *ValidationError. body=%s", rr.Code, rr.Body.String())
			}
			if got := decodeCoded(t, rr).Error.Code; got != "VALIDATION_ERROR" {
				t.Fatalf("code=%q, want VALIDATION_ERROR", got)
			}
		})
	}
}

// TestAnUnansweredProbeFallsThroughToTheWritesOwnAnswer pins the fail
// direction in both of its cases, on the import and on create: a revoked
// deployment is still answered the freeze, by the database's refusal of the
// write, and a deployment that may write is not refused because the probe
// failed.
func TestAnUnansweredProbeFallsThroughToTheWritesOwnAnswer(t *testing.T) {
	probeErr := errors.New("connection reset by peer")
	routes := []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/policies/import", realisticImport},
		{http.MethodPost, "/api/v1/dynamic-policies/import", realisticImport},
		{http.MethodPost, "/api/v1/tenant-policies/import", realisticImport},
		{http.MethodPost, "/api/v1/policies", realisticRow},
		{http.MethodPost, "/api/v1/dynamic-policies", realisticRow},
		{http.MethodPut, "/api/v1/policies/p1", `{"name":"w3x-4237-renamed"}`},
		{http.MethodPut, "/api/v1/dynamic-policies/p1", `{"name":"w3x-4237-renamed"}`},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path+" the database's refusal of the write is still the freeze", func(t *testing.T) {
			svc := &guardStub{probeErr: probeErr, writeErr: freezeError()}
			rr, _ := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, rt.body, tenantAndOrg)
			if rr.Code != http.StatusConflict || decodeCoded(t, rr).Error.Code != legacyfreeze.ErrCode {
				t.Fatalf("status=%d, want the classified 409. body=%s", rr.Code, rr.Body.String())
			}
			if svc.imports+svc.writes != 1 {
				t.Fatalf("imports=%d writes=%d, want 1: the 409 must come from the write, not from the unanswered guard", svc.imports, svc.writes)
			}
		})
		t.Run(rt.method+" "+rt.path+" a deployment that may write is not refused on a failed probe", func(t *testing.T) {
			svc := &guardStub{probeErr: probeErr}
			rr, _ := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, rt.body, tenantAndOrg)
			if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
				t.Fatalf("status=%d, want 200 or 201. body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestAWrappedValidationErrorIsA400OnEveryLegacyWriteThatStillValidates covers
// the six sites that asserted the concrete type: create and update on both
// handler types (and the successor spelling), and the two import handlers on
// an owner pool. Each is paired with an unclassified failure on the same route,
// which must stay 500 - so the 400 is about the error's type, not a handler
// that answers 400 to everything.
func TestAWrappedValidationErrorIsA400OnEveryLegacyWriteThatStillValidates(t *testing.T) {
	routes := []struct{ name, method, path, body string }{
		{"policies create", http.MethodPost, "/api/v1/policies", `{"name":"n","type":"content"}`},
		{"policies update", http.MethodPut, "/api/v1/policies/p1", `{"name":"n"}`},
		{"policies import", http.MethodPost, "/api/v1/policies/import", malformedImport},
		{"dynamic create", http.MethodPost, "/api/v1/dynamic-policies", `{"name":"n","type":"content","category":"dynamic-compliance"}`},
		{"dynamic update", http.MethodPut, "/api/v1/dynamic-policies/p1", `{"name":"n"}`},
		{"dynamic import", http.MethodPost, "/api/v1/dynamic-policies/import", malformedImport},
		{"tenant create", http.MethodPost, "/api/v1/tenant-policies", `{"name":"n","type":"content","category":"dynamic-compliance"}`},
		{"tenant update", http.MethodPut, "/api/v1/tenant-policies/p1", `{"name":"n"}`},
	}
	for _, rt := range routes {
		t.Run(rt.name+" a wrapped *ValidationError is a 400", func(t *testing.T) {
			svc := &guardStub{may: true, writeErr: wrappedValidation}
			rr, _ := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, rt.body, tenantAndOrg)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400. body=%s", rr.Code, rr.Body.String())
			}
			if got := decodeCoded(t, rr).Error.Code; got != "VALIDATION_ERROR" {
				t.Fatalf("code=%q, want VALIDATION_ERROR", got)
			}
		})
		t.Run(rt.name+" an unclassified failure is still a 500", func(t *testing.T) {
			svc := &guardStub{may: true, writeErr: errors.New("connection reset by peer")}
			rr, _ := legacyImport(t, legacyImportRouter(t, svc), rt.method, rt.path, rt.body, tenantAndOrg)
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d, want 500. body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}
