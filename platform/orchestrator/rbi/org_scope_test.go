// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// #3066 C3-3 / epic #3071.
//
// The RBI handler families used to resolve the scoping org from a
// CLIENT-SUPPLIED `?org_id=` query parameter. In the audit-export family the
// query parameter outranked the gateway-stamped X-Org-ID header outright; in
// the other five it was a fallback taken whenever the header was absent.
//
// The agent gateway Set()s X-Org-ID from the cryptographically validated client
// credential on every proxied route (platform/agent/proxy.go, proxyAuthMiddleware
// — /api/v1/rbi is in the proxied prefix list), and it Set()s rather than Adds so
// a client-supplied header is overwritten. NOTHING sanitises the query string.
// So the parameter was a scope the caller chose for itself:
//
//	GET    /api/v1/rbi/audit-exports?org_id=<victim>       → victim's exports
//	DELETE /api/v1/rbi/audit-exports/{id}?org_id=<victim>  → destroys them
//
// These tests drive the REAL handlers through the REAL gorilla/mux router that
// run.go registers (RBIModule.RegisterRoutesWithMux), so the route adapters,
// the method matchers and the path rewriting are all in the loop.

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const (
	orgAttacker = "org-attacker"
	orgVictim   = "org-victim"
)

// newAuditExportRouter builds the audit-export family on the production router
// with a repository whose org filtering mirrors the real SQL exactly
// (`WHERE id = $1 AND org_id = $2`, `WHERE org_id = $1`, `DELETE ... AND org_id = $2`
// — see auditexport_repository.go:129/147/265). The mock does NOT replicate any
// fail-open comparison, so an isolation assertion through it is a real one.
func newAuditExportRouter(t *testing.T) (*mux.Router, *AuditExportService) {
	t.Helper()
	repo := NewMockAuditExportRepository()
	svc := NewAuditExportService(repo, nil, nil, nil, nil, nil, t.TempDir(), nil)
	module := &RBIModule{
		AuditService: svc,
		AuditHandler: NewAuditExportHandler(svc),
		// RegisterRoutesWithMux short-circuits on a nil RegistryHandler.
		RegistryHandler:   NewAISystemRegistryHandler(&MockAISystemRegistryService{}),
		ValidationHandler: NewModelValidationHandler(&MockModelValidationService{}),
		IncidentHandler:   NewAIIncidentHandler(&MockAIIncidentService{}),
		KillSwitchHandler: NewKillSwitchHandler(NewMockKillSwitchService()),
		BoardHandler:      NewBoardReportHandler(NewMockBoardReportServiceForHandlers()),
	}
	r := mux.NewRouter()
	module.RegisterRoutesWithMux(r)
	return r, svc
}

// seedExport creates an export the way PRODUCTION creates one: through the
// POST handler on the real router, carrying only the gateway-stamped header.
// Building the fixture through the real writer is deliberate — a hand-built row
// can encode a shape the writer never emits, and an isolation suite standing on
// such a row certifies nothing.
func seedExport(t *testing.T, r *mux.Router, orgID, purpose string) string {
	t.Helper()
	body, _ := json.Marshal(CreateAuditExportRequest{
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
		Purpose:    purpose,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/audit-exports", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", orgID)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed export for %s: want 201, got %d: %s", orgID, rr.Code, rr.Body.String())
	}
	var resp AuditExportResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("seed export for %s: decode: %v", orgID, err)
	}
	if resp.Export == nil || resp.Export.ID == "" {
		t.Fatalf("seed export for %s: no export in response: %s", orgID, rr.Body.String())
	}
	if resp.Export.OrgID != orgID {
		t.Fatalf("seed export: created row stamped org %q, want %q", resp.Export.OrgID, orgID)
	}
	return resp.Export.ID
}

// do issues a request through the router. orgHeader == "" omits X-Org-ID
// entirely (the unauthenticated case).
func do(t *testing.T, r *mux.Router, method, path, orgHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if orgHeader != "" {
		req.Header.Set("X-Org-ID", orgHeader)
	}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// C3-3: the audit-export family
// ---------------------------------------------------------------------------

// TestAuditExport_QueryParamCannotSelectAnotherOrg is the two-directional
// isolation proof. BOTH orgs are seeded with real export rows first: without a
// victim row to leak, "the attacker saw nothing" would be vacuously true, and
// without an attacker row "the attacker still reads its own" is untested.
func TestAuditExport_QueryParamCannotSelectAnotherOrg(t *testing.T) {
	r, _ := newAuditExportRouter(t)

	attackerExport := seedExport(t, r, orgAttacker, "attacker's own export")
	victimExport := seedExport(t, r, orgVictim, "VICTIM-SENTINEL-do-not-leak")

	t.Run("list: own rows still readable", func(t *testing.T) {
		rr := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports", orgAttacker)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), attackerExport) {
			t.Errorf("attacker cannot read its OWN export %s — isolation assertions below would be vacuous: %s",
				attackerExport, rr.Body.String())
		}
	})

	t.Run("list: query param cannot select the victim org", func(t *testing.T) {
		rr := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200 (scoped to the attacker's own org), got %d: %s", rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if strings.Contains(body, victimExport) || strings.Contains(body, "VICTIM-SENTINEL") {
			t.Errorf("CROSS-TENANT READ: ?org_id=%s returned the victim's exports: %s", orgVictim, body)
		}
		if !strings.Contains(body, attackerExport) {
			t.Errorf("scope collapsed instead of binding to the header: own export %s missing: %s",
				attackerExport, body)
		}
	})

	t.Run("get by id: query param cannot select the victim org", func(t *testing.T) {
		rr := do(t, r, http.MethodGet,
			"/api/v1/rbi/audit-exports/"+victimExport+"?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT READ: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "VICTIM-SENTINEL") {
			t.Errorf("CROSS-TENANT READ: victim payload in the body: %s", rr.Body.String())
		}
	})

	t.Run("get by id: own row still readable", func(t *testing.T) {
		rr := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports/"+attackerExport, orgAttacker)
		if rr.Code != http.StatusOK {
			t.Errorf("want 200 for own export, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("download: query param cannot select the victim org", func(t *testing.T) {
		rr := do(t, r, http.MethodGet,
			"/api/v1/rbi/audit-exports/"+victimExport+"/download?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT READ: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("process: query param cannot select the victim org", func(t *testing.T) {
		rr := do(t, r, http.MethodPost,
			"/api/v1/rbi/audit-exports/"+victimExport+"/process?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT WRITE: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	// The destructive half. A GET-only suite leaves the worse outcome unproven.
	t.Run("delete: query param cannot destroy the victim's exports", func(t *testing.T) {
		rr := do(t, r, http.MethodDelete,
			"/api/v1/rbi/audit-exports/"+victimExport+"?org_id="+orgVictim, orgAttacker)
		if rr.Code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT DELETE: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
		// Survival check, read back as the victim — the status code alone does
		// not prove the row is still there.
		still := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports/"+victimExport, orgVictim)
		if still.Code != http.StatusOK {
			t.Errorf("CROSS-TENANT DELETE: victim's export %s was destroyed (read-back got %d: %s)",
				victimExport, still.Code, still.Body.String())
		}
	})

	t.Run("delete: own row still deletable", func(t *testing.T) {
		rr := do(t, r, http.MethodDelete, "/api/v1/rbi/audit-exports/"+attackerExport, orgAttacker)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("want 204 deleting own export, got %d: %s", rr.Code, rr.Body.String())
		}
		gone := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports/"+attackerExport, orgAttacker)
		if gone.Code != http.StatusNotFound {
			t.Errorf("own export still present after DELETE: got %d", gone.Code)
		}
	})
}

// TestAuditExport_CreateIgnoresQueryParamOrg proves the WRITE path stamps the
// authenticated org, not the client-named one — otherwise a caller could plant
// rows inside another org.
func TestAuditExport_CreateIgnoresQueryParamOrg(t *testing.T) {
	r, _ := newAuditExportRouter(t)

	body, _ := json.Marshal(CreateAuditExportRequest{
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
		Purpose:    "PLANTED-SENTINEL",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/rbi/audit-exports?org_id="+orgVictim, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", orgAttacker)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp AuditExportResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Export.OrgID != orgAttacker {
		t.Fatalf("CROSS-TENANT WRITE: export stamped org %q, want the authenticated %q",
			resp.Export.OrgID, orgAttacker)
	}
	// And it must not be visible to the named victim.
	victimList := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports", orgVictim)
	if strings.Contains(victimList.Body.String(), "PLANTED-SENTINEL") {
		t.Errorf("CROSS-TENANT WRITE: planted row landed in %s: %s", orgVictim, victimList.Body.String())
	}
}

// TestAuditExport_NoAuthenticatedOrgFailsClosed covers the case the whole class
// keeps regressing on: no resolvable org must be 401, never an empty-string org
// that a downstream predicate treats as "match all".
func TestAuditExport_NoAuthenticatedOrgFailsClosed(t *testing.T) {
	r, _ := newAuditExportRouter(t)
	victimExport := seedExport(t, r, orgVictim, "VICTIM-SENTINEL-do-not-leak")

	cases := []struct {
		name      string
		method    string
		path      string
		orgHeader string
	}{
		{"list, only a query param", http.MethodGet, "/api/v1/rbi/audit-exports?org_id=" + orgVictim, ""},
		{"list, nothing at all", http.MethodGet, "/api/v1/rbi/audit-exports", ""},
		{"list, whitespace-only header", http.MethodGet, "/api/v1/rbi/audit-exports?org_id=" + orgVictim, "   "},
		{"get by id, only a query param", http.MethodGet, "/api/v1/rbi/audit-exports/" + victimExport + "?org_id=" + orgVictim, ""},
		{"delete, only a query param", http.MethodDelete, "/api/v1/rbi/audit-exports/" + victimExport + "?org_id=" + orgVictim, ""},
		{"download, only a query param", http.MethodGet, "/api/v1/rbi/audit-exports/" + victimExport + "/download?org_id=" + orgVictim, ""},
		{"process, only a query param", http.MethodPost, "/api/v1/rbi/audit-exports/" + victimExport + "/process?org_id=" + orgVictim, ""},
		{"create, only a query param", http.MethodPost, "/api/v1/rbi/audit-exports?org_id=" + orgVictim, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := do(t, r, tc.method, tc.path, tc.orgHeader)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("want 401, got %d: %s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "VICTIM-SENTINEL") {
				t.Errorf("victim payload leaked in the error body: %s", rr.Body.String())
			}
		})
	}

	// The victim's row must have survived every probe above, including the
	// DELETE and the process.
	still := do(t, r, http.MethodGet, "/api/v1/rbi/audit-exports/"+victimExport, orgVictim)
	if still.Code != http.StatusOK {
		t.Errorf("victim's export did not survive the unauthenticated probes: got %d: %s",
			still.Code, still.Body.String())
	}
}

// ---------------------------------------------------------------------------
// The five sibling families
// ---------------------------------------------------------------------------

// TestRBISiblingFamilies_QueryParamCannotAuthenticate covers the other five RBI
// handler families. There the query parameter was a FALLBACK (header checked
// first), so it was inert for gateway-proxied traffic — but it still let a
// caller presenting NO authenticated org name any org it liked, and the SQL
// binds that value faithfully (`WHERE org_id = $1`), so it selected exactly
// which org's rows came back. Post-fix the service must never be reached.
func TestRBISiblingFamilies_QueryParamCannotAuthenticate(t *testing.T) {
	type probe struct {
		name   string
		method string
		path   string
		build  func(spy *orgSpy) *mux.Router
	}

	newRouter := func(m *RBIModule) *mux.Router {
		// RegisterRoutesWithMux short-circuits on a nil RegistryHandler, so
		// every module below gets one.
		if m.RegistryHandler == nil {
			m.RegistryHandler = NewAISystemRegistryHandler(&MockAISystemRegistryService{})
		}
		r := mux.NewRouter()
		m.RegisterRoutesWithMux(r)
		return r
	}

	// Each spy records the org the handler actually handed to the org-scoped
	// service call, which is the property under test stated directly.
	probes := []probe{
		{
			name: "ai-system registry", method: http.MethodGet, path: "/api/v1/rbi/ai-systems",
			build: func(spy *orgSpy) *mux.Router {
				return newRouter(&RBIModule{RegistryHandler: NewAISystemRegistryHandler(
					&registrySpy{MockAISystemRegistryService: &MockAISystemRegistryService{}, spy: spy})})
			},
		},
		{
			name: "model validations", method: http.MethodGet, path: "/api/v1/rbi/validations",
			build: func(spy *orgSpy) *mux.Router {
				return newRouter(&RBIModule{ValidationHandler: NewModelValidationHandler(
					&validationSpy{MockModelValidationService: &MockModelValidationService{}, spy: spy})})
			},
		},
		{
			name: "ai incidents", method: http.MethodGet, path: "/api/v1/rbi/incidents",
			build: func(spy *orgSpy) *mux.Router {
				return newRouter(&RBIModule{IncidentHandler: NewAIIncidentHandler(
					&incidentSpy{MockAIIncidentService: &MockAIIncidentService{}, spy: spy})})
			},
		},
		{
			name: "kill switches", method: http.MethodGet, path: "/api/v1/rbi/killswitches",
			build: func(spy *orgSpy) *mux.Router {
				return newRouter(&RBIModule{KillSwitchHandler: NewKillSwitchHandler(
					&killSwitchSpy{MockKillSwitchService: NewMockKillSwitchService(), spy: spy})})
			},
		},
		{
			name: "board reports", method: http.MethodGet, path: "/api/v1/rbi/reports",
			build: func(spy *orgSpy) *mux.Router {
				return newRouter(&RBIModule{BoardHandler: NewBoardReportHandler(
					&boardReportSpy{MockBoardReportService: NewMockBoardReportServiceForHandlers(), spy: spy})})
			},
		},
	}

	for _, p := range probes {
		t.Run(p.name+": query param alone cannot authenticate", func(t *testing.T) {
			spy := &orgSpy{}
			r := p.build(spy)
			req := httptest.NewRequest(p.method, p.path+"?org_id="+orgVictim, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("want 401, got %d: %s", rr.Code, rr.Body.String())
			}
			if spy.called {
				t.Errorf("CROSS-TENANT READ: the org-scoped service was invoked with org %q "+
					"for a caller with no authenticated org", spy.orgID)
			}
			if strings.Contains(rr.Body.String(), orgVictim) {
				t.Errorf("response echoes the client-named org: %s", rr.Body.String())
			}
		})

		t.Run(p.name+": header binds the scope", func(t *testing.T) {
			spy := &orgSpy{}
			r := p.build(spy)
			req := httptest.NewRequest(p.method, p.path+"?org_id="+orgVictim, nil)
			req.Header.Set("X-Org-ID", orgAttacker)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("want 200 for an authenticated caller, got %d: %s", rr.Code, rr.Body.String())
			}
			if !spy.called {
				t.Fatalf("service was not invoked — the positive direction is untested")
			}
			if spy.orgID != orgAttacker {
				t.Errorf("CROSS-TENANT READ: service scoped to %q, want the authenticated %q",
					spy.orgID, orgAttacker)
			}
			if strings.Contains(rr.Body.String(), orgVictim) {
				t.Errorf("CROSS-TENANT READ: rows scoped to the client-named org: %s", rr.Body.String())
			}
		})

		t.Run(p.name+": whitespace-only header fails closed", func(t *testing.T) {
			spy := &orgSpy{}
			r := p.build(spy)
			req := httptest.NewRequest(p.method, p.path, nil)
			req.Header.Set("X-Org-ID", "  ")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("want 401 for a blank org, got %d: %s", rr.Code, rr.Body.String())
			}
			if spy.called {
				t.Errorf("service invoked with org %q — an empty scope aliases every unstamped row",
					spy.orgID)
			}
		})
	}
}

// orgSpy records the org a handler handed to its org-scoped service call.
type orgSpy struct {
	called bool
	orgID  string
}

func (s *orgSpy) record(orgID string) { s.called, s.orgID = true, orgID }

// The five spies embed the package's existing handler mocks so they satisfy the
// full service interface, and override only the list method the probe drives.

type registrySpy struct {
	*MockAISystemRegistryService
	spy *orgSpy
}

func (s *registrySpy) ListSystems(_ context.Context, orgID string, _ *ListAISystemsParams) ([]*AISystem, int, error) {
	s.spy.record(orgID)
	return []*AISystem{{ID: "row-1", OrgID: orgID}}, 1, nil
}

type validationSpy struct {
	*MockModelValidationService
	spy *orgSpy
}

func (s *validationSpy) ListValidations(_ context.Context, orgID string, _ *ListValidationsParams) ([]*ModelValidation, int, error) {
	s.spy.record(orgID)
	return []*ModelValidation{{ID: "row-1", OrgID: orgID}}, 1, nil
}

type incidentSpy struct {
	*MockAIIncidentService
	spy *orgSpy
}

func (s *incidentSpy) ListIncidents(_ context.Context, orgID string, _ *ListIncidentsParams) ([]*AIIncident, int, error) {
	s.spy.record(orgID)
	return []*AIIncident{{ID: "row-1", OrgID: orgID}}, 1, nil
}

type killSwitchSpy struct {
	*MockKillSwitchService
	spy *orgSpy
}

func (s *killSwitchSpy) ListKillSwitches(_ context.Context, orgID string, _ *ListKillSwitchParams) ([]*KillSwitch, int, error) {
	s.spy.record(orgID)
	return []*KillSwitch{{ID: "row-1", OrgID: orgID}}, 1, nil
}

type boardReportSpy struct {
	*MockBoardReportService
	spy *orgSpy
}

func (s *boardReportSpy) ListReports(_ context.Context, orgID string, _ *ListBoardReportsParams) ([]*BoardReport, int, error) {
	s.spy.record(orgID)
	return []*BoardReport{{ID: "row-1", OrgID: orgID}}, 1, nil
}

// ---------------------------------------------------------------------------
// Invariant guard (AST): the pattern must not come back
// ---------------------------------------------------------------------------

// TestRBIHandlersNeverReadScopeFromTheQueryString is the durable half. The
// per-door fix above is only as good as the next handler somebody adds; this
// parses every non-test source file in the package and fails on
//
//	(a) any single-string-literal read of a scope-bearing key (`org_id`,
//	    `tenant_id`, …) through one of the request-parameter accessors below,
//	    on ANY receiver, and
//	(b) any such read of X-Org-ID/X-Tenant-ID/X-Client-ID outside org_scope.go —
//	    so the choke point stays a choke point rather than being re-inlined per
//	    handler.
//
// Guarding the invariant at the package level rather than at the six doors a
// review happened to name is the epic #3071 lesson: five of the eight prior
// fixes in this class were per-door censuses and each was outlived by a door it
// did not enumerate.
//
// Both rules match on the ACCESSOR NAME and the key, deliberately ignoring the
// shape of the receiver. An earlier revision required the receiver to be a
// literal `….Query()` call, which let the two nearest Go idioms straight
// through: `q := r.URL.Query()` followed by `q.Get("org_id")` (a url.Values
// bound to a local is an *ast.Ident, not an *ast.CallExpr — and that binding
// appears eight times in non-test code elsewhere in this repo), and
// `r.FormValue("org_id")`, which is strictly worse than the pattern removed
// here because it reads the query string AND the POST body form.
//
// NOT covered, stated so the guard is not mistaken for more than it is:
//   - body-borne scope. No RBI request type carries an org field today
//     (verified by hand across every json.Decode target in the six handler
//     files); if one is ever added, this guard will not see it.
//   - a key supplied as a non-literal (a constant, a variable or a
//     concatenation) rather than a string literal.
//   - mux.Vars(r)["org_id"] and other map-index forms, which are index
//     expressions rather than calls.
func TestRBIHandlersNeverReadScopeFromTheQueryString(t *testing.T) {
	// Scope-bearing parameter names. Anything here, read off a request, is a
	// client-chosen tenant boundary.
	bannedQueryKeys := map[string]bool{
		"org_id":          true,
		"orgId":           true,
		"organization_id": true,
		"tenant_id":       true,
		"tenantId":        true,
		"client_id":       true,
	}
	// Scope headers may only be read inside the choke point.
	scopeHeaders := map[string]bool{
		"X-Org-ID":    true,
		"X-Tenant-ID": true,
		"X-Client-ID": true,
	}
	// Single-argument accessors that read one named parameter off a request,
	// matched by NAME so the receiver's shape is irrelevant: url.Values
	// (`Get`/`Has`, however the values were obtained — including a local
	// binding), http.Header (`Get`/`Values`), and the *http.Request form
	// helpers (`FormValue` reads the query string AND the POST body form).
	scopeReaders := map[string]bool{
		"Get":           true,
		"Has":           true,
		"Values":        true,
		"FormValue":     true,
		"PostFormValue": true,
	}
	const chokePointFile = "org_scope.go"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	scanned := 0
	sawChokePoint := false
	violations := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		if name == chokePointFile {
			sawChokePoint = true
		}

		ast.Inspect(src, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !scopeReaders[sel.Sel.Name] {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			key, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}

			// (a) any request-parameter accessor naming a scope-bearing key,
			// whatever the receiver: r.URL.Query().Get("org_id"),
			// q.Get("org_id") off a local url.Values, r.FormValue("org_id"),
			// r.PostFormValue("org_id"), …
			if bannedQueryKeys[key] {
				violations++
				t.Errorf("%s: reads the tenant scope from a client-supplied request "+
					"parameter (%s(%s)). Scope must come from the gateway-stamped X-Org-ID "+
					"header via resolveOrgID(r) — see #3066 C3-3.",
					fset.Position(lit.Pos()), sel.Sel.Name, lit.Value)
				return true
			}

			// (b) any read of a scope header outside the choke point.
			if scopeHeaders[key] && name != chokePointFile {
				violations++
				t.Errorf("%s: reads the scope header %s directly. Route it through "+
					"resolveOrgID(r) in %s so the trim + fail-closed contract has exactly "+
					"one implementation — see #3066 C3-3.",
					fset.Position(lit.Pos()), lit.Value, chokePointFile)
			}
			return true
		})
	}

	if scanned == 0 {
		t.Fatal("guard scanned zero files — it would pass vacuously")
	}
	if !sawChokePoint {
		t.Fatalf("guard never saw %s — its exemption is untested and rule (b) may be inert",
			chokePointFile)
	}
	t.Logf("scanned %d source files, %d violations", scanned, violations)
}

// TestResolveOrgIDIgnoresEverythingButTheHeader pins the choke point itself.
func TestResolveOrgIDIgnoresEverythingButTheHeader(t *testing.T) {
	cases := []struct {
		name   string
		target string
		header *string
		want   string
	}{
		{"header only", "/x", strPtr("org-a"), "org-a"},
		{"header wins over a mismatching query param", "/x?org_id=org-b", strPtr("org-a"), "org-a"},
		{"query param alone resolves to nothing", "/x?org_id=org-b", nil, ""},
		{"blank header resolves to nothing", "/x?org_id=org-b", strPtr("   "), ""},
		{"tab/newline header resolves to nothing", "/x", strPtr("\t"), ""},
		{"header is trimmed", "/x", strPtr("  org-a  "), "org-a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.header != nil {
				req.Header.Set("X-Org-ID", *tc.header)
			}
			if got := resolveOrgID(req); got != tc.want {
				t.Errorf("resolveOrgID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func strPtr(s string) *string { return &s }
