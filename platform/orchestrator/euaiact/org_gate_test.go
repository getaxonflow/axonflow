// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Negative-authorization tests for the #3241 organization gate.
//
// These exist as their own file, and their own named cases, because the fix
// required adding `X-Org-ID` to ~30 EXISTING handler tests. A mechanical
// "add the header everywhere" sweep ARMS every one of those tests and would
// have silently deleted the property that the header is required at all
// (`[[feedback_mechanical_sweep_must_skip_negative_auth_tests]]`,
// `[[feedback_fixing_a_fail_open_means_inverting_the_gates_that_pinned_it]]`).
// Nothing in this file may ever set an organization header.

// seededOrgGateHandlers returns handlers backed by mocks holding one row each,
// owned by "victim-org". The row EXISTS, so a refusal below can only come from
// the organization gate - not from an empty repository.
func seededOrgGateHandlers(t *testing.T) (*ExportHandler, *ConformityHandler) {
	t.Helper()
	exportRepo := NewMockExportRepository()
	exportRepo.exports["export-123"] = &Export{
		ID:     "export-123",
		OrgID:  "victim-org",
		Status: ExportStatusCompleted,
	}
	conformityRepo := NewMockConformityRepository()
	conformityRepo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "victim-org",
		Status: AssessmentStatusDraft,
		Requirements: []RequirementStatus{
			{RequirementID: "req-1", Article: "Article 9", Status: "compliant"},
		},
	}
	return NewExportHandler(NewExportService(exportRepo, nil)),
		NewConformityHandler(NewConformityService(conformityRepo))
}

// TestOrgGate_ByIDPathsRefuseAMissingOrgHeader pins that every by-id path is
// closed to a request carrying no authenticated organization.
func TestOrgGate_ByIDPathsRefuseAMissingOrgHeader(t *testing.T) {
	exportHandler, conformityHandler := seededOrgGateHandlers(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		serve  func(http.ResponseWriter, *http.Request)
	}{
		{"export get", http.MethodGet, "/api/v1/euaiact/export/export-123", "", exportHandler.handleExportByID},
		{"export download", http.MethodGet, "/api/v1/euaiact/export/export-123/download", "", exportHandler.handleExportByID},
		{"conformity get", http.MethodGet, "/api/v1/euaiact/conformity/assess-123", "", conformityHandler.handleConformityByID},
		{"conformity update", http.MethodPut, "/api/v1/euaiact/conformity/assess-123", `{"system_name":"x"}`, conformityHandler.handleConformityByID},
		{"conformity submit", http.MethodPost, "/api/v1/euaiact/conformity/assess-123/submit", "", conformityHandler.handleConformityByID},
		{"conformity approve", http.MethodPost, "/api/v1/euaiact/conformity/assess-123/approve", "", conformityHandler.handleConformityByID},
		{"conformity reject", http.MethodPost, "/api/v1/euaiact/conformity/assess-123/reject", `{"reason":"no"}`, conformityHandler.handleConformityByID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
			// NO organization header. That is the point of this file.
			rr := httptest.NewRecorder()
			tc.serve(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400 for a request with no organization header. body=%s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "victim-org") {
				t.Errorf("refusal leaked the owning organization: %s", rr.Body.String())
			}
		})
	}
}

// TestOrgGate_WhitespaceOnlyOrgHeaderIsTreatedAsAbsent pins the trimming rule.
// An untrimmed "   " is non-empty, so it passes an `orgID == ""` check and then
// matches no row: a silent zero-rows result that reads as "our data is gone"
// (the #3039 class) rather than as a refusal.
func TestOrgGate_WhitespaceOnlyOrgHeaderIsTreatedAsAbsent(t *testing.T) {
	exportHandler, conformityHandler := seededOrgGateHandlers(t)

	for _, tc := range []struct {
		name  string
		path  string
		serve func(http.ResponseWriter, *http.Request)
	}{
		{"export", "/api/v1/euaiact/export/export-123", exportHandler.handleExportByID},
		{"conformity", "/api/v1/euaiact/conformity/assess-123", conformityHandler.handleConformityByID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("X-Org-ID", "   ")
			rr := httptest.NewRecorder()
			tc.serve(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400 for a whitespace-only organization header. body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestOrgGate_CrossOrgByIDIsRefusedWith404 pins the refusal SHAPE: a foreign
// organization gets the same 404 an unknown id gets, so the endpoint cannot be
// used to enumerate which report ids exist elsewhere on the deployment.
func TestOrgGate_CrossOrgByIDIsRefusedWith404(t *testing.T) {
	exportHandler, conformityHandler := seededOrgGateHandlers(t)

	for _, tc := range []struct {
		name    string
		path    string
		unknown string
		serve   func(http.ResponseWriter, *http.Request)
	}{
		{"export", "/api/v1/euaiact/export/export-123", "/api/v1/euaiact/export/does-not-exist", exportHandler.handleExportByID},
		{"conformity", "/api/v1/euaiact/conformity/assess-123", "/api/v1/euaiact/conformity/does-not-exist", conformityHandler.handleConformityByID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serve := func(path string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("X-Org-ID", "attacker-org")
				rr := httptest.NewRecorder()
				tc.serve(rr, req)
				return rr
			}
			foreign := serve(tc.path)
			unknown := serve(tc.unknown)

			if foreign.Code != http.StatusNotFound {
				t.Errorf("cross-org by-id: got %d, want 404. body=%s", foreign.Code, foreign.Body.String())
			}
			if foreign.Code != unknown.Code {
				t.Errorf("cross-org (%d) and unknown-id (%d) refusals differ - the endpoint is an existence oracle",
					foreign.Code, unknown.Code)
			}
			if foreign.Body.String() != unknown.Body.String() {
				t.Errorf("cross-org and unknown-id refusal BODIES differ - still an existence oracle.\n cross-org: %s\n unknown:   %s",
					foreign.Body.String(), unknown.Body.String())
			}
		})
	}
}

// TestOrgGate_PreflightAndMethodChecksRunBeforeTheOrgGate pins that adding the
// organization gate did not change what an OPTIONS preflight or a wrong verb
// sees. A preflight that started answering "header required" would break CORS
// on every browser client, and it carries no credentials by definition.
func TestOrgGate_PreflightAndMethodChecksRunBeforeTheOrgGate(t *testing.T) {
	_, conformityHandler := seededOrgGateHandlers(t)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/euaiact/conformity/assess-123", nil)
	rr := httptest.NewRecorder()
	conformityHandler.handleConformityByID(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("OPTIONS preflight: got %d, want 200", rr.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/euaiact/conformity/assess-123", nil)
	rr = httptest.NewRecorder()
	conformityHandler.handleConformityByID(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE on a GET/PUT route: got %d, want 405", rr.Code)
	}
}
