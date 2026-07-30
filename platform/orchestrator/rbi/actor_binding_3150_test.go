// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/shared/identity"
)

// #3150 — an RBI compliance actor must come from the authenticated request, not
// from the JSON body.
//
// Eight handlers in this module took the acting principal from the body and
// persisted it as the actor of a regulator-facing action: who requested an
// audit export, who generated / submitted / approved / rejected a board report,
// who armed or released a kill switch, who gave board approval to an AI system.
// resolveOrgID has bound the ORGANIZATION since #3066, so this crosses no
// tenant boundary and the caller must already hold a credential — what it
// defeats is attribution and non-repudiation on the artefact the regulator
// reads.
//
// The tests drive the real handlers over HTTP with a body that names somebody
// else, because that is the exploit. Constructing the request struct in Go and
// checking the field would test the struct, not the path.

const (
	ab3150Org      = "ab3150-org"
	ab3150Client   = "ab3150-client"
	ab3150Synth    = "ab3150-client@axonflow.local"
	ab3150ForgedID = "cro.impersonated"
)

// ab3150Post issues an authenticated request the way the agent's proxy does:
// X-Org-ID and X-Client-ID stamped from the validated credential, no per-user
// identity (the default posture — AXONFLOW_TRUST_IDENTITY_HEADERS is off, and
// none of the in-tree RBI clients send one).
func ab3150Post(t *testing.T, h http.HandlerFunc, method, path, body string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", ab3150Org)
	req.Header.Set("X-Client-ID", ab3150Client)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// resolveActor
// ---------------------------------------------------------------------------

func TestResolveActor_Precedence(t *testing.T) {
	t.Run("credential only: synthetic identity, service role", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", nil)
		r.Header.Set("X-Client-ID", ab3150Client)
		got := resolveActor(r)
		if got.ID != ab3150Client {
			t.Errorf("ID = %q, want the validated client credential", got.ID)
		}
		if got.Email != ab3150Synth {
			t.Errorf("Email = %q, want %q", got.Email, ab3150Synth)
		}
		if got.Role != actorRoleService {
			t.Errorf("Role = %q, want %q — the record must not imply a named person", got.Role, actorRoleService)
		}
	})

	t.Run("X-Tenant-ID is accepted as the v9 alias", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", nil)
		r.Header.Set("X-Tenant-ID", ab3150Client)
		if got := resolveActor(r); got.ID != ab3150Client {
			t.Errorf("ID = %q, want the credential from the X-Tenant-ID alias", got.ID)
		}
	})

	t.Run("no identity at all: system, never empty", func(t *testing.T) {
		got := resolveActor(httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", nil))
		if got.ID != systemActorID {
			t.Errorf("ID = %q, want %q", got.ID, systemActorID)
		}
		// An empty actor id would satisfy the service layer's
		// `if req.ActorID == ""` guard as "missing", turning an attribution
		// change into a 400 for every header-less caller.
		if got.ID == "" {
			t.Error("actor id must never be empty")
		}
	})

	t.Run("nil request is safe", func(t *testing.T) {
		if got := resolveActor(nil); got.ID != systemActorID {
			t.Errorf("ID = %q, want %q", got.ID, systemActorID)
		}
	})

	t.Run("identity headers are IGNORED while the trust gate is off", func(t *testing.T) {
		t.Setenv(identity.EnvVar, "")
		r := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", nil)
		r.Header.Set("X-User-Email", "Forged.Person@Example.com")
		r.Header.Set("X-User-ID", "forged")
		r.Header.Set("X-Client-ID", ab3150Client)
		got := resolveActor(r)
		if got.ID != ab3150Client || got.Role != actorRoleService {
			t.Errorf("gate-off request honoured a client-asserted identity: %+v", got)
		}
	})

	t.Run("identity headers are honoured once the deployment opts in", func(t *testing.T) {
		t.Setenv(identity.EnvVar, "true")
		r := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", nil)
		r.Header.Set("X-User-Email", "Real.Person@Example.com")
		r.Header.Set("X-Client-ID", ab3150Client)
		got := resolveActor(r)
		if got.Email != "real.person@example.com" {
			t.Errorf("Email = %q, want the canonicalised header identity", got.Email)
		}
		if got.Role != actorRoleUser {
			t.Errorf("Role = %q, want %q", got.Role, actorRoleUser)
		}
	})
}

// TestResolveActor_RoleIsHowNotWho pins that actor_role describes the
// authentication method and can never carry a claim like "compliance_officer".
func TestResolveActor_RoleIsHowNotWho(t *testing.T) {
	t.Setenv(identity.EnvVar, "true")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/killswitches/x/activate", nil)
	r.Header.Set("X-User-Email", "person@example.com")
	r.Header.Set("X-Axonflow-User-Role", "chief_risk_officer")
	got := resolveActor(r)
	if got.Role != actorRoleUser {
		t.Errorf("Role = %q, want %q — this plane may only say HOW the caller authenticated", got.Role, actorRoleUser)
	}
}

// ---------------------------------------------------------------------------
// The handlers, over HTTP, with a body that names somebody else
// ---------------------------------------------------------------------------

func TestAuditExport3150_RequesterIsTheCredentialNotTheBody(t *testing.T) {
	service := NewAuditExportService(NewMockAuditExportRepository(), nil, nil, nil, nil, nil, t.TempDir(), nil)
	handler := NewAuditExportHandler(service)

	body := `{"export_type":"full","format":"json",` +
		`"requested_by":"` + ab3150ForgedID + `","requested_by_email":"cro@victim.example.com"}`
	rr := ab3150Post(t, handler.handleExports, http.MethodPost, "/api/v1/rbi/audit-exports", body, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
	}

	var resp AuditExportResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Export.RequestedBy != ab3150Client {
		t.Errorf("RequestedBy = %q, want the authenticated credential %q", resp.Export.RequestedBy, ab3150Client)
	}
	if resp.Export.RequestedByEmail != ab3150Synth {
		t.Errorf("RequestedByEmail = %q, want %q", resp.Export.RequestedByEmail, ab3150Synth)
	}
	if strings.Contains(resp.Export.RequestedBy, ab3150ForgedID) {
		t.Error("the body's requester survived onto the evidence artefact")
	}
}

func TestBoardReport3150_ActorsAreTheCredentialNotTheBody(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Generate.
	genBody := `{"report_type":"quarterly","generated_by":"` + ab3150ForgedID +
		`","generated_by_email":"cro@victim.example.com"}`
	rr := ab3150Post(t, handler.handleReports, http.MethodPost, "/api/v1/rbi/reports", genBody, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("generate: status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
	}
	var report BoardReport
	if err := json.NewDecoder(rr.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.GeneratedBy != ab3150Client {
		t.Errorf("GeneratedBy = %q, want %q", report.GeneratedBy, ab3150Client)
	}
	if report.GeneratedByEmail != ab3150Synth {
		t.Errorf("GeneratedByEmail = %q, want %q", report.GeneratedByEmail, ab3150Synth)
	}

	// Submit, then approve — the two that write the approval evidence.
	subBody := `{"submitted_by":"` + ab3150ForgedID + `"}`
	rr = ab3150Post(t, handler.handleReportRoutes, http.MethodPost,
		"/api/v1/rbi/reports/"+report.ID+"/submit", subBody, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("submit: status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}

	appBody := `{"approved_by":"` + ab3150ForgedID + `","approved_by_email":"chair@victim.example.com",` +
		`"approval_notes":"looks fine"}`
	rr = ab3150Post(t, handler.handleReportRoutes, http.MethodPost,
		"/api/v1/rbi/reports/"+report.ID+"/approve", appBody, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("approve: status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var approved BoardReport
	if err := json.NewDecoder(rr.Body).Decode(&approved); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if approved.ApprovedBy != ab3150Client {
		t.Errorf("ApprovedBy = %q, want the authenticated credential %q — a board approval "+
			"whose approver is self-asserted is not evidence of approval", approved.ApprovedBy, ab3150Client)
	}
	if approved.ApprovedByEmail != ab3150Synth {
		t.Errorf("ApprovedByEmail = %q, want %q", approved.ApprovedByEmail, ab3150Synth)
	}
	// The approval NOTES are legitimate free text and must survive; a fix that
	// blanked the whole body would pass every assertion above.
	if approved.ApprovalNotes != "looks fine" {
		t.Errorf("ApprovalNotes = %q — non-identity body fields must be unaffected", approved.ApprovalNotes)
	}
}

// ab3150KillSwitchCapture records the request the HANDLER passed down. That is
// the boundary this change moved: killswitch_service.go copies req.Actor* onto
// the KillSwitch row and onto every rbi_kill_switch_history entry verbatim
// (killswitch_service.go Activate/Deactivate), so what the handler hands it IS
// what the Article-14-grade oversight record says.
type ab3150KillSwitchCapture struct {
	*MockKillSwitchService
	activate   *ActivateKillSwitchRequest
	deactivate *DeactivateKillSwitchRequest
}

func (c *ab3150KillSwitchCapture) Activate(ctx context.Context, orgID, id string, req *ActivateKillSwitchRequest) (*KillSwitch, error) {
	c.activate = req
	return c.MockKillSwitchService.Activate(ctx, orgID, id, req)
}

func (c *ab3150KillSwitchCapture) Deactivate(ctx context.Context, orgID, id string, req *DeactivateKillSwitchRequest) (*KillSwitch, error) {
	c.deactivate = req
	return c.MockKillSwitchService.Deactivate(ctx, orgID, id, req)
}

func TestKillSwitch3150_ActorIsTheCredentialNotTheBody(t *testing.T) {
	inner := NewMockKillSwitchService()
	capture := &ab3150KillSwitchCapture{MockKillSwitchService: inner}
	handler := NewKillSwitchHandler(capture)

	ks, err := inner.CreateKillSwitch(context.Background(), ab3150Org, &CreateKillSwitchRequest{
		Scope: "system", SystemID: "credit-scoring", FallbackBehavior: "block_all",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"actor_id":"` + ab3150ForgedID + `","actor_email":"cro@victim.example.com",` +
		`"actor_role":"chief_risk_officer","actor_ip":"203.0.113.9","reason":"drift detected"}`
	rr := ab3150Post(t, handler.handleKillSwitchRoutes, http.MethodPost,
		"/api/v1/rbi/killswitches/"+ks.ID+"/activate", body, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("activate: status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if capture.activate == nil {
		t.Fatal("the service was never called — every assertion below would be vacuous")
	}
	got := capture.activate
	if got.ActorID != ab3150Client {
		t.Errorf("ActorID = %q, want the authenticated credential %q", got.ActorID, ab3150Client)
	}
	if got.ActorEmail != ab3150Synth {
		t.Errorf("ActorEmail = %q, want %q", got.ActorEmail, ab3150Synth)
	}
	if got.ActorRole == "chief_risk_officer" {
		t.Error("the body's actor_role survived: the history would claim a role nothing authenticated")
	}
	if got.ActorRole != actorRoleService {
		t.Errorf("ActorRole = %q, want %q", got.ActorRole, actorRoleService)
	}
	if got.ActorIP == "203.0.113.9" {
		t.Error("the body's actor_ip survived: actor_ip must describe the connection, not the claim")
	}
	if got.Reason != "drift detected" {
		t.Errorf("Reason = %q — the reason is legitimate caller input and must survive", got.Reason)
	}

	// Release is the more sensitive half of the pair.
	rr = ab3150Post(t, handler.handleKillSwitchRoutes, http.MethodPost,
		"/api/v1/rbi/killswitches/"+ks.ID+"/deactivate",
		`{"actor_id":"`+ab3150ForgedID+`","actor_role":"chief_risk_officer","reason":"resolved"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("deactivate: status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if capture.deactivate == nil {
		t.Fatal("the service was never called on deactivate")
	}
	if capture.deactivate.ActorID != ab3150Client || capture.deactivate.ActorRole != actorRoleService {
		t.Errorf("deactivate actor = %+v, want the authenticated credential", capture.deactivate)
	}
}

func TestBoardApproval3150_ApproverIsTheCredentialNotTheBody(t *testing.T) {
	// The mock echoes back the approver the HANDLER passed down, which is the
	// value the real registry_service.go assigns to
	// rbi_ai_systems.board_approver_name.
	var seen string
	mock := &MockAISystemRegistryService{
		processBoardFunc: func(_ context.Context, orgID, id string, req *BoardApprovalRequest) (*AISystem, error) {
			seen = req.Approver
			return &AISystem{ID: id, OrgID: orgID, BoardApproverName: req.Approver,
				BoardApprovalStatus: BoardApprovalApproved, BoardApprovalNotes: req.Notes}, nil
		},
	}
	handler := NewAISystemRegistryHandler(mock)

	body := `{"action":"approve","reference":"BOARD-2026-001","approver":"` + ab3150ForgedID +
		`","notes":"approved after risk review"}`
	rr := ab3150Post(t, handler.handleAISystemByID, http.MethodPost,
		"/api/v1/rbi/ai-systems/sys-3150/board-approval", body, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if seen != ab3150Client {
		t.Errorf("approver passed to the service = %q, want the authenticated credential %q", seen, ab3150Client)
	}
	if seen == ab3150ForgedID {
		t.Error("the body named the board member who approved this AI system")
	}

	var approved AISystem
	if err := json.NewDecoder(rr.Body).Decode(&approved); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if approved.BoardApprovalNotes != "approved after risk review" {
		t.Errorf("BoardApprovalNotes = %q — non-identity body fields must be unaffected", approved.BoardApprovalNotes)
	}
}

// TestActorFieldsAreNotOnTheWire pins the structural half of the fix: the
// #3146 precedent is to DELETE the body fields rather than merely ignore them,
// so a future reader cannot re-wire an identity the caller can type. These
// structs are request-only, so json:"-" removes the field from the wire in
// both directions.
func TestActorFieldsAreNotOnTheWire(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		decode  func(string) (map[string]string, error)
	}{
		{"CreateAuditExportRequest", `{"requested_by":"x","requested_by_email":"x@y.z"}`,
			func(s string) (map[string]string, error) {
				var v CreateAuditExportRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"RequestedBy": v.RequestedBy, "RequestedByEmail": v.RequestedByEmail}, err
			}},
		{"GenerateReportRequest", `{"generated_by":"x","generated_by_email":"x@y.z"}`,
			func(s string) (map[string]string, error) {
				var v GenerateReportRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"GeneratedBy": v.GeneratedBy, "GeneratedByEmail": v.GeneratedByEmail}, err
			}},
		{"SubmitForApprovalRequest", `{"submitted_by":"x","submitted_by_email":"x@y.z"}`,
			func(s string) (map[string]string, error) {
				var v SubmitForApprovalRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"SubmittedBy": v.SubmittedBy, "SubmittedByEmail": v.SubmittedByEmail}, err
			}},
		{"ApproveReportRequest", `{"approved_by":"x","approved_by_email":"x@y.z"}`,
			func(s string) (map[string]string, error) {
				var v ApproveReportRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"ApprovedBy": v.ApprovedBy, "ApprovedByEmail": v.ApprovedByEmail}, err
			}},
		{"RejectReportRequest", `{"rejected_by":"x","rejected_by_email":"x@y.z"}`,
			func(s string) (map[string]string, error) {
				var v RejectReportRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"RejectedBy": v.RejectedBy, "RejectedByEmail": v.RejectedByEmail}, err
			}},
		{"ActivateKillSwitchRequest", `{"actor_id":"x","actor_email":"x@y.z","actor_role":"r","actor_ip":"1.2.3.4"}`,
			func(s string) (map[string]string, error) {
				var v ActivateKillSwitchRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"ActorID": v.ActorID, "ActorEmail": v.ActorEmail,
					"ActorRole": v.ActorRole, "ActorIP": v.ActorIP}, err
			}},
		{"DeactivateKillSwitchRequest", `{"actor_id":"x","actor_email":"x@y.z","actor_role":"r","actor_ip":"1.2.3.4"}`,
			func(s string) (map[string]string, error) {
				var v DeactivateKillSwitchRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"ActorID": v.ActorID, "ActorEmail": v.ActorEmail,
					"ActorRole": v.ActorRole, "ActorIP": v.ActorIP}, err
			}},
		{"BoardApprovalRequest", `{"approver":"x"}`,
			func(s string) (map[string]string, error) {
				var v BoardApprovalRequest
				err := json.Unmarshal([]byte(s), &v)
				return map[string]string{"Approver": v.Approver}, err
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields, err := tc.decode(tc.payload)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(fields) == 0 {
				t.Fatal("no fields inspected — the case is vacuous")
			}
			for name, got := range fields {
				if got != "" {
					t.Errorf("%s.%s decoded %q from the request body", tc.name, name, got)
				}
			}
		})
	}
}

// TestNoRBIHandlerReadsAnActorFromTheBody is the class guard. The eight
// handlers this issue names were found by reading the module; this fails if a
// ninth appears.
func TestNoRBIHandlerReadsAnActorFromTheBody(t *testing.T) {
	// Every json tag in this package that names an acting principal must be
	// `-`. Tags describing a SUBJECT rather than an actor (owner_email on an AI
	// system, assigned_to on a corrective action, detected_by which is a
	// DetectionMethod enum) are legitimately caller-supplied and are not in
	// this set.
	forbidden := []string{
		"requested_by", "requested_by_email",
		"generated_by", "generated_by_email",
		"submitted_by", "submitted_by_email",
		"approved_by", "approved_by_email",
		"rejected_by", "rejected_by_email",
		"actor_id", "actor_email", "actor_role", "actor_ip",
		"approver",
	}

	// The request types are the wire surface; the read models (AuditExport,
	// BoardReport, KillSwitchHistoryEntry, AISystem) legitimately serialise
	// these values back out, so only decode targets are policed.
	requestTypes := map[string]any{
		"CreateAuditExportRequest":    &CreateAuditExportRequest{},
		"GenerateReportRequest":       &GenerateReportRequest{},
		"SubmitForApprovalRequest":    &SubmitForApprovalRequest{},
		"ApproveReportRequest":        &ApproveReportRequest{},
		"RejectReportRequest":         &RejectReportRequest{},
		"ActivateKillSwitchRequest":   &ActivateKillSwitchRequest{},
		"DeactivateKillSwitchRequest": &DeactivateKillSwitchRequest{},
		"BoardApprovalRequest":        &BoardApprovalRequest{},
	}

	for name, v := range requestTypes {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var probe map[string]any
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		for _, tag := range forbidden {
			if _, present := probe[tag]; present {
				t.Errorf("%s still exposes %q on the wire", name, tag)
			}
		}
	}
}
