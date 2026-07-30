package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// #3179: forwardToOrchestrator is the MAIN governance forward — /api/v1/process,
// /api/v1/plan, /api/v1/plan/execute. It builds a FRESH request, so before this
// fix it carried the validated per-user identity only in the BODY, which #3152
// correctly stopped the orchestrator trusting. That left the plane with no
// identity channel at all.
//
// This test pins the header channel. It fails before the fix (both headers
// absent) and passes after.
func TestForwardToOrchestrator_StampsValidatedIdentityHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	prev := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = prev }()

	user := &User{
		Email:    "dev@corp.example",
		Role:     "analyst",
		TenantID: "tenant-a",
	}
	client := &Client{ClientID: "client-1", OrgID: "org-a", TenantID: "tenant-a"}

	if _, err := forwardToOrchestrator(ClientRequest{RequestType: "chat"}, user, client); err != nil {
		t.Fatalf("forward failed: %v", err)
	}

	if v := got.Get("X-User-Email"); v != "dev@corp.example" {
		t.Errorf("X-User-Email = %q, want %q — the validated JWT email must reach the "+
			"orchestrator as a header, not only in the body", v, "dev@corp.example")
	}
	if v := got.Get(sharedidentity.HeaderUserRole); v != "analyst" {
		t.Errorf("%s = %q, want %q — without it a {user.role not_in <privileged>} policy "+
			"stops EXEMPTING a caller whose JWT says they are privileged",
			sharedidentity.HeaderUserRole, v, "analyst")
	}
}

// An anonymous / token-less caller must not acquire a stamped identity. Absence
// has to stay absence: a blank header is a different claim from no claim.
func TestForwardToOrchestrator_NoUser_StampsNoIdentity(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	prev := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = prev }()

	client := &Client{ClientID: "client-1", OrgID: "org-a", TenantID: "tenant-a"}
	if _, err := forwardToOrchestrator(ClientRequest{RequestType: "chat"}, nil, client); err != nil {
		t.Fatalf("forward failed: %v", err)
	}

	if _, ok := got["X-User-Email"]; ok {
		t.Errorf("X-User-Email present with no validated user: %q", got.Get("X-User-Email"))
	}
	if _, ok := got[http.CanonicalHeaderKey(sharedidentity.HeaderUserRole)]; ok {
		t.Errorf("%s present with no validated user: %q",
			sharedidentity.HeaderUserRole, got.Get(sharedidentity.HeaderUserRole))
	}
}
