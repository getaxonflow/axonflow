// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// #2922 agent-plane tests. The AUTHORITATIVE enforcement is server-side
// (orchestrator resolveCallerReadScope); these pin the agent's belt-and-braces
// behavior: the search_audit_events tool injects the caller's OWN identity as
// the user_email filter for a non-admin, honors a user_email arg only for
// admin/owner, and forwards the validated role over the trusted channel.

// captureForward stands up a stub orchestrator, points orchestratorURL at it,
// and returns the decoded JSON body + headers of the single request the tool
// forwards. DEPLOYMENT_MODE is forced to enterprise so sessionCanReadTenant
// keys on the role, not the community bypass.
func captureForward(t *testing.T, session *mcpSession, args map[string]interface{}) (map[string]interface{}, http.Header) {
	t.Helper()
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	t.Cleanup(func() { os.Unsetenv("DEPLOYMENT_MODE") })

	var gotBody map[string]interface{}
	var gotHeader http.Header
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"entries":[]}`))
	}))
	t.Cleanup(stub.Close)

	orig := orchestratorURL
	orchestratorURL = stub.URL
	t.Cleanup(func() { orchestratorURL = orig })

	if _, err := mcpToolSearchAuditEvents(session, args); err != nil {
		t.Fatalf("search tool error: %v", err)
	}
	return gotBody, gotHeader
}

func TestMCPSearch_NonAdmin_InjectsOwnIdentity(t *testing.T) {
	session := &mcpSession{
		tenantID: "tenant-a", clientID: "c1",
		userEmail: "dev@acme.com", userRole: "developer",
	}
	body, hdr := captureForward(t, session, map[string]interface{}{})

	if body["user_email"] != "dev@acme.com" {
		t.Fatalf("non-admin must forward own user_email, got %v", body["user_email"])
	}
	if hdr.Get(sharedidentity.HeaderUserRole) != "developer" {
		t.Fatalf("validated role must be forwarded over the trusted channel, got %q", hdr.Get(sharedidentity.HeaderUserRole))
	}
}

func TestMCPSearch_NonAdmin_UserEmailArgCannotWiden(t *testing.T) {
	session := &mcpSession{
		tenantID: "tenant-a", clientID: "c1",
		userEmail: "dev@acme.com", userRole: "developer",
	}
	// Caller tries to widen to a colleague — must be overridden with own id.
	body, _ := captureForward(t, session, map[string]interface{}{"user_email": "victim@acme.com"})
	if body["user_email"] != "dev@acme.com" {
		t.Fatalf("non-admin user_email arg must NOT widen; got %v", body["user_email"])
	}
}

func TestMCPSearch_Admin_HonorsUserEmailArg(t *testing.T) {
	session := &mcpSession{
		tenantID: "tenant-a", clientID: "c1",
		userEmail: "boss@acme.com", userRole: "admin",
	}
	// Admin may filter by any user; absent arg ⇒ no user_email filter (full).
	body, _ := captureForward(t, session, map[string]interface{}{"user_email": "someone@acme.com"})
	if body["user_email"] != "someone@acme.com" {
		t.Fatalf("admin user_email arg must be honored, got %v", body["user_email"])
	}

	body2, _ := captureForward(t, session, map[string]interface{}{})
	if _, present := body2["user_email"]; present {
		t.Fatalf("admin with no arg must not inject a user_email filter, got %v", body2["user_email"])
	}
}

func TestMCPSearch_LeastPrivilegeRole_InjectsOwnIdentity(t *testing.T) {
	// The reported exploit's exact shape: a shared-credential caller resolves
	// to a client-scoped pseudo-identity with role "" (least-privilege). It
	// must be scoped to that identity — never tenant-wide.
	session := &mcpSession{
		tenantID: "tenant-a", clientID: "c1",
		userEmail: "mcp-client:c1", userRole: "",
	}
	body, hdr := captureForward(t, session, map[string]interface{}{})
	if body["user_email"] != "mcp-client:c1" {
		t.Fatalf("least-privilege caller must be scoped to its own pseudo-identity, got %v", body["user_email"])
	}
	if hdr.Get(sharedidentity.HeaderUserRole) != "" {
		t.Fatalf("least-privilege role must NOT be forwarded as a value, got %q", hdr.Get(sharedidentity.HeaderUserRole))
	}
}

// sessionCanReadTenant unit coverage across the trust ladder.
func TestSessionCanReadTenant(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	cases := map[string]bool{
		"admin": true, "owner": true,
		"developer": false, "member": false, "viewer": false,
		"policy_admin": false, "": false, "root": false,
	}
	for role, want := range cases {
		if got := sessionCanReadTenant(&mcpSession{userRole: role}); got != want {
			t.Errorf("sessionCanReadTenant(role=%q) = %v, want %v", role, got, want)
		}
	}
}

func TestSessionCanReadTenant_CommunityIsTenantWide(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	// Even least-privilege: community single-operator is tenant-wide.
	if !sessionCanReadTenant(&mcpSession{userRole: ""}) {
		t.Fatal("community mode must be tenant-wide regardless of role")
	}
}
