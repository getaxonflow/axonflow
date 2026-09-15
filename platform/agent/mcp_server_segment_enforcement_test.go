// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"
)

// The MCP-server JSON-RPC plane's two tools are decided by the anchored
// engine: check_policy by the mcp:request pass (mcp_request_enforcing_seam.go)
// and check_output by the mcp:response pass (mcp_response_enforcing_seam.go).
// Neither reads governance segments, so neither consults the segment resolver
// for any session, and a resolver that would fail changes no verdict. The gate
// that stood in front of both (#3430) refused a session on behalf of an
// organization's segment-scoped rows, which no longer decide (PRD v11 §1.2).
//
// Both tools take an already-built *mcpSession, so the sessions below set its
// identity fields directly: one stands in for a validated per-user token, the
// other for the client-scoped pseudo-identity a token-less session gets.

// toolRespMap normalizes a tool result into a map, failing the test on any
// error or unexpected shape.
func toolRespMap(t *testing.T, resp interface{}, err error) map[string]interface{} {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("resp not a map: %T", resp)
	}
	return m
}

// authenticatedToolContext is the context requireMCPAuth hands an MCP-server
// tool: the session's credential stamped by stampAuthContext, from the client
// the session was created for.
func authenticatedToolContext(session *mcpSession) context.Context {
	return stampAuthContext(context.Background(), &Client{ID: session.clientID, ClientID: session.clientID, TenantID: session.tenantID, OrgID: session.orgID}, session.authKind)
}

func TestMCPServerTools_AreDecidedWithoutConsultingSegments(t *testing.T) {
	sessions := []struct {
		name    string
		session func() *mcpSession
	}{
		{"a session with a validated per-user token", func() *mcpSession {
			s := &mcpSession{tenantID: "seg-fc-tenant", orgID: "seg-fc-org", userEmail: "erin@corp.example", userID: "erin@corp.example", userRole: "developer", clientID: "seg-mcp-client"}
			s.identityInputs.tokenResolvedIdentity = true
			return s
		}},
		{"a token-less session on the client pseudo-identity", func() *mcpSession {
			return &mcpSession{tenantID: "seg-fc-tenant", orgID: "seg-fc-org", userEmail: mcpClientPseudoIdentityPrefix + "legacy-client", clientID: "legacy-client"}
		}},
	}
	tools := []struct {
		name string
		call func(context.Context, *mcpSession) (interface{}, error)
	}{
		{"check_policy", func(ctx context.Context, s *mcpSession) (interface{}, error) {
			return mcpToolCheckPolicy(ctx, s, map[string]interface{}{"connector_type": "postgres", "statement": "what is the weather forecast"}, pepHandshakeResolution{})
		}},
		{"check_output", func(ctx context.Context, s *mcpSession) (interface{}, error) {
			return mcpToolCheckOutput(ctx, s, map[string]interface{}{"connector_type": "postgres", "message": "totally benign output"}, pepHandshakeResolution{})
		}},
	}

	for _, tool := range tools {
		for _, sc := range sessions {
			t.Run(tool.name+"/"+sc.name, func(t *testing.T) {
				fake := &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}
				withFleetSegmentResolver(t, fake)
				installUsageDBMock(t)

				session := sc.session()
				resp, err := tool.call(authenticatedToolContext(session), session)
				m := toolRespMap(t, resp, err)
				if allowed, _ := m["allowed"].(bool); !allowed {
					t.Fatalf("%s did not allow benign content: %+v", tool.name, m)
				}
				if c := fake.callCount(); c != 0 {
					t.Fatalf("%s consulted the segment resolver %d time(s); the anchored engine reads no segments", tool.name, c)
				}
			})
		}
	}
}
