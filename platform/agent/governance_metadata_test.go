// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Tests for the governance-plane metadata exemption (#2803, epic #2800): an
// override justification containing the very strings a content policy blocks
// (`.env`, `eval`, `REVOKE`, `0.0.0.0/0`) must never be blocked by that policy,
// while the override's TARGET scope fields stay fully governed.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// partnerJustification is the DoD regression justification: it contains all
// four trigger strings from the partner report (.env, eval, REVOKE,
// 0.0.0.0/0) in one plausible free-text explanation.
const partnerJustification = `Documentation-only Jira edit: need to describe the .env file layout, the 0.0.0.0/0 ingress rule removal, and the local eval workflow. I will REVOKE access immediately after the single edit call. Command being documented: echo "KEY=value" > .env`

// jqMarshal serializes like the plugins' `jq -c` does — compact, WITHOUT
// HTML escaping (json.Marshal would rewrite `>` as `\u003e` and hide the
// shell-redirection shapes these tests depend on).
func jqMarshal(t *testing.T, v interface{}) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("jqMarshal: %v", err)
	}
	return strings.TrimRight(buf.String(), "\n")
}

func TestGovernedToolName(t *testing.T) {
	cases := []struct {
		connectorType string
		want          string
	}{
		// Claude Code hook form for an MCP tool: claude_code.mcp__<server>__<tool>
		// (the server segment is user-chosen and must not matter).
		{"claude_code.mcp__axonflow__create_override", "create_override"},
		{"claude_code.mcp__axonflow-governance__create_override", "create_override"},
		{"openclaw.mcp__ax__create_override", "create_override"},
		// Built-in tool form: <client>.<ToolName>. The segment is returned
		// verbatim (no case-folding) so the exemption match stays exact.
		{"claude_code.Bash", "Bash"},
		{"claude_code.Write", "Write"},
		// Bare tool name (direct API callers).
		{"create_override", "create_override"},
		{"CREATE_OVERRIDE", "CREATE_OVERRIDE"},
		// Ordinary connectors.
		{"postgres", "postgres"},
		{"", ""},
	}
	for _, c := range cases {
		if got := governedToolName(c.connectorType); got != c.want {
			t.Errorf("governedToolName(%q) = %q, want %q", c.connectorType, got, c.want)
		}
	}
}

func TestStripGovernanceMetadata(t *testing.T) {
	overrideStatement := func(reason string) string {
		return jqMarshal(t, map[string]interface{}{
			"policy_id":       "sys_dangerous_agent_config",
			"policy_type":     "static",
			"override_reason": reason,
			"tool_signature":  "editJiraIssue",
			"ttl_seconds":     3600,
		})
	}

	t.Run("strips override_reason for create_override, keeps scope fields", func(t *testing.T) {
		raw := overrideStatement(partnerJustification)
		sanitized, stripped := stripGovernanceMetadata("claude_code.mcp__axonflow__create_override", raw)
		if len(stripped) != 1 || stripped[0] != "override_reason" {
			t.Fatalf("stripped = %v, want [override_reason]", stripped)
		}
		if strings.Contains(sanitized, ".env") || strings.Contains(sanitized, "REVOKE") ||
			strings.Contains(sanitized, "eval") || strings.Contains(sanitized, "0.0.0.0/0") {
			t.Errorf("sanitized statement still carries justification content: %s", sanitized)
		}
		// The override TARGET scope must survive sanitization — it is still
		// governed content (#2803: no blanket exemption of the request object).
		for _, keep := range []string{"sys_dangerous_agent_config", "static", "editJiraIssue", "ttl_seconds"} {
			if !strings.Contains(sanitized, keep) {
				t.Errorf("sanitized statement lost scope field content %q: %s", keep, sanitized)
			}
		}
	})

	t.Run("no exemption for non-governance tools", func(t *testing.T) {
		raw := overrideStatement(partnerJustification)
		for _, ct := range []string{"claude_code.mcp__jira__editJiraIssue", "claude_code.Bash", "postgres"} {
			sanitized, stripped := stripGovernanceMetadata(ct, raw)
			if sanitized != raw || stripped != nil {
				t.Errorf("%s: an override_reason field on a non-governance tool must NOT be exempt", ct)
			}
		}
	})

	t.Run("non-JSON statement is evaluated as-is (fail closed)", func(t *testing.T) {
		raw := "plain text mentioning .env with no JSON structure"
		sanitized, stripped := stripGovernanceMetadata("claude_code.mcp__ax__create_override", raw)
		if sanitized != raw || stripped != nil {
			t.Errorf("non-JSON statement must pass through unchanged, got %q / %v", sanitized, stripped)
		}
	})

	t.Run("JSON array statement is evaluated as-is (fail closed)", func(t *testing.T) {
		raw := `[{"override_reason":".env"}]`
		sanitized, stripped := stripGovernanceMetadata("claude_code.mcp__ax__create_override", raw)
		if sanitized != raw || stripped != nil {
			t.Errorf("JSON-array statement must pass through unchanged, got %q / %v", sanitized, stripped)
		}
	})

	t.Run("nested same-named key is NOT stripped", func(t *testing.T) {
		raw := `{"policy_id":"p1","policy_type":"static","payload":{"override_reason":"echo x > .env"}}`
		sanitized, stripped := stripGovernanceMetadata("claude_code.mcp__ax__create_override", raw)
		if sanitized != raw || stripped != nil {
			t.Errorf("nested override_reason is payload, not metadata; must pass through unchanged")
		}
	})

	t.Run("absent metadata field passes through unchanged", func(t *testing.T) {
		raw := `{"policy_id":"p1","policy_type":"static"}`
		sanitized, stripped := stripGovernanceMetadata("claude_code.mcp__ax__create_override", raw)
		if sanitized != raw || stripped != nil {
			t.Errorf("statement without metadata fields must pass through unchanged")
		}
	})

	// #2803 R3 finding 1: the exemption is bound to the AxonFlow override SHAPE.
	// A tool merely named create_override that lacks the required scope fields is
	// NOT exempted — so a third-party tool with a colliding name can't get its
	// override_reason smuggled past evaluation.
	t.Run("missing required scope fields → not exempt (shape guard)", func(t *testing.T) {
		for _, raw := range []string{
			`{"override_reason":"echo x > .env"}`,                        // no policy_id/policy_type
			`{"policy_id":"p1","override_reason":"echo x > .env"}`,       // policy_id only
			`{"policy_type":"static","override_reason":"echo x > .env"}`, // policy_type only
		} {
			sanitized, stripped := stripGovernanceMetadata("srv.mcp__thirdparty__create_override", raw)
			if sanitized != raw || stripped != nil {
				t.Errorf("statement not matching the AxonFlow override shape must NOT be exempt: %q", raw)
			}
		}
	})

	// #2803 R3 finding 2: duplicate top-level keys would be collapsed to the last
	// value on re-serialize, which could drop dangerous content from a KEPT scope
	// field. Fail closed: evaluate the raw statement in full (no strip).
	t.Run("duplicate top-level key → fail closed (evaluate raw)", func(t *testing.T) {
		raw := `{"policy_id":"p1","policy_type":"static","tool_signature":"echo x > .env","tool_signature":"safe","override_reason":"x"}`
		sanitized, stripped := stripGovernanceMetadata("claude_code.mcp__ax__create_override", raw)
		if sanitized != raw || stripped != nil {
			t.Errorf("duplicate-key statement must be evaluated raw (fail closed), got sanitized=%q stripped=%v", sanitized, stripped)
		}
	})
}

func TestHasDuplicateTopLevelKey(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"no dups", `{"a":1,"b":2,"c":3}`, false},
		{"top-level dup", `{"a":1,"a":2}`, true},
		{"dup after nested object", `{"a":{"x":1},"a":2}`, true},
		{"nested key same as top not a dup", `{"a":{"b":1},"b":2}`, false},
		{"nested array with objects", `{"a":[{"b":1},{"b":2}],"c":3}`, false},
		{"dup separated by nested", `{"x":1,"y":{"x":9},"x":2}`, true},
		{"not an object", `["a","a"]`, false},
		{"empty object", `{}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasDuplicateTopLevelKey(c.in); got != c.want {
				t.Errorf("hasDuplicateTopLevelKey(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestStripGovernanceMetadata_PatternProof reproduces the partner's meta-bug
// against the REAL sys_dangerous_agent_config patterns: the raw create_override
// statement matches (that is the reported block), the sanitized statement does
// not, and content smuggled into the TARGET scope (tool_signature) still
// matches after sanitization. Proven against BOTH the original migration-059
// pattern and the migration-135 hardened pattern, because #2803 must hold with
// or without #2802 (the workstreams ship independently).
func TestStripGovernanceMetadata_PatternProof(t *testing.T) {
	patterns := map[string]*regexp.Regexp{
		"migration-059 original": regexp.MustCompile(`(\.env\b|\.env\.local|\.env\.production|credentials\.json|service-account\.json)`),
		"migration-135 hardened": regexp.MustCompile(`(?m)(?:(?:\b(?:rm|del|mv|cp|tee|touch|chmod|chown|truncate|unlink|shred|ln|install|sed)\s+(?:(?:-{1,2}[\w=/,.:@-]+|[0-7]{3,4}|[\w-]*[/.~][\w~./\\-]*|'[^'\r\n]{0,80}'|"[^"\r\n]{0,80}")\s+){0,5}|[^\r\n>][ \t]*>>?[ \t]*|\bof=|\bopen\s*\(\s*['"]?|\b(?:curl|wget)\b[^\r\n;|&]{0,120}\s(?:-o|-O|--output|--output-document)\s+)['"]?[\w~./\\-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json)\b|^[ \t]*['"]?[\w~./\\-]*(?:\.env(?:\.\w+)?|credentials\.json|service-account\.json)['"]?[ \t]*$)`),
	}

	justified := jqMarshal(t, map[string]interface{}{
		"policy_id":       "sys_dangerous_agent_config",
		"policy_type":     "static",
		"override_reason": partnerJustification,
	})
	smuggled := jqMarshal(t, map[string]interface{}{
		"policy_id":       "sys_dangerous_agent_config",
		"policy_type":     "static",
		"override_reason": "legitimate reason",
		"tool_signature":  `echo "KEY=x" > .env`,
	})

	for name, re := range patterns {
		t.Run(name, func(t *testing.T) {
			if !re.MatchString(justified) {
				t.Fatalf("raw statement does not match — not a reproduction of the reported block")
			}
			sanitized, stripped := stripGovernanceMetadata("claude_code.mcp__axonflow__create_override", justified)
			if len(stripped) == 0 {
				t.Fatal("expected override_reason to be stripped")
			}
			if re.MatchString(sanitized) {
				t.Errorf("sanitized statement still matches the agent-config pattern — justification not exempt: %s", sanitized)
			}

			// Smuggle-proof: the same content in a TARGET scope field survives
			// sanitization and is still caught.
			sanitizedSmuggle, _ := stripGovernanceMetadata("claude_code.mcp__axonflow__create_override", smuggled)
			if !re.MatchString(sanitizedSmuggle) {
				t.Errorf("content smuggled into tool_signature escaped evaluation after sanitization: %s", sanitizedSmuggle)
			}
		})
	}
}

// TestMCPToolCheckPolicy_OverrideJustification_RealPostgres is the end-to-end
// DoD regression for #2803: against a REAL Postgres carrying the full core
// migration chain and the REAL shared policy engine, a create_override tool
// call whose justification contains all four partner trigger strings is
// ALLOWED, while (a) the same content in the override's tool_signature and
// (b) an override_reason field on a non-governance tool are both still
// BLOCKED.
func TestMCPToolCheckPolicy_OverrideJustification_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres override-justification test")
	}

	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	for _, kv := range []struct{ key, val string }{
		{"app.db_password", "testpass"},
		{"app.deployment_org_id", "local-dev-org"},
		{"app.deployment_kind", "dev"},
		{"app.current_org_id", "local-dev-org"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", kv.key, kv.val); err != nil {
			t.Fatalf("set_config %s: %v", kv.key, err)
		}
	}
	applyAllCoreMigrations(t, db, "../../migrations/core")

	// Point the shared static engine at the migrated DB and pin the MCP
	// detection config so security-dangerous evaluates with action=block
	// (the partner deployment's posture for sys_dangerous_agent_config).
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{
		Enabled:                true,
		PIIAction:              DetectionActionWarn,
		SQLIAction:             DetectionActionWarn,
		SensitiveDataAction:    DetectionActionWarn,
		DangerousQueryAction:   DetectionActionWarn,
		DangerousCommandAction: DetectionActionBlock,
	}
	detectionConfigMu.Unlock()
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(db, sharedpolicy.EngineConfig{}, nil))
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
		sharedpolicy.SetGlobalEngine(origEngine)
	})

	session := &mcpSession{
		tenantID: "t-2803", orgID: "o-2803", clientID: "c-2803",
		userID: "u1", userRole: "admin", userEmail: "dev@example.com",
	}
	callCheckPolicy := func(t *testing.T, connectorType string, args map[string]interface{}) map[string]interface{} {
		t.Helper()
		resp, err := mcpToolCheckPolicy(context.Background(), session, map[string]interface{}{
			"connector_type": connectorType,
			"statement":      jqMarshal(t, args),
			"operation":      "execute",
		})
		if err != nil {
			t.Fatalf("mcpToolCheckPolicy: %v", err)
		}
		m, ok := resp.(map[string]interface{})
		if !ok {
			t.Fatalf("unexpected response type %T", resp)
		}
		return m
	}

	// (1) DoD regression: the override request with the four trigger strings
	// in its justification must be ALLOWED.
	resp := callCheckPolicy(t, "claude_code.mcp__axonflow__create_override", map[string]interface{}{
		"policy_id":       "sys_dangerous_agent_config",
		"policy_type":     "static",
		"override_reason": partnerJustification,
	})
	if allowed, _ := resp["allowed"].(bool); !allowed {
		t.Errorf("override request blocked by its own justification (meta-bug not fixed): %+v", resp)
	}

	// (2) Smuggle-proof: the same dangerous content in the override's TARGET
	// scope (tool_signature) must still be BLOCKED.
	resp = callCheckPolicy(t, "claude_code.mcp__axonflow__create_override", map[string]interface{}{
		"policy_id":       "sys_dangerous_agent_config",
		"policy_type":     "static",
		"override_reason": "legitimate reason",
		"tool_signature":  `echo "KEY=x" > .env`,
	})
	if allowed, _ := resp["allowed"].(bool); allowed {
		t.Errorf("dangerous content in tool_signature escaped evaluation via the metadata exemption: %+v", resp)
	}

	// (3) Tool-identity keying: an override_reason field on a NON-governance
	// tool is ordinary content and must still be BLOCKED.
	//
	// The tool must be non-governance AND non-text-document: capability
	// scoping (#2801, added after this #2803 test) removes execution-class
	// detectors from text-document tools, so routing this dangerous content
	// through editJiraIssue would legitimately allow it (scoped out) and no
	// longer test the override-exemption keying. claude_code.Bash is a
	// non-governance, execution-capable tool where sys_dangerous_agent_config
	// still evaluates — so a block here proves the override exemption is keyed
	// to the governance tool, not that scoping happens to hide the content.
	resp = callCheckPolicy(t, "claude_code.Bash", map[string]interface{}{
		"summary":         "docs",
		"override_reason": `run echo "KEY=x" > .env to finish`,
	})
	if allowed, _ := resp["allowed"].(bool); allowed {
		t.Errorf("non-governance tool call with dangerous content was allowed: %+v", resp)
	}

	// (4) The HTTP surface (POST /api/v1/mcp/check-input) applies the same
	// exemption — the OpenClaw/Cursor/Codex hooks use this endpoint rather
	// than the MCP-server check_policy tool.
	cleanupMode := setupCommunityModeForTest(t)
	defer cleanupMode()
	callCheckInput := func(t *testing.T, connectorType string, args map[string]interface{}) MCPCheckInputResponse {
		t.Helper()
		body, _ := json.Marshal(MCPCheckInputRequest{
			ConnectorType: connectorType,
			Statement:     jqMarshal(t, args),
			TenantID:      "default",
		})
		req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mcpCheckInputHandler(w, req)
		var out MCPCheckInputResponse
		if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
			t.Fatalf("check-input decode (status %d): %v", w.Code, err)
		}
		return out
	}

	inResp := callCheckInput(t, "openclaw.mcp__axonflow__create_override", map[string]interface{}{
		"policy_id":       "sys_dangerous_agent_config",
		"policy_type":     "static",
		"override_reason": partnerJustification,
	})
	if !inResp.Allowed {
		t.Errorf("check-input: override request blocked by its own justification (meta-bug not fixed): block_reason=%q", inResp.BlockReason)
	}
	inResp = callCheckInput(t, "openclaw.mcp__axonflow__create_override", map[string]interface{}{
		"policy_id":       "sys_dangerous_agent_config",
		"policy_type":     "static",
		"override_reason": "legitimate reason",
		"tool_signature":  `echo "KEY=x" > .env`,
	})
	if inResp.Allowed {
		t.Errorf("check-input: dangerous content in tool_signature escaped evaluation via the metadata exemption")
	}
}
