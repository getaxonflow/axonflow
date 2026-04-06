// Copyright 2025-2026 AxonFlow
package agent

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

func TestAutoDetectIntegration_NilDB(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	AutoDetectIntegration(nil, "openclaw.exec")
	if IsIntegrationActive("openclaw") {
		t.Error("Should not activate without DB")
	}

	AutoDetectIntegration(nil, "claude_code.Bash")
	if IsIntegrationActive("claude-code") {
		t.Error("Should not activate without DB")
	}
}

func TestAutoDetectIntegration_UnknownPrefix(t *testing.T) {
	AutoDetectIntegration(nil, "unknown_system.tool")
}

func TestAutoDetectIntegration_AlreadyActive(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = map[string]bool{"openclaw": true}
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	// Should skip activation because openclaw is already active
	// Even with a nil DB, this exercises the alreadyActive check path
	AutoDetectIntegration(nil, "openclaw.exec")
	if !IsIntegrationActive("openclaw") {
		t.Error("openclaw should still be active")
	}
}

func TestAutoDetectFromClientInfo_NilDB(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	AutoDetectFromClientInfo(nil, "claude-code")
	if IsIntegrationActive("claude-code") {
		t.Error("Should not activate without DB")
	}
}

func TestAutoDetectFromClientInfo_OpenClaw(t *testing.T) {
	AutoDetectFromClientInfo(nil, "openclaw")
}

func TestAutoDetectFromClientInfo_TestClient(t *testing.T) {
	AutoDetectFromClientInfo(nil, "e2e-test")
}

func TestAutoDetectFromClientInfo_Empty(t *testing.T) {
	AutoDetectFromClientInfo(nil, "")
}

func TestAutoDetectFromClientInfo_Unknown(t *testing.T) {
	AutoDetectFromClientInfo(nil, "some-random-client")
}

func TestAutoDetectFromClientInfo_AlreadyActive(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = map[string]bool{"claude-code": true}
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	// Already active — should skip activation
	AutoDetectFromClientInfo(nil, "claude-code")
	if !IsIntegrationActive("claude-code") {
		t.Error("claude-code should still be active")
	}
}

func TestAutoDetectFromClientInfo_CaseVariants(t *testing.T) {
	AutoDetectFromClientInfo(nil, "Claude Code")
	AutoDetectFromClientInfo(nil, "claude_code")
	AutoDetectFromClientInfo(nil, "open-claw")
}

// --- shouldActivate* Tests (DB-independent) ---

func TestShouldActivateForConnector_OpenClaw(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForConnector("openclaw.exec")
	if id != "openclaw" {
		t.Errorf("Expected openclaw, got %s", id)
	}
}

func TestShouldActivateForConnector_ClaudeCode(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForConnector("claude_code.Bash")
	if id != "claude-code" {
		t.Errorf("Expected claude-code, got %s", id)
	}
}

func TestShouldActivateForConnector_AlreadyActive(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = map[string]bool{"openclaw": true}
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForConnector("openclaw.exec")
	if id != "" {
		t.Errorf("Expected empty (already active), got %s", id)
	}
}

func TestShouldActivateForConnector_Unknown(t *testing.T) {
	id := shouldActivateForConnector("unknown.tool")
	if id != "" {
		t.Errorf("Expected empty for unknown, got %s", id)
	}
}

func TestShouldActivateForClient_ClaudeCode(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForClient("claude-code")
	if id != "claude-code" {
		t.Errorf("Expected claude-code, got %s", id)
	}
}

func TestShouldActivateForClient_OpenClaw(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForClient("openclaw")
	if id != "openclaw" {
		t.Errorf("Expected openclaw, got %s", id)
	}
}

func TestShouldActivateForClient_CaseVariants(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	for _, name := range []string{"Claude Code", "claude_code", "open-claw"} {
		id := shouldActivateForClient(name)
		if id == "" {
			t.Errorf("Expected activation for %q, got empty", name)
		}
	}
}

func TestShouldActivateForClient_AlreadyActive(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = map[string]bool{"claude-code": true}
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForClient("claude-code")
	if id != "" {
		t.Errorf("Expected empty (already active), got %s", id)
	}
}

func TestShouldActivateForClient_Empty(t *testing.T) {
	if id := shouldActivateForClient(""); id != "" {
		t.Errorf("Expected empty for empty client, got %s", id)
	}
}

func TestShouldActivateForClient_TestClient(t *testing.T) {
	if id := shouldActivateForClient("e2e-test"); id != "" {
		t.Errorf("Expected empty for test client, got %s", id)
	}
	if id := shouldActivateForClient("axonflow-test"); id != "" {
		t.Errorf("Expected empty for test client, got %s", id)
	}
}

func TestShouldActivateForClient_Unknown(t *testing.T) {
	if id := shouldActivateForClient("random-app"); id != "" {
		t.Errorf("Expected empty for unknown client, got %s", id)
	}
}

func TestShouldActivateForConnector_Cursor(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForConnector("cursor.Bash")
	if id != "cursor" {
		t.Errorf("Expected cursor, got %s", id)
	}
	id = shouldActivateForConnector("cursor.Write")
	if id != "cursor" {
		t.Errorf("Expected cursor for cursor.Write, got %s", id)
	}
}

func TestShouldActivateForConnector_Codex(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	id := shouldActivateForConnector("codex.Bash")
	if id != "codex" {
		t.Errorf("Expected codex, got %s", id)
	}
	id = shouldActivateForConnector("codex.mcp__postgres")
	if id != "codex" {
		t.Errorf("Expected codex for codex.mcp__postgres, got %s", id)
	}
}

func TestShouldActivateForClient_Cursor(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	for _, name := range []string{"cursor", "cursor-ide", "Cursor IDE", "CURSOR"} {
		id := shouldActivateForClient(name)
		if id != "cursor" {
			t.Errorf("Expected cursor for %q, got %s", name, id)
		}
	}
}

func TestShouldActivateForClient_Codex(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	for _, name := range []string{"codex", "openai-codex", "OpenAI Codex", "CODEX"} {
		id := shouldActivateForClient(name)
		if id != "codex" {
			t.Errorf("Expected codex for %q, got %s", name, id)
		}
	}
}

func TestKnownIntegrations_CursorCodexPrefixes(t *testing.T) {
	cursor := findKnownIntegration("cursor")
	if cursor == nil {
		t.Fatal("cursor integration not found")
	}
	if cursor.ConnectorPrefix != "cursor." {
		t.Errorf("Expected connector prefix 'cursor.', got %s", cursor.ConnectorPrefix)
	}
	if cursor.PolicyPrefix != "int_cursor" {
		t.Errorf("Expected policy prefix 'int_cursor', got %s", cursor.PolicyPrefix)
	}

	codex := findKnownIntegration("codex")
	if codex == nil {
		t.Fatal("codex integration not found")
	}
	if codex.ConnectorPrefix != "codex." {
		t.Errorf("Expected connector prefix 'codex.', got %s", codex.ConnectorPrefix)
	}
	if codex.PolicyPrefix != "int_codex" {
		t.Errorf("Expected policy prefix 'int_codex', got %s", codex.PolicyPrefix)
	}
}

func TestGetActiveIntegrations_Empty(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	active := GetActiveIntegrations()
	if len(active) != 0 {
		t.Errorf("Expected 0 active integrations, got %d", len(active))
	}
}

func TestGetActiveIntegrations_WithActive(t *testing.T) {
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = map[string]bool{"openclaw": true, "claude-code": true}
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	active := GetActiveIntegrations()
	if len(active) != 2 {
		t.Errorf("Expected 2 active integrations, got %d", len(active))
	}
}

func TestKnownIntegrations_HasExpectedEntries(t *testing.T) {
	found := map[string]bool{}
	for _, ki := range knownIntegrations {
		found[ki.ID] = true
	}
	if !found["openclaw"] {
		t.Error("Missing openclaw in knownIntegrations")
	}
	if !found["claude-code"] {
		t.Error("Missing claude-code in knownIntegrations")
	}
}

func TestKnownIntegrations_PolicyPrefixMatchesPolicyIDs(t *testing.T) {
	// Verify that policy prefixes match the expected naming convention
	// This prevents the bug where claude-code's policies couldn't be activated
	// because the prefix didn't match the policy_id pattern
	expectedPrefixes := map[string]string{
		"openclaw":    "int_openclaw",
		"claude-code": "int_claude",
		"cursor":      "int_cursor",
		"codex":       "int_codex",
	}

	for _, ki := range knownIntegrations {
		expected, ok := expectedPrefixes[ki.ID]
		if !ok {
			t.Errorf("Unknown integration %s — add expected prefix", ki.ID)
			continue
		}
		if ki.PolicyPrefix != expected {
			t.Errorf("Integration %s: PolicyPrefix=%q, expected=%q", ki.ID, ki.PolicyPrefix, expected)
		}
		// Policy prefix must NOT contain dashes (SQL LIKE doesn't match them in policy_ids)
		if strings.Contains(ki.PolicyPrefix, "-") {
			t.Errorf("Integration %s: PolicyPrefix %q contains dash — policy_ids use underscores", ki.ID, ki.PolicyPrefix)
		}
	}
}

func TestFindKnownIntegration_Found(t *testing.T) {
	ki := findKnownIntegration("openclaw")
	if ki == nil {
		t.Fatal("Expected to find openclaw")
	}
	if ki.DisplayName != "OpenClaw" {
		t.Errorf("Expected OpenClaw, got %s", ki.DisplayName)
	}
}

func TestFindKnownIntegration_ClaudeCode(t *testing.T) {
	ki := findKnownIntegration("claude-code")
	if ki == nil {
		t.Fatal("Expected to find claude-code")
	}
	if ki.PolicyPrefix != "int_claude" {
		t.Errorf("Expected int_claude, got %s", ki.PolicyPrefix)
	}
}

func TestFindKnownIntegration_NotFound(t *testing.T) {
	ki := findKnownIntegration("nonexistent")
	if ki != nil {
		t.Error("Expected nil for nonexistent integration")
	}
}

func TestMatchIntegrationByConnector_OpenClaw(t *testing.T) {
	ki := matchIntegrationByConnector("openclaw.exec")
	if ki == nil || ki.ID != "openclaw" {
		t.Errorf("Expected openclaw, got %v", ki)
	}
}

func TestMatchIntegrationByConnector_ClaudeCode(t *testing.T) {
	ki := matchIntegrationByConnector("claude_code.Bash")
	if ki == nil || ki.ID != "claude-code" {
		t.Errorf("Expected claude-code, got %v", ki)
	}
}

func TestMatchIntegrationByConnector_Unknown(t *testing.T) {
	ki := matchIntegrationByConnector("unknown.tool")
	if ki != nil {
		t.Error("Expected nil for unknown connector")
	}
}

func TestMatchIntegrationByConnector_MCP(t *testing.T) {
	ki := matchIntegrationByConnector("claude_code.mcp__postgres")
	if ki == nil || ki.ID != "claude-code" {
		t.Errorf("Expected claude-code for MCP tool, got %v", ki)
	}
}

func TestMatchIntegrationByConnector_OpenClawMessage(t *testing.T) {
	ki := matchIntegrationByConnector("openclaw.message_sending")
	if ki == nil || ki.ID != "openclaw" {
		t.Errorf("Expected openclaw for message_sending, got %v", ki)
	}
}

func TestActivateIntegration_UnknownID(t *testing.T) {
	// Should log warning but not panic
	activateIntegration(nil, "nonexistent-integration", "test")
}

func TestActivateIntegrationsFromEnv_NoEnv(t *testing.T) {
	// No AXONFLOW_INTEGRATIONS set — should be a no-op
	ActivateIntegrationsFromEnv(nil)
}

func TestActivateIntegrationsFromEnv_EmptyString(t *testing.T) {
	os.Setenv("AXONFLOW_INTEGRATIONS", "")
	defer os.Unsetenv("AXONFLOW_INTEGRATIONS")
	ActivateIntegrationsFromEnv(nil)
}

func TestActivateIntegrationsFromEnv_WithValues(t *testing.T) {
	os.Setenv("AXONFLOW_INTEGRATIONS", "openclaw,claude-code")
	defer os.Unsetenv("AXONFLOW_INTEGRATIONS")
	// DB is nil so activation won't happen, but the parsing should work without panic
	ActivateIntegrationsFromEnv(nil)
}

func TestKnownIntegrations_ConnectorPrefixEndsWithDot(t *testing.T) {
	for _, ki := range knownIntegrations {
		if !strings.HasSuffix(ki.ConnectorPrefix, ".") {
			t.Errorf("Integration %s: ConnectorPrefix %q should end with '.'", ki.ID, ki.ConnectorPrefix)
		}
	}
}

// =============================================================================
// Integration Tests (require DATABASE_URL or skip)
// These tests run in CI where PostgreSQL is available.
// =============================================================================

func getIntegrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping integration test: DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Database ping failed: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestIntegration_ActivateOpenClaw(t *testing.T) {
	db := getIntegrationTestDB(t)

	// Reset state
	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	// Ensure the activation function exists and integration_activations table exists
	// (migration 060 creates both)
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'integration_activations')").Scan(&exists)
	if err != nil || !exists {
		t.Skip("integration_activations table not found (migration 060 not applied)")
	}

	// Activate openclaw
	activateIntegration(db, "openclaw", "test")

	if !IsIntegrationActive("openclaw") {
		t.Error("Expected openclaw to be active after activation")
	}

	// Check activation was recorded in DB
	var activatedBy string
	err = db.QueryRow("SELECT activated_by FROM integration_activations WHERE integration_id = 'openclaw'").Scan(&activatedBy)
	if err != nil {
		t.Fatalf("Failed to query activation record: %v", err)
	}
	if activatedBy != "test" {
		t.Errorf("Expected activated_by 'test', got '%s'", activatedBy)
	}
}

func TestIntegration_ActivateClaudeCode(t *testing.T) {
	db := getIntegrationTestDB(t)

	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'integration_activations')").Scan(&exists)
	if err != nil || !exists {
		t.Skip("integration_activations table not found")
	}

	activateIntegration(db, "claude-code", "test")

	if !IsIntegrationActive("claude-code") {
		t.Error("Expected claude-code to be active after activation")
	}
}

func TestIntegration_ActivateFromEnv(t *testing.T) {
	db := getIntegrationTestDB(t)

	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'integration_activations')").Scan(&exists)
	if err != nil || !exists {
		t.Skip("integration_activations table not found")
	}

	os.Setenv("AXONFLOW_INTEGRATIONS", "openclaw,claude-code")
	defer os.Unsetenv("AXONFLOW_INTEGRATIONS")

	ActivateIntegrationsFromEnv(db)

	if !IsIntegrationActive("openclaw") {
		t.Error("Expected openclaw to be active")
	}
	if !IsIntegrationActive("claude-code") {
		t.Error("Expected claude-code to be active")
	}

	active := GetActiveIntegrations()
	if len(active) < 2 {
		t.Errorf("Expected at least 2 active integrations, got %d", len(active))
	}
}

func TestIntegration_AutoDetectByConnector(t *testing.T) {
	db := getIntegrationTestDB(t)

	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'integration_activations')").Scan(&exists)
	if err != nil || !exists {
		t.Skip("integration_activations table not found")
	}

	// Auto-detect via connector type
	AutoDetectIntegration(db, "openclaw.exec")

	if !IsIntegrationActive("openclaw") {
		t.Error("Expected openclaw to be auto-activated from connector type")
	}

	// Calling again should be a no-op (already active)
	AutoDetectIntegration(db, "openclaw.web_fetch")
	// No error expected
}

func TestIntegration_AutoDetectByClient(t *testing.T) {
	db := getIntegrationTestDB(t)

	activatedIntegrationsMu.Lock()
	original := activatedIntegrations
	activatedIntegrations = make(map[string]bool)
	activatedIntegrationsMu.Unlock()
	defer func() {
		activatedIntegrationsMu.Lock()
		activatedIntegrations = original
		activatedIntegrationsMu.Unlock()
	}()

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'integration_activations')").Scan(&exists)
	if err != nil || !exists {
		t.Skip("integration_activations table not found")
	}

	AutoDetectFromClientInfo(db, "claude-code")

	if !IsIntegrationActive("claude-code") {
		t.Error("Expected claude-code to be auto-activated from client info")
	}
}

func TestIntegration_ActivateUnknown(t *testing.T) {
	db := getIntegrationTestDB(t)

	// Should log warning but not fail
	activateIntegration(db, "nonexistent", "test")

	if IsIntegrationActive("nonexistent") {
		t.Error("Should not activate unknown integration")
	}
}
