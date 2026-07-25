// Copyright 2025-2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// Integration Policy Activation
//
// Manages the lifecycle of integration-specific policies. Policies are
// pre-loaded as disabled in the database (migration 060). When an integration
// is detected — either via AXONFLOW_INTEGRATIONS env var or auto-detection
// from incoming requests — its policies are enabled.
//
// Known integrations:
//   openclaw    → connector prefix "openclaw."    → protects SOUL.md, MEMORY.md, etc.
//   claude-code → connector prefix "claude_code." → protects .claude/settings, hooks
//
// This avoids runtime migrations. Only UPDATE statements on existing rows.
// =============================================================================

// KnownIntegration describes a supported integration and its activation metadata.
type KnownIntegration struct {
	ID              string // e.g., "openclaw", "claude-code"
	DisplayName     string // e.g., "OpenClaw", "Claude Code"
	ConnectorPrefix string // e.g., "openclaw.", "claude_code."
	PolicyPrefix    string // e.g., "int_openclaw", "int_claude" (matches policy_id naming)
}

// knownIntegrations is the registry of supported integrations.
// PolicyPrefix must match the actual policy_id prefix in migration 060.
//
// claude-desktop is registry-only: it is the canonical ID for the Claude
// Desktop MCP governance proxy (axonflow-claude-desktop-plugin) so /health
// can advertise its min/recommended versions (capabilities.go lockstep).
// It never auto-activates — the proxy governs via HTTP decide/check-output
// (not the agent's MCP clientInfo handshake) and fronts arbitrary backend
// servers, so no "claude_desktop." connector types exist in practice, and
// migration 060 carries no int_desktop policies to enable (the activation
// function UPDATEs zero rows if it is ever invoked explicitly). The prefix
// deliberately avoids claude-code's "int_claude" LIKE-prefix so neither
// activation can ever shadow the other's policy set.
var knownIntegrations = []KnownIntegration{
	{ID: "openclaw", DisplayName: "OpenClaw", ConnectorPrefix: "openclaw.", PolicyPrefix: "int_openclaw"},
	{ID: "claude-code", DisplayName: "Claude Code", ConnectorPrefix: "claude_code.", PolicyPrefix: "int_claude"},
	{ID: "cursor", DisplayName: "Cursor IDE", ConnectorPrefix: "cursor.", PolicyPrefix: "int_cursor"},
	{ID: "codex", DisplayName: "OpenAI Codex", ConnectorPrefix: "codex.", PolicyPrefix: "int_codex"},
	{ID: "claude-desktop", DisplayName: "Claude Desktop", ConnectorPrefix: "claude_desktop.", PolicyPrefix: "int_desktop"},
}

var (
	activatedIntegrations   = make(map[string]bool)
	activatedIntegrationsMu sync.RWMutex
)

// ActivateIntegrationsFromEnv reads AXONFLOW_INTEGRATIONS env var and activates
// each listed integration. Called once at startup after database is connected.
//
// Example: AXONFLOW_INTEGRATIONS=openclaw,claude-code
func ActivateIntegrationsFromEnv(db *sql.DB) {
	envValue := os.Getenv("AXONFLOW_INTEGRATIONS")
	if envValue == "" {
		return
	}

	for _, id := range strings.Split(envValue, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		activateIntegration(db, id, "env:AXONFLOW_INTEGRATIONS")
	}
}

// AutoDetectIntegration checks if a connector type belongs to a known integration
// and activates it if not already active. Called on every check_policy/check_output
// call — the check is fast (in-memory map lookup) and only hits the DB on first detection.
func AutoDetectIntegration(db *sql.DB, connectorType string) {
	integrationID := shouldActivateForConnector(connectorType)
	if integrationID == "" || db == nil {
		return
	}
	activateIntegration(db, integrationID, "auto-detect:"+connectorType)
}

// shouldActivateForConnector checks if a connector type matches a known
// integration that isn't already active. Returns the integration ID to
// activate, or empty string if no activation needed.
func shouldActivateForConnector(connectorType string) string {
	integration := matchIntegrationByConnector(connectorType)
	if integration == nil {
		return ""
	}

	activatedIntegrationsMu.RLock()
	alreadyActive := activatedIntegrations[integration.ID]
	activatedIntegrationsMu.RUnlock()

	if alreadyActive {
		return ""
	}
	return integration.ID
}

// AutoDetectFromClientInfo activates an integration based on MCP client info.
// Called during MCP initialize when clientInfo.name matches a known integration.
func AutoDetectFromClientInfo(db *sql.DB, clientName string) {
	integrationID := shouldActivateForClient(clientName)
	if integrationID == "" || db == nil {
		return
	}
	activateIntegration(db, integrationID, "auto-detect:client:"+clientName)
}

// shouldActivateForClient checks if a client name matches a known integration
// that isn't already active. Returns the integration ID, or empty string.
func shouldActivateForClient(clientName string) string {
	if clientName == "" {
		return ""
	}

	clientName = strings.ToLower(clientName)

	clientMappings := map[string]string{
		"claude-code":   "claude-code",
		"claude_code":   "claude-code",
		"claude code":   "claude-code",
		"openclaw":      "openclaw",
		"open-claw":     "openclaw",
		"cursor":        "cursor",
		"cursor-ide":    "cursor",
		"cursor ide":    "cursor",
		"codex":         "codex",
		"openai-codex":  "codex",
		"openai codex":  "codex",
		"axonflow-test": "",
		"e2e-test":      "",
	}

	integrationID, known := clientMappings[clientName]
	if !known || integrationID == "" {
		return ""
	}

	activatedIntegrationsMu.RLock()
	alreadyActive := activatedIntegrations[integrationID]
	activatedIntegrationsMu.RUnlock()

	if alreadyActive {
		return ""
	}
	return integrationID
}

// IsIntegrationActive returns whether a specific integration's policies are enabled.
func IsIntegrationActive(integrationID string) bool {
	activatedIntegrationsMu.RLock()
	defer activatedIntegrationsMu.RUnlock()
	return activatedIntegrations[integrationID]
}

// GetActiveIntegrations returns a list of currently active integration IDs.
func GetActiveIntegrations() []string {
	activatedIntegrationsMu.RLock()
	defer activatedIntegrationsMu.RUnlock()

	result := make([]string, 0, len(activatedIntegrations))
	for id, active := range activatedIntegrations {
		if active {
			result = append(result, id)
		}
	}
	return result
}

// findKnownIntegration looks up an integration by ID in the registry.
// Returns nil if not found.
func findKnownIntegration(integrationID string) *KnownIntegration {
	for i := range knownIntegrations {
		if knownIntegrations[i].ID == integrationID {
			return &knownIntegrations[i]
		}
	}
	return nil
}

// matchIntegrationByConnector finds which integration a connector type belongs to.
// Returns nil if no known integration matches.
//
// Matches either the legacy composite form (connectorType has the registered
// "prefix." — e.g. "claude_code.Bash") OR an exact bare-server match against
// the prefix with its trailing dot trimmed (e.g. connectorType == "claude_code").
// The latter covers #2904's split (server, tool) schema: once a caller sends
// connector_type="claude_code" alone (tool carried separately), the method
// name that used to follow the dot is gone, but the server name alone is
// still a complete, unambiguous signal — dropping it here would silently stop
// activating a tenant's int_claude_* policies for any migrated caller.
func matchIntegrationByConnector(connectorType string) *KnownIntegration {
	for i := range knownIntegrations {
		prefix := knownIntegrations[i].ConnectorPrefix
		if strings.HasPrefix(connectorType, prefix) || connectorType == strings.TrimSuffix(prefix, ".") {
			return &knownIntegrations[i]
		}
	}
	return nil
}

// activateIntegration enables an integration's policies in the database.
func activateIntegration(db *sql.DB, integrationID, activatedBy string) {
	if db == nil {
		return
	}

	integration := findKnownIntegration(integrationID)
	if integration == nil {
		log.Printf("[Integration] Unknown integration: %s (skipping)", logutil.Sanitize(integrationID))
		return
	}

	// Call the database activation function
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// #3048 census: activate_integration is a plain (SECURITY INVOKER)
	// plpgsql function whose body UPDATEs static_policies rows with
	// tenant_id='global' / org_id='global'. static_policies is RLS-enabled
	// (mig 018), so under axonflow_app_role the UPDATE's USING predicate saw
	// zero rows with the GUC unset — activation "succeeded" with
	// policy_count=0 and the integration's int_* policies silently never
	// enabled on app-role deployments. Wrap in the 'global' org scope so the
	// UPDATE sees (and WITH CHECK re-admits) the global rows. The call slips
	// past the write-audit static test because it is lexically a SELECT.
	var policyCount int
	err := WithOrgScope(ctx, db, GlobalOrgSentinel, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			"SELECT activate_integration($1, $2, $3, $4, $5)",
			integration.ID, integration.DisplayName, integration.ConnectorPrefix, integration.PolicyPrefix, activatedBy,
		).Scan(&policyCount)
	})

	if err != nil {
		log.Printf("[Integration] Failed to activate %s: %v", logutil.Sanitize(integrationID), err)
		return
	}

	activatedIntegrationsMu.Lock()
	activatedIntegrations[integrationID] = true
	activatedIntegrationsMu.Unlock()

	if policyCount > 0 {
		log.Printf("[Integration] ✅ Activated %s: %d policies enabled (by: %s)",
			logutil.Sanitize(integration.DisplayName), policyCount, logutil.Sanitize(activatedBy))

		// Invalidate ALL tenant caches so the newly enabled policies take
		// effect immediately. Integration policies use tenant_id='global'
		// which is included in every tenant's effective policy set. A
		// per-tenant invalidation would miss tenants with warm caches,
		// leaving a bypass window until TTL expires.
		if engine := sharedpolicy.GetGlobalEngine(); engine != nil {
			engine.InvalidateAllCaches()
			log.Printf("[Integration] All policy caches invalidated for %s", logutil.Sanitize(integration.DisplayName))
		}
	} else {
		log.Printf("[Integration] ✅ %s already active (0 new policies)", logutil.Sanitize(integration.DisplayName))
	}
}
