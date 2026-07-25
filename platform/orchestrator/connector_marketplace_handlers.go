// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent"
	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
	"axonflow/platform/connectors/registry"
	logutil "axonflow/platform/shared/logger"
)

// Global connector registry
var connectorRegistry *registry.Registry

// credentialEncryptor handles encryption/decryption of connector credentials at rest.
var credentialEncryptor *config.CredentialEncryptor

// ConnectorMetadata represents connector information for the marketplace
type ConnectorMetadata struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Version      string      `json:"version"`
	Description  string      `json:"description"`
	Category     string      `json:"category"`
	Icon         string      `json:"icon"`
	Tags         []string    `json:"tags"`
	Capabilities []string    `json:"capabilities"`
	ConfigSchema interface{} `json:"config_schema"`
	Installed    bool        `json:"installed"`
	Healthy      bool        `json:"healthy,omitempty"`
	LastCheck    string      `json:"last_check,omitempty"`
}

// ConnectorInstallRequest represents a request to install a connector
type ConnectorInstallRequest struct {
	ConnectorID string                 `json:"connector_id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Options     map[string]interface{} `json:"options"`
	Credentials map[string]string      `json:"credentials"`
}

// buildConnectionURL constructs a connection URL from options and credentials.
// Delegates to base.BuildConnectionURL for the actual URL construction.
func buildConnectionURL(connectorType string, options map[string]interface{}, credentials map[string]string) string {
	return base.BuildConnectionURL(connectorType, options, credentials)
}

// getStringOption safely extracts a string from options map (nil-safe).
func getStringOption(options map[string]interface{}, key, defaultVal string) string {
	return base.GetStringOption(options, key, defaultVal)
}

// getIntOption safely extracts an int from options map (handles float64 from JSON, nil-safe).
func getIntOption(options map[string]interface{}, key string, defaultVal int) int {
	return base.GetIntOption(options, key, defaultVal)
}

// createConnectorInstance is a factory function that creates connector instances by type
func createConnectorInstance(connectorType string) (base.Connector, error) {
	return createConnectorInstanceByType(connectorType)
}

// initializeConnectorRegistry initializes the global connector registry
func initializeConnectorRegistry() {
	// Initialize credential encryption (no-op when CONNECTOR_ENCRYPTION_KEY not set)
	credentialEncryptor = config.NewCredentialEncryptor()
	if credentialEncryptor.IsEnabled() {
		log.Println("Connector credential encryption enabled (AES-256-GCM)")
	} else {
		log.Println("Connector credential encryption disabled (set CONNECTOR_ENCRYPTION_KEY to enable)")
	}

	// Check if DATABASE_URL is available for persistent storage
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		// #3048: the registry's cross-replica sync (ListConnectors) + by-id
		// lazy loads (GetConnector) are deployment-wide reads that match 0
		// rows through mig 107's FORCE RLS on the app-role runtime pool —
		// installed connectors silently vanished from the registry on
		// app-role deployments. Same OpenPlatformAdminConnection split as
		// the #3039 cross-org read pools; nil-with-nil-err means the admin
		// DSN is unset (documented fallback contract for owner-pool
		// deployments).
		registryOpts := []registry.RegistryOption{
			registry.WithEncryptor(credentialEncryptor),
			// v9 Brief 11.5 / Session 20: inject the agent's app-role opener
			// so the connector_registry's runtime pool authenticates as
			// axonflow_app_role and the FORCE RLS policies on connectors +
			// connector_configs (mig 107) gate this code path.
			registry.WithAppRoleOpener(agent.OpenAppRoleConnection),
		}
		if adminDB, adminErr := agent.OpenPlatformAdminConnection(context.Background(), 3); adminErr != nil || adminDB == nil {
			log.Printf("⚠️  connector-registry cross-org read pool: platform-admin pool unavailable (err=%v) — registry sync reads fall back to the runtime pool (under app-role RLS they read 0 rows)", adminErr)
		} else {
			adminDB.SetMaxOpenConns(2)
			adminDB.SetMaxIdleConns(1)
			registryOpts = append(registryOpts, registry.WithCrossOrgDB(adminDB))
		}
		var err error
		connectorRegistry, err = registry.NewRegistryWithStorage(
			dbURL,
			registryOpts...,
		)
		if err != nil {
			log.Printf("Failed to initialize registry with storage: %v. Falling back to in-memory.", err)
			connectorRegistry = registry.NewRegistry()
		} else {
			log.Println("Connector registry initialized with PostgreSQL persistence")

			// Set factory for lazy-loading connectors
			connectorRegistry.SetFactory(createConnectorInstance)

			// Start periodic reload every 30 seconds to sync with other orchestrator instances
			ctx := context.Background()
			connectorRegistry.StartPeriodicReload(ctx, 30*time.Second)
			log.Println("Started periodic connector reload (every 30 seconds)")
		}
	} else {
		connectorRegistry = registry.NewRegistry()
		log.Println("Connector registry initialized with in-memory storage")
	}
}

// getConnectorMetadata returns metadata for all available connectors
func getConnectorMetadata() []ConnectorMetadata {
	return getConnectorMetadataByEdition()
}

// listConnectorsHandler returns all available connectors with their metadata
func listConnectorsHandler(w http.ResponseWriter, r *http.Request) {
	metadata := getConnectorMetadata()

	// Add installation status for each connector
	installedConnectors := connectorRegistry.ListWithTypes()

	for i := range metadata {
		_, installed := installedConnectors[metadata[i].ID]
		metadata[i].Installed = installed

		if installed {
			// Get health status
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			status, err := connectorRegistry.HealthCheckSingle(ctx, metadata[i].ID)
			cancel()
			if err == nil && status != nil {
				metadata[i].Healthy = status.Healthy
				metadata[i].LastCheck = status.Timestamp.Format(time.RFC3339)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"connectors": metadata,
		"total":      len(metadata),
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// getConnectorDetailsHandler returns details for a specific connector
func getConnectorDetailsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	metadata := getConnectorMetadata()

	var found *ConnectorMetadata
	for i := range metadata {
		if metadata[i].ID == connectorID {
			found = &metadata[i]
			break
		}
	}

	if found == nil {
		http.Error(w, "Connector not found", http.StatusNotFound)
		return
	}

	// Add installation status
	installedConnectors := connectorRegistry.ListWithTypes()
	_, installed := installedConnectors[connectorID]
	found.Installed = installed

	if installed {
		// Get health status
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		status, err := connectorRegistry.HealthCheckSingle(ctx, connectorID)
		if err == nil && status != nil {
			found.Healthy = status.Healthy
			found.LastCheck = status.Timestamp.Format(time.RFC3339)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(found); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// installConnectorHandler installs a connector for a tenant
func installConnectorHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	var req ConnectorInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate connector ID
	metadata := getConnectorMetadata()
	var connectorType string
	for i := range metadata {
		if metadata[i].ID == connectorID {
			connectorType = metadata[i].Type
			break
		}
	}

	if connectorType == "" {
		http.Error(w, "Connector not found", http.StatusNotFound)
		return
	}

	// Create connector instance
	connector, err := createConnectorInstanceByType(connectorType)
	if err != nil {
		http.Error(w, "Unsupported connector type", http.StatusBadRequest)
		return
	}

	tenantID := resolveTenantID(r, req.TenantID)
	if usageDB != nil && (tenantID == "" || tenantID == "*") {
		http.Error(w, "tenant_id is required for connector installation", http.StatusBadRequest)
		return
	}
	if tenantID == "" {
		tenantID = "*"
	}

	// Create config with properly constructed ConnectionURL
	displayName := req.Name
	if displayName == "" {
		displayName = connectorID
	}
	config := &base.ConnectorConfig{
		Name:          displayName,
		Type:          connectorType,
		ConnectionURL: buildConnectionURL(connectorType, req.Options, req.Credentials),
		TenantID:      tenantID,
		Options:       req.Options,
		Credentials:   req.Credentials,
		Timeout:       30 * time.Second,
	}

	if err := upsertConnectorConfig(r.Context(), connectorID, connectorType, tenantID, &req, config); err != nil {
		http.Error(w, "Failed to persist connector config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Register connector in-memory; roll back DB write on failure
	if err := connectorRegistry.Register(connectorID, connector, config); err != nil {
		// Best-effort rollback: remove the DB record we just wrote
		if rbErr := deleteConnectorConfig(r.Context(), connectorID, tenantID); rbErr != nil {
			log.Printf("[Connector Marketplace] WARNING: Registry failed and DB rollback also failed for %s: register=%v, rollback=%v", logutil.Sanitize(connectorID), err, rbErr)
		}
		http.Error(w, "Failed to install connector: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      "Connector installed successfully",
		"connector_id": connectorID,
		"name":         req.Name,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// uninstallConnectorHandler uninstalls a connector
func uninstallConnectorHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	tenantID := resolveTenantID(r, "")
	if tenantID == "" && connectorRegistry != nil {
		if cfg, err := connectorRegistry.GetConfig(connectorID); err == nil {
			tenantID = cfg.TenantID
		}
	}
	if usageDB != nil && (tenantID == "" || tenantID == "*") {
		http.Error(w, "tenant_id is required for connector uninstall", http.StatusBadRequest)
		return
	}
	// Unregister from memory first — if this fails, the DB record is still intact
	// and the connector remains consistently registered in both places.
	if err := connectorRegistry.Unregister(connectorID); err != nil {
		http.Error(w, "Failed to uninstall connector: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := deleteConnectorConfig(r.Context(), connectorID, tenantID); err != nil {
		// Memory unregistration succeeded but DB delete failed.
		// Log the error — the orphaned DB record will be harmless (connector
		// can't serve requests without being in the registry) and will be
		// overwritten on re-install.
		log.Printf("Warning: connector %q unregistered from memory but DB delete failed: %v", logutil.Sanitize(connectorID), err)
		http.Error(w, "Failed to delete connector config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Connector uninstalled successfully",
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func resolveTenantID(r *http.Request, requested string) string {
	if requested != "" && requested != "*" {
		return requested
	}
	if headerTenant := r.Header.Get("X-Tenant-ID"); headerTenant != "" {
		return headerTenant
	}
	return requested
}

func upsertConnectorConfig(ctx context.Context, connectorID, connectorType, tenantID string, req *ConnectorInstallRequest, config *base.ConnectorConfig) error {
	if usageDB == nil {
		log.Printf("[Connector Marketplace] usageDB not initialized; skipping connector config upsert")
		return nil
	}

	options := req.Options
	if options == nil {
		options = make(map[string]interface{})
	}
	credentials := req.Credentials
	if credentials == nil {
		credentials = make(map[string]string)
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("failed to serialize options: %w", err)
	}
	var credentialsJSON []byte
	if credentialEncryptor != nil {
		credentialsJSON, err = credentialEncryptor.Encrypt(credentials)
	} else {
		credentialsJSON, err = json.Marshal(credentials)
	}
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %w", err)
	}

	meta := findConnectorMetadata(connectorID)
	displayName := req.Name
	if displayName == "" && meta != nil {
		displayName = meta.Name
	}
	description := ""
	if meta != nil {
		description = meta.Description
	}

	// Build credential-free URL for storage. Credentials are stored separately
	// in the encrypted credentials column and injected at runtime.
	storedURL := buildConnectionURL(connectorType, options, nil)

	timeoutMs := int(config.Timeout / time.Millisecond)
	// v9 Phase 8 B8 (#2339): mig 107 added NOT NULL org_id on connector_configs.
	// Same value as tenant_id at this writer (the historical schema collapse).
	query := `
		INSERT INTO connector_configs (
			tenant_id,
			org_id,
			connector_name,
			connector_type,
			display_name,
			description,
			connection_url,
			options,
			credentials,
			timeout_ms,
			max_retries,
			enabled,
			health_status,
			created_by,
			updated_by
		) VALUES (
			$1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, 'unknown', $11, $11
		)
		ON CONFLICT (tenant_id, connector_name) DO UPDATE SET
			connector_type = EXCLUDED.connector_type,
			display_name = EXCLUDED.display_name,
			description = EXCLUDED.description,
			connection_url = EXCLUDED.connection_url,
			options = EXCLUDED.options,
			credentials = EXCLUDED.credentials,
			timeout_ms = EXCLUDED.timeout_ms,
			max_retries = EXCLUDED.max_retries,
			enabled = EXCLUDED.enabled,
			health_status = EXCLUDED.health_status,
			updated_by = EXCLUDED.updated_by
	`

	// v9 Phase 8 PR-C2 (#2384): connector_configs is FORCE RLS (mig 107) with policy
	// `org_id = current_setting('app.current_org_id', true)`. Under axonflow_app_role
	// the INSERT WITH CHECK gates fail without the GUC. tenantID == orgID at this
	// writer (historical tenant_id collapse) so we wrap the INSERT in WithOrgScope.
	if err := agent.WithOrgScope(ctx, usageDB, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(
			ctx,
			query,
			tenantID,
			connectorID,
			connectorType,
			displayName,
			description,
			storedURL,
			optionsJSON,
			credentialsJSON,
			timeoutMs,
			config.MaxRetries,
			"connector_marketplace",
		)
		return execErr
	}); err != nil {
		return fmt.Errorf("connector config upsert failed: %w", err)
	}

	return nil
}

func deleteConnectorConfig(ctx context.Context, connectorID, tenantID string) error {
	if usageDB == nil {
		log.Printf("[Connector Marketplace] usageDB not initialized; skipping connector config delete")
		return nil
	}
	if tenantID == "" || tenantID == "*" {
		return fmt.Errorf("tenant_id required to delete connector config")
	}

	// v9 Phase 8 PR-C2 (#2384): connector_configs FORCE RLS DELETE policy
	// (`USING org_id = current_setting('app.current_org_id', true)`) silently
	// affects 0 rows under axonflow_app_role without the GUC. Wrap so the
	// DELETE sees its tenant's row + reports rows-affected accurately.
	var rows int64
	if err := agent.WithOrgScope(ctx, usageDB, tenantID, func(tx *sql.Tx) error {
		result, execErr := tx.ExecContext(
			ctx,
			`DELETE FROM connector_configs WHERE tenant_id = $1 AND connector_name = $2`,
			tenantID,
			connectorID,
		)
		if execErr != nil {
			return execErr
		}
		rows, _ = result.RowsAffected()
		return nil
	}); err != nil {
		return fmt.Errorf("connector config delete failed: %w", err)
	}

	if rows == 0 {
		log.Printf("[Connector Marketplace] No connector config found for tenant=%s connector=%s", logutil.Sanitize(tenantID), logutil.Sanitize(connectorID))
	}

	return nil
}

func findConnectorMetadata(connectorID string) *ConnectorMetadata {
	for _, meta := range getConnectorMetadata() {
		if meta.ID == connectorID {
			found := meta
			return &found
		}
	}
	return nil
}

// connectorHealthCheckHandler performs health check on a specific connector
func connectorHealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, err := connectorRegistry.HealthCheckSingle(ctx, connectorID)
	if err != nil {
		http.Error(w, "Health check failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}
