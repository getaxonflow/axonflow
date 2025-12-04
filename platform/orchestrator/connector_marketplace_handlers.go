// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
	httpconnector "axonflow/platform/connectors/http"
	"axonflow/platform/connectors/postgres"
	"axonflow/platform/connectors/redis"
	"axonflow/platform/connectors/registry"
)

// Global connector registry
var connectorRegistry *registry.Registry

// ConnectorMetadata represents connector information for the marketplace
type ConnectorMetadata struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Category     string   `json:"category"`
	Icon         string   `json:"icon"`
	Tags         []string `json:"tags"`
	Capabilities []string `json:"capabilities"`
	ConfigSchema interface{} `json:"config_schema"`
	Installed    bool     `json:"installed"`
	Healthy      bool     `json:"healthy,omitempty"`
	LastCheck    string   `json:"last_check,omitempty"`
}

// ConnectorInstallRequest represents a request to install a connector
type ConnectorInstallRequest struct {
	ConnectorID string                 `json:"connector_id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Options     map[string]interface{} `json:"options"`
	Credentials map[string]string      `json:"credentials"`
}

// createConnectorInstance is a factory function that creates connector instances by type
func createConnectorInstance(connectorType string) (base.Connector, error) {
	switch connectorType {
	case "amadeus":
		return NewAmadeusConnector(), nil
	case "redis":
		return redis.NewRedisConnector(), nil
	case "http":
		return httpconnector.NewHTTPConnector(), nil
	case "postgres":
		return postgres.NewPostgresConnector(), nil
	default:
		return nil, fmt.Errorf("unsupported connector type: %s", connectorType)
	}
}

// initializeConnectorRegistry initializes the global connector registry
func initializeConnectorRegistry() {
	// Check if DATABASE_URL is available for persistent storage
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		var err error
		connectorRegistry, err = registry.NewRegistryWithStorage(dbURL)
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
	return []ConnectorMetadata{
		{
			ID:          "amadeus-travel",
			Name:        "Amadeus Travel API",
			Type:        "amadeus",
			Version:     "0.2.0",
			Description: "Access flight search, hotel search, and airport information from Amadeus Travel API",
			Category:    "Travel",
			Icon:        "✈️",
			Tags:        []string{"travel", "flights", "hotels", "api"},
			Capabilities: []string{"query", "flights", "hotels", "airports"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"api_key", "api_secret"},
				"properties": map[string]interface{}{
					"environment": map[string]interface{}{
						"type": "string",
						"enum": []string{"test", "production"},
						"default": "test",
						"description": "API environment (test or production)",
					},
				},
				"credentials": map[string]interface{}{
					"api_key": map[string]interface{}{
						"type": "string",
						"description": "Amadeus API Key",
					},
					"api_secret": map[string]interface{}{
						"type": "string",
						"description": "Amadeus API Secret",
					},
				},
			},
		},
		{
			ID:          "redis-cache",
			Name:        "Redis Cache",
			Type:        "redis",
			Version:     "0.2.0",
			Description: "High-performance key-value caching with sub-10ms latency",
			Category:    "Cache",
			Icon:        "⚡",
			Tags:        []string{"cache", "redis", "kv-store", "performance"},
			Capabilities: []string{"query", "execute", "cache", "kv-store"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"host"},
				"properties": map[string]interface{}{
					"host": map[string]interface{}{
						"type": "string",
						"description": "Redis host",
					},
					"port": map[string]interface{}{
						"type": "number",
						"default": 6379,
						"description": "Redis port",
					},
					"db": map[string]interface{}{
						"type": "number",
						"default": 0,
						"description": "Redis database number",
					},
				},
				"credentials": map[string]interface{}{
					"password": map[string]interface{}{
						"type": "string",
						"description": "Redis password (optional)",
					},
				},
			},
		},
		{
			ID:          "http-rest",
			Name:        "HTTP REST API",
			Type:        "http",
			Version:     "0.2.0",
			Description: "Generic REST API connector with multiple authentication methods",
			Category:    "API",
			Icon:        "🔌",
			Tags:        []string{"http", "rest", "api", "generic"},
			Capabilities: []string{"query", "execute", "rest-api"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"base_url"},
				"properties": map[string]interface{}{
					"base_url": map[string]interface{}{
						"type": "string",
						"description": "Base URL of the API",
					},
					"auth_type": map[string]interface{}{
						"type": "string",
						"enum": []string{"none", "bearer", "basic", "api-key"},
						"default": "none",
						"description": "Authentication type",
					},
					"timeout": map[string]interface{}{
						"type": "number",
						"default": 30,
						"description": "Request timeout in seconds",
					},
					"headers": map[string]interface{}{
						"type": "object",
						"description": "Custom headers to include in requests",
					},
				},
				"credentials": map[string]interface{}{
					"token": map[string]interface{}{
						"type": "string",
						"description": "Bearer token (for bearer auth)",
					},
					"username": map[string]interface{}{
						"type": "string",
						"description": "Username (for basic auth)",
					},
					"password": map[string]interface{}{
						"type": "string",
						"description": "Password (for basic auth)",
					},
					"api_key": map[string]interface{}{
						"type": "string",
						"description": "API key (for api-key auth)",
					},
					"header_name": map[string]interface{}{
						"type": "string",
						"default": "X-API-Key",
						"description": "Header name for API key (for api-key auth)",
					},
				},
			},
		},
		{
			ID:          "postgresql",
			Name:        "PostgreSQL Database",
			Type:        "postgres",
			Version:     "0.1.0",
			Description: "Connect to PostgreSQL databases with connection pooling",
			Category:    "Database",
			Icon:        "🐘",
			Tags:        []string{"database", "sql", "postgres"},
			Capabilities: []string{"query", "execute", "transactions"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"host", "database"},
				"properties": map[string]interface{}{
					"host": map[string]interface{}{
						"type": "string",
						"description": "PostgreSQL host",
					},
					"port": map[string]interface{}{
						"type": "number",
						"default": 5432,
						"description": "PostgreSQL port",
					},
					"database": map[string]interface{}{
						"type": "string",
						"description": "Database name",
					},
				},
				"credentials": map[string]interface{}{
					"username": map[string]interface{}{
						"type": "string",
						"description": "Database username",
					},
					"password": map[string]interface{}{
						"type": "string",
						"description": "Database password",
					},
				},
			},
		},
	}
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
			defer cancel()

			status, err := connectorRegistry.HealthCheckSingle(ctx, metadata[i].ID)
			if err == nil && status != nil {
				metadata[i].Healthy = status.Healthy
				metadata[i].LastCheck = status.Timestamp.Format(time.RFC3339)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"connectors": metadata,
		"total": len(metadata),
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
	var connector base.Connector
	switch connectorType {
	case "amadeus":
		connector = NewAmadeusConnector() // Use orchestrator's version with real OAuth
	case "redis":
		connector = redis.NewRedisConnector()
	case "http":
		connector = httpconnector.NewHTTPConnector()
	case "postgres":
		connector = postgres.NewPostgresConnector()
	default:
		http.Error(w, "Unsupported connector type", http.StatusBadRequest)
		return
	}

	// Create config
	config := &base.ConnectorConfig{
		Name:        req.Name,
		Type:        connectorType,
		TenantID:    req.TenantID,
		Options:     req.Options,
		Credentials: req.Credentials,
		Timeout:     30 * time.Second,
	}

	// Register connector
	if err := connectorRegistry.Register(connectorID, connector, config); err != nil {
		http.Error(w, "Failed to install connector: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Connector installed successfully",
		"connector_id": connectorID,
		"name": req.Name,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// uninstallConnectorHandler uninstalls a connector
func uninstallConnectorHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	if err := connectorRegistry.Unregister(connectorID); err != nil {
		http.Error(w, "Failed to uninstall connector: "+err.Error(), http.StatusInternalServerError)
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
