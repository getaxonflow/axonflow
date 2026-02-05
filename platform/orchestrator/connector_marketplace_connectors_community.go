//go:build !enterprise

package orchestrator

import (
	"fmt"

	"axonflow/platform/connectors/base"
	httpconnector "axonflow/platform/connectors/http"
	"axonflow/platform/connectors/mongodb"
	"axonflow/platform/connectors/mysql"
	"axonflow/platform/connectors/postgres"
	"axonflow/platform/connectors/redis"
)

func createConnectorInstanceByType(connectorType string) (base.Connector, error) {
	switch connectorType {
	case "amadeus":
		return NewAmadeusConnector(), nil
	case "redis":
		return redis.NewRedisConnector(), nil
	case "http":
		return httpconnector.NewHTTPConnector(), nil
	case "postgres":
		return postgres.NewPostgresConnector(), nil
	case "mysql":
		return mysql.NewMySQLConnector(), nil
	case "mongodb":
		return mongodb.NewMongoDBConnector(), nil
	default:
		return nil, fmt.Errorf("unsupported connector type: %s", connectorType)
	}
}

func getConnectorMetadataByEdition() []ConnectorMetadata {
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
