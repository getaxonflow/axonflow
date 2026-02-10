// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"net/http"
)

// DatabaseAgentSourceFactory creates a DatabaseAgentSource from a database connection.
// This is registered by enterprise builds via init() in agent_registry_db_enterprise.go.
type DatabaseAgentSourceFactory func(db *sql.DB) DatabaseAgentSource

// AgentCRUDHandlerFactory creates an HTTP handler for enterprise agent CRUD operations.
// This is registered by enterprise builds via init() in agent_registry_db_enterprise.go.
// The factory receives db for persistence and registry for hot-reloading agent configs.
type AgentCRUDHandlerFactory func(db *sql.DB, registry *AgentRegistry) http.Handler

// dbAgentSourceFactory is set by enterprise builds to enable database-backed agent configs.
var dbAgentSourceFactory DatabaseAgentSourceFactory

// agentCRUDHandlerFactory is set by enterprise builds to enable agent CRUD API.
var agentCRUDHandlerFactory AgentCRUDHandlerFactory

// RegisterDatabaseAgentSourceFactory registers a factory for creating DatabaseAgentSource instances.
// This is called from init() in enterprise builds.
// Uses registerIfAbsent pattern: plain factories serve as fallback, SDK-backed override.
func RegisterDatabaseAgentSourceFactory(factory DatabaseAgentSourceFactory) {
	if dbAgentSourceFactory != nil {
		return // already registered — do not override
	}
	dbAgentSourceFactory = factory
}

// RegisterAgentCRUDHandlerFactory registers a factory for creating agent CRUD HTTP handlers.
// This is called from init() in enterprise builds.
// Uses registerIfAbsent pattern: plain factories serve as fallback, SDK-backed override.
func RegisterAgentCRUDHandlerFactory(factory AgentCRUDHandlerFactory) {
	if agentCRUDHandlerFactory != nil {
		return // already registered — do not override
	}
	agentCRUDHandlerFactory = factory
}

// GetDatabaseAgentSourceFactory returns the registered factory, or nil if not available.
func GetDatabaseAgentSourceFactory() DatabaseAgentSourceFactory {
	return dbAgentSourceFactory
}

// GetAgentCRUDHandlerFactory returns the registered factory, or nil if not available.
func GetAgentCRUDHandlerFactory() AgentCRUDHandlerFactory {
	return agentCRUDHandlerFactory
}
