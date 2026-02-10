// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"net/http"
	"testing"
)

// TestRegisterDatabaseAgentSourceFactory verifies that registering a factory stores it
// and GetDatabaseAgentSourceFactory returns it correctly.
func TestRegisterDatabaseAgentSourceFactory(t *testing.T) {
	// Save and restore the package-level variable
	oldFactory := dbAgentSourceFactory
	defer func() { dbAgentSourceFactory = oldFactory }()

	// Start with nil
	dbAgentSourceFactory = nil
	if got := GetDatabaseAgentSourceFactory(); got != nil {
		t.Fatal("expected nil factory before registration")
	}

	// Register a factory
	called := false
	factory := func(db *sql.DB) DatabaseAgentSource {
		called = true
		return nil
	}
	RegisterDatabaseAgentSourceFactory(factory)

	// Verify it was stored
	got := GetDatabaseAgentSourceFactory()
	if got == nil {
		t.Fatal("expected non-nil factory after registration")
	}

	// Verify calling the returned factory invokes the original
	got(nil)
	if !called {
		t.Error("expected factory function to be called")
	}
}

// TestRegisterAgentCRUDHandlerFactory verifies that registering a CRUD handler factory
// stores it and GetAgentCRUDHandlerFactory returns it correctly.
func TestRegisterAgentCRUDHandlerFactory(t *testing.T) {
	// Save and restore the package-level variable
	oldFactory := agentCRUDHandlerFactory
	defer func() { agentCRUDHandlerFactory = oldFactory }()

	// Start with nil
	agentCRUDHandlerFactory = nil
	if got := GetAgentCRUDHandlerFactory(); got != nil {
		t.Fatal("expected nil factory before registration")
	}

	// Register a factory
	called := false
	factory := func(db *sql.DB, registry *AgentRegistry) http.Handler {
		called = true
		return http.NotFoundHandler()
	}
	RegisterAgentCRUDHandlerFactory(factory)

	// Verify it was stored
	got := GetAgentCRUDHandlerFactory()
	if got == nil {
		t.Fatal("expected non-nil factory after registration")
	}

	// Verify calling the returned factory invokes the original
	handler := got(nil, nil)
	if !called {
		t.Error("expected factory function to be called")
	}
	if handler == nil {
		t.Error("expected non-nil handler from factory")
	}
}

// TestGetDatabaseAgentSourceFactory_NilByDefault verifies the getter returns nil
// when no factory has been registered.
func TestGetDatabaseAgentSourceFactory_NilByDefault(t *testing.T) {
	oldFactory := dbAgentSourceFactory
	defer func() { dbAgentSourceFactory = oldFactory }()

	dbAgentSourceFactory = nil
	if got := GetDatabaseAgentSourceFactory(); got != nil {
		t.Error("expected nil when no factory registered")
	}
}

// TestGetAgentCRUDHandlerFactory_NilByDefault verifies the getter returns nil
// when no factory has been registered.
func TestGetAgentCRUDHandlerFactory_NilByDefault(t *testing.T) {
	oldFactory := agentCRUDHandlerFactory
	defer func() { agentCRUDHandlerFactory = oldFactory }()

	agentCRUDHandlerFactory = nil
	if got := GetAgentCRUDHandlerFactory(); got != nil {
		t.Error("expected nil when no factory registered")
	}
}

// TestRegisterDatabaseAgentSourceFactory_RegisterIfAbsent verifies that re-registering
// a factory does NOT overwrite the previous one (registerIfAbsent pattern).
func TestRegisterDatabaseAgentSourceFactory_RegisterIfAbsent(t *testing.T) {
	oldFactory := dbAgentSourceFactory
	defer func() { dbAgentSourceFactory = oldFactory }()

	dbAgentSourceFactory = nil

	firstCalled := false
	first := func(db *sql.DB) DatabaseAgentSource {
		firstCalled = true
		return nil
	}
	RegisterDatabaseAgentSourceFactory(first)

	secondCalled := false
	second := func(db *sql.DB) DatabaseAgentSource {
		secondCalled = true
		return nil
	}
	RegisterDatabaseAgentSourceFactory(second)

	got := GetDatabaseAgentSourceFactory()
	if got == nil {
		t.Fatal("expected non-nil factory")
	}

	got(nil)
	if !firstCalled {
		t.Error("first factory should have been called (registerIfAbsent keeps first)")
	}
	if secondCalled {
		t.Error("second factory should NOT have been called (registerIfAbsent ignores duplicate)")
	}
}

// TestRegisterAgentCRUDHandlerFactory_RegisterIfAbsent verifies that re-registering
// a CRUD handler factory does NOT overwrite the previous one (registerIfAbsent pattern).
func TestRegisterAgentCRUDHandlerFactory_RegisterIfAbsent(t *testing.T) {
	oldFactory := agentCRUDHandlerFactory
	defer func() { agentCRUDHandlerFactory = oldFactory }()

	agentCRUDHandlerFactory = nil

	firstCalled := false
	first := func(db *sql.DB, registry *AgentRegistry) http.Handler {
		firstCalled = true
		return nil
	}
	RegisterAgentCRUDHandlerFactory(first)

	secondCalled := false
	second := func(db *sql.DB, registry *AgentRegistry) http.Handler {
		secondCalled = true
		return http.NotFoundHandler()
	}
	RegisterAgentCRUDHandlerFactory(second)

	got := GetAgentCRUDHandlerFactory()
	if got == nil {
		t.Fatal("expected non-nil factory")
	}

	got(nil, nil)
	if !firstCalled {
		t.Error("first factory should have been called (registerIfAbsent keeps first)")
	}
	if secondCalled {
		t.Error("second factory should NOT have been called (registerIfAbsent ignores duplicate)")
	}
}
