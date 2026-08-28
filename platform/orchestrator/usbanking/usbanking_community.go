//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package usbanking is the US banking compliance module.
//
// This file is the COMMUNITY build: the US examination package is an
// Enterprise feature, so in a `!enterprise` build the module constructs,
// registers nothing, and reports itself unhealthy. Same shape as the sibling
// compliance modules' community stubs (masfeat/masfeat_community.go,
// compliancereport/compliancereport_community.go): the edition gate is the
// build tag, not a runtime health check.
//
// The exported surface here MUST stay a superset of what
// platform/orchestrator/run.go touches, because run.go carries no build tag and
// is compiled in both editions. That is asserted by
// TestCommunityStubCoversRunGoSurface in usbanking_community_test.go.
package usbanking

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"
)

// ModuleConfig is accepted but ignored in community mode. The field set
// mirrors the enterprise ModuleConfig exactly so run.go's single (untagged)
// construction site compiles in both editions.
type ModuleConfig struct {
	DB *sql.DB
}

// Module is the community stub for the US banking compliance module.
type Module struct{}

// NewModule returns an empty module in community mode.
func NewModule(config ModuleConfig) (*Module, error) { return &Module{}, nil }

// RegisterRoutes is a no-op in community mode.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {}

// RegisterRoutesWithMux is a no-op in community mode.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {}

// IsHealthy returns false in community mode.
func (m *Module) IsHealthy() bool { return false }

// HealthCheck reports the module as disabled in community mode.
func (m *Module) HealthCheck() map[string]string {
	return map[string]string{
		"usbanking_evidence": "disabled",
	}
}
