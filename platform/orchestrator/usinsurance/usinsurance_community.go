//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package usinsurance is the US insurance regulatory module.
//
// This file is the COMMUNITY build of the package: the NAIC exhibit set and its
// NYDFS and Colorado annexes are an Enterprise feature, so in a `!enterprise`
// build the module constructs, registers nothing, and reports itself unhealthy.
// Same shape as the sibling compliance modules' community stubs
// (ojk/ojk_community.go, euaiact/euaiact_community.go): the edition gate is the
// build tag, not a runtime health check.
//
// The exported surface here MUST stay a superset of what
// platform/orchestrator/run.go touches, because run.go carries no build tag and
// is compiled in both editions. That is asserted by
// TestCommunityStubCoversRunGoSurface in usinsurance_community_test.go.
package usinsurance

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"
)

// Module is the community stub for the US insurance module.
type Module struct{}

// NewModule returns an empty module in community mode. The signature mirrors
// the enterprise constructor exactly so run.go's single untagged construction
// site compiles in both editions.
func NewModule(db *sql.DB) (*Module, error) { return &Module{}, nil }

// RegisterRoutes is a no-op in community mode.
func (m *Module) RegisterRoutes(sm *http.ServeMux) {}

// RegisterRoutesWithMux is a no-op in community mode.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {}

// IsHealthy returns false in community mode.
func (m *Module) IsHealthy() bool { return false }

// HealthCheck reports the module as disabled in community mode.
func (m *Module) HealthCheck() map[string]string {
	return map[string]string{"usinsurance": "disabled"}
}
