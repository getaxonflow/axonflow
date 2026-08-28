//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package compliancereport is the unified compliance report facade.
//
// This file is the COMMUNITY build of the package: the regulator report facade
// is an Enterprise feature, so in a `!enterprise` build the module constructs,
// registers nothing, and reports itself unhealthy. Same shape as the sibling
// compliance modules' community stubs (ojk/ojk_community.go,
// euaiact/euaiact_community.go): the edition gate is the build tag, not a
// runtime health check.
//
// The exported surface here MUST stay a superset of what
// platform/orchestrator/run.go touches, because run.go carries no build tag and
// is compiled in both editions. That is asserted by
// TestCommunityStubCoversRunGoSurface in compliancereport_community_test.go.
package compliancereport

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/cloudstorage"
	"axonflow/platform/orchestrator/euaiact"
	"axonflow/platform/orchestrator/masfeat"
	"axonflow/platform/orchestrator/ojk"
	"axonflow/platform/orchestrator/rbi"
	"axonflow/platform/orchestrator/sebi"
	"axonflow/platform/orchestrator/usbanking"
	"axonflow/platform/orchestrator/usinsurance"
	"axonflow/platform/orchestrator/ussecurities"
)

// ModuleConfig is accepted but ignored in community mode.
//
// The field set mirrors the enterprise ModuleConfig exactly so run.go's single
// (untagged) construction site compiles in both editions. The eight module
// pointers reference the sibling packages' own community stub types.
type ModuleConfig struct {
	DB             *sql.DB
	StorageBackend cloudstorage.StorageBackend
	Licenses       interface{}

	EUAIAct      *euaiact.Module
	SEBI         *sebi.SEBIModule
	RBI          *rbi.RBIModule
	MASFEAT      *masfeat.Module
	OJK          *ojk.OJKModule
	USInsurance  *usinsurance.Module
	USBanking    *usbanking.Module
	USSecurities *ussecurities.Module
}

// Module is the community stub for the compliance report facade.
type Module struct{}

// NewModule returns an empty module in community mode.
func NewModule(config ModuleConfig) (*Module, error) { return &Module{}, nil }

// RegisterRoutes is a no-op in community mode.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {}

// RegisterRoutesWithMux is a no-op in community mode.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {}

// IsHealthy returns false in community mode.
func (m *Module) IsHealthy() bool { return false }

// HealthCheck reports the facade as disabled in community mode.
func (m *Module) HealthCheck() map[string]string {
	return map[string]string{
		"report_facade": "disabled",
	}
}
