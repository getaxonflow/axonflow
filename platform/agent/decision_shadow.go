// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"log"

	"axonflow/platform/shared/planeshadow"
)

// initDecisionShadow assembles the ADR-065 per-plane decision shadow and
// installs it process-wide (#3564).
//
// IT IS FATAL ON AN UNUSABLE CONFIGURATION, for the reason initIdentityCompat
// is: AXONFLOW_DECISION_SHADOW_MODE=shadwo is an operator who believes their
// planes are being measured, and booting anyway with the shadow silently off
// would leave them believing it until v11's gate is read off a window that was
// never open. A container that refuses to start is the one failure an operator
// sees immediately.
//
// It runs unconditionally, in both DB and no-DB modes, so the configuration is
// validated even on a deployment where nothing else would touch it. With no
// database the observer is nil, which is off, and the startup line says so.
func initDecisionShadow(db *sql.DB) {
	obs, err := planeshadow.Bootstrap(planeshadow.BootstrapConfig{
		Component: "agent",
		DB:        db,
		OrgModes:  decisionShadowOrgModes(),
		OrgPlanes: decisionShadowOrgPlanes(),
	})
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	planeshadow.InstallProcess(obs, "agent")
}

// decisionShadowOrgModes is the per-organization mode source, or nil when none
// was wired (every community build; an enterprise build with no database).
//
// It is the SAME store the identity axis reads (identityOrgSettings), because
// the two per-organization modes are two columns of one row: a second store
// would read the same table twice on the same TTL and give the two axes two
// different staleness windows, so an operator could not say which instant
// either mode was true at.
func decisionShadowOrgModes() planeshadow.OrgModeSource {
	if identityOrgSettings == nil {
		return nil
	}
	return identityOrgSettings
}

// decisionShadowOrgPlanes is the per-organization PLANE narrowing source
// (#3552 gap 3), or nil when none was wired.
//
// THE SAME STORE, AND THE SAME GUARD, as decisionShadowOrgModes above: the
// narrowing is one more column of the row that carries the two modes, so
// reading it through a second store would give one row two staleness windows.
// Written as its own function rather than by passing identityOrgSettings twice
// at the call site, so that the nil guard cannot be satisfied for one axis and
// skipped for the other.
func decisionShadowOrgPlanes() planeshadow.OrgPlanesSource {
	if identityOrgSettings == nil {
		return nil
	}
	return identityOrgSettings
}
