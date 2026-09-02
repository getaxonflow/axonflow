// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"log"

	"axonflow/platform/shared/planeshadow"
)

// initDecisionShadow assembles the ADR-065 per-plane decision shadow and
// installs it process-wide (#3564).
//
// # WHY THIS BINARY WIRES IT TOO
//
// Four of the twelve enforcement planes - wcp, map, policy_simulation and
// policy_test - evaluate the dynamic substrate here, and orchestrator_response
// evaluates the static one. Gate 18 is stated PER PLANE, so a deployment that
// shadowed only the agent would have no evidence at all for five planes while
// its dashboard showed a healthy window for the other seven. Both binaries
// therefore read the same table through the same store and the same
// configuration, exactly as initIdentityCompat's own header argues for the
// identity axis.
//
// Fatal on an unusable configuration, for the reason the agent's copy gives.
func initDecisionShadow(db *sql.DB) {
	obs, err := planeshadow.Bootstrap(planeshadow.BootstrapConfig{
		Component: "orchestrator",
		DB:        db,
		OrgModes:  decisionShadowOrgModes(db),
	})
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	planeshadow.InstallProcess(obs, "orchestrator")
}

// decisionShadowOrgModes builds the per-organization settings store over this
// process's database, or returns nil where none can exist.
//
// Enterprise-only by construction: the community constructor returns
// ErrEnterpriseOnly, which is SKIPPED - a nil source means the process mode is
// the whole answer, which is the correct behaviour for a build with no
// organization-management surface. Any OTHER construction failure is fatal, for
// orchestratorOrgModeSource's reason: a deployment that HAS the table and could
// not open a store for it would silently run every organization in the process
// mode while its records say otherwise, and would do so for the shadow's whole
// observation window.
func decisionShadowOrgModes(db *sql.DB) planeshadow.OrgModeSource {
	if db == nil {
		return nil
	}
	// THE SAME STORE THE IDENTITY AXIS READS, not a second one over the same
	// table. The two per-organization modes are two COLUMNS OF ONE ROW; a
	// second store would give the two axes two different staleness windows on
	// one row, so an operator could not say which instant either mode was true
	// at. It also carries the deployment-mode gate: without it a
	// community-schema deployment does one failed read per organization per
	// TTL window against a table that cannot exist there.
	// initDecisionShadow runs AFTER initIdentityCompat (run.go states the
	// ordering and why), so this is the store that boot already built - not a
	// second one, and not a lazily-built one whose first caller decides the
	// deployment mode it was gated on.
	if orchestratorOrgSettingsStore == nil {
		return nil
	}
	return orchestratorOrgSettingsStore
}
