// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"

	sharedidentity "axonflow/platform/shared/identity"
)

// orchestratorRealmDeployment records what this process wired, for the typed
// authoring catalog's built-in realm vocabulary (#3895): whether a SCIM-backed
// directory exists here decides whether those realms carry a group graph, and
// whether the deployment wires the enterprise OIDC realm source decides whether
// the `oidc` realm is declared at all (#4249).
var orchestratorRealmDeployment sharedidentity.BuiltinRealmDeployment

// noteOrchestratorDirectoryWired records that a SCIM-backed directory is
// available in this process, so the realms that can carry one declare
// DirectorySourceSCIM rather than the positive "this realm has no group
// graph".
func noteOrchestratorDirectoryWired() {
	orchestratorRealmDeployment.HasDirectory = true
}

// noteOrchestratorOIDCWiring records whether this deployment wires the
// enterprise OIDC realm source, from the SAME predicate the agent builds that
// source from (sharedidentity.OIDCRealmSourceWiring).
//
// THE ORCHESTRATOR REGISTERS NO OIDC REALM, and declares it anyway. HasOIDC is
// a DEPLOYMENT fact the vocabulary reads, not a statement that this process
// admits IdP tokens: a policy naming `User::oidc:<sub>` is validated here at
// publication and enforced by the agent, and the two must resolve one
// vocabulary (one realm set, one digest). An IdP token presented to this
// process still stops at its identity gate, which knows no OIDC realm.
func noteOrchestratorOIDCWiring(db *sql.DB) {
	if _, wired, _ := sharedidentity.OIDCRealmSourceWiring(db); wired {
		orchestratorRealmDeployment.HasOIDC = true
	}
}
