// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import sharedidentity "axonflow/platform/shared/identity"

// orchestratorRealmDeployment records what this process wired, for the typed
// authoring catalog's built-in realm vocabulary (#3895): whether a SCIM-backed
// directory exists here decides whether those realms carry a group graph.
var orchestratorRealmDeployment sharedidentity.BuiltinRealmDeployment

// noteOrchestratorDirectoryWired records that a SCIM-backed directory is
// available in this process, so the realms that can carry one declare
// DirectorySourceSCIM rather than the positive "this realm has no group
// graph".
func noteOrchestratorDirectoryWired() {
	orchestratorRealmDeployment.HasDirectory = true
}
