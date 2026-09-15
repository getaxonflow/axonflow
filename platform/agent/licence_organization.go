// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"

	"axonflow/platform/agent/license"
	"axonflow/platform/shared/retiredenv"
)

// refuseOrgLessLicence refuses a licence that names no organization: one that
// carries neither deployment_id (V3) nor org_id (V2).
//
// Every verdict is the ADR-065 decision plane's, and it is decided for an
// ORGANIZATION: the identity plane admits a subject in one, and an activation is
// built for one. A licence naming none authenticates requests to no
// organization, so every one of them would fail closed with a 503 that reads as
// a policy decision. Refusing the licence itself - the process licence at boot,
// a client licence at authentication, each naming the missing fields - is the
// PRD's rule for a process the only engine cannot author for (§1.8): it
// does not start, and a credential it cannot decide for is not admitted.
func refuseOrgLessLicence(result *license.ValidationResult) error {
	if result == nil || result.LicenseDeploymentID() != "" {
		return nil
	}
	return fmt.Errorf("the licence names no organization: it carries neither deployment_id (V3) nor org_id (V2). "+
		"The v11 decision plane decides every request for an organization (%s §1.8), so a licence that names none "+
		"authenticates to nothing it can decide for; request a licence that names this deployment's organization", retiredenv.PRD)
}
