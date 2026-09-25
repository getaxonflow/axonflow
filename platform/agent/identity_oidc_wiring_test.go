// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/shared/deploymode"
	sharedidentity "axonflow/platform/shared/identity"
)

// restoreIdentityWiring saves what registerFleetValidators writes - the
// process's identity deployment and the collaborators noted beside it - and
// restores them when the test ends.
//
// A TEST THAT CALLS registerFleetValidators WITH A DATABASE AND DOES NOT RESTORE
// THEM LEAKS ITS DEPLOYMENT INTO EVERY LATER TEST (#4249). The leak hid nothing
// while the fields it set were HasDirectory and HasRevocation, which do not move
// which realms are interactive; HasOIDC does, and a later test that resolved
// the deployment vocabulary (the installed FinCrime pack's approver pool) then
// read an `oidc` realm its own setup never wired, passing alone and failing by
// order.
//
// IT RESTORES THE DECLARATION, NOT THE REGISTRIES. The validator registry is
// reset by sharedidentity.ResetRegistryForTest, which every caller already runs,
// and the fleet segment resolver by ResetFleetSegmentResolverForTest.
func restoreIdentityWiring(t *testing.T) {
	t.Helper()
	dep, configs, rev, settings := identityDeployment, identityOIDCConfigs, identityRevocations, identityOrgSettings
	t.Cleanup(func() {
		identityDeployment, identityOIDCConfigs, identityRevocations, identityOrgSettings = dep, configs, rev, settings
	})
}

// TestTheAgentDeclaresHasOIDCFromTheSharedPredicate: the agent's HasOIDC is
// what sharedidentity.OIDCRealmSourceWiring answers for its database, driven
// through registerFleetValidators, with and without a database, on whichever
// build runs it (#4249). The orchestrator and the portal assert the same
// against the same function, so the process that validates a policy naming
// the `oidc` realm and the process that enforces it cannot disagree.
func TestTheAgentDeclaresHasOIDCFromTheSharedPredicate(t *testing.T) {
	origDB, origSecret := usageDB, jwtSecret
	restoreIdentityWiring(t)
	t.Cleanup(func() {
		usageDB, jwtSecret = origDB, origSecret
		sharedidentity.ResetRegistryForTest()
		ResetFleetSegmentResolverForTest()
	})
	jwtSecret = []byte(testJWTSecret)

	mock, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close() })

	for _, mode := range []string{"", "community", "community-saas", "evaluation", "in-vpc-enterprise", "saas"} {
		t.Setenv("DEPLOYMENT_MODE", mode)
		if mode == "" {
			// UNSET, not set-empty: t.Setenv restores the variable at cleanup.
			_ = os.Unsetenv("DEPLOYMENT_MODE")
		}
		for _, db := range []*sql.DB{nil, mock} {
			usageDB = db
			identityDeployment = sharedidentity.BuiltinRealmDeployment{}
			identityOIDCConfigs, identityRevocations, identityOrgSettings = nil, nil, nil
			sharedidentity.ResetRegistryForTest()
			ResetFleetSegmentResolverForTest()

			registerFleetValidators()

			_, wired, predErr := sharedidentity.OIDCRealmSourceWiring(db)
			// Not vacuous: an enterprise build with a database on an enterprise
			// schema must wire it, and on any other deployment mode must not, so
			// the agreement below is checked on both answers.
			enterpriseBuild := !errors.Is(predErr, sharedidentity.ErrEnterpriseOnly)
			if want := enterpriseBuild && db != nil && deploymode.AppliesEnterpriseSchema(); wired != want {
				t.Fatalf("DEPLOYMENT_MODE=%q database=%v: the predicate answered wired=%v, want %v (%v)", deploymode.Current(), db != nil, wired, want, predErr)
			}
			if identityDeployment.HasOIDC != wired {
				t.Fatalf("database=%v: the agent declared HasOIDC=%v and the shared predicate answers %v", db != nil, identityDeployment.HasOIDC, wired)
			}
			if (identityOIDCConfigs != nil) != wired {
				t.Fatalf("database=%v: an OIDC configuration provider wired=%v while HasOIDC=%v; the realm source and the declaration must be one fact",
					db != nil, identityOIDCConfigs != nil, wired)
			}
		}
	}
}
