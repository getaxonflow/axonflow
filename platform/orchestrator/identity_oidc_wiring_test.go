// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/shared/authoringvocabulary"
	"axonflow/platform/shared/deploymode"
	sharedidentity "axonflow/platform/shared/identity"
)

// TestTheOrchestratorDeclaresHasOIDCFromTheSharedPredicate: the orchestrator's
// HasOIDC, driven through initSegmentPolicyGate, is what
// sharedidentity.OIDCRealmSourceWiring answers, and equals what the portal's
// DeploymentFromDatabase derives from the same database (#4249). The agent
// asserts the same against the same function.
func TestTheOrchestratorDeclaresHasOIDCFromTheSharedPredicate(t *testing.T) {
	orig := orchestratorRealmDeployment
	t.Cleanup(func() {
		orchestratorRealmDeployment = orig
		ResetOrchestratorSegmentResolverForTest()
	})
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
			orchestratorRealmDeployment = sharedidentity.BuiltinRealmDeployment{}
			ResetOrchestratorSegmentResolverForTest()

			initSegmentPolicyGate(db)

			_, wired, predErr := sharedidentity.OIDCRealmSourceWiring(db)
			// Not vacuous: an enterprise build with a database on an enterprise
			// schema must wire it, and on any other deployment mode must not, so
			// the agreement below is checked on both answers.
			enterpriseBuild := !errors.Is(predErr, sharedidentity.ErrEnterpriseOnly)
			if want := enterpriseBuild && db != nil && deploymode.AppliesEnterpriseSchema(); wired != want {
				t.Fatalf("DEPLOYMENT_MODE=%q database=%v: the predicate answered wired=%v, want %v (%v)", deploymode.Current(), db != nil, wired, want, predErr)
			}
			if orchestratorRealmDeployment.HasOIDC != wired {
				t.Fatalf("database=%v: the orchestrator declared HasOIDC=%v and the shared predicate answers %v", db != nil, orchestratorRealmDeployment.HasOIDC, wired)
			}
			if portal := authoringvocabulary.DeploymentFromDatabase(db); portal != orchestratorRealmDeployment {
				t.Fatalf("database=%v: the orchestrator derived %+v and the portal derives %+v from the same database", db != nil, orchestratorRealmDeployment, portal)
			}
		}
	}
}
