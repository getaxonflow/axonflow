//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringvocabulary_test

import (
	"database/sql"
	"testing"

	"axonflow/platform/shared/authoringvocabulary"
)

// assertDerivedFromADatabase, community build: a database wires neither a
// directory nor the OIDC source, so the derived vocabulary is the base's.
func assertDerivedFromADatabase(t *testing.T) {
	t.Helper()
	db := sql.OpenDB(refusingConnector{})
	defer db.Close()
	dep := authoringvocabulary.DeploymentFromDatabase(db)
	if dep.HasOIDC || dep.HasDirectory {
		t.Fatalf("community build with a database derived %+v; a community build federates no IdP and has no directory", dep)
	}
	for _, mode := range []string{"", "community-saas"} {
		withMode(t, mode, func() {
			if got := resolve(t, dep).Digest; got != communityBaseDigest {
				t.Fatalf("DEPLOYMENT_MODE=%q: community build with a database digests to %s; want the base %s", mode, got, communityBaseDigest)
			}
		})
	}
}
