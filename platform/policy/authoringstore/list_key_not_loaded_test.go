// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// THE DURABLE LIST'S key_not_loaded BRANCH (master R3 round 1 on #4397, M3).
//
// ListArtifacts leaves out an artifact that did not load and names it, with
// one of two reasons: artifact_unverifiable, and key_not_loaded for a key a
// reload has not settled. Only the first had a cell: the owed Real-PG one
// cannot reach the second, because a store opened against a real database
// carries a StaticTrust, which never defers. A stub reloadable that DOES defer
// reaches it without a database, over sqlmock's rows.
func TestTheDurableListNamesAnArtifactWhoseKeyIsNotLoaded(t *testing.T) {
	authorized, authorizedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const authorizedKeyID = "probe-4397-authorized"
	loaded, loadedRaw := artifactFor(t, authorizedKeyID, authorizedPriv, 2)
	_, unknownRaw := artifactFor(t, "probe-4397-unknown", unknownPriv, 1)

	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, authorizedKeyID, authorized)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The listing runs inside rls.WithOrgScope, so the org scope is set first
	// and the transaction is committed after.
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT digest, artifact FROM typed_policy_artifacts").
		WillReturnRows(sqlmock.NewRows([]string{"digest", "artifact"}).
			AddRow(loaded.Digest(), loadedRaw).
			AddRow("sha256:probe-4397-unknown-key", unknownRaw))
	mock.ExpectCommit()

	// The reload is DEFERRED, which is what makes the unknown key
	// key_not_loaded rather than unverifiable.
	s := &Store{db: db, orgID: "org-a", trust: &deferredTrust{current: trust}}
	arts, err := s.ListArtifacts(context.Background(), pdp.RootOrganization, 0)

	if len(arts) != 1 || arts[0].Digest() != loaded.Digest() {
		t.Fatalf("the listing returned %d artifact(s); want the one that loads", len(arts))
	}
	var skipped *authoring.ArtifactsSkipped
	if !errors.As(err, &skipped) {
		t.Fatalf("the listing returned %v; want an ArtifactsSkipped naming the one left out", err)
	}
	if len(skipped.Skipped) != 1 {
		t.Fatalf("skipped = %+v; want exactly the unknown-key artifact", skipped.Skipped)
	}
	if skipped.Skipped[0].Reason != "key_not_loaded" {
		t.Fatalf("reason = %q, want key_not_loaded: a key a deferred reload has not settled is not an integrity fault", skipped.Skipped[0].Reason)
	}
	if !errors.Is(skipped.Skipped[0].Err, ErrSigningKeyNotLoaded) {
		t.Errorf("the skipped artifact's error is %v; want ErrSigningKeyNotLoaded", skipped.Skipped[0].Err)
	}
	// AND IT IS NOT AN OUTAGE: a store that cannot be read at all still fails
	// the whole listing, which is the distinction this branch exists to keep.
	if errors.Is(err, authoring.ErrStoreUnavailable) {
		t.Errorf("a skipped artifact was reported as the store failing: %v", err)
	}
}
