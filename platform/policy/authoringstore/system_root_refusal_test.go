// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestTheDurableStoreRefusesTheSystemRootOnEveryWriteAndTrustPath is the Go half
// of the line migrations/core/178 holds in the schema (#4047): no write, and no
// trust load, under a root other than the organization's.
//
// NO DATABASE IS NEEDED, AND THAT IS THE ASSERTION. The handle points at a port
// nothing listens on, so a refusal that happened only after a statement was sent
// would come back as a connection error rather than ErrSystemRootNotStored -
// every refusal here must be decided before this package touches the database.
func TestTheDurableStoreRefusesTheSystemRootOnEveryWriteAndTrustPath(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("postgres", "host=127.0.0.1 port=1 user=nobody dbname=nothing sslmode=disable connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := New(db, "org-a", authoring.StaticTrust(pdp.NewTrustStore()))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := KeyIDFor("probe", "org-a", pub)
	actor := contract.MustParseID(contract.KindPrincipal, "User::portal:alice@example.com")

	for _, path := range []struct {
		name string
		run  func() error
	}{
		{"OpenForSigning", func() error {
			_, _, _, err := OpenForSigning(ctx, db, pdp.RootSystem, "org-a", "probe", pub, "probe")
			return err
		}},
		{"OpenForVerifying", func() error {
			_, _, err := OpenForVerifying(ctx, db, pdp.RootSystem, "org-a")
			return err
		}},
		{"AuthorizeKey", func() error { return store.AuthorizeKey(ctx, pdp.RootSystem, keyID, pub, "probe") }},
		{"RevokeKey", func() error { return store.RevokeKey(ctx, pdp.RootSystem, keyID, "probe") }},
		{"LoadTrust", func() error {
			_, err := store.LoadTrust(ctx, pdp.RootSystem)
			return err
		}},
		{"PutArtifact", func() error { return store.PutArtifact(ctx, pdp.RootSystem, nil) }},
		{"AppendActivation", func() error {
			return store.AppendActivation(ctx, pdp.RootSystem, authoring.Activation{Actor: actor}, "")
		}},
	} {
		t.Run(path.name, func(t *testing.T) {
			if err := path.run(); !errors.Is(err, ErrSystemRootNotStored) {
				t.Fatalf("%s under the system root returned %v; want ErrSystemRootNotStored, decided before any statement", path.name, err)
			}
		})
	}
}
