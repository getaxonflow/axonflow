// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"axonflow/platform/decision/pdp"
)

// The two production checks Promote and Rollback run BEFORE the store (#3895):
// a fixture catalog is refused by name, and an installed activator that
// refuses leaves the active digest where it was.

func publishedAPI(t *testing.T, fixture bool) (*API, *Artifact) {
	t.Helper()
	cat := baseCatalog(t)
	cat.Provenance = CatalogProvenance{Source: "test", Fixture: fixture}
	// THE ORGANIZATION ROOT: an API is the organization authority (#4047).
	trust, priv := organizationTrust(t)
	api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	art, _, err := api.Publish(context.Background(), organizationDocument(t), organizationPublishOptions(t, priv))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	return api, art
}

func TestAFixtureCatalogMayPublishAndMayNeverActivate(t *testing.T) {
	api, art := publishedAPI(t, true)
	ctx := context.Background()
	for _, verb := range []struct {
		name string
		run  func() error
	}{
		{"promote", func() error {
			_, err := api.Promote(ctx, pdp.RootOrganization, art.Digest(), pid(t, principalBob), timeFixture(), "rollout")
			return err
		}},
		{"rollback", func() error {
			_, err := api.Rollback(ctx, pdp.RootOrganization, art.Digest(), pid(t, principalBob), timeFixture(), "restore")
			return err
		}},
	} {
		err := verb.run()
		var fixture *ErrCatalogIsFixture
		if !errors.As(err, &fixture) {
			t.Fatalf("%s on a fixture catalog was not refused as a fixture: %v", verb.name, err)
		}
		if fixture.Code() != CodeCatalogIsFixture {
			t.Fatalf("%s refused with %q, want %q", verb.name, fixture.Code(), CodeCatalogIsFixture)
		}
	}
	if _, active, err := api.Store().Active(ctx, pdp.RootOrganization); err != nil || active {
		t.Fatalf("a refused activation left something active (active=%v err=%v)", active, err)
	}

	// POSITIVE CONTROL, same publication path: the identical document on a
	// non-fixture catalog promotes. The refusal above is about the fixture
	// bit and nothing else.
	control, cart := publishedAPI(t, false)
	if _, err := control.Promote(ctx, pdp.RootOrganization, cart.Digest(), pid(t, principalBob), timeFixture(), "rollout"); err != nil {
		t.Fatalf("the control promotion failed: %v", err)
	}
}

func TestTheActivatorRunsBeforeTheStoreAndItsRefusalLeavesNothingActive(t *testing.T) {
	api, art := publishedAPI(t, false)
	ctx := context.Background()

	var seen []string
	api.WithActivator(func(_ context.Context, kind ActivationKind, candidate *Artifact) error {
		seen = append(seen, string(kind)+":"+candidate.Digest())
		return fmt.Errorf("this engine cannot be built: BLANKET_PERMISSION_REFUSED")
	})
	_, err := api.Promote(ctx, pdp.RootOrganization, art.Digest(), pid(t, principalBob), timeFixture(), "rollout")
	if err == nil || !strings.Contains(err.Error(), "BLANKET_PERMISSION_REFUSED") {
		t.Fatalf("a refusing activator did not refuse the promotion: %v", err)
	}
	if len(seen) != 1 || seen[0] != "promote:"+art.Digest() {
		t.Fatalf("the activator saw %v; it must see the promote of the store's own artifact exactly once", seen)
	}
	if _, active, _ := api.Store().Active(ctx, pdp.RootOrganization); active {
		t.Fatal("the store flipped the active digest although the activator refused; the activator must run first")
	}

	// The activator is handed the artifact the STORE holds, not one the caller
	// names: an unadmitted digest never reaches it.
	seen = nil
	if _, err := api.Promote(ctx, pdp.RootOrganization, "sha256:not-admitted", pid(t, principalBob), timeFixture(), "rollout"); err == nil {
		t.Fatal("an unadmitted digest was promoted")
	}
	if len(seen) != 0 {
		t.Fatalf("the activator was called for an unadmitted digest: %v", seen)
	}

	// POSITIVE CONTROL: an accepting activator lets the same promotion through
	// and is called with the same kind and digest.
	api.WithActivator(func(_ context.Context, kind ActivationKind, candidate *Artifact) error {
		seen = append(seen, string(kind)+":"+candidate.Digest())
		return nil
	})
	if _, err := api.Promote(ctx, pdp.RootOrganization, art.Digest(), pid(t, principalBob), timeFixture(), "rollout"); err != nil {
		t.Fatalf("the control promotion failed under an accepting activator: %v", err)
	}
	if len(seen) != 1 || seen[0] != "promote:"+art.Digest() {
		t.Fatalf("the accepting activator saw %v", seen)
	}
	// And rollback goes through the same hook, with its own kind: promote a
	// v2, then roll back to v1.
	v2 := organizationDocumentWith(t, api.Catalog(), func(m *Metadata, d *pdp.Document) {
		m.Supersedes = art.Digest()
		d.Version = 2
	})
	_, priv := testKeys(t)
	art2, _, err := api.Publish(ctx, v2, organizationPublishOptions(t, priv))
	if err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	if _, err := api.Promote(ctx, pdp.RootOrganization, art2.Digest(), pid(t, principalBob), timeFixture(), "v2"); err != nil {
		t.Fatalf("promote v2: %v", err)
	}
	seen = nil
	if _, err := api.Rollback(ctx, pdp.RootOrganization, art.Digest(), pid(t, principalBob), timeFixture(), "restore"); err != nil {
		t.Fatalf("rollback under an accepting activator: %v", err)
	}
	if len(seen) != 1 || seen[0] != "rollback:"+art.Digest() {
		t.Fatalf("the activator saw %v for a rollback", seen)
	}
}
