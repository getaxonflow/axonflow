// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Cross-tenant isolation of the connector registry (#3067 S-1 / S-5).
//
// Before this change the registry was a flat `map[name]Connector` +
// `map[name]*ConnectorConfig` filled deployment-wide from a BYPASSRLS read,
// and every accessor took a bare name. A caller that named another tenant's
// connector resolved it and executed against it with the victim's
// ConnectionURL and decrypted Credentials.
//
// Every test here is written so that it FAILS against the pre-fix code: the
// pre-fix Get(name) resolved tenant A's connector for any caller, so the
// "tenant B cannot resolve" assertions would not hold. The signatures
// themselves changed, so the vacuity proof is compile-level as well —
// the pre-fix by-name accessors no longer exist.

package registry

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
)

const (
	tenantA = "org-alpha"
	tenantB = "org-beta"
)

// twoTenantRegistry builds a registry holding one connector per tenant, both
// named the same thing — the exact shape a by-name lookup cannot disambiguate.
func twoTenantRegistry(t *testing.T) (*Registry, *mockConnector, *mockConnector) {
	t.Helper()

	r := NewRegistry()

	connA := &mockConnector{name: "shared-name", connType: "postgres", healthy: true}
	if err := r.Register("shared-name", connA, &base.ConnectorConfig{
		Name:          "shared-name",
		Type:          "postgres",
		TenantID:      tenantA,
		ConnectionURL: "postgres://alpha-secret@alpha-db/alpha",
		Credentials:   map[string]string{"password": "alpha-password"},
		Timeout:       5 * time.Second,
	}); err != nil {
		t.Fatalf("register tenant A connector: %v", err)
	}

	connB := &mockConnector{name: "shared-name", connType: "postgres", healthy: true}
	if err := r.Register("shared-name", connB, &base.ConnectorConfig{
		Name:          "shared-name",
		Type:          "postgres",
		TenantID:      tenantB,
		ConnectionURL: "postgres://beta-secret@beta-db/beta",
		Credentials:   map[string]string{"password": "beta-password"},
		Timeout:       5 * time.Second,
	}); err != nil {
		t.Fatalf("register tenant B connector: %v", err)
	}

	return r, connA, connB
}

func TestRegistry_TenantsCannotResolveEachOthersConnectors(t *testing.T) {
	r, connA, connB := twoTenantRegistry(t)

	// Positive control: each tenant resolves ITS OWN connector instance.
	gotA, err := r.Get(tenantA, "shared-name")
	if err != nil {
		t.Fatalf("tenant A must still resolve its own connector: %v", err)
	}
	if gotA != base.Connector(connA) {
		t.Error("tenant A resolved the wrong connector instance")
	}

	gotB, err := r.Get(tenantB, "shared-name")
	if err != nil {
		t.Fatalf("tenant B must still resolve its own connector: %v", err)
	}
	if gotB != base.Connector(connB) {
		t.Error("tenant B resolved the wrong connector instance")
	}

	// Refusal: a third tenant naming the connector explicitly gets nothing.
	if _, err := r.Get("org-gamma", "shared-name"); err == nil {
		t.Fatal("a tenant with no connector of this name must not resolve another tenant's")
	}
}

func TestRegistry_CredentialsNeverCrossTenants(t *testing.T) {
	r, _, _ := twoTenantRegistry(t)

	cfgA, err := r.GetConfig(tenantA, "shared-name")
	if err != nil {
		t.Fatalf("positive control: tenant A must read its own config: %v", err)
	}
	if cfgA.Credentials["password"] != "alpha-password" {
		t.Fatalf("tenant A got the wrong config: %q", cfgA.ConnectionURL)
	}

	cfgB, err := r.GetConfig(tenantB, "shared-name")
	if err != nil {
		t.Fatalf("positive control: tenant B must read its own config: %v", err)
	}
	// The core assertion: B's by-name read must NOT hand back A's credentials.
	if cfgB.Credentials["password"] == "alpha-password" || cfgB.ConnectionURL == cfgA.ConnectionURL {
		t.Fatal("tenant B resolved tenant A's connection URL / credentials")
	}

	if _, err := r.GetConfig("org-gamma", "shared-name"); err == nil {
		t.Fatal("an unrelated tenant must not read either config")
	}
}

func TestRegistry_ListAndHealthCheckAreTenantScoped(t *testing.T) {
	r := NewRegistry()

	if err := r.Register("alpha-db", &mockConnector{connType: "postgres", healthy: true},
		&base.ConnectorConfig{Name: "alpha-db", Type: "postgres", TenantID: tenantA, Timeout: time.Second}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register("beta-db", &mockConnector{connType: "postgres", healthy: false},
		&base.ConnectorConfig{Name: "beta-db", Type: "postgres", TenantID: tenantB, Timeout: time.Second}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register("operator-db", &mockConnector{connType: "postgres", healthy: true},
		&base.ConnectorConfig{Name: "operator-db", Type: "postgres", TenantID: SharedTenant, Timeout: time.Second}); err != nil {
		t.Fatalf("register: %v", err)
	}

	namesA := r.List(tenantA)
	if !contains(namesA, "alpha-db") {
		t.Error("positive control: tenant A must see its own connector")
	}
	if !contains(namesA, "operator-db") {
		t.Error("positive control: tenant A must see deployment-shared connectors")
	}
	if contains(namesA, "beta-db") {
		t.Fatal("tenant A must NOT see tenant B's connector in List")
	}

	typesA := r.ListWithTypes(tenantA)
	if _, ok := typesA["beta-db"]; ok {
		t.Fatal("tenant A must NOT see tenant B's connector in ListWithTypes")
	}

	// HealthCheck must not even OPEN a connection for a foreign connector —
	// the pre-fix version returned every tenant's raw driver error string.
	healthA := r.HealthCheck(context.Background(), tenantA)
	if _, ok := healthA["alpha-db"]; !ok {
		t.Error("positive control: tenant A must get health for its own connector")
	}
	if _, ok := healthA["beta-db"]; ok {
		t.Fatal("tenant A health check reached tenant B's connector")
	}

	if _, err := r.HealthCheckSingle(context.Background(), tenantA, "beta-db"); err == nil {
		t.Fatal("tenant A must not health-check tenant B's connector by name")
	}
	if _, err := r.HealthCheckSingle(context.Background(), tenantB, "beta-db"); err != nil {
		t.Fatalf("positive control: tenant B must health-check its own connector: %v", err)
	}

	if got := r.CountForTenant(tenantA); got != 2 {
		t.Errorf("tenant A should count its own + shared = 2, got %d", got)
	}
	if got := r.Count(); got != 3 {
		t.Errorf("deployment-wide count should still see all 3, got %d", got)
	}
}

func TestRegistry_UnregisterCannotRemoveAnotherTenantsConnector(t *testing.T) {
	r, _, connB := twoTenantRegistry(t)

	// Refusal: A cannot unregister B's connector by naming it.
	if err := r.Unregister(tenantA, "only-b-has-this"); err == nil {
		t.Fatal("unregistering a name the caller does not own must fail")
	}

	// The tenant-A unregister removes ONLY tenant A's entry.
	if err := r.Unregister(tenantA, "shared-name"); err != nil {
		t.Fatalf("positive control: tenant A must unregister its own connector: %v", err)
	}
	got, err := r.Get(tenantB, "shared-name")
	if err != nil {
		t.Fatalf("tenant B's connector must survive tenant A's unregister: %v", err)
	}
	if got != base.Connector(connB) {
		t.Error("tenant B resolved the wrong connector after tenant A unregistered")
	}
}

// TestRegistry_UnregisterCannotRemoveTheSharedConnector (R3): reads may fall
// back to the deployment-shared scope; a MUTATION must not. With the read
// resolver here, any tenant could unregister — and DELETE from storage — the
// operator's shared connector, taking it away from every other tenant.
func TestRegistry_UnregisterCannotRemoveTheSharedConnector(t *testing.T) {
	r := NewRegistry()

	shared := &mockConnector{connType: "postgres", healthy: true}
	if err := r.Register("operator-db", shared,
		&base.ConnectorConfig{Name: "operator-db", Type: "postgres", TenantID: SharedTenant, Timeout: time.Second}); err != nil {
		t.Fatalf("register shared: %v", err)
	}

	// Positive control first: every tenant CAN reach it.
	if _, err := r.Get(tenantA, "operator-db"); err != nil {
		t.Fatalf("positive control: a tenant must reach the shared connector: %v", err)
	}

	if err := r.Unregister(tenantA, "operator-db"); err == nil {
		t.Fatal("SECURITY: a tenant unregistered the deployment-shared connector")
	}

	// ...and it is still there for everyone.
	if _, err := r.Get(tenantB, "operator-db"); err != nil {
		t.Fatalf("SECURITY: the shared connector was removed by a tenant's unregister: %v", err)
	}

	// The operator (shared scope) can still remove it.
	if err := r.Unregister(SharedTenant, "operator-db"); err != nil {
		t.Fatalf("positive control: the shared scope must be able to unregister its own connector: %v", err)
	}
	if _, err := r.Get(tenantB, "operator-db"); err == nil {
		t.Fatal("the shared connector should be gone after the shared-scope unregister")
	}
}

// TestRegistry_NameCollisionAcrossTenantsIsRefusedWithStorage (R3): the
// in-memory map is tenant-keyed but `connectors.id` is a deployment-wide
// primary key whose upsert does NOT rewrite tenant_id. Allowing two tenants to
// hold the same name in memory would either silently produce a memory-only
// connector (the write fails, Register only warns) or overwrite the first
// tenant's row with the second's credentials. The flat map's global duplicate
// check used to make both impossible.
func TestRegistry_NameCollisionAcrossTenantsIsRefusedWithStorage(t *testing.T) {
	r := NewRegistry()
	// Simulate a persistence-backed registry without a live database: the flag
	// is what NewRegistryWithStorage sets, and it is the only thing the
	// collision guard consults.
	r.deploymentWideNames = true

	cfg := func(tenant string) *base.ConnectorConfig {
		return &base.ConnectorConfig{Name: "postgres", Type: "postgres", TenantID: tenant, Timeout: time.Second}
	}

	if err := r.Register("postgres", &mockConnector{connType: "postgres"}, cfg(tenantA)); err != nil {
		t.Fatalf("first registration must succeed: %v", err)
	}
	if err := r.Register("postgres", &mockConnector{connType: "postgres"}, cfg(tenantB)); err == nil {
		t.Fatal("a second tenant claiming a name already persisted deployment-wide must be refused")
	}

	// Tenant A's entry — and its credentials — are untouched.
	cfgA, err := r.GetConfig(tenantA, "postgres")
	if err != nil {
		t.Fatalf("tenant A's connector must survive: %v", err)
	}
	if cfgA.TenantID != tenantA {
		t.Fatalf("tenant A's connector was rebound to %q", cfgA.TenantID)
	}

	// Without storage the in-memory registry has no deployment-wide id to
	// collide with, so per-tenant names remain independent.
	mem := NewRegistry()
	if err := mem.Register("postgres", &mockConnector{connType: "postgres"}, cfg(tenantA)); err != nil {
		t.Fatalf("in-memory first registration: %v", err)
	}
	if err := mem.Register("postgres", &mockConnector{connType: "postgres"}, cfg(tenantB)); err != nil {
		t.Fatalf("in-memory registry has no deployment-wide id constraint, so this must still succeed: %v", err)
	}
}

func TestRegistry_ValidateTenantAccessUsesTheKeyNotAFieldCompare(t *testing.T) {
	r, _, _ := twoTenantRegistry(t)

	if err := r.ValidateTenantAccess("shared-name", tenantA); err != nil {
		t.Fatalf("positive control: tenant A has access to its own connector: %v", err)
	}
	if err := r.ValidateTenantAccess("shared-name", "org-gamma"); err == nil {
		t.Fatal("an unrelated tenant must be refused")
	}

	// Deployment-shared connectors stay reachable by every tenant — the
	// pre-existing `tenant_id = '*'` semantic, deliberately preserved.
	if err := r.Register("operator-db", &mockConnector{connType: "http", healthy: true},
		&base.ConnectorConfig{Name: "operator-db", Type: "http", TenantID: SharedTenant, Timeout: time.Second}); err != nil {
		t.Fatalf("register shared: %v", err)
	}
	if err := r.ValidateTenantAccess("operator-db", "org-gamma"); err != nil {
		t.Fatalf("shared connectors must remain reachable: %v", err)
	}
}

// TestRegistry_SameNameDifferentTenantsIsNotADuplicate proves the duplicate
// check is no longer a cross-tenant existence oracle: two tenants may each
// register `postgres` and neither learns about the other.
func TestRegistry_SameNameDifferentTenantsIsNotADuplicate(t *testing.T) {
	// No storage: no deployment-wide `connectors.id` to collide with, so the
	// tenant-keyed map is the only constraint. (With storage configured the
	// deployment-wide guard applies — see
	// TestRegistry_NameCollisionAcrossTenantsIsRefusedWithStorage.)
	r := NewRegistry()

	cfg := func(tenant string) *base.ConnectorConfig {
		return &base.ConnectorConfig{Name: "postgres", Type: "postgres", TenantID: tenant, Timeout: time.Second}
	}

	if err := r.Register("postgres", &mockConnector{connType: "postgres"}, cfg(tenantA)); err != nil {
		t.Fatalf("tenant A register: %v", err)
	}
	if err := r.Register("postgres", &mockConnector{connType: "postgres"}, cfg(tenantB)); err != nil {
		t.Fatalf("tenant B must be able to use the same connector name: %v", err)
	}
	// ...but a second registration WITHIN a tenancy is still a duplicate.
	if err := r.Register("postgres", &mockConnector{connType: "postgres"}, cfg(tenantA)); err == nil {
		t.Fatal("re-registering within the same tenancy must still be rejected")
	}
}

// TestRegistry_NameCannotBeCraftedToCollideWithAnotherTenant guards the key
// encoding itself: the separator is NUL, which cannot appear in a connector
// name sourced from a Postgres text column, so no name can be shaped to
// resolve into a different tenancy.
func TestRegistry_NameCannotBeCraftedToCollideWithAnotherTenant(t *testing.T) {
	r, _, _ := twoTenantRegistry(t)

	for _, crafted := range []string{
		tenantA + ":shared-name",
		tenantA + "/shared-name",
		tenantA + "\x00shared-name",
	} {
		if _, err := r.Get(tenantB, crafted); err == nil {
			t.Errorf("crafted name %q resolved across tenancies", crafted)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
