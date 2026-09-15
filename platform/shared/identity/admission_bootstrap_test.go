// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestNewSubjectAdmitterRefusesWhatWouldRefuseEverything: without a registry
// or a realm source every credential would be refused UNKNOWN_REALM, so both
// are refused at construction rather than at the first request.
func TestNewSubjectAdmitterRefusesWhatWouldRefuseEverything(t *testing.T) {
	reg := NewRealmRegistry()
	src, err := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	if _, err := NewSubjectAdmitter(nil, src); err == nil {
		t.Error("an admitter with no realm registry was built")
	}
	if _, err := NewSubjectAdmitter(reg, nil); err == nil {
		t.Error("an admitter with no realm source was built")
	}
	a, err := NewSubjectAdmitter(reg, src)
	if err != nil || a.now == nil {
		t.Fatalf("NewSubjectAdmitter(registry, source) = %v, %v; want an admitter with a clock", a, err)
	}
}

// revokedDeployment is a deployment whose minted realm declares a revocation
// source, and an oracle that has revoked mintedClaims' jti.
func revokedDeployment() (BuiltinRealmDeployment, RevocationOracle) {
	return BuiltinRealmDeployment{HasRevocation: true}, staticRevocations{revoked: map[string]bool{"jti-1": true}}
}

// TestBootstrapAdmissionWiresTheRevocationOracle: the admission the enforcing
// planes admit through consults the configured oracle, so a revoked token is
// refused as revoked rather than admitted or reported as an outage.
func TestBootstrapAdmissionWiresTheRevocationOracle(t *testing.T) {
	dep, oracle := revokedDeployment()
	adm, err := BootstrapAdmission(AdmissionBootstrapConfig{Deployment: dep, Revocations: oracle})
	if err != nil {
		t.Fatalf("BootstrapAdmission: %v", err)
	}
	adm.Admitter.now = func() time.Time { return fixtureNow }
	chain, got := adm.Admitter.AdmitDecisionSubject(context.Background(),
		HS256Principal(fixtureOrg, mintedClaims(), true, ""), DefaultMaxDelegationDepth)
	if chain != nil || got.Reason != ReasonCredentialRevoked {
		t.Fatalf("admission = %s %s (chain %v), want a refusal for %s", got.State, got.Reason, chain, ReasonCredentialRevoked)
	}
}

// TestBootstrapAdmissionPropagatesAnExtraSourceFailure: a realm source that
// could not be built is a boot failure, never a deployment that silently
// declares fewer realms than it was configured with.
func TestBootstrapAdmissionPropagatesAnExtraSourceFailure(t *testing.T) {
	boom := errors.New("no OIDC provider")
	_, err := BootstrapAdmission(AdmissionBootstrapConfig{
		ExtraRealmSources: func(*RealmRegistry) ([]RealmSource, error) { return nil, boom },
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the extra source's failure", err)
	}
}
