// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// AdmissionBootstrapConfig is what a binary knows at boot about verifying its
// callers' credentials.
type AdmissionBootstrapConfig struct {
	// Deployment describes what this deployment actually wired, and is what
	// the built-in realms are derived from.
	Deployment BuiltinRealmDeployment
	// ExtraRealmSources builds the sources consulted after the built-ins, in
	// order. The enterprise OIDC realm source goes here.
	//
	// It is a FUNCTION of the registry rather than a slice because a realm
	// source registers into the registry, and the registry is created here.
	// The alternative - construct the admitter, then attach sources to it -
	// would make its source list mutable after the first request has already
	// been served against it, which is a realm set that changes under a
	// running verification.
	ExtraRealmSources func(reg *RealmRegistry) ([]RealmSource, error)
	// Revocations is the oracle consulted for realms declaring a revocation
	// source. Nil is legitimate for a deployment whose realms all declare
	// RevocationSourceNone; it is an outage for one that does not.
	Revocations RevocationOracle
}

// AdmissionBootstrap is the assembled subject admission.
type AdmissionBootstrap struct {
	// Registry holds the declared realms.
	Registry *RealmRegistry
	// Realms is the realm source an organization's realms are established
	// through. Exposed for the CAEP push receiver, which must establish them
	// BEFORE resolving a SET's issuer: realms are registered lazily on the
	// first admission, so a push that arrives first would otherwise read as an
	// undeclared issuer.
	Realms RealmSource
	// Admitter admits each request's subject for the enforcing planes.
	Admitter *SubjectAdmitter
}

// BootstrapAdmission assembles the realm registry, the built-in realm source
// with the configured extra sources after it, and the admitter over them.
func BootstrapAdmission(cfg AdmissionBootstrapConfig) (*AdmissionBootstrap, error) {
	registry := NewRealmRegistry()
	var extra []RealmSource
	if cfg.ExtraRealmSources != nil {
		var err error
		extra, err = cfg.ExtraRealmSources(registry)
		if err != nil {
			return nil, err
		}
	}
	source, err := NewBuiltinRealmSource(registry, cfg.Deployment, extra...)
	if err != nil {
		return nil, err
	}
	var opts []SubjectAdmitterOption
	if cfg.Revocations != nil {
		opts = append(opts, WithAdmitterRevocations(cfg.Revocations))
	}
	admitter, err := NewSubjectAdmitter(registry, source, opts...)
	if err != nil {
		return nil, err
	}
	return &AdmissionBootstrap{Registry: registry, Realms: source, Admitter: admitter}, nil
}
