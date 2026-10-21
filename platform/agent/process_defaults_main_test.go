// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"testing"

	"axonflow/platform/agent/license"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
)

// TestMain runs this package's tests in the process an agent actually is: one
// with the shared engine loaded from a migrated database and the anchored
// enforcer installed. Boot refuses to start without the enforcer
// (wireEnforcingSeams), and a migrated database cannot lose the shipped system
// rows, so a handler test missing either would measure a process that cannot
// exist - every request pass would fail closed.
//
// The engine reads the shipped rows, none of which matches a test's content
// (migrated_database_test.go). The enforcer serves no organization a document,
// so every organization is decided under its implicit baseline (PRD v11 §1.4).
// A test that needs planted rows, a published document, an unreadable store or
// no enforcer at all installs its own and restores the default at cleanup.
//
// It also installs an EPHEMERAL licence-signing key pair (#4470): the verifier
// trusts a fresh pair generated for this process, and the package's licence
// helpers sign with its private halves. No test in this package holds, or
// needs, the private half of a key a shipped binary trusts.
func TestMain(m *testing.M) {
	for name, install := range map[string]func() error{
		"shared engine":                  installDefaultTestEngine,
		"anchored enforcer":              installDefaultTestEnforcer,
		"ephemeral licence signing keys": installEphemeralLicenseSigningKeys,
	} {
		if err := install(); err != nil {
			fmt.Fprintf(os.Stderr, "installing the package's default %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// testEvalLicenseSigningKey and testEntLicenseSigningKey sign the licences this
// package's tests mint: Evaluation tier with the first, every other tier with
// the second. They are generated per test process by
// installEphemeralLicenseSigningKeys and their public halves are the only keys
// the licence verifier trusts in that process. A test that installs its own
// pair with license.OverridePublicKeysForTest restores these at cleanup,
// because the override saves whatever is installed when it is called.
var (
	testEvalLicenseSigningKey ed25519.PrivateKey
	testEntLicenseSigningKey  ed25519.PrivateKey
)

// installEphemeralLicenseSigningKeys generates the package's licence-signing
// pair and installs its public halves in the verifier for the life of the
// process (the restore func is deliberately dropped: TestMain exits after
// m.Run). Until #4470 the helpers signed with the PRODUCTION private seeds,
// committed as "test seeds", because nothing replaced the compiled-in keys.
func installEphemeralLicenseSigningKeys() error {
	evalPub, evalPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("evaluation key: %w", err)
	}
	entPub, entPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("enterprise key: %w", err)
	}
	testEvalLicenseSigningKey, testEntLicenseSigningKey = evalPriv, entPriv
	_ = license.OverridePublicKeysForTest(evalPub, entPub)
	return nil
}

// testLicenseSigningKeyForTier returns the ephemeral key that signs tier:
// the evaluation key for "Evaluation", the enterprise key for every other tier
// (Professional, Enterprise, Plus), matching the verifier's key selection.
func testLicenseSigningKeyForTier(tier string) ed25519.PrivateKey {
	if tier == "Evaluation" {
		return testEvalLicenseSigningKey
	}
	return testEntLicenseSigningKey
}

// noDocumentsPublished is an active-document source for a deployment in which
// no organization has published a document.
type noDocumentsPublished struct{}

func (noDocumentsPublished) ActiveTip(context.Context, string) (string, int64, error) {
	return "", 0, nil
}

func (noDocumentsPublished) Load(context.Context, string, string) (*authoring.Artifact, *pdp.TrustStore, error) {
	return nil, nil, errors.New("no organization has published a document")
}

// installDefaultTestEnforcer installs the package default. Its vocabulary is
// resolved on every activation rather than memoized as boot memoizes it: a
// process's edition is fixed, but this package's tests set DEPLOYMENT_MODE
// per test, and a memoized vocabulary would decide every later test under the
// first one's edition.
func installDefaultTestEnforcer() error {
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		return err
	}
	e, err := newAnchoredEnforcer(noDocumentsPublished{}, func() (*authoringcatalog.Snapshot, error) {
		return authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	}, boot.Admitter, boot.Registry.Epoch, sharedidentity.NoGraphOnlyResolver{})
	if err != nil {
		return err
	}
	anchoredEnforcerInstance.Store(e)
	return nil
}
