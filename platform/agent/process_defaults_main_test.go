// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

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
func TestMain(m *testing.M) {
	for name, install := range map[string]func() error{
		"shared engine":     installDefaultTestEngine,
		"anchored enforcer": installDefaultTestEnforcer,
	} {
		if err := install(); err != nil {
			fmt.Fprintf(os.Stderr, "installing the package's default %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
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
	}, boot.Admitter, boot.Registry.Epoch)
	if err != nil {
		return err
	}
	anchoredEnforcerInstance.Store(e)
	return nil
}
