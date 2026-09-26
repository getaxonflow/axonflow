// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4249 row 5774029945: the deployment's approval window reaches the engine
// every anchored activation builds. activation.Inputs.ApprovalTTL existed and
// no production caller set it, so every approval expired at the engine's
// 15-minute default whatever the deployment wanted.

import (
	"context"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
)

func newTTLEnforcer(t *testing.T) (*anchoredenforcer.Enforcer, error) {
	t.Helper()
	setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil || snap == nil {
		t.Fatalf("resolving the deployment vocabulary: %v", err)
	}
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return anchoredenforcer.New(respDocuments{}, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch, sharedidentity.NoGraphOnlyResolver{},
		anchoredenforcer.Options{Overrides: orchestratorRecordedOverrides, Delivers: orchestratorSeamDelivers, EditionBoundary: orchestratorEditionBoundary})
}

func TestTheDeploymentApprovalWindowReachesTheActivatedEngine(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"unset: the engine's 15 minutes", "", 15 * time.Minute},
		{"a day", "86400", 24 * time.Hour},
		{"a minute", "60", time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(anchoredenforcer.ApprovalTTLEnv, tc.raw)
			e, err := newTTLEnforcer(t)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			act, err := e.ActivationFor(context.Background(), wcpSeamScope, "org-ttl", "", nil)
			if err != nil {
				t.Fatalf("ActivationFor: %v", err)
			}
			if got := act.Engine.ApprovalTTL(); got != tc.want {
				t.Errorf("the activated engine stamps %v, want %v", got, tc.want)
			}
		})
	}
}

// An invalid window refuses the enforcer, which both processes answer by
// refusing to boot (wireOrchestratorEnforcer, the agent's wireEnforcingSeams).
func TestAnInvalidDeploymentApprovalWindowRefusesTheEnforcer(t *testing.T) {
	t.Setenv(anchoredenforcer.ApprovalTTLEnv, "30")
	e, err := newTTLEnforcer(t)
	if err == nil || e != nil || !strings.Contains(err.Error(), anchoredenforcer.ApprovalTTLEnv) {
		t.Fatalf("New = %v, %v; want refused naming %s", e, err, anchoredenforcer.ApprovalTTLEnv)
	}
}
