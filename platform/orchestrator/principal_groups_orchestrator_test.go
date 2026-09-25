// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
)

// NO ORCHESTRATOR SEAM STATES principal.groups (#4249 row 5667380844; the
// forced plumbing of the agent-side change). The enforcer resolves a group
// closure only for a subject admitted through the user door, and all four of
// this process's seams present the credential the agent authenticated
// (headerCredentialSubject), so the resolver the install passes is never
// reached and every verdict's identity detail is empty. The day either stops
// holding, the orchestrator half of the design has begun, and these fail.

type orchestratorGroupsRecorder struct {
	mu    sync.Mutex
	calls int
}

func (r *orchestratorGroupsRecorder) ResolveClosure(_ context.Context, _ string, _ sharedidentity.TrustRealm,
	subject sharedidentity.ClosureSubject, _ sharedidentity.ClosureBounds) sharedidentity.ClosureResult {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return sharedidentity.NewUnreachableClosure(subject.Principal, "the orchestrator reached a group closure", time.Now())
}

func (r *orchestratorGroupsRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// The install hands the enforcer the resolver that cannot state a directory's
// groups.
func TestTheOrchestratorInstallPassesTheNoGraphResolver(t *testing.T) {
	isolateOrchestratorEnforcer(t)
	setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var passed sharedidentity.GroupClosureResolver
	newOrchestratorEnforcer = func(d anchoredenforcer.ActiveDocumentSource, v func() (*authoringcatalog.Snapshot, error), a *sharedidentity.SubjectAdmitter,
		epoch func() int64, groups sharedidentity.GroupClosureResolver, o anchoredenforcer.Options) (*anchoredenforcer.Enforcer, error) {
		passed = groups
		return anchoredenforcer.New(d, v, a, epoch, groups, o)
	}
	if err := installOrchestratorEnforcer(db); err != nil {
		t.Fatalf("PREMISE: the install refused: %v", err)
	}
	if _, ok := passed.(sharedidentity.NoGraphOnlyResolver); !ok {
		t.Fatalf("the install passed %T; want sharedidentity.NoGraphOnlyResolver", passed)
	}
}

// Every orchestrator seam's subject is the credential, so a real enforcer with a
// recording resolver never reaches it and states no identity detail, on both
// editions.
func TestNoOrchestratorSeamReachesTheGroupClosure(t *testing.T) {
	for _, mode := range []string{"community", "enterprise"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
			snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
			if err != nil {
				t.Fatal(err)
			}
			boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{Deployment: orchestratorRealmDeployment})
			if err != nil {
				t.Fatal(err)
			}
			groups := &orchestratorGroupsRecorder{}
			e, err := anchoredenforcer.New(respDocuments{}, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch, groups,
				anchoredenforcer.Options{Overrides: orchestratorRecordedOverrides, Delivers: orchestratorSeamDelivers, EditionBoundary: orchestratorEditionBoundary})
			if err != nil {
				t.Fatal(err)
			}
			subject := headerCredentialSubject(respHeaders())
			if s, ok := subject(time.Now()); !ok || !s.Credential {
				t.Fatalf("PREMISE: the seams' subject builder answered (%+v, %v); want the credential", s, ok)
			}
			if len(orchestratorEnforcingScopes) == 0 {
				t.Fatal("PREMISE: no orchestrator enforcing scope registered")
			}
			for _, scope := range orchestratorEnforcingScopes {
				v := e.Evaluate(context.Background(), anchoredenforcer.Call{
					Scope: scope, OrgID: respOrg, RequestID: "req-groups-" + scope.String(),
					Action: authoringcatalog.ActionLLMCompletion, Subject: subject, Query: "hello",
				})
				if v.Unavailable != "" || v.Decision == nil {
					t.Fatalf("PREMISE: %s did not decide (unavailable %q)", scope, v.Unavailable)
				}
				if v.IdentityDetail != "" {
					t.Errorf("%s stated identity detail %q; want none for a credential subject", scope, v.IdentityDetail)
				}
			}
			if n := groups.count(); n != 0 {
				t.Fatalf("an orchestrator scope reached the group closure %d times; want never", n)
			}
		})
	}
}
