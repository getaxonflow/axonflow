// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// THE ORCHESTRATOR'S ANCHORED ENFORCER (PRD v11 §1.1).
//
// The anchored engine authors the verdict on every enforcing scope this binary
// decides, through the ONE enforcer every enforcing process shares
// (platform/shared/anchoredenforcer), installed here once at boot. This file
// wires it and nothing else: each enforcing seam registers its scope in
// orchestratorEnforcingScopes in its own change, and decides through
// orchestratorEnforcer().
//
// What only this process can supply, it supplies:
//
//   - the identity plane: sharedidentity.BootstrapAdmission over what this
//     process wired (orchestratorRealmDeployment, which initSegmentPolicyGate
//     settles before the install runs);
//   - each organization's active typed document, read from usageDB;
//   - the deployment vocabulary, resolved on first use and memoized on success;
//   - the recorded detection overrides, read FAIL-CLOSED through the override
//     cache InitDetectionOverrides wires: a store error is an error, never
//     "no override", because enforcing the shipped action an organization
//     recorded a change to is not a safe answer;
//   - what each registered scope's wire delivers (legacycompile.ScopeDeliveries);
//   - the edition boundary, resolved from this process's licence HERE, under
//     the orchestrator's Dockerfile (the authoring-edition deployment guard).
//
// FATAL, NOT DEGRADED. A process that serves an enforcing scope with no
// enforcer would fail every request closed, an outage that reads as a policy
// decision, so an orchestrator that has no database or cannot build its
// enforcer refuses to start, as the agent's does (wireEnforcingSeams).
//
// Edition: community-visible, no build tag.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync/atomic"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/authoringedition"
	"axonflow/platform/shared/authoringvocabulary"
	"axonflow/platform/shared/detectionposture"
	sharedidentity "axonflow/platform/shared/identity"
)

// anchoredEnforcement is what an orchestrator enforcing seam decides through:
// the shared enforcer's one decision path. It is an interface so a seam's tests
// can install a double; the process installs *anchoredenforcer.Enforcer.
type anchoredEnforcement interface {
	Evaluate(ctx context.Context, call anchoredenforcer.Call) anchoredenforcer.Verdict
}

// orchestratorEnforcerSlot holds the installed enforcement, so the pointer can
// be swapped atomically whatever its dynamic type.
type orchestratorEnforcerSlot struct {
	enforcement anchoredEnforcement
}

var orchestratorEnforcerInstance atomic.Pointer[orchestratorEnforcerSlot]

// orchestratorEnforcer is the process enforcer, nil when none is wired. A seam
// that reads nil fails closed with anchoredenforcer.CauseNotWired; a serving
// orchestrator is never in that state, because wiring one is fatal at boot.
func orchestratorEnforcer() anchoredEnforcement {
	if slot := orchestratorEnforcerInstance.Load(); slot != nil {
		return slot.enforcement
	}
	return nil
}

// orchestratorEnforcingScopes is every enforcing scope this binary wires: the
// list /health reports, and the scopes the enforcer tells activation what their
// wire delivers. Each seam registers its own scope in its own change, so two
// seams landing separately add disjoint entries.
var orchestratorEnforcingScopes = []legacycompile.EnforcementScope{}

// orchestratorSeamDelivers is what the seam registered for scope delivers, read
// from the one statement of it (legacycompile.ScopeDeliveries); nil for a scope
// with no seam in this binary.
func orchestratorSeamDelivers(scope legacycompile.EnforcementScope) []contract.Capability {
	for _, registered := range orchestratorEnforcingScopes {
		if registered == scope {
			return legacycompile.ScopeDeliveries(scope)
		}
	}
	return nil
}

// orchestratorEnforcingScopeNames is the registration list as /health and the
// boot log name it, sorted, and never nil.
func orchestratorEnforcingScopeNames() []string {
	names := make([]string, 0, len(orchestratorEnforcingScopes))
	for _, scope := range orchestratorEnforcingScopes {
		names = append(names, scope.String())
	}
	sort.Strings(names)
	return names
}

// The two constructors the install calls, replaceable so a test can make each
// fail and prove the refusal.
var (
	bootstrapOrchestratorAdmission = sharedidentity.BootstrapAdmission
	newOrchestratorEnforcer        = anchoredenforcer.New
)

// installOrchestratorEnforcer builds the process enforcer and installs it, or
// says which dependency is missing. Nothing is installed on a refusal.
func installOrchestratorEnforcer(db *sql.DB) error {
	if db == nil {
		return errors.New("the anchored engine authors every enforcing plane's verdict and reads each organization's typed policy from the database, and this orchestrator has no database (PRD v11 §1.1)")
	}
	if getDetectionOverrideCache() == nil {
		return errors.New("the anchored engine enforces each organization's recorded detection overrides, and this orchestrator's override store is not wired")
	}
	boot, err := bootstrapOrchestratorAdmission(sharedidentity.AdmissionBootstrapConfig{Deployment: orchestratorRealmDeployment})
	if err != nil {
		return fmt.Errorf("the anchored engine admits each request's subject through the identity plane, and the orchestrator's identity plane could not be assembled: %w", err)
	}
	if boot == nil || boot.Admitter == nil || boot.Registry == nil {
		return errors.New("the anchored engine admits each request's subject through the identity plane, and the orchestrator's identity plane is not bootstrapped")
	}
	enforcer, err := newOrchestratorEnforcer(
		anchoredenforcer.NewDurableActiveDocuments(db),
		// The deployment vocabulary is read lazily, so what this process wired is
		// settled before it is read, as the agent's is.
		anchoredenforcer.MemoizedDeploymentVocabulary(func() (*authoringcatalog.Snapshot, error) {
			return authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, orchestratorRealmDeployment)
		}),
		boot.Admitter,
		boot.Registry.Epoch,
		anchoredenforcer.Options{
			Overrides:       orchestratorRecordedOverrides,
			Delivers:        orchestratorSeamDelivers,
			EditionBoundary: orchestratorEditionBoundary,
		},
	)
	if err != nil {
		return fmt.Errorf("the orchestrator's anchored enforcer could not be built: %w", err)
	}
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: enforcer})
	return nil
}

// wireOrchestratorEnforcer installs the process enforcer, and refuses to boot
// when it cannot (PRD v11 §1.1).
func wireOrchestratorEnforcer(db *sql.DB) {
	if err := installOrchestratorEnforcer(db); err != nil {
		log.Fatalf("❌ [ANCHORED-ENFORCE] %v", err)
	}
	names := orchestratorEnforcingScopeNames()
	if len(names) == 0 {
		log.Println("✅ [ANCHORED-ENFORCE] the orchestrator's anchored enforcer is wired; no enforcing scope is registered in this binary yet")
		return
	}
	log.Printf("✅ [ANCHORED-ENFORCE] the orchestrator's anchored enforcer authors every verdict on: %s", strings.Join(names, ", "))
}

// orchestratorRecordedOverrides is the enforcer's read of an organization's
// recorded detection overrides, in the anchored engine's key. It fails CLOSED:
// a store that cannot be read is an error (detectionOverrideCache.read), and so
// is an override store that was never wired, because the install refuses that
// process and a request reaching this read without one is a wiring defect.
func orchestratorRecordedOverrides(ctx context.Context, orgID string) (legacycompile.CategoryActions, error) {
	cache := getDetectionOverrideCache()
	if cache == nil {
		return nil, errors.New("the orchestrator's recorded detection overrides are not wired")
	}
	if orgID == "" {
		return nil, nil
	}
	recorded, err := cache.read(ctx, orgID)
	if err != nil {
		return nil, err
	}
	plain := make(map[string]string, len(recorded))
	for category, action := range recorded {
		plain[category] = string(action)
	}
	return detectionposture.AnchoredCategoryActions(plain)
}

// orchestratorEditionBoundary is the edition boundary every activation this
// process builds is gated by: the deployment's authoring profile, and whether
// the construct check may refuse. It is GATED rather than unconditional, as
// the agent's is: an activation error on an enforcing scope refuses the
// request, so it must not fire for a deployment that merely cannot establish
// its tier, nor for one whose operator has declared a licence transition.
// EnforcesConstructBoundary is that question, asked once, by the one resolver.
func orchestratorEditionBoundary(ctx context.Context) (authoring.Profile, bool) {
	edition := authoringedition.Resolve(ctx)
	return edition.Profile, edition.EnforcesConstructBoundary()
}

// orchestratorDecisionPosture is /health's `decision` member: the scopes whose
// verdict the anchored engine authors in this process (PRD v11 §5.1), the same
// member the agent's /health carries. It is nil, and the member OMITTED, only
// on a process with no enforcer, which a serving orchestrator is not.
func orchestratorDecisionPosture() map[string]interface{} {
	if orchestratorEnforcer() == nil {
		return nil
	}
	return map[string]interface{}{"enforcing_planes": orchestratorEnforcingScopeNames()}
}
