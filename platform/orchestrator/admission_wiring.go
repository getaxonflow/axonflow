// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/agent/license/admission"
)

// This file is the orchestrator's ONE call site of admission.Admit (#3593),
// for the one dimension this binary creates: organization-root policies.
// Both creation paths - PolicyService.validateTierForCreate (single create)
// and PolicyService.ImportBulk - call admitOrgRootPolicy, and the census in
// platform/agent/license/admission/callsite_census_test.go pins that they do
// and that nothing else here calls Admit.
//
// The ruled limit is 0 on Community and on Evaluation (organization-root
// authoring is Enterprise-only, under ee/) and unlimited on Enterprise, so
// with the ruled values the ledger is never written from this binary: an
// unlimited tier returns before any I/O, and a zero limit refuses a NEW policy
// before any write. The ledger is wired all the same, so a future non-zero
// Evaluation value would be counted and replay-safe without a second path.
//
// A refusal is the same TierValidationError shape every other tier refusal
// on this service uses, carrying the admission code
// (ERR_TIER_LIMIT_ORG_ROOT_POLICY) so the portal and the CLI can route it.

var tierAdmitter atomic.Pointer[admission.Admitter]

var admissionUnwiredTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_orchestrator_tier_admission_unwired_total",
	Help: "Organization-root policy admissions that found no admitter wired during the boot window and were allowed by default.",
}, []string{"dimension"})

var admissionUnwiredLogged sync.Once

func init() {
	admissionUnwiredTotal.WithLabelValues(string(admission.OrgRootPolicy)).Add(0)
}

// initTierAdmission wires the ledger and the refusal audit sink over the
// application pool. Called once from run.go where the policy repository is
// built over the same pool.
//
// THIS BINARY DOES NOT DRAIN ON THE WAY OUT, deliberately and with a cost.
// Run() ends in log.Fatal(http.Serve(...)) and the package registers no signal
// handler, so no deferred cleanup in Run has ever executed - not this one, and
// not the three that predate it (heartbeatService.Stop, nodeMonitor.Stop,
// ClosePolicyRedis). A drain was added here in an earlier round and removed
// again once that was measured: a defer that cannot run is worse than none,
// because it reads as a guarantee.
//
// What is actually lost on exit is queued REFUSAL AUDIT rows - the audit sink
// above is wired, so refusals do queue - and nothing else. No org_root_policy
// telemetry record is lost, because this dimension writes none on an unlimited
// tier (see admitOrgRootPolicy). A lost audit row describes a refusal the
// caller was already told about synchronously, so the cost is an incomplete
// audit trail across a restart rather than a wrong decision.
//
// REVISIT WHEN: this binary gains a graceful shutdown - signal.Notify plus
// http.Server.Shutdown, so Run returns and its defers unwind. At that point
// every one of those four cleanups starts working for the first time, and a
// drain belongs here with them. Adding shutdown to serve this alone was judged
// out of scope for a licence change and is tracked separately.
func initTierAdmission(db *sql.DB) *admission.Admitter {
	a := admission.New(
		admission.NewPostgresLedger(db),
		admission.WithAuditSink(admission.NewDBAuditSink(db)),
		// The same fingerprint the agent stamps, from the same helper, because
		// both wirings write org_root_policy and human/service rows into ONE
		// ledger: two spellings of "which licence was held" would read as two
		// deployments. Never the key itself.
		admission.WithLicenceFingerprint(admission.LicenceFingerprint(os.Getenv("AXONFLOW_LICENSE_KEY"))),
	)
	tierAdmitter.Store(a)
	log.Printf("[admission] orchestrator tier admission wired for %s", admission.OrgRootPolicy)
	return a
}

// admitOrgRootPolicy is the ONE call site of admission.Admit in this package.
// policyName is the principal key: it is what a replayed create or import
// presents again, so the same name is one admission.
//
// THIS DIMENSION WRITES NO LEDGER ROW ON AN UNLIMITED TIER, and an earlier
// version of this comment claimed the opposite. recordUnlimited records
// human_principal and service_principal only, so an Enterprise deployment
// authoring organization-root policies records NOTHING here - measured 1/1/0
// rows across the three ledger dimensions.
//
// That exclusion is correct, and the reason is what the recording is FOR. On
// the principal dimensions a recorded row is what lets an established
// principal keep working after a licence lapse, because a principal is
// re-admitted on every request. An organization-root policy is admitted once,
// at CREATE, and never again: nothing re-admits it when it is evaluated. So a
// row would buy nothing after a lapse, and the honest statement of the
// post-lapse behaviour is that Community's ceiling of 0 refuses every NEW
// org-root policy while the policies that already exist go on being evaluated,
// untouched - not that "the names in the ledger keep working", which describes
// a mechanism that is not there.
//
// The name is still the principal key, so a replayed create or import is one
// admission rather than one per replay. On the ruled values that only matters
// if Evaluation ever moves off 0.
func admitOrgRootPolicy(ctx context.Context, orgID, policyName string) error {
	a := tierAdmitter.Load()
	if a == nil {
		admissionUnwiredTotal.WithLabelValues(string(admission.OrgRootPolicy)).Inc()
		admissionUnwiredLogged.Do(func() {
			log.Printf("[admission] no admitter wired for %s; organization-root policies are admitted by default until run.go wires the ledger "+
				"(counted on axonflow_orchestrator_tier_admission_unwired_total)", admission.OrgRootPolicy)
		})
		return nil
	}
	principal := strings.TrimSpace(policyName)
	if principal == "" {
		// A create request with no name fails validation before it reaches
		// the tier gate; a bulk import row without one is refused here rather
		// than admitted under an empty key.
		return NewTierValidationError("organization-root policy admission needs a policy name", admission.OrgRootPolicy.Code())
	}
	dec, err := a.Admit(ctx, admission.Request{Dimension: admission.OrgRootPolicy, OrgID: orgID, PrincipalID: principal})
	if err != nil {
		return NewTierValidationError("organization-root policy admission could not be decided: "+err.Error(), admission.OrgRootPolicy.Code())
	}
	if dec.Allowed {
		return nil
	}
	err2 := NewTierValidationError(dec.Message(), dec.Code)
	// The OUTAGE refusal is the retryable one and must say so. dec.Code is the
	// same ERR_TIER_LIMIT_ORG_ROOT_POLICY for both reasons - deliberately, so
	// there is one code for "tier admission refused" - which means the status
	// alone cannot tell a ceiling from a database blip. Retry-After is what
	// separates them, exactly as it does on the agent planes.
	err2.RetryAfter = dec.RetryAfter
	return err2
}
