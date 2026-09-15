// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"fmt"
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
// for the one dimension this binary creates: customer-authored policies.
// THREE creation paths call admitOrgRootPolicies - PolicyService.validateTierForCreate
// (legacy single create), PolicyService.ImportPolicies (legacy bulk import) and
// TypedAuthoringRouteHandler.handlePublish (the typed authoring route, #3907) -
// and the census in platform/agent/license/admission/callsite_census_test.go
// pins that all three do and that nothing else here calls Admit.
//
// THE RULED LIMIT MOVED AND SO DID EVERYTHING THIS PARAGRAPH USED TO SAY
// (#3906). It was 0 on Community and Evaluation and unlimited on Enterprise,
// which meant the ledger was never written from this binary at all: an
// unlimited tier returns before any I/O and a zero ceiling refuses a new policy
// before any write. It is now 20 / 50 / unlimited, so this binary writes the
// ledger on both limited tiers, and - since #3907 also made an unlimited tier
// record - on Enterprise too, off the request path.
//
// A refusal is the same TierValidationError shape every other tier refusal
// on this service uses, carrying the admission code
// (ERR_TIER_LIMIT_ORG_ROOT_POLICY) so the portal and the CLI can route it.

var tierAdmitter atomic.Pointer[admission.Admitter]

var admissionUnwiredTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_orchestrator_tier_admission_unwired_total",
	Help: "Customer-authored policy admissions that found no admitter wired during the boot window and were allowed by default.",
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
// not the two that predate it (heartbeatService.Stop, nodeMonitor.Stop; a third,
// ClosePolicyRedis, went with the MCP dynamic-policy endpoint in v11). A drain
// was added here in an earlier round and removed
// again once that was measured: a defer that cannot run is worse than none,
// because it reads as a guarantee.
//
// What is actually lost on exit is queued background writes, and #3907 ADDED A
// SECOND KIND. Before it, only refusal audit rows queued here, because
// org_root_policy recorded nothing on an unlimited tier; now the dimension
// records, so an Enterprise orchestrator killed with records still queued loses
// them too.
//
// The two losses cost different things and both are bounded. A lost audit row
// describes a refusal the caller was already told about synchronously, so the
// cost is an incomplete audit trail across a restart rather than a wrong
// decision. A lost telemetry record is a document that is not in the ledger, and
// it costs nothing while the tier stays unlimited - an unlimited tier never
// reads the ledger for a decision - but leaves the count low if the licence
// later lapses, so the deployment gets slightly more headroom under the new
// ceiling than it should. Neither is a wrong decision in the running process.
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

// admitOrgRootPolicies is the ONE call site of the admission package's decision
// in this package, and it admits a whole document's policies or none of them.
//
// THE SET IS THE UNIT, and that is #3973. One call per policy cannot be
// all-or-nothing: a document refused at the ceiling left the policies before the
// boundary admitted, against a ledger that is append-only by design, so an
// organization that overshot once sat at its ceiling with nothing published and
// could never publish again - including the smaller document the refusal told it
// to publish. Measured, not hypothesised: 19 of 21.
//
// Each policy name is the principal key: it is what a replayed create, import or
// re-publication presents again, so the same name is one admission however many
// times it arrives.
//
// THIS DIMENSION NOW WRITES A LEDGER ROW ON AN UNLIMITED TIER TOO (#3907), and
// this comment has been wrong in BOTH directions across three rounds, which is
// why it now states the mechanism rather than the count.
//
// Round 1 claimed an Enterprise deployment accumulates rows so the policies
// "keep working" after a lapse. That was false twice over: nothing recorded,
// and the mechanism described does not exist - nothing re-admits a policy when
// it is evaluated, so no row makes an existing policy keep working. Round 2
// measured 1/1/0 and excluded the dimension. Round 3 is this: the exclusion was
// free only while the ceiling was 0, #3906 moved it to 20 and 50, and the row
// buys something the earlier rounds did not consider - the COUNT. Without it an
// Enterprise deployment holding 500 documents lapses to Community with a ledger
// count of zero and may write 20 more.
//
// So: policies already written go on being evaluated after a lapse, untouched,
// on every edition. What the ledger decides is whether a NEW one is admitted,
// and the recording is what makes that decision describe the deployment.
//
// The key is the identity of the thing authored - the policy NAME on the two
// legacy paths, the DOCUMENT ID on the typed route - so a replayed create, a
// replayed import or a re-publication of the same document is one admission
// rather than one per replay.
func admitOrgRootPolicies(ctx context.Context, orgID string, policyNames []string) error {
	a := tierAdmitter.Load()
	if a == nil {
		// COUNTED PER POLICY, not per call, so the metric keeps meaning what it
		// meant when this admitted one at a time: how many customer-authored
		// policies were admitted by default during a boot window.
		admissionUnwiredTotal.WithLabelValues(string(admission.OrgRootPolicy)).Add(float64(len(policyNames)))
		admissionUnwiredLogged.Do(func() {
			log.Printf("[admission] no admitter wired for %s; organization-root policies are admitted by default until run.go wires the ledger "+
				"(counted on axonflow_orchestrator_tier_admission_unwired_total)", admission.OrgRootPolicy)
		})
		return nil
	}
	principals := make([]string, 0, len(policyNames))
	for _, name := range policyNames {
		principal := strings.TrimSpace(name)
		if principal == "" {
			// A create request with no name fails validation before it reaches
			// the tier gate; a bulk import row without one is refused here rather
			// than admitted under an empty key. REFUSED FOR THE WHOLE SET, since
			// the set is the unit: admitting the named ones and refusing the
			// batch is the partial admission this change exists to remove.
			return NewTierValidationError("organization-root policy admission needs a policy name", admission.OrgRootPolicy.Code())
		}
		principals = append(principals, principal)
	}
	dec, err := a.AdmitAll(ctx, admission.OrgRootPolicy, orgID, principals)
	if err != nil {
		return NewTierValidationError("organization-root policy admission could not be decided: "+err.Error(), admission.OrgRootPolicy.Code())
	}
	if dec.Allowed {
		return nil
	}
	// THE BATCH CONTEXT IS FOLDED INTO THE MESSAGE, because the message is the
	// only field that reaches a caller. Decision.Message() renders the ledger
	// count BEFORE this call and knows nothing about how many policies were
	// submitted, so a fresh organization sending 21 under a ceiling of 20 reads
	// "20 ... and 0 are already admitted" - true, and useless, because it names
	// neither the size of what was refused nor the policy that crossed.
	//
	// Both writeTierError implementations emit Code and Message only, and
	// Error() is what the logs carry, so anything not in the message is lost on
	// every wire this refusal travels.
	msg := dec.Message()
	if dec.Reason == admission.ReasonOverLimit && dec.PrincipalID != "" {
		msg = fmt.Sprintf("%s This request asked to admit %d organization-root policy(s), and %q is the first that does not fit; "+
			"nothing was admitted, so this refusal spent none of the organization's capacity, and a request with fewer policies can still be admitted.",
			msg, len(principals), dec.PrincipalID)
	}
	err2 := NewTierValidationError(msg, dec.Code)
	// The policy that crossed the boundary, in the order the caller supplied
	// them. Empty on an outage refusal, where no particular policy is at fault.
	err2.Policy = dec.PrincipalID
	// The OUTAGE refusal is the retryable one and must say so. dec.Code is the
	// same ERR_TIER_LIMIT_ORG_ROOT_POLICY for both reasons - deliberately, so
	// there is one code for "tier admission refused" - which means the status
	// alone cannot tell a ceiling from a database blip. Retry-After is what
	// separates them, exactly as it does on the agent planes.
	err2.RetryAfter = dec.RetryAfter
	return err2
}
