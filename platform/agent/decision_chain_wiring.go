// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

// =============================================================================
// Wiring the per-record signing chain into the live decision path (#2732)
// =============================================================================
//
// WS-6 (#2722) built the DecisionChainTracker: per-record Ed25519 signing +
// prev_hash chaining + the GET /api/v1/audit/{chains,records}/.../verify
// endpoints. But until this file, the only WRITING instance was synthetic /
// test traffic, the production tracker was instantiated verify-only
// (AsyncQueueSize:-1), and the live decision handlers emitted only the OTel
// TELEMETRY decision span (decisionTracerProvider.Tracer.RecordDecision). So
// "prove which agent made this call" had nothing real to prove.
//
// recordSignedDecision is the single bridge from a live decision to a signed,
// chained, verifiable record. It is called at the three live decision points:
//
//   - handleDecide -> recordDecideDecision (decision_handler.go): the
//     POST /api/v1/decide path AND the OpenAI-compat /v1/chat/completions path.
//   - the Gateway pre-check main exit (gateway_handlers.go): terminal verdict
//     for a pre-check, including a redaction (signed distinctly from a clean
//     allow; the /decide plane instead carries redaction as an allow+obligation
//     per the decide->fulfill contract, see decisionOutcomeForVerdict).
//   - recordPreCheckDecision (gateway_handlers.go): the early-return deny paths
//     (kill-switch / Indonesia-PII / RBI-PII / budget).
//
// Design invariants this helper guarantees, matching the brief:
//
//   1. OrgID is ALWAYS validated before the entry is built. decision_chain is
//      FORCE ROW LEVEL SECURITY (migration 100), so RecordDecision rejects an
//      empty OrgID. We guard here and skip+meter rather than let a hot-path
//      call return an error: a missing org is an instrumentation gap, never a
//      reason to fail the decision the PEP already holds.
//   2. Signing stays OFF the hot path. RecordDecision on a writing tracker only
//      validates + computes a cheap audit hash + does a non-blocking channel
//      send; the per-(org,chain) advisory lock, tail read, Ed25519 sign and
//      INSERT all happen in the async worker. This call adds no DB round-trip
//      and no signing latency to the decision response.
//   3. Best-effort. A nil tracker (DB-less deployment, or signing-init failure)
//      makes this a no-op; the verify endpoints then honestly report records as
//      unsigned. A RecordDecision error is logged + metered, never propagated:
//      the decision verdict is independent of whether its audit record persists.

import (
	"context"
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

// decisionChainRecordSkipped counts live decisions that did NOT produce a
// signed chain record, by reason, so an operator can alert on a silently
// degraded non-repudiation path (the symmetric companion to
// decideAuditWriteFailures, which covers the canonical audit_logs writer).
//
// Reason labels:
//   - missing_org:         OrgID empty on the decision (RLS pivot absent); the
//     record would be rejected by RecordDecision, so we skip it up front.
//   - missing_decision_id: no decision/context id to key the chain on.
//   - record_error:        RecordDecision returned an error (queue full + sync
//     write failed, or a validation error); the decision itself is unaffected.
//
// A nil tracker (signing not wired) is the expected steady state for DB-less
// deployments and is deliberately NOT counted, it is configuration, not a
// degraded path.
var decisionChainRecordSkipped = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_decision_chain_record_skipped_total",
		Help: "Live decisions that produced no signed decision-chain record, by reason (missing_org|missing_decision_id|record_error)",
	},
	[]string{"reason"},
)

func init() {
	_ = prometheus.Register(decisionChainRecordSkipped)
}

// decisionTypeForStage maps the decision-mode stage ("llm" | "tool" | "agent")
// onto the DecisionType vocabulary stored (and signed) on the chain record.
// Unknown stages fall back to a system action rather than guessing a more
// specific type, the stage string itself is preserved verbatim in metadata.
func decisionTypeForStage(stage string) DecisionType {
	switch stage {
	case "llm":
		return DecisionTypeLLMGeneration
	case "tool":
		return DecisionTypeDataRetrieval
	case "agent":
		return DecisionTypeSystemAction
	default:
		return DecisionTypeSystemAction
	}
}

// decisionOutcomeForVerdict maps a decision verdict onto the DecisionOutcome
// vocabulary. It accepts BOTH verdict dialects the live call sites use:
//
//   - the telemetry/PEP wire verdict:   allow | deny | needs_approval | error
//   - the canonical audit past-tense:   allowed | blocked | redacted | needs_approval
//
// so a "redacted" verdict is recorded as DecisionOutcomeModified (NOT collapsed
// to approved) and a HITL hold as DecisionOutcomePendingReview. The outcome IS
// part of the signed record digest, so this mapping is security-relevant: an
// unrecognized verdict maps to DecisionOutcomeError rather than silently
// labeling an unknown decision "approved".
//
// Plane note: only the Gateway pre-check supplies "redacted" (it resolves the
// redaction inline). On the /decide PDP plane a redaction is an OBLIGATION on an
// "allow" verdict per the decide->fulfill contract, so it signs as approved with
// the obligation reasons captured in metadata; that is the engine's verdict and
// is the value we faithfully sign.
func decisionOutcomeForVerdict(verdict string) DecisionOutcome {
	switch verdict {
	case "allow", "allowed":
		return DecisionOutcomeApproved
	case "deny", "blocked":
		return DecisionOutcomeBlocked
	case "redacted":
		return DecisionOutcomeModified
	case "needs_approval":
		return DecisionOutcomePendingReview
	case "error":
		return DecisionOutcomeError
	default:
		return DecisionOutcomeError
	}
}

// recordSignedDecision records a live decision into the signing chain so it
// becomes a signed, prev_hash-chained, verifiable record. It is best-effort and
// adds no signing latency to the caller (see file header for the invariants).
//
// chainID/recordID retrievability: the record's ChainID is the decisionID, so
// GET /api/v1/audit/chains/{decisionID}/verify resolves it; the record's own id
// (a uuid assigned by RecordDecision) is what /records/{id}/verify takes, and is
// discoverable by reading the chain. reasons is captured in metadata for the
// audit trail; it is intentionally NOT folded into the signed digest (only the
// outcome, type, policies and timing are), mirroring decision_chain's existing
// digest contract.
func recordSignedDecision(ctx context.Context, decisionID, orgID, tenantID, stage, verdict string, policyIDs, reasons []string, latencyMs int64) {
	t := decisionChainTracker
	if t == nil {
		// Signing not wired (DB-less deployment or init failure). The verify
		// endpoints report any records as unsigned honestly; nothing to do.
		return
	}
	if orgID == "" {
		// decision_chain is FORCE RLS: an empty OrgID would be rejected by
		// RecordDecision. Skip + meter rather than error the hot path.
		decisionChainRecordSkipped.WithLabelValues("missing_org").Inc()
		return
	}
	if decisionID == "" {
		decisionChainRecordSkipped.WithLabelValues("missing_decision_id").Inc()
		return
	}

	outcome := decisionOutcomeForVerdict(verdict)
	entry := DecisionEntry{
		ChainID:           decisionID,
		RequestID:         decisionID,
		OrgID:             orgID,
		TenantID:          tenantID,
		DecisionType:      decisionTypeForStage(stage),
		DecisionOutcome:   outcome,
		PoliciesEvaluated: policyIDs,
		ProcessingTimeMs:  latencyMs,
		Metadata: map[string]interface{}{
			"stage":   stage,
			"verdict": verdict,
			"reasons": reasons,
		},
	}
	// On a block, attribute the last-evaluated policy as the trigger, matching
	// RecordFromTransparencyInfo's convention.
	if outcome == DecisionOutcomeBlocked && len(policyIDs) > 0 {
		entry.PolicyTriggered = policyIDs[len(policyIDs)-1]
	}

	// Async: this enqueues; the worker holds the per-chain advisory lock, signs
	// and writes. A full queue degrades to a synchronous write inside
	// RecordDecision (still off the response's critical section only insofar as
	// the queue isn't saturated, the degradation is logged by the tracker).
	if err := t.RecordDecision(ctx, entry); err != nil {
		decisionChainRecordSkipped.WithLabelValues("record_error").Inc()
		log.Printf("[DecisionChain] live record failed (best-effort, verdict unaffected): %v", err)
	}
}
