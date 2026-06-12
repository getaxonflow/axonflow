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

// Package audit defines the canonical, cross-plane vocabulary for the
// audit_logs.policy_decision column and the single read-time normalizer that
// every writer, reader, and exporter is expected to converge on.
//
// History (why this package exists). Before convergence, four surfaces each
// re-invented the same enum and disagreed:
//
//	agent        VerdictAllow="allow"  VerdictDeny="deny"  VerdictNeedsApproval="needs_approval"
//	orchestrator responseVerdictAllowed="allowed"  ...Blocked="blocked"  ...Redacted="redacted"
//	frontend     type AuditAction = 'allowed'|'blocked'|'modified'|'logged'|'alerted'
//	exports      euaiact/mapDecisionVerdict + sebi/mapDecisionOutcome (each its own switch)
//
// "allow"≠"allowed", "deny"≠"blocked", "redacted"≠"modified",
// "needs_approval"≠"require_approval"; the frontend's "modified"/"logged"/
// "alerted" are phantoms no writer emits. The result was mislabeled and
// unfilterable decisions (the "everything shows Logged" symptom, #2636) and a
// distinct enum every new audit surface had to re-derive (#2638, child of the
// audit-coverage epic #2625; arbitrated by ADR-058).
//
// Relationship to the already-merged writer-side work. EVERY forward audit
// writer already emits this exact canonical set, each via its own plane-local
// copy of the constants: the orchestrator response plane (`responseVerdict*`,
// #2630), the agent /decide decision plane (`AuditVerdict*` + the
// `canonicalAuditVerdict` helper that fails an unrecognized verdict SAFE to
// "error", #2643), the agent MCP plane (`mcpVerdict*` via `writeMCPDecisionAudit`,
// #2641/#2651), and the agent gateway plane (`gatewayAudit*` via
// `gatewayPreCheckAuditVerdict`, #2642). No forward writer emits the legacy
// allow/deny anymore — those are now the wire-only Decision-API verdicts, and
// migration 122 backfilled the historical allow/deny rows in audit_logs. This
// package is the SHARED single source of truth those FOUR plane-local copies
// converge onto, AND the read-time normalizer #2643 explicitly defers to #2638 —
// so its canonical set and its "error" fail-safe class are kept identical to the
// merged writers by construction. It DEFINES the vocabulary only; it does not
// rewire writers, readers, or exporters (the follow-on S-WRITERS / S-READERS
// work, kept separate to avoid an un-reviewable mega-diff and file collisions).
package audit

import "strings"

// Canonical policy_decision values (ADR-058; identical strings to the agent's
// #2643 AuditVerdict* and the orchestrator's #2630 responseVerdict*). Past-tense,
// because the orchestrator and the frontend already lean that way and only the
// agent's wire vocabulary (allow/deny) was the outlier. Every writer should
// write one of these; every reader should compare against one of these after
// calling Normalize on the raw value.
const (
	// DecisionAllowed — the request/response was permitted unchanged. Also the
	// truthful verdict for detect-don't-modify outcomes (warn/log): a detector
	// fired but nothing was blocked or altered, so the decision is "allowed".
	DecisionAllowed = "allowed"

	// DecisionBlocked — the request/response was denied; nothing reached the
	// downstream model/tool, or the response was withheld.
	DecisionBlocked = "blocked"

	// DecisionRedacted — the request/response was permitted but modified
	// (PII masked / fields stripped). Distinct from DecisionAllowed so a
	// redaction is never mislabeled as a clean allow.
	DecisionRedacted = "redacted"

	// DecisionNeedsApproval — the decision is deferred to a human (HITL); the
	// request is neither allowed nor blocked yet. Subsumes the legacy
	// "require_approval" and "pending_approval" spellings.
	DecisionNeedsApproval = "needs_approval"

	// DecisionError — the decision could not be computed (engine error, failed
	// plan/tool step). This is ALSO the fail-safe Normalize returns for any
	// unrecognized value (see Normalize): an unknown verdict could not be
	// classified, which is itself an error condition, and "error" is the
	// fail-safe class the merged writer-side helper (#2643 canonicalAuditVerdict)
	// already uses — so the shared normalizer and the writer agree. The one
	// invariant that matters is that an unrecognized value is NEVER "allowed".
	DecisionError = "error"
)

// DecisionOverrideLifecycle is a recognized NON-verdict marker the override
// audit writer (platform/orchestrator/override_audit.go) stores in the
// policy_decision column for override grant/revoke lifecycle events. It is
// intentionally not a PEP verdict: those rows are identified by their
// RequestType (IsOverrideEventType), not by policy_decision. Normalize passes it
// through unchanged so a verdict-bucketing reader sees an explicit, recognized
// marker (routed by RequestType) rather than mislabeling an override event as a
// processing "error". The writer-side helper (#2643) never sees this value (it
// lives on the orchestrator override plane), so only this read-side normalizer
// needs to recognize it.
const DecisionOverrideLifecycle = "override_lifecycle"

// All returns the canonical verdict set, in a stable order suitable for
// building filter allowlists, API docs, and exhaustiveness tests. It does NOT
// include DecisionOverrideLifecycle — that is a non-verdict marker, not a
// verdict.
func All() []string {
	return []string{
		DecisionAllowed,
		DecisionBlocked,
		DecisionRedacted,
		DecisionNeedsApproval,
		DecisionError,
	}
}

// canonicalSet is the membership test backing IsCanonical. Built once from
// All() so it can never drift from it.
var canonicalSet = func() map[string]struct{} {
	m := make(map[string]struct{}, 5)
	for _, v := range All() {
		m[v] = struct{}{}
	}
	return m
}()

// legacyAliases maps every known legacy / divergent / defensive spelling
// (lower-cased, trimmed) to its canonical verdict. Canonical values are also
// present so a single map lookup is the whole of Normalize's happy path, and so
// IsKnown can distinguish a recognized value from a true unknown.
//
// The table is exhaustive against the real written-value set confirmed by the
// audit sweep (see the mapping table in ADR-058 and the package tests):
//
//	WRITTEN today (ALL forward audit writers already emit the canonical set —
//	  no forward writer emits raw allow/deny anymore; that is now wire-only +
//	  historical, see below):
//	               allowed, blocked, redacted, needs_approval, error (agent
//	                 decision plane canonicalAuditVerdict #2643; agent MCP plane
//	                 writeMCPDecisionAudit / mcpVerdict* #2641/#2651-bucket-C;
//	                 agent gateway plane gatewayPreCheckAuditVerdict / gatewayAudit*
//	                 #2642-bucket-D; orchestrator responseVerdict* #2630);
//	               pending_approval, override_lifecycle (orchestrator audit_logger.go /
//	                 override_audit.go);
//	               allowed, blocked (EE HITL gate, ee/platform/agent/hitl/repository.go).
//	WIRE + HISTORICAL:
//	               allow, deny — the agent Decision API WIRE verdicts
//	                 (VerdictAllow/VerdictDeny, decision_handler.go:73-75) returned to
//	                 the PEP; converted to allowed/blocked at every audit-write
//	                 boundary, so they no longer land in audit_logs. Pre-canonical
//	                 historical rows were backfilled by migration 122. Kept as
//	                 Normalize aliases for stragglers + raw-SQL safety.
//	READ/legacy:   require_approval (decisions filter + exporters), denied
//	               (audit_summary switch + migration 122), modified (frontend
//	               display vocab).
//
//	NOTE: each writer plane above currently carries its OWN copy of these
//	constants (AuditVerdict* / mcpVerdict* / gatewayAudit* / responseVerdict*) —
//	string-identical, but four copies. Collapsing them into THIS package is the
//	S-WRITERS const-swap; the values + fail-safe already match by construction.
//
// Defensive entries (block, redact, masked, the *-approval variants, errored,
// failed) are spellings no writer emits today but that a future writer or a
// hand-written row could plausibly produce; mapping them is free robustness and
// is called out in the tests so the table stays honest about real vs. defensive.
var legacyAliases = map[string]string{
	// allowed
	"allow":   DecisionAllowed,
	"allowed": DecisionAllowed,

	// blocked
	"deny":    DecisionBlocked,
	"denied":  DecisionBlocked, // legacy: audit_summary switch + migration 122
	"block":   DecisionBlocked, // defensive: workflow Decision input pre-mapping
	"blocked": DecisionBlocked,

	// redacted
	"redact":   DecisionRedacted, // defensive
	"redacted": DecisionRedacted,
	"masked":   DecisionRedacted, // defensive
	"modified": DecisionRedacted, // frontend display vocab → backend canonical

	// needs_approval
	"needs_approval":    DecisionNeedsApproval,
	"need_approval":     DecisionNeedsApproval, // defensive
	"needs-approval":    DecisionNeedsApproval, // defensive
	"require_approval":  DecisionNeedsApproval, // decisions filter + exporters
	"requires_approval": DecisionNeedsApproval, // defensive
	"requires-approval": DecisionNeedsApproval, // defensive
	"pending_approval":  DecisionNeedsApproval, // orchestrator workflow gate
	"pending-approval":  DecisionNeedsApproval, // defensive
	"awaiting_approval": DecisionNeedsApproval, // defensive

	// error
	"error":   DecisionError,
	"errored": DecisionError, // defensive
	"failed":  DecisionError, // defensive

	// recognized non-verdict marker — passes through unchanged
	"override_lifecycle": DecisionOverrideLifecycle,
}

// canonicalize lower-cases and trims a raw value so lookups are spelling- and
// whitespace-insensitive.
func canonicalize(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// Normalize maps a raw policy_decision value — from any writer, any era, or a
// reader's filter input — to the canonical vocabulary.
//
// Contract (a read-side superset of the agent's writer-side #2643
// canonicalAuditVerdict, sharing the same canonical set and the same fail-safe
// class):
//   - recognized verdict spellings (canonical or legacy) → the canonical verdict.
//   - the recognized non-verdict marker DecisionOverrideLifecycle → itself.
//   - anything else (including empty) → DecisionError.
//
// An unrecognized value is NEVER mapped to DecisionAllowed. A vocabulary gap
// must fail safe to an explicit, non-allowed value, never fail open — this is
// the single behavior the whole package exists to guarantee, and it matches the
// merged writer's choice of "error" as the fail-safe so the two never disagree.
// (Today's broken readers fail OPEN instead: audit_summary_handler.go's
// default→"allowed" buckets needs_approval/error as allowed and corrupts
// block-rate/compliance metrics; the frontend's || 'logged' fallback hides the
// agent allow/deny stream.)
func Normalize(raw string) string {
	if canonical, ok := legacyAliases[canonicalize(raw)]; ok {
		return canonical
	}
	return DecisionError
}

// IsCanonical reports whether raw is EXACTLY one of the canonical verdicts in
// All() (case-insensitive, trimmed). It does not normalize: "allow" is not
// canonical ("allowed" is), and DecisionOverrideLifecycle is not canonical. Use
// this to assert a writer is already emitting the canonical value; use Normalize
// when you need to coerce a legacy value.
func IsCanonical(raw string) bool {
	_, ok := canonicalSet[canonicalize(raw)]
	return ok
}

// IsKnown reports whether raw is a value this package recognizes — a canonical
// verdict, a known legacy/defensive spelling, or the DecisionOverrideLifecycle
// marker. It is a membership test, NOT "Normalize(raw) != DecisionError": a
// genuine "error" input is known, whereas an unrecognized value is not (even
// though both Normalize to DecisionError under the fail-safe). A false here is
// the signal that a writer is emitting a spelling this vocabulary has not caught
// up with — extend legacyAliases (and the TS mirror) with a test.
func IsKnown(raw string) bool {
	_, ok := legacyAliases[canonicalize(raw)]
	return ok
}
