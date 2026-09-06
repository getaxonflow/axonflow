// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Policy-authored HITL step-ups on the agent planes (#3509).
//
// Three planes evaluate a `require_approval` policy and hold the caller:
// POST /api/v1/decide (needs_approval), POST /api/request (403) and
// POST /api/policy/pre-check (200 with approved:false). Until this file, only
// a FinCrime-attributed step-up on /decide ever wrote a hitl_approval_queue
// row, so a policy authored for any other reason - an EU AI Act human-
// oversight rule, say - produced a hold with nothing for a reviewer to see and
// nothing to approve. This is the shared enqueue those three planes call, and
// the single-use grant consumption that makes an approval admit the retry.
//
// Untagged, so it compiles into both editions. Its OBSERVABLE effect is
// enterprise-only for two independent reasons, either of which alone is
// sufficient: every call site is guarded on !isCommunityMode(), and the
// community build's hitl.Service.CreateApprovalRequest is a stub that always
// returns ErrHITLApprovalDisabledByTier (hitl_community.go:186).

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/agent/hitl"
	logutil "axonflow/platform/shared/logger"
)

// HITLRequestTypePolicyStepUp is the hitl_approval_queue.request_type written
// for a policy-authored step-up on the agent planes, and the value the grant
// consume predicate matches on.
//
// ONE value across all three planes, deliberately. The plane that raised the
// entry is recorded in request_context.plane for the reviewer; it is not part
// of the match key, because a PEP that is held on one surface may legitimately
// retry on another and the single-use property already bounds the grant to
// exactly one admission wherever it is spent.
//
// It is also what keeps the two pre-existing writers out of the grant path:
// the FinCrime seam writes "fincrime_review" and the orchestrator's WCP step
// gate writes "wcp_step_gate". Neither can be consumed here. That exclusion is
// deliberate for FinCrime in particular - its verdict is a function of the
// score computed for THAT transaction, so admitting the next request because a
// previous one was approved would authorise something no reviewer ever saw.
const HITLRequestTypePolicyStepUp = "policy_step_up"

// Plane labels for the metrics below and for request_context.plane.
const (
	hitlPlaneDecide          = "decide"
	hitlPlaneAgentRequest    = "agent_request"
	hitlPlaneGatewayPreCheck = "gateway_precheck"
)

// Enqueue outcomes. Every one of these is COUNTED: the pre-existing FinCrime
// enqueue was best-effort and silent, which is survivable while it is the only
// caller and its tier is unlimited, and is not survivable once every
// require_approval policy in the field starts writing rows against a cap of 5
// (Community/Free/Pro/Premium) or 25 (Evaluation).
const (
	hitlEnqueueCreated = "created"
	// hitlEnqueueDeduped: the request joined an entry a reviewer is already
	// looking at. A SUCCESS outcome - there IS a reviewable entry - reported
	// separately from "created" so an operator can tell a retry loop from
	// genuinely new oversight work.
	hitlEnqueueDeduped      = "deduped"
	hitlEnqueueCapReached   = "cap_reached"
	hitlEnqueueTierDisabled = "tier_disabled"
	hitlEnqueueUnavailable  = "unavailable"
	hitlEnqueueError        = "error"
)

// Grant consume outcomes.
const (
	hitlGrantConsumed       = "consumed"
	hitlGrantNone           = "none"
	hitlGrantUnavailable    = "unavailable"
	hitlGrantError          = "error"
	hitlGrantMissingSubject = "missing_subject"
)

var (
	// hitlPolicyEnqueueTotal counts every attempt to raise a policy-authored
	// approval entry, by plane and outcome. `cap_reached` is the one an
	// operator must alert on: the caller is still held, but no reviewer will
	// ever see the request, so the tenant is back to the dead end this change
	// exists to remove - just for a different reason.
	hitlPolicyEnqueueTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_hitl_policy_enqueue_total",
			Help: "HITL approval entries raised by plane (decide|agent_request|gateway_precheck|fincrime) and outcome (created|deduped|cap_reached|tier_disabled|unavailable|error)",
		},
		[]string{"plane", "outcome"},
	)

	// hitlGrantConsumeTotal counts every grant lookup on the enforcement path.
	// `none` is the overwhelmingly common outcome (no approval outstanding) and
	// is counted so that a sudden absence of `consumed` is distinguishable from
	// a sudden absence of traffic.
	hitlGrantConsumeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_hitl_grant_consume_total",
			Help: "Single-use HITL approval grant consumption attempts by plane and outcome (consumed|none|missing_subject|unavailable|error)",
		},
		[]string{"plane", "outcome"},
	)
)

func init() {
	_ = prometheus.Register(hitlPolicyEnqueueTotal)
	_ = prometheus.Register(hitlGrantConsumeTotal)
}

// EnvHITLGrantTTLSeconds bounds how long an approval stays spendable, measured
// from the moment the reviewer actioned it.
//
// The TTL is the BACKSTOP, not the safety property. Single use is the safety
// property, and it is enforced by the consume UPDATE's `consumed_at IS NULL`
// guard in one statement, so a grant can never admit more than one request no
// matter how generous this value is. That is what lets the default be generous
// enough to survive a human: the caller does not poll (the Decision Mode MCP
// adapter returns JSON-RPC -32002 and gives up), so a reviewer who approves and
// then tells the user to try again must not be racing a 30-second window.
//
// Naming follows AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS and
// AXONFLOW_REQUIRE_USER_TOKEN_TTL_SECONDS.
const EnvHITLGrantTTLSeconds = "AXONFLOW_HITL_GRANT_TTL_SECONDS"

const (
	defaultHITLGrantTTL = 15 * time.Minute
	minHITLGrantTTL     = 1 * time.Minute
	maxHITLGrantTTL     = 24 * time.Hour
)

// hitlGrantTTLOrFatal refuses to boot on a value this deployment cannot
// interpret, and is called once from Run().
//
// The alternative - parse, fail, silently use the default - is invisible
// afterwards and gets the security posture wrong in whichever direction the
// operator did not intend: a value meant to be 60 that arrives as "60s" would
// silently become 15 minutes, and a value meant to be generous that arrives
// malformed would silently shrink. Mirrors requireUserTokenEnvOrFatal.
//
// Out-of-range values are CLAMPED rather than fatal, and reported. A clamp is
// safe to guess at because both bounds are defensible postures and the operator
// is told which one applied; an unparseable value is not, because the intent is
// unknown.
func hitlGrantTTLOrFatal() {
	raw := strings.TrimSpace(os.Getenv(EnvHITLGrantTTLSeconds))
	if raw == "" {
		return
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		log.Fatalf("❌ [HITL] %s=%q is not an integer number of seconds. Refusing to boot rather than guess: "+
			"this value decides how long an approved human-oversight decision stays spendable, and silently "+
			"substituting the default is invisible afterwards.", EnvHITLGrantTTLSeconds, raw)
	}
	if secs <= 0 {
		log.Fatalf("❌ [HITL] %s=%d must be a positive number of seconds. Refusing to boot rather than guess: "+
			"zero or negative would make every approval unspendable the instant it was granted, which is "+
			"indistinguishable from the defect this control exists to fix.", EnvHITLGrantTTLSeconds, secs)
	}
	got := time.Duration(secs) * time.Second
	if clamped := clampHITLGrantTTL(got); clamped != got {
		log.Printf("⚠️ [HITL] %s=%ds is outside [%s, %s]; clamped to %s.",
			EnvHITLGrantTTLSeconds, secs, minHITLGrantTTL, maxHITLGrantTTL, clamped)
	}
}

func clampHITLGrantTTL(d time.Duration) time.Duration {
	if d < minHITLGrantTTL {
		return minHITLGrantTTL
	}
	if d > maxHITLGrantTTL {
		return maxHITLGrantTTL
	}
	return d
}

// hitlGrantTTL resolves the effective TTL. Unset or unparseable resolves to the
// default; an unparseable value cannot reach here in a booted process because
// hitlGrantTTLOrFatal already refused to start.
func hitlGrantTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv(EnvHITLGrantTTLSeconds))
	if raw == "" {
		return defaultHITLGrantTTL
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return defaultHITLGrantTTL
	}
	return clampHITLGrantTTL(time.Duration(secs) * time.Second)
}

// policyStepUpInput is what a plane knows about a held request. Everything on
// it is either an identifier the deployment already holds or a descriptor this
// file builds - never caller content. See hitlQueryDescriptor.
type policyStepUpInput struct {
	Plane      string
	OrgID      string
	TenantID   string
	ClientID   string
	UserID     string // numeric users.id, stringified - the grant match key
	UserEmail  string // reviewer-facing attribution, request_context only
	PolicyID   string
	PolicyName string
	Reason     string
	Severity   string
	// DecisionID is this plane's decision/context identifier, so a reviewer (or
	// an auditor) can join the queue entry back to the audit_logs row that
	// holds the full evaluated request.
	DecisionID string
	// CorrelationID is the W3C trace-id shared by every decision row of one
	// logical request (#2598, migration core/121).
	//
	// Recorded on the queue entry for #3718: when the approval is later decided,
	// the HITL audit row stamps it as its OWN correlation_id, which is what puts
	// the human decision into the SAME chain as the machine decision that asked
	// for it. Without it the approval row can be found in the decisions feed
	// (its decision_id is minted from the request) but groups as a singleton,
	// so an exporter reconstructing the chain shows the request and the block
	// and not the person who decided.
	//
	// Empty is legitimate and common: a caller that propagated no traceparent
	// has no chain to join.
	CorrelationID string
	// Stage is the gateway layer the PEP declared, where the plane has one.
	Stage string
	// Query is the caller's request text. It is used ONLY to derive the
	// SHA-256 recorded as request_context.query_hash; it is never stored.
	Query string
	// Target describes what was being reached for (tool server / tool name, or
	// a connector), where the plane knows it. Descriptor material, not content.
	Target string
}

// policyStepUpResult is what the calling plane needs in order to tell the
// truth in its response and on its audit row.
type policyStepUpResult struct {
	// RequestID is the created entry's UUID, empty when nothing was created.
	RequestID string
	// Outcome is one of the hitlEnqueue* constants. Always set.
	Outcome string
	// Detail is a caller-safe explanation for a non-created outcome, suitable
	// for an audit reason. Empty on success.
	Detail string
}

// hitlQueryDescriptor builds the value stored in
// hitl_approval_queue.original_query.
//
// It is a DESCRIPTOR, never the caller's query, and the reason is not the same
// as the reason audit_logs.query stores the raw text. audit_logs is an
// org-scoped store under the org's own retention; hitl_approval_queue.
// original_query additionally EGRESSES off-platform - Service.dispatchTerminal
// copies it verbatim into WebhookEnvelope.OriginalQuery and POSTs it to a
// customer-configured notify_url on every approve, reject and expiry
// (ee/platform/agent/hitl/service.go:590-613). A raw prompt on that channel is
// a materially different exposure from the same prompt in audit_logs, and it
// leaves the platform's retention and RLS boundary entirely.
//
// The in-table precedent is on the same side: the orchestrator's WCP step gate
// stores req.StepName here (hitl_wcp_enterprise.go:105), not step input. The
// outlier is the FinCrime seam, which passes the raw query; that is
// pre-existing and deliberately left alone by this change (see
// createFinCrimeApprovalForDecision), and is raised on #3509 rather than
// altered here, because changing it would be exactly the FinCrime behaviour
// drift this work is required not to introduce.
//
// The reviewer is not left guessing: the entry carries the triggering policy
// and its display name, the trigger reason, the attributed user, the plane,
// the stage, the target, and both the decision_id and the query hash, so the
// full request is one indexed lookup away in audit_logs for anyone with the
// authority to read it.
func hitlQueryDescriptor(in policyStepUpInput) string {
	plane := in.Plane
	if plane == "" {
		plane = "agent"
	}
	desc := fmt.Sprintf("%s request held for approval", plane)
	if in.Stage != "" {
		desc = fmt.Sprintf("%s (stage %s)", desc, in.Stage)
	}
	if in.Target != "" {
		desc = fmt.Sprintf("%s targeting %s", desc, in.Target)
	}
	if in.DecisionID != "" {
		desc = fmt.Sprintf("%s; decision %s", desc, in.DecisionID)
	}
	return desc
}

// decideTargetDescriptor renders what a held request was reaching for, from
// identifiers the PEP declared - a tool server and tool name, or the bare
// target type. It is IDENTITY, not content: server and tool names are the same
// values already recorded on audit_logs.policy_details.tool_server/tool_name,
// and the target type is a short enum token.
func decideTargetDescriptor(toolServer, toolName, targetType string) string {
	switch {
	case toolServer != "" && toolName != "":
		return fmt.Sprintf("tool %s/%s", toolServer, toolName)
	case toolName != "":
		return fmt.Sprintf("tool %s", toolName)
	case toolServer != "":
		return fmt.Sprintf("tool server %s", toolServer)
	case targetType != "":
		return targetType
	default:
		return ""
	}
}

// hitlQueryHash is the SHA-256 of the caller's query, hex-encoded - the same
// derivation audit_logs.query_hash uses (writeDecisionAuditRow), so a reviewer
// or an exporter can correlate the queue entry to its decision row without
// either store carrying the content twice.
func hitlQueryHash(query string) string {
	sum := sha256.Sum256([]byte(query))
	return hex.EncodeToString(sum[:])
}

// findOpenPolicyStepUp is a package-level indirection over the HITL service's
// lookup, so the dedup branch has a seam a test can drive.
//
// It is a var and not a direct call because the alternative was a test that
// could only ever exercise the FALL-THROUGH half: mcpHITLService is a concrete
// *hitl.Service, a repo-less one returns "", and a mutation run duly showed
// that deleting the entire dedup branch left every assertion green. A branch
// whose taken side no test can reach is a branch no test guards.
var findOpenPolicyStepUp = func(ctx context.Context, subj hitl.GrantSubject, policyID, plane, queryHash string) (string, error) {
	if mcpHITLService == nil {
		return "", nil
	}
	return mcpHITLService.FindOpenPolicyStepUp(ctx, subj, policyID, plane, queryHash)
}

// enqueueApproval is the SINGLE place an approval entry is raised from the
// agent, and the single place a failure to raise one is classified.
//
// Both the policy-authored step-up (enqueuePolicyStepUp, the three planes this
// change fixes) and the FinCrime seam (createFinCrimeApprovalForDecision) call
// it. Before this change the seam was the only enqueue path in the agent and
// it was best-effort and SILENT: it logged one line and returned "". That is
// survivable while the only caller is a tier with an unlimited cap, and stops
// being survivable the moment every require_approval policy in the field
// starts writing rows against a cap of 5 or 25 - a full queue would then
// reproduce the exact invisible dead end this work exists to remove, under a
// different cause.
//
// Contract, and it is the whole point: the caller's hold is NEVER weakened by
// anything that happens here. Every failure path returns a result whose
// Outcome names what went wrong and whose Detail is safe to put on an audit
// row; the plane keeps holding the request either way.
func enqueueApproval(ctx context.Context, plane string, input HITLCreateInput) policyStepUpResult {
	if plane == "" {
		plane = "agent"
	}
	record := func(outcome, detail string) policyStepUpResult {
		hitlPolicyEnqueueTotal.WithLabelValues(plane, outcome).Inc()
		return policyStepUpResult{Outcome: outcome, Detail: detail}
	}

	if fincrimeHITLBridge == nil {
		// The bridge is wired unconditionally in Run() alongside the HITL
		// service, so this is a not-yet-booted or test process rather than a
		// deployment state - but it must still be visible, not assumed away.
		return record(hitlEnqueueUnavailable, "approval queue not configured on this deployment")
	}
	if input.OrgID == "" {
		// hitl_approval_queue is RLS-enabled (mig 025) with INSERT WITH CHECK on
		// org_id, and Repository.Create refuses an empty org outright. Catching
		// it here means the failure names the cause instead of surfacing as a
		// generic insert error.
		return record(hitlEnqueueError, "approval entry not created: no organization scope on the request")
	}

	approval, err := fincrimeHITLBridge.CreateApproval(ctx, input)
	if err != nil {
		policyID := input.TriggeredPolicyID
		switch {
		case errors.Is(err, hitl.ErrPendingApprovalLimitExceeded):
			// The deliberate decision, and the one the brief called a landmine:
			// the request STAYS HELD and the caller is told why. Admitting it
			// because the queue is full would make a capacity limit into a
			// governance bypass - the single worst possible failure direction
			// for this control. Dropping the entry silently, which is what the
			// pre-change seam did, would put the tenant back in the dead end
			// this work removes, invisibly.
			log.Printf("⚠️ [HITL] %s: approval entry NOT created for policy %s - tenant %s is at its pending-approval limit. "+
				"The request remains held. Clear the queue, or raise the tier's MaxPendingApprovals.",
				plane, logutil.Sanitize(policyID), logutil.Sanitize(input.TenantID))
			return record(hitlEnqueueCapReached,
				"approval entry not created: this tenant is at its pending-approval limit; the request remains held and no reviewer will see it until the queue is cleared")
		case errors.Is(err, hitl.ErrHITLApprovalDisabledByTier):
			// An unentitled tier in enterprise deployment mode. The hold is
			// correct and is what the tier matrix documents; the entry cannot
			// exist. Counted so an operator can see WHY their queue is empty.
			//
			// The wording NAMES NO TIER. Since the 2026-08-26 Enterprise-only
			// decision this arm is reached by Community, Free, Pro, Premium
			// AND Evaluation, so naming one of them sends four of the five
			// hunting a licence-loading bug that does not exist. It also no
			// longer offers Evaluation as the way out, which it is not.
			log.Printf("⏸️ [HITL] %s: approval entry not created for policy %s - %v. The request remains held.",
				plane, logutil.Sanitize(policyID), hitl.ErrHITLApprovalDisabledByTier)
			return record(hitlEnqueueTierDisabled,
				"approval entry not created: "+hitl.ErrHITLApprovalDisabledByTier.Error()+"; the request remains held")
		default:
			log.Printf("❌ [HITL] %s: approval entry not created for policy %s (verdict stands): %v",
				plane, logutil.Sanitize(policyID), err)
			return record(hitlEnqueueError,
				"approval entry not created: the approval queue write failed; the request remains held")
		}
	}

	hitlPolicyEnqueueTotal.WithLabelValues(plane, hitlEnqueueCreated).Inc()
	log.Printf("⏸️ [HITL] %s: approval %s created for policy %s",
		plane, approval.RequestID, logutil.Sanitize(input.TriggeredPolicyID))
	return policyStepUpResult{RequestID: approval.RequestID.String(), Outcome: hitlEnqueueCreated}
}

// enqueuePolicyStepUp raises the reviewable queue entry for a request held by
// a policy-authored require_approval on one of the three agent planes.
//
// It normalises what the planes know into the queue's shape and hands off to
// enqueueApproval; it is the FinCrime seam's sibling, not its wrapper.
func enqueuePolicyStepUp(ctx context.Context, in policyStepUpInput) policyStepUpResult {
	plane := in.Plane
	if plane == "" {
		plane = "agent"
	}
	policyID := approvalPolicyKey(in.PolicyID)
	policyName := in.PolicyName
	if in.PolicyID == "" {
		policyName = "Unattributed require_approval policy"
	}
	if policyName == "" {
		policyName = policyID
	}
	reason := in.Reason
	if reason == "" {
		reason = "human approval required by policy"
	}
	severity := in.Severity
	if !validHITLSeverity(severity) {
		// CreateApprovalRequest rejects an unrecognised severity outright, and
		// the tier engines emit values this table's CHECK constraint does not
		// accept. Defaulting matches the service's own empty-severity default.
		severity = "high"
	}

	reqCtx := map[string]interface{}{
		"plane":       plane,
		"source":      "policy_step_up",
		"decision_id": in.DecisionID,
		"query_hash":  hitlQueryHash(in.Query),
	}
	// Only when present. An empty correlation_id written as "" would be read
	// back by the HITL audit writer as a value and stamped on the compliance
	// row, where the exporters' `correlation_id IS NOT NULL` predicate would
	// group every untraced approval into one bogus chain (#3718). Absent means
	// absent.
	if in.CorrelationID != "" {
		reqCtx["correlation_id"] = in.CorrelationID
	}
	if in.Stage != "" {
		reqCtx["stage"] = in.Stage
	}
	if in.Target != "" {
		reqCtx["target"] = in.Target
	}
	if in.UserEmail != "" {
		reqCtx["user_email"] = in.UserEmail
	}

	// Join an approval a reviewer is ALREADY looking at rather than raising a
	// second one for the SAME held request. Without this, a PEP retry loop mints
	// a row per attempt: before #3509 these planes wrote none at all, so
	// generalising the enqueue put an unbounded, caller-driven write on the
	// queue, and on Enterprise (MaxPendingApprovals = -1) the pending cap does
	// not run to bound it. Duplicated entries do not just waste rows, they bury
	// the one decision a reviewer has to make.
	//
	// "The same held request" means same caller, same policy, SAME PLANE and
	// SAME QUERY. The last two are not padding: without the plane, a caller
	// held on /decide and then on /api/request for one rule collapses two
	// genuinely different governed events into one review and two planes stop
	// producing entries at all; without the query hash, a DIFFERENT request
	// tripping the same policy joins the first entry, so the reviewer approves
	// a descriptor and a decision id belonging to request A while the grant
	// admits request B. Both were review findings, and the second is the more
	// dangerous because it looks like it is working.
	//
	// Best-effort by construction: any error, and any tier without a queue,
	// falls through to the enqueue. That is the safe direction - a duplicate
	// entry is a nuisance, a missing entry is the defect this work removes.
	if in.OrgID != "" && in.TenantID != "" && in.ClientID != "" && in.UserID != "" {
		if existing, err := findOpenPolicyStepUp(ctx, hitl.GrantSubject{
			OrgID:    in.OrgID,
			TenantID: in.TenantID,
			ClientID: in.ClientID,
			UserID:   in.UserID,
		}, policyID, plane, hitlQueryHash(in.Query)); err == nil && existing != "" {
			hitlPolicyEnqueueTotal.WithLabelValues(plane, hitlEnqueueDeduped).Inc()
			log.Printf("⏸️ [HITL] %s: request joins approval %s, already pending for policy %s",
				plane, logutil.Sanitize(existing), logutil.Sanitize(policyID))
			return policyStepUpResult{RequestID: existing, Outcome: hitlEnqueueDeduped}
		}
	}

	return enqueueApproval(ctx, plane, HITLCreateInput{
		OrgID:               in.OrgID,
		TenantID:            in.TenantID,
		ClientID:            in.ClientID,
		UserID:              in.UserID,
		OriginalQuery:       hitlQueryDescriptor(in),
		RequestType:         HITLRequestTypePolicyStepUp,
		RequestContext:      reqCtx,
		TriggeredPolicyID:   policyID,
		TriggeredPolicyName: policyName,
		TriggerReason:       reason,
		Severity:            severity,
		ComplianceFramework: "EU AI Act",
	})
}

// validHITLSeverity mirrors the set CreateApprovalRequest accepts and the
// hitl_valid_severity CHECK constraint enforces (mig 025).
func validHITLSeverity(s string) bool {
	switch s {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// approvalPolicyKey is the value written to hitl_approval_queue.
// triggered_policy_id AND matched by the grant consume predicate. ONE function,
// because the two halves disagreeing is silent: the entry is written under the
// substituted placeholder while the consume passes the raw empty value, so a
// reviewer's approval is unspendable forever and each retry mints another row -
// which is #3509 defect 2 all over again, for the population
// StaticPolicyResult.ApprovalPolicyID's own doc comment calls a legitimate
// state.
//
// The placeholder is deliberately a value that names its own uncertainty. A
// held request whose triggering rule could not be attributed is still worth
// queueing - a reviewer seeing "some policy held this" can act, one seeing
// nothing cannot - but the entry must not pretend to an attribution it does
// not have.
func approvalPolicyKey(policyID string) string {
	if policyID == "" {
		return "require_approval"
	}
	return policyID
}

// policyStepUpReason is the wire-facing reason a plane appends when an entry
// WAS created, so the PEP can name the pending review to its user.
func policyStepUpReason(requestID string) string {
	return fmt.Sprintf("approval request %s pending human review", requestID)
}

// --- Single-use grant consumption (#3509 defect 2) ---

// consumeApprovalGrant spends an outstanding approval, if the reviewer granted
// one for this exact (org, user, policy), and reports whether the held request
// may now proceed.
//
// The consume is ONE atomic statement in the repository - an UPDATE guarded on
// `consumed_at IS NULL` with RETURNING - so two concurrent retries cannot both
// observe an unspent grant. Nothing here reads first and writes second.
//
// FAIL CLOSED, without exception. An empty org or user, an unwired service, a
// database that will not answer: every one of those returns "not consumed", so
// the caller stays held. The failure direction matters more here than almost
// anywhere else in the request path, because the thing on the other side of a
// wrong answer is a human-oversight control that a regulator was told exists.
func consumeApprovalGrant(ctx context.Context, plane string, subj hitl.GrantSubject, policyID, query string) (string, bool) {
	record := func(outcome string) {
		hitlGrantConsumeTotal.WithLabelValues(plane, outcome).Inc()
	}
	if mcpHITLService == nil {
		record(hitlGrantUnavailable)
		return "", false
	}
	if subj.OrgID == "" || subj.TenantID == "" || subj.ClientID == "" || subj.UserID == "" || policyID == "" || query == "" {
		// A grant that matched on a missing dimension would be a grant that
		// matched across callers, tenants or orgs. Refuse, and count it: a
		// sustained missing_subject means a plane is calling without a fully
		// attributed principal, which is a wiring defect and not a quiet no-op.
		record(hitlGrantMissingSubject)
		return "", false
	}
	requestID, err := mcpHITLService.ConsumeApprovalGrant(ctx, subj, policyID, hitlQueryHash(query), hitlGrantTTL())
	if err != nil {
		if errors.Is(err, hitl.ErrHITLApprovalDisabledByTier) {
			// Community build or Community tier: there is no queue, so there is
			// nothing to spend. Not an error condition.
			record(hitlGrantNone)
			return "", false
		}
		log.Printf("⚠️ [HITL] %s: approval grant lookup failed for policy %s (request stays held): %v",
			plane, logutil.Sanitize(policyID), err)
		record(hitlGrantError)
		return "", false
	}
	if requestID == "" {
		record(hitlGrantNone)
		return "", false
	}
	record(hitlGrantConsumed)
	log.Printf("✅ [HITL] %s: approval %s consumed for policy %s - admitting exactly this one request",
		plane, logutil.Sanitize(requestID), logutil.Sanitize(policyID))
	return requestID, true
}

// approvalGrantReason is the wire-facing reason recorded when a grant admitted
// a request, so the admission is never a silent allow: the audit row names the
// approval that authorised it.
func approvalGrantReason(requestID string) string {
	return fmt.Sprintf("admitted by approved human-oversight request %s (single use, now spent)", requestID)
}
