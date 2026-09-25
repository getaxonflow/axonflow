// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// A PENDING APPROVAL ON THE PLANES THAT CANNOT HOLD A REQUEST OPEN (#4370).
//
// PRD v11 §1.13: a challenge holds where the plane can hold. The workflow step
// gate keeps its step pending; a request plane answers and forgets. Before
// #4370 a challenge on mcp:request and decide therefore answered a deny whose
// reason is approval_required - honest, and a dead end: nothing was queued,
// so nobody could approve anything, and a customer's MCP adapter had every
// tool call refused while an approval requirement was active (2026-09-21).
//
// On an Enterprise deployment with the approval queue wired, those two planes
// now hold the way a request plane can:
//
//  1. The challenge queues ONE approval for exactly this call, bound to it
//     (approvalBinding), and answers the caller a pending approval with its
//     id. Pending is not allow: nothing runs.
//  2. The caller retries the same call naming the id (the X-Axonflow-Approval-Id
//     header, or an approval_id argument for a client that cannot set
//     headers). The retry is decided exactly as the first call was; only if it
//     is again a challenge, and the approval is approved, live, unspent,
//     approved by a person who is not the caller, and bound to this very call,
//     does it pass - and the approval is spent in the same transaction
//     (queue.SpendBindingGrant). An allow on the retry spends nothing (the
//     approval was not needed); a deny is never lifted by any approval.
//
// Every other plane is unchanged (the plane matrix in #4370's PR body), and
// the Community build keeps today's refusal exactly: the hold lives in
// approval_hold_enterprise.go, and approval_hold_community.go answers "no
// hold".

import (
	"context"
	"net/http"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/pep"
)

// The retry's carriers. The header is the primary spelling; the argument (MCP)
// and the body field (decide) exist for clients that cannot set headers.
const (
	approvalIDHeader   = "X-Axonflow-Approval-Id"
	approvalIDArgument = "approval_id"
)

// The planes that hold by pending approval, as the pending answer names them.
const (
	approvalHoldPlaneMCPRequest = "mcp:request"
	approvalHoldPlaneDecide     = "decide"
)

// THE REASONS a held call can be answered with. ONE table: the breaker feed,
// the decide `reasons` writer, the mcp:request writers and the published
// contract (docs/api/agent-api.yaml, ApprovalHoldReason) all read it, and
// TestTheApprovalHoldReasonsMatchThePublishedContract holds the document to it.
//
// They are the AGENT's codes, deliberately not decision-contract ReasonCodes:
// they are outcomes of this plane's hold and retry, never an engine decision,
// and contract.AllReasonCodes is the closed AuthZEN reason enum the generated
// SDKs consume (TestAuthZENSchemaEnumerationsMatchTheGoDeclarations went red
// when they were put there; reverted). Two spellings are the approval
// authority's own (approval.ReasonExhausted, approval.ReasonBoundInputChanged),
// so one fact has one string.
const (
	reasonApprovalPending              = "approval_pending"
	reasonApprovalRejected             = "approval_rejected"
	reasonApprovalConsumed             = "approval_already_consumed"
	reasonApprovalNotFound             = "approval_not_found"
	reasonBoundInputChanged            = "bound_input_changed"
	reasonApprovalReviewerUnattributed = "approval_reviewer_unattributed"
	reasonApprovalReviewerExcluded     = "approval_reviewer_excluded"
	// approval_expired is the decision contract's own code
	// (contract.ReasonApprovalExpired), which the step gate already answers
	// for a lapsed approval; the table carries it so its breaker rule is here.
	reasonApprovalExpired = string(contract.ReasonApprovalExpired)
)

// approvalHoldReason is one row of the table.
type approvalHoldReason struct {
	code string
	// meaning is the sentence the caller reads after the code.
	meaning string
	// feedsBreaker says the outcome is the caller's doing, so it counts toward
	// the circuit breaker like any other refusal (violationFeedsCircuitBreaker).
	// A slow human, a credential approving, or a call still waiting is not.
	feedsBreaker bool
}

var approvalHoldReasons = []approvalHoldReason{
	{reasonApprovalPending, "an approval for this call is queued and has not been decided; retry naming it once a person approves", false},
	{reasonApprovalRejected, "the approval this retry names was rejected", true},
	{reasonApprovalConsumed, "the approval this retry names has already admitted its one call", true},
	{reasonApprovalNotFound, "no approval with this id is visible to the caller's organization", true},
	{reasonBoundInputChanged, "the approval this retry names was granted for a different call (other input, tool, route, requester or requirement)", true},
	{reasonApprovalReviewerUnattributed, "the approval this retry names was approved by a credential, not a person; approve it from a person's portal login", false},
	{reasonApprovalReviewerExcluded, "the approval this retry names was approved by the caller itself", true},
	{reasonApprovalExpired, "the approval this retry names expired before it was spent; timeout is a deny", false},
}

// approvalHoldReasonFor returns the table row for code.
func approvalHoldReasonFor(code string) (approvalHoldReason, bool) {
	for _, r := range approvalHoldReasons {
		if r.code == code {
			return r, true
		}
	}
	return approvalHoldReason{}, false
}

// pendingApproval is the `pending_approval` member of a held call's answer:
// the shared PEP type (pep.PendingApproval), so the agent's answer and the
// type a PEP decodes it into are one definition.
type pendingApproval = pep.PendingApproval

// pendingApprovalRetry says how to name the approval on the retry.
type pendingApprovalRetry = pep.PendingApprovalRetry

// approvalHoldCall is one call on a plane that holds by pending approval.
type approvalHoldCall struct {
	plane string
	// route names the entry point within the plane (check_policy, mcp_query,
	// mcp_execute, mcp_check_input, decide). It is bound: an approval asked
	// for on one route does not admit the same input on another.
	route    string
	orgID    string
	tenantID string
	clientID string
	// userEmail is the caller's VALIDATED per-user email (the identity the
	// enforcer admitted), empty for a credential caller. It joins the
	// self-approval exclusion; it is never read from a header or a body.
	userEmail string
	// input is exactly what the approval binds, with the approval id removed.
	input any
	// approvalID is the id the retry names, empty on a first call.
	approvalID string
	// approvalIDConflict says the header and the argument named different
	// ids: no single approval is named, and the retry is refused not found.
	approvalIDConflict bool
	// preflight, when set, runs the wire's own refusals of an ALLOW against
	// the permit an approval would release, BEFORE the approval is spent. It
	// answers the refusal's code and reason, or "" to admit. A wire whose
	// allow can still be refused after the decision (a projection, an
	// obligation gate) sets it, so an approval is never spent on a call the
	// wire then refuses.
	preflight func(allowed requestPassEnforcement) (code, reason string)
	// descriptor is the non-PII label the queue row and the reviewer see
	// (never the statement itself).
	descriptor string
	// label is the queue's step label: the tool name, or the decide target.
	label string
	// decisionID is the plane's decision id, the one the caller's answer and
	// the audit row name. Only the log line of an approval that could not be
	// queued reads it, so an operator can find the cause the wire withholds.
	decisionID string
}

// The codes a preflight answers an approval's permit with: the wire could not
// decide it (an outage, whose reason is then the CAUSE, an enforceCause* key),
// or its gates refuse what the permit carries.
const (
	approvalPreflightOutage  = string(contract.ReasonEvaluationError)
	approvalPreflightRefused = string(contract.ReasonUnsupportedObligation)
)

// mcpConnectorPreflight is the connector routes' (query, execute) preflight:
// the refusal refuseMCPConnectorRequest gives an allow, read from the same
// rendering. That wire delivers no obligation, so a permit still carrying one
// (a redaction under a pii=redact posture) is refused before the spend and not
// after it (#4375 R3 round 1: spend, refuse, re-hold, approve again).
func mcpConnectorPreflight(allowed requestPassEnforcement) (code, reason string) {
	if allowed.unavailable != "" {
		return approvalPreflightOutage, allowed.unavailable
	}
	if result, code := allowed.staticPolicyResult(mcpRequestSeamScope); result.Blocked {
		return code, result.Reason
	}
	return "", ""
}

// approvalSpentOutcome is the hold's outcome when an approval admitted the
// call (an allow, so it is not one of the refusal reasons).
const approvalSpentOutcome = "approval_spent"

// mcpHoldLabel is the queue's step label for an MCP call: the governed tool,
// else its connector.
func mcpHoldLabel(connectorType, tool string) string {
	if tool != "" {
		return tool
	}
	return connectorType
}

// sessionValidatedEmail is the MCP session's validated per-user email - the
// identity sessionSubject admits (mcp_response_enforcing_seam.go) - or empty
// for a credential caller. Never a header.
func sessionValidatedEmail(session *mcpSession) string {
	if session == nil || session.identityInputs.validatedToken == nil {
		return ""
	}
	return session.identityInputs.validatedToken.Email
}

// verifiedCallerEmail is a connector route caller's email when a validator
// VERIFIED its user token (callerIsVerifiedHuman), else empty. It is the email
// the self-approval exclusion may use: never the attributed email, which a
// trusted identity header can supply.
func verifiedCallerEmail(auth *AuthResult, user *User, userErr *AuthError, presentedToken string) string {
	if user == nil || !callerIsVerifiedHuman(auth, userErr, presentedToken) {
		return ""
	}
	return user.Email
}

// mcpStatementInput is what an approval on an MCP call binds: the connector,
// the governed tool, the operation (defaulted as the routes default it), the
// statement as governed and its parameters.
func mcpStatementInput(connectorType, tool, operation, statement string, parameters map[string]interface{}) map[string]interface{} {
	if operation == "" {
		operation = "execute"
	}
	return map[string]interface{}{
		"connector_type": connectorType,
		"tool":           tool,
		"operation":      operation,
		"statement":      statement,
		"parameters":     parameters,
	}
}

// decideHoldLabel is the queue's step label for a decide call: the tool or
// model the PEP declared as its target, else the target type, else the stage.
func decideHoldLabel(stage string, target DecisionTarget) string {
	for _, v := range []string{target.Tool, target.Model, target.Type} {
		if v != "" {
			return v
		}
	}
	return stage
}

// spentApprovalID is the approval that admitted a call, or empty.
func spentApprovalID(held approvalHoldResult) string {
	if held.outcome == approvalSpentOutcome {
		return held.approvalID
	}
	return ""
}

// approvalHoldResult is what the hold made of a call's enforcement.
type approvalHoldResult struct {
	enforced requestPassEnforcement
	// pending is set when the answer is a pending approval.
	pending *pendingApproval
	// approvalID and outcome are what the call's audit row records, set
	// whenever the hold acted (queued, reused, spent or refused a retry).
	approvalID string
	outcome    string
}

type approvalIDHeaderKey struct{}

// withApprovalIDHeader carries the retry's X-Axonflow-Approval-Id header onto
// the context, for an entry point whose tool body sees no *http.Request (the
// MCP server's tools/call dispatch).
func withApprovalIDHeader(ctx context.Context, r *http.Request) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, approvalIDHeaderKey{}, r.Header.Get(approvalIDHeader))
}

// approvalIDFor reads the retry's approval id: the header, else the argument
// or body field. A header and a field that name DIFFERENT ids name no single
// approval; the retry is then answered approval_not_found (conflict).
func approvalIDFor(header, field string) (id string, conflict bool) {
	h, b := strings.TrimSpace(header), strings.TrimSpace(field)
	switch {
	case h != "" && b != "" && h != b:
		return "", true
	case h != "":
		return h, false
	default:
		return b, false
	}
}

// approvalIDHeaderFrom is the header withApprovalIDHeader carried.
func approvalIDHeaderFrom(ctx context.Context) string {
	v, _ := ctx.Value(approvalIDHeaderKey{}).(string)
	return v
}
