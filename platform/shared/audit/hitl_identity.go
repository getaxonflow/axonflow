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

package audit

import (
	"fmt"
	"time"
)

// This file is the IDENTITY half of the audit-attribution class that
// policy_identity.go opened.
//
// v9.16.1 (#3243) fixed the POLICY-ATTRIBUTION half: HITL approval rows named
// their policy under keys the compliance exporters did not read, so the OJK
// export rendered a blank Policy column on every one of them. The IDENTITY
// half - the keys that let a row be CORRELATED and FILTERED at all - was never
// fixed, and its cost is larger (#3718):
//
//	ee/platform/agent/hitl/repository.go wrote an audit_logs row with fifteen
//	columns and none of them was decision_id, plane or correlation_id.
//
//	platform/orchestrator/decisions_list_handler.go selects on exactly that:
//	  AND (decision_id IS NOT NULL OR policy_details->>'decision_id' IS NOT NULL)
//
// So NO HUMAN APPROVAL DECISION HAS EVER APPEARED IN THE DECISIONS FEED, and
// every plane-scoped export dropped them. An approval is the most consequential
// decision the platform records - a person confirmed or overrode a policy
// outcome - and it was the one class a reviewer could not find there.
//
// WHY THESE HELPERS LIVE HERE rather than beside the writer. The writer is
// ee/platform/agent/hitl/repository.go, which the Enterprise image copies OVER
// platform/agent/hitl/ at build time; the package that reads these rows is
// platform/orchestrator. Neither can import the other, and platform/shared/audit
// is what both already import - the same reasoning that put
// PolicyIdentitySQLExpr here.

// PlaneHITL is the audit_logs.plane value for a HUMAN OVERSIGHT decision: an
// approve, reject or override recorded through the HITL API.
//
// It is its own plane rather than a reuse of "agent" or "decision", for the
// reason PlaneAccessEvaluation is its own plane: `plane` answers "which surface
// decided", and a person deciding through the Article 14 oversight API is not
// the agent gateway PEP. Folding it into an existing plane would make every
// plane-scoped export either lose these rows or silently mix a human decision
// in with machine enforcement.
//
// SAFE FOR THE LATENCY TILE, and that is checked rather than assumed:
// LatencyEnforcementPredicate admits any row with a non-null, non-'llm' plane,
// so stamping a plane on a row could have started voting it into the operator's
// enforcement-latency average. It cannot: the predicate's first conjunct is
// `response_time_ms IS NOT NULL`, and the HITL writer binds
// MeasuredLatencyMs(LatencyUnmeasured) = NULL, because an approve/reject is an
// asynchronous human decision with no enforcement duration to record (#3424).
// TestHITLPlaneIsExcludedFromTheLatencyTile pins that pair.
const PlaneHITL = "hitl"

// HITLDecisionID is the decision_id stamped on a human-oversight audit row.
//
// IT IS THE APPROVAL'S OWN DECISION ID, NOT THE ORIGINATING ONE, and the
// distinction is the whole design:
//
//   - decision_id is documented (migration core/119) as the "stable satellite
//     join key" and every writer "mints a FRESH id per decision". Two rows
//     sharing one would make the decisions feed render one decision twice and
//     give any satellite join two parents.
//   - the originating decision is carried by correlation_id, which migration
//     core/121 defines as exactly that: "a single value shared by every decision
//     row of one logical request". A reviewer asking "what did the human decide
//     about decision D?" groups on correlation_id, which is the column for the
//     question.
//
// DETERMINISTIC, because the row it identifies is. The audit row's primary key
// is already `hitl_<action>_<request_id>` with ON CONFLICT DO NOTHING so a
// replayed write collides instead of duplicating; a random decision_id would
// break that idempotence in the one column a reader joins on.
//
// NEVER EMPTY. This is the "say so explicitly rather than leaving the column
// null" requirement in #3718, and it is satisfied structurally rather than by a
// fallback: the id is derived from the approval request, which always exists, so
// there is no path on which a HITL row can carry a null decision_id and vanish
// from the feed. A HITL row with no ORIGINATING decision still has its own.
func HITLDecisionID(action, requestID string) string {
	return fmt.Sprintf("hitl_%s_%s", action, requestID)
}

// HITLDetailKeyOriginatingDecision is the policy_details key carrying the
// decision id of the request that RAISED the approval, when there was one.
//
// Recorded in addition to correlation_id rather than instead of it. The two
// answer different questions and a reader needs both: correlation_id groups the
// chain (and may be a trace id shared by several decisions), while this names
// the single decision a human was asked about. On a HITL row raised by a policy
// step-up the enqueue path records that id in
// hitl_approval_queue.request_context, which is where the writer reads it from.
const HITLDetailKeyOriginatingDecision = "originating_decision_id"

// HITLAttributionNoOriginatingDecision is the value stamped under
// HITLDetailKeyOriginatingDecision when a HITL row genuinely has no originating
// decision.
//
// Stated affirmatively for the same reason PolicyAttributionUnnamedGate is: a
// missing key and an absent decision are indistinguishable to a reader, and one
// of them is a bug. A row carrying this value is making a claim the writer can
// back - the approval request recorded no decision_id in its request_context -
// rather than leaving a reviewer to guess whether the plumbing dropped it.
const HITLAttributionNoOriginatingDecision = "no originating decision recorded"

// HITLAuditRow is one human-oversight audit_logs row, in bind order.
//
// WHY THE STATEMENT LIVES HERE AND NOT BESIDE ITS WRITER.
//
// The writer is a Repository method in a package the Enterprise image copies
// over platform/agent/hitl/ at build time, and the READER is
// platform/orchestrator's decisions feed. Neither module can import the other,
// so before this change the only thing binding them was that somebody had
// remembered to write the same three columns on both sides - and nobody had,
// for the whole life of the feed (#3718).
//
// Putting the statement and the feed's predicate (DecisionRowPredicate, below)
// in one file is the same device MeasuredLatencyMs / LatencyMeasuredPredicate
// uses one file over: a write-side and a read-side that MUST agree are declared
// together, so a change to either is a change a reviewer sees next to the other.
// It also makes the outcome testable without a cross-module import - the
// realpg test in platform/orchestrator inserts through this exact statement and
// asks the production feed query whether the row came back.
type HITLAuditRow struct {
	ID             string
	RequestID      string
	Timestamp      time.Time
	ReviewerEmail  string
	ReviewerRole   string
	ClientID       string
	TenantID       string
	OrgID          string
	RequestType    string
	Query          string
	QueryHash      string
	PolicyDecision string
	PolicyDetails  []byte

	// Action and ApprovalRequestID derive decision_id. They are the INPUTS
	// rather than a precomputed id so no call site can bind a decision_id this
	// package did not mint - the property #3718 turns on.
	Action            string
	ApprovalRequestID string

	// CorrelationID is empty when the raising caller propagated no trace.
	CorrelationID string
}

// HITLAuditInsertSQL is the single authored INSERT for a human-oversight
// audit_logs row.
//
// ON CONFLICT (id) DO NOTHING keeps a replayed write idempotent: the id is
// `hitl_<action>_<request_id>`, so a retry collides rather than double-counting
// an approval on a regulator artifact. Callers who want an append-only trail
// use hitl_approval_history, which is the immutable source of record; this row
// is a denormalized projection for portal-facing and feed-facing queries.
const HITLAuditInsertSQL = `
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, response_time_ms,
			decision_id, plane, correlation_id
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12,
			$13, $14, $15,
			$16, $17, $18
		)
		ON CONFLICT (id) DO NOTHING
	`

// auditUserRoleMaxLen mirrors audit_logs.user_role's VARCHAR(50). A long
// SAML/OIDC role claim would otherwise make PostgreSQL reject the whole INSERT
// and silently drop the compliance row.
const auditUserRoleMaxLen = 50

// HITLAuditArgs renders a row as the ordered bind list for HITLAuditInsertSQL.
//
// Three of the eighteen values are NOT taken from the caller, on purpose:
//
//	plane            always PlaneHITL. A human decided this row whichever
//	                 surface asked, and a per-call-site plane is a value a
//	                 call site can get wrong.
//	decision_id      minted here from Action + ApprovalRequestID, so it is
//	                 deterministic, matches the row's own primary key shape,
//	                 and CANNOT BE EMPTY - which is what stops a HITL row
//	                 failing the decisions feed's IS NOT NULL predicate.
//	response_time_ms always NULL. An approve/reject is an asynchronous human
//	                 decision with no enforcement duration; a stored 0 would
//	                 vote a real sub-millisecond measurement's value into the
//	                 operator's latency average (#3424).
//
// user_id binds the literal 0: HITL reviewers have no integer users.id, and
// their identity lives in user_email/user_role. The column is NOT NULL.
func HITLAuditArgs(row HITLAuditRow) []interface{} {
	var correlationArg interface{}
	if row.CorrelationID != "" {
		// NULL rather than '' when absent: the partial index and every exporter
		// predicate are `correlation_id IS NOT NULL`, so an empty string would
		// enter the index and group every untraced approval into one chain.
		correlationArg = row.CorrelationID
	}
	role := row.ReviewerRole
	if len(role) > auditUserRoleMaxLen {
		role = role[:auditUserRoleMaxLen]
	}
	return []interface{}{
		row.ID,
		row.RequestID,
		row.Timestamp,
		0, // user_id
		row.ReviewerEmail,
		role,
		row.ClientID,
		row.TenantID,
		row.OrgID,
		row.RequestType,
		row.Query,
		row.QueryHash,
		row.PolicyDecision,
		row.PolicyDetails,
		MeasuredLatencyMs(LatencyUnmeasured),
		HITLDecisionID(row.Action, row.ApprovalRequestID),
		PlaneHITL,
		correlationArg,
	}
}

// DecisionIDSQLExpr is how every reader resolves a row's decision id.
//
// COALESCE over the column and the JSONB mirror, because migration core/119
// promoted decision_id to a column and backfilled it, but writers DUAL-WRITE
// both and a deployment mid-upgrade has rows with only the JSONB. Exported so
// the SELECT list and the WHERE clause cannot drift apart.
const DecisionIDSQLExpr = `COALESCE(decision_id, policy_details->>'decision_id')`

// DecisionRowPredicate is the clause that decides whether an audit_logs row is
// a DECISION - i.e. whether it appears in the decisions feed and in every
// decision-chain export.
//
// This is the exact predicate that made #3718 invisible for the life of the
// feed: HITL approval rows carried neither the column nor the JSONB key, so
// every human approval failed it silently. Nothing about a row that fails this
// clause looks wrong; it is simply absent.
//
// Exported for the same reason LatencyMeasuredPredicate is: the feed, the
// exports and any test that claims a row "appears in the feed" must range over
// the SAME rows, and a re-typed copy of a predicate is a copy that drifts. It
// carries no placeholders, so it composes into any WHERE clause without
// disturbing positional argument numbering.
const DecisionRowPredicate = `(decision_id IS NOT NULL OR policy_details->>'decision_id' IS NOT NULL)`
