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

// This file is the single definition of the "top triggered policies"
// aggregation. TWO surfaces render it (#3426):
//
//	portal tile   GET  /api/v1/audit/summary -> top_policies -> the audit
//	              page's "Top Triggered Policies" chips
//	export        POST /api/v1/audit/report  -> top_policies -> the Compliance
//	              Report's Top Triggered Policies table
//
// They used to carry two hand-copied duplicates of the same query, and both
// duplicates read policy_details->>'policy_name' directly:
//
//	SELECT COALESCE(policy_details->>'policy_name', 'unknown') ...
//	 WHERE policy_details->>'policy_name' IS NOT NULL
//	 GROUP BY policy_details->>'policy_name'
//
// That singular scalar is a documented HITL-ONLY exception
// (ee/platform/agent/hitl/repository.go BuildHITLAuditDetails). The decide
// plane, the MCP planes and the FinCrime seam stamp the PLURAL policy_names
// array and policy_ids, so those rows failed the IS NOT NULL predicate and
// were dropped BEFORE grouping, not merely miscounted. On the fraud demo the
// tile showed exactly one chip, the single HITL row, while several FinCrime
// controls had demonstrably fired; the Compliance Report under-reported which
// policies fired by the identical mechanism, on a regulator-facing artifact.
//
// The fix is not a second key in two queries. Both surfaces now build their
// query HERE, off PolicyIdentitySetSQLExpr, so:
//
//   - the aggregation reads every shape any writer has ever produced, through
//     the same #3243 / v9.16.1 resolution chain the OJK, SEBI and EU AI Act
//     exporters use, and a NEW writer key becomes readable everywhere at once;
//   - the tile and the export cannot drift from each other, because there is
//     one query text;
//   - the aggregation resolves a policy out of the SAME KEY the row-level
//     Policy column beside it resolves from, so a reader can reconcile "policy
//     X fired 4 times" against the rows.
//
// It does NOT render that policy the same way, and the difference is carried
// explicitly rather than papered over. This chain is IDENTITY-first
// (PolicyIdentitySQLExpr's documented order: ids beat names, because a
// fabricated-looking name on a regulator artifact is worse than a raw
// identifier, and because policy_names is explicitly NOT index-parallel to
// policy_ids per #3347 / #3359, so no name can be paired to an id at read
// time). The portal's Policy column is NAME-first
// (resolvePolicyIdentityDisplay in customer-portal-ui/lib/api.ts). Since #3365
// every canonical writer stamps policy_names, so on one panel the table row can
// legitimately read "PII: IBAN" while the chip above it reads `sys_pii_iban`.
//
// What both surfaces DO share is the half of the #3347 / #3359 discipline
// (census row AU-9) that this aggregate can honestly keep: a value resolved
// out of an IDENTIFIER key is never rendered as though it were a display name.
// TopPoliciesQuery returns identity_is_name per policy, resolved from WHICH ARM
// matched, and both renderers mark such a value with the NEUTRAL
// POLICY_IDENTIFIER_MARKER. Inventing a display name for an id is still
// refused, as ojkPolicyDisplayName refuses it.
//
// The qualifier is load-bearing, not hedging. The flag can only trust the KEY a
// value came out of, so a writer that puts IDS in a name key defeats it: the
// legacy CSV `{"policy_names":"fincrime_structuring, legacy_only"}` resolves
// through the names arm and reports identity_is_name TRUE for two strings that
// are plainly identifiers (the real-Postgres fixture pins exactly this). No
// read-time rule can tell that apart without a catalog lookup, which #3347
// refuses on purpose - a policy renamed after the row was written would then
// display a name the row never carried. "Never renders an id as a name" is
// therefore false as stated and is not claimed.
//
// It deliberately does NOT reuse the row-level POLICY_NAME_NOT_RECORDED_MARKER
// ("(name not recorded)"), and the reason is a defect this file shipped once
// (#3438 R3). That marker is a claim about the WRITER, and on this aggregate it
// was false in the DEFAULT case: since #3365 stampPolicyIdentityNames stamps
// policy_names beside policy_ids on every canonical writer, so a decide-plane
// row records a name AND resolves the id arm. Every such chip and every such
// Compliance Report row asserted "name not recorded" about a policy whose name
// the audit table on the same screen was printing. See
// PolicyIdentityIsNameSQLExpr for why answering the writer question here is
// both expensive and, for display purposes, useless.

// TopPoliciesLimit is how many policies the aggregation returns. Both surfaces
// use it, and the portal tile additionally shows only the leading few chips.
//
// The limit TRUNCATES, and pre-#3426 it effectively never bit: the aggregation
// could only see rows carrying the singular policy_name, so reaching ten
// distinct policies took a stack with ten distinct HITL gates. Widening the
// reader makes ten a realistic count on a single day of FinCrime traffic, and a
// silently truncated table on a REGULATOR-FACING compliance report reads as
// "these are the policies that fired". TopPoliciesQuery therefore also returns
// the total number of DISTINCT policies in range (see below) so both surfaces
// can disclose "top 10 of 37" rather than imply 37 does not exist.
const TopPoliciesLimit = 10

// TopPoliciesTimeout bounds the aggregation. Every caller runs it under
// QueryContext with this deadline, so a slow range releases its pool connection
// instead of running to completion.
//
// It is not a defensive constant looking for a problem. The query's cost is
// linear in IN-SCOPE ROWS (not table size), measured on PostgreSQL 16.14 at
// roughly 2.9 microseconds per in-scope row, and the summary handler permits a
// 365-DAY range (audit_summary_handler.go). Measured envelope, median of 11
// client-timed runs over a decorrelated corpus (every in-scope row a distinct
// JSONB document across all five writer shapes):
//
//	in-scope rows   pre-#3426   this query
//	      6,066        2.5 ms      22.5 ms
//	    300,000       29.5 ms     929    ms
//	  3,000,000      140   ms    8658    ms
//
// Attribution of the delta, so the next reader does not have to re-derive it:
// the SET EXPANSION dominates at about 80%, the identity_is_name flag adds
// ~28% on top of it (720 ms to 924 ms at 300k), and the total_policies window
// plus BOTH override exclusions are together within run-to-run noise (924 ms
// to 929 ms). No index removes any of it: the cost is per-row JSONB expansion
// across every in-scope row.
//
// The last row is the single-tenant self-hosted topology, which is the common
// enterprise deployment: 8.7 SECONDS on one on-demand tile render, holding a
// connection the whole time, on a `database/sql` pool shared with the request
// path. Neither call site took a context before this, and there is no
// statement_timeout anywhere in the repo, so nothing bounded it at all.
//
// 15s rather than something tighter because the alternative to a slow answer
// here is NO answer: each surface degrades explicitly rather than silently --
// the compliance summary sets TopPoliciesUnavailable and the portal renders
// "could not be computed", while the regulator-facing report fails the whole
// response with a 500 (it has no such field, by design) -- and a
// self-hosted tenant with three million in-scope rows should get its real
// numbers rather than a permanent refusal. lib/pq propagates the cancellation
// to the server, so the backend stops working when the deadline fires.
const TopPoliciesTimeout = 15 * time.Second

// topPoliciesAlias is the LATERAL alias the aggregation groups on. Local to
// the generated SQL, so it cannot collide with a caller's WHERE clause.
const topPoliciesAlias = "fired_policy"

// TopPoliciesQuery builds the complete top-policies aggregation.
//
//	predicate      the caller's row predicate WITHOUT the "WHERE" keyword,
//	               using positional placeholders bound by the caller. It is
//	               PARENTHESISED before the builder ANDs its own
//	               policy_details filter onto it: taking a ready-made WHERE
//	               clause and appending " AND ..." binds tighter than a
//	               top-level OR in the caller's predicate, which would silently
//	               widen the aggregation past the rows the caller scoped it to.
//	blockedParam   the positional placeholder (e.g. "$4") bound to
//	               pq.Array(Spellings(DecisionBlocked)) for the block_count
//	               FILTER. It must be the LAST argument the caller appends.
//
// Columns, in scan order: policy identity, identity_is_name, trigger_count,
// block_count, total_policies.
//
//	identity_is_name false when the identity is a raw IDENTIFIER, true when it
//	                 is a display NAME. A property of the RESOLVED STRING, never
//	                 of the writer: the chain is id-first, so the common
//	                 decide-plane row resolves an id and reports false even
//	                 though the same row also stamps policy_names. Without the
//	                 flag the aggregate would render that id as though it were a
//	                 name; with it MISREAD as a writer claim, the aggregate
//	                 renders "(name not recorded)" against a recorded name.
//	                 bool_and, not bool_or: when two rows resolve the same
//	                 string out of DIFFERENT arms, under-claiming is the right
//	                 direction on a regulator artifact. COALESCEd to false so an
//	                 all-NULL group takes the identifier affordance rather than
//	                 failing the scan.
//	total_policies   the number of DISTINCT policies in range BEFORE
//	                 TopPoliciesLimit truncates. A window over the grouped rows
//	                 (WindowAgg runs above the aggregate and below the Limit),
//	                 so it costs no second query and no second scan. Identical
//	                 on every returned row; callers read it once.
//
// Row shape gained two columns relative to the two queries this replaces; both
// callers' scan targets are updated in the same commit.
//
// A row is counted ONCE PER DISTINCT POLICY it recorded. A single decide-plane
// row on which four FinCrime controls fired stamps four ids in policy_ids and
// now contributes one trigger to each, which is what "top triggered policies"
// has to mean: attributing such a row to policy_ids[0] alone under-reports the
// other three by the same mechanism as the excluded-rows defect. The counts
// therefore do NOT sum to the number of audit rows, and neither surface
// presents them as a share of one.
//
// A row that records NO policy identity under any key contributes nothing:
// unnest over the empty array PolicyIdentitySetSQLExpr returns yields zero
// rows, so the CROSS JOIN LATERAL drops it. That preserves the pre-fix
// behaviour for those rows (the old IS NOT NULL predicate dropped them too) and
// keeps the aggregation free of a bucket that is not a policy. The
// unconditional `policy_details IS NOT NULL` below is a cheap pre-filter for
// the same class, not a semantic difference.
//
// OVERRIDE EVENT ROWS ARE EXCLUDED, ON EVERY PLANE, KEYED ON request_type.
// They stamp the plural policy_ids (and, since #3365, policy_names) and never
// the singular policy_name, so pre-#3426 they failed the
// `policy_name IS NOT NULL` filter and were dropped by accident. Widening the
// reader resolves them, and counting them is a real regression on a compliance
// artifact:
//
//   - override_created / _revoked / _expired record a GRANT, not an
//     evaluation. No policy fired on those rows at all.
//   - override_used records the policy whose block was BYPASSED, and it is a
//     SECOND row for an enforcement the plane's own row already counted. An
//     actively-overridden policy would otherwise top "Top Triggered Policies"
//     while being the one policy that was NOT enforced. The report table is
//     Policy / Triggers / Blocks, so a bypass renders indistinguishably from an
//     enforcement.
//
// THE DISCRIMINATOR IS request_type, NOT policy_decision, and an earlier round
// of this PR got that wrong in a way that left the fix half-applied. The two
// override writers agree on request_type and DISAGREE on policy_decision:
//
//	orchestrator LogOverrideEvent (override_audit.go)
//	    request_type = the event type, policy_decision = override_lifecycle
//	agent writeOverrideUsedEvent (mcp_richer_context.go:512)
//	    request_type = "override_used", policy_decision = "allowed"
//
// So `policy_decision <> 'override_lifecycle'` excludes the orchestrator plane
// and silently keeps the MCP one - the override_used row, i.e. exactly the
// harm above, arriving by the other plane. policy_decision.go says so in the
// same package: those rows "are identified by their RequestType
// (IsOverrideEventType), not by policy_decision". ONE predicate on request_type
// covers both planes; see OverrideEventExclusionSQL.
//
// BOTH keys are excluded rather than only request_type. The request_type
// predicate is the complete one and is what makes the fix whole; the
// policy_decision one is retained because it is the spelling the four sibling
// aggregates use (foldDecisionCount, audit_summary_handler.go's verdict triage,
// LatencyEnforcementPredicate, and session_summary_handler.go's bucket
// aggregation) and dropping it here would leave this file the only one that
// does not visibly refuse a non-verdict marker. Measured cost of
// the added request_type predicate at 300k in-scope rows: 924 ms to 929 ms,
// i.e. inside run-to-run variance.
//
// Two schema facts make both bare literal comparisons safe, and both were
// checked rather than assumed, because this is the shape that silently drops
// rows when they do not hold:
//
//   - audit_logs.policy_decision and audit_logs.request_type are BOTH
//     `VARCHAR(50) NOT NULL` (migration core/059). `NULL <> 'x'` is NULL, so a
//     nullable column would have made these predicates quietly exclude every
//     unstamped row from the aggregation as well.
//   - migration core/123 normalizes policy_decision to, and CHECKs it against,
//     exactly {allowed, blocked, redacted, needs_approval, error,
//     override_lifecycle} in lower case. So the literal comparison cannot miss
//     a case or whitespace variant the way a reader that skipped Normalize
//     otherwise could.
//
// NOT justified by "consistency with the Total beside it". An earlier round
// kept the MCP override_used row on that ground; it is not a property this
// aggregate has or claims. A single row contributes one trigger to EACH policy
// it recorded, so per the paragraph above "the counts therefore do NOT sum to
// the number of audit rows, and neither surface presents them as a share of
// one."
//
// FLAGGED, NOT CHANGED: the four sibling aggregates still key on
// policy_decision alone, so the MCP override_used row is counted as an ordinary
// "allowed" verdict by each of them. That is defensible for a verdict count
// (the request really was allowed) and dubious for LatencyEnforcementPredicate,
// but none is a policy RANKING, which is the harm this exclusion addresses. The
// fourth is session_summary_handler.go's bucket aggregation, whose own comment
// used to assert the bare <> was complete there; corrected in this PR.
//
// ORDER BY carries an identity tiebreak so equal trigger counts return in a
// stable order rather than whatever the plan happens to emit.
func TopPoliciesQuery(predicate, blockedParam string) string {
	return fmt.Sprintf(`
		SELECT
			%[1]s.policy AS policy_name,
			COALESCE(bool_and(%[6]s), false) AS identity_is_name,
			COUNT(*) AS trigger_count,
			COUNT(*) FILTER (WHERE policy_decision = ANY(%[2]s)) AS block_count,
			COUNT(*) OVER () AS total_policies
		FROM audit_logs
		CROSS JOIN LATERAL unnest(%[3]s) AS %[1]s(policy)
		WHERE (%[4]s)
		  AND policy_details IS NOT NULL
		  AND policy_decision <> '%[7]s'
		  AND %[8]s
		GROUP BY %[1]s.policy
		ORDER BY trigger_count DESC, %[1]s.policy ASC
		LIMIT %[5]d
	`, topPoliciesAlias, blockedParam, PolicyIdentitySetSQLExpr("policy_details"), predicate, TopPoliciesLimit,
		PolicyIdentityIsNameSQLExpr("policy_details"), DecisionOverrideLifecycle,
		OverrideEventExclusionSQL("request_type"))
}
