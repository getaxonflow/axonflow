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

// LatencyUnmeasured is the sentinel a writer passes when it has nothing to
// measure, as distinct from having measured a duration that rounded to zero.
//
// It is NEGATIVE on purpose. audit_logs.response_time_ms is BIGINT
// milliseconds, so a decision completing in under a millisecond truncates to 0
// through time.Duration.Milliseconds(); 0 therefore has to stay available as a
// REAL value, or every sub-millisecond enforcement decision disappears from the
// average and the tile silently reports only the slow tail. A duration can
// never be negative, so -1 is unambiguously "no measurement" and cannot collide
// with one.
const LatencyUnmeasured int64 = -1

// LatencyMeasuredPredicate is the SQL fragment every reader uses to decide
// which audit_logs rows carry a real enforcement-latency measurement. It is
// exported so an aggregate and its sample count cannot drift apart: the mean
// and the divisor must range over the same rows, which is precisely what
// /api/v1/audit/report got wrong before #3424 (it summed over measured rows
// and divided by all of them, so an unmeasured row acted as a zero-latency
// sample and pulled the mean down).
//
// It admits a stored 0. That is a behaviour CHANGE from the first cut of the
// #3424 fix, which required `> 0` and so treated a sub-millisecond decision
// exactly like an unmeasured one: measured, fast, and erased. Measured live,
// 19 of 20 ordinary ALLOW decisions recorded no sample under that rule, leaving
// the tile to average the slow tail and report 5ms for traffic whose true mean
// was well under 1ms. With latency_sample_count on the wire an average of 0.4
// over 1000 samples is unambiguous, so the honest representation of a fast
// decision is the 0 the clock produced, not a NULL that makes it wear a missing
// measurement's costume. The writers hold up the other half of that contract by
// storing LatencyUnmeasured as NULL rather than as a 0 (see MeasuredLatencyMs),
// and migration core/161 nulls the fabricated zeros written before this change
// so they cannot be read back as samples.
//
// It has no placeholders, so it composes into any WHERE or FILTER clause
// without disturbing positional argument numbering.
const LatencyMeasuredPredicate = "response_time_ms IS NOT NULL"

// LatencyProviderPlane is the audit_logs.plane value whose response_time_ms is
// a PROVIDER round trip rather than an enforcement duration. Mirrors
// agent.PlaneLLM, which this package cannot import (the agent package imports
// this one); TestLatencyProviderPlaneMatchesAgentConstant in platform/agent
// pins the two equal so the string cannot drift.
const LatencyProviderPlane = "llm"

// LatencyEnforcementPredicate is LatencyMeasuredPredicate narrowed to the rows
// whose measurement is an ENFORCEMENT duration and which the portal's audit
// page also counts in total_requests. Every reader that shows an operator an
// enforcement-latency figure uses this one, not the bare measured predicate.
//
// Two narrowings, both from #3424 round 2:
//
//   - plane <> 'llm'. response_time_ms does not mean the same thing on every
//     plane: the orchestrator's LLM-forward writer stores the provider round
//     trip, the decision planes store the enforcement duration, and the two
//     differ by orders of magnitude. Measured live on a mixed stack, THREE
//     llm-plane rows among 53 moved the tile from 5ms to 724ms, so a customer
//     whose traffic mix shifted would read a 3x "speedup" that never happened.
//     The audit page's tile is the enforcement number (the same quantity the
//     axonflow_decision_duration_milliseconds histogram reports), so the
//     provider plane is excluded rather than averaged in. That round trip is
//     still recorded on the row itself; it is not lost, it is just not this
//     average. #3435 makes that half of the sentence reachable rather than
//     merely true: the SEBI regulator export's llm_calls section now reads
//     these same plane='llm' rows and carries their response_time_ms, so the
//     provider latency the tile excludes has a surface that reports it. It was
//     not reachable through that export before, because the section's query
//     named eleven columns its table does not have and returned an empty
//     section on every deployment.
//
//   - the row must NAME its plane in the COLUMN, which is what makes the line
//     above actually work. audit_logs.plane arrived in migration core/119, and
//     that migration backfilled only decision_id -- it never backfilled plane.
//     So every LLM-forward row older than it carries a PROVIDER ROUND TRIP
//     with a NULL plane, and neither `plane <> 'llm'` nor the NULL-safe
//     `plane IS DISTINCT FROM 'llm'` matches a NULL: written either of those
//     ways the exclusion admits, on an install with history, precisely the
//     population it exists to remove.
//
//     The empty-string arm is belt and braces, not a second known population.
//     The BatchWriter binds nullIfEmpty(entry.Plane), so its unstamped rows are
//     NULL rather than blank, and every other writer binds a plane CONSTANT.
//     The empty string is reachable only from hand-written SQL (seed data, a
//     fixture, an operator's backfill), which is exactly the class this
//     predicate should not have to trust.
//
//     WHAT THIS COSTS, stated rather than waved at: a row that is measured and
//     unstamped is dropped from the average even if it is enforcement latency.
//     Before #3424 no enforcement WRITER populated response_time_ms, so no
//     such row can exist from the platform -- but hand-written SQL can create
//     one, and did: config/seed-data/demo_data.sql seeded measured, unstamped,
//     non-provider rows until this change taught it to stamp a plane. If a
//     future fixture forgets, its rows go quiet in the tile rather than
//     poisoning it, which is the direction this is deliberately biased in.
//
//     DELIBERATELY NOT the COALESCE(plane, policy_details->>'plane') idiom
//     used by ojk/export_queries.go and ojk/retention.go. That idiom recovers
//     a plane for rows whose column predates the migration, which is right for
//     an exporter that must not lose a row. Here it would buy a narrow
//     recall gain (a pre-119 row whose JSONB names a non-llm plane) for a
//     JSONB extraction on every row of every summary query, and it would still
//     miss rows predating the JSONB dual-write. The recall it does buy is
//     measured latency the platform's enforcement writers could not have
//     produced in that era, so the trade is not close.
//
//   - policy_decision <> 'override_lifecycle'. The summary's total_requests
//     routes lifecycle markers out of the verdict triage, so admitting them
//     here could make latency_sample_count exceed total_requests and turn the
//     tile's own basis disclosure ("6 of 28 measured") into nonsense.
//
// Like LatencyMeasuredPredicate it carries no placeholders.
var LatencyEnforcementPredicate = LatencyMeasuredPredicate +
	" AND plane IS NOT NULL AND plane <> '' AND plane <> '" + LatencyProviderPlane + "'" +
	" AND policy_decision <> '" + DecisionOverrideLifecycle + "'"

// MeasuredLatencyMs converts a writer's OWN measured enforcement duration into
// the value to bind to audit_logs.response_time_ms: the duration itself when
// the writer measured one (including a 0 produced by a decision faster than the
// column's 1ms resolution), or an untyped nil (SQL NULL) when the caller passed
// LatencyUnmeasured.
//
// This is the write-side half of LatencyMeasuredPredicate, and the two exist as
// one pair on purpose (#3424). The distinction the pair encodes is between a
// measurement and the ABSENCE of one, never between a fast measurement and a
// slow one:
//
//   - A writer that measured stores what it measured. A 0 here is a claim the
//     writer can back: it started a clock, stopped it, and the elapsed time was
//     below one millisecond.
//   - A writer with nothing to record passes LatencyUnmeasured and stores NULL,
//     never 0. NULL is the absence of a claim, and it is what makes "no measured
//     samples" representable end to end: AVG over no rows is NULL, the API emits
//     null rather than 0, and the portal renders "N/A".
//
// The return type is interface{} because that is what database/sql binds: a
// typed nil pointer would encode as NULL too, but an untyped nil keeps the call
// sites free of a per-writer pointer local.
//
// KNOWN SEMANTIC, deliberately not resolved here: response_time_ms carries
// THREE different quantities, not two.
//
//	plane            quantity                     who measured it
//	---------------  ---------------------------  ---------------------------
//	decision,        enforcement duration         AxonFlow, wall clock around
//	gateway, mcp,    (what the decision-duration  its own evaluation
//	openai_compat    histogram reports)
//	llm              PROVIDER round trip          AxonFlow, around an outbound
//	                 (LogSuccessfulRequest, from  call to a third party
//	                 ProviderInfo.ResponseTimeMs)
//	cowork,          CLIENT-ASSERTED duration_ms  the AI tool itself, self-
//	claude_code      off the OTLP span            reported over the ingest API
//
// The third one is not even AxonFlow's measurement: cowork_otel_ingest.go binds
// whatever duration_ms the exporting client put on the span, which is that
// tool's own end-to-end time, is unverified, and is not comparable with an
// enforcement duration. LatencyEnforcementPredicate excludes the provider plane
// today; the client-asserted planes stay in, are a far smaller distortion, and
// are filed separately (#3431) rather than smuggled into this change. Recorded
// here so the next person to average this column learns it before, not after.
func MeasuredLatencyMs(ms int64) interface{} {
	if ms < 0 {
		return nil
	}
	return ms
}

// LatencyValue is the pointer form of MeasuredLatencyMs, for writers that carry
// the measurement as an optional field rather than through a sentinel. A nil
// pointer is the absence of a measurement (SQL NULL); a non-nil one is bound as
// measured, including a 0.
//
// orchestrator.AuditEntry.ResponseTime is *int64 for exactly this reason: seven
// of its eight producers never measure anything, and with a plain int64 field
// their zero VALUE was indistinguishable from a measured zero both on the INSERT
// and on the JSON the /audit/search read path emits (#3424 round 2 blocker).
func LatencyValue(ms *int64) interface{} {
	if ms == nil {
		return nil
	}
	return MeasuredLatencyMs(*ms)
}

// NullIfUnmeasuredLatency is for durations AxonFlow did NOT measure itself and
// which arrive over an API that cannot distinguish "zero" from "field absent":
// today that is only the OTLP ingest plane, where duration_ms is asserted by
// the exporting client and a missing attribute decodes as 0.
//
// Non-positive therefore means "the client told us nothing" and stores NULL. Do
// NOT use this for a duration the platform measured with its own clock: there a
// 0 is a real sub-millisecond result and MeasuredLatencyMs keeps it.
func NullIfUnmeasuredLatency(ms int64) interface{} {
	if ms <= 0 {
		return nil
	}
	return ms
}
