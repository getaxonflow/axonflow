// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package admission enforces the Community and Evaluation SCALE boundaries
// (#3593, decision D4 of the v11.0.0 plan): how many distinct human
// principals, service principals, nodes and organization-root policies an
// organization may admit on the tier its SIGNED LICENCE grants.
//
// It is RESTRICTION code and ships in the community binary - it is what makes
// Community and Evaluation smaller, so it must exist where they run. The
// feature code that raises or removes a limit lives under ee/ and is not here.
//
// # ONE PACKAGE, ONE ENTRY POINT, ONE TABLE, ONE SEEN-SET
//
// Admit is the only decision. Every path that brings a principal into
// existence calls it - the agent's client-credential boundary (service
// principals), its per-user token boundaries (human principals), its boot
// (the node), and the orchestrator's organization-policy create path - and
// callsite_census_test.go pins, by AST walk, that each of those paths reaches
// it and that nothing else calls it. There is no per-handler counter, no
// second limits table and no environment override: the limit is
// license.GetTierLimits(tier) for the tier license.ReadCurrentTier returns,
// and the deployment-mode variable is not read anywhere in this package -
// env_free_test.go walks the AST for any environment read and greps the
// source, comments included, for the variable's name.
//
// # THE DECISION, IN ORDER
//
//  1. Unlimited tier (limit -1): allowed, before any I/O ON THE REQUEST PATH,
//     so a ledger outage cannot reach Enterprise traffic and a counting fake
//     proves zero request-path calls. It is NOT true that an unlimited tier
//     never touches the ledger: it records the principal afterwards, off the
//     request path - see the recording note below.
//  2. Principal in the bounded in-memory seen-set: allowed, no I/O.
//  3. Principal in the ledger (principal_admissions, migrations/core/171):
//     allowed, and remembered in the seen-set.
//  4. Otherwise the ledger admits it atomically if count(org, dimension) is
//     below the limit - N-1 rows admit the Nth, N rows refuse the N+1th -
//     under a per-(org, dimension) advisory lock, so two racing first-time
//     principals cannot both slip in at N-1.
//  5. If the ledger cannot be asked at step 3 or 4, the principal is refused
//     with ReasonDependencyUnreachable - NOT ReasonOverLimit - and a
//     Retry-After. Fail closed for NEW principals only, never for traffic:
//     a principal that reached step 2 was never affected.
//
// # NODES ARE LEASES, NOT LEDGER ROWS
//
// A node is a CONCURRENCY dimension (master ruling, 2026-09-08): an ECS task
// or a Kubernetes pod gets a fresh identity on every recreate, so a ledger
// that remembered every node forever would read a routine redeploy as a
// second node. Admit(Node) therefore goes to node_leases (NodeLeases) on
// every call - each call IS the heartbeat, every NodeHeartbeatInterval - and
// the limit counts leases renewed within NodeLeaseTTL. A node that holds a
// lease renews it whatever the count; a node with none is admitted only while
// fewer than `limit` OTHER leases are unexpired. The node identity is
// AXONFLOW_NODE_ID, else an id generated once and persisted under the agent's
// data directory (never the hostname). And the node refusal is the one place
// "unreachable" is NOT fail-closed: a node has no local seen-set, so the
// wiring boots and keeps serving on ReasonDependencyUnreachable (counted and
// audited) and refuses to run only on a POSITIVE over_limit answer - after
// waiting up to nodeBootWait (fifteen minutes) for the foreign lease to
// expire. The budget is that long because the clock that matters is the OTHER
// node's last heartbeat, which keeps advancing while it lives: a rolling
// deploy routinely overlaps for longer than one lease TTL.
//
// REVISIT WHEN: an unreachable lease store stops being the more likely cause of
// a missing renewal than a genuine second node. The availability-first choice
// here - keep serving on unreachable, refuse only on a positive answer - is
// priced on a self-hosted deployment where the store is the deployment's own
// database, so an outage means the operator has bigger problems than a node
// count. A hosted lease store shared across tenants would invert that, and the
// posture should be re-argued rather than inherited.
//
// THE RUNNING NODE HAS A BOUND TOO, and it is not the boot one. Once serving,
// each heartbeat is an Admit: an unreachable lease store never stops the node
// (it is logged and the count is CLEARED), but ten CONSECUTIVE positive
// over_limit answers do - five minutes at NodeHeartbeatInterval, which is
// longer than NodeLeaseTTL so a stale foreign lease has had time to expire
// first. Because a dependency_unreachable beat resets the count rather than
// being skipped, a flapping link defers the stop indefinitely; that is the
// availability posture applied consistently, not an oversight. Total exposure
// on a partition is therefore the partition itself plus about five and a half
// minutes, and the split brain ends by the process exiting rather than by
// someone noticing. nextOverLimitBeats is that decision, extracted from the
// loop so TestNextOverLimitBeatsBoundsTheSplitBrain can drive every case.
//
// # AN UNLIMITED TIER RECORDS, OFF THE REQUEST PATH
//
// The operator's ruling is that the ledger still records on unlimited tiers,
// "for telemetry and the qualification profile; a recording failure is logged
// and dropped, never surfaced to the request". It is also what makes a
// downgrade survivable: without it an Enterprise deployment's ledger is empty,
// so the moment its licence expires every principal is new at once and all but
// the first N are refused. The write is asynchronous, deduped by the seen-set
// to one attempt per principal per process, capped at MaxBackgroundWriters
// concurrent writers, and every drop is counted on
// axonflow_tier_admission_background_drops_total.
//
// # THE EXPIRED LICENCE IS A NAMED CASE
//
// license.ReadCurrentTier resolves an expired, forged or absent key to
// TierCommunity and says WHY (TierRead.Rejected / ReasonClass). Admit reads
// that: the deployment degrades to the Community table, existing principals
// keep working (steps 2-3 do not consult the tier), new principals are
// measured against Community limits, and Decision.LicenceState names the
// state so a refusal message can say "licence expired" rather than only
// "limit reached". It never becomes unlimited.
//
// # WHAT A REFUSAL LOOKS LIKE
//
// Three observables, each distinct from an authentication failure:
//   - the error code ERR_TIER_LIMIT_<DIMENSION> (Dimension.Code) with HTTP
//     402 (HTTPStatus) on every wire that carries a status;
//   - axonflow_tier_limit_refusals_total{dimension, edition, reason}, with
//     reason over_limit or dependency_unreachable;
//   - one audit_logs row with request_type tier_limit_refusal and the same
//     fields under policy_details.
//
// # WHAT IS COUNTED, AND WHAT HAS NO RECLAIM PATH
//
// The two principal dimensions count DISTINCT PRINCIPALS EVER ADMITTED, not
// principals concurrently active: the ledger is append-only, so no supported
// path releases a slot. A departed employee holds one of the 25 until the
// organization's row set is dropped, and even a superuser has to drop a
// trigger to remove one. That is a deliberate consequence of the append-only
// guarantee the outage posture rests on - "already admitted" has to be a fact
// nothing can un-make - and it is stated here, in the docs page and on #3593
// rather than left for an operator to discover at the ceiling. PRD section 6's
// trailing-30-day active-principal window is the design that would change it,
// and it is not built.
//
// REVISIT WHEN: a deployment reaches its ceiling on principals that are no
// longer active - departed staff, rotated service credentials, a re-keyed
// integration - rather than on the people currently using it. That is the
// signal that the count has stopped measuring the thing the limit is for, and
// it is the point at which PRD section 6's window earns its complexity. Until
// then "ever admitted" is the stricter reading and the one an append-only
// table can actually prove.
//
// # THE SEEN-SET IS A CACHE, NOT A STORE
//
// It is bounded (DefaultSeenSetCap = 10,000), LRU, per process, warmed from
// the ledger at boot for the deployment's own organizations and filled as
// principals are admitted. The cap is shared across organizations, so a
// deployment serving very many of them (the community-SaaS shape, where each
// tenant is its own org) can evict faster than it fills; the cost of an
// eviction is one ledger round trip on that principal's next request, never a
// refusal, and such a deployment is on an unlimited tier in the first place. A cap hit evicts the least recently used key and NOTHING ELSE
// happens: an evicted principal is looked up in the ledger on its next request
// (step 3) and is admitted there. Only when BOTH the seen-set misses AND the
// ledger is unreachable does step 5 apply. A process that restarts while the
// ledger is unreachable starts with an empty set and re-warms as soon as the
// ledger answers (Warm is retried by the wiring); until then every principal
// is "new" to that process, which is the honest reading of the ruling rather
// than a second store pretending otherwise.
package admission
