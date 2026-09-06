// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

// The ConsumeGrant scope census, moved here from
// platform/agent/hitl_consume_grant_twins_enterprise_test.go (#3714).
//
// WHY THE OLD TEST IS GONE AND THIS ONE REPLACES IT.
//
// That test compared the ConsumeGrant body in platform/agent/hitl/repository.go
// against the ee/ overlay twin, clause by clause, because the Enterprise image
// copies the ee/ file over the platform/ one and NOTHING except a person
// remembering kept the two equal. Its own header said so: "a fix applied to one
// ConsumeGrant and not the other would pass every test and ship the unfixed
// predicate."
//
// The statement now exists ONCE, in transitions.go, and both Repository copies
// call it. The twin-drift subject the old test existed for no longer has two
// sides, so keeping a two-copy comparison would be asserting a property of a
// thing that is not there - which is a test that can only ever pass.
//
// WHAT IS NOT LOST, and this is the half worth keeping: every clause in that
// predicate is a SCOPE NARROWING, and deleting one silently widens the match
// across users, orgs, planes, past the single-use guard or past the TTL. That
// census moves here intact.
//
// THREE THINGS IMPROVE IN THE MOVE, none of them the reason for it:
//
//   - It reads the COMPILED CONSTANT rather than the file. The old census
//     string-matched source text, so a clause could be present in the file and
//     absent from the statement the code runs (a second const, an edit to the
//     wrong function). Here the subject IS what executes.
//   - It carries NO BUILD TAG. The old file was `//go:build enterprise` because
//     both twins were enterprise-only; this package is tag-free and ships to the
//     community mirror, so the census now runs there too.
//   - The clause list can no longer be satisfied by a SIBLING function, which
//     the old census had to scope a body extractor around after a mutation run
//     found `FindOpenPolicyStepUp` covering for a deleted clause.

import (
	"strings"
	"testing"
	"time"
)

// TestConsumeGrantPredicateKeepsEveryScopeNarrowing.
//
// Every entry below is load-bearing. The two that read like belt-and-braces are
// not:
//
//	client_id       a caller presenting no per-user token gets a SYNTHETIC
//	                identity with ID 0, so user_id is the string "0" for EVERY
//	                such caller in the org. Without this clause one PEP's
//	                approval admits a different PEP's request.
//	reviewer_role   the approve route has no role gate, and on the
//	                organization-license path client_id is an unvalidated
//	                Basic-auth username - so a clause comparing only reviewer_id
//	                to the caller's credential is defeated by re-presenting the
//	                same licence under a different username. Only the role
//	                clause is not defeatable that way.
func TestConsumeGrantPredicateKeepsEveryScopeNarrowing(t *testing.T) {
	clauses := []string{
		"WHERE org_id = $1",
		"AND tenant_id = $2",
		"AND client_id = $3",
		"AND user_id = $4",
		"AND triggered_policy_id = $5",
		// A LITERAL, not a bound parameter: it has to match the partial index's
		// own literal predicate (migration core/167) or the planner cannot use
		// the index under a generic plan, and the consume degrades to a scan of
		// the org's whole queue history on the latency path of a held decision.
		"AND request_type = 'policy_step_up'",
		"AND status = 'approved'",
		"AND consumed_at IS NULL",
		"AND reviewed_at IS NOT NULL",
		"AND reviewed_at > CURRENT_TIMESTAMP - $6::interval",
		"AND reviewer_role IS NOT NULL",
		"AND reviewer_role <> 'service'",
		"AND reviewer_id IS NOT NULL",
		"AND reviewer_id <> $3",
		"AND reviewer_id <> $4",
		// The grant admits the request the reviewer SAW, not the next one the
		// same rule holds.
		"AND request_context->>'query_hash' = $7",
		"ORDER BY reviewed_at ASC",
		"FOR UPDATE SKIP LOCKED",
		"SET consumed_at = CURRENT_TIMESTAMP",
	}

	compared := 0
	for _, c := range clauses {
		compared++
		if !strings.Contains(ConsumeGrantSQL, c) {
			t.Errorf("ConsumeGrantSQL is missing the clause %q. Every clause in this predicate is a "+
				"scope narrowing; dropping one widens the match across users, orgs, planes, past the "+
				"single-use guard or past the TTL. This statement is what the Enterprise image runs.", c)
		}
	}

	// Anti-vacuity, stated as an ABSOLUTE rather than as len(clauses): an
	// arithmetic floor derived from the list it measures is a tautology, and a
	// future edit that builds the list conditionally could otherwise reduce the
	// census to nothing while still satisfying its own count.
	if compared < 19 {
		t.Fatalf("compared only %d clauses; this census is not covering the predicate it claims to", compared)
	}
}

// TestConsumeGrantFailsClosedOnAMissingDimension.
//
// The predicate is only as good as the arguments it is given: an empty scope key
// binds to the empty string and the clause matches nothing OR, worse, matches a
// row whose column is also empty. The guard refuses before the statement runs.
//
// Six one-sided mutants, one per dimension, because a guard written as a
// conjunction can lose ONE disjunct and stay green against a test that only ever
// omits the same field.
func TestConsumeGrantFailsClosedOnAMissingDimension(t *testing.T) {
	full := ConsumeGrantParams{
		OrgID:     "org-1",
		TenantID:  "tenant-1",
		ClientID:  "client-1",
		UserID:    "7",
		PolicyID:  "policy-1",
		QueryHash: "hash-1",
		TTL:       30 * time.Minute,
	}

	for _, tc := range []struct {
		name  string
		blank func(*ConsumeGrantParams)
	}{
		{"OrgID", func(p *ConsumeGrantParams) { p.OrgID = "" }},
		{"TenantID", func(p *ConsumeGrantParams) { p.TenantID = "" }},
		{"ClientID", func(p *ConsumeGrantParams) { p.ClientID = "" }},
		{"UserID", func(p *ConsumeGrantParams) { p.UserID = "" }},
		{"PolicyID", func(p *ConsumeGrantParams) { p.PolicyID = "" }},
		{"QueryHash", func(p *ConsumeGrantParams) { p.QueryHash = "" }},
	} {
		t.Run("empty_"+tc.name, func(t *testing.T) {
			p := full
			tc.blank(&p)
			// A nil *sql.DB is deliberate: the guard must refuse BEFORE it
			// reaches the database, so a test that needed a live connection
			// would be testing a weaker property. A guard that let this through
			// would nil-panic, which the test would report as a failure either
			// way.
			_, _, err := ConsumeGrant(nil, nil, p)
			if err == nil {
				t.Fatalf("an empty %s was accepted; the predicate then widens across that dimension", tc.name)
			}
			if !strings.Contains(err.Error(), "are all required") {
				t.Errorf("an empty %s was rejected for the WRONG reason (%v); the fail-closed guard "+
					"is not what refused it", tc.name, err)
			}
		})
	}

	// A non-positive TTL is refused too: `CURRENT_TIMESTAMP - '0 seconds'` makes
	// the freshness clause admit nothing, and a NEGATIVE one makes it admit
	// approvals from the future.
	for _, ttl := range []int{0, -1} {
		p := full
		p.TTL = time.Duration(ttl) * time.Second
		if _, _, err := ConsumeGrant(nil, nil, p); err == nil {
			t.Errorf("a TTL of %ds was accepted", ttl)
		}
	}

	// ...and the FULL params must NOT be refused by the guard, or every
	// assertion above passes because the guard rejects everything. It reaches
	// the database and fails there instead, which is the correct next step.
	if _, _, err := ConsumeGrant(nil, nil, full); err != nil && strings.Contains(err.Error(), "are all required") {
		t.Errorf("fully-populated params were refused by the fail-closed guard (%v); every "+
			"assertion above is then vacuous", err)
	}
}
