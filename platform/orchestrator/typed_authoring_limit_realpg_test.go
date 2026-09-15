// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
)

// The ladder's numbers, driven through the community route against a REAL
// Postgres ledger (#3907, #3906).
//
// # Why a real database rather than the counting fake
//
// The ceiling is not enforced by anything in this package. It is enforced by an
// advisory-locked INSERT in admission.PostgresLedger.AdmitUnderLimit that
// counts rows on (org, dimension) and writes only under the bound, inside RLS,
// on an append-only table. A fake counter would assert that this route calls
// something - which the call-site census already pins, statically, without a
// database - and would say nothing about whether 20 means 20.
//
// # What the drive asserts, and the two ways it could be vacuous
//
// N-1 / N / N+1 rather than "the 21st fails": a refusal test that never
// observes a success is satisfied by a route that refuses everything, and one
// that stops at N never sees the boundary. So the 20th must SUCCEED and the
// 21st must fail, on the same handler, in one run.
//
// And the refusal is asserted BY ITS REASON. A 402 is not evidence of a
// ceiling: an unreachable ledger produces the same status on the same
// dimension, deliberately, with the difference carried in the reason and in
// Retry-After. A test satisfied by "the request failed" would pass against a
// database that was simply down, which is the exact instrument that reports a
// working limit on a broken deployment.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).

// ledgerBackedHandler wires the package-level admitter over a real ledger at a
// named tier and returns a router over the community route.
//
// It writes tierAdmitter, which is package state, so these tests do not run in
// parallel with each other and say so here rather than leaving it to be
// discovered.
func ledgerBackedHandler(t *testing.T, appDB *sql.DB, tier license.Tier) (*TypedAuthoringRouteHandler, func()) {
	t.Helper()
	a := admission.New(
		admission.NewPostgresLedger(appDB),
		admission.WithAuditSink(admission.NewDBAuditSink(appDB)),
		// The tier is PRESENTED rather than read from the environment: the one
		// verified read resolves AXONFLOW_LICENSE_KEY, and a test that had to
		// mint three signed licences to check three numbers would be testing
		// the key format.
		admission.WithTierReader(func(context.Context) license.TierRead {
			return license.TierRead{Tier: tier, KeyPresent: true}
		}),
		// No memo: the tier must be re-read per admission so a test that
		// changes it sees the change.
		admission.WithTierMemoTTL(0),
	)
	previous := tierAdmitter.Load()
	tierAdmitter.Store(a)
	h := newRouteHandler(t, authoring.EditionFor(string(tier)))
	return h, func() {
		a.WaitForRecording()
		_ = a.Close(context.Background())
		tierAdmitter.Store(previous)
	}
}

// ledgerRowCount counts admitted rows for one organization.
//
// IT COUNTS THROUGH A BYPASSRLS CONNECTION, AND THE FIRST VERSION OF IT DID
// NOT. principal_admissions is FORCE ROW LEVEL SECURITY on
// org_id = current_setting('app.current_org_id'), and the ledger sets that GUC
// per statement inside rls.WithOrgScope. A plain query on the app-role pool
// sets nothing, so it matched ZERO rows for every organization - and zero rows
// is an ABSENT answer, not a clean one. The drive caught it because it asserts
// a count of 20 rather than a count of 0; an assertion in the other direction
// ("nothing was written for the refused document") would have passed against
// exactly the same blind instrument, forever.
//
// So this takes the owner pool, which is what platform/agent's own
// admission_realpg_test.go uses for the same question, and it answers about the
// table rather than about the reader's scope.
func ledgerRowCount(t *testing.T, ownerDB *sql.DB, orgID string) int {
	t.Helper()
	var n int
	if err := ownerDB.QueryRow(
		`SELECT count(*) FROM principal_admissions WHERE org_id = $1 AND dimension = $2`,
		orgID, string(admission.OrgRootPolicy)).Scan(&n); err != nil {
		t.Fatalf("counting ledger rows: %v", err)
	}
	return n
}

// publishWithRules publishes ONE document carrying n distinct policies.
//
// THE UNIT IS THE POLICY, which is what the ceiling counts and why this helper
// varies the rule count rather than the document count. An earlier version
// published n DOCUMENTS of two rules each and measured the wrong thing - and
// measured it green: because every document carried the same two rule ids,
// admission was idempotent and twenty publications wrote TWO ledger rows. A
// root carries one document, so a per-document ceiling never binds and 20 would
// have meant "unlimited". See the admission block in handlePublish.
func publishWithRules(t *testing.T, h *TypedAuthoringRouteHandler, orgID string, n int) (int, map[string]any) {
	t.Helper()
	d := communityDocument()
	base := d.Policy.Policies[0]
	rules := make([]pdp.Policy, 0, n)
	for i := 1; i <= n; i++ {
		p := base
		p.ID = fmt.Sprintf("rule-%03d", i)
		rules = append(rules, p)
	}
	d.Policy.Policies = rules

	// The gauntlet requires a fixture naming exactly the policies the document
	// declares, so the expectation set is DERIVED from the document rather than
	// written beside it.
	fx := refundFixtures()
	for i := range fx {
		fx[i].Expect = map[string]pdp.Verdict{}
		for _, p := range rules {
			fx[i].Expect[p.ID] = pdp.VerdictMatch
		}
	}
	rr := call(t, routerFor(h), http.MethodPost, TypedAuthoringRoutePrefix+"/publish",
		typedAuthoringDocumentRequest{Document: d, Fixtures: fx},
		map[string]string{"X-Org-ID": orgID, "X-User-ID": testUser})
	return rr.Code, decodeBody(t, rr)
}

// TestTheLadderIsRealOnTheRouteACustomerWritesThrough_RealPG is the DoD drive.
func TestTheLadderIsRealOnTheRouteACustomerWritesThrough_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	t.Cleanup(env.Cleanup)

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	// The verification pool. See ledgerRowCount for why it must not be the
	// app-role one.
	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })

	// ANTI-VACUITY FOR THE INSTRUMENT ITSELF, before any of it is trusted: a
	// counter that can only ever return zero would satisfy several assertions
	// below, and the run that discovered this was one where it did. The table
	// must be reachable and must currently be empty for the orgs under test.
	for _, org := range []string{"org-com", "org-eval", "org-ent"} {
		if got := ledgerRowCount(t, ownerDB, org); got != 0 {
			t.Fatalf("the ledger already holds %d row(s) for %s before the drive started", got, org)
		}
	}

	cases := []struct {
		tier  license.Tier
		limit int
		org   string
	}{
		{license.TierCommunity, 20, "org-com"},
		{license.TierEvaluation, 50, "org-eval"},
	}

	for _, tc := range cases {
		t.Run(string(tc.tier), func(t *testing.T) {
			// The number is READ FROM THE ONE LIMITS TABLE rather than written
			// here. A test carrying its own copy of 20 would keep passing after
			// somebody changed the ladder, which is the failure this whole lane
			// is about: a number that is true in one place and false in another.
			want := license.GetTierLimits(tc.tier).OrgPolicies
			if want != tc.limit {
				t.Fatalf("the limits table says %s admits %d customer-authored policies and this drive expects %d; "+
					"one of the two moved without the other", tc.tier, want, tc.limit)
			}

			h, done := ledgerBackedHandler(t, appDB, tc.tier)
			defer done()

			// N-1: a document one rule under the ceiling publishes.
			if code, body := publishWithRules(t, h, tc.org, want-1); code != http.StatusOK {
				t.Fatalf("a document of %d rules was refused under a ceiling of %d: status=%d body=%v",
					want-1, want, code, body)
			}
			// N: exactly at the ceiling. Idempotent on the first want-1 ids, so
			// this spends ONE more rather than starting again - the property
			// that lets an author edit a document sitting at the ceiling.
			if code, body := publishWithRules(t, h, tc.org, want); code != http.StatusOK {
				t.Fatalf("a document of exactly %d rules was refused AT the ceiling: status=%d body=%v", want, code, body)
			}
			if got := ledgerRowCount(t, ownerDB, tc.org); got != want {
				t.Fatalf("the ledger holds %d rows after publishing %d rules; the ceiling counts RULES, so a mismatch "+
					"means the route and the ledger disagree about what was admitted", got, want)
			}

			// N+1: refused, and refused FOR THE CEILING.
			code, body := publishWithRules(t, h, tc.org, want+1)
			if code != http.StatusPaymentRequired {
				t.Fatalf("a document of %d rules was NOT refused past a ceiling of %d: status=%d body=%v",
					want+1, want, code, body)
			}
			if body["reason"] != "tier_limit" {
				t.Fatalf("refused with reason=%v, want tier_limit", body["reason"])
			}
			// The refusal names WHICH rule crossed the boundary. A ceiling that
			// says only "too many" leaves an author a document to bisect.
			if body["policy"] != fmt.Sprintf("rule-%03d", want+1) {
				t.Fatalf("the refusal names policy %v, want the %dth rule", body["policy"], want+1)
			}
			if body["code"] != admission.OrgRootPolicy.Code() {
				t.Fatalf("refusal code=%v, want %q", body["code"], admission.OrgRootPolicy.Code())
			}
			// THE MESSAGE NAMES THE LIMIT. This is the difference between "you
			// were refused" and "you were refused BECAUSE the ceiling is 20 and
			// you hold 20", and it is what separates a ceiling from an outage:
			// the dependency_unreachable refusal on this same dimension carries
			// the same status and the same code, and would satisfy every
			// assertion above.
			msg, _ := body["error"].(string)
			if !strings.Contains(msg, strconv.Itoa(want)) {
				t.Fatalf("the refusal does not name the ceiling of %d: %q", want, msg)
			}
			if !strings.Contains(msg, string(tc.tier)) && !strings.Contains(msg, strings.ToLower(string(tc.tier))) {
				t.Fatalf("the refusal does not name the edition: %q", msg)
			}
			if strings.Contains(msg, "Retry") || strings.Contains(msg, "retry") {
				t.Fatalf("the refusal reads as retryable, which is the OUTAGE refusal on this dimension rather than "+
					"the ceiling: %q", msg)
			}
			// The refused document wrote nothing PAST the ceiling: the rules
			// before the boundary are the same ids already held, and the one
			// past it was not admitted.
			if got := ledgerRowCount(t, ownerDB, tc.org); got != want {
				t.Fatalf("the ledger grew to %d rows on a refused publication", got)
			}

			// RE-PUBLISHING THE SAME RULES IS NOT A NEW ADMISSION. Editing a
			// document must not spend capacity, or a deployment at the ceiling
			// could never change a policy again - #3893's requirement, and the
			// reason the key is the rule identifier rather than anything
			// derived from the publication.
			code, body = publishWithRules(t, h, tc.org, want)
			if code != http.StatusOK {
				t.Fatalf("re-publishing the same %d rules was refused: status=%d body=%v", want, code, body)
			}
			if got := ledgerRowCount(t, ownerDB, tc.org); got != want {
				t.Fatalf("re-publishing the same rules wrote row %d; admission is not idempotent on the rule id", got)
			}
		})
	}

	// THE NEGATIVE TWIN: an Enterprise deployment is not newly limited.
	//
	// It publishes past the largest limited ceiling without a refusal. It is
	// driven here, on the same ledger, rather than reasoned from "-1 returns
	// early": the unlimited branch also RECORDS since #3907, so Enterprise now
	// touches this table for the first time and the interesting question is
	// whether that recording can ever refuse. It cannot - the record is off the
	// request path - and this is the measurement of that.
	t.Run("enterprise is not newly limited", func(t *testing.T) {
		h, done := ledgerBackedHandler(t, appDB, license.TierEnterprise)
		defer done()
		// Enterprise cannot publish through THIS route - it has separation of
		// duties and this route names no approver - so the assertion is about
		// the ADMISSION, which is the part the ladder governs. Publishing is
		// refused at 422 for the approver reason on every attempt, never at 402
		// for a ceiling, however many documents exist.
		const beyondEveryCeiling = 55
		for i := 1; i <= beyondEveryCeiling; i++ {
			code, body := publishWithRules(t, h, "org-ent", i)
			if code == http.StatusPaymentRequired {
				t.Fatalf("an Enterprise deployment hit a tier ceiling at document %d: %v", i, body)
			}
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("document %d: status=%d, want 422 (no approver on this route); body=%v", i, code, body)
			}
			if body["code"] == admission.OrgRootPolicy.Code() {
				t.Fatalf("document %d carries a tier-limit code on an unlimited tier: %v", i, body)
			}
		}
		// THOSE 55 REFUSALS NOW RECORD NOTHING, AND THIS ASSERTION USED TO SAY
		// THE OPPOSITE (#3973).
		//
		// It required the ledger to be non-empty here, reasoning that a later
		// downgrade would otherwise find an empty ledger and hand the deployment
		// a fresh full ceiling. The requirement is right. The rows were not: on
		// this route an Enterprise publication is ALWAYS refused 422 for the
		// approver reason, so every row it was counting described a document
		// that does not exist. It was asserting on garbage, and the fix that
		// makes a refused publication consume nothing takes that count to zero.
		if got := ledgerRowCount(t, ownerDB, "org-ent"); got != 0 {
			t.Fatalf("%d ledger row(s) survive %d REFUSED publications; a refused publication must consume nothing, "+
				"and on an unlimited tier the recording happens off the request path only for one that succeeded",
				got, beyondEveryCeiling)
		}

		// #3907'S REQUIREMENT, RE-ASSERTED ON ROWS THAT DESCRIBE SOMETHING THAT
		// HAPPENED. The downgrade material comes from the paths that actually
		// admit - the legacy create and bulk import, which reach the same choke
		// point this calls - rather than from publications that were refused.
		// Seeded through admitOrgRootPolicies for that reason: it IS the
		// function PolicyService.validateTierForCreate and ImportPolicies call,
		// so this is the production path and not a fixture standing in for it.
		if err := admitOrgRootPolicies(context.Background(), "org-ent", []string{"legacy-org-policy-a", "legacy-org-policy-b"}); err != nil {
			t.Fatalf("an unlimited tier refused an admission: %v", err)
		}
		// The unlimited tier records asynchronously, off the request path.
		tierAdmitter.Load().WaitForRecording()
		if got := ledgerRowCount(t, ownerDB, "org-ent"); got != 2 {
			t.Fatalf("an unlimited tier recorded %d of 2 admissions; a later downgrade would find a short ledger and "+
				"give this deployment more headroom under the new ceiling than it should have", got)
		}
	})
}

// TestTheLimitDriveCanActuallyFail is the planted positive control for the
// drive above.
//
// The N+1 assertions are only evidence if the instrument can produce a failure.
// This plants a ceiling of ONE by presenting a limits table with OrgPolicies=1
// and asserts the SECOND document is refused - so the same code path that
// reports "20 then refused" is shown reporting "1 then refused" on demand,
// which a route that never refuses, or a ledger that never counts, cannot do.
func TestTheLimitDriveCanActuallyFail_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	t.Cleanup(env.Cleanup)

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })

	planted := license.CommunityLimits
	planted.OrgPolicies = 1
	a := admission.New(
		admission.NewPostgresLedger(appDB),
		admission.WithTierReader(func(context.Context) license.TierRead {
			return license.TierRead{Tier: license.TierCommunity, KeyPresent: true}
		}),
		admission.WithLimits(func(license.Tier) license.TierLimits { return planted }),
		admission.WithTierMemoTTL(0),
	)
	previous := tierAdmitter.Load()
	tierAdmitter.Store(a)
	t.Cleanup(func() { a.WaitForRecording(); _ = a.Close(context.Background()); tierAdmitter.Store(previous) })

	h := newRouteHandler(t, authoring.EditionCommunity)
	if code, body := publishWithRules(t, h, "org-planted", 1); code != http.StatusOK {
		t.Fatalf("the first document under a planted ceiling of 1 was refused: status=%d body=%v", code, body)
	}
	code, body := publishWithRules(t, h, "org-planted", 2)
	if code != http.StatusPaymentRequired {
		t.Fatalf("the second document under a planted ceiling of 1 was NOT refused: status=%d body=%v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "1 ") {
		t.Fatalf("the planted refusal does not name the planted ceiling: %q", msg)
	}
}

// TestARefusedCeilingPublicationSpendsNothing_RealPG is #3973's headline.
//
// # What it pins that the drive above cannot
//
// The ladder drive publishes 19, then 20, then 21 against the SAME
// organization, so by the time it overshoots, twenty ids are already admitted
// and only the twenty-first is new. Admission is idempotent on the key, so the
// count does not move and the drive is green either way. The defect needs a
// FRESH organization meeting the ceiling in ONE document - which is what an
// operator importing a legacy policy set actually does.
//
// Against the code this replaces, this test fails at [2]: the loop admitted
// rule-001 through rule-020, refused rule-021, and left the ceiling's worth of
// rows behind for a publication that never took effect. The organization was
// then at 20 of 20 with nothing active, and #3973's own acceptance criterion -
// "after a refusal at the ceiling, a document AT the ceiling publishes
// successfully" - was impossible to satisfy, which is what [3] asserts.
//
// # Why each leg is here
//
// [0] is anti-vacuity for the INSTRUMENT before anything is trusted: this file
// already records a counter that read zero for every organization because it
// queried without the RLS scope, and every "nothing was written" assertion in
// this test would pass against exactly that blind instrument, forever.
//
// [1] asserts the refusal BY ITS REASON and by the policy it names. A 402 alone
// is also what an unreachable ledger produces on this dimension, deliberately,
// so a test satisfied by "the request failed" would pass against a database that
// was simply down.
//
// [3] is the anti-vacuity for [2] and the acceptance criterion at once: the same
// organization, through the same handler, must be able to publish AT the ceiling
// afterwards. Without it, a route that had stopped admitting anything at all
// would satisfy [2].
func TestARefusedCeilingPublicationSpendsNothing_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	t.Cleanup(env.Cleanup)

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	// A PRECONDITION of every RLS assertion below, not a detail.
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })

	h, done := ledgerBackedHandler(t, appDB, license.TierCommunity)
	defer done()

	// The number is READ FROM THE ONE LIMITS TABLE, never written here.
	want := license.GetTierLimits(license.TierCommunity).OrgPolicies
	const org = "org-overshoot"

	// [0] the instrument can see this organization at all.
	if got := ledgerRowCount(t, ownerDB, org); got != 0 {
		t.Fatalf("the ledger already holds %d row(s) for %s before the drive started", got, org)
	}

	// [1] ONE document, one policy past the ceiling, against a FRESH org.
	code, body := publishWithRules(t, h, org, want+1)
	if code != http.StatusPaymentRequired {
		t.Fatalf("a document of %d policies was not refused past a ceiling of %d: status=%d body=%v",
			want+1, want, code, body)
	}
	if body["reason"] != "tier_limit" {
		t.Fatalf("refused with reason=%v, want tier_limit", body["reason"])
	}
	if body["policy"] != fmt.Sprintf("rule-%03d", want+1) {
		t.Fatalf("the refusal names policy %v, want the %dth rule - the batch must report the FIRST policy that "+
			"did not fit, or an author is handed a document to bisect", body["policy"], want+1)
	}
	if msg, _ := body["error"].(string); strings.Contains(msg, "Retry") || strings.Contains(msg, "retry") {
		t.Fatalf("the refusal reads as retryable, which is the OUTAGE refusal on this dimension rather than the "+
			"ceiling: %q", msg)
	}

	// [2] THE WHOLE TEST: it spent nothing.
	if got := ledgerRowCount(t, ownerDB, org); got != 0 {
		t.Fatalf("a publication refused at the ceiling spent %d ledger row(s). principal_admissions is append-only "+
			"with no release, so this organization now holds capacity for a document that was never published - and "+
			"at %d of %d it can never publish again, including the smaller document the refusal told it to publish. "+
			"Admission must be one all-or-nothing batch, made after the document is judged", got, got, want)
	}

	// [3] the remedy the refusal prescribes must be PERFORMABLE.
	if code, body := publishWithRules(t, h, org, want); code != http.StatusOK {
		t.Fatalf("a document AT the ceiling was refused after an over-ceiling attempt: status=%d body=%v. This is "+
			"#3973's acceptance criterion: the refusal instructs the author to publish fewer policies, and following "+
			"that instruction has to work", code, body)
	}
	if got := ledgerRowCount(t, ownerDB, org); got != want {
		t.Fatalf("the accepted document wrote %d rows, want %d; the counter reads wrong for everything and [2] "+
			"proves nothing", got, want)
	}
}

// TestAnEditionRefusalSpendsNoCapacity_RealPG is the second half of #3973, and
// it covers the refusals the first half cannot.
//
// # Why this is not the invalid-document test one file down
//
// An invalid document is refused by `rebuild`, which runs BEFORE anything is
// admitted and always did - that test passes on both trees. The refusals this
// change is actually about are raised INSIDE Publish, after the point where the
// old code had already admitted every policy in the document.
//
// The edition boundary is exactly such a refusal, and that is read from the tree
// rather than assumed: `checkEditionConstructs` has ONE caller, publish.go:236,
// and `NewDocument`/`Validate` take a *Catalog and no Profile, so the rebuild
// path cannot apply an edition boundary at all. edition.go:455-460 states the
// design - Validate answers "is this well formed", which is edition-free;
// Publish answers "may this become a signed artifact".
//
// # What it costs on the old code, and why the number is derived
//
// groupScopedDocument() is communityDocument() with the first policy's scope
// swapped for a group, so the document carries TWO policies. Against the code
// this replaces, the loop admitted both and Publish then refused the
// publication: two permanent rows for a document that never existed. Measured
// at exactly that on a booted Community stack before the fix.
//
// # Why it is not the Enterprise arm above either
//
// That arm asserts 55 APPROVER_IS_AUTHOR refusals spend nothing, which is a
// SEPARATION-OF-DUTIES refusal. Both are raised inside Publish and both must
// spend nothing, but they are different gates and one passing is not evidence
// about the other.
func TestAnEditionRefusalSpendsNoCapacity_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	t.Cleanup(env.Cleanup)

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })

	// A REAL ledger behind the handler is the whole point. The unit test that
	// already drives this refusal - see
	// TestTheEditionBoundaryIsAppliedThroughTheRouteAndNotOnlyInTheLibrary -
	// uses newRouteHandler, which leaves
	// tierAdmitter NIL on purpose - so admitOrgRootPolicies returns nil, the
	// ledger is never touched, and that test can say nothing whatever about what
	// the refusal spent.
	h, done := ledgerBackedHandler(t, appDB, license.TierCommunity)
	defer done()

	const org = "org-edition-refusal"
	if got := ledgerRowCount(t, ownerDB, org); got != 0 {
		t.Fatalf("the ledger already holds %d row(s) for %s before the drive started", got, org)
	}

	// [1] REFUSED, AND FOR THE EDITION REASON. A bare 422 would also be produced
	//     by a malformed document, which is refused before admission on both
	//     trees and would make this test vacuous.
	rr := call(t, routerFor(h), http.MethodPost, TypedAuthoringRoutePrefix+"/publish",
		publishBody(groupScopedDocument()), map[string]string{"X-Org-ID": org, "X-User-ID": testUser})
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422 for a group-scoped document on Community; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), authoring.CodeGroupScopeNotInEdition) {
		t.Fatalf("refused, but not for the edition reason; this test needs an EDITION refusal to be about "+
			"anything: %s", rr.Body.String())
	}

	// [2] AND IT SPENT NOTHING. Against the code this replaces: 2.
	if got := ledgerRowCount(t, ownerDB, org); got != 0 {
		t.Fatalf("a publication refused for the EDITION BOUNDARY spent %d ledger row(s). The author cannot act on "+
			"this by trimming the document - the construct is not in their edition at all - so the capacity is gone "+
			"for a document that could never have been published. Admission must run after Publish has judged the "+
			"document, not before it", got)
	}

	// [3] ANTI-VACUITY, and it is load bearing: the SAME organization through
	//     the SAME handler must write rows once the document is one Community
	//     can carry. Without it, a handler that had stopped admitting entirely -
	//     or the RLS-blind counter this file already documents - satisfies [2]
	//     forever.
	if code, body := publishWithRules(t, h, org, 2); code != http.StatusOK {
		t.Fatalf("the valid control was refused: status=%d body=%v", code, body)
	}
	if got := ledgerRowCount(t, ownerDB, org); got != 2 {
		t.Fatalf("the valid control wrote %d rows, want 2; the counter reads zero for everything and [2] proves "+
			"nothing", got)
	}
}

// TestAnInvalidDocumentSpendsNoCapacity_RealPG pins the ordering.
//
// The rules are admitted from the REBUILT document, after NewDocument has run
// the full save-time check set — so a document that cannot be saved is refused
// before a single ledger row is written for it. That matters because
// principal_admissions is APPEND-ONLY: a row spent on a document that never
// existed is not recoverable, and an author fixing a validation error one
// attempt at a time would burn their ceiling doing it.
//
// It is a test rather than a comment because the ordering is invisible: admit
// before rebuild and every assertion in the drive above still passes.
func TestAnInvalidDocumentSpendsNoCapacity_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	t.Cleanup(env.Cleanup)

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })

	h, done := ledgerBackedHandler(t, appDB, license.TierCommunity)
	defer done()

	// A document naming an action the registry does not contain. It is well
	// under the ceiling, so the ONLY thing that can refuse it is validation.
	d := communityDocument()
	d.Policy.Policies[0].Actions = pdp.ActionSelector{
		Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::not.registered")},
	}
	rr := call(t, routerFor(h), http.MethodPost, TypedAuthoringRoutePrefix+"/publish",
		publishBody(d), map[string]string{"X-Org-ID": "org-invalid", "X-User-ID": testUser})
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422 for a document naming an unregistered action; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), authoring.CodeActionNotRegistered) {
		t.Fatalf("refused for the wrong reason; this test needs a VALIDATION refusal to be about anything: %s", rr.Body.String())
	}
	if got := ledgerRowCount(t, ownerDB, "org-invalid"); got != 0 {
		t.Fatalf("an invalid document spent %d ledger row(s); the ledger is append-only, so an author fixing a "+
			"validation error one attempt at a time would burn their ceiling doing it", got)
	}

	// ANTI-VACUITY: the same org publishing a VALID document does write rows,
	// so the zero above is a property of the refusal rather than of the
	// organisation, the pool or the counter.
	if code, body := publishWithRules(t, h, "org-invalid", 2); code != http.StatusOK {
		t.Fatalf("the valid control was refused: status=%d body=%v", code, body)
	}
	if got := ledgerRowCount(t, ownerDB, "org-invalid"); got != 2 {
		t.Fatalf("the valid control wrote %d rows, want 2; the counter reads zero for everything", got)
	}
}

// TestAStorageOutageSpendsNoCapacity_RealPG pins the ORDER of two refusals.
//
// It is the sibling of the test above and it exists because the two refusals
// are not the same kind of thing. A validation refusal is about the document
// the author sent; a storage outage is about us. The ledger is append-only with
// no release, so admissions spent on the way to a refusal the caller could not
// have avoided are gone - the caller pays part of their ceiling for our
// database being unreachable, and pays again on every retry until it is back.
//
// #3973 ruled the general form: the ledger records what happened, not what was
// attempted.
//
// THE ORDERING IS INVISIBLE WITHOUT THIS TEST. Every other assertion in this
// package holds whichever way round the two run, including the transient-failure
// drive in typed_authoring_persistence_realpg_test.go: that one asserts the 503,
// the uncached workspace and the recovery, none of which move. The only
// observable difference is the row count, and only against a real ledger -
// realPGRouteHandler wires no admitter, so admitOrgRootPolicies returns nil
// there and would count zero under every ordering.
//
// SINCE #3973 THIS IS BELT AND BRACES RATHER THAN THE ONLY GUARD, and it is kept
// for what it still proves. Admission now runs inside PublishAdmitting, after
// the document is judged and before the artifact is stored, so a storage refusal
// raised here could not spend a slot even if this block moved. What this test
// pins is that the early refusal keeps happening early - a workspace or storage
// failure is reported without judging the document first.
func TestAStorageOutageSpendsNoCapacity_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")
	t.Cleanup(env.Cleanup)

	appDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appDB.Close() })
	// The role is a PRECONDITION of every RLS assertion below, not a detail:
	// the owner pool would count rows the app role can never write.
	approletest.AssertCurrentUser(t, appDB, "axonflow_app_role")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ownerDB.Close() })

	h, done := ledgerBackedHandler(t, appDB, license.TierCommunity)
	defer done()
	// A CONFIGURED database is what makes the degraded posture reachable at
	// all: with h.db nil the route builds an in-process workspace and never
	// refuses. ledgerBackedHandler leaves it nil because its own drive is about
	// the ceiling.
	h.db = appDB

	// Fails ONCE, then delegates. The recovery is what proves the zero below is
	// a property of the refusal rather than of a handler that never worked.
	var calls int
	h.openForSigning = func(ctx context.Context, db *sql.DB, root pdp.Root, orgID, prefix string,
		pub ed25519.PublicKey, by string) (*authoringstore.Store, authoring.TrustSource, string, error) {
		calls++
		if calls == 1 {
			return nil, nil, "", errors.New("simulated outage: connection refused")
		}
		return authoringstore.OpenForSigning(ctx, db, root, orgID, prefix, pub, by)
	}

	// [1] THE OUTAGE REFUSAL, asserted by its reason. A 503 alone would also be
	//     produced by a handler that is simply broken.
	code, body := publishWithRules(t, h, "org-outage", 2)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("publish during a storage outage returned %d, want 503; body=%v", code, body)
	}
	if reason, _ := body["reason"].(string); reason != "storage_unavailable" {
		t.Fatalf("refused for the wrong reason %q; this test needs an OUTAGE refusal to be about anything", reason)
	}

	// [2] AND IT SPENT NOTHING. This is the whole test.
	if got := ledgerRowCount(t, ownerDB, "org-outage"); got != 0 {
		t.Fatalf("a publication refused for OUR storage outage spent %d ledger row(s). principal_admissions is "+
			"append-only with no release, so the caller has paid part of their ceiling for our database being "+
			"unreachable - and pays again on every retry. Since #3973 admission runs inside PublishAdmitting, "+
			"after the document is judged and before the artifact is stored, so reaching this line means either "+
			"the admission hook moved back above ws.api.PublishAdmitting in handlePublish, or the hook is being "+
			"called for a publication that was refused", got)
	}

	// [3] ANTI-VACUITY, and it is the load-bearing half: the SAME handler, the
	//     SAME organization and the SAME publish helper write rows once the
	//     database is back. Without this, a counter that reads zero for
	//     everything - the RLS-blind instrument this file already documents -
	//     passes [2] forever.
	if code, body := publishWithRules(t, h, "org-outage", 2); code != http.StatusOK {
		t.Fatalf("the recovered control was refused: status=%d body=%v", code, body)
	}
	if calls < 2 {
		t.Fatalf("the durable open was attempted %d time(s), so the recovery was not a retry", calls)
	}
	if got := ledgerRowCount(t, ownerDB, "org-outage"); got != 2 {
		t.Fatalf("the recovered control wrote %d rows, want 2; the counter reads zero for everything and the "+
			"assertion above proves nothing", got)
	}
}
