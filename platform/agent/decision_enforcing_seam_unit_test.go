// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE SEAM'S FAIL-CLOSED BRANCHES AND ITS PURE PIECES (#3895 PR-A2).
//
// decision_handler_enforcing_test.go drives the happy path and the headline
// refusals through the real handler. This file covers what that suite does not
// reach: every cause a request can fail closed with, the subject builder, the
// implicit baseline's replacement by digest, the durable document source's
// caching, the obligation rendering, and the constructors' refusals. A
// request-reachable cause is asserted on the RESPONSE; the pure functions are
// asserted directly, because they have no response of their own.

// enfUnloadableDocuments names an active digest and cannot load it.
type enfUnloadableDocuments struct{ *enfDocuments }

func (enfUnloadableDocuments) Load(context.Context, string, string) (*authoring.Artifact, *pdp.TrustStore, error) {
	return nil, nil, errors.New("the artifact row is unreadable")
}

// TestTheSeamFailsClosedNamingEachCause drives every fail-closed cause a
// request can reach through handleDecide and reads the encoded 503.
//
// The causes no request reaches - an unknown stage (refused 400 by the handler
// first), an unestablishable subject and an unbuildable request - are driven
// one level down, in TestTheSeamFailsClosedOnTheCausesNoRequestCanReach, which
// also says why evaluation_failed has no driven test at all.
func TestTheSeamFailsClosedNamingEachCause(t *testing.T) {
	enfSetup(t)
	good := enfPublishDocument(t, enfSnapshot(t))

	cases := []struct {
		name    string
		org     string
		cause   string
		leak    string
		arrange func(t *testing.T)
	}{
		{
			name:    "the organization's active document cannot be read",
			org:     enfOrgBroken,
			cause:   enforceCauseActiveDocument,
			leak:    "unreachable",
			arrange: func(*testing.T) {},
		},
		{
			name:  "no enforcer is wired in this process",
			org:   enfOrgPublished,
			cause: enforceCauseNotWired,
			arrange: func(t *testing.T) {
				prev := anchoredEnforcerInstance.Load()
				anchoredEnforcerInstance.Store(nil)
				t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })
			},
		},
		{
			name:  "the deployment vocabulary cannot be resolved",
			org:   enfOrgPublished,
			cause: enforceCauseActivation,
			leak:  "the catalog is unreadable",
			arrange: func(t *testing.T) {
				enfInstallSeamWith(t, good, func() (*authoringcatalog.Snapshot, error) {
					return nil, errors.New("the catalog is unreadable")
				})
			},
		},
		{
			name:  "the active document cannot be loaded",
			org:   enfOrgPublished,
			cause: enforceCauseActivation,
			leak:  "the artifact row is unreadable",
			arrange: func(t *testing.T) {
				enfInstallSeam(t, enfUnloadableDocuments{good})
			},
		},
		{
			name:  "the organization's recorded detection overrides cannot be read",
			org:   enfOrgPublished,
			cause: enforceCauseOverrides,
			leak:  "the override table is unreadable",
			arrange: func(t *testing.T) {
				installTestOverrideCache(t, &fakeOverrideReader{err: errors.New("the override table is unreadable")}, time.Minute)
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.arrange(t)
			counter := anchoredEnforceDecisions.WithLabelValues(decideSeamScope.String(), decisionEngineAnchored, "unavailable", c.cause)
			before := testutil.ToFloat64(counter)

			r := enfDecide(t, c.org, true, DecisionStageLLM, "What is the weather today?")
			if r.code != http.StatusServiceUnavailable || r.str(t, "verdict") != VerdictDeny {
				t.Fatalf("got HTTP %d verdict %q; want 503 with the fail-closed deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
			}
			if got, want := r.str(t, "error"), enforceCauseMessages[c.cause]; got != want {
				t.Fatalf("the 503 says %q; want the %s cause, %q", got, c.cause, want)
			}
			if c.leak != "" && strings.Contains(string(r.raw), c.leak) {
				t.Fatalf("the 503 leaked the underlying error to the caller: %s", r.raw)
			}
			if after := testutil.ToFloat64(counter); after != before+1 {
				t.Fatalf("the unavailable counter for %s moved %v -> %v; want +1", c.cause, before, after)
			}
		})
	}

	// CONTROL: the failures above were the arrangements, not the setup.
	t.Run("CONTROL: with nothing broken the same request is decided by the anchored engine", func(t *testing.T) {
		r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, "What is the weather today?")
		if r.code != http.StatusOK || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d engine %q; want 200 from the anchored engine. body=%s", r.code, r.str(t, "engine"), r.raw)
		}
	})
}

// enfSeamUnit is an enforcer over docs with the fixture's snapshot, and the
// request pass input alice's verified token produces.
func enfSeamUnit(t *testing.T, docs activeDocumentSource) (func(t *testing.T) *anchoredEnforcer, requestPassInput) {
	t.Helper()
	snap := enfSnapshot(t)
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// The subject arrives exactly as handleDecide hands it over: a production
	// claim-set token, resolved by the agent's own ResolveUser.
	user, authErr := ResolveUser(&AuthResult{Kind: AuthKindEnterprise, OrgID: enfOrgPublished, TenantID: enfOrgPublished, ClientID: enfOrgPublished},
		enfMintUserToken(t, enfOrgPublished, enfUser))
	if authErr != nil {
		t.Fatalf("resolving the minted user token: %v", authErr.Message)
	}
	enforcer := func(t *testing.T) *anchoredEnforcer {
		t.Helper()
		e, err := newAnchoredEnforcer(docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	return enforcer, requestPassInput{
		orgID: enfOrgPublished, decisionID: "decision-seam-unit", stage: DecisionStageLLM,
		query: "What is the weather today?", user: user, userIdentity: userVerified,
		auth:        &AuthResult{Kind: AuthKindEnterprise, OrgID: enfOrgPublished, TenantID: enfOrgPublished, ClientID: "seam-unit-client"},
		observation: enfCleanObservation(t, decideSeamScope),
	}
}

// enfCleanObservation is the detector facts a clean evaluation hands the seam on
// scope: every census detector the scope's restriction and the organization
// template read ran and did not match. A handler gets these from the shared engine; a pass driven directly
// must be handed them, or every detector reaches the engine ABSENT.
func enfCleanObservation(t *testing.T, scope legacycompile.EnforcementScope) *sharedpolicy.Observation {
	t.Helper()
	obs := &sharedpolicy.Observation{}
	seen := map[string]bool{}
	template, err := templateControls(scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range append(enfScopeControls(t, scope), template...) {
		if !seen[c.row.PolicyID] {
			seen[c.row.PolicyID] = true
			obs.Rows = append(obs.Rows, sharedpolicy.DetectorFact{PolicyID: c.row.PolicyID, Ran: true})
		}
	}
	if len(obs.Rows) == 0 {
		t.Fatalf("%s reads no census detector, so this observation would judge nothing", scope)
	}
	return obs
}

// TestTheSeamFailsClosedOnTheCausesNoRequestCanReach drives decideRequestPass
// directly for the causes handleDecide cannot produce. Each is a
// `return unavailable(...)` that a `return out` mutant turns into an unlabelled
// verdict, so each needs an input that reaches it (#3895 PR-A2, round-1
// MEDIUM-2).
//
// evaluation_failed IS NOT HERE, because no seam input reaches it. pdp's
// DecideWith turns every caller-shaped failure into a DECISION rather than an
// error: an invalid request (req.Validate) and a runtime evaluation error both
// return an ERROR decision through Combine. It returns a non-nil error only
// when the engine breaks its own invariants - Combine handed no request, a
// decision Combine built failing its own Validate inside MeetDecisions, or
// chain hops disagreeing on snapshot or request id, which a one-hop request
// cannot. The branch stays as the defensive answer to that, and its `return out`
// mutant survives by construction.
func TestTheSeamFailsClosedOnTheCausesNoRequestCanReach(t *testing.T) {
	enfSetup(t)
	ctx := context.Background()
	enforcer, base := enfSeamUnit(t, enfPublishDocument(t, enfSnapshot(t)))
	start := requestPassEnforcement{engine: decisionEngineAnchored}

	// CONTROL: the unmodified input is decided, so each case below fails for its
	// own mutation and not for the setup.
	if got := enforcer(t).decideRequestPass(ctx, decideSeamScope, base, start); got.unavailable != "" || got.verdict == "" {
		t.Fatalf("CONTROL: decide returned verdict=%q unavailable=%q; the unmodified input must be decided", got.verdict, got.unavailable)
	}

	for _, c := range []struct {
		name   string
		cause  string
		mutate func(in *requestPassInput)
	}{
		{"a stage no registered action carries", enforceCauseRequest,
			func(in *requestPassInput) { in.stage = "not-a-registered-stage" }},
		{"a decision id that cannot name the request resource", enforceCauseRequest,
			func(in *requestPassInput) { in.decisionID = "" }},
		{"no subject the identity plane can establish", enforceCauseSubjectUnverifiable,
			func(in *requestPassInput) { in.userIdentity, in.user, in.auth = userAbsent, nil, nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := base
			c.mutate(&in)
			got := enforcer(t).decideRequestPass(ctx, decideSeamScope, in, start)
			if got.unavailable != c.cause {
				t.Fatalf("unavailable=%q verdict=%q; want the %s cause and no verdict", got.unavailable, got.verdict, c.cause)
			}
			if got.engine != decisionEngineAnchored || got.verdict != "" {
				t.Fatalf("engine=%q verdict=%q; a request must fail closed without authoring a verdict", got.engine, got.verdict)
			}
		})
	}
}

// TestAScopeWithNoSeamFailsClosed: enforceRequestPass is the path for every
// scope in enforcingSeams and no other. A scope no seam is registered for -
// here policy_test, an operator surface no seam delivers for - fails closed rather than being decided
// by an engine nobody declared a delivery for.
func TestAScopeWithNoSeamFailsClosed(t *testing.T) {
	enfSetup(t)
	_, in := enfSeamUnit(t, enfPublishDocument(t, enfSnapshot(t)))
	noSeam := legacycompile.MustScopeFor(legacycompile.PlanePolicyTest, "")
	if _, wired := seamFor(noSeam); wired {
		t.Fatalf("PREMISE: %s has a registered seam; pick a scope that does not", noSeam)
	}
	if got := enforceRequestPass(context.Background(), noSeam, in); got.unavailable != enforceCauseNotWired || got.verdict != "" {
		t.Fatalf("%s: unavailable=%q verdict=%q; want %s and no verdict", noSeam, got.unavailable, got.verdict, enforceCauseNotWired)
	}
	if got := enforceRequestPass(context.Background(), decideSeamScope, in); got.unavailable != "" || got.verdict == "" {
		t.Fatalf("CONTROL: decide, which has a seam, returned unavailable=%q verdict=%q", got.unavailable, got.verdict)
	}
}

// TestAPresentedTokenThatDidNotVerifyIsNeverTheCredentialPrincipal holds PRD v11
// §1.6's line at the seam itself: admission is for the ABSENCE of a user
// identity, never for a bad one.
//
// The organization is one that has published nothing, so its implicit baseline
// WOULD allow the client credential - the CONTROL proves it. A request carrying
// a token that did not verify must not reach that allow: it goes to the user
// door, which refuses it.
func TestAPresentedTokenThatDidNotVerifyIsNeverTheCredentialPrincipal(t *testing.T) {
	enfSetup(t)
	ctx := context.Background()
	enforcer, base := enfSeamUnit(t, enfPublishDocument(t, enfSnapshot(t)))
	base.orgID = enfOrgImplicit
	base.auth = &AuthResult{Kind: AuthKindEnterprise, OrgID: enfOrgImplicit, TenantID: enfOrgImplicit, ClientID: "seam-unit-client"}
	start := requestPassEnforcement{engine: decisionEngineAnchored}

	absent := base
	absent.userIdentity, absent.user = userAbsent, nil
	if got := enforcer(t).decideRequestPass(ctx, decideSeamScope, absent, start); got.verdict != VerdictAllow || got.subjectType != string(sharedidentity.SubjectClient) {
		t.Fatalf("CONTROL: a request with no user identity got verdict=%q reason=%q reasons=%v subject_type=%q unavailable=%q; the implicit baseline admits and allows the credential",
			got.verdict, got.reasonCode, got.reasons, got.subjectType, got.unavailable)
	}

	unverified := base
	unverified.userIdentity, unverified.user = userUnverified, nil
	got := enforcer(t).decideRequestPass(ctx, decideSeamScope, unverified, start)
	if got.verdict == VerdictAllow || got.subjectType == string(sharedidentity.SubjectClient) {
		t.Fatalf("a request carrying a token that did not verify got verdict=%q subject_type=%q; it was admitted as the credential principal in the token's place",
			got.verdict, got.subjectType)
	}
	if got.verdict == "" && got.unavailable == "" {
		t.Fatalf("a request carrying a token that did not verify got no verdict and no cause: %+v", got)
	}
}

// TestCallerUserIdentityNeverCallsAFailedTokenAbsent is the classifier the seam
// reads, on each deployment shape.
func TestCallerUserIdentityNeverCallsAFailedTokenAbsent(t *testing.T) {
	failed := &AuthError{Code: "INVALID_TOKEN", Message: "the token did not verify"}
	for _, c := range []struct {
		mode    string
		kind    AuthKind
		userErr *AuthError
		token   string
		want    userIdentity
	}{
		{"enterprise", AuthKindEnterprise, nil, "a-verified-token", userVerified},
		{"enterprise", AuthKindEnterprise, failed, "a-token-that-failed", userUnverified},
		{"enterprise", AuthKindEnterprise, failed, "", userAbsent},
		{"enterprise", AuthKindInternalService, nil, "", userAbsent},
		// A deployment that verifies no user token: any token is not a user
		// identity at all, so the credential is the principal.
		{"community", AuthKindEnterprise, nil, "an-ignored-token", userAbsent},
		{"community-saas", AuthKindCommunitySaaS, nil, "an-ignored-token", userAbsent},
	} {
		t.Setenv("DEPLOYMENT_MODE", c.mode)
		if got := callerUserIdentity(c.kind, c.userErr, c.token); got != c.want {
			t.Errorf("%s kind=%v err=%v token=%q: got %v, want %v", c.mode, c.kind, c.userErr != nil, c.token, got, c.want)
		}
	}
}

// enfSwitchableDocuments is an active-document source whose tip an operator
// moves: the implicit baseline (""), or one of the published documents, each
// loaded from the store that holds it.
type enfSwitchableDocuments struct {
	tip     string
	sources []*enfDocuments
}

func (d *enfSwitchableDocuments) ActiveTip(context.Context, string) (string, int64, error) {
	return d.tip, 1, nil
}

func (d *enfSwitchableDocuments) Load(ctx context.Context, orgID, digest string) (*authoring.Artifact, *pdp.TrustStore, error) {
	for _, s := range d.sources {
		if art, trust, err := s.Load(ctx, orgID, digest); err == nil {
			return art, trust, nil
		}
	}
	return nil, nil, errors.New("no source holds that digest")
}

// TestTheImplicitBaselineIsReplacedByDigestAndReturns is master's condition 3
// on #3746 (PRD v11 §1.4): publishing replaces the implicit baseline by digest,
// a tip that returns to nothing brings it back, and a rollback to an earlier
// document replaces by digest too. No production route returns a tip to
// nothing (the activation ledger is append-only); the seam's half - a digest
// change is a rebuild - is what is asserted.
func TestTheImplicitBaselineIsReplacedByDigestAndReturns(t *testing.T) {
	enfSetup(t)
	ctx := context.Background()
	snap := enfSnapshot(t)
	noLLM := enfPublishConstraints(t, snap, enfConstraint{"ceiling.no_llm_for_alice", enfUser, []string{authoringcatalog.ActionLLMCompletion}})
	noTool := enfPublishConstraints(t, snap, enfConstraint{"ceiling.no_tool_for_alice", enfUser, []string{authoringcatalog.ActionToolCall}})
	digestOf := func(d *enfDocuments) string {
		tip, _, err := d.ActiveTip(ctx, enfOrgPublished)
		if err != nil || tip == "" {
			t.Fatalf("the fixture document has no tip: %q %v", tip, err)
		}
		return tip
	}
	docs := &enfSwitchableDocuments{sources: []*enfDocuments{noLLM, noTool}}
	enforcer, in := enfSeamUnit(t, docs)
	e := enforcer(t)
	decide := func() requestPassEnforcement {
		t.Helper()
		out := e.decideRequestPass(ctx, decideSeamScope, in, requestPassEnforcement{engine: decisionEngineAnchored})
		if out.unavailable != "" {
			t.Fatalf("the pass failed closed (%s)", out.unavailable)
		}
		return out
	}

	steps := []struct {
		name    string
		tip     string
		verdict string
	}{
		{"nothing published: the implicit baseline allows", "", VerdictAllow},
		{"a document constraining alice's llm.completion replaces the baseline and denies", digestOf(noLLM), VerdictDeny},
		{"a document constraining only tool.call is promoted: llm.completion is allowed again", digestOf(noTool), VerdictAllow},
		{"rolled back to the llm constraint: denied again, by that digest", digestOf(noLLM), VerdictDeny},
		{"the tip returns to nothing: the implicit baseline returns", "", VerdictAllow},
	}
	bundles := make([]string, len(steps))
	for i, s := range steps {
		docs.tip = s.tip
		got := decide()
		if got.verdict != s.verdict {
			t.Fatalf("%s: verdict %q (reason %q, reasons %v); want %q", s.name, got.verdict, got.reasonCode, got.reasons, s.verdict)
		}
		bundles[i] = got.policyBundle
	}
	if bundles[0] == bundles[1] || bundles[1] == bundles[2] {
		t.Fatalf("the policy bundle did not move with the document: %v", bundles)
	}
	if bundles[3] != bundles[1] {
		t.Fatalf("the rollback decided under %s; the llm constraint's bundle is %s - a rollback replaces by digest", bundles[3], bundles[1])
	}
	if bundles[4] != bundles[0] {
		t.Fatalf("the returned baseline decided under %s; the implicit baseline's bundle is %s", bundles[4], bundles[0])
	}
}

// TestEveryEnforcingSeamPermitsEveryRegisteredActionUnderTheImplicitBaseline is
// master's condition 2 on #3746, measured: the implicit baseline is the
// deployment's baseline permission pack, so on every enforcing scope every
// registered action is permitted to an organization that has published
// nothing. A registered action the pack missed would be the outage of an
// explicit pack in a different coat. The subject is the client credential, the
// population with the least identity, and the content is empty so every
// detector the scope's policies read is a determined false.
func TestEveryEnforcingSeamPermitsEveryRegisteredActionUnderTheImplicitBaseline(t *testing.T) {
	enfSetup(t)
	ctx := context.Background()
	enforcer, _ := enfSeamUnit(t, enfPublishDocument(t, enfSnapshot(t)))
	e := enforcer(t)
	auth := &AuthResult{Kind: AuthKindEnterprise, OrgID: enfOrgImplicit, TenantID: enfOrgImplicit, ClientID: "seam-unit-client"}
	actions := authoringcatalog.DeploymentActions()
	if len(actions) == 0 {
		t.Fatal("the deployment registers no action, so nothing below is measured")
	}
	var matrix []string
	for _, seam := range enforcingSeams {
		for _, action := range actions {
			v := e.evaluate(ctx, anchoredCall{
				scope: seam.scope, orgID: enfOrgImplicit, requestID: "implicit-" + action, action: action,
				subject: requestSubject(enfOrgImplicit, auth, nil, userAbsent), query: "", emptyContent: true,
			})
			switch {
			case v.unavailable != "":
				t.Errorf("%s / %s: failed closed (%s)", seam.scope, action, v.unavailable)
			case v.refusal != nil:
				t.Errorf("%s / %s: the credential was refused %s", seam.scope, action, v.refusal.Reason)
			case v.decision.State != contract.StateAllow || v.subjectType != string(sharedidentity.SubjectClient):
				t.Errorf("%s / %s: state %s reason %s subject %q; want ALLOW for a Client under the implicit baseline",
					seam.scope, action, v.decision.State, v.decision.Reason, v.subjectType)
			case !v.act.ImplicitBaseline:
				t.Errorf("%s / %s: decided under an activation that is not the implicit baseline", seam.scope, action)
			}
			matrix = append(matrix, seam.scope.String()+"/"+action)
		}
	}
	sort.Strings(matrix)
	t.Logf("allowed under the implicit baseline, per scope and registered action (%d): %s", len(matrix), strings.Join(matrix, " "))
}

// TestTheDurableActiveDocumentSourceFailsClosedAndDoesNotCacheTheFailure
// proves both halves of storeFor's contract against the SQL it issues: a
// failed open is retried by the next request, and a successful open is not
// repeated. Each request's statements are expected in order, so a cached
// failure (no second key query) and an uncached success (a second key query
// where only the tip query belongs) both break the sequence.
func TestTheDurableActiveDocumentSourceFailsClosedAndDoesNotCacheTheFailure(t *testing.T) {
	const org = "org-durable"
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	errUnreachable := errors.New("the database is unreachable")
	setOrg := regexp.QuoteMeta("SELECT set_config('app.current_org_id', $1, true)")
	keys := regexp.QuoteMeta("SELECT key_id, public_key FROM typed_policy_signing_keys")
	tip := regexp.QuoteMeta("SELECT kind, digest, seq FROM typed_policy_activations")
	root := string(pdp.RootOrganization)

	// Requests 1 and 2: the open fails at the key read, twice.
	for i := 0; i < 2; i++ {
		mock.ExpectBegin()
		mock.ExpectExec(setOrg).WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(keys).WithArgs(org, root).WillReturnError(errUnreachable)
		mock.ExpectRollback()
	}
	// Request 3: the open succeeds, then the tip is read.
	mock.ExpectBegin()
	mock.ExpectExec(setOrg).WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(keys).WithArgs(org, root).WillReturnRows(sqlmock.NewRows([]string{"key_id", "public_key"}))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(setOrg).WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(tip).WithArgs(org, root).WillReturnRows(sqlmock.NewRows([]string{"kind", "digest", "seq"}).AddRow("promote", "sha256:tip", int64(3)))
	mock.ExpectCommit()
	// Request 4: the store is reused, so only the tip is read.
	mock.ExpectBegin()
	mock.ExpectExec(setOrg).WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(tip).WithArgs(org, root).WillReturnRows(sqlmock.NewRows([]string{"kind", "digest", "seq"}).AddRow("promote", "sha256:tip", int64(3)))
	mock.ExpectCommit()

	ctx := context.Background()
	docs := newDurableActiveDocuments(db)
	if _, _, err := docs.ActiveTip(ctx, org); !errors.Is(err, errUnreachable) {
		t.Fatalf("request 1: ActiveTip returned %v; want the unreachable database, so the seam fails closed", err)
	}
	if _, _, err := docs.Load(ctx, org, "sha256:tip"); !errors.Is(err, errUnreachable) {
		t.Fatalf("request 2: Load returned %v; want the unreachable database again, which means the first failure was not cached", err)
	}
	for i := 3; i <= 4; i++ {
		digest, seq, err := docs.ActiveTip(ctx, org)
		if err != nil || digest != "sha256:tip" || seq != 3 {
			t.Fatalf("request %d: ActiveTip returned (%q, %d, %v); want (sha256:tip, 3, nil)", i, digest, seq, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the statements issued are not one key read per failed request and one per organization after a success: %v", err)
	}
}

func TestTheDeploymentVocabularyIsMemoizedOnlyOnSuccess(t *testing.T) {
	snap := enfSnapshot(t)
	answers := []func() (*authoringcatalog.Snapshot, error){
		func() (*authoringcatalog.Snapshot, error) { return nil, errors.New("the catalog is not yet readable") },
		func() (*authoringcatalog.Snapshot, error) { return nil, nil },
		func() (*authoringcatalog.Snapshot, error) { return snap, nil },
	}
	calls := 0
	vocabulary := memoizedDeploymentVocabulary(func() (*authoringcatalog.Snapshot, error) {
		i := calls
		calls++
		if i >= len(answers) {
			t.Fatalf("the resolver was called %d times; a successful resolution must be memoized", calls)
		}
		return answers[i]()
	})

	if _, err := vocabulary(); err == nil || !strings.Contains(err.Error(), "not yet readable") {
		t.Fatalf("first resolution returned %v; want the resolver's error", err)
	}
	if _, err := vocabulary(); err == nil || !strings.Contains(err.Error(), "resolved to nothing") {
		t.Fatalf("second resolution returned %v; a transient failure must not be memoized, and a nil snapshot is an error", err)
	}
	for i := 0; i < 2; i++ {
		got, err := vocabulary()
		if err != nil || got != snap {
			t.Fatalf("resolution %d returned (%p, %v); want the resolved snapshot %p", i+3, got, err, snap)
		}
	}
	if calls != 3 {
		t.Fatalf("the resolver was called %d times; want 3 - two failures retried, one success memoized", calls)
	}
}

func TestWireObligationsCarryRedactionAndRefuseWhatTheWireCannotExpress(t *testing.T) {
	out, refusal := wireObligationsFor([]contract.Obligation{
		{Type: contract.ObImmutableAudit, Mandatory: true, SchemaVersion: 1, SourcePolicy: "corpus:audit"},
		{Type: contract.ObFieldRedact, Target: "response.ssn", Mandatory: true, SchemaVersion: 1, SourcePolicy: "org:pii"},
		{Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true, SchemaVersion: 1, SourcePolicy: "corpus:pii"},
		{Type: contract.ObNotification, Mandatory: false, SchemaVersion: 1, SourcePolicy: "corpus:notify"},
	}, decideSeamScope)
	if refusal != "" {
		t.Fatalf("refused %q; every obligation above is either expressible, discharged by the audit row, or advisory", refusal)
	}
	if len(out) != 2 {
		t.Fatalf("got %d obligations %+v; want the two redactions - immutable_audit is discharged by the audit row and an advisory notification is dropped", len(out), out)
	}
	response, request := out[0], out[1]
	if response.Type != ObligationRedactPII || response.Fulfillment == nil ||
		response.Fulfillment.Phase != ObligationPhaseResponse ||
		response.Fulfillment.Endpoint != responseRedactionEndpoint ||
		response.Fulfillment.Method != http.MethodPost {
		t.Fatalf("a response.* redaction rendered as %+v (fulfillment %+v); want redact_pii fulfilled at the response gate", response, response.Fulfillment)
	}
	if !strings.Contains(response.Detail, "response.ssn") || !strings.Contains(response.Detail, "org:pii") {
		t.Fatalf("the detail %q names neither the target nor the policy that required it", response.Detail)
	}
	// THE EVALUATED CONTENT ON DECIDE IS THE REQUEST (#4046): decide evaluates
	// the request, so its redaction is the request-phase obligation the legacy
	// engine emits - not a fan-out to the response gate.
	if want := newRedactPIIObligation(request.Detail); !reflect.DeepEqual(request, want) {
		t.Fatalf("decide's redaction of the evaluated content rendered as %+v; want the request-phase obligation every other emission site builds, %+v", request, want)
	}

	// The same obligation on a RESPONSE-phase scope is fulfilled on the
	// response: the scope, not the target, says which content was evaluated.
	onResponse, refusal := wireObligationsFor([]contract.Obligation{
		{Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true, SchemaVersion: 1, SourcePolicy: "corpus:pii"},
	}, mcpResponseSeamScope)
	if refusal != "" || len(onResponse) != 1 || onResponse[0].Fulfillment == nil || onResponse[0].Fulfillment.Phase != ObligationPhaseResponse {
		t.Fatalf("the evaluated content on %s rendered as %+v (refusal %q); want one redact_pii fulfilled on the response", mcpResponseSeamScope, onResponse, refusal)
	}

	none, refusal := wireObligationsFor([]contract.Obligation{
		{Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true, SchemaVersion: 1, SourcePolicy: "corpus:pii"},
		{Type: contract.ObNotification, Mandatory: true, SchemaVersion: 1, SourcePolicy: "grant.page-oncall"},
	}, decideSeamScope)
	if none != nil {
		t.Fatalf("returned obligations %+v alongside a refusal; an enforcement point told to allow must not also be handed a partial set", none)
	}
	for _, want := range []string{string(contract.ReasonUnsupportedObligation) + ": ", string(contract.ObNotification), "grant.page-oncall"} {
		if !strings.Contains(refusal, want) {
			t.Fatalf("the refusal %q does not name %q", refusal, want)
		}
	}

	// EXACT VERSION: redact_pii stands for field_redact@1, so a mandatory
	// field_redact@2 is not something the wire can tell a caller to discharge.
	if _, refusal := wireObligationsFor([]contract.Obligation{
		{Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true, SchemaVersion: 2, SourcePolicy: "corpus:pii-v2"},
	}, decideSeamScope); !strings.Contains(refusal, "corpus:pii-v2") {
		t.Fatalf("a mandatory field_redact@2 rendered as redact_pii (refusal %q); the wire name stands for version 1 only", refusal)
	}
}

func TestAnAnchoredChallengeOrAnUnexpressibleObligationIsNeverAnAllow(t *testing.T) {
	act := &activation.Activation{PolicyBundle: "sha256:bundle-under-test", Scope: decideSeamScope}
	base := requestPassEnforcement{engine: decisionEngineAnchored}
	redact := contract.Obligation{Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true, SchemaVersion: 1, SourcePolicy: "corpus:pii"}

	// Every wired scope, the MCP request pass included, reaches this mapping
	// through its seam, and each refusal names its own plane.
	for _, scope := range wiredSeamScopes {
		scopeAct := &activation.Activation{PolicyBundle: act.PolicyBundle, Scope: scope}
		t.Run("CHALLENGE on "+scope.String()+" is a deny that names the plane it cannot be held on", func(t *testing.T) {
			got := mapAnchoredDecision(base, &contract.Decision{State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired}, scopeAct)
			if got.verdict != VerdictDeny || got.reasonCode != string(contract.ReasonApprovalRequired) {
				t.Fatalf("verdict %q reason %q; want deny approval_required", got.verdict, got.reasonCode)
			}
			if len(got.reasons) != 1 || !strings.HasPrefix(got.reasons[0], "approval_required: ") ||
				!strings.Contains(got.reasons[0], "the "+scope.String()+" plane has no approval hold") ||
				!strings.Contains(got.reasons[0], "PRD v11 §1.13") {
				t.Fatalf("reasons %v; want one naming the %s plane as having no approval hold (PRD v11 §1.13)", got.reasons, scope)
			}
			if got.policyBundle != scopeAct.PolicyBundle {
				t.Fatalf("policy bundle %q; want %q on every anchored decision", got.policyBundle, scopeAct.PolicyBundle)
			}
		})
	}

	t.Run("an ALLOW carrying a mandatory obligation the wire cannot express is a deny", func(t *testing.T) {
		got := mapAnchoredDecision(base, &contract.Decision{
			State: contract.StateAllow, Reason: contract.ReasonPermitted,
			Obligations: []contract.Obligation{redact, {Type: contract.ObNotification, Mandatory: true, SourcePolicy: "grant.page-oncall"}},
			Determining: contract.Determining{MatchedPermissions: []string{"grant.x"}},
		}, act)
		if got.verdict != VerdictDeny || got.reasonCode != string(contract.ReasonUnsupportedObligation) || len(got.obligations) != 0 {
			t.Fatalf("verdict %q reason %q obligations %+v; want deny unsupported_obligation with no obligations", got.verdict, got.reasonCode, got.obligations)
		}
	})

	t.Run("an ALLOW with an expressible obligation carries it and an empty reason list", func(t *testing.T) {
		got := mapAnchoredDecision(base, &contract.Decision{
			State: contract.StateAllow, Reason: contract.ReasonPermitted,
			Obligations: []contract.Obligation{redact},
			Determining: contract.Determining{MatchedPermissions: []string{"grant.x"}},
		}, act)
		if got.verdict != VerdictAllow || got.reasonCode != string(contract.ReasonPermitted) || len(got.obligations) != 1 {
			t.Fatalf("verdict %q reason %q obligations %+v; want allow permitted with the redaction", got.verdict, got.reasonCode, got.obligations)
		}
		if got.reasons == nil || len(got.reasons) != 0 {
			t.Fatalf("reasons %#v; want an empty, non-nil list so the body carries [] and never null", got.reasons)
		}
		if !reflect.DeepEqual(got.evaluatedPolicies, []string{"grant.x"}) {
			t.Fatalf("evaluated_policies %v; want the permission that matched", got.evaluatedPolicies)
		}
	})

	t.Run("a DENY names its blocking constraint, and a shipped one or an override's replacement of one is tiered system", func(t *testing.T) {
		for id, tier := range map[string]string{
			legacycompile.CorpusPolicyIDFor("static_policies", "sys_under_test"):                                     "system",
			activation.OverridePolicyIDPrefix + legacycompile.CorpusPolicyIDFor("static_policies", "sys_under_test"): "system",
			"ceiling.org-authored": "organization",
		} {
			got := mapAnchoredDecision(base, &contract.Decision{
				State: contract.StateDeny, Reason: contract.ReasonExplicitConstraint,
				Determining: contract.Determining{MatchedConstraints: []string{id}},
			}, act)
			if got.verdict != VerdictDeny || got.blockingPolicyID != id || got.blockingPolicyTier != tier {
				t.Fatalf("%s: verdict %q blocking %q tier %q; want deny blocking %q tier %q", id, got.verdict, got.blockingPolicyID, got.blockingPolicyTier, id, tier)
			}
			if !reflect.DeepEqual(got.reasons, []string{string(contract.ReasonExplicitConstraint)}) {
				t.Fatalf("%s: reasons %v; want [explicit_constraint]", id, got.reasons)
			}
		}
	})

	t.Run("an ERROR is a deny under its own reason, with nothing named as blocking", func(t *testing.T) {
		got := mapAnchoredDecision(base, &contract.Decision{State: contract.StateError, Reason: contract.ReasonUnknownConstraint}, act)
		if got.verdict != VerdictDeny || !reflect.DeepEqual(got.reasons, []string{string(contract.ReasonUnknownConstraint)}) || got.blockingPolicyID != "" {
			t.Fatalf("verdict %q reasons %v blocking %q; want deny [unknown_constraint] with no blocking policy", got.verdict, got.reasons, got.blockingPolicyID)
		}
	})

	t.Run("an UNKNOWN_CONSTRAINT refusal names each constraint it could not evaluate, the binding one first, and why (#4227)", func(t *testing.T) {
		got := mapAnchoredDecision(base, &contract.Decision{
			State: contract.StateError, Reason: contract.ReasonUnknownConstraint,
			Determining: contract.Determining{
				MatchedPermissions: []string{"grant.x"},
				Unknown: []contract.UnknownPolicy{
					{PolicyID: "ceiling.by-department", Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied, Paths: []string{"principal.department", "resource.owner"}},
					{PolicyID: "require.audit", Authority: contract.AuthorityRequirement, Reason: contract.ReasonStale, Paths: []string{"resource.epoch"}},
					{PolicyID: "ceiling.stale", Authority: contract.AuthorityConstraint, Reason: contract.ReasonStale},
				},
			},
		}, act)
		want := []string{
			string(contract.ReasonUnknownConstraint),
			"ceiling.by-department could not be evaluated: no value was supplied for principal.department, resource.owner",
			"ceiling.stale could not be evaluated: an attribute it reads could not be read within the freshness bound",
		}
		if got.verdict != VerdictDeny || !reflect.DeepEqual(got.reasons, want) {
			t.Fatalf("verdict %q reasons %q; want deny %q: the bare code first, then each constraint, never the requirement", got.verdict, got.reasons, want)
		}
		if evaluated := []string{"ceiling.by-department", "ceiling.stale", "grant.x"}; !reflect.DeepEqual(got.evaluatedPolicies, evaluated) {
			t.Fatalf("evaluated_policies %v; want %v, the binding constraint first", got.evaluatedPolicies, evaluated)
		}
		if got.blockingPolicyID != "ceiling.by-department" || got.blockingPolicyTier != "organization" {
			t.Fatalf("blocking %q tier %q; want the binding constraint, tiered organization", got.blockingPolicyID, got.blockingPolicyTier)
		}
		if len(got.policyIdentities) != len(got.evaluatedPolicies) || got.policyIdentities[0].ID != "ceiling.by-department" {
			t.Fatalf("policy identities %+v; want one per evaluated policy, in its order", got.policyIdentities)
		}
	})

	t.Run("the binding constraint is the one the combining rule names in the trace, wherever it is listed (#4227)", func(t *testing.T) {
		got := mapAnchoredDecision(base, &contract.Decision{
			State: contract.StateError, Reason: contract.ReasonUnknownConstraint,
			Determining: contract.Determining{Unknown: []contract.UnknownPolicy{
				{PolicyID: "ceiling.a", Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied},
				{PolicyID: "ceiling.b", Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied},
			}},
			Trace: &contract.Trace{BindingPolicy: "ceiling.b"},
		}, act)
		if !reflect.DeepEqual(got.evaluatedPolicies, []string{"ceiling.b", "ceiling.a"}) || got.blockingPolicyID != "ceiling.b" ||
			len(got.reasons) != 3 || !strings.HasPrefix(got.reasons[1], "ceiling.b could not be evaluated: ") {
			t.Fatalf("evaluated %v blocking %q reasons %q; want the trace's binding ceiling.b first everywhere", got.evaluatedPolicies, got.blockingPolicyID, got.reasons)
		}
	})

	t.Run("a DETERMINATE refusal names what decided it, not a constraint it also could not evaluate", func(t *testing.T) {
		got := mapAnchoredDecision(base, &contract.Decision{
			State: contract.StateDeny, Reason: contract.ReasonExplicitConstraint,
			Determining: contract.Determining{
				MatchedConstraints: []string{"ceiling.matched"},
				Unknown:            []contract.UnknownPolicy{{PolicyID: "ceiling.unknown", Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied}},
			},
		}, act)
		if !reflect.DeepEqual(got.reasons, []string{string(contract.ReasonExplicitConstraint)}) ||
			!reflect.DeepEqual(got.evaluatedPolicies, []string{"ceiling.matched"}) || got.blockingPolicyID != "ceiling.matched" {
			t.Fatalf("reasons %v evaluated %v blocking %q; want only the matched constraint", got.reasons, got.evaluatedPolicies, got.blockingPolicyID)
		}
	})

	t.Run("a deny with no blocking constraint is keyed on the first policy it names, at the same bounded tier (#4227)", func(t *testing.T) {
		for first, tier := range map[string]string{
			"grant.org-authored":             "organization",
			"baseline.permit.llm.completion": "organization",
			legacycompile.CorpusPolicyIDFor("static_policies", "sys_under_test"): "system",
		} {
			got := mapAnchoredDecision(base, &contract.Decision{
				State: contract.StateError, Reason: contract.ReasonUnknownRequirement,
				Determining: contract.Determining{MatchedPermissions: []string{first}},
			}, act)
			if got.verdict != VerdictDeny || got.blockingPolicyID != "" || got.blockingPolicyTier != tier {
				t.Fatalf("%s: verdict %q blocking %q tier %q; want a deny naming no blocking policy, keyed at tier %q", first, got.verdict, got.blockingPolicyID, got.blockingPolicyTier, tier)
			}
		}
	})
}

// TestTheEnforcerIsNotInstalledWithoutADatabaseOrAnIdentityPlane: each missing
// dependency is refused by name, because wireEnforcingSeams turns the refusal
// into a refusal to boot and the operator reads the message.
func TestTheEnforcerIsNotInstalledWithoutADatabaseOrAnIdentityPlane(t *testing.T) {
	prev := anchoredEnforcerInstance.Load()
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })

	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"no database", nil, "no database"},
		{"no identity bootstrap", nil, "identity plane is not bootstrapped"},
		{"an identity bootstrap with no adapter", nil, "identity plane is not bootstrapped"},
	} {
		anchoredEnforcerInstance.Store(nil)
		switch c.name {
		case "no database":
			c.err = installAnchoredEnforcer(nil, boot)
		case "no identity bootstrap":
			c.err = installAnchoredEnforcer(db, nil)
		default:
			c.err = installAnchoredEnforcer(db, &sharedidentity.AdmissionBootstrap{Registry: boot.Registry})
		}
		if c.err == nil || !strings.Contains(c.err.Error(), c.want) {
			t.Errorf("%s: got %v; want a refusal saying %q", c.name, c.err, c.want)
		}
		if anchoredEnforcerInstance.Load() != nil {
			t.Errorf("%s: an enforcer was installed with nothing to read documents from or admit subjects with", c.name)
		}
	}

	// CONTROL: the refusals above are about the missing piece, not the call.
	anchoredEnforcerInstance.Store(nil)
	if err := installAnchoredEnforcer(db, boot); err != nil || anchoredEnforcerInstance.Load() == nil {
		t.Fatalf("with a database and an identity plane the installer returned %v, so the refusals above prove nothing", err)
	}
}

func TestNewDecideEnforcerRefusesAMissingDependency(t *testing.T) {
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	docs := &enfDocuments{}
	vocabulary := func() (*authoringcatalog.Snapshot, error) { return nil, errors.New("unused") }

	for name, build := range map[string]func() (*anchoredEnforcer, error){
		"no active-document source": func() (*anchoredEnforcer, error) {
			return newAnchoredEnforcer(nil, vocabulary, boot.Admitter, boot.Registry.Epoch)
		},
		"no vocabulary": func() (*anchoredEnforcer, error) {
			return newAnchoredEnforcer(docs, nil, boot.Admitter, boot.Registry.Epoch)
		},
		"no identity adapter": func() (*anchoredEnforcer, error) {
			return newAnchoredEnforcer(docs, vocabulary, nil, boot.Registry.Epoch)
		},
		"no realm epoch": func() (*anchoredEnforcer, error) {
			return newAnchoredEnforcer(docs, vocabulary, boot.Admitter, nil)
		},
	} {
		if e, err := build(); err == nil || e != nil {
			t.Errorf("%s: got enforcer %v and error %v; want a refusal and no enforcer", name, e, err)
		}
	}
	if e, err := newAnchoredEnforcer(docs, vocabulary, boot.Admitter, boot.Registry.Epoch); err != nil || e == nil {
		t.Fatalf("CONTROL: with every dependency present got (%v, %v); the refusals above prove nothing", e, err)
	}
}

// TestEachRequestPassBuildsTheEngineForItsOwnScope reads the ACTIVATION the
// enforcer built, not the verdict it produced.
//
// NO VERDICT CAN CATCH THIS TODAY, and that is the point. The restrictions of
// decide, gateway_request, proxy_request and openai_compatible bind the same
// shipped controls - measured - so a pass that built its engine for decide's
// scope would answer identically, and the plane label on the counter comes from
// the handler rather than from the call. What differs is the engine the request
// is evaluated against, which is this assertion's subject: the activation is
// cached per (scope, organization), and its Scope is the scope it was built
// for.
func TestEachRequestPassBuildsTheEngineForItsOwnScope(t *testing.T) {
	enfSetup(t)
	ctx := context.Background()
	enforcer, in := enfSeamUnit(t, enfPublishDocument(t, enfSnapshot(t)))
	for _, scope := range []legacycompile.EnforcementScope{decideSeamScope, gatewayRequestSeamScope, proxyRequestSeamScope, openaiCompatibleSeamScope} {
		t.Run(scope.String(), func(t *testing.T) {
			e := enforcer(t)
			out := e.decideRequestPass(ctx, scope, in, requestPassEnforcement{engine: decisionEngineAnchored})
			if out.unavailable != "" || out.verdict == "" {
				t.Fatalf("CONTROL: the pass was not decided (unavailable=%q verdict=%q), so the activation below would be nothing's", out.unavailable, out.verdict)
			}
			cached := e.CachedActivations()
			if len(cached) != 1 {
				t.Fatalf("the enforcer cached %d activations for one request; want exactly the one this scope needs", len(cached))
			}
			for _, c := range cached {
				if c.Scope != scope {
					t.Errorf("the request on %s built its engine under the cache key %s; a pass must activate ITS OWN scope", scope, c.Scope)
				}
				if c.Activation.Scope != scope {
					t.Errorf("the request on %s was evaluated against an engine activated for %s", scope, c.Activation.Scope)
				}
			}
		})
	}
}

// TestEachRequestWireDeclaresWhatItsProjectionCarries derives each seam's
// declared delivery from the WIRE'S OWN BEHAVIOUR rather than from the seam
// list it is checked against.
//
// A test that reads enforcingSeams for both the expectation and the value
// cannot see a declaration go missing: the two sides move together, which is
// exactly how a dropped delivery survived a mutant. So the expectation here is
// computed by asking the projection what the wire carries - the pre-check turns
// a request-phase redact_pii into requires_redaction, /api/request and the
// OpenAI-compatible route refuse it - and the seam list must agree with that
// answer.
func TestEachRequestWireDeclaresWhatItsProjectionCarries(t *testing.T) {
	redaction := requestPassEnforcement{
		engine: decisionEngineAnchored, verdict: VerdictAllow, reasonCode: "permitted",
		obligations: []DecisionObligation{redactObligationFor(
			contract.Obligation{Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true, SchemaVersion: 1, SourcePolicy: "corpus:pii"},
			gatewayRequestSeamScope)},
	}
	redactPII := contract.Capability{Type: contract.ObFieldRedact, Version: 1}

	// THE EXPECTATION IS STATED HERE, not read from the seam list.
	for _, w := range []struct {
		scope legacycompile.EnforcementScope
		tells bool
	}{
		{gatewayRequestSeamScope, true},
		{proxyRequestSeamScope, false},
		{openaiCompatibleSeamScope, false},
	} {
		t.Run(w.scope.String(), func(t *testing.T) {
			result, _ := redaction.staticPolicyResult(w.scope)
			carries := result.RequiresRedaction && !result.Blocked
			if carries != w.tells {
				t.Errorf("%s %s a request redaction to its caller; its wire %s one. A wire that cannot tell a redaction must REFUSE the request, "+
					"and one that can must instruct it.", w.scope,
					map[bool]string{true: "CARRIES", false: "does not carry"}[carries],
					map[bool]string{true: "carries", false: "does not carry"}[w.tells])
			}
			declared := false
			for _, c := range seamDelivers(w.scope) {
				if c == redactPII {
					declared = true
				}
			}
			if declared != w.tells {
				t.Errorf("%s's seam entry %s %v. A wire that carries an obligation must DECLARE it, or activation will refuse the scope the day a "+
					"shipped control binds one; a wire that cannot must declare nothing, or activation will admit a control it cannot discharge.",
					w.scope, map[bool]string{true: "declares", false: "does not declare"}[declared], redactPII)
			}
		})
	}
}
