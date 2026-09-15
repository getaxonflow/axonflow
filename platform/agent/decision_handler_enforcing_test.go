// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/ed25519"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
	"slices"
)

// THE DECIDE PLANE'S ENFORCING SEAM, THROUGH THE REAL HANDLER (#3895 PR-A2;
// PRD v11 §1).
//
// Every assertion reads the ENCODED RESPONSE (or the audit row the handler
// wrote), never the seam's producing functions, because a producer can be right
// while the handler assembles something else. The pieces are the production
// ones: the identity plane's adapter admits the subject, activation.Activate
// builds the anchored engine from the shipped corpus restriction and either a
// document published and promoted through the real authoring API or the
// implicit baseline, and the shared engine runs the real decide call site over
// the census's system rows. Only storage is in memory.

const (
	// enfOrgPublished has published and activated a document of its own.
	enfOrgPublished = "org-published"
	// enfOrgImplicit has published nothing, so the implicit baseline decides
	// (PRD v11 §1.4).
	enfOrgImplicit = "org-implicit"
	// enfOrgBroken's typed-authoring tables cannot be read.
	enfOrgBroken = "org-broken"
	enfUser      = "alice@corp.example"
)

// enfDocuments serves ONE active document for every organization except the
// ones named: an organization that has published nothing, and one whose tables
// cannot be read.
type enfDocuments struct {
	api              *authoring.API
	orgKeyID         string
	orgPub           ed25519.PublicKey
	nothingPublished map[string]bool
	broken           map[string]bool
}

func (d *enfDocuments) ActiveTip(ctx context.Context, orgID string) (string, int64, error) {
	if d.broken[orgID] {
		return "", 0, errors.New("the typed-authoring tables are unreachable")
	}
	if d.nothingPublished[orgID] {
		return "", 0, nil
	}
	art, ok, err := d.api.Store().Active(ctx, pdp.RootOrganization)
	if err != nil || !ok {
		return "", 0, err
	}
	history, err := d.api.Store().History(ctx, pdp.RootOrganization)
	return art.Digest(), int64(len(history)), err
}

func (d *enfDocuments) Load(ctx context.Context, _ string, digest string) (*authoring.Artifact, *pdp.TrustStore, error) {
	art, ok, err := d.api.Store().Get(ctx, pdp.RootOrganization, digest)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, errors.New("no artifact under that digest")
	}
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, d.orgKeyID, d.orgPub)
	return art, trust, nil
}

// enfSnapshot resolves the deployment vocabulary for an Enterprise-mode build.
func enfSnapshot(t *testing.T) *authoringcatalog.Snapshot {
	t.Helper()
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil || snap == nil {
		t.Fatalf("resolving the deployment vocabulary: %v", err)
	}
	return snap
}

// enfBob is a principal of the organization the fixture document constrains.
const enfBob = "bob@corp.example"

// enfConstraint is one principal-scoped constraint a fixture document carries:
// policyID denies the named actions to the minted-realm principal of user.
type enfConstraint struct {
	policyID string
	user     string
	actions  []string
}

// enfPublishDocument publishes and promotes the organization's document: two
// PRINCIPAL-SCOPED CONSTRAINTS, ceiling.block_bob on every registered action
// and ceiling.no_tool_for_alice on tool.call.
//
// CONSTRAINTS, because the deployment's baseline pack permits every registered
// action beside any document (PRD v11 §1.4): a document narrows it only by
// denying. PRINCIPAL-SCOPED, so the subject the identity plane admits is load
// bearing: bob is denied and alice is not, a seam that built the principal in
// any other realm - or from anything but the token's mapped subject - would
// answer them alike, and a client credential, which is neither, is denied by
// neither.
func enfPublishDocument(t *testing.T, snap *authoringcatalog.Snapshot) *enfDocuments {
	t.Helper()
	return enfPublishConstraints(t, snap,
		enfConstraint{"ceiling.block_bob", enfBob, authoringcatalog.DeploymentActions()},
		enfConstraint{"ceiling.no_tool_for_alice", enfUser, []string{authoringcatalog.ActionToolCall}},
	)
}

// enfMintedPrincipal is the minted-realm principal the identity plane admits
// for email.
func enfMintedPrincipal(email string) string {
	return "User::" + string(sharedidentity.BuiltinRealmMinted) + ":" + email
}

// enfConstraintName is the display name the fixture's document gives the
// constraint id: its own, and never the identifier (PRD v11 §1.14).
func enfConstraintName(policyID string) string { return "Constraint " + policyID + ", by name" }

// enfPublishConstraints publishes and promotes a document carrying the given
// constraints, each named (enfConstraintName) and proven by a publish fixture
// in which it matches.
func enfPublishConstraints(t *testing.T, snap *authoringcatalog.Snapshot, constraints ...enfConstraint) *enfDocuments {
	t.Helper()
	now := time.Now().UTC()
	doc := pdp.Document{
		Root: pdp.RootOrganization, Version: 1,
		Attributes: []pdp.AttributeSchema{{Path: "principal.id", Type: pdp.TypeString}},
	}
	var fixtures []authoring.Fixture
	for _, c := range constraints {
		actions := make([]contract.ID, 0, len(c.actions))
		exercised := ""
		for _, a := range c.actions {
			actions = append(actions, contract.MustParseID(contract.KindAction, "Action::"+a))
			if exercised == "" && authzenActionStage[a] != "" {
				exercised = a
			}
		}
		if exercised == "" {
			t.Fatalf("%s names no action with a Decision API stage, so no publish fixture can exercise it", c.policyID)
		}
		principal := enfMintedPrincipal(c.user)
		doc.Policies = append(doc.Policies, pdp.Policy{
			ID: c.policyID, Name: enfConstraintName(c.policyID), Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
			Scope:   pdp.Scope{Principals: []contract.ID{contract.MustParseID(contract.KindPrincipal, principal)}},
			Actions: pdp.ActionSelector{Actions: actions},
			Where:   pdp.True(),
		})
		fixtures = append(fixtures, authoring.Fixture{
			Name: c.user + " is denied " + exercised,
			Attributes: contract.AttributeSet{
				"action.id":    contract.Known("Action::"+exercised, contract.ProvPlatform, 1, now),
				"action.tags":  contract.Known([]any{"stage:" + authzenActionStage[exercised]}, contract.ProvPlatform, 1, now),
				"args.query":   contract.Known("hello", contract.ProvCaller, 1, now),
				"principal.id": contract.Known(principal, contract.ProvAuthentication, 1, now),
			},
			Expect: map[string]pdp.Verdict{c.policyID: pdp.VerdictMatch},
		})
	}
	return enfPublishPolicyDocument(t, snap, doc, fixtures)
}

// enfPublishPolicyDocument publishes and promotes doc as the organization's
// document through the real authoring API, proven by fixtures.
func enfPublishPolicyDocument(t *testing.T, snap *authoringcatalog.Snapshot, doc pdp.Document, fixtures []authoring.Fixture) *enfDocuments {
	t.Helper()
	return enfPublishPolicyDocumentAs(t, authoring.EditionCommunity, snap, doc, fixtures)
}

// enfPublishPolicyDocumentAs is enfPublishPolicyDocument under edition's
// authoring profile: an Enterprise obligation family, such as approval, is
// refused under the Community one (authoring/edition.go).
func enfPublishPolicyDocumentAs(t *testing.T, edition authoring.Edition, snap *authoringcatalog.Snapshot, doc pdp.Document, fixtures []authoring.Fixture) *enfDocuments {
	t.Helper()
	ctx := context.Background()
	orgPub, orgPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, "org-key", orgPub)
	profile, err := authoring.ProfileFor(edition)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(snap.Catalog, authoring.StaticTrust(trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	meta := authoring.Metadata{
		DocumentID: "s13-decide-seam", Title: "enforcing seam fixture",
		Author: contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:installer"),
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: doc}, snap.Catalog)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	reviewer := contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:reviewer")
	art, findings, err := api.Publish(ctx, d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: "org-key", PrivateKey: orgPriv,
		Approvers: []contract.ID{reviewer},
		Fixtures:  fixtures,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("publish: %v\n%v", err, findings)
	}
	if _, err := api.Promote(ctx, pdp.RootOrganization, art.Digest(), reviewer, now, "s13 fixture"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	return &enfDocuments{
		api: api, orgKeyID: "org-key", orgPub: orgPub,
		nothingPublished: map[string]bool{enfOrgImplicit: true},
		broken:           map[string]bool{enfOrgBroken: true},
	}
}

// enfConstraintProbe is the content the fixture's constraint detector matches.
// The anchored constraint keys on the DETECTOR, not on the pattern text, so a
// unique token makes the match deterministic without depending on a shipped
// regular expression.
const enfConstraintProbe = "s13-constraint-probe-token"

// enfScopeControl is one policy a scope's restriction keeps, with the census
// row of the detector it reads.
type enfScopeControl struct {
	policy pdp.Policy
	row    registry.CensusRow
}

// enfScopeControls is scopeControls, failing the test on an error.
func enfScopeControls(t *testing.T, scope legacycompile.EnforcementScope) []enfScopeControl {
	t.Helper()
	controls, err := scopeControls(scope)
	if err != nil {
		t.Fatal(err)
	}
	return controls
}

// enfConstraintPolicy is a CONSTRAINT decide's restriction keeps, reading the
// detector of an enabled system row that carries no validator, so a probe token
// is all it takes to fire it. It is DERIVED from the restriction rather than
// named here, and it returns both halves a test needs: the census row the
// fixture installs the probe on, and the policy id a denial names - which is
// the restriction's, because the corpus binds decide its own variant of a
// control whose action differs by scope (#4046).
func enfConstraintPolicy(t *testing.T) (rowID, policyID string) {
	t.Helper()
	for _, c := range enfScopeControls(t, decideSeamScope) {
		if c.policy.Authority != contract.AuthorityConstraint || c.row.Tier != "system" || !c.row.Enabled {
			continue
		}
		if sharedpolicy.ValidatorFor(c.row.PolicyID, sharedpolicy.PolicyCategory(c.row.Category)) == nil {
			return c.row.PolicyID, c.policy.ID
		}
	}
	t.Fatal("decide's restriction keeps no constraint reading an enabled, validator-free system detector")
	return "", ""
}

// enfInstallDecideDetectors installs the shared engine over EVERY enabled
// system row the census carries - the population a migrated database loads -
// with patterns that never match except the one constraint detector.
func enfInstallDecideDetectors(t *testing.T, constraintPolicyID string) {
	t.Helper()
	enfInstallDetectors(t, map[string]string{constraintPolicyID: enfConstraintProbe}, nil)
}

// enfInstallDetectors installs the shared engine over EVERY enabled system row
// the census carries (appendShippedGlobalRows), each never matching except the
// rows named in probes, which match their probe text, and storing the phase
// actions the corpus binds except where responseActions names one.
func enfInstallDetectors(t *testing.T, probes, responseActions map[string]string) {
	t.Helper()
	enfInstallDetectorsWithPacks(t, probes, responseActions, nil)
}

// enfInstallDetectorsWithPacks is enfInstallDetectors with installed policy
// pack detectors riding on every load, as the agent's boot installs them
// (policy_packs.go).
func enfInstallDetectorsWithPacks(t *testing.T, probes, responseActions map[string]string, installed []sharedpolicy.CompiledPolicy) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	for i := 0; i < 64; i++ {
		mockSQL.ExpectQuery("SELECT").WillReturnRows(appendShippedGlobalRows(t, sqlmock.NewRows(policytest.LoaderCols()), probes, responseActions))
	}
	policytest.ScopedTxPlumbing(mockSQL, 64)
	// A CACHE TTL, because a zero TTL expires an entry the moment it is stored:
	// every load would re-query and spend one of the finite mock results above,
	// so a test sending more requests than that would see the engine fail to
	// load policies for a reason that has nothing to do with the seam. With a
	// TTL each (tenant, org) scope loads once.
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{CacheTTL: time.Hour, InstalledDetectors: installed}, nil)
	prev := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(prev) })
}

// enfInstallSeam installs the process enforcer over docs, restored at cleanup.
func enfInstallSeam(t *testing.T, docs activeDocumentSource) {
	t.Helper()
	snap := enfSnapshot(t)
	enfInstallSeamWith(t, docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil })
}

// enfInstallSeamWith is enfInstallSeam with the vocabulary supplied, so a test
// can make its resolution fail.
func enfInstallSeamWith(t *testing.T, docs activeDocumentSource, vocabulary func() (*authoringcatalog.Snapshot, error)) {
	t.Helper()
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newAnchoredEnforcer(docs, vocabulary, boot.Admitter, boot.Registry.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	prevEnforcer := anchoredEnforcerInstance.Load()
	anchoredEnforcerInstance.Store(e)
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prevEnforcer) })
}

// enfImplicitBundle is the policy bundle an organization that has published
// nothing is decided under on scope: the implicit baseline's digest, computed
// by the installed enforcer exactly as a request computes it.
func enfImplicitBundle(t *testing.T, scope legacycompile.EnforcementScope, org string) string {
	t.Helper()
	e := anchoredEnforcerInstance.Load()
	if e == nil {
		t.Fatal("no enforcer is installed")
	}
	act, err := e.activationFor(context.Background(), scope, org, "", nil)
	if err != nil {
		t.Fatalf("activating the implicit baseline for %s on %s: %v", org, scope, err)
	}
	if !act.ImplicitBaseline {
		t.Fatalf("the activation for %s on %s with no document is not the implicit baseline", org, scope)
	}
	return act.PolicyBundle
}

// enfNoCircuitBreaker removes the circuit breaker for the test.
//
// The breaker is a control OUTSIDE the policy engines and not this file's
// subject; both handleDecide sites guard a nil instance. installCircuitBreaker's
// repository over a nil database is safe only on the community build, whose
// breaker is a stub: under the enterprise tag the real breaker dereferences the
// database when an anchored constraint deny is recorded as a policy violation.
func enfNoCircuitBreaker(t *testing.T) {
	t.Helper()
	prev := circuitBreakerInstance
	circuitBreakerInstance = nil
	t.Cleanup(func() { circuitBreakerInstance = prev })
}

func enfMintUserToken(t *testing.T, org, email string) string {
	t.Helper()
	now := time.Now()
	// PRODUCTION'S CLAIM SET, copied from the customer portal's issueToken:
	// the minted realm maps the subject from `sub`.
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       sharedidentity.UserTokenIssuer,
		"sub":       email,
		"email":     email,
		"role":      "user",
		"org_id":    org,
		"tenant_id": org,
		"jti":       "jti-" + org + "-" + email,
		"iat":       jwt.NewNumericDate(now.Add(-time.Minute)),
		"nbf":       jwt.NewNumericDate(now.Add(-time.Minute)),
		"exp":       jwt.NewNumericDate(now.Add(time.Hour)),
	}).SignedString(jwtSecret)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type enfResponse struct {
	code int
	raw  []byte
	body map[string]json.RawMessage
}

func (r enfResponse) str(t *testing.T, member string) string {
	t.Helper()
	v, ok := r.body[member]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		t.Fatalf("member %s is not a string: %s", member, v)
	}
	return s
}

func (r enfResponse) strings(t *testing.T, member string) []string {
	t.Helper()
	var out []string
	if v, ok := r.body[member]; ok {
		if err := json.Unmarshal(v, &out); err != nil {
			t.Fatalf("member %s is not a string list: %s", member, v)
		}
	}
	return out
}

// noMode fails when a body carries the retired `mode` member.
func (r enfResponse) noMode(t *testing.T) {
	t.Helper()
	if v, has := r.body["mode"]; has {
		t.Fatalf("the body carries a mode member (%s); v11 has no decision mode. body=%s", v, r.raw)
	}
}

// enfDecide drives one request through handleDecide as an Enterprise caller,
// with alice's verified user token or with none.
func enfDecide(t *testing.T, org string, withUserToken bool, stage, query string) enfResponse {
	t.Helper()
	token := ""
	if withUserToken {
		token = enfMintUserToken(t, org, enfUser)
	}
	return enfDecideWithToken(t, org, token, stage, query)
}

// enfDecideWithToken drives one request through handleDecide as an Enterprise
// caller presenting token as its user token ("" for none).
func enfDecideWithToken(t *testing.T, org, token, stage, query string) enfResponse {
	t.Helper()
	return enfDecideWithHandshake(t, org, token, stage, query, "")
}

// enfDecideWithHandshake is enfDecideWithToken from an enforcement point
// presenting handshake as its PEP capability declaration ("" presents none).
func enfDecideWithHandshake(t *testing.T, org, token, stage, query, handshake string) enfResponse {
	t.Helper()
	body := DecideRequest{Stage: stage, Target: DecisionTarget{Type: stage}, Query: query, UserToken: token}
	req := decideEnterpriseReq(t, body, org, org)
	if handshake != "" {
		req.Header.Set(contract.PEPHandshakeHeader, handshake)
	}
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
	out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
	if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("the response is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return out
}

func enfSetup(t *testing.T) (constraintPolicy string) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })
	enfNoCircuitBreaker(t)
	var constraintRow string
	constraintRow, constraintPolicy = enfConstraintPolicy(t)
	enfInstallDecideDetectors(t, constraintRow)
	for _, org := range []string{enfOrgPublished, enfOrgImplicit, enfOrgBroken} {
		rutInstallCache(t, org, false)
	}
	enfInstallSeam(t, enfPublishDocument(t, enfSnapshot(t)))
	return constraintPolicy
}

func TestDecideEnforcingSeam(t *testing.T) {
	constraintPolicy := enfSetup(t)
	implicitBundle := enfImplicitBundle(t, decideSeamScope, enfOrgImplicit)

	t.Run("a published document + verified user: the ANCHORED engine allows, and the body names the engine, the User subject and the document's bundle", func(t *testing.T) {
		counter := anchoredEnforceDecisions.WithLabelValues(decideSeamScope.String(), decisionEngineAnchored, VerdictAllow, string(contract.ReasonPermitted))
		before := testutil.ToFloat64(counter)
		r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, "What is the weather today?")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow {
			t.Fatalf("got HTTP %d verdict %q; want 200 allow. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		if r.str(t, "engine") != decisionEngineAnchored || r.str(t, "subject_type") != string(sharedidentity.SubjectUser) {
			t.Fatalf("engine=%q subject_type=%q; want anchored/User. body=%s", r.str(t, "engine"), r.str(t, "subject_type"), r.raw)
		}
		r.noMode(t)
		if bundle := r.str(t, "policy_bundle"); bundle == "" || bundle == implicitBundle {
			t.Fatalf("policy_bundle %q; want the published document's bundle, which is not the implicit baseline's %q", bundle, implicitBundle)
		}
		if !slices.Contains(r.strings(t, "evaluated_policies"), "baseline.permit."+authoringcatalog.ActionLLMCompletion) {
			t.Fatalf("evaluated_policies %v does not name the deployment pack's permission, which permits this beside the document", r.strings(t, "evaluated_policies"))
		}
		if after := testutil.ToFloat64(counter); after != before+1 {
			t.Fatalf("the decide allow counter moved %v -> %v; want +1", before, after)
		}
	})

	t.Run("a published document: an action it constrains for this principal is DENIED explicit_constraint, naming the constraint", func(t *testing.T) {
		r := enfDecide(t, enfOrgPublished, true, DecisionStageTool, "list the open tickets")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d verdict %q engine %q; want 200 deny anchored. body=%s", r.code, r.str(t, "verdict"), r.str(t, "engine"), r.raw)
		}
		if reasons := r.strings(t, "reasons"); len(reasons) != 1 || reasons[0] != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("reasons %v; want exactly [%s]", reasons, contract.ReasonExplicitConstraint)
		}
		if policies := r.strings(t, "evaluated_policies"); len(policies) == 0 || policies[0] != "ceiling.no_tool_for_alice" {
			t.Fatalf("evaluated_policies %v; the document's constraint must decide", policies)
		}
	})

	t.Run("a published document: a principal it constrains is DENIED, so the subject the identity plane admits is load bearing", func(t *testing.T) {
		r := enfDecideWithToken(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfBob), DecisionStageLLM, "What is the weather today?")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d verdict %q engine %q; want 200 deny anchored for bob. body=%s", r.code, r.str(t, "verdict"), r.str(t, "engine"), r.raw)
		}
		if policies := r.strings(t, "evaluated_policies"); len(policies) == 0 || policies[0] != "ceiling.block_bob" {
			t.Fatalf("evaluated_policies %v; bob's constraint must decide", policies)
		}
	})

	// PRD v11 §1.4, and the control for the deny above: an organization that has
	// published nothing is decided by the anchored engine under the implicit
	// baseline, which grants every registered action - so the SAME request is
	// allowed, and the body names the bundle that allowed it.
	t.Run("an organization that has published nothing: the same request is ALLOWED under the implicit baseline, named by its digest", func(t *testing.T) {
		r := enfDecide(t, enfOrgImplicit, true, DecisionStageTool, "list the open tickets")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d verdict %q engine %q; want 200 allow from the anchored engine. body=%s", r.code, r.str(t, "verdict"), r.str(t, "engine"), r.raw)
		}
		if got := r.str(t, "policy_bundle"); got != implicitBundle {
			t.Fatalf("policy_bundle %q; want the implicit baseline's %q", got, implicitBundle)
		}
		r.noMode(t)
	})

	// PRD v11 §1.6: a request that carries no user identity is evaluated for its
	// client credential, recorded as a Client. The credential is neither alice
	// nor bob, so the document's principal-scoped constraints bind it on no
	// action: the tool stage alice is denied is allowed for it.
	t.Run("a request carrying no user token is evaluated for its client credential, recorded as a Client", func(t *testing.T) {
		for _, org := range []string{enfOrgImplicit, enfOrgPublished} {
			for _, stage := range []string{DecisionStageLLM, DecisionStageTool} {
				r := enfDecide(t, org, false, stage, "What is the weather today?")
				if r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow || r.str(t, "subject_type") != string(sharedidentity.SubjectClient) {
					t.Fatalf("%s, %s stage: HTTP %d verdict %q subject_type %q; want 200 allow for a Client, whom no constraint names. body=%s",
						org, stage, r.code, r.str(t, "verdict"), r.str(t, "subject_type"), r.raw)
				}
			}
		}
	})

	// ADMISSION IS FOR THE ABSENCE OF A USER IDENTITY, NEVER FOR A BAD ONE. A
	// token that does not verify is refused at authentication, before the seam
	// runs, and never becomes the credential principal.
	t.Run("a presented user token that does not verify is refused 401, and no engine decides it", func(t *testing.T) {
		before := testutil.ToFloat64(anchoredEnforceDecisions.WithLabelValues(decideSeamScope.String(), decisionEngineAnchored, VerdictAllow, string(contract.ReasonPermitted)))
		for _, org := range []string{enfOrgPublished, enfOrgImplicit} {
			r := enfDecideWithToken(t, org, enfMintUserToken(t, org, enfUser)+"tampered", DecisionStageLLM, "What is the weather today?")
			if r.code != http.StatusUnauthorized {
				t.Fatalf("%s: got HTTP %d; a presented token that does not verify is refused 401. body=%s", org, r.code, r.raw)
			}
			if _, has := r.body["engine"]; has {
				t.Fatalf("%s: the refusal carries an engine member; no engine decided it. body=%s", org, r.raw)
			}
		}
		if after := testutil.ToFloat64(anchoredEnforceDecisions.WithLabelValues(decideSeamScope.String(), decisionEngineAnchored, VerdictAllow, string(contract.ReasonPermitted))); after != before {
			t.Fatalf("a refused token moved the allow counter %v -> %v", before, after)
		}
	})

	t.Run("a published document: content a shipped block control detects is DENIED by that constraint", func(t *testing.T) {
		r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, "please run "+enfConstraintProbe+" now")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d verdict %q engine %q; want 200 deny anchored. body=%s", r.code, r.str(t, "verdict"), r.str(t, "engine"), r.raw)
		}
		if reasons := r.strings(t, "reasons"); len(reasons) != 1 || reasons[0] != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("reasons %v; want exactly [%s]", reasons, contract.ReasonExplicitConstraint)
		}
		if policies := r.strings(t, "evaluated_policies"); len(policies) == 0 || policies[0] != constraintPolicy {
			t.Fatalf("evaluated_policies %v; the blocking shipped control %s must come first", policies, constraintPolicy)
		}
	})
}

// enfPostureMatcher asserts the audit row's policy_details carries the engine,
// the subject type and a policy bundle, and no retired `mode`.
type enfPostureMatcher struct{ engine, subjectType string }

func (m enfPostureMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d map[string]interface{}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	_, hasMode := d["mode"]
	bundle, _ := d["policy_bundle"].(string)
	return d["engine"] == m.engine && d["subject_type"] == m.subjectType && bundle != "" && !hasMode
}

// TestDecideWritesEngineSubjectTypeAndBundleOnTheAuditRow reads the decision
// RECORD the handler writes, for a published document and for the implicit
// baseline, for a verified user and for a client credential.
func TestDecideWritesEngineSubjectTypeAndBundleOnTheAuditRow(t *testing.T) {
	enfSetup(t)
	for _, tc := range []struct {
		name        string
		org         string
		token       bool
		subjectType string
	}{
		{"published document, verified user", enfOrgPublished, true, string(sharedidentity.SubjectUser)},
		{"implicit baseline, verified user", enfOrgImplicit, true, string(sharedidentity.SubjectUser)},
		{"implicit baseline, client credential", enfOrgImplicit, false, string(sharedidentity.SubjectClient)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(decideAuditInsertArgs(AuditVerdictAllowed, enfPostureMatcher{engine: decisionEngineAnchored, subjectType: tc.subjectType})...).
				WillReturnResult(sqlmock.NewResult(0, 1))
			r := enfDecide(t, tc.org, tc.token, DecisionStageLLM, "What is the weather today?")
			if r.code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", r.code, r.raw)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the audit row did not record engine=%s subject_type=%s with a policy bundle and no mode: %v", decisionEngineAnchored, tc.subjectType, err)
			}
		})
	}
}
