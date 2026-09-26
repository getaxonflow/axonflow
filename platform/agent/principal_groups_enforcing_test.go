// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	sharedidentity "axonflow/platform/shared/identity"
)

// principal.groups ON THE ANCHORED REQUEST (#4249 rows 5675113134, 5667380844):
// the enforcer states the admitted user subject's group closure, and a typed
// group-scoped constraint applies to its members, not to its non-members, and
// is Indeterminate - naming the directory's cause - when the closure is not
// known. A request that carries no user identity is stated nothing, so its
// outcome is today's.

// enfGroupFinance is the group the fixture document's ceiling is scoped to.
const enfGroupFinance = "g-finance"

// enfGroupStatement is the exact statement the ceiling refuses; any other
// statement is outside it.
const (
	enfGroupStatement = "p3 group ceiling marked statement"
	enfOtherStatement = "p3 group ceiling other statement"
)

// groupsCall is one closure the enforcer asked for.
type groupsCall struct {
	org     string
	realm   sharedidentity.TrustRealm
	subject sharedidentity.ClosureSubject
}

// recordingGroups is a GroupClosureResolver that records every resolution and
// answers per email through answer.
type recordingGroups struct {
	mu     sync.Mutex
	calls  []groupsCall
	answer func(realm sharedidentity.TrustRealm, subject sharedidentity.ClosureSubject) sharedidentity.ClosureResult
}

func (r *recordingGroups) ResolveClosure(_ context.Context, orgID string, realm sharedidentity.TrustRealm,
	subject sharedidentity.ClosureSubject, _ sharedidentity.ClosureBounds) sharedidentity.ClosureResult {
	r.mu.Lock()
	r.calls = append(r.calls, groupsCall{org: orgID, realm: realm, subject: subject})
	answer := r.answer
	r.mu.Unlock()
	if answer == nil {
		return sharedidentity.NewAuthoritativeClosure(subject.Principal, nil, nil, nil, 1, "test", time.Now())
	}
	return answer(realm, subject)
}

func (r *recordingGroups) recorded() []groupsCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]groupsCall(nil), r.calls...)
}

// since returns the calls recorded after the first n.
func (r *recordingGroups) since(n int) []groupsCall {
	all := r.recorded()
	if n > len(all) {
		return nil
	}
	return all[n:]
}

// enfDirectory answers a closure per verified email: alice in the finance
// group, every other email a present user in no group (bob), and one email per
// Unknown cause, eve being a user the directory holds no row for.
func enfDirectory(realm sharedidentity.TrustRealm, subject sharedidentity.ClosureSubject) sharedidentity.ClosureResult {
	now := time.Now()
	p := subject.Principal
	switch subject.Alias(sharedidentity.AliasEmail) {
	case enfUser:
		return sharedidentity.NewAuthoritativeClosure(p, []sharedidentity.PrincipalID{sharedidentity.MustNewGroupID(sharedidentity.SCIMDirectoryGroupRealm, enfGroupFinance)}, nil, nil, 1, "test", now)
	case "down@corp.example":
		return sharedidentity.NewUnreachableClosure(p, "the directory is down for this test", now)
	case "wide@corp.example":
		return sharedidentity.NewTruncatedClosure(p, nil, nil, nil, 1, "the subject is in 2000 directory groups and the closure is bounded at 1024", "test", now)
	case "off@corp.example":
		res := sharedidentity.NewUnreachableClosure(p, "the directory marks this subject deactivated", now)
		res.Reason = sharedidentity.ReasonCredentialRevoked
		return res
	case "eve@corp.example":
		res := sharedidentity.NewUnreachableClosure(p, "the directory holds no user for this subject", now)
		res.Reason = sharedidentity.ReasonSubjectMissing
		return res
	}
	return sharedidentity.NewAuthoritativeClosure(p, nil, nil, nil, 1, "test", now)
}

// enfInstallSeamGroups installs the process enforcer over docs with groups as
// its group-closure resolver, restored at cleanup.
func enfInstallSeamGroups(t *testing.T, docs activeDocumentSource, groups sharedidentity.GroupClosureResolver) {
	t.Helper()
	snap := enfSnapshot(t)
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newAnchoredEnforcer(docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch, groups)
	if err != nil {
		t.Fatal(err)
	}
	prev := anchoredEnforcerInstance.Load()
	anchoredEnforcerInstance.Store(e)
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })
}

// enfPublishGroupCeiling publishes one organization ceiling scoped to the
// finance group of the SCIM directory's namespace, on every registered action, refusing
// exactly enfGroupStatement. Group scope is an Enterprise construct, so it is
// published under the Enterprise authoring profile.
func enfPublishGroupCeiling(t *testing.T) *enfDocuments {
	t.Helper()
	group := contract.MustParseID(contract.KindGroup, "Group::"+string(sharedidentity.SCIMDirectoryGroupRealm)+":"+enfGroupFinance)
	actions := make([]contract.ID, 0)
	for _, a := range authoringcatalog.DeploymentActions() {
		actions = append(actions, contract.MustParseID(contract.KindAction, "Action::"+a))
	}
	now := time.Now().UTC()
	doc := pdp.Document{
		Root: pdp.RootOrganization, Version: 1,
		Attributes: []pdp.AttributeSchema{
			{Path: pdp.PrincipalIDPath, Type: pdp.TypeString},
			{Path: pdp.PrincipalGroupsPath, Type: pdp.TypeArray},
			{Path: "args.query", Type: pdp.TypeString},
		},
		Policies: []pdp.Policy{{
			ID: "ceiling.finance_group", Name: enfConstraintName("ceiling.finance_group"),
			Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
			Scope:   pdp.Scope{Groups: []contract.ID{group}},
			Actions: pdp.ActionSelector{Actions: actions},
			Where:   pdp.Compare("args.query", pdp.OpEq, enfGroupStatement),
		}},
	}
	tool := authoringcatalog.ActionToolCall
	return enfPublishPolicyDocumentAs(t, authoring.EditionEnterprise, enfSnapshot(t), doc, []authoring.Fixture{{
		Name: "a finance member's marked statement is refused",
		Attributes: contract.AttributeSet{
			pdp.PrincipalIDPath:     contract.Known(enfMintedPrincipal(enfUser), contract.ProvAuthentication, 1, now),
			pdp.PrincipalGroupsPath: contract.Known([]any{group.String()}, contract.ProvDirectory, 1, now),
			pdp.ActionIDPath:        contract.Known("Action::"+tool, contract.ProvPlatform, 1, now),
			pdp.ActionTagsPath:      contract.Known([]any{"stage:" + authzenActionStage[tool]}, contract.ProvPlatform, 1, now),
			"args.query":            contract.Known(enfGroupStatement, contract.ProvCaller, 1, now),
		},
		Expect: map[string]pdp.Verdict{"ceiling.finance_group": pdp.VerdictMatch},
	}})
}

const enfGroupCeilingNamed = "ceiling.finance_group (organization, document version 1) could not be evaluated: "

// A typed group-scoped ceiling, decided through handleDecide: every closure
// state the enforcer can state, and the one it states nothing for.
func TestAGroupScopedConstraintAppliesToItsMembersAndNamesAnUnknownClosuresCause(t *testing.T) {
	enfSetup(t)
	groups := &recordingGroups{answer: enfDirectory}
	enfInstallSeamGroups(t, enfPublishGroupCeiling(t), groups)
	decide := func(t *testing.T, email, statement string) enfResponse {
		t.Helper()
		token := ""
		if email != "" {
			token = enfMintUserToken(t, enfOrgPublished, email)
		}
		return enfDecideWithToken(t, enfOrgPublished, token, DecisionStageTool, statement)
	}
	allowed := func(t *testing.T, r enfResponse) {
		t.Helper()
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("HTTP %d verdict %q engine %q; want 200 anchored allow. body=%s", r.code, r.str(t, "verdict"), r.str(t, "engine"), r.raw)
		}
		if strings.Contains(string(r.raw), "ceiling.finance_group") {
			t.Fatalf("an allowed request names the group ceiling: %s", r.raw)
		}
	}
	unknown := func(t *testing.T, r enfResponse, why string) {
		t.Helper()
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny {
			t.Fatalf("HTTP %d verdict %q; want 200 deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		want := []string{string(contract.ReasonUnknownConstraint), enfGroupCeilingNamed + why}
		if reasons := r.strings(t, "reasons"); !reflect.DeepEqual(reasons, want) {
			t.Fatalf("reasons %q; want %q", reasons, want)
		}
		if evaluated := r.strings(t, "evaluated_policies"); len(evaluated) == 0 || evaluated[0] != "ceiling.finance_group" {
			t.Fatalf("evaluated_policies %v; want the group ceiling first", evaluated)
		}
	}

	t.Run("a member is refused by the ceiling, which is named", func(t *testing.T) {
		r := decide(t, enfUser, enfGroupStatement)
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny {
			t.Fatalf("HTTP %d verdict %q; want 200 deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		if reasons := r.strings(t, "reasons"); !reflect.DeepEqual(reasons, []string{string(contract.ReasonExplicitConstraint)}) {
			t.Fatalf("reasons %q; want exactly [%s]", reasons, contract.ReasonExplicitConstraint)
		}
		if evaluated := r.strings(t, "evaluated_policies"); len(evaluated) == 0 || evaluated[0] != "ceiling.finance_group" {
			t.Fatalf("evaluated_policies %v; want the group ceiling to decide", evaluated)
		}
	})
	t.Run("CONTROL: a non-member's identical request is allowed", func(t *testing.T) {
		allowed(t, decide(t, enfBob, enfGroupStatement))
	})
	t.Run("CONTROL: the member's other statement is allowed", func(t *testing.T) {
		allowed(t, decide(t, enfUser, enfOtherStatement))
	})
	t.Run("an unreachable directory is Indeterminate, naming the closure and the directory's detail", func(t *testing.T) {
		unknown(t, decide(t, "down@corp.example", enfGroupStatement),
			"the group or resource closure behind principal.groups could not be computed (the directory is down for this test)")
	})
	t.Run("a truncated closure is Indeterminate, naming the bound", func(t *testing.T) {
		unknown(t, decide(t, "wide@corp.example", enfGroupStatement),
			"the group or resource closure behind principal.groups hit its depth or size bound (the subject is in 2000 directory groups and the closure is bounded at 1024)")
	})
	t.Run("a deactivated subject is Indeterminate, resolution failed, naming deactivation", func(t *testing.T) {
		unknown(t, decide(t, "off@corp.example", enfGroupStatement),
			"principal.groups could not be resolved (the directory marks this subject deactivated)")
	})
	t.Run("a subject the directory holds no user for is Indeterminate, resolution failed, naming it", func(t *testing.T) {
		unknown(t, decide(t, "eve@corp.example", enfGroupStatement),
			"principal.groups could not be resolved (the directory holds no user for this subject)")
	})
	t.Run("an Unknown closure outside the ceiling's statement is not refused by it", func(t *testing.T) {
		allowed(t, decide(t, "down@corp.example", enfOtherStatement))
	})
	t.Run("a request with no user identity is stated nothing: attribute_not_supplied, and the directory is not asked", func(t *testing.T) {
		before := len(groups.recorded())
		unknown(t, decide(t, "", enfGroupStatement), "no value was supplied for principal.groups")
		if calls := groups.since(before); len(calls) != 0 {
			t.Fatalf("the directory was asked %d times for a request with no user identity: %+v", len(calls), calls)
		}
	})
	t.Run("the closure is asked for the admitted principal, under its realm, keyed by its verified email", func(t *testing.T) {
		before := len(groups.recorded())
		decide(t, enfBob, enfOtherStatement)
		calls := groups.since(before)
		if len(calls) != 1 {
			t.Fatalf("the directory was asked %d times for one request; want 1", len(calls))
		}
		c := calls[0]
		if c.org != enfOrgPublished || c.realm.RealmID != sharedidentity.BuiltinRealmMinted || c.subject.Principal.String() != enfMintedPrincipal(enfBob) {
			t.Fatalf("asked for org %q realm %q principal %q; want %q %q %q", c.org, c.realm.RealmID, c.subject.Principal, enfOrgPublished, sharedidentity.BuiltinRealmMinted, enfMintedPrincipal(enfBob))
		}
		if got := c.subject.Alias(sharedidentity.AliasEmail); got != enfBob {
			t.Fatalf("the verified email alias is %q; want %q", got, enfBob)
		}
	})
}

// assertGroupsAskedFor holds the calls a request made to the closure resolver to
// the admitted user email: at least one, every one for its minted principal and
// keyed by its verified email alias.
func assertGroupsAskedFor(t *testing.T, calls []groupsCall, email string) {
	t.Helper()
	if len(calls) == 0 {
		t.Fatalf("the enforcer stated no principal.groups for %s's verified token: the closure resolver was never asked", email)
	}
	for _, c := range calls {
		if c.subject.Principal.String() != enfMintedPrincipal(email) || c.subject.Alias(sharedidentity.AliasEmail) != email {
			t.Fatalf("asked for %q keyed by %q; want %q keyed by %q", c.subject.Principal, c.subject.Alias(sharedidentity.AliasEmail), enfMintedPrincipal(email), email)
		}
	}
}

func assertGroupsNotAsked(t *testing.T, calls []groupsCall, why string) {
	t.Helper()
	if len(calls) != 0 {
		t.Fatalf("%s, and the closure resolver was asked %d times: %+v", why, len(calls), calls)
	}
}

// principal.groups IS STATED AT EVERY SEAM THAT ADMITS A VERIFIED USER, AND AT
// NO SEAM THAT DOES NOT. Each construction site is driven through its own
// handler with the recording resolver installed: a user token asks for the
// closure of the admitted principal, keyed by its verified email; the same
// request with no user token asks for nothing.
func TestPrincipalGroupsIsStatedAtEveryAgentSeamThatAdmitsAVerifiedUser(t *testing.T) {
	t.Run("1 decide", func(t *testing.T) {
		enfSetup(t)
		groups := &recordingGroups{}
		enfInstallSeamGroups(t, enfPublishDocument(t, enfSnapshot(t)), groups)
		n := len(groups.recorded())
		enfDecide(t, enfOrgPublished, true, DecisionStageLLM, "What is the weather today?")
		assertGroupsAskedFor(t, groups.since(n), enfUser)
		n = len(groups.recorded())
		if r := enfDecide(t, enfOrgPublished, false, DecisionStageLLM, "What is the weather today?"); r.code != http.StatusOK || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("PREMISE: the token-less decide did not reach the enforcer: HTTP %d body=%s", r.code, r.raw)
		}
		assertGroupsNotAsked(t, groups.since(n), "decide carried no user token")
	})

	t.Run("2 /api/request", func(t *testing.T) {
		enfProxySetup(t)
		groups := &recordingGroups{}
		enfInstallSeamGroups(t, enfPublishDocument(t, enfSnapshot(t)), groups)
		n := len(groups.recorded())
		enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "SELECT id FROM products")
		assertGroupsAskedFor(t, groups.since(n), enfUser)
		n = len(groups.recorded())
		// An Enterprise /api/request with no user token is refused at the
		// authentication boundary, before the enforcer
		// (TestProxyRequestEnforcingSeam); asserted, so this arm is not read as
		// a credential subject that reached the resolver and was not asked.
		if r := enfProxy(t, enfOrgPublished, "", "SELECT id FROM products"); r.code != http.StatusUnauthorized {
			t.Fatalf("PREMISE: the token-less Enterprise /api/request was not refused at authentication: HTTP %d body=%s", r.code, r.raw)
		}
		assertGroupsNotAsked(t, groups.since(n), "/api/request carried no user token")
	})

	t.Run("3 gateway pre-check", func(t *testing.T) {
		enfSetup(t)
		groups := &recordingGroups{}
		enfInstallSeamGroups(t, enfPublishDocument(t, enfSnapshot(t)), groups)
		n := len(groups.recorded())
		enfPreCheck(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "What is the weather today?")
		assertGroupsAskedFor(t, groups.since(n), enfUser)
		n = len(groups.recorded())
		// As /api/request: refused at authentication on Enterprise
		// (TestGatewayPreCheckEnforcingSeam), asserted so the arm is not vacuous.
		if r := enfPreCheck(t, enfOrgPublished, "", "What is the weather today?"); r.code != http.StatusUnauthorized {
			t.Fatalf("PREMISE: the token-less Enterprise pre-check was not refused at authentication: HTTP %d body=%s", r.code, r.raw)
		}
		assertGroupsNotAsked(t, groups.since(n), "the pre-check carried no user token")
	})

	t.Run("4 MCP proxy routes", func(t *testing.T) {
		w := mrsSetup(t)
		groups := &recordingGroups{}
		enfInstallSeamGroups(t, w.docs, groups)
		const ran = "p3-connector-ran"
		for _, route := range []struct {
			name string
			conn *mockConnector
			post func(token string) *httptest.ResponseRecorder
		}{
			{"check-input", nil, func(token string) *httptest.ResponseRecorder {
				body, _ := json.Marshal(MCPCheckInputRequest{ConnectorType: "postgres", Statement: mrsBenign, UserToken: token})
				req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", utrBasicAuthHeader())
				rr := httptest.NewRecorder()
				mcpCheckInputHandler(rr, req)
				return rr
			}},
			{"resources/query", &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": ran}}, RowCount: 1}},
				func(token string) *httptest.ResponseRecorder {
					return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
				}},
			{"tools/execute", &mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: ran}},
				func(token string) *httptest.ResponseRecorder {
					return mrsPost("/mcp/tools/execute", MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE orders SET x=1", UserToken: token}, mcpExecuteHandler)
				}},
		} {
			t.Run(route.name, func(t *testing.T) {
				if route.conn != nil {
					registerExecConnector(t, route.conn)
				}
				n := len(groups.recorded())
				if rr := route.post(mrsToken(t)); rr.Code != http.StatusOK {
					t.Fatalf("alice: HTTP %d; want 200. body=%s", rr.Code, rr.Body.String())
				}
				assertGroupsAskedFor(t, groups.since(n), enfUser)
				n = len(groups.recorded())
				if rr := route.post(""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), decisionEngineAnchored) {
					t.Fatalf("PREMISE: the token-less %s did not reach the enforcer: HTTP %d body=%s", route.name, rr.Code, rr.Body.String())
				}
				assertGroupsNotAsked(t, groups.since(n), route.name+" carried no user token")
			})
		}
	})

	t.Run("5 MCP server check_policy session", func(t *testing.T) {
		w := mrsSetup(t)
		groups := &recordingGroups{}
		enfInstallSeamGroups(t, w.docs, groups)
		n := len(groups.recorded())
		if got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfUser), mrsBenign); err != nil || got["engine"] != decisionEngineAnchored {
			t.Fatalf("PREMISE: alice's check_policy was not decided by the anchored engine: %v, %v", got, err)
		}
		assertGroupsAskedFor(t, groups.since(n), enfUser)
		n = len(groups.recorded())
		if got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, ""), mrsBenign); err != nil || got["engine"] != decisionEngineAnchored {
			t.Fatalf("PREMISE: the token-less session's check_policy was not decided by the anchored engine: %v, %v", got, err)
		}
		assertGroupsNotAsked(t, groups.since(n), "the MCP session holds no validated token")
	})

	t.Run("6 MCP response pass", func(t *testing.T) {
		w := mrsSetup(t)
		groups := &recordingGroups{}
		enfInstallSeamGroups(t, w.docs, groups)
		n := len(groups.recorded())
		if r := mrsCheckOutput(t, mrsToken(t), mrsBenign); r.code != http.StatusOK {
			t.Fatalf("alice's check-output: HTTP %d; want 200. body=%s", r.code, r.raw)
		}
		assertGroupsAskedFor(t, groups.since(n), enfUser)
		n = len(groups.recorded())
		if r := mrsCheckOutput(t, "", mrsBenign); r.code != http.StatusOK || !strings.Contains(r.raw, decisionEngineAnchored) {
			t.Fatalf("PREMISE: the credential's check-output was not decided by the anchored engine: HTTP %d body=%s", r.code, r.raw)
		}
		assertGroupsNotAsked(t, groups.since(n), "check-output carried no user token")

		ctx := context.WithValue(context.Background(), ContextKeyOrgID, w.org)
		args := map[string]interface{}{"connector_type": "postgres", "message": mrsBenign}
		n = len(groups.recorded())
		if _, err := mcpToolCheckOutput(ctx, mrqSession(t, w.org, enfUser), args, pepHandshakeResolution{}); err != nil {
			t.Fatal(err)
		}
		assertGroupsAskedFor(t, groups.since(n), enfUser)
		n = len(groups.recorded())
		if _, err := mcpToolCheckOutput(ctx, mrqSession(t, w.org, ""), args, pepHandshakeResolution{}); err != nil {
			t.Fatal(err)
		}
		assertGroupsNotAsked(t, groups.since(n), "the MCP session's check_output holds no validated token")
	})

	// The policy-test preview's arm is
	// TestPrincipalGroupsIsNotAskedByThePolicyTestPreview in
	// principal_groups_enforcing_preview_enterprise_test.go: its helpers live in
	// policy_test_preview_enterprise_test.go, which the community sync strips by
	// its *_enterprise name.

	t.Run("by construction: the OpenAI-compatible route, even naming a user", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		t.Setenv("ENVIRONMENT", "development")
		installSharedEngineForOpenAITest(t)
		groups := &recordingGroups{}
		enfInstallSeamGroups(t, noDocumentsPublished{}, groups)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-p3","object":"chat.completion","choices":[]}`))
		}))
		t.Cleanup(upstream.Close)
		oldEndpoints := providerEndpoints
		providerEndpoints = map[string]string{"gpt-": upstream.URL}
		t.Cleanup(func() { providerEndpoints = oldEndpoints })
		rr := openaiCompatForTest(t, makeChatBody("gpt-4o", simpleMessages("What is 2+2?"), map[string]interface{}{"user": enfUser}),
			map[string]string{"X-Provider-Key": "test-provider-key"})
		if got := rr.Header().Get(openaiCompatibleSubjectTypeHeader); got != string(sharedidentity.SubjectClient) {
			t.Fatalf("PREMISE: the route was not decided for the client credential (%s=%q, HTTP %d)", openaiCompatibleSubjectTypeHeader, got, rr.Code)
		}
		assertGroupsNotAsked(t, groups.recorded(), "the OpenAI-compatible route carries no user identity")
	})
}

// redeclaringRevocations re-declares the minted realm, at the next version, the
// first time admission consults revocation: after the realm the subject is
// verified under was read, and before the enforcer resolves the closure.
type redeclaringRevocations struct {
	t        *testing.T
	registry *sharedidentity.RealmRegistry
	done     bool
}

func (r *redeclaringRevocations) IsRevoked(orgID string, realm sharedidentity.RealmID, _ string) (bool, error) {
	if !r.done && realm == sharedidentity.BuiltinRealmMinted {
		r.done = true
		declared, ok := r.registry.Lookup(orgID, realm)
		if !ok {
			r.t.Errorf("PREMISE: the minted realm is not declared for %s while it is being verified", orgID)
			return false, nil
		}
		declared.Version++
		if err := r.registry.Register(declared); err != nil {
			r.t.Errorf("re-declaring the minted realm: %v", err)
		}
	}
	return false, nil
}

// THE CLOSURE IS RESOLVED UNDER THE REALM THAT ADMITTED THE SUBJECT
// (AdmittedSubject), never under a second registry lookup: a realm re-declared
// between admission and the closure read would otherwise hand the directory a
// declaration the subject was never verified under.
func TestTheGroupClosureIsResolvedUnderTheRealmThatAdmittedTheSubject(t *testing.T) {
	enfSetup(t)
	oracle := &redeclaringRevocations{t: t}
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{
		Deployment:  sharedidentity.BuiltinRealmDeployment{HasRevocation: true, HasDirectory: true},
		Revocations: oracle,
	})
	if err != nil {
		t.Fatal(err)
	}
	oracle.registry = boot.Registry
	snap := enfSnapshot(t)
	groups := &recordingGroups{}
	e, err := newAnchoredEnforcer(enfPublishDocument(t, snap), func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch, groups)
	if err != nil {
		t.Fatal(err)
	}
	prev := anchoredEnforcerInstance.Load()
	anchoredEnforcerInstance.Store(e)
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })

	if r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, "What is the weather today?"); r.code != http.StatusOK {
		t.Fatalf("PREMISE: decide answered HTTP %d. body=%s", r.code, r.raw)
	}
	if !oracle.done {
		t.Fatal("PREMISE: admission never consulted revocation, so nothing was re-declared and this proves nothing")
	}
	calls := groups.recorded()
	if len(calls) != 1 {
		t.Fatalf("the closure was asked for %d times; want 1", len(calls))
	}
	live, ok := boot.Registry.Lookup(enfOrgPublished, sharedidentity.BuiltinRealmMinted)
	if !ok {
		t.Fatal("PREMISE: the minted realm is not declared")
	}
	if got := calls[0].realm.Version; got != live.Version-1 {
		t.Fatalf("the closure was resolved under realm version %d and the live declaration is %d; want %d, the version that admitted the subject",
			got, live.Version, live.Version-1)
	}
}

// THE MCP-SERVER SESSION REQUEST PASS, END TO END (site 5): the plane the suite
// of record (runtime-e2e/3550_caep_receiver) proves live, and the one whose
// subject comes from the session's validated token rather than from the
// request. decide is the other seam held end to end; the remaining seams are
// held by the resolver-call assertions above, because every seam reaches the
// one builder (anchoredRequest) that TestTheGroupClosureIsStatedOnTheRootActorAsItsTriState
// holds, so what differs per seam is only whether its subject reaches the
// resolver.
func TestAGroupScopedConstraintDecidesTheMCPServerSessionRequestPass(t *testing.T) {
	w := mrsSetup(t)
	groups := &recordingGroups{answer: enfDirectory}
	enfInstallSeamGroups(t, enfPublishGroupCeiling(t), groups)
	check := func(t *testing.T, email, statement string) map[string]interface{} {
		t.Helper()
		got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, email), statement)
		if err != nil {
			t.Fatalf("check_policy for %q: %v", email, err)
		}
		if got["engine"] != decisionEngineAnchored {
			t.Fatalf("check_policy for %q was not decided by the anchored engine: %v", email, got)
		}
		return got
	}
	named := func(got map[string]interface{}) bool {
		b, _ := json.Marshal(got)
		return strings.Contains(string(b), "ceiling.finance_group")
	}

	t.Run("a member's session is refused by the group ceiling, which is named", func(t *testing.T) {
		got := check(t, enfUser, enfGroupStatement)
		if got["allowed"] != false || got["blocked_by"] != "ceiling.finance_group" || got["block_reason"] != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("alice's session got %v; want refused explicit_constraint, blocked_by ceiling.finance_group", got)
		}
	})
	t.Run("CONTROL: a non-member's session is allowed on the identical call", func(t *testing.T) {
		if got := check(t, enfBob, enfGroupStatement); got["allowed"] != true || named(got) {
			t.Fatalf("bob's session got %v; want allowed with the ceiling named nowhere", got)
		}
	})
	t.Run("CONTROL: the member's other statement is allowed", func(t *testing.T) {
		if got := check(t, enfUser, enfOtherStatement); got["allowed"] != true || named(got) {
			t.Fatalf("alice's other statement got %v; want allowed with the ceiling named nowhere", got)
		}
	})
	t.Run("an unreachable directory is refused naming the closure and the directory's detail", func(t *testing.T) {
		got := check(t, "down@corp.example", enfGroupStatement)
		want := string(contract.ReasonUnknownConstraint) + "; " + enfGroupCeilingNamed +
			"the group or resource closure behind principal.groups could not be computed (the directory is down for this test)"
		if got["allowed"] != false || got["block_reason"] != want {
			t.Fatalf("the down session got %v; want refused with block_reason %q", got, want)
		}
	})
	t.Run("a session with no validated token is stated nothing, and the directory is not asked", func(t *testing.T) {
		before := len(groups.recorded())
		got := check(t, "", enfGroupStatement)
		want := string(contract.ReasonUnknownConstraint) + "; " + enfGroupCeilingNamed + "no value was supplied for principal.groups"
		if got["allowed"] != false || got["block_reason"] != want {
			t.Fatalf("the token-less session got %v; want refused with block_reason %q", got, want)
		}
		assertGroupsNotAsked(t, groups.since(before), "the session holds no validated token")
	})
}
