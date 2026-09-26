// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
)

// #4276 / #4249 row 5659512406: both tier-limit branches of /api/request - the
// credential's service principal refused in Authenticate, the user token's
// human principal refused in ResolveUser - answer one shape: 402, the
// documented ClientResponse with blocked:true, the ERR_TIER_LIMIT_* code as a
// field, and Retry-After only when the refusal carries one (the ledger
// outage). At base both wrote blocked:false, which the Go SDK returns to its
// caller as a non-error, not-blocked response.

const tierRequestOrg = "tier-4276-org"

// tierRequestClient registers an enterprise credential of tierRequestOrg under
// clientID and returns its licence key.
func tierRequestClient(t *testing.T, clientID string) string {
	t.Helper()
	key := generateTestLicenseKey(tierRequestOrg, "Enterprise", "20351231")
	knownClients[clientID] = &ClientAuth{ClientID: clientID, LicenseKey: key, Name: clientID, TenantID: tierRequestOrg, Enabled: true, RateLimit: 1000}
	t.Cleanup(func() { delete(knownClients, clientID) })
	useRateLimitKey(t, clientID)
	return key
}

func tierRequestSetup(t *testing.T) *admission.MemoryLedger {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{latencies: []int64{}, lastLatencies: []int64{}, staticPolicyLatencies: []int64{}, dynamicPolicyLatencies: []int64{}}
	}
	return wireMemoryAdmitter(t, license.TierCommunity)
}

// postAPIRequest drives clientRequestHandler as the SDKs call it: Basic
// credential, JSON body with client_id and user_token.
func postAPIRequest(t *testing.T, clientID, secret, userToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(ClientRequest{ClientID: clientID, RequestType: "chat", Query: "hello", UserToken: userToken})
	req := httptest.NewRequest(http.MethodPost, "/api/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	w := httptest.NewRecorder()
	clientRequestHandler(w, req)
	return w
}

// sdkClientResponse is the Go SDK's ClientResponse fields a caller branches on
// (axonflow-sdk-go axonflow.go, parsed from a 402 body and returned as a
// non-error).
type sdkClientResponse struct {
	Success     bool   `json:"success"`
	Error       string `json:"error"`
	Blocked     bool   `json:"blocked"`
	BlockReason string `json:"block_reason"`
}

// assertTierClientRefusal pins the one shape.
func assertTierClientRefusal(t *testing.T, w *httptest.ResponseRecorder, code, retryAfter string) {
	t.Helper()
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402: %s", w.Code, w.Body.String())
	}
	// Read from the written response, not the recorder's live header map, so a
	// header set after WriteHeader (which never reaches the wire) is not seen.
	if got := w.Result().Header.Get("Retry-After"); got != retryAfter {
		t.Errorf("Retry-After = %q, want %q", got, retryAfter)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, w.Body.String())
	}
	if raw["code"] != code {
		t.Errorf("code = %v, want %s", raw["code"], code)
	}
	if _, wire := raw["dimension"]; wire {
		t.Errorf("the body is admission.Wire, not a ClientResponse: %s", w.Body.String())
	}
	var sdk sdkClientResponse
	if err := json.Unmarshal(w.Body.Bytes(), &sdk); err != nil {
		t.Fatalf("the body does not decode as the Go SDK's ClientResponse: %v", err)
	}
	if !sdk.Blocked || sdk.Success || !strings.HasPrefix(sdk.Error, code+":") || sdk.BlockReason != sdk.Error {
		t.Errorf("SDK-shaped decode = %+v, want blocked, not success, error and block_reason the message beginning with %s", sdk, code)
	}
}

// The user token's human principal over the ceiling: 402, the human code,
// blocked, no Retry-After.
func TestAPIRequestUserTokenOverTheCeilingIsOneShape(t *testing.T) {
	tierRequestSetup(t)
	secret := tierRequestClient(t, "tier-4276-client")
	for i := 0; i < license.CommunityLimits.MaxHumanPrincipals; i++ {
		if ref := admitPrincipal(t.Context(), admission.HumanPrincipal, tierRequestOrg, fmt.Sprintf("human-%d@example.com", i)); ref != nil {
			t.Fatalf("pre-admit %d: %v", i, ref)
		}
	}
	tok := generateTestJWTWithOrgEmail(1, tierRequestOrg, tierRequestOrg, "one-too-many@example.com", []string{"query"}, "developer")

	w := postAPIRequest(t, "tier-4276-client", secret, tok)

	assertTierClientRefusal(t, w, admission.HumanPrincipal.Code(), "")
}

// The user token's human principal during a ledger outage (limit > 0, so the
// outage reason and not over_limit): 402 with Retry-After: 30.
func TestAPIRequestUserTokenDuringALedgerOutageCarriesRetryAfter(t *testing.T) {
	mem := tierRequestSetup(t)
	secret := tierRequestClient(t, "tier-4276-client")
	if ref := admitPrincipal(t.Context(), admission.ServicePrincipal, tierRequestOrg, "tier-4276-client"); ref != nil {
		t.Fatalf("pre-admit the credential: %v", ref)
	}
	mem.SetDown(true)
	tok := generateTestJWTWithOrgEmail(1, tierRequestOrg, tierRequestOrg, "never-seen@example.com", []string{"query"}, "developer")

	w := postAPIRequest(t, "tier-4276-client", secret, tok)

	assertTierClientRefusal(t, w, admission.HumanPrincipal.Code(), "30")
}

// The credential's service principal over the ceiling: the same shape, the
// service code.
func TestAPIRequestCredentialOverTheCeilingIsOneShape(t *testing.T) {
	tierRequestSetup(t)
	secret := tierRequestClient(t, "tier-4276-new-client")
	for i := 0; i < license.CommunityLimits.MaxServicePrincipals; i++ {
		if ref := admitPrincipal(t.Context(), admission.ServicePrincipal, tierRequestOrg, fmt.Sprintf("service-%d", i)); ref != nil {
			t.Fatalf("pre-admit %d: %v", i, ref)
		}
	}

	w := postAPIRequest(t, "tier-4276-new-client", secret, "")

	assertTierClientRefusal(t, w, admission.ServicePrincipal.Code(), "")
}

// The credential's service principal during a ledger outage: Retry-After: 30.
func TestAPIRequestCredentialDuringALedgerOutageCarriesRetryAfter(t *testing.T) {
	mem := tierRequestSetup(t)
	secret := tierRequestClient(t, "tier-4276-new-client")
	mem.SetDown(true)

	w := postAPIRequest(t, "tier-4276-new-client", secret, "")

	assertTierClientRefusal(t, w, admission.ServicePrincipal.Code(), "30")
}

// The gate: an AuthError that is not a tier-limit refusal keeps its own path,
// byte for byte - an invalid user token (401) and the Community-SaaS
// per-minute refusal (429, Retry-After: 60). Neither carries a code or
// blocked:true.
func TestAPIRequestNonTierAuthErrorsKeepTheirShape(t *testing.T) {
	t.Run("an invalid user token", func(t *testing.T) {
		tierRequestSetup(t)
		secret := tierRequestClient(t, "tier-4276-client")

		w := postAPIRequest(t, "tier-4276-client", secret, "not-a-token")

		if w.Code != http.StatusUnauthorized || w.Result().Header.Get("Retry-After") != "" || !strings.Contains(w.Body.String(), "Invalid user token") {
			t.Fatalf("= %d Retry-After %q, want ResolveUser's 401 and no Retry-After: %s", w.Code, w.Result().Header.Get("Retry-After"), w.Body.String())
		}
		assertSendErrorResponseBytes(t, w)
	})
	t.Run("the Community-SaaS per-minute refusal", func(t *testing.T) {
		pinMinuteLimits(t)
		t.Setenv("DEPLOYMENT_MODE", "community-saas")
		if agentMetrics == nil {
			agentMetrics = &AgentMetrics{latencies: []int64{}, lastLatencies: []int64{}, staticPolicyLatencies: []int64{}, dynamicPolicyLatencies: []int64{}}
		}
		clientID := "cs_4276_rate_limited"
		useRateLimitKey(t, clientID)
		seedRateLimitCount(clientID, 200)

		w := postAPIRequest(t, clientID, "never-checked-past-the-limiter", "")

		if w.Code != http.StatusTooManyRequests || w.Result().Header.Get("Retry-After") != "60" || !strings.Contains(w.Body.String(), "Rate limit exceeded") {
			t.Fatalf("= %d Retry-After %q, want 429 and 60: %s", w.Code, w.Result().Header.Get("Retry-After"), w.Body.String())
		}
		assertSendErrorResponseBytes(t, w)
	})
}

// assertSendErrorResponseBytes: the body is exactly what sendErrorResponse
// writes for its message, which is the base shape {success, error, blocked}.
func assertSendErrorResponseBytes(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var got ClientResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	want := httptest.NewRecorder()
	sendErrorResponse(want, got.Error, w.Code, nil)
	if !bytes.Equal(w.Body.Bytes(), want.Body.Bytes()) {
		t.Errorf("body = %s, want sendErrorResponse's %s", w.Body.String(), want.Body.String())
	}
	var raw map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	if _, has := raw["code"]; has || raw["blocked"] != false {
		t.Errorf("a non-tier refusal carries code or blocked: %s", w.Body.String())
	}
}

// The boundary, per the ceiling's definition (count < limit admits): with limit
// N the Nth distinct principal is admitted, the (N+1)th refused with count N,
// and repeating the Nth is admitted.
func TestTheHumanCeilingBoundaryAdmitsTheNthAndRefusesTheNextOne(t *testing.T) {
	wireMemoryAdmitter(t, license.TierCommunity)
	n := license.CommunityLimits.MaxHumanPrincipals
	for i := 1; i <= n; i++ {
		if ref := admitPrincipal(t.Context(), admission.HumanPrincipal, tierRequestOrg, fmt.Sprintf("b-%d@example.com", i)); ref != nil {
			t.Fatalf("principal %d of %d refused: %v", i, n, ref)
		}
	}
	ref := admitPrincipal(t.Context(), admission.HumanPrincipal, tierRequestOrg, "b-next@example.com")
	if ref == nil || ref.Decision.Reason != admission.ReasonOverLimit || ref.Decision.Count != n || ref.Decision.Limit != n {
		t.Fatalf("principal %d = %+v, want over_limit with count and limit %d", n+1, ref, n)
	}
	if ref := admitPrincipal(t.Context(), admission.HumanPrincipal, tierRequestOrg, fmt.Sprintf("b-%d@example.com", n)); ref != nil {
		t.Errorf("repeating principal %d refused: %v", n, ref)
	}
}

// Both tier-limit branches of clientRequestHandler render through the one
// helper, each gated on isTierLimitAuthError, and nothing else in the handler
// calls it.
func TestBothAPIRequestTierBranchesCallTheOneGatedHelper(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var handler *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "clientRequestHandler" {
			handler = fn
		}
	}
	if handler == nil {
		t.Fatal("PREMISE: clientRequestHandler not found in run.go")
	}
	gated := map[string]bool{}
	calls := 0
	ast.Inspect(handler, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "writeTierLimitClientRefusal" {
					calls++
				}
			}
			return true
		}
		cond, ok := ifs.Cond.(*ast.CallExpr)
		if !ok || len(cond.Args) != 1 {
			return true
		}
		if id, ok := cond.Fun.(*ast.Ident); !ok || id.Name != "isTierLimitAuthError" {
			return true
		}
		arg, ok := cond.Args[0].(*ast.Ident)
		if !ok {
			return true
		}
		for _, stmt := range ifs.Body.List {
			if es, ok := stmt.(*ast.ExprStmt); ok {
				if call, ok := es.X.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "writeTierLimitClientRefusal" && len(call.Args) == 2 {
						if a, ok := call.Args[1].(*ast.Ident); ok && a.Name == arg.Name {
							gated[arg.Name] = true
						}
					}
				}
			}
		}
		return true
	})
	if !gated["authErr"] || !gated["userAuthErr"] {
		t.Errorf("gated helper calls for %v, want both authErr (Authenticate) and userAuthErr (ResolveUser)", gated)
	}
	if calls != 2 {
		t.Errorf("clientRequestHandler calls writeTierLimitClientRefusal %d times, want exactly 2", calls)
	}
}

// The published ClientResponse.code enum is exactly the admission dimensions'
// codes, so a new dimension moves the spec with it; and /api/request's 402
// declares the Retry-After header the outage refusal carries.
func TestTheClientResponseCodeEnumIsTheAdmissionDimensions(t *testing.T) {
	doc := loadAgentAPI(t)
	p := schemaProperty(t, doc, "ClientResponse", "code")
	rawEnum, ok := p["enum"].([]any)
	if !ok || len(rawEnum) == 0 {
		t.Fatal("ClientResponse.code declares no enum")
	}
	published := map[string]bool{}
	for _, v := range rawEnum {
		published[v.(string)] = true
	}
	want := map[string]bool{}
	for _, d := range admission.Dimensions() {
		want[d.Code()] = true
	}
	if len(published) != len(rawEnum) || len(published) != len(want) {
		t.Errorf("published %d codes (%d distinct), want the %d admission dimensions' codes", len(rawEnum), len(published), len(want))
	}
	for code := range want {
		if !published[code] {
			t.Errorf("admission dimension code %s is missing from ClientResponse.code's enum", code)
		}
	}
	for code := range published {
		if !want[code] {
			t.Errorf("ClientResponse.code publishes %s, which no admission dimension answers", code)
		}
	}

	paths, _ := doc["paths"].(map[string]any)
	route, _ := paths["/api/request"].(map[string]any)
	post, _ := route["post"].(map[string]any)
	responses, _ := post["responses"].(map[string]any)
	r402, ok := responses["402"].(map[string]any)
	if !ok {
		t.Fatal("/api/request declares no 402")
	}
	headers, _ := r402["headers"].(map[string]any)
	if _, ok := headers["Retry-After"]; !ok {
		t.Error("/api/request's 402 does not declare the Retry-After header its outage refusal carries")
	}
	// The route does answer 429 (the Community-SaaS limiters), so what is
	// pinned is that no 429 describes the licence ceiling, which answers 402.
	if r429, ok := responses["429"].(map[string]any); ok {
		if desc, _ := r429["description"].(string); strings.Contains(desc, "ERR_TIER_LIMIT") || strings.Contains(strings.ToLower(desc), "ceiling") {
			t.Error("/api/request documents the licence ceiling under 429; it answers 402 on this route")
		}
	}
}

// The /api/request shape stays on /api/request: nothing else in the package
// calls writeTierLimitClientRefusal, so /api/v1/decide (sendDecideError) and
// the raw-JSON planes (writeTierLimitRefusal, admission.Wire) keep their own
// tier-refusal shapes unchanged.
func TestOnlyTheAPIRequestHandlerWritesTheClientResponseTierRefusal(t *testing.T) {
	files, err := filepathGlobGo()
	if err != nil {
		t.Fatal(err)
	}
	callers := map[string]int{}
	for _, name := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "writeTierLimitClientRefusal" {
						callers[fn.Name.Name]++
					}
				}
				return true
			})
		}
	}
	if len(callers) != 1 || callers["clientRequestHandler"] != 2 {
		t.Errorf("writeTierLimitClientRefusal callers = %v, want only clientRequestHandler, twice", callers)
	}
}

func filepathGlobGo() ([]string, error) {
	all, err := filepath.Glob("*.go")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range all {
		if !strings.HasSuffix(f, "_test.go") {
			out = append(out, f)
		}
	}
	return out, nil
}
