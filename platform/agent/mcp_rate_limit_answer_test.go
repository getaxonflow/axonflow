// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-redis/redis/v8"
)

// #4261: the MCP server path answers a Community SaaS rate limit with HTTP
// 429, a Retry-After and the V1 envelope in result.content[0].text. The
// installed plugin hooks read an envelope only from a 429 or a 403, so the
// 200 this path used to send was passed by as an ordinary result and every
// hook allowed the call silently.

// pinMinuteLimits pins the tier limits these tests count against, so an
// ambient COMMUNITY_SAAS_MINUTE_LIMIT_* cannot move them.
func pinMinuteLimits(t *testing.T) {
	t.Helper()
	t.Setenv("COMMUNITY_SAAS_MINUTE_LIMIT_FREE", "25")
	t.Setenv("COMMUNITY_SAAS_MINUTE_LIMIT_PRO", "200")
	t.Setenv("COMMUNITY_SAAS_MINUTE_LIMIT", "200")
	if redisClient != nil {
		t.Fatal("these tests drive the in-memory limiter, but redisClient is set")
	}
}

// useRateLimitKey starts a limiter key at zero and removes it afterwards.
func useRateLimitKey(t *testing.T, key string) {
	t.Helper()
	drop := func() {
		rateLimitMu.Lock()
		delete(rateLimitMap, key)
		rateLimitMu.Unlock()
	}
	drop()
	t.Cleanup(drop)
}

func seedRateLimitCount(key string, count int) {
	rateLimitMu.Lock()
	rateLimitMap[key] = &RateLimitEntry{Count: count, ResetTime: time.Now().Add(30 * time.Second)}
	rateLimitMu.Unlock()
}

// stubDailyChecker replaces the daily-quota checker for one test.
func stubDailyChecker(t *testing.T, fn func(context.Context, string, int, *sql.DB) error) {
	t.Helper()
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })
	proxyDailyLimitChecker = fn
}

// decodeMCPEnvelope reads the envelope where the installed hooks look for
// it on a JSON-RPC answer: result.content[0].text, with isError set.
func decodeMCPEnvelope(t *testing.T, rr *httptest.ResponseRecorder) rateLimitEnvelope {
	t.Helper()
	var rpc struct {
		JSONRPC string `json:"jsonrpc"`
		Result  struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rpc); err != nil {
		t.Fatalf("body is not JSON-RPC: %v\n%s", err, rr.Body.String())
	}
	if rpc.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", rpc.JSONRPC)
	}
	if !rpc.Result.IsError {
		t.Error("result.isError = false, want true")
	}
	if len(rpc.Result.Content) != 1 || rpc.Result.Content[0].Type != "text" {
		t.Fatalf("result.content = %+v, want one text item", rpc.Result.Content)
	}
	var env rateLimitEnvelope
	if err := json.Unmarshal([]byte(rpc.Result.Content[0].Text), &env); err != nil {
		t.Fatalf("result.content[0].text is not the envelope: %v\n%s", err, rpc.Result.Content[0].Text)
	}
	return env
}

// assertPerMinuteAnswer asserts the ruled per-minute answer: 429, Retry-After
// 60, the per_minute headers, and the envelope with this limit and tier.
func assertPerMinuteAnswer(t *testing.T, rr *httptest.ResponseRecorder, tier string, limit int) {
	t.Helper()
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60", got)
	}
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != LimitTypePerMinute {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, LimitTypePerMinute)
	}
	if got := rr.Header().Get("X-Axonflow-Upgrade-URL"); got != v1ProUpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL = %q, want %q", got, v1ProUpgradeCompareURL)
	}
	env := decodeMCPEnvelope(t, rr)
	if env.LimitType != LimitTypePerMinute {
		t.Errorf("envelope.limit_type = %q, want %q", env.LimitType, LimitTypePerMinute)
	}
	if env.Window != "minute" {
		t.Errorf("envelope.window = %q, want minute", env.Window)
	}
	if env.Tier != tier {
		t.Errorf("envelope.tier = %q, want %q", env.Tier, tier)
	}
	if env.Limit != limit {
		t.Errorf("envelope.limit = %d, want %d", env.Limit, limit)
	}
	if env.Remaining != 0 {
		t.Errorf("envelope.remaining = %d, want 0", env.Remaining)
	}
	if env.ResetsAt == nil {
		t.Fatal("envelope.resets_at missing: a hook throttles by it before it reads Retry-After")
	}
	if until := time.Until(*env.ResetsAt); until < 50*time.Second || until > 61*time.Second {
		t.Errorf("envelope.resets_at is %v away, want about a minute (not midnight)", until)
	}
	if env.Error == "" || env.Error != env.Upgrade.Wording {
		t.Errorf("envelope.error %q and upgrade.wording %q must be the same non-empty text", env.Error, env.Upgrade.Wording)
	}
	if env.Upgrade.CompareURL != v1ProUpgradeCompareURL || env.Upgrade.BuyURL != v1ProUpgradeBuyURL {
		t.Errorf("envelope.upgrade URLs = %q, %q", env.Upgrade.CompareURL, env.Upgrade.BuyURL)
	}
}

func TestWriteMinuteRateLimitErrorJSONRPC_AnswersTheRuledShape(t *testing.T) {
	pinMinuteLimits(t)
	rr := httptest.NewRecorder()
	writeMinuteRateLimitErrorJSONRPC(rr, "id-4261", "cs_t", "Free", 25, 60)
	assertPerMinuteAnswer(t, rr, "Free", 25)
}

func TestPerMinuteWordingNamesProOnlyToAFreeCaller(t *testing.T) {
	pinMinuteLimits(t)
	cases := []struct {
		tier  string
		limit int
		want  string
	}{
		{"Free", 25, "Per-minute limit reached on Free tier (25 requests). Pro raises this to 200/min. Try again in a minute."},
		{"Pro", 200, "Per-minute limit reached (200 requests). Try again in a minute."},
		{"Premium", 200, "Per-minute limit reached (200 requests). Try again in a minute."},
		// The pre-credential limiter runs before the tier is known.
		{"", 200, "Per-minute limit reached (200 requests). Try again in a minute."},
	}
	for _, tc := range cases {
		if got := renderPerMinuteWording(tc.tier, tc.limit); got != tc.want {
			t.Errorf("renderPerMinuteWording(%q, %d) = %q, want %q", tc.tier, tc.limit, got, tc.want)
		}
		if len(tc.want) > 200 {
			t.Errorf("wording for %q is %d chars; the envelope wordings stay under 200", tc.tier, len(tc.want))
		}
	}
}

// A session built for this request (the hooks send no Mcp-Session-Id) was
// already counted by Authenticate's pre-credential limiter. Before #4261 the
// cap counted it again, so a Free tenant was refused at its 13th call.
func TestEnforceMCPSessionDailyCap_ASessionBuiltForTheRequestIsCountedOnce(t *testing.T) {
	pinMinuteLimits(t)
	stubDailyChecker(t, func(context.Context, string, int, *sql.DB) error { return nil })
	key := "cs_4261_counted_once"
	useRateLimitKey(t, key)

	for call := 1; call <= 26; call++ {
		// What Authenticate's pre-credential limiter does on this request.
		if err := checkRateLimitRedis(context.Background(), key, 200); err != nil {
			t.Fatalf("call %d: the pre-credential limiter refused under 200: %v", call, err)
		}
		rr := httptest.NewRecorder()
		session := &mcpSession{tenantID: key, tier: "Free", authenticatedThisRequest: true}
		blocked := enforceMCPSessionDailyCap(rr, &jsonRPCRequest{ID: call}, session)

		if got := rateLimitCount(key); got != call {
			t.Fatalf("after call %d the count is %d, want %d: each call is counted once", call, got, call)
		}
		if call <= 25 {
			if blocked {
				t.Fatalf("call %d was refused under the Free limit of 25", call)
			}
			continue
		}
		if !blocked {
			t.Fatal("call 26 was allowed past the Free limit of 25")
		}
		assertPerMinuteAnswer(t, rr, "Free", 25)
	}
}

// A cached MCP-protocol session skips Authenticate, so the cap is what
// counts its calls.
func TestEnforceMCPSessionDailyCap_ACachedSessionIsCountedByTheCap(t *testing.T) {
	pinMinuteLimits(t)
	stubDailyChecker(t, func(context.Context, string, int, *sql.DB) error { return nil })
	key := "cs_4261_cached_session"
	useRateLimitKey(t, key)

	for call := 1; call <= 26; call++ {
		rr := httptest.NewRecorder()
		session := &mcpSession{tenantID: key, tier: "Free"}
		blocked := enforceMCPSessionDailyCap(rr, &jsonRPCRequest{ID: call}, session)

		if got := rateLimitCount(key); got != call {
			t.Fatalf("after call %d the count is %d, want %d: the cap counts a cached session's call", call, got, call)
		}
		if call <= 25 {
			if blocked {
				t.Fatalf("call %d was refused under the Free limit of 25", call)
			}
			continue
		}
		if !blocked {
			t.Fatal("call 26 was allowed past the Free limit of 25")
		}
		assertPerMinuteAnswer(t, rr, "Free", 25)
	}
}

// The minute branch answers per_minute, never the daily envelope (before
// #4261 it sent daily_quota, resets at midnight, for a one-minute limit).
func TestEnforceMCPSessionDailyCap_TheMinuteBranchAnswersPerMinute(t *testing.T) {
	pinMinuteLimits(t)
	stubDailyChecker(t, func(context.Context, string, int, *sql.DB) error {
		t.Fatal("the daily checker ran after the minute limit refused the call")
		return nil
	})
	key := "cs_4261_minute_branch"
	useRateLimitKey(t, key)
	seedRateLimitCount(key, 100)

	rr := httptest.NewRecorder()
	if !enforceMCPSessionDailyCap(rr, &jsonRPCRequest{ID: "m"}, &mcpSession{tenantID: key, tier: "Free", authenticatedThisRequest: true}) {
		t.Fatal("a count of 100 was allowed past the Free limit of 25")
	}
	assertPerMinuteAnswer(t, rr, "Free", 25)
	if strings.Contains(rr.Body.String(), LimitTypeDailyQuota) {
		t.Errorf("the per-minute answer mentions %s:\n%s", LimitTypeDailyQuota, rr.Body.String())
	}
}

// A credential the pre-credential limiter refuses is answered 429 with its
// Retry-After and the per-minute envelope on every method that
// authenticates. Before #4261 it was flattened into the 401 "Authentication
// required", which reads as a bad credential, not a limit.
func TestMCPServer_ARateLimitedCredentialIsAnswered429NotAuthRequired(t *testing.T) {
	pinMinuteLimits(t)
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	clientID := "cs_4261_rate_limited_client"
	useRateLimitKey(t, clientID)
	seedRateLimitCount(clientID, 200) // the next request is the 201st
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":never-checked-past-the-limiter"))
	router := setupMCPServerRouter()

	for _, method := range []string{"initialize", "tools/list", "tools/call"} {
		t.Run(method, func(t *testing.T) {
			var params interface{}
			if method == "tools/call" {
				params = map[string]interface{}{"name": "check_policy", "arguments": map[string]interface{}{"statement": "ls"}}
			}
			w := mcpServerPost(t, router, method, "rl-"+method, params, "Authorization", basic)
			if got := w.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("a rate-limited credential got the 401 challenge %q", got)
			}
			assertPerMinuteAnswer(t, w, "", 200)
		})
	}
}

// The control: a refusal that is not a rate limit keeps the 401 and -32001.
func TestMCPServer_AMissingCredentialIsStillAnswered401(t *testing.T) {
	pinMinuteLimits(t)
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	router := setupMCPServerRouter()

	for _, method := range []string{"initialize", "tools/list", "tools/call"} {
		t.Run(method, func(t *testing.T) {
			w := mcpServerPost(t, router, method, "noauth-"+method, nil)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401\n%s", w.Code, w.Body.String())
			}
			resp := parseJSONRPCResponse(t, w)
			if resp.Error == nil || resp.Error.Code != jsonRPCAuthError {
				t.Errorf("error = %+v, want code %d", resp.Error, jsonRPCAuthError)
			}
		})
	}
}

// Only a session built for the request is marked as already counted; a
// session created by initialize and served from the cache is not.
func TestResolveMCPSession_MarksOnlyASessionBuiltForTheRequest(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	built, err := resolveMCPSessionWithErr(httptest.NewRequest("POST", "/api/v1/mcp-server", nil))
	if err != nil || built == nil {
		t.Fatalf("a request with no session header resolved to (%v, %v)", built, err)
	}
	if !built.authenticatedThisRequest {
		t.Error("a session built for the request is not marked: the cap would count the request a second time")
	}

	sessionID := initMCPSession(t, setupMCPServerRouter())
	cachedReq := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	cachedReq.Header.Set(mcpSessionHeaderKey, sessionID)
	cached, err := resolveMCPSessionWithErr(cachedReq)
	if err != nil || cached == nil {
		t.Fatalf("the initialized session resolved to (%v, %v)", cached, err)
	}
	if cached.authenticatedThisRequest {
		t.Error("a cached session is marked: the cap would never count its calls")
	}
}

// detailsNaming matches the policy_details JSONB of an audit row that names
// exactly one policy id and one reason.
type detailsNaming struct{ policyID, reason string }

func (m detailsNaming) Match(v driver.Value) bool {
	var b []byte
	switch x := v.(type) {
	case []byte:
		b = x
	case string:
		b = []byte(x)
	default:
		return false
	}
	var d struct {
		PolicyIDs []string `json:"policy_ids"`
		Reasons   []string `json:"reasons"`
	}
	if json.Unmarshal(b, &d) != nil {
		return false
	}
	return len(d.PolicyIDs) == 1 && d.PolicyIDs[0] == m.policyID && len(d.Reasons) == 1 && d.Reasons[0] == m.reason
}

// cacheMCPSession puts a session in the cache as initialize does, and removes
// it afterwards.
func cacheMCPSession(t *testing.T, s *mcpSession) {
	t.Helper()
	mcpSessionsMu.Lock()
	mcpSessions[s.id] = s
	mcpSessionsMu.Unlock()
	t.Cleanup(func() {
		mcpSessionsMu.Lock()
		delete(mcpSessions, s.id)
		mcpSessionsMu.Unlock()
	})
}

// A tools/call refused by a Community SaaS limit is audited as a blocked row
// naming the limit that refused it: per_minute for the minute branch,
// daily_cap for the daily quota. Before #4261 a per-minute refusal was
// recorded as "daily usage cap exceeded" / daily_cap.
func TestHandleMCPToolsCall_ALimitRefusalIsAuditedAsTheLimitThatRefused(t *testing.T) {
	cases := []struct {
		name, policyID, reason string
		seedCount              int
		daily                  error
	}{
		{"per_minute", "per_minute", "per-minute rate limit exceeded", 100, nil},
		{"daily_quota", "daily_cap", "daily usage cap exceeded", 0, ErrDailyLimitExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pinMinuteLimits(t)
			t.Setenv("DEPLOYMENT_MODE", "community-saas")
			key := "cs_4261_audit_" + tc.name
			useRateLimitKey(t, key)
			if tc.seedCount > 0 {
				seedRateLimitCount(key, tc.seedCount)
			}
			stubDailyChecker(t, func(context.Context, string, int, *sql.DB) error { return tc.daily })

			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			origDB := usageDB
			usageDB = db
			defer func() { usageDB = origDB }()
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(), key, key, key,
					"mcp_tools_call", "mcp tools/call: check_policy", sqlmock.AnyArg(),
					mcpVerdictBlocked,
					detailsNaming{tc.policyID, tc.reason},
					sqlmock.AnyArg(), PlaneMCP,
					nil, nil, nil,
					sqlmock.AnyArg(),
				).
				WillReturnResult(sqlmock.NewResult(1, 1))

			now := time.Now()
			sessionID := "sess-4261-audit-" + tc.name
			cacheMCPSession(t, &mcpSession{id: sessionID, createdAt: now, lastUsed: now,
				tenantID: key, orgID: key, clientID: key, userEmail: "u@e.com", userRole: "user", tier: "Free"})
			w := mcpServerPost(t, setupMCPServerRouter(), "tools/call", "audit-"+tc.name,
				map[string]interface{}{"name": "check_policy", "arguments": map[string]interface{}{"connector_type": "claude_code", "statement": "ls"}},
				mcpSessionHeaderKey, sessionID)
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429\n%s", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the refusal was not audited as %s: %v", tc.policyID, err)
			}
		})
	}
}

// A tools/call the pre-credential limiter refuses is audited as the
// per-minute refusal it was answered with, under the unauthenticated tenant
// sentinel since the credential was never checked, not as "authentication
// required".
func TestHandleMCPToolsCall_ARateLimitedCredentialIsAuditedAsPerMinute(t *testing.T) {
	pinMinuteLimits(t)
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	clientID := "cs_4261_audit_precredential"
	useRateLimitKey(t, clientID)
	seedRateLimitCount(clientID, 200) // the next request is the 201st

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 0,
			sqlmock.AnyArg(), "service", clientID,
			mcpUnauthenticatedTenant, "",
			"mcp_tools_call", "mcp tools/call: rate limited before authentication", sqlmock.AnyArg(),
			mcpVerdictBlocked,
			detailsNaming{LimitTypePerMinute, "per-minute rate limit exceeded"},
			sqlmock.AnyArg(), PlaneMCP,
			nil, nil, nil,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":never-checked-past-the-limiter"))
	w := mcpServerPost(t, setupMCPServerRouter(), "tools/call", "rl-audit",
		map[string]interface{}{"name": "check_policy", "arguments": map[string]interface{}{"connector_type": "claude_code", "statement": "ls"}},
		"Authorization", basic)
	assertPerMinuteAnswer(t, w, "", 200)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the pre-credential refusal was not audited as per_minute: %v", err)
	}
}

// While Redis fails, the limiter counts in memory, and the per-minute count is
// read from there, so a sessionless Free tenant is still refused at its 26th
// call. Before, the read answered 0 and every such call was let through for
// as long as Redis failed.
func TestRateLimitCount_ReadsTheInMemoryCountWhileRedisFails(t *testing.T) {
	pinMinuteLimits(t)
	stubDailyChecker(t, func(context.Context, string, int, *sql.DB) error { return nil })
	failing := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	t.Cleanup(func() { _ = failing.Close() })
	orig := redisClient
	redisClient = failing
	t.Cleanup(func() { redisClient = orig })
	key := "cs_4261_redis_down"
	useRateLimitKey(t, key)

	for call := 1; call <= 26; call++ {
		// Authenticate's pre-credential limiter, falling back to memory.
		_ = checkRateLimitRedis(context.Background(), key, 200)
		rr := httptest.NewRecorder()
		blocked := enforceMCPSessionDailyCap(rr, &jsonRPCRequest{ID: call}, &mcpSession{tenantID: key, tier: "Free", authenticatedThisRequest: true})
		if got := rateLimitCount(key); got != call {
			t.Fatalf("after call %d the count read while Redis fails is %d, want %d", call, got, call)
		}
		if call <= 25 && blocked {
			t.Fatalf("call %d was refused under the Free limit of 25", call)
		}
		if call == 26 && !blocked {
			t.Fatal("call 26 was allowed past the Free limit of 25 while Redis failed")
		}
	}
}

// A session DELETE whose credential the pre-credential limiter refuses keeps
// the 429 and Retry-After, and is audited as per_minute; before #4261 it was a
// bare 401 audited as unauthenticated. The session stays.
func TestMCPSessionDelete_ARateLimitedCredentialIsAnswered429(t *testing.T) {
	pinMinuteLimits(t)
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	clientID := "cs_4261_delete_rate_limited"
	useRateLimitKey(t, clientID)
	seedRateLimitCount(clientID, 200)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), clientID, clientID, clientID,
			"mcp_session_delete", sqlmock.AnyArg(), sqlmock.AnyArg(),
			mcpVerdictBlocked,
			detailsNaming{LimitTypePerMinute, "per-minute rate limit exceeded"},
			sqlmock.AnyArg(), PlaneMCP,
			nil, nil, nil,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	now := time.Now()
	sessionID := "sess-4261-delete"
	cacheMCPSession(t, &mcpSession{id: sessionID, createdAt: now, lastUsed: now,
		tenantID: clientID, orgID: clientID, clientID: clientID, tier: "Free"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mcp-server", nil)
	req.Header.Set(mcpSessionHeaderKey, sessionID)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":never-checked-past-the-limiter")))
	w := httptest.NewRecorder()
	setupMCPServerRouter().ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60", got)
	}
	if getSessionByID(sessionID) == nil {
		t.Error("a refused DELETE removed the session")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the refused DELETE was not audited as per_minute: %v", err)
	}
}
