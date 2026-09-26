// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4254: the LLM routing hints (#883) move from the dynamic engine's verdict into
// the fact layer, merged by one function in the order evaluation walks the rows.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"axonflow/platform/decision/legacycompile"
)

const routeTestOrg = "org-route"

// routeRow is one cached dynamic_policies row carrying a route action, in the
// shape refreshPolicies stores. nil conditions leave the key out, so the row
// applies to every request (vacuous truth, as evaluation reads it).
func routeRow(id string, priority int, createdAt time.Time, conditions []PolicyCondition, config map[string]interface{}) map[string]interface{} {
	actions, _ := json.Marshal([]PolicyAction{{Type: "route", Config: config}})
	row := map[string]interface{}{
		"policy_id": id,
		"name":      id,
		"type":      "content",
		"actions":   json.RawMessage(actions),
		"tenant_id": "global",
		"priority":  priority,
		"_metadata": map[string]interface{}{
			"id":         id,
			"name":       id,
			"tenant_id":  "global",
			"org_id":     routeTestOrg,
			"priority":   priority,
			"created_at": createdAt,
		},
	}
	if conditions != nil {
		raw, _ := json.Marshal(conditions)
		row["conditions"] = json.RawMessage(raw)
	}
	return row
}

// routeTestRows is the dynamic engine's organization-scoped list over cached
// rows: the production row source of the fact producer, and the one place this
// file names the engine.
func routeTestRows(cached map[string]interface{}) dynamicFactRows {
	return &DatabaseDynamicPolicyEngine{policies: cached}
}

// routeProducerOver is a fact producer over rows, with segment resolution
// stubbed to "none".
func routeProducerOver(t *testing.T, rows dynamicFactRows, presentsNoContent bool) *dynamicFactProducer {
	t.Helper()
	p, err := newDynamicFactProducer(rows)
	if err != nil {
		t.Fatalf("newDynamicFactProducer: %v", err)
	}
	p.segments = func(context.Context, string, string) ([]string, bool) { return nil, true }
	p.presentsNoContent = presentsNoContent
	return p
}

func routeRequest(query, requestType string) OrchestratorRequest {
	return OrchestratorRequest{
		RequestID:   "req-route",
		Query:       query,
		RequestType: requestType,
		Client:      ClientContext{OrgID: routeTestOrg},
		User:        UserContext{OrgID: routeTestOrg},
	}
}

func routesFor(t *testing.T, p *dynamicFactProducer, req OrchestratorRequest) routeEffects {
	t.Helper()
	_, routes, err := p.Produce(context.Background(), req)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	return routes
}

// The list the fact producer reads comes back in the order evaluation walks the
// rows: priority descending, then newest first. It used to range over a map, so
// its order changed between calls. Looped, because a randomized order agrees
// with the expected one by chance on any single call.
func TestTheTenantListWalksRowsInEvaluationOrder(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rows := routeTestRows(map[string]interface{}{
		"r-low-old": routeRow("r-low-old", 10, t0, nil, map[string]interface{}{"preferred_provider": "a"}),
		"r-high":    routeRow("r-high", 100, t0, nil, map[string]interface{}{"preferred_provider": "b"}),
		"r-low-new": routeRow("r-low-new", 10, t0.Add(time.Hour), nil, map[string]interface{}{"preferred_provider": "c"}),
		"r-mid":     routeRow("r-mid", 50, t0, nil, map[string]interface{}{"preferred_provider": "d"}),
	})
	want := []string{"r-high", "r-mid", "r-low-new", "r-low-old"}
	for i := 0; i < 50; i++ {
		var got []string
		for _, row := range rows.ListActivePoliciesForTenant(routeTestOrg, nil) {
			got = append(got, row.ID)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: list order = %v, want evaluation order %v", i, got, want)
		}
	}
}

// THE SHIPPED WINNER RULE, PRESERVED ON PURPOSE: each applying route row
// overwrites the preferred provider and the reason in evaluation order, so the
// last one wins, which is the lowest priority. Whether the highest should win is
// decided in v11.1.0:
// https://github.com/getaxonflow/axonflow-enterprise/issues/4249#issuecomment-5668036520
// Looped 50 times so an unordered walk, which picks either row, cannot pass.
func TestTheLastApplyingRouteRowInEvaluationOrderWinsThePreferredProvider(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rows := routeTestRows(map[string]interface{}{
		"route-high": routeRow("route-high", 100, t0, nil, map[string]interface{}{"preferred_provider": "openai", "reason": "high priority"}),
		"route-low":  routeRow("route-low", 10, t0, nil, map[string]interface{}{"preferred_provider": "anthropic", "reason": "low priority"}),
	})
	p := routeProducerOver(t, rows, false)
	for i := 0; i < 50; i++ {
		routes := routesFor(t, p, routeRequest("hello", "chat"))
		if routes.PreferredProvider != "anthropic" || routes.RoutingReason != "low priority" {
			t.Fatalf("run %d: preferred=%q reason=%q, want the last applying row's (anthropic, low priority)",
				i, routes.PreferredProvider, routes.RoutingReason)
		}
	}
}

// allowed_providers intersect across every applying row, as a sorted set: the
// list no longer follows the first row's order, because every reader of it
// (llm/router.go's filter, fallback and preferred-provider check) reads
// membership only, and a set is what makes the merge order-independent
// (#4249 row 5698088094).
func TestApplyingRouteRowsIntersectTheirAllowedProviders(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rows := routeTestRows(map[string]interface{}{
		"allow-wide":   routeRow("allow-wide", 100, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"openai", "anthropic", "bedrock"}}),
		"allow-narrow": routeRow("allow-narrow", 10, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"bedrock", "openai"}}),
	})
	p := routeProducerOver(t, rows, false)
	for i := 0; i < 50; i++ {
		routes := routesFor(t, p, routeRequest("hello", "chat"))
		if want := []string{"bedrock", "openai"}; !reflect.DeepEqual(routes.AllowedProviders, want) || !routes.Restricted || routes.NothingPermitted() {
			t.Fatalf("run %d: allowed providers = %v, want the intersection %v", i, routes.AllowedProviders, want)
		}
	}
}

// A route row applies only when every one of its conditions holds.
func TestARouteRowWhoseConditionFailsSteersNothing(t *testing.T) {
	if legacycompile.IsContentOperator("equals") {
		t.Fatal("PREMISE: equals is a content operator, so this row would test the content path instead")
	}
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rows := routeTestRows(map[string]interface{}{
		"route-batch": routeRow("route-batch", 100, t0,
			[]PolicyCondition{{Field: "request_type", Operator: "equals", Value: "batch"}},
			map[string]interface{}{"preferred_provider": "bedrock", "allowed_providers": []interface{}{"bedrock"}}),
	})
	p := routeProducerOver(t, rows, false)

	if routes := routesFor(t, p, routeRequest("hello", "batch")); routes.PreferredProvider != "bedrock" {
		t.Fatalf("PREMISE: the row does not steer a request its condition holds for (preferred=%q)", routes.PreferredProvider)
	}
	routes := routesFor(t, p, routeRequest("hello", "chat"))
	if routes.PreferredProvider != "" || len(routes.AllowedProviders) != 0 || routes.RoutingReason != "" {
		t.Errorf("a row whose condition fails steered the request: %+v", routes)
	}
}

// A route row conditioned on content never steers on a plane that presents no
// content: the producer states its content conditions false there, and a row
// applies only when all of them hold.
func TestAContentConditionedRouteRowNeverSteersOnANoContentPlane(t *testing.T) {
	if !legacycompile.IsContentOperator("contains") {
		t.Fatal("PREMISE: contains is not a content operator, so this row does not test the content path")
	}
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rows := routeTestRows(map[string]interface{}{
		"route-content": routeRow("route-content", 100, t0,
			[]PolicyCondition{{Field: "query", Operator: "contains", Value: "route-me"}},
			map[string]interface{}{"preferred_provider": "openai"}),
	})
	req := routeRequest("please route-me now", "chat")

	if routes := routesFor(t, routeProducerOver(t, rows, false), req); routes.PreferredProvider != "openai" {
		t.Fatalf("PREMISE: on a plane that presents the query, the row does not steer (preferred=%q)", routes.PreferredProvider)
	}
	if routes := routesFor(t, routeProducerOver(t, rows, true), req); routes.PreferredProvider != "" {
		t.Errorf("a content-conditioned route row steered a plane that presents no content: preferred=%q", routes.PreferredProvider)
	}
}

// allowedProvidersConfig is a route action config declaring providers.
func allowedProvidersConfig(providers ...string) map[string]interface{} {
	list := make([]interface{}, 0, len(providers))
	for _, p := range providers {
		list = append(list, p)
	}
	return map[string]interface{}{"allowed_providers": list}
}

// permutations returns every ordering of n indexes.
func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, rest := range permutations(n - 1) {
		for i := 0; i <= len(rest); i++ {
			perm := append(append(append([]int{}, rest[:i]...), n-1), rest[i:]...)
			out = append(out, perm)
		}
	}
	return out
}

// THE MERGE, FIELD BY FIELD (#4249 row 5698088094). Each case applies its
// configs in EVERY order and asserts one result, so a merge whose outcome
// depends on the order rows are walked in cannot pass. The retired rule replaced
// an empty intersection with the next row's list: "disjoint pair" came out
// unrestricted and "disjoint pair then a third" came out as the third row's list.
func TestTheRouteMergeIsOneSetInEveryOrder(t *testing.T) {
	type want struct {
		allowed          []string
		restricted       bool
		nothingPermitted bool
	}
	cases := []struct {
		name    string
		configs []map[string]interface{}
		want    want
	}{
		{"no route config", []map[string]interface{}{{}}, want{nil, false, false}},
		{"absent key beside a preference", []map[string]interface{}{{"preferred_provider": "openai"}}, want{nil, false, false}},
		{"one row", []map[string]interface{}{allowedProvidersConfig("openai", "anthropic")}, want{[]string{"anthropic", "openai"}, true, false}},
		{"one row with a duplicate", []map[string]interface{}{allowedProvidersConfig("openai", "openai")}, want{[]string{"openai"}, true, false}},
		{"declared empty alone", []map[string]interface{}{allowedProvidersConfig()}, want{nil, false, false}},
		{"declared empty beside a restriction", []map[string]interface{}{allowedProvidersConfig(), allowedProvidersConfig("ollama")}, want{[]string{"ollama"}, true, false}},
		{"two overlapping", []map[string]interface{}{allowedProvidersConfig("openai", "anthropic", "bedrock"), allowedProvidersConfig("bedrock", "openai")}, want{[]string{"bedrock", "openai"}, true, false}},
		{"two disjoint", []map[string]interface{}{allowedProvidersConfig("anthropic"), allowedProvidersConfig("openai")}, want{[]string{}, true, true}},
		{"a disjoint pair and a third", []map[string]interface{}{allowedProvidersConfig("anthropic"), allowedProvidersConfig("openai"), allowedProvidersConfig("ollama")}, want{[]string{}, true, true}},
		{"a disjoint pair, a third and a declared empty", []map[string]interface{}{allowedProvidersConfig("anthropic"), allowedProvidersConfig("openai"), allowedProvidersConfig("ollama"), allowedProvidersConfig()}, want{[]string{}, true, true}},
		{"three that share one", []map[string]interface{}{allowedProvidersConfig("a", "b", "c"), allowedProvidersConfig("c", "b"), allowedProvidersConfig("b", "d")}, want{[]string{"b"}, true, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, perm := range permutations(len(tc.configs)) {
				var r routeEffects
				for _, i := range perm {
					r.apply(tc.configs[i])
				}
				if r.Restricted != tc.want.restricted || r.NothingPermitted() != tc.want.nothingPermitted {
					t.Errorf("order %v: restricted=%v nothingPermitted=%v, want %v and %v",
						perm, r.Restricted, r.NothingPermitted(), tc.want.restricted, tc.want.nothingPermitted)
				}
				if len(tc.want.allowed) == 0 {
					if len(r.AllowedProviders) != 0 {
						t.Errorf("order %v: allowed providers = %v, want none", perm, r.AllowedProviders)
					}
				} else if !reflect.DeepEqual(r.AllowedProviders, tc.want.allowed) {
					t.Errorf("order %v: allowed providers = %v, want %v", perm, r.AllowedProviders, tc.want.allowed)
				}
			}
		})
	}
}

// Through the fact producer: rows whose allowed_providers share no provider
// permit nothing, whatever their priorities, and a third row does not restore a
// restriction of its own. Every assignment of the three priorities is walked, so
// the rows are merged in every order evaluation can walk them in.
func TestDisjointRouteRowsPermitNothingInEveryEvaluationOrder(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	priorities := []int{100, 50, 10}
	lists := [][]interface{}{{"anthropic"}, {"openai"}, {"ollama"}}
	for _, perm := range permutations(3) {
		cached := map[string]interface{}{}
		for i, id := range []string{"route-a", "route-b", "route-c"} {
			cached[id] = routeRow(id, priorities[perm[i]], t0, nil, map[string]interface{}{"allowed_providers": lists[i]})
		}
		routes := routesFor(t, routeProducerOver(t, routeTestRows(cached), false), routeRequest("hello", "chat"))
		if !routes.NothingPermitted() || len(routes.AllowedProviders) != 0 {
			t.Errorf("priorities %v: routes = %+v, want nothing permitted", perm, routes)
		}
	}

	// CONTROL: one of the three alone restricts to its own list.
	routes := routesFor(t, routeProducerOver(t, routeTestRows(map[string]interface{}{
		"route-c": routeRow("route-c", 10, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"ollama"}}),
	}), false), routeRequest("hello", "chat"))
	if routes.NothingPermitted() || !reflect.DeepEqual(routes.AllowedProviders, []string{"ollama"}) {
		t.Errorf("one row: routes = %+v, want restricted to [ollama]", routes)
	}
}

// THE PREVIEW PATH (DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies, reached
// from the test-policy and simulation handlers) merges with the same function
// and answers restrictions that permit nothing the way the route-request seam
// does: Allowed=false, with the reason. The rows are walked in every priority
// order.
func TestThePreviewRefusesRouteRowsThatPermitNothing(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	preview := func(cached map[string]interface{}) *PolicyEvaluationResult {
		engine := &DatabaseDynamicPolicyEngine{policies: cached, cacheTimeout: 30 * time.Second, lastRefresh: time.Now()}
		return engine.EvaluateDynamicPolicies(context.Background(), routeRequest("hello", "chat"))
	}
	refusal := "blocked: " + reasonNoCompliantProvider
	priorities := []int{100, 50, 10}
	lists := [][]interface{}{{"anthropic"}, {"openai"}, {"ollama"}}
	for _, perm := range permutations(3) {
		cached := map[string]interface{}{}
		for i, id := range []string{"route-a", "route-b", "route-c"} {
			cached[id] = routeRow(id, priorities[perm[i]], t0, nil, map[string]interface{}{"allowed_providers": lists[i]})
		}
		result := preview(cached)
		if result.Allowed || len(result.AllowedProviders) != 0 || !containsString(result.RequiredActions, refusal) {
			t.Errorf("priorities %v: allowed=%v allowed_providers=%v required=%v, want refused with %q",
				perm, result.Allowed, result.AllowedProviders, result.RequiredActions, refusal)
		}
	}

	// CONTROL: overlapping rows are admitted, restricted to what they share.
	result := preview(map[string]interface{}{
		"route-a": routeRow("route-a", 100, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"openai", "ollama"}}),
		"route-b": routeRow("route-b", 10, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"ollama"}}),
	})
	if !result.Allowed || !reflect.DeepEqual(result.AllowedProviders, []string{"ollama"}) || containsString(result.RequiredActions, refusal) {
		t.Errorf("overlapping rows: allowed=%v allowed_providers=%v required=%v, want admitted with [ollama]",
			result.Allowed, result.AllowedProviders, result.RequiredActions)
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// segmentRouteRow is routeRow scoped to segment (empty = unsegmented) and
// optionally to another organization.
func segmentRouteRow(id, org, segment string, priority int, providers ...string) map[string]interface{} {
	list := make([]interface{}, 0, len(providers))
	for _, p := range providers {
		list = append(list, p)
	}
	row := routeRow(id, priority, time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC), nil, map[string]interface{}{"allowed_providers": list})
	metadata := row["_metadata"].(map[string]interface{})
	metadata["org_id"] = org
	if segment != "" {
		metadata["segment_id"] = segment
	}
	return row
}

// conditionedSegmentRouteRow is segmentRouteRow in this test's organization,
// applying only to requests of requestType.
func conditionedSegmentRouteRow(id, segment string, priority int, requestType string, providers ...string) map[string]interface{} {
	row := segmentRouteRow(id, routeTestOrg, segment, priority, providers...)
	raw, _ := json.Marshal([]PolicyCondition{{Field: "request_type", Operator: "equals", Value: requestType}})
	row["conditions"] = json.RawMessage(raw)
	return row
}

func policyIDs(rows []DynamicPolicy) []string {
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// THE EVERY-SEGMENT LIST (ADR-067 step 1b): an organization's unsegmented rows
// and every one of its segment-scoped rows, never another organization's, and
// the established list over the same cache unchanged beside it.
func TestTheEverySegmentListAppliesEverySegmentOfTheOrganizationOnly(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{policies: map[string]interface{}{
		"unsegmented":       segmentRouteRow("unsegmented", routeTestOrg, "", 100, "ollama", "anthropic"),
		"finance":           segmentRouteRow("finance", routeTestOrg, "seg-finance", 50, "anthropic"),
		"engineering":       segmentRouteRow("engineering", routeTestOrg, "seg-engineering", 10, "ollama"),
		"other-org-segment": segmentRouteRow("other-org-segment", "org-other", "seg-other", 10, "openai"),
		"other-org":         segmentRouteRow("other-org", "org-other", "", 10, "openai"),
	}}
	if got, want := policyIDs(engine.ListActivePoliciesForOrgInEverySegment(routeTestOrg)), []string{"engineering", "finance", "unsegmented"}; !reflect.DeepEqual(got, want) {
		t.Errorf("every-segment rows = %v, want %v", got, want)
	}
	// ESTABLISHED, UNCHANGED: the predicate selects by the caller's segments.
	for _, tc := range []struct {
		segments []string
		want     []string
	}{
		{nil, []string{"unsegmented"}},
		{[]string{"seg-finance"}, []string{"finance", "unsegmented"}},
		{[]string{"seg-finance", "seg-engineering"}, []string{"engineering", "finance", "unsegmented"}},
		{[]string{"seg-other"}, []string{"unsegmented"}},
	} {
		if got := policyIDs(engine.ListActivePoliciesForTenant(routeTestOrg, tc.segments)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("established rows for %v = %v, want %v", tc.segments, got, tc.want)
		}
	}
}

// THE 1b CELLS, through the fact producer over the engine. alice resolves to
// seg-finance. Each cell states which rows apply and the route effect:
// established selects by segment as before; a non-empty email that is not
// established (no marker, or a context that never passed proxy auth) gets
// every segment's rows and is never resolved; an empty email is the anonymous
// baseline (unsegmented rows only) either way. Every DEPLOYMENT_MODE on this
// build answers the same: nothing here reads the mode.
func TestSegmentMembershipNotEstablishedAppliesEverySegmentsRouteRows(t *testing.T) {
	type rowsCase struct {
		name string
		rows map[string]interface{}
		// established effect for alice (seg-finance), not-established effect, and
		// the anonymous (no email) effect; nil = unrestricted, [] = nothing permitted.
		established, notEstablished, anonymous []string
	}
	cases := []rowsCase{
		{"unsegmented only", map[string]interface{}{
			"u": segmentRouteRow("u", routeTestOrg, "", 100, "ollama"),
		}, []string{"ollama"}, []string{"ollama"}, []string{"ollama"}},
		{"one segment row", map[string]interface{}{
			"f": segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic"),
		}, []string{"anthropic"}, []string{"anthropic"}, nil},
		{"one row of another segment", map[string]interface{}{
			"e": segmentRouteRow("e", routeTestOrg, "seg-engineering", 100, "ollama"),
		}, nil, []string{"ollama"}, nil},
		{"two segment rows, disjoint", map[string]interface{}{
			"f": segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic"),
			"e": segmentRouteRow("e", routeTestOrg, "seg-engineering", 10, "ollama"),
		}, []string{"anthropic"}, []string{}, nil},
		{"two segment rows, overlapping", map[string]interface{}{
			"f": segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic", "ollama"),
			"e": segmentRouteRow("e", routeTestOrg, "seg-engineering", 10, "ollama"),
		}, []string{"anthropic", "ollama"}, []string{"ollama"}, nil},
	}
	check := func(t *testing.T, what string, routes routeEffects, want []string) {
		t.Helper()
		switch {
		case want == nil:
			if routes.Restricted {
				t.Errorf("%s: routes = %+v, want unrestricted", what, routes)
			}
		case len(want) == 0:
			if !routes.NothingPermitted() {
				t.Errorf("%s: routes = %+v, want nothing permitted", what, routes)
			}
		default:
			if !routes.Restricted || !reflect.DeepEqual(routes.AllowedProviders, want) {
				t.Errorf("%s: routes = %+v, want restricted to %v", what, routes, want)
			}
		}
	}
	for _, mode := range []string{"", "community", "community-saas", "in-vpc-enterprise", "saas"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				t.Setenv("DEPLOYMENT_MODE", mode)
				p := routeProducerOver(t, routeTestRows(tc.rows), false)
				resolved := 0
				p.segments = func(_ context.Context, _, email string) ([]string, bool) {
					if email != "" {
						resolved++
					}
					if email == "alice@example.com" {
						return []string{"seg-finance"}, true
					}
					return nil, true
				}
				alice := routeRequest("hello", "chat")
				alice.User.Email = "alice@example.com"
				produce := func(ctx context.Context, req OrchestratorRequest) routeEffects {
					_, routes, err := p.Produce(ctx, req)
					if err != nil {
						t.Fatalf("produce: %v", err)
					}
					return routes
				}

				check(t, "established", produce(withIdentityEstablished(context.Background(), true), alice), tc.established)
				if resolved != 1 {
					t.Errorf("PREMISE: the established email was resolved %d times, want once", resolved)
				}
				resolved = 0
				check(t, "marker read as not established", produce(withIdentityEstablished(context.Background(), false), alice), tc.notEstablished)
				// THE FAIL-CLOSED SHAPE FOR ANY FUTURE ASYNC HOP: a context that
				// never passed requireInternalProxyAuth is not established.
				check(t, "background context", produce(context.Background(), alice), tc.notEstablished)
				if resolved != 0 {
					t.Errorf("a not-established email was resolved %d times, want never", resolved)
				}
				anonymous := routeRequest("hello", "chat")
				check(t, "anonymous, established context", produce(withIdentityEstablished(context.Background(), true), anonymous), tc.anonymous)
				check(t, "anonymous, background context", produce(context.Background(), anonymous), tc.anonymous)
			})
		}
	}
}

// THE REFUSAL'S NAME IS ITS CAUSE (R3 round 1 finding 2). For a header identity:
// segment rows that take the last provider away from what the unsegmented rows
// permit = segment_not_established; unsegmented rows that permit nothing on their
// own = no_compliant_provider, because no identity would change that. An
// established caller is never named segment_not_established.
func TestSegmentNotEstablishedNamesOnlyARefusalTheSegmentRowsCaused(t *testing.T) {
	cases := []struct {
		name            string
		rows            map[string]interface{}
		wantNothing     bool
		wantSegmentName bool
	}{
		{"two disjoint segment rows", map[string]interface{}{
			"f": segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic"),
			"e": segmentRouteRow("e", routeTestOrg, "seg-engineering", 10, "ollama"),
		}, true, true},
		{"an unsegmented row and a disjoint segment row", map[string]interface{}{
			"u": segmentRouteRow("u", routeTestOrg, "", 100, "anthropic"),
			"e": segmentRouteRow("e", routeTestOrg, "seg-engineering", 10, "ollama"),
		}, true, true},
		{"two disjoint unsegmented rows", map[string]interface{}{
			"u1": segmentRouteRow("u1", routeTestOrg, "", 100, "anthropic"),
			"u2": segmentRouteRow("u2", routeTestOrg, "", 10, "openai"),
		}, true, false},
		{"two disjoint unsegmented rows beside a segment row", map[string]interface{}{
			"u1": segmentRouteRow("u1", routeTestOrg, "", 100, "anthropic"),
			"u2": segmentRouteRow("u2", routeTestOrg, "", 50, "openai"),
			"f":  segmentRouteRow("f", routeTestOrg, "seg-finance", 10, "ollama"),
		}, true, false},
		// The unsegmented merge counts only rows that APPLY: two disjoint
		// unsegmented rows whose condition fails permit nothing on their own
		// only if they were (wrongly) merged, so this names the segment rows.
		{"disjoint unsegmented rows whose condition fails beside disjoint segment rows", map[string]interface{}{
			"u1": conditionedSegmentRouteRow("u1", "", 200, "batch", "anthropic"),
			"u2": conditionedSegmentRouteRow("u2", "", 150, "batch", "openai"),
			"f":  segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic"),
			"e":  segmentRouteRow("e", routeTestOrg, "seg-engineering", 10, "ollama"),
		}, true, true},
		{"overlapping segment rows", map[string]interface{}{
			"f": segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic", "ollama"),
			"e": segmentRouteRow("e", routeTestOrg, "seg-engineering", 10, "ollama"),
		}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := routeProducerOver(t, routeTestRows(tc.rows), false)
			p.segments = func(context.Context, string, string) ([]string, bool) { return []string{"seg-engineering"}, true }
			req := routeRequest("hello", "chat")
			req.User.Email = "alice@example.com"

			_, header, err := p.Produce(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if header.NothingPermitted() != tc.wantNothing || header.SegmentNotEstablished != tc.wantSegmentName {
				t.Errorf("header identity: nothing=%v segment_not_established=%v, want %v and %v (%+v)",
					header.NothingPermitted(), header.SegmentNotEstablished, tc.wantNothing, tc.wantSegmentName, header)
			}
			_, token, err := p.Produce(withIdentityEstablished(context.Background(), true), req)
			if err != nil {
				t.Fatal(err)
			}
			if token.SegmentNotEstablished {
				t.Errorf("validated token: named segment_not_established (%+v); an established caller never is", token)
			}
		})
	}
}

// A block action that already refused is not the route layer's refusal: the
// preview names BlockedBy only when the route restriction was what refused.
func TestThePreviewNamesTheRouteLayerOnlyWhenNothingElseRefused(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	disjoint := map[string]interface{}{
		"route-a": routeRow("route-a", 100, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"anthropic"}}),
		"route-b": routeRow("route-b", 50, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"openai"}}),
	}
	preview := func(cached map[string]interface{}) *PolicyEvaluationResult {
		engine := &DatabaseDynamicPolicyEngine{policies: cached, cacheTimeout: 30 * time.Second, lastRefresh: time.Now()}
		return engine.EvaluateDynamicPolicies(context.Background(), routeRequest("hello", "chat"))
	}
	if r := preview(disjoint); r.Allowed || r.BlockedBy != blockedByRouteLayer {
		t.Errorf("route rows alone: allowed=%v blocked_by=%q, want refused by %q", r.Allowed, r.BlockedBy, blockedByRouteLayer)
	}
	withBlock := map[string]interface{}{}
	for k, v := range disjoint {
		withBlock[k] = v
	}
	actions, _ := json.Marshal([]PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "blocked"}}})
	block := routeRow("block-row", 200, t0, nil, nil)
	block["actions"] = json.RawMessage(actions)
	withBlock["block-row"] = block
	if r := preview(withBlock); r.Allowed || r.BlockedBy != "" {
		t.Errorf("a block action beside the route rows: allowed=%v blocked_by=%q, want refused with no route-layer name", r.Allowed, r.BlockedBy)
	}
}

// A not-established caller is never resolved, so a resolver outage cannot turn
// the not-established outcome into segment_resolution_failed; an established
// caller's outage still fails closed exactly as before.
func TestAResolverOutageFailsClosedOnlyForAnEstablishedEmail(t *testing.T) {
	p := routeProducerOver(t, routeTestRows(map[string]interface{}{
		"f": segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic"),
	}), false)
	p.segments = func(context.Context, string, string) ([]string, bool) { return nil, false }
	alice := routeRequest("hello", "chat")
	alice.User.Email = "alice@example.com"

	if _, _, err := p.Produce(withIdentityEstablished(context.Background(), true), alice); !errors.Is(err, errDynamicFactsUnavailable) {
		t.Errorf("established with a failing resolver: err = %v, want errDynamicFactsUnavailable", err)
	}
	_, routes, err := p.Produce(context.Background(), alice)
	if err != nil || !reflect.DeepEqual(routes.AllowedProviders, []string{"anthropic"}) {
		t.Errorf("not established with a failing resolver: routes = %+v err = %v, want the finance row applied", routes, err)
	}
}

// Community mode, where the agent's forward carries a SYNTHESISED email with no
// marker and no organization has segment-scoped rows: the not-established
// reading changes nothing, facts and effects alike.
func TestASynthesisedCommunityEmailOverUnsegmentedRowsIsUnchanged(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	rows := routeTestRows(map[string]interface{}{
		"u1": segmentRouteRow("u1", routeTestOrg, "", 100, "ollama", "anthropic"),
		"u2": segmentRouteRow("u2", routeTestOrg, "", 10, "ollama"),
	})
	p := routeProducerOver(t, rows, false)
	req := routeRequest("hello", "chat")
	req.User.Email = "local-dev@axonflow.local"

	factsEstablished, routesEstablished, err := p.Produce(withIdentityEstablished(context.Background(), true), req)
	if err != nil {
		t.Fatal(err)
	}
	factsUnmarked, routesUnmarked, err := p.Produce(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(routesEstablished, routesUnmarked) || !reflect.DeepEqual(routesUnmarked.AllowedProviders, []string{"ollama"}) {
		t.Errorf("routes established %+v vs unmarked %+v, want identical and restricted to [ollama]", routesEstablished, routesUnmarked)
	}
	if !reflect.DeepEqual(factsEstablished, factsUnmarked) {
		t.Errorf("facts established %v vs unmarked %v, want identical", factsEstablished, factsUnmarked)
	}
}

// THE PREVIEW IS UNCHANGED BY 1b (ADR-067 tables it for step 2): it still
// resolves the email it is handed and selects rows by the resolved segment,
// with no identity stamp on its context.
func TestThePreviewStillResolvesTheEmailItIsGiven(t *testing.T) {
	fake := resolverReturning("seg-finance")
	withOrchestratorSegmentResolver(t, fake)
	engine := &DatabaseDynamicPolicyEngine{policies: map[string]interface{}{
		"finance":     segmentRouteRow("finance", routeTestOrg, "seg-finance", 50, "anthropic"),
		"engineering": segmentRouteRow("engineering", routeTestOrg, "seg-engineering", 10, "ollama"),
	}, cacheTimeout: 30 * time.Second, lastRefresh: time.Now()}
	req := routeRequest("hello", "chat")
	req.User.Email = "alice@example.com"

	result := engine.EvaluateDynamicPolicies(context.Background(), req)
	if fake.callCount() != 1 {
		t.Errorf("the preview resolved the email %d times, want once", fake.callCount())
	}
	if !result.Allowed || !reflect.DeepEqual(result.AllowedProviders, []string{"anthropic"}) {
		t.Errorf("preview = allowed %v providers %v, want admitted with the finance row's [anthropic] only", result.Allowed, result.AllowedProviders)
	}
}

// THE SHAPE THE RUNTIME SUITES SEED (R3 round 1 finding 1). A route row whose
// conditions are a stored empty array is dropped by the cache conversion
// (#3384: `[]` is the released update gap's residue), so it restricts nothing;
// the suites therefore seed a query-contains condition, which applies to a
// request carrying the marker on the route-request plane and to no other.
func TestARouteRowTheSuitesSeedAppliesOnlyToItsMarker(t *testing.T) {
	t0 := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	marker := "e2e-4249-route-probe"
	conditioned := routeTestRows(map[string]interface{}{
		"a": routeRow("a", 100, t0, []PolicyCondition{{Field: "query", Operator: "contains", Value: marker}}, map[string]interface{}{"allowed_providers": []interface{}{"anthropic"}}),
		"b": routeRow("b", 50, t0, []PolicyCondition{{Field: "query", Operator: "contains", Value: marker}}, map[string]interface{}{"allowed_providers": []interface{}{"openai"}}),
	})
	p := routeProducerOver(t, conditioned, false)
	if routes := routesFor(t, p, routeRequest("what is the weather "+marker, "llm")); !routes.NothingPermitted() {
		t.Errorf("a request carrying the marker: routes = %+v, want nothing permitted", routes)
	}
	if routes := routesFor(t, p, routeRequest("what is the weather", "llm")); routes.Restricted {
		t.Errorf("a request without the marker: routes = %+v, want no restriction", routes)
	}

	emptyArray := routeTestRows(map[string]interface{}{
		"a": routeRow("a", 100, t0, []PolicyCondition{}, map[string]interface{}{"allowed_providers": []interface{}{"anthropic"}}),
		"b": routeRow("b", 50, t0, []PolicyCondition{}, map[string]interface{}{"allowed_providers": []interface{}{"openai"}}),
	})
	if routes := routesFor(t, routeProducerOver(t, emptyArray, false), routeRequest("what is the weather "+marker, "llm")); routes.Restricted {
		t.Errorf("rows stored with conditions []: routes = %+v, want them dropped (no restriction)", routes)
	}
}
