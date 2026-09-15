// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4254: the LLM routing hints (#883) move from the dynamic engine's verdict into
// the fact layer, merged by one function in the order evaluation walks the rows.

import (
	"context"
	"encoding/json"
	"reflect"
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
	return (&DatabaseDynamicPolicyEngine{policies: cached}).ListActivePoliciesForTenant
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
		for _, row := range rows(routeTestOrg, nil) {
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

// allowed_providers intersect across every applying row, in the order of the
// first row's list.
func TestApplyingRouteRowsIntersectTheirAllowedProviders(t *testing.T) {
	t0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	rows := routeTestRows(map[string]interface{}{
		"allow-wide":   routeRow("allow-wide", 100, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"openai", "anthropic", "bedrock"}}),
		"allow-narrow": routeRow("allow-narrow", 10, t0, nil, map[string]interface{}{"allowed_providers": []interface{}{"bedrock", "openai"}}),
	})
	p := routeProducerOver(t, rows, false)
	for i := 0; i < 50; i++ {
		routes := routesFor(t, p, routeRequest("hello", "chat"))
		if want := []string{"openai", "bedrock"}; !reflect.DeepEqual(routes.AllowedProviders, want) {
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
