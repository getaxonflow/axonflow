// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// TestBindsOnThroughTheTypedAuthoringRoute (#4371) drives binds_on through the
// real POST /api/v1/typed-policies/publish over the deployment vocabulary: a
// Community constraint on tool.call scoped to the step gate and the MCP request
// pass publishes, and each refusal arrives as a 422 naming its code and the
// scope it refused.
func TestBindsOnThroughTheTypedAuthoringRoute(t *testing.T) {
	cases := []struct {
		name     string
		binds    []string
		code     string
		fragment string
	}{
		{"scoped to the step gate and the MCP request pass", []string{"mcp:request", "wcp"}, "", ""},
		{"an empty list", []string{}, authoring.CodeBindsOnEmpty, "binds_on is []"},
		{"a two-phase plane without its phase", []string{"mcp"}, authoring.CodePlaneNotDeclared, `\"mcp\"`},
		{"a plane that presents no tool call", []string{"openai_compatible"}, authoring.CodeActionNotPresentedOnPlane, `\"openai_compatible\"`},
		{"a repeated plane", []string{"wcp", "wcp"}, authoring.CodeBindsOnDuplicatePlane, `\"wcp\"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
			rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", rawBindsOnBody(t, tc.binds), gatewayHeaders())
			if tc.code == "" {
				if rr.Code != http.StatusOK {
					t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
				}
				return
			}
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d, want 422; body=%s", rr.Code, rr.Body.String())
			}
			body := rr.Body.String()
			if !strings.Contains(body, tc.code) || !strings.Contains(body, tc.fragment) {
				t.Fatalf("refused, but not %s naming %s: %s", tc.code, tc.fragment, body)
			}
		})
	}
}

// rawBindsOnBody is publishBody(communityDocument()) with binds_on written into
// the ceiling's JSON as an author writes it, so the route is tested against
// the bytes and not only against what the Go types encode.
func rawBindsOnBody(t *testing.T, binds []string) map[string]any {
	t.Helper()
	raw, err := json.Marshal(publishBody(communityDocument()))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	policies := body["document"].(map[string]any)["policy"].(map[string]any)["policies"].([]any)
	list := make([]any, 0, len(binds))
	for _, b := range binds {
		list = append(list, b)
	}
	policies[1].(map[string]any)["binds_on"] = list
	return body
}

// TestAnEmptyBindsOnBuiltFromGoTypesIsRefused is the regression #4371's own
// route cell found: with BindsOn a plain []string under omitempty, a document
// built from Go types with a computed-empty list encoded binds_on as ABSENT,
// and the route published the control on every scope (200). BindsOn is a
// pointer now, so the empty list reaches the wire as [] and is refused.
func TestAnEmptyBindsOnBuiltFromGoTypesIsRefused(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	d := communityDocument()
	d.Policy.Policies[1].BindsOn = pdp.BindingScopes([]string{})
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(d), gatewayHeaders())
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), authoring.CodeBindsOnEmpty) {
		t.Fatalf("status=%d, want 422 %s; body=%s", rr.Code, authoring.CodeBindsOnEmpty, rr.Body.String())
	}
}

// TestTheRouteRefusesABindsOnItWouldReadAsAbsent (#4371): the route decodes
// with the portal's parser (authoring.DecodeStrict). A null binds_on and a
// misspelled sibling (bind_on) both decoded as ABSENT - every plane - through
// the route's former plain decoder; each is now refused 400 malformed_request,
// as the portal refuses it.
func TestTheRouteRefusesABindsOnItWouldReadAsAbsent(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"null":       func(p map[string]any) { p["binds_on"] = nil },
		"misspelled": func(p map[string]any) { p["bind_on"] = []any{"wcp"} },
	} {
		t.Run(name, func(t *testing.T) {
			r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
			body := rawBindsOnBody(t, []string{"wcp"})
			ceiling := body["document"].(map[string]any)["policy"].(map[string]any)["policies"].([]any)[1].(map[string]any)
			delete(ceiling, "binds_on")
			mutate(ceiling)
			rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", body, gatewayHeaders())
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "malformed_request") {
				t.Fatalf("status=%d, want 400 malformed_request; body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}
