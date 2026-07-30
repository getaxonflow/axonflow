// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3117 M4 — the MCP server handler had a SECOND origin policy.
//
// mcpServerHandler answered its own OPTIONS with
//
//	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
//
// unconditionally, bypassing resolveCORSOptions(). Under the deny-all default
// #3096 introduced, a plain OPTIONS to /api/v1/mcp-server still came back with
// `Access-Control-Allow-Origin: https://evil.example`.
//
// Severity, stated precisely so the tests are not read as covering more than
// they do: this was LATENT, not live. A real browser preflight carries
// Access-Control-Request-Method, and rs/cors wraps the whole router and answers
// (or refuses) such a request before mux ever matches this route — so no
// browser could reach the reflection. It is the same latency the `*` +
// credentials pairing had, and it was left in the very package that had just
// been fixed, with cors.go's own doc comment warning against "a second,
// drifting source of truth for the origin policy".
//
// Every test below fails on the pre-fix handler:
//   - deny-all posture   → got "https://evil.example", want ""
//   - explicit allowlist → got "https://evil.example", want "" for a
//     non-allowlisted origin, and no Access-Control-Allow-Credentials for the
//     allowlisted one
//   - community posture  → got "https://anything.example", want "*"

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"axonflow/platform/shared/corspolicy"
)

// mcpPreflight drives a plain OPTIONS (no Access-Control-Request-Method — the
// shape that actually reaches this handler) through the real handler and
// returns what the wire would carry back.
func mcpPreflight(t *testing.T, origin string) (status int, acao, acac, vary string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/mcp-server", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rr := httptest.NewRecorder()
	mcpServerHandler(rr, req)

	h := rr.Header()
	return rr.Code,
		h.Get("Access-Control-Allow-Origin"),
		h.Get("Access-Control-Allow-Credentials"),
		h.Get("Vary")
}

// TestMCPServerCORS_UnsetOutsideCommunity_DoesNotReflectOrigin is the core
// assertion. It is the exact posture resolveCORSOptions() denies, so a handler
// that answers differently is by definition a second policy.
func TestMCPServerCORS_UnsetOutsideCommunity_DoesNotReflectOrigin(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	t.Setenv(corsAllowedOriginsEnv, "")

	status, acao, acac, vary := mcpPreflight(t, "https://evil.example")

	if acao != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty — the MCP handler "+
			"must not reflect an origin the shared policy denies (#3117)", acao)
	}
	if acac != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want empty", acac)
	}
	// The preflight is still ANSWERED, and still terminated here — the fix
	// changes which origins are blessed, not whether OPTIONS reaches dispatch.
	if status != http.StatusNoContent {
		t.Errorf("status = %d, want %d", status, http.StatusNoContent)
	}
	if vary != "Origin" {
		t.Errorf("Vary = %q, want %q — a denied preflight must still be Origin-varying "+
			"so a shared cache cannot serve an allowed response to a denied origin", vary, "Origin")
	}
}

// TestMCPServerCORS_MatchesResolvedPolicy walks every branch of the resolved
// policy and asserts the handler agrees with it. The point is not the
// individual values but that ONE resolution produces them.
func TestMCPServerCORS_MatchesResolvedPolicy(t *testing.T) {
	const allowed = "https://portal.example.com"

	cases := []struct {
		name        string
		mode        string
		originsEnv  string
		origin      string
		wantACAO    string
		wantACAC    string
		explanation string
	}{
		{
			name: "deny-all posture refuses an attacker origin",
			mode: "enterprise", originsEnv: "", origin: "https://evil.example",
			wantACAO: "", wantACAC: "",
			explanation: "unset origins outside community mode denies everything",
		},
		{
			name: "deny-all posture refuses even a plausible origin",
			mode: "in-vpc-enterprise", originsEnv: "", origin: allowed,
			wantACAO: "", wantACAC: "",
			explanation: "nothing is allowlisted, so nothing is allowed",
		},
		{
			name: "allowlisted origin is echoed with credentials",
			mode: "enterprise", originsEnv: allowed + ",https://app.example.com", origin: allowed,
			wantACAO: allowed, wantACAC: "true",
			explanation: "a named allowlist is the only combination that may carry credentials",
		},
		{
			name: "origin outside the allowlist is refused",
			mode: "enterprise", originsEnv: allowed, origin: "https://evil.example",
			wantACAO: "", wantACAC: "",
			explanation: "membership is exact, not prefix or suffix",
		},
		{
			name: "community fallback allows all WITHOUT credentials",
			mode: "community", originsEnv: "", origin: "https://anything.example",
			wantACAO: "*", wantACAC: "",
			explanation: "the literal `*`, matching what rs/cors emits for the same policy",
		},
		{
			name: "explicit wildcard allows all WITHOUT credentials",
			mode: "enterprise", originsEnv: "*", origin: "https://anything.example",
			wantACAO: "*", wantACAC: "",
			explanation: "an operator may ask for `*`, but never with credentials",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", c.mode)
			t.Setenv(corsAllowedOriginsEnv, c.originsEnv)

			_, acao, acac, _ := mcpPreflight(t, c.origin)

			if acao != c.wantACAO {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q (%s)", acao, c.wantACAO, c.explanation)
			}
			if acac != c.wantACAC {
				t.Errorf("Access-Control-Allow-Credentials = %q, want %q (%s)", acac, c.wantACAC, c.explanation)
			}
		})
	}
}

// TestMCPServerCORS_NoOriginHeaderEmitsNoACAO covers the request shape that is
// not a preflight at all: a non-browser client sending OPTIONS with no Origin.
// The pre-fix handler emitted `Access-Control-Allow-Origin: ` (an empty header,
// which is present-but-empty on the wire, not absent).
func TestMCPServerCORS_NoOriginHeaderEmitsNoACAO(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv(corsAllowedOriginsEnv, "")

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/mcp-server", nil)
	rr := httptest.NewRecorder()
	mcpServerHandler(rr, req)

	if _, present := rr.Header()["Access-Control-Allow-Origin"]; present {
		t.Errorf("Access-Control-Allow-Origin header present for a request with no Origin; "+
			"header block = %v", rr.Header())
	}
}

// TestCORSPolicy_SingleSourceOfTruth pins the invariant the M4 fix exists to
// establish: for every posture and every origin, the handler's answer is
// exactly what the shared policy resolves. If a future edit reintroduces a
// local rule in either place, this disagrees.
func TestCORSPolicy_SingleSourceOfTruth(t *testing.T) {
	postures := []struct{ mode, origins string }{
		{"enterprise", ""},
		{"enterprise", "https://portal.example.com"},
		{"enterprise", "*"},
		{"community", ""},
		{"in-vpc-banking", "https://a.example,https://b.example"},
		{"", ""}, // unset mode: fails closed since #3096
	}
	origins := []string{
		"https://portal.example.com",
		"https://a.example",
		"https://evil.example",
		"null",
	}

	for _, p := range postures {
		for _, origin := range origins {
			t.Setenv("DEPLOYMENT_MODE", p.mode)
			t.Setenv(corsAllowedOriginsEnv, p.origins)

			wantACAO, wantCreds, ok := corspolicy.Resolve().Allow(origin)
			if !ok {
				wantACAO = ""
			}

			_, gotACAO, gotACAC, _ := mcpPreflight(t, origin)

			if gotACAO != wantACAO {
				t.Errorf("mode=%q origins=%q origin=%q: handler emitted ACAO %q, shared policy resolves %q",
					p.mode, p.origins, origin, gotACAO, wantACAO)
			}
			wantACAC := ""
			if ok && wantCreds {
				wantACAC = "true"
			}
			if gotACAC != wantACAC {
				t.Errorf("mode=%q origins=%q origin=%q: handler emitted ACAC %q, shared policy resolves %q",
					p.mode, p.origins, origin, gotACAC, wantACAC)
			}
		}
	}
}
