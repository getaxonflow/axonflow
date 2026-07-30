// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3096 part 2 regression tests for the agent's CORS policy.
//
// These assert the headers rs/cors actually EMITS for a preflight, not the
// fields of the cors.Options struct. That distinction is the whole point:
// `AllowedOrigins: []string{}` reads like a lockdown but rs/cors treats a
// zero-length slice as "allow all" (cors.go:163-167), so a config-field
// assertion would happily pass on a policy that allows every origin.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/cors"
)

// preflight drives a real browser-shaped preflight through the resolved policy
// and returns what the wire would carry back.
func preflight(t *testing.T, origin string) (acao, acac string) {
	t.Helper()

	handler := cors.New(resolveCORSOptions()).Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/decide", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	return rr.Header().Get("Access-Control-Allow-Origin"),
		rr.Header().Get("Access-Control-Allow-Credentials")
}

// TestCORS_UnsetOutsideCommunity_DeniesCrossOrigin is the core assertion: an
// unconfigured non-community deployment allows no cross-origin browser access.
// Before #3096 this returned `*` with credentials enabled.
func TestCORS_UnsetOutsideCommunity_DeniesCrossOrigin(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	t.Setenv(corsAllowedOriginsEnv, "")

	acao, acac := preflight(t, "https://evil.example")

	if acao != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty (deny)", acao)
	}
	if acac != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want empty", acac)
	}
}

// TestCORS_NeverPairsWildcardWithCredentials pins the invalid combination out
// of existence on every branch that can produce a wildcard. `*` with
// credentials is rejected by browsers, and "fixing" it by reflecting the Origin
// while credentials stay on is the live vulnerability this guards against.
func TestCORS_NeverPairsWildcardWithCredentials(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		origins string
	}{
		{"community fallback", "community", ""},
		{"operator asked for wildcard explicitly", "enterprise", "*"},
		{"wildcard among named origins", "enterprise", "https://a.example,*"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", c.mode)
			t.Setenv(corsAllowedOriginsEnv, c.origins)

			acao, acac := preflight(t, "https://evil.example")

			if acao != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", acao, "*")
			}
			if acac != "" {
				t.Errorf("Access-Control-Allow-Credentials = %q, want empty — "+
					"`*` with credentials is invalid per the Fetch spec", acac)
			}
		})
	}
}

// TestCORS_ExplicitAllowlist checks that a named allowlist admits its members
// with credentials and refuses everyone else.
func TestCORS_ExplicitAllowlist(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	// Deliberately ragged: whitespace and a trailing comma must not create an
	// empty entry, because a non-empty list suppresses the community fallback.
	t.Setenv(corsAllowedOriginsEnv, " https://portal.example.com , https://app.example.com ,")

	t.Run("allowlisted origin admitted with credentials", func(t *testing.T) {
		acao, acac := preflight(t, "https://portal.example.com")
		if acao != "https://portal.example.com" {
			t.Errorf("Access-Control-Allow-Origin = %q, want the requesting origin", acao)
		}
		if acac != "true" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want %q", acac, "true")
		}
	})

	t.Run("second allowlisted origin admitted", func(t *testing.T) {
		if acao, _ := preflight(t, "https://app.example.com"); acao != "https://app.example.com" {
			t.Errorf("Access-Control-Allow-Origin = %q, want the requesting origin", acao)
		}
	})

	t.Run("origin outside the allowlist refused", func(t *testing.T) {
		acao, acac := preflight(t, "https://evil.example")
		if acao != "" {
			t.Errorf("Access-Control-Allow-Origin = %q, want empty (deny)", acao)
		}
		if acac != "" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want empty", acac)
		}
	})
}

// TestParseAllowedOrigins covers the parser directly, including the cases that
// decide whether the caller falls through to the community/deny branches.
func TestParseAllowedOrigins(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 0},
		{"   ", 0},
		{",", 0},
		{",,  ,", 0},
		{"https://a.example", 1},
		{" https://a.example , https://b.example ,", 2},
	}

	for _, c := range cases {
		if got := parseAllowedOrigins(c.raw); len(got) != c.want {
			t.Errorf("parseAllowedOrigins(%q) = %v (len %d), want len %d", c.raw, got, len(got), c.want)
		}
	}
}

// TestCORS_EmptyAllowedOriginsWouldNotDeny documents, as an executable note,
// the rs/cors behaviour that makes the AllowOriginFunc in resolveCORSOptions
// load-bearing. If a future edit "simplifies" the deny branch to an empty
// AllowedOrigins slice, this test explains why the result allows everything.
func TestCORS_EmptyAllowedOriginsWouldNotDeny(t *testing.T) {
	handler := cors.New(cors.Options{AllowedOrigins: []string{}}).Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/decide", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("rs/cors changed: an empty AllowedOrigins emitted %q, not %q. "+
			"resolveCORSOptions' deny branch uses AllowOriginFunc specifically because "+
			"an empty slice meant allow-all; re-check that branch.", got, "*")
	}
}
