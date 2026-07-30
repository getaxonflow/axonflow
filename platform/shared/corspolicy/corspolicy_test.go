// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package corspolicy

// Tests for the shared resolver (#3161).
//
// These assert what rs/cors actually EMITS for each resolved policy, not the
// fields of the cors.Options struct. That distinction is the whole point:
// `AllowedOrigins: []string{}` reads like a lockdown but rs/cors treats a
// zero-length slice as "allow all", so a config-field assertion would happily
// pass on a policy that admits every origin.
//
// The agent's and orchestrator's own suites cover their surfaces. This file
// covers the branches that belong to the shared package and to no single
// caller — in particular the pattern-origin branch, which #3161's review found
// resolving to credentials ON.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/cors"
)

// emit drives a real browser-shaped preflight through a policy and returns what
// the wire would carry back.
func emit(t *testing.T, p Policy, origin string) (acao, acac string) {
	t.Helper()
	handler := cors.New(p.Apply(cors.Options{
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/anything", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Header().Get("Access-Control-Allow-Origin"), rr.Header().Get("Access-Control-Allow-Credentials")
}

// TestPatternOriginNeverGetsCredentials is THE regression from #3161's review.
//
// rs/cors splits an allowlist entry on the first `*` and matches prefix +
// suffix (cors.go:181-185), so `https://*.example.com` admits every subdomain —
// while the CloudFormation parameter descriptions, docs/configuration.md and
// this package all told operators entries are exact with no suffix matching. An
// operator following that documentation would have believed the entry matched
// nothing; instead it handed an unenumerated set of origins a credentialed
// cross-origin read of a session-authenticated API.
//
// Measured before the fix:
//
//	resolved: origins=[https://*.example.com] credentials=true
//	MIDDLEWARE ACAO="https://evil-sub.example.com" ACAC="true"
func TestPatternOriginNeverGetsCredentials(t *testing.T) {
	cases := []struct {
		name, config, probe string
		wantACAO            string
	}{
		{"subdomain pattern", "https://*.example.com", "https://evil-sub.example.com", "https://evil-sub.example.com"},
		{"pattern beside an exact entry", "https://exact.example.com,https://*.example.com", "https://anything.example.com", "https://anything.example.com"},
		{"the exact entry in a pattern list also loses credentials", "https://exact.example.com,https://*.example.com", "https://exact.example.com", "https://exact.example.com"},
		{"scheme pattern", "*://portal.example.com", "https://portal.example.com", "https://portal.example.com"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
			t.Setenv(AllowedOriginsEnv, c.config)

			p := Resolve()
			if p.Credentials {
				t.Errorf("policy for %q resolved with Credentials=true — a `*` in an entry names a set "+
					"nobody enumerated, and rs/cors DOES match it", c.config)
			}
			if p.Notice == "" {
				t.Errorf("policy for %q emitted no operator notice; the documented contract says entries "+
					"are exact, so an operator must be told this one is not", c.config)
			}

			acao, acac := emit(t, p, c.probe)
			if acao != c.wantACAO {
				t.Errorf("ACAO = %q, want %q — the entry is honoured, not dropped", acao, c.wantACAO)
			}
			if acac != "" {
				t.Errorf("ACAC = %q, want empty. This is the defect: %q admitted %q WITH credentials",
					acac, c.config, c.probe)
			}
		})
	}
}

// TestExactAllowlistStillGetsCredentials is the other half: the pattern branch
// must not have made every allowlist credential-less, which would break the one
// configuration a cookie-authenticated API depends on.
func TestExactAllowlistStillGetsCredentials(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	t.Setenv(AllowedOriginsEnv, " https://portal.example.com , https://app.example.com ,")

	acao, acac := emit(t, Resolve(), "https://portal.example.com")
	if acao != "https://portal.example.com" || acac != "true" {
		t.Errorf("ACAO=%q ACAC=%q, want the origin and \"true\"", acao, acac)
	}
	if acao, _ := emit(t, Resolve(), "https://evil.example"); acao != "" {
		t.Errorf("unlisted origin admitted: ACAO=%q", acao)
	}
}

// TestBareWildcardIsStillItsOwnBranch — a bare `*` must keep emitting the
// literal `*`, not fall into the pattern branch and echo the request Origin.
// Echoing the Origin is the exact "obvious fix" the package doc warns about.
func TestBareWildcardIsStillItsOwnBranch(t *testing.T) {
	for _, config := range []string{"*", "https://a.example,*"} {
		t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
		t.Setenv(AllowedOriginsEnv, config)

		p := Resolve()
		if !p.Wildcard {
			t.Errorf("%q did not resolve to the wildcard branch", config)
		}
		acao, acac := emit(t, p, "https://evil.example")
		if acao != "*" {
			t.Errorf("%q: ACAO = %q, want the literal \"*\" — echoing the Origin is the live vulnerability", config, acao)
		}
		if acac != "" {
			t.Errorf("%q: ACAC = %q, want empty", config, acac)
		}
	}
}

// TestApplyOverwritesAllowCredentialsOnTheBranchThatNeedsIt.
//
// The deny and wildcard branches re-clear AllowCredentials themselves, so a
// test using either proves nothing about the assignment at the top of Apply.
// The branch that depends on it is a NAMED list resolved to Credentials=false —
// the pattern branch. A caller's stale `AllowCredentials: true` must not
// survive into it.
func TestApplyOverwritesAllowCredentialsOnTheBranchThatNeedsIt(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	t.Setenv(AllowedOriginsEnv, "https://*.example.com")

	stale := cors.Options{AllowedMethods: []string{"GET"}, AllowCredentials: true}
	handler := cors.New(Resolve().Apply(stale)).Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/anything", nil)
	req.Header.Set("Origin", "https://sub.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Fatal("precondition: the pattern entry was not admitted at all, so this proves nothing")
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("ACAC = %q, want empty — the caller's stale AllowCredentials survived Apply on the "+
			"one branch where the top-of-function assignment is load-bearing", got)
	}
}

// TestCommunityFallbackCannotSmuggleCredentials — the fallback is supplied by
// the caller and has been through none of Resolve's checks. A fallback list
// containing a `*` must still lose credentials, or the package's central claim
// ("credentials only for a list of exact origins") is false on that branch.
func TestCommunityFallbackCannotSmuggleCredentials(t *testing.T) {
	for _, origins := range [][]string{
		{"https://*.example.com"},
		{"*"},
		{"http://localhost:3000", "https://*.example.com"},
	} {
		t.Setenv("DEPLOYMENT_MODE", "community")
		t.Setenv(AllowedOriginsEnv, "")

		p := ResolveWithCommunityFallback(Policy{Origins: origins, Credentials: true})
		if p.Credentials {
			t.Errorf("fallback %v resolved with Credentials=true", origins)
		}
		if _, acac := emit(t, p, "https://evil-sub.example.com"); acac != "" {
			t.Errorf("fallback %v advertised credentials on the wire: ACAC=%q", origins, acac)
		}
	}
}

// TestApplyOverwritesEveryOriginDecidingField.
//
// rs/cors consults AllowOriginRequestFunc and AllowOriginVaryRequestFunc BEFORE
// AllowedOrigins/AllowOriginFunc (cors.go:153-159) and documents them as
// overriding both. A caller that left one in its base options would defeat the
// deny-all branch completely — a second, drifting origin policy, which is what
// this package exists to make impossible.
func TestApplyOverwritesEveryOriginDecidingField(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	t.Setenv(AllowedOriginsEnv, "")

	hostile := cors.Options{
		AllowedMethods:             []string{"GET"},
		AllowCredentials:           true,
		AllowedOrigins:             []string{"https://leftover.example"},
		AllowOriginFunc:            func(string) bool { return true },
		AllowOriginRequestFunc:     func(*http.Request, string) bool { return true },
		AllowOriginVaryRequestFunc: func(*http.Request, string) (bool, []string) { return true, nil },
	}

	handler := cors.New(Resolve().Apply(hostile)).Handler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/anything", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q, want empty. A field Apply does not clear survived and admitted an origin "+
			"under the deny-all policy.", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("ACAC = %q, want empty — a stale AllowCredentials survived Apply", got)
	}
}

// TestAllowMatchesTheMiddlewareOnCase — Allow is consumed by handlers that write
// their own preflight headers. rs/cors lowercases both the configured list and
// the request Origin, so an exact-string comparison here would refuse an origin
// the middleware admits, on the same process, for the same configuration.
func TestAllowMatchesTheMiddlewareOnCase(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	t.Setenv(AllowedOriginsEnv, "https://Portal.Example.com")

	p := Resolve()
	acao, _ := emit(t, p, "https://portal.example.com")
	value, creds, ok := p.Allow("https://portal.example.com")

	if acao == "" {
		t.Fatal("precondition: the middleware did not admit the differently-cased origin; rs/cors changed")
	}
	if !ok || !creds {
		t.Errorf("Allow refused %q (ok=%v creds=%v) while the middleware admitted it as %q",
			"https://portal.example.com", ok, creds, acao)
	}
	if value != "https://portal.example.com" {
		t.Errorf("Allow echoed %q, want the REQUEST origin (what the middleware emits), not the configured casing", value)
	}
}

// TestAllowNeverAdmitsMoreThanTheMiddleware pins the PROPERTY, not the current
// implementation: for every posture and every probe, an origin Allow admits
// must be one the middleware admits too. Allow feeds handlers that write their
// own preflight headers, so the reverse — Allow saying yes where the middleware
// says no — is a second origin policy, which is the thing this package exists
// to prevent.
//
// The first draft asserted this only inside `if ok`, which is false on the one
// posture it was written for, so the whole body was dead: making Allow return
// true for EVERY origin left the suite green.
func TestAllowNeverAdmitsMoreThanTheMiddleware(t *testing.T) {
	postures := []struct{ mode, origins string }{
		{"in-vpc-enterprise", "https://*.example.com"},
		{"in-vpc-enterprise", "https://portal.example.com,https://app.example.com"},
		{"in-vpc-enterprise", "https://Portal.Example.com"},
		{"in-vpc-enterprise", "*"},
		{"in-vpc-enterprise", ""},
		{"community", ""},
	}
	probes := []string{
		"https://sub.example.com",
		"https://example.com",
		"https://portal.example.com",
		"https://evil.example",
		"http://localhost:3000",
		"null",
	}

	sawAnAdmission := false
	for _, posture := range postures {
		for _, probe := range probes {
			t.Setenv("DEPLOYMENT_MODE", posture.mode)
			t.Setenv(AllowedOriginsEnv, posture.origins)

			p := Resolve()
			acao, acac := emit(t, p, probe)
			value, creds, ok := p.Allow(probe)

			if !ok {
				continue // denying more than the middleware is the safe direction
			}
			sawAnAdmission = true
			if acao == "" {
				t.Errorf("mode=%q origins=%q probe=%q: Allow admitted it as %q, the middleware refused it. "+
					"A handler writing its own preflight headers would open a door the router keeps shut.",
					posture.mode, posture.origins, probe, value)
			}
			if creds && acac != "true" {
				t.Errorf("mode=%q origins=%q probe=%q: Allow advertised credentials, the middleware did not",
					posture.mode, posture.origins, probe)
			}
		}
	}

	// Without this, an Allow that refused everything would satisfy the loop
	// above while making applyCORSPreflightHeaders useless.
	if !sawAnAdmission {
		t.Fatal("Allow admitted nothing across every posture — the assertions above proved nothing")
	}
}

// TestUnsetOutsideCommunityDeniesEverything and TestCommunityFallbackIsCallerSupplied
// cover the two branches every caller shares.
func TestUnsetOutsideCommunityDeniesEverything(t *testing.T) {
	for _, mode := range []string{"enterprise", "in-vpc-enterprise", "community-saas", "Community", " community", ""} {
		t.Setenv("DEPLOYMENT_MODE", mode)
		t.Setenv(AllowedOriginsEnv, "")

		acao, acac := emit(t, Resolve(), "https://evil.example")
		if acao != "" || acac != "" {
			t.Errorf("DEPLOYMENT_MODE=%q: ACAO=%q ACAC=%q, want both empty", mode, acao, acac)
		}
	}
}

func TestCommunityFallbackIsCallerSupplied(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv(AllowedOriginsEnv, "")

	fallback := Policy{Origins: []string{"http://localhost:3000"}, Credentials: true}
	acao, acac := emit(t, ResolveWithCommunityFallback(fallback), "http://localhost:3000")
	if acao != "http://localhost:3000" || acac != "true" {
		t.Errorf("ACAO=%q ACAC=%q, want the fallback origin with credentials", acao, acac)
	}
	if acao, _ := emit(t, ResolveWithCommunityFallback(fallback), "https://evil.example"); acao != "" {
		t.Errorf("the caller's fallback admitted an origin outside it: %q", acao)
	}

	t.Run("a configured value replaces the fallback rather than extending it", func(t *testing.T) {
		t.Setenv(AllowedOriginsEnv, "https://configured.example")
		if acao, _ := emit(t, ResolveWithCommunityFallback(fallback), "http://localhost:3000"); acao != "" {
			t.Errorf("the fallback survived alongside a configured allowlist: ACAO=%q", acao)
		}
	})
}
