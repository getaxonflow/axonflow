// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policypath

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This package is depended on by four planes, and its doc comment calls the
// segment-boundary rule "load-bearing". Until this file existed that rule was
// exercised only from a test in another package - so `go test ./shared/...`
// reported "no test files" for the one package whose correctness the other
// three inherit.

func TestSuccessorOf(t *testing.T) {
	cases := []struct {
		path string
		want string // "" means: not a legacy path
	}{
		// exact family roots
		{"/api/v1/static-policies", "/api/v1/system-policies"},
		{"/api/v1/dynamic-policies", "/api/v1/tenant-policies"},

		// suffixes are preserved verbatim, at every depth
		{"/api/v1/static-policies/effective", "/api/v1/system-policies/effective"},
		{"/api/v1/static-policies/abc/override", "/api/v1/system-policies/abc/override"},
		{"/api/v1/static-policies/{id}/versions", "/api/v1/system-policies/{id}/versions"},
		{"/api/v1/dynamic-policies/x/test", "/api/v1/tenant-policies/x/test"},

		// a trailing slash is a suffix like any other, not a special case
		{"/api/v1/static-policies/", "/api/v1/system-policies/"},

		// NEAR MISSES. These are the reason the rule is not strings.HasPrefix:
		// each shares a byte prefix with a family but is a different route, and
		// stamping one would name a successor that does not exist.
		{"/api/v1/static-policies-archive", ""},
		{"/api/v1/static-policiesX", ""},
		{"/api/v1/dynamic-policies-v2", ""},
		{"/api/v1/dynamic-policiesabc", ""},

		// #1431 successors are never themselves #1431-legacy, which is what
		// the portal's upstream-spelling rewrite rests on (the v11
		// deprecation, IsDeprecated, covers both spellings)
		{"/api/v1/system-policies", ""},
		{"/api/v1/system-policies/effective", ""},
		{"/api/v1/tenant-policies", ""},
		{"/api/v1/tenant-policies/abc", ""},

		// unrelated paths, including one that contains a family name but does
		// not START with it
		{"/api/v1/policy-overrides", ""},
		{"/api/v1/policies", ""},
		{"/api/v2/static-policies", ""},
		{"/proxy/api/v1/static-policies", ""},
		{"/health", ""},
		{"", ""},
		{"/", ""},
	}

	for _, c := range cases {
		got, ok := SuccessorOf(c.path)
		if c.want == "" {
			if ok {
				t.Errorf("SuccessorOf(%q) = %q, true; want no match", c.path, got)
			}
			if IsLegacy(c.path) {
				t.Errorf("IsLegacy(%q) = true; want false", c.path)
			}
			continue
		}
		if !ok {
			t.Errorf("SuccessorOf(%q) returned no match; want %q", c.path, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("SuccessorOf(%q) = %q; want %q", c.path, got, c.want)
		}
		if !IsLegacy(c.path) {
			t.Errorf("IsLegacy(%q) = false; want true", c.path)
		}
		// The successor of a legacy path must never itself be legacy, or
		// following the Link header would loop.
		if IsLegacy(got) {
			t.Errorf("SuccessorOf(%q) = %q, which is ITSELF legacy - a client following "+
				"rel=\"successor-version\" would never terminate", c.path, got)
		}
		if !IsSuccessor(got) {
			t.Errorf("IsSuccessor(%q) = false, but it is the successor of %q", got, c.path)
		}
	}
}

// TestIsSuccessorAndIsLegacyAreDisjoint is the property the portal's
// upstream-spelling rewrite rests on (static_policies.go, policy_overrides.go):
// it maps a successor-spelled request onto the successor upstream only because
// no path can be both.
func TestIsSuccessorAndIsLegacyAreDisjoint(t *testing.T) {
	fams := Families()
	if len(fams) == 0 {
		t.Fatal("Families() is empty - every assertion in this file is vacuous")
	}
	for _, p := range fams {
		for _, suffix := range []string{"", "/", "/effective", "/abc/override"} {
			legacy, successor := p.Legacy+suffix, p.Successor+suffix
			if !IsLegacy(legacy) || IsSuccessor(legacy) {
				t.Errorf("%q: IsLegacy=%v IsSuccessor=%v; want true/false",
					legacy, IsLegacy(legacy), IsSuccessor(legacy))
			}
			if IsLegacy(successor) || !IsSuccessor(successor) {
				t.Errorf("%q: IsLegacy=%v IsSuccessor=%v; want false/true",
					successor, IsLegacy(successor), IsSuccessor(successor))
			}
		}
	}
}

// TestFamiliesReturnsACopy pins the reason Families exists rather than an
// exported slice: a caller that mutates what it is handed must not be able to
// change what the next caller sees.
func TestFamiliesReturnsACopy(t *testing.T) {
	first := Families()
	if len(first) == 0 {
		t.Fatal("Families() is empty")
	}
	original := first[0]
	first[0] = Pair{Legacy: "/tampered", Successor: "/tampered"}

	if got := Families()[0]; got != original {
		t.Errorf("mutating the returned slice changed the table: now %+v, want %+v", got, original)
	}
	if _, ok := SuccessorOf(original.Legacy); !ok {
		t.Errorf("SuccessorOf(%q) stopped matching after a caller mutated its copy", original.Legacy)
	}
}

// The wire values, written out rather than derived from the package: an
// expectation computed by the code under test agrees with it whatever it does.
const (
	wantLink      = `</api/v1/typed-policies>; rel="successor-version"`
	wantRemovedIn = "v11.1"
	// fixedSince and fixedDeprecation pin the RFC 9745 FORMAT against a fixed
	// date: 2026-10-01T00:00:00Z is 1790812800 seconds after the epoch. The
	// real date is DeprecatedSince, which release prep sets.
	fixedSince       = "2026-10-01"
	fixedDeprecation = "@1790812800"
)

func TestIsDeprecated(t *testing.T) {
	members := DeprecatedFamilies()
	// Eight prefixes: static/system, dynamic/tenant, policies, templates, the
	// policy-overrides alias and the RBI policy-template catalogue. A shorter
	// table is a family that answers unstamped, and every other assertion in
	// this file would pass over it.
	if len(members) != 8 {
		t.Fatalf("DeprecatedFamilies() has %d prefixes, want 8: %v", len(members), members)
	}
	for _, f := range members {
		for _, suffix := range []string{"", "/", "/abc", "/{id}/versions"} {
			if !IsDeprecated(f + suffix) {
				t.Errorf("IsDeprecated(%q) = false", f+suffix)
			}
		}
	}
	for _, p := range []string{
		// The successor must never be deprecated itself: a client following
		// rel="successor-version" would loop.
		Successor, Successor + "/active", "/api/v1/typed-policies",
		// Near misses on a segment boundary.
		"/api/v1/policies-archive", "/api/v1/templatesX", "/api/v1/policy-overrides-v2",
		// The RBI module's other policy read, and a near miss on the catalogue.
		"/api/v1/rbi/policies/categories", "/api/v1/rbi/policies/templatesX",
		// ADR-044's session overrides: not in this surface until its successor exists.
		"/api/v1/overrides", "/api/v1/overrides/abc",
		"/api/v2/policies", "/proxy/api/v1/policies", "/health", "", "/",
	} {
		if IsDeprecated(p) {
			t.Errorf("IsDeprecated(%q) = true, want false", p)
		}
	}
}

func TestDeprecatedFamiliesReturnsACopy(t *testing.T) {
	first := DeprecatedFamilies()
	original := first[0]
	first[0] = "/tampered"
	if got := DeprecatedFamilies()[0]; got != original {
		t.Errorf("mutating the returned slice changed the table: now %q, want %q", got, original)
	}
}

func TestDeprecationValue(t *testing.T) {
	if got, ok := DeprecationValue(fixedSince); !ok || got != fixedDeprecation {
		t.Errorf("DeprecationValue(%q) = %q, %v; want %q, true", fixedSince, got, ok, fixedDeprecation)
	}
	for _, bad := range []string{"", "2026-13-01", "01/10/2026", "2026-10-01T00:00:00Z", "true"} {
		if got, ok := DeprecationValue(bad); ok {
			t.Errorf("DeprecationValue(%q) = %q, true; want no value", bad, got)
		}
	}
}

func TestStampDeprecation(t *testing.T) {
	t.Run("stamps every deprecated family with the typed route and the removal release", func(t *testing.T) {
		for _, f := range DeprecatedFamilies() {
			for _, suffix := range []string{"", "/abc", "/abc/versions"} {
				h := http.Header{}
				if !stamp(h, f+suffix, fixedSince) {
					t.Errorf("%s: stamp reported no match", f+suffix)
					continue
				}
				for k, want := range map[string]string{
					HeaderDeprecation: fixedDeprecation,
					HeaderLink:        wantLink,
					HeaderRemovedIn:   wantRemovedIn,
				} {
					if got := h.Get(k); got != want {
						t.Errorf("%s: %s = %q; want %q", f+suffix, k, got, want)
					}
				}
				// Sunset is a DATE (RFC 8594), and v11.1 has none yet.
				if got := h.Get("Sunset"); got != "" {
					t.Errorf("%s: Sunset = %q; want empty", f+suffix, got)
				}
			}
		}
	})

	t.Run("omits Deprecation rather than guess while the date is unset or unparseable", func(t *testing.T) {
		for _, since := range []string{"", "not-a-date"} {
			h := http.Header{}
			if !stamp(h, Policies, since) {
				t.Fatalf("since=%q: stamp reported no match on %s", since, Policies)
			}
			if _, present := h[HeaderDeprecation]; present {
				t.Errorf("since=%q: Deprecation = %q; want the header absent", since, h.Get(HeaderDeprecation))
			}
			if h.Get(HeaderLink) != wantLink || h.Get(HeaderRemovedIn) != wantRemovedIn {
				t.Errorf("since=%q: Link=%q Removed-In=%q; the signal must still name the successor and the release",
					since, h.Get(HeaderLink), h.Get(HeaderRemovedIn))
			}
		}
	})

	t.Run("StampDeprecation dates the header from DeprecatedSince", func(t *testing.T) {
		h := http.Header{}
		StampDeprecation(h, Templates)
		want, dated := DeprecationValue(DeprecatedSince)
		if got, present := h[HeaderDeprecation]; present != dated || (dated && got[0] != want) {
			t.Errorf("Deprecation = %v (present=%v); DeprecatedSince=%q wants present=%v value %q",
				got, present, DeprecatedSince, dated, want)
		}
	})

	t.Run("is inert on the typed route and on near misses", func(t *testing.T) {
		for _, p := range []string{Successor, "/api/v1/policies-archive", "/api/v1/overrides", "/health"} {
			h := http.Header{}
			if stamp(h, p, fixedSince) {
				t.Errorf("stamp matched %q", p)
			}
			if len(h) != 0 {
				t.Errorf("wrote headers on %q: %v", p, h)
			}
		}
	})

	t.Run("overwrites rather than appends", func(t *testing.T) {
		// Set, not Add: a stamp applied on two hops reaches the client once.
		h := http.Header{}
		stamp(h, LegacySystemPolicies, fixedSince)
		stamp(h, LegacySystemPolicies, fixedSince)
		for _, k := range DeprecationHeaders() {
			if n := len(h.Values(k)); n != 1 {
				t.Errorf("%s appears %d times after two stamps; want 1", k, n)
			}
		}
	})
}

// TestDeprecationHeadersListsEveryStampedHeader pins DeprecationHeaders to what
// a dated stamp writes. The CORS tests on every plane read their expectation
// from DeprecationHeaders, so a header the stamp writes and the list omits
// would be stamped, never exposed to a browser, and pass every one of them.
func TestDeprecationHeadersListsEveryStampedHeader(t *testing.T) {
	h := http.Header{}
	stamp(h, Policies, fixedSince)
	listed := map[string]bool{}
	for _, k := range DeprecationHeaders() {
		listed[http.CanonicalHeaderKey(k)] = true
	}
	for k := range h {
		if !listed[k] {
			t.Errorf("stamp writes %s, which DeprecationHeaders omits - no plane exposes it to a browser", k)
		}
	}
	if len(listed) != len(h) {
		t.Errorf("DeprecationHeaders lists %v and a dated stamp writes %v", DeprecationHeaders(), h)
	}
}

// requireDeprecationDate is the release-prep rule: once VERSION reaches the
// release that deprecates the surface, the date that release was tagged must
// be set, because the Deprecation header is omitted without it.
func requireDeprecationDate(version, deprecatedIn, since string) error {
	reached, err := versionReaches(version, deprecatedIn)
	if err != nil {
		return err
	}
	if !reached {
		return nil
	}
	if _, ok := DeprecationValue(since); !ok {
		return fmt.Errorf("VERSION is %s, which is at or past %s, and DeprecatedSince is %q: "+
			"set it to the UTC date (YYYY-MM-DD) %s was tagged, or the legacy policy routes ship without "+
			"their RFC 9745 Deprecation header", version, deprecatedIn, since, deprecatedIn)
	}
	return nil
}

// versionReaches reports whether version is at or past target under semver
// precedence, where a pre-release (11.0.0-rc.1) precedes its release.
func versionReaches(version, target string) (bool, error) {
	core, pre, _ := strings.Cut(strings.TrimSpace(version), "-")
	v, err := semverCore(core)
	if err != nil {
		return false, fmt.Errorf("VERSION %q: %w", version, err)
	}
	want, err := semverCore(target)
	if err != nil {
		return false, fmt.Errorf("DeprecatedInRelease %q: %w", target, err)
	}
	for i := range v {
		if v[i] != want[i] {
			return v[i] > want[i], nil
		}
	}
	return pre == "", nil
}

func semverCore(s string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("not MAJOR.MINOR.PATCH")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("not MAJOR.MINOR.PATCH")
		}
		out[i] = n
	}
	return out, nil
}

// TestTheDeprecationDateRuleRedsWhereItShould is the planted positive for the
// guard below: without it, a rule that returned nil for every input would pass
// on every VERSION this repository has ever carried.
func TestTheDeprecationDateRuleRedsWhereItShould(t *testing.T) {
	for _, c := range []struct {
		version, since string
		wantErr        bool
	}{
		{"10.4.0", "", false},
		{"11.0.0-rc.1", "", false},
		{"11.0.0", "", true},
		{"11.0.0", "2026-13-01", true},
		{"11.0.0", fixedSince, false},
		{"11.1.0", "", true},
		{"12.0.0", "", true},
		{"11.0", "", true}, // an unreadable VERSION is an error, not a pass
	} {
		err := requireDeprecationDate(c.version, DeprecatedInRelease, c.since)
		if (err != nil) != c.wantErr {
			t.Errorf("VERSION=%q since=%q: err=%v, want error=%v", c.version, c.since, err, c.wantErr)
		}
	}
}

// TestDeprecatedSinceIsSetOnceVERSIONReachesTheDeprecatingRelease reds the
// release-prep commit that moves VERSION to 11.0.0 until DeprecatedSince is
// set, which is how the tag date reaches the wire without a guessed one ever
// shipping.
func TestDeprecatedSinceIsSetOnceVERSIONReachesTheDeprecatingRelease(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "VERSION"))
	if err != nil {
		t.Fatalf("read the repository's VERSION file: %v", err)
	}
	if err := requireDeprecationDate(string(raw), DeprecatedInRelease, DeprecatedSince); err != nil {
		t.Fatal(err)
	}
}

func TestDeprecateLegacyMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	})

	for _, c := range []struct {
		path    string
		stamped bool
	}{
		{"/api/v1/static-policies", true},
		{"/api/v1/system-policies", true},
		{"/api/v1/dynamic-policies/x", true},
		{"/api/v1/tenant-policies/x", true},
		{"/api/v1/policies/abc/versions", true},
		{"/api/v1/templates/stats", true},
		{"/api/v1/typed-policies/active", false},
		{"/health", false},
	} {
		for name, h := range map[string]http.Handler{
			"handler": DeprecateLegacy(next),
			"func":    http.HandlerFunc(DeprecateLegacyFunc(next.ServeHTTP)),
		} {
			rr := newRecorder()
			h.ServeHTTP(rr, httpRequest(c.path))
			want := ""
			if c.stamped {
				want = wantLink
			}
			if got := rr.Header().Get(HeaderLink); got != want {
				t.Errorf("%s %s: Link = %q; want %q", name, c.path, got, want)
			}
			// The wrapper must be transparent: same status, same body.
			if rr.code != http.StatusOK {
				t.Errorf("%s %s: status = %d; want 200", name, c.path, rr.code)
			}
			if rr.body != "body" {
				t.Errorf("%s %s: body = %q; want %q", name, c.path, rr.body, "body")
			}
		}
	}
}

// minimal recorder, so this package's tests pull in nothing beyond net/http.
type recorder struct {
	hdr  http.Header
	code int
	body string
}

func newRecorder() *recorder { return &recorder{hdr: http.Header{}} }

func (r *recorder) Header() http.Header { return r.hdr }
func (r *recorder) WriteHeader(c int)   { r.code = c }
func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	r.body += string(b)
	return len(b), nil
}

func httpRequest(path string) *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	if err != nil {
		panic(err)
	}
	return req
}
