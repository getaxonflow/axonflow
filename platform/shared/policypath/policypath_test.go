// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policypath

import (
	"net/http"
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

		// successors are never themselves legacy - this is what makes
		// DeprecateLegacy safe to mount anywhere
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

// TestIsSuccessorAndIsLegacyAreDisjoint is the property the whole design rests
// on: DeprecateLegacy is mounted on routers that also carry successor routes,
// and it is safe there only because no path can be both.
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

func TestStampDeprecation(t *testing.T) {
	t.Run("stamps a legacy path", func(t *testing.T) {
		h := http.Header{}
		if !StampDeprecation(h, "/api/v1/static-policies/abc") {
			t.Fatal("StampDeprecation reported no match on a legacy path")
		}
		if got := h.Get(HeaderDeprecation); got != DeprecationValue {
			t.Errorf("Deprecation = %q; want %q", got, DeprecationValue)
		}
		want := LinkSuccessor("/api/v1/system-policies/abc")
		if got := h.Get(HeaderLink); got != want {
			t.Errorf("Link = %q; want %q", got, want)
		}
		// A Sunset value is a promise that the path stops working on a given
		// day. This change makes no such promise, so the package must not be
		// able to emit one.
		if got := h.Get("Sunset"); got != "" {
			t.Errorf("Sunset = %q; want empty", got)
		}
	})

	t.Run("is inert on a successor path", func(t *testing.T) {
		h := http.Header{}
		if StampDeprecation(h, "/api/v1/system-policies") {
			t.Error("StampDeprecation reported a match on a successor path")
		}
		if len(h) != 0 {
			t.Errorf("wrote headers on a successor path: %v", h)
		}
	})

	t.Run("is inert on a near miss", func(t *testing.T) {
		h := http.Header{}
		if StampDeprecation(h, "/api/v1/static-policies-archive") {
			t.Error("StampDeprecation matched a path that only shares a byte prefix")
		}
		if len(h) != 0 {
			t.Errorf("wrote headers on a near miss: %v", h)
		}
	})

	t.Run("overwrites rather than appends", func(t *testing.T) {
		// Set, not Add: a stamp applied twice must not reach the client as
		// "Deprecation: true, true".
		h := http.Header{}
		StampDeprecation(h, "/api/v1/static-policies")
		StampDeprecation(h, "/api/v1/static-policies")
		if n := len(h.Values(HeaderDeprecation)); n != 1 {
			t.Errorf("Deprecation appears %d times after two stamps; want 1", n)
		}
		if n := len(h.Values(HeaderLink)); n != 1 {
			t.Errorf("Link appears %d times after two stamps; want 1", n)
		}
	})
}

func TestDeprecateLegacyMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
	})

	for _, c := range []struct{ path, wantDeprecation string }{
		{"/api/v1/static-policies", DeprecationValue},
		{"/api/v1/dynamic-policies/x", DeprecationValue},
		{"/api/v1/system-policies", ""},
		{"/api/v1/tenant-policies/x", ""},
		{"/health", ""},
	} {
		for name, h := range map[string]http.Handler{
			"handler": DeprecateLegacy(next),
			"func":    http.HandlerFunc(DeprecateLegacyFunc(next.ServeHTTP)),
		} {
			rr := newRecorder()
			h.ServeHTTP(rr, httpRequest(c.path))
			if got := rr.Header().Get(HeaderDeprecation); got != c.wantDeprecation {
				t.Errorf("%s %s: Deprecation = %q; want %q", name, c.path, got, c.wantDeprecation)
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
