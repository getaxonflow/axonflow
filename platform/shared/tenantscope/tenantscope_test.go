// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package tenantscope

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"testing"
)

// The helper is the deliverable, so its own fail-closed behaviour is pinned
// exhaustively: an R3 question this change must answer is "does the helper
// itself fail open on some input?".

func TestAuthorize_FailsClosedOnEveryEmptyCombination(t *testing.T) {
	cases := []struct {
		name                    string
		callerOrg, callerTenant string
		rowOrg, rowTenant       string
		wantErr                 error
		note                    string
	}{
		{"both sides fully populated and matching", "org-a", "tenant-a", "org-a", "tenant-a", nil, "the positive control — if this ever fails, the fix broke everything"},

		// The vulnerability: the old compare returned TRUE for all of these.
		{"caller omitted everything, row unstamped", "", "", "", "", ErrNoCallerScope, "#3065 verbatim: omitting the headers WAS the exploit"},
		{"caller omitted everything, row owned by another tenant", "", "", "org-b", "tenant-b", ErrNoCallerScope, "the cross-tenant read/write the issue reports"},
		{"caller omitted org only", "", "tenant-a", "org-b", "tenant-b", ErrNoCallerScope, ""},
		{"caller omitted tenant only", "org-a", "", "org-b", "tenant-b", ErrNoCallerScope, ""},
		{"row carries no org", "org-a", "tenant-a", "", "tenant-a", ErrNotOwned, "an unowned row belongs to nobody, not to everybody"},
		{"row carries no tenant", "org-a", "tenant-a", "org-a", "", ErrNotOwned, ""},
		{"row carries neither", "org-a", "tenant-a", "", "", ErrNotOwned, ""},

		// Ordinary mismatches.
		{"different org", "org-a", "tenant-a", "org-b", "tenant-a", ErrNotOwned, ""},
		{"different tenant, same org", "org-a", "tenant-a", "org-a", "tenant-b", ErrNotOwned, "a shared enterprise org does not make two tenants one"},

		// Whitespace: a scope built by struct literal never passes through New.
		{"whitespace-only caller org", "   ", "tenant-a", "org-a", "tenant-a", ErrNoCallerScope, ""},
		{"whitespace-only row org", "org-a", "tenant-a", "  ", "tenant-a", ErrNotOwned, ""},
		{"padded values still match", " org-a ", " tenant-a ", "org-a", "tenant-a", nil, "padding must not manufacture a distinct tenancy"},

		// The unowned sentinel is never authorizable, from either direction.
		{"row stamped unowned", "org-a", "tenant-a", UnownedOrgSentinel, "tenant-a", ErrNotOwned, "migration core/156 stamps orphan rows with this"},
		{"caller claims the sentinel as its org", UnownedOrgSentinel, "tenant-a", UnownedOrgSentinel, "tenant-a", ErrNoCallerScope, "an operator setting ORG_ID to the sentinel must not unlock orphan rows"},
		{"caller claims the sentinel as its tenant", "org-a", UnownedOrgSentinel, "org-a", UnownedOrgSentinel, ErrNoCallerScope, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Scope{OrgID: tc.callerOrg, TenantID: tc.callerTenant}
			err := s.Authorize(tc.rowOrg, tc.rowTenant)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Authorize(%q,%q) as (%q,%q) = %v, want %v — %s",
					tc.rowOrg, tc.rowTenant, tc.callerOrg, tc.callerTenant, err, tc.wantErr, tc.note)
			}
		})
	}
}

func TestAuthorizeOrgOnly_FailsClosedOnEmptyEitherSide(t *testing.T) {
	cases := []struct {
		name    string
		caller  string
		row     string
		wantErr error
	}{
		{"match", "org-a", "org-a", nil},
		{"caller empty, row owned", "", "org-b", ErrNoCallerScope},
		{"caller empty, row unowned", "", "", ErrNoCallerScope},
		{"row unowned", "org-a", "", ErrNotOwned},
		{"mismatch", "org-a", "org-b", ErrNotOwned},
		{"row stamped unowned", "org-a", UnownedOrgSentinel, ErrNotOwned},
		{"caller claims the sentinel", UnownedOrgSentinel, UnownedOrgSentinel, ErrNoCallerScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := NewOrgOnly(tc.caller).AuthorizeOrgOnly(tc.row); !errors.Is(err, tc.wantErr) {
				t.Fatalf("AuthorizeOrgOnly(%q) as %q = %v, want %v", tc.row, tc.caller, err, tc.wantErr)
			}
		})
	}
}

// TestAuthorize_NeverAuthorizesTenantWhenOnlyOrgIsBound proves the two
// methods are not interchangeable: a scope built for the org-only surfaces
// must not satisfy the two-dimension check by accident.
func TestAuthorize_NeverAuthorizesTenantWhenOnlyOrgIsBound(t *testing.T) {
	s := NewOrgOnly("org-a")
	if err := s.Authorize("org-a", ""); !errors.Is(err, ErrNotOwned) && !errors.Is(err, ErrNoCallerScope) {
		t.Fatalf("an org-only scope must never satisfy Authorize; got %v", err)
	}
	if s.Bound() {
		t.Fatal("an org-only scope must not report itself Bound")
	}
}

func TestBind(t *testing.T) {
	t.Run("both headers present", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/workflows/wf_1", nil)
		r.Header.Set(HeaderOrgID, "org-a")
		r.Header.Set(HeaderTenantID, "tenant-a")
		s, err := Bind(r)
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		if s.OrgID != "org-a" || s.TenantID != "tenant-a" {
			t.Fatalf("unexpected scope: %+v", s)
		}
	})

	t.Run("org header omitted is a denial", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/workflows/wf_1", nil)
		r.Header.Set(HeaderTenantID, "tenant-a")
		if _, err := Bind(r); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("omitting %s must fail closed, got %v", HeaderOrgID, err)
		}
	})

	t.Run("tenant header omitted is a denial", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/workflows/wf_1", nil)
		r.Header.Set(HeaderOrgID, "org-a")
		if _, err := Bind(r); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("omitting %s must fail closed, got %v", HeaderTenantID, err)
		}
	})

	t.Run("no headers at all is a denial", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/workflows/wf_1", nil)
		if _, err := Bind(r); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("a request with no identity must fail closed, got %v", err)
		}
	})

	t.Run("whitespace-only headers are absent", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/workflows/wf_1", nil)
		r.Header.Set(HeaderOrgID, "   ")
		r.Header.Set(HeaderTenantID, "\t")
		if _, err := Bind(r); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("whitespace-only identity must fail closed, got %v", err)
		}
	})

	t.Run("a caller claiming the unowned sentinel is refused", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/workflows/wf_1", nil)
		r.Header.Set(HeaderOrgID, UnownedOrgSentinel)
		r.Header.Set(HeaderTenantID, UnownedOrgSentinel)
		if _, err := Bind(r); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("the sentinel must never bind, got %v", err)
		}
	})

	// #3065 R3 round 1: Bind reads the auth-stamped HEADER and nothing else.
	// A context value under a plain string key must not be able to assert a
	// tenancy — that is a colliding-key trust path into an authorization
	// decision, and the census found no production writer of those keys.
	t.Run("a context value cannot assert a scope", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/workflows/wf_1", nil)
		//nolint:staticcheck // deliberately the plain string key an attacker-ish caller might collide on
		ctx := context.WithValue(r.Context(), "org_id", "org-a") //nolint:revive
		//nolint:staticcheck // ditto
		ctx = context.WithValue(ctx, "tenant_id", "tenant-a") //nolint:revive
		if _, err := Bind(r.WithContext(ctx)); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("context values must not bind a scope, got %v", err)
		}
	})

	t.Run("nil request", func(t *testing.T) {
		if _, err := Bind(nil); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("nil request must fail closed, got %v", err)
		}
	})
}

func TestValidateRowKeys(t *testing.T) {
	cases := []struct {
		name        string
		org, tenant string
		wantErr     bool
	}{
		{"both present", "org-a", "tenant-a", false},
		{"org missing", "", "tenant-a", true},
		{"tenant missing", "org-a", "", true},
		{"both missing", "", "", true},
		{"whitespace only", " ", " ", true},
		{"sentinel is not a valid owner", UnownedOrgSentinel, "tenant-a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRowKeys(tc.org, tc.tenant)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateRowKeys(%q,%q) = %v, wantErr=%v", tc.org, tc.tenant, err, tc.wantErr)
			}
		})
	}
}

// TestNew mirrors Bind's contract for the non-HTTP constructor.
func TestNew(t *testing.T) {
	if _, err := New("org-a", "tenant-a"); err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tc := range [][2]string{{"", "tenant-a"}, {"org-a", ""}, {"", ""}, {UnownedOrgSentinel, "tenant-a"}} {
		if _, err := New(tc[0], tc[1]); !errors.Is(err, ErrNoCallerScope) {
			t.Fatalf("New(%q,%q) must fail closed, got %v", tc[0], tc[1], err)
		}
	}
}

// TestFailOpenSQLRule pins the SQL half of the lint against the exact
// fragments the codebase contained, so a future relaxation of the regex is
// visible rather than silent.
func TestFailOpenSQLRule(t *testing.T) {
	flagged := []struct{ name, sql string }{
		{"#3065 F4 verbatim (budgets)", "AND ($2 = '' OR org_id IS NULL OR org_id = '' OR org_id = $2)"},
		{"#3065 replay summaries", "AND ($3 = '' OR tenant_id IS NULL OR tenant_id = '' OR tenant_id = $3)"},
		{"caller-empty disjunct alone", "WHERE a = $1 AND ($2 = '' OR org_id = $2)"},
		{"qualified column", "WHERE ($1 = '' OR w.tenant_id = $1)"},
		{"bare null disjunct", "WHERE scope = $1 AND (org_id = $2 OR org_id IS NULL)"},
	}
	for _, tc := range flagged {
		t.Run("flagged/"+tc.name, func(t *testing.T) {
			if _, bad := failOpenSQL(tc.sql); !bad {
				t.Fatalf("must be flagged: %s", tc.sql)
			}
		})
	}

	clean := []struct{ name, sql string }{
		{"strict equality", "WHERE id = $1 AND org_id = $2 AND tenant_id = $3"},
		{"guarded null branch", "WHERE (org_id = $5 OR (org_id IS NULL AND $5 = ''))"},
		{"null tenant as a scope selector, not a disjunct", "WHERE policy_id = $1 AND organization_id = $2 AND tenant_id IS NULL"},
		{"optional non-tenancy narrowing", "WHERE w.tenant_id = $1 AND ($2 = '' OR w.user_id = $2)"},
		{"no tenancy column at all", "WHERE ($1 = '' OR name = $1)"},
	}
	for _, tc := range clean {
		t.Run("clean/"+tc.name, func(t *testing.T) {
			if why, bad := failOpenSQL(tc.sql); bad {
				t.Fatalf("false positive on %s: %s", tc.sql, why)
			}
		})
	}
}

// TestFailOpenChainRule_CatchesTheReintroductionShapes pins the Go half of the
// lint against the forms an R3 review demonstrated it originally missed.
//
// The first version only walked `&&` chains and only recognised a literal `""`
// comparison, so nine of eleven realistic reintroductions evaded it — most
// importantly the De Morgan dual (`a == "" || b == "" || b == a`), which is
// how an `isAuthorized` helper is naturally written, and `len(x) > 0`, which
// is how the same check is written by anyone avoiding a string literal.
func TestFailOpenChainRule_CatchesTheReintroductionShapes(t *testing.T) {
	flagged := []struct{ name, src string }{
		{"the original reject form", `
			package p
			func f(callerOrg, rowOrg string) bool {
				return callerOrg != "" && rowOrg != "" && rowOrg != callerOrg
			}`},
		{"the De Morgan allow form", `
			package p
			func f(callerOrg, rowOrg string) bool {
				return callerOrg == "" || rowOrg == "" || rowOrg == callerOrg
			}`},
		{"len-based emptiness", `
			package p
			func f(callerOrg, rowOrg string) bool {
				return len(callerOrg) > 0 && len(rowOrg) > 0 && rowOrg != callerOrg
			}`},
		{"len-based, allow polarity", `
			package p
			func f(callerTenant, rowTenant string) bool {
				return len(callerTenant) == 0 || len(rowTenant) == 0 || rowTenant == callerTenant
			}`},
		{"emptiness helper by name", `
			package p
			func notEmpty(s string) bool { return s != "" }
			func f(callerOrg, rowOrg string) bool {
				return notEmpty(callerOrg) && notEmpty(rowOrg) && rowOrg != callerOrg
			}`},
		{"named empty constant", `
			package p
			const emptyOrg = ""
			func f(callerOrg, rowOrg string) bool {
				return callerOrg != emptyOrg && rowOrg != emptyOrg && rowOrg != callerOrg
			}`},
	}
	for _, tc := range flagged {
		t.Run("flagged/"+tc.name, func(t *testing.T) {
			if !lintFlagsSource(t, tc.src) {
				t.Fatalf("this reintroduction of the #3065 idiom must fail the build:\n%s", tc.src)
			}
		})
	}

	clean := []struct{ name, src string }{
		{"the fixed form — no emptiness test at all", `
			package p
			import "axonflow/platform/shared/tenantscope"
			func f(s tenantscope.Scope, rowOrg, rowTenant string) error {
				return s.Authorize(rowOrg, rowTenant)
			}`},
		{"non-tenancy identifiers (the PII masking shape)", `
			package p
			func f(value, masked string) bool {
				return value != "" && masked != "" && masked != value
			}`},
		{"a plain equality guard with no emptiness test", `
			package p
			func f(callerOrg, rowOrg string) bool { return rowOrg == callerOrg }`},
	}
	for _, tc := range clean {
		t.Run("clean/"+tc.name, func(t *testing.T) {
			if lintFlagsSource(t, tc.src) {
				t.Fatalf("false positive:\n%s", tc.src)
			}
		})
	}
}

// lintFlagsSource runs the Go half of the rule over an in-memory source file.
func lintFlagsSource(t *testing.T, src string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "probe.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}
	flagged := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			be, ok := n.(*ast.BinaryExpr)
			if !ok || (be.Op != token.LAND && be.Op != token.LOR) {
				return true
			}
			if parentIsBoolChain(fn, be) {
				return true
			}
			if _, bad := failOpenChain(fset, be.Op, flattenBoolChain(be)); bad {
				flagged = true
			}
			return true
		})
	}
	return flagged
}
