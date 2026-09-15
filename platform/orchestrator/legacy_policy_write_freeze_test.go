// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/lib/pq"

	"axonflow/platform/shared/legacyfreeze"
)

// freezeStubService is a PolicyServicer that fails every write with a supplied
// error. It exists so the RESPONSE can be asserted: the freeze is a fact about
// what a customer's integration receives, and a test on the classifier alone
// would not notice a handler that classified correctly and then wrote 500
// anyway.
type freezeStubService struct{ err error }

func (s *freezeStubService) CreatePolicy(context.Context, string, string, *CreatePolicyRequest, string) (*PolicyResource, error) {
	return nil, s.err
}

func (s *freezeStubService) UpdatePolicy(context.Context, string, string, string, *UpdatePolicyRequest, string) (*PolicyResource, error) {
	return nil, s.err
}

func (s *freezeStubService) DeletePolicy(context.Context, string, string, string, string) error {
	return s.err
}

func (s *freezeStubService) ImportPolicies(context.Context, string, string, *ImportPoliciesRequest, string) (*ImportPoliciesResponse, error) {
	return nil, s.err
}

// MayWriteLegacyPolicies answers as an owner pool does: this stub models the
// write REACHING the database, so the refusal these tests see is the one Answer
// classifies. The pre-read refusal is legacy_policy_import_guard_test.go's.
func (s *freezeStubService) MayWriteLegacyPolicies(context.Context) (bool, error) {
	return true, nil
}

// GetPolicy must SUCCEED: deletePolicy looks the policy up before deleting it,
// so a stub that failed here would refuse at the lookup and the delete path
// would never reach the freeze at all.
func (s *freezeStubService) GetPolicy(context.Context, string, string, string) (*PolicyResource, error) {
	return &PolicyResource{ID: "p1", Name: "existing"}, nil
}

func (s *freezeStubService) ListPolicies(context.Context, string, string, ListPoliciesParams) (*PoliciesListResponse, error) {
	return &PoliciesListResponse{}, nil
}

func (s *freezeStubService) TestPolicy(context.Context, string, string, string, *TestPolicyRequest) (*TestPolicyResponse, error) {
	return &TestPolicyResponse{}, nil
}

func (s *freezeStubService) GetPolicyVersions(context.Context, string, string) (*PolicyVersionResponse, error) {
	return &PolicyVersionResponse{}, nil
}

func (s *freezeStubService) ExportPolicies(context.Context, string, string) (*ExportPoliciesResponse, error) {
	return &ExportPoliciesResponse{}, nil
}

// freezeError is what Postgres raises once core/172 has revoked the write.
func freezeError() error {
	return fmt.Errorf("failed to insert policy: %w", &pq.Error{
		Code:    "42501",
		Message: `permission denied for table dynamic_policies`,
	})
}

// rlsError is the OTHER 42501: a WITH CHECK violation, which is a defect in our
// own org scoping and must NOT be reported as the freeze.
func rlsError() error {
	return fmt.Errorf("failed to insert policy: %w", &pq.Error{
		Code:    "42501",
		Message: `new row violates row-level security policy for table "dynamic_policies"`,
	})
}

// versionsRefusal is a privilege refusal on a table these routes write that
// core/172 did NOT freeze: the repository writes policy_versions on the same
// transaction. It must answer 500, because "author through the typed route" is
// the wrong remedy for a table whose write path is something else - and it is
// the case that goes red in THIS binary if the shared classifier ever stops
// anchoring on the table name.
func versionsRefusal() error {
	return fmt.Errorf("failed to record version: %w", &pq.Error{
		Code:    "42501",
		Message: `permission denied for table policy_versions`,
	})
}

// namedElsewhere and prefixSibling are the anchor's two weaker forms: the
// frozen name outside the subject position, and a longer table sharing it as
// a prefix. Both must answer 500 in THIS binary too - a classifier that kept
// the table names but lost either property would pass every other case here.
func namedElsewhere() error {
	return fmt.Errorf("x: %w", &pq.Error{Code: "42501",
		Message: `permission denied for table policy_versions (while inserting into dynamic_policies)`})
}

func prefixSibling() error {
	return fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table dynamic_policies_archive`})
}

// TestTheLegacyFreezeIsAnsweredAsAClearClientErrorRatherThanA500 is #4010's
// customer-facing half.
//
// Before this, every legacy policy WRITE fell through to
// `500 INTERNAL_ERROR "Failed to create policy"` with the real cause visible
// only in the server log - so an operator whose integration stopped working saw
// a server fault and had nothing to act on, when what had actually happened is
// that the write path was retired and a different one exists.
//
// The classifier itself is tested where it lives, in package legacyfreeze
// (TestTheFreezeClassifierMatchesTheCausePositively).
func TestTheLegacyFreezeIsAnsweredAsAClearClientErrorRatherThanA500(t *testing.T) {
	// ALL FOUR WRITE ROUTES, not the two the issue named. core/172 revokes
	// INSERT, UPDATE, DELETE and TRUNCATE, and the repository writes
	// dynamic_policies from Create, Update, Delete and both ImportBulk paths.
	routes := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"create", http.MethodPost, "/api/v1/policies", `{"name":"n","type":"context_aware"}`},
		{"update", http.MethodPut, "/api/v1/policies/p1", `{"name":"n"}`},
		{"delete", http.MethodDelete, "/api/v1/policies/p1", ``},
		{"import", http.MethodPost, "/api/v1/policies/import", `{"policies":[{"name":"n","type":"context_aware"}]}`},
	}

	call := func(t *testing.T, svcErr error, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		// The registrar run.go calls, over the package-level handler its
		// routes delegate to: the path production takes, stamp included.
		prev := policyAPIHandler
		policyAPIHandler = NewPolicyAPIHandler(&freezeStubService{err: svcErr})
		t.Cleanup(func() { policyAPIHandler = prev })
		router := mux.NewRouter()
		registerLegacyPolicyRoutes(router, nil, nil)
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		r.Header.Set("X-Tenant-ID", "tenant-a")
		r.Header.Set("X-Org-ID", "org-a")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, r)
		return rr
	}

	for _, rt := range routes {
		t.Run(rt.name+" answers the freeze", func(t *testing.T) {
			rr := call(t, freezeError(), rt.method, rt.path, rt.body)
			if rr.Code != http.StatusConflict {
				t.Fatalf("status=%d, want 409; a caller told 500 reads this as our fault and retries. body=%s",
					rr.Code, rr.Body.String())
			}
			// The refusal is served from the deprecated export surface, so it
			// names the successor on the wire as well as in its body.
			assertDeprecationSignal(t, rt.path, rr.Header())
			var out PolicyAPIError
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				t.Fatalf("decode body: %v (%s)", err, rr.Body.String())
			}
			if out.Error.Code != legacyfreeze.ErrCode {
				t.Fatalf("code=%q, want %q", out.Error.Code, legacyfreeze.ErrCode)
			}
			// THE REMEDY MUST BE NAMED, and it must be the route THIS binary
			// serves. A refusal an operator cannot act on is only marginally
			// better than the 500 it replaced.
			if !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
				t.Fatalf("the refusal does not name the typed authoring route as the write path: %q", out.Error.Message)
			}
		})

		t.Run(rt.name+" does NOT answer an RLS violation as the freeze", func(t *testing.T) {
			// The discrimination that makes this classifier honest. An RLS
			// WITH CHECK failure carries the SAME SQLSTATE and is a defect in
			// OUR org scoping; reporting it as the freeze would tell an
			// operator to change their integration because of our bug.
			rr := call(t, rlsError(), rt.method, rt.path, rt.body)
			if rr.Code == http.StatusConflict {
				t.Fatalf("an RLS WITH CHECK violation was reported as the legacy freeze; both are 42501 and only "+
					"the message separates them. body=%s", rr.Body.String())
			}
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d, want 500 - an unclassified 42501 must keep today's behaviour", rr.Code)
			}
		})

		t.Run(rt.name+" does NOT answer a refusal on a table the freeze does not cover", func(t *testing.T) {
			rr := call(t, versionsRefusal(), rt.method, rt.path, rt.body)
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d, want 500 - a privilege refusal on policy_versions is not the core/172 freeze. body=%s",
					rr.Code, rr.Body.String())
			}
		})

		for label, mk := range map[string]func() error{
			"the frozen table named outside the subject position": namedElsewhere,
			"a longer table sharing the frozen name as a prefix":  prefixSibling,
		} {
			t.Run(rt.name+" does NOT answer "+label, func(t *testing.T) {
				rr := call(t, mk(), rt.method, rt.path, rt.body)
				if rr.Code != http.StatusInternalServerError {
					t.Fatalf("status=%d, want 500. body=%s", rr.Code, rr.Body.String())
				}
			})
		}
	}

	// ANTI-VACUITY: the same routes with no error at all must NOT answer 409,
	// or every assertion above would pass against a handler that refuses
	// everything.
	t.Run("a successful write is untouched", func(t *testing.T) {
		rr := call(t, nil, http.MethodDelete, "/api/v1/policies/p1", ``)
		if rr.Code == http.StatusConflict {
			t.Fatalf("a successful delete answered the freeze: %s", rr.Body.String())
		}
	})
}

// TestTheFreezeRemedyIsTheRouteTheOrchestratorServes welds the route the
// refusal names to the route this binary registers.
//
// The message is defined in package legacyfreeze so the agent can send it too,
// which puts the route's spelling in a package that does not serve it. A
// rename of the typed authoring route that missed that constant would make
// every refusal send an operator to a 404, on both binaries at once.
func TestTheFreezeRemedyIsTheRouteTheOrchestratorServes(t *testing.T) {
	if legacyfreeze.TypedAuthoringRoute != TypedAuthoringRoutePrefix {
		t.Fatalf("legacyfreeze.TypedAuthoringRoute = %q, but the orchestrator serves typed authoring at %q",
			legacyfreeze.TypedAuthoringRoute, TypedAuthoringRoutePrefix)
	}
}

// TestTemplateApplyAnswersTheFreeze is #4088: POST /api/v1/templates/{id}/apply
// creates a policy through PolicyRepository.Create, so core/172 refuses it the
// way it refuses the policy routes, and it must answer the same way.
func TestTemplateApplyAnswersTheFreeze(t *testing.T) {
	apply := func(t *testing.T, svcErr error) *httptest.ResponseRecorder {
		t.Helper()
		h := NewTemplateAPIHandler(&mockTemplateService{
			applyTemplateFunc: func(context.Context, string, string, string, *ApplyTemplateRequest, string) (*ApplyTemplateResponse, error) {
				if svcErr != nil {
					return nil, svcErr
				}
				return &ApplyTemplateResponse{Success: true, UsageID: "u1"}, nil
			},
		})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tpl_general_rate_limiting/apply",
			strings.NewReader(`{"policy_name":"rate limit","variables":{"max_requests_per_hour":100},"enabled":true}`))
		r.Header.Set("X-Tenant-ID", "tenant-a")
		r.Header.Set("X-Org-ID", "org-a")
		rr := httptest.NewRecorder()
		h.HandleApplyTemplate(rr, r, "tpl_general_rate_limiting")
		return rr
	}
	// The shape the service returns: ApplyTemplate wraps the repository error
	// with %w, and the repository wraps the driver's.
	wrap := func(err error) error { return fmt.Errorf("failed to create policy from template: %w", err) }

	t.Run("the freeze is answered 409 with the code and the typed route named", func(t *testing.T) {
		rr := apply(t, wrap(freezeError()))
		if rr.Code != http.StatusConflict {
			t.Fatalf("status=%d, want 409. body=%s", rr.Code, rr.Body.String())
		}
		var out TemplateAPIError
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode body: %v (%s)", err, rr.Body.String())
		}
		if out.Error.Code != legacyfreeze.ErrCode {
			t.Fatalf("code=%q, want %q", out.Error.Code, legacyfreeze.ErrCode)
		}
		if !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
			t.Fatalf("the refusal does not name the typed authoring route: %q", out.Error.Message)
		}
	})

	// Every other outcome keeps the status it had. The first two are the
	// discrimination; the rest prove the new arm sits below the route's own
	// refusals and above nothing but the generic 500.
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"an RLS violation stays a server error", wrap(rlsError()), http.StatusInternalServerError},
		{"a refusal on a table the freeze does not cover stays a server error", wrap(versionsRefusal()), http.StatusInternalServerError},
		{"the frozen table named outside the subject position stays a server error", wrap(namedElsewhere()), http.StatusInternalServerError},
		{"a longer table sharing the frozen name as a prefix stays a server error", wrap(prefixSibling()), http.StatusInternalServerError},
		{"an ordinary failure stays a server error", wrap(errors.New("connection reset")), http.StatusInternalServerError},
		{"a missing template stays 404", errors.New("template not found"), http.StatusNotFound},
		{"a validation failure stays 400", &TemplateValidationError{Errors: []TemplateFieldError{{Field: "policy_name", Message: "too short"}}}, http.StatusBadRequest},
		{"a successful apply stays 201", nil, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := apply(t, tc.err)
			if rr.Code != tc.status {
				t.Fatalf("status=%d, want %d. body=%s", rr.Code, tc.status, rr.Body.String())
			}
		})
	}
}
