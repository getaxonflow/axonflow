// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// The /api/v1/connectors/* family declares `400 -> application/json
// ErrorResponse` and emitted text/plain via http.Error, so `res.json()` threw
// on every error (#3901 §1, #3896). It is the documented ingress through the
// agent proxy (proxy.go:756), which is why this family and not another.
//
// EVERY ASSERTION HERE IS DRIVEN. The handler is called, the bytes it wrote are
// decoded, and the decode is the assertion - reading the handler and observing
// that it now calls sendErrorResponse would prove nothing about what reaches a
// client, which is precisely the mistake that let the original defect ship
// under a spec that said otherwise.

package orchestrator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/registry"
)

// documentedErrorEnvelope is the shape docs/api/orchestrator-api.yaml declares
// as ErrorResponse: `{success: boolean, error: string}`.
//
// ONE STRUCT FOR EVERY ENDPOINT IN THE FAMILY. That is the property #3897 says
// an integrator cannot get today ("a client cannot write one deserialiser"), so
// the test is written the way the client would be: one type, every endpoint,
// and DisallowUnknownFields off because additive members are allowed while a
// changed or absent member is not.
type documentedErrorEnvelope struct {
	Success *bool  `json:"success"`
	Error   string `json:"error"`
}

// connectorErrorCase is one reachable error path in the family.
//
// Each is chosen to be reachable WITHOUT a database, a registry or a licence:
// they are the decode and lookup failures that happen before any global is
// touched. A case needing initialization would be skipped in unit CI, and a
// skipped case is a case that proves nothing.
type connectorErrorCase struct {
	name       string
	method     string
	target     string
	route      string
	handler    http.HandlerFunc
	body       string
	wantStatus int
}

func connectorErrorCases() []connectorErrorCase {
	return []connectorErrorCase{
		{
			name:       "install rejects an undecodable body",
			method:     http.MethodPost,
			target:     "/api/v1/connectors/postgres/install",
			route:      "/api/v1/connectors/{id}/install",
			handler:    installConnectorHandler,
			body:       "{not json",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "install rejects an unknown connector id",
			method:     http.MethodPost,
			target:     "/api/v1/connectors/no-such-connector-xyz/install",
			route:      "/api/v1/connectors/{id}/install",
			handler:    installConnectorHandler,
			body:       `{"tenant_id":"t1"}`,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "connector detail rejects an unknown connector id",
			method:     http.MethodGet,
			target:     "/api/v1/connectors/no-such-connector-xyz",
			route:      "/api/v1/connectors/{id}",
			handler:    getConnectorDetailsHandler,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "uninstall rejects an unregistered connector",
			method:     http.MethodDelete,
			target:     "/api/v1/connectors/no-such-connector-xyz/uninstall",
			route:      "/api/v1/connectors/{id}/uninstall",
			handler:    uninstallConnectorHandler,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "health check reports an unregistered connector",
			method:     http.MethodGet,
			target:     "/api/v1/connectors/no-such-connector-xyz/health",
			route:      "/api/v1/connectors/{id}/health",
			handler:    connectorHealthCheckHandler,
			wantStatus: http.StatusInternalServerError,
		},
	}
}

// TestTheConnectorFamilyErrorsAreDecodableByOneClient is the guard.
func TestTheConnectorFamilyErrorsAreDecodableByOneClient(t *testing.T) {
	// The uninstall and health routes dereference the package-level registry
	// unconditionally, so without one they panic rather than answering - which
	// is why the first version of this test drove only the two routes that do
	// not touch it, and why four of the eleven fixed sites were unguarded.
	// An empty in-memory registry is enough: every case below names a
	// connector it does not contain, which is the error path being asserted.
	if connectorRegistry == nil {
		connectorRegistry = registry.NewRegistry()
		t.Cleanup(func() { connectorRegistry = nil })
	}

	cases := connectorErrorCases()

	// THE FLOOR IS ROUTE COVERAGE, not the length of the slice above it.
	// The first version compared `len(cases)` against 3 while the function
	// returned a fixed three-element literal - a restatement of a constant,
	// which R3 correctly called out as decoration. Worse, its message claimed
	// the sweep showed the envelope was uniform ACROSS the family while it
	// drove two of the five routes, so four of the eleven sites this change
	// fixed could revert with the test green - measured, not supposed.
	//
	// THE ROUTES WITH AN ERROR SITE, which is four of the family's five.
	//
	// R3 round 2 caught the first version holding four entries under a comment
	// claiming five, with `GET /api/v1/connectors` in neither the list nor the
	// cases. Adding a case for it was the wrong repair: `listConnectorsHandler`
	// contains ZERO error sites - measured, not assumed - so there is nothing
	// on that route for this test to assert about and nothing that can regress
	// to text/plain. The eleven sites this change converted are 6 in install,
	// 3 in uninstall, 1 in the detail handler and 1 in health, and the four
	// routes below are exactly the ones that carry them.
	//
	// R3 also correctly noted that a SIXTH route added to run.go would not fail
	// here, because this is a literal rather than a derivation from run.go.
	// That is left as it is and said plainly rather than papered over: deriving
	// it would mean parsing run.go from a test whose subject is the response
	// envelope, and a wrong derivation is worse than an honest list.
	familyRoutes := []string{
		"/api/v1/connectors/{id}",
		"/api/v1/connectors/{id}/install",
		"/api/v1/connectors/{id}/uninstall",
		"/api/v1/connectors/{id}/health",
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.route] = true
	}
	var uncovered []string
	for _, r := range familyRoutes {
		if !covered[r] {
			uncovered = append(uncovered, r)
		}
	}
	if len(uncovered) > 0 {
		t.Fatalf("%d error-bearing route(s) of the /api/v1/connectors/* family have no case here: %v. "+
			"Every http.Error site on an undriven route can revert to text/plain with this test green, "+
			"which is the state four of the eleven fixed sites were in.", len(uncovered), uncovered)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mux.NewRouter()
			r.HandleFunc(tc.route, tc.handler)
			rec := httptest.NewRecorder()
			var body *bytes.Reader
			if tc.body == "" {
				body = bytes.NewReader(nil)
			} else {
				body = bytes.NewReader([]byte(tc.body))
			}
			r.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, body))

			if rec.Code != tc.wantStatus {
				t.Fatalf("got status %d, want %d; the case no longer reaches the error path it names, "+
					"so its envelope assertion is about something else.\nbody: %s",
					rec.Code, tc.wantStatus, rec.Body.String())
			}

			// THE DEFECT, STATED AS THE ASSERTION. http.Error writes
			// `text/plain; charset=utf-8`, and a client doing res.json() throws
			// on it while the published document promises application/json.
			ct := rec.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type is %q, and docs/api/orchestrator-api.yaml declares this "+
					"response as application/json ErrorResponse. A client calling res.json() throws "+
					"(#3901 §1).\nbody: %s", ct, rec.Body.String())
			}

			var env documentedErrorEnvelope
			dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
			if err := dec.Decode(&env); err != nil {
				t.Fatalf("the response does not decode into the documented ErrorResponse shape: %v\n"+
					"body: %s", err, rec.Body.String())
			}
			if env.Success == nil {
				t.Errorf("the response carries no `success` member; ErrorResponse declares it and a "+
					"client branching on it sees the zero value instead.\nbody: %s", rec.Body.String())
			} else if *env.Success {
				t.Errorf("`success` is true on a %d response.\nbody: %s", rec.Code, rec.Body.String())
			}
			if strings.TrimSpace(env.Error) == "" {
				t.Errorf("the response carries no `error` message, so a client has nothing to show a "+
					"user.\nbody: %s", rec.Body.String())
			}
		})
	}
}
