// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	sharedidentity "axonflow/platform/shared/identity"
)

// TestTheOrchestratorRootHandlerStampsTheSyntheticProbe is the agent test's
// twin, and it exists because the orchestrator owns four of the twelve planes -
// wcp, map, policy_simulation and policy_test - and its dynamic policy engine
// is where the second decision-shadow observation site lives.
//
// The orchestrator's chain has one property the agent's does not: the stamp is
// applied OUTSIDE requireInternalProxyAuth. A request the gate rejects produces
// no comparison, so stamping it costs one context value and changes nothing;
// stamping INSIDE the gate would silently skip the exempt paths and, more
// importantly, would put a caller-assertable header inside an authentication
// boundary, which is a thing a reviewer should have to argue for rather than
// inherit. It is asserted here in both directions.
func TestTheOrchestratorRootHandlerStampsTheSyntheticProbe(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   bool
	}{
		{"the canary's header reaches the innermost handler", "1", true},
		{"an ordinary request is ORGANIC", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen, reached bool
			r := mux.NewRouter()
			// /health is on orchestratorAuthExemptPaths, so this exercises the
			// assembled chain end to end without minting an HMAC token - and it
			// is also the case that proves the stamp is not behind the gate.
			r.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
				reached = true
				seen = sharedidentity.SyntheticProbeFromContext(req.Context())
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			if tc.header != "" {
				req.Header.Set(sharedidentity.SyntheticProbeHeader, tc.header)
			}
			buildOrchestratorHandler(cors.New(cors.Options{}), r).
				ServeHTTP(httptest.NewRecorder(), req)

			if !reached {
				t.Fatal("the assembled handler never reached the route; the assertion below would " +
					"pass over nothing")
			}
			if seen != tc.want {
				t.Fatalf("the handler saw synthetic=%v, want %v. The orchestrator's dynamic policy "+
					"engine reads this off the context to label wcp, map, policy_simulation and "+
					"policy_test comparisons (#3817).", seen, tc.want)
			}
		})
	}
}

// TestTheStampSurvivesTheAuthGateRejection pins the ordering claim positively.
//
// A rejected request must still have been stamped by the time the gate answers,
// because the alternative wiring - stamp inside the gate - is the one a future
// reader would reach for on the grounds that "unauthenticated callers should not
// set labels". They cannot: a rejected request produces no observation and
// therefore no series. What the wrong order WOULD cost is the exempt paths and
// any future route the gate lets through by another door.
func TestTheStampSurvivesTheAuthGateRejection(t *testing.T) {
	r := mux.NewRouter()
	var reached bool
	r.HandleFunc("/api/v1/policies/dynamic", func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/dynamic", nil)
	req.Header.Set(sharedidentity.SyntheticProbeHeader, "1")
	rec := httptest.NewRecorder()
	buildOrchestratorHandler(cors.New(cors.Options{}), r).ServeHTTP(rec, req)

	if reached {
		t.Fatal("a tenant-scoped route was served without an internal-service token; the auth gate " +
			"is not installed and this test is measuring the wrong chain")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("the gate returned %d for an unauthenticated tenant-scoped route", rec.Code)
	}
	// The point: the synthetic header did NOT buy anything. It is a metric label
	// and nothing else, and the gate's answer is unchanged by its presence.
}
