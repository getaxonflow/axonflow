// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/deploymode"
)

// ---------------------------------------------------------------------------
// Vocabularies, DERIVED from the packages that own them.
//
// Every one of these could have been a hand-written list beside the domain
// declaration, and that is exactly the shape #3720 says is blind: the PEP
// handshake's own history records a first version of its domain test that
// "built the 'declared' set from allPEPHandshakeOutcomes() and then compared it
// against a hand-copied literal of the same six constants, so it could only
// fail if somebody edited one of two adjacent lists".
// ---------------------------------------------------------------------------

func operationalStateNames() []string {
	states := contract.AllOperationalStates()
	out := make([]string, 0, len(states))
	for _, s := range states {
		out = append(out, string(s))
	}
	return out
}

func authzenErrorCodeNames() []string {
	codes := contract.AllAuthZENErrorCodes()
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		out = append(out, string(c))
	}
	return out
}

// canonicalModeNames is the deployment modes the client-version recorder can
// actually emit: deploymode.Resolve folds an alias onto its canonical name, so
// the ALIASES in RecognisedModes() are unreachable at that label.
func canonicalModeNames() []string {
	modes := deploymode.CanonicalModes()
	out := make([]string, 0, len(modes))
	for m := range modes {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func obligationTypeNames() []string {
	types := contract.AllObligationTypes()
	out := make([]string, 0, len(types))
	for _, ty := range types {
		out = append(out, string(ty))
	}
	return out
}

// policyIDShape is the shape a seeded policy id takes. It is NOT a bound on the
// blocks metric's `policy` label by itself - see boundedBlockPolicy and
// TestBoundedBlockPolicyCollapsesPerTenantIds - and is declared so the domain
// says what it actually admits rather than claiming a closed set it does not
// have.
var policyIDShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)

// clientSlugShape / clientVersionShape / clientVersionMaxSeriesDeclared mirror
// the client-version family's own gates, which live in an enterprise-tagged
// file this untagged declaration cannot name.
//
// A mirror is a second list, so it is pinned:
// TestClientVersionDomainsMatchTheRealConstants (enterprise-tagged) fails if
// either side moves.
var (
	clientSlugShape                = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	clientVersionShape             = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)
	clientVersionMaxSeriesDeclared = 1024
)

// unknownObligationLabelDeclared mirrors capabilityRefusalUnknownObligation,
// which is declared in pep_handshake_enforce_enterprise.go. The METRIC is
// declared in the untagged pep_handshake.go, so the census derives it in both
// builds and this untagged file has to name its domain - while the constant
// itself exists in only one of them. Pinned, for the reason above.
const unknownObligationLabelDeclared = "unknown"

// ---------------------------------------------------------------------------
// Drivers. Each one puts a CALLER-SUPPLIED value through the real write path.
// ---------------------------------------------------------------------------

// driveDecideForLabels sends one POST /api/v1/decide through the real handler.
//
// The response is deliberately not asserted. This test is about what reached a
// LABEL, and every outcome the handler can produce - 200, a 400 on the stage
// gate, a refusal - writes to decideRequests. Requiring a particular status
// code would couple it to the decision engine's wiring and would make the
// hostile cases (which are supposed to be refused) look like failures.
func driveDecideForLabels(t *testing.T, clientHeader, gatewayID, stage string) {
	t.Helper()
	body, err := json.Marshal(DecideRequest{
		Stage:          stage,
		CallerIdentity: DecisionCallerIdentity{GatewayID: gatewayID},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o"},
		Query:          "hello",
	})
	if err != nil {
		t.Fatalf("marshal decide request: %v", err)
	}
	driveDecideRaw(t, clientHeader, body, nil)
}

// driveDecideRaw sends one POST /api/v1/decide with a caller-supplied body and
// optional extra headers.
//
// # THE PRE-DECODE ARMS ARE A SEPARATE CALL SITE, AND MISSING THEM LEFT THE
// # HEADLINE MUTANT ALIVE
//
// classifyDecisionOrigin is called TWICE: once up-front at
// decision_handler.go:664, and again at :804 once caller_identity.gateway_id is
// parsed. Only the second is reached by a well-formed request, so replacing the
// FIRST with the raw header - the exact mutation this file's plant describes -
// survived the entire platform/agent package. The two arms that carry the
// up-front value both return BEFORE the refresh: a refused PEP handshake, and a
// body that does not decode. Both are driven below.
func driveDecideRaw(t *testing.T, clientHeader string, body []byte, extra map[string]string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, decisionHandlerPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if clientHeader != "" {
		// http.Header.Set would panic or mangle a header containing a newline,
		// and the newline case is one of the inputs that matters, so the value
		// is placed directly into the map the way a hostile peer's bytes would
		// arrive after parsing.
		req.Header["X-Axonflow-Client"] = []string{clientHeader}
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
}

// hostilePEPHandshakeHeaders are caller-supplied X-Axonflow-PEP-Handshake
// values.
//
// The `family` label's value derives from a capability TYPE inside this header,
// and contract.FamilyOf's closed lookup is the only step between the two.
//
// The well-formed cases are built with contract.PEPHandshake.Encode rather than
// by hand-rolling base64 JSON: the wire form is the contract's to define, and a
// hand-rolled copy would drift into being refused as malformed - at which point
// every capability assertion below would be about the refusal path and nothing
// would say so.
func hostilePEPHandshakeHeaders(t *testing.T) []string {
	t.Helper()
	// caps is a SLICE, not a variadic: contract.PEPHandshake refuses an ABSENT
	// capabilities member while accepting an empty one - "an enforcement point
	// that discharges nothing declares an empty list rather than omitting the
	// member" - and a variadic with no arguments produces nil, which marshals
	// as absent. The DeclaredNone case below needs the empty list.
	encode := func(caps []contract.Capability) string {
		h := contract.PEPHandshake{
			ProfileVersion: contract.PEPHandshakeProfileV1,
			PEPID:          "labels-probe",
			Audience:       "https://example.test/audience",
			Capabilities:   caps,
		}
		v, refusal := h.Encode()
		if refusal != nil {
			t.Fatalf("encoding a probe handshake was refused: %v", refusal)
		}
		return v
	}
	cap := func(ty string) contract.Capability {
		return contract.Capability{Type: contract.ObligationType(ty), Version: 1}
	}
	// rawHandshake builds the header the way a HOSTILE caller does: base64 over
	// JSON it assembled itself.
	//
	// contract.PEPHandshake.Encode REFUSES an undeclared obligation type - "a
	// capability this build cannot name is one it cannot match" - so using it
	// for the out-of-domain cases turns them into a t.Fatal instead of an
	// input. A probe rejected by our own encoder never reaches the code under
	// test, and every assertion downstream of it would be vacuous. An attacker
	// does not call Encode.
	rawHandshake := func(types ...string) string {
		caps := make([]map[string]any, 0, len(types))
		for _, ty := range types {
			caps = append(caps, map[string]any{"type": ty, "version": 1})
		}
		body, err := json.Marshal(map[string]any{
			"profile_version": contract.PEPHandshakeProfileV1,
			"pep_id":          "labels-probe",
			"audience":        "https://example.test/audience",
			"capabilities":    caps,
		})
		if err != nil {
			t.Fatalf("marshal raw handshake: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(body)
	}

	return []string{
		// Not base64 at all - the malformed arm.
		"!!! not base64 !!!",
		// Valid base64 of something that is not a handshake.
		base64.RawURLEncoding.EncodeToString([]byte(`{"nope":true}`)),
		// A capability type nobody declared, hand-rolled past our own encoder.
		rawHandshake("a_type_nobody_declared"),
		// A type carrying label-separator bytes.
		rawHandshake(`type",plane="decision`),
		// Several distinct undeclared types in ONE request: if the family label
		// were unbounded, this alone is three new series from one caller.
		rawHandshake("type_one", "type_two", "type_three"),
		// A DECLARED, NON-ENTERPRISE type: plain acceptance.
		encode([]contract.Capability{cap(string(contract.ObFieldRedact))}),
		// AN ENTERPRISE-ONLY FAMILY, which is the ONLY input that reaches the
		// over-advertised counter at all: SplitOverAdvertised drops a capability
		// only when the edition is Community AND its family is enterprise-only,
		// and a type whose family cannot be resolved is KEPT. The first version
		// of this driver sent only undeclared types and collected ZERO series -
		// a green assertion about nothing, reported by metricdomain.Check's
		// zero-series floor rather than noticed by reading the code.
		encode([]contract.Capability{cap(string(contract.ObApprovalChallenge))}),
		// The dropped and kept arms of ONE request - hand-rolled, because the
		// undeclared half would be refused by Encode.
		rawHandshake(string(contract.ObApprovalChallenge), `still",plane="decision`),
		// Structurally valid, capabilities present and EMPTY: the DeclaredNone
		// case, which the contract deliberately distinguishes from absent.
		encode([]contract.Capability{}),
	}
}

// drivePEPHandshakeForLabels drives the handshake through the same entry point
// the decision handler uses, with a caller-supplied header.
func drivePEPHandshakeForLabels(t *testing.T, header string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, decisionHandlerPath, bytes.NewReader([]byte(`{}`)))
	req.Header.Set(contract.PEPHandshakeHeader, header)
	// The authenticated client id comes from the CREDENTIAL, not the header -
	// registry.ExternalPEPID's whole point - so it is a fixed value here and
	// the header is the only thing varying.
	res := resolvePEPHandshake(req, "test-client")
	recordPEPHandshakeOutcome(PlaneDecision, res)
	// #3766: the MCP plane writes the SAME two series with plane=PlaneMCP. It
	// is driven here rather than left to the MCP handler tests because the
	// census asserts the DRIVEN set: a plane value declared in the domain but
	// never written by any driver reads to this guard as an undriven
	// declaration, and a plane written by the handlers but never driven here
	// would leave the declaration unexercised. Same header, same resolution,
	// the plane label is the only thing that differs.
	recordPEPHandshakeOutcome(PlaneMCP, res)
	// #3778: the gateway pre-check plane writes the same two series with
	// plane=PlaneGateway. Driven here for the same reason PlaneMCP is: the
	// census asserts the DRIVEN set, so a plane declared in the domain but
	// never written reads as an undriven declaration.
	recordPEPHandshakeOutcome(PlaneGateway, res)
}

// driveAuthZENForLabels sends one POST to the AuthZEN evaluation route with a
// caller-supplied envelope and client header.
//
// The refusal path is the one that matters here: it writes BOTH
// axonflow_authzen_refusals_total{code} and
// axonflow_authzen_requests_total{outcome="refused",shape="unknown",origin},
// and `origin` on that path comes from the SAME classifyDecisionOrigin call
// site shape that survived a mutant on the decide plane.
func driveAuthZENForLabels(t *testing.T, clientHeader string, body []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, authzenHandlerPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if clientHeader != "" {
		req.Header["X-Axonflow-Client"] = []string{clientHeader}
	}
	rr := httptest.NewRecorder()
	handleAuthZENEvaluation(rr, req)
}

// hostileAuthZENEnvelopes are caller-supplied AuthZEN request bodies.
func hostileAuthZENEnvelopes() [][]byte {
	return [][]byte{
		[]byte("{not json"),
		[]byte(`{}`),
		[]byte(`{"subject":{},"action":{},"resource":{}}`),
		[]byte(`{"subject":{"type":"user","id":"u1"},"action":{"name":"read"},` +
			`"resource":{"type":"doc","id":"d1"}}`),
		[]byte(`{"evaluations":[]}`),
		[]byte(`{"evaluations":[{"subject":{"type":"user","id":"u1"},` +
			`"action":{"name":"read"},"resource":{"type":"doc","id":"d1"}}]}`),
	}
}
