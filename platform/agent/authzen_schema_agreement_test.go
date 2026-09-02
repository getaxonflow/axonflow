package agent

import (
	"encoding/json"
	"testing"

	"axonflow/platform/decision/contract"
)

// admitThroughTheRoute is THE PRODUCTION BOUNDARY for an inbound envelope:
// decode strictly, then run the adapter the route runs.
//
// It is deliberately both steps, and they are the two steps
// handleAuthZENEvaluation actually takes. DecodeAuthZENEnvelope enforces the
// STRUCTURAL rules - strict keys, no duplicate members, exactly one of the two
// top-level members, a non-empty plural array - and nothing else; it does not
// enforce the schema's required set, so `{"subject":{"id":"alice@corp"}}`
// decodes cleanly. Everything past that is mapEnvelope's, including the
// completeness and required-ness rules, which are resolved AFTER a plural
// entry has inherited from the shared base.
//
// WHY THIS TEST LIVES HERE AND NOT IN platform/decision/contract. It used to
// live there, measuring DecodeAuthZENEnvelope + AuthZENEnvelope.Project, under
// a comment calling that "the boundary in production". It was not: `grep -rn
// "\.Project("` outside the contract package returns only _test.go files, and
// Project enforces required-ness while the serving path did not. So the drift
// test reported agreement about a rule NOTHING on the request path applied,
// and the one defect it existed to catch - a schema that requires
// `subject.type` in front of a server that read its absence as "gateway" -
// passed it. The contract module may not import the rest of the platform, so
// the test comes to the boundary rather than the boundary to the test.
//
// The contract package keeps the narrower half of this: that the DECODER and
// the schema agree about structure. See TestTheDecoderAndTheSchemaAgreeOnShape
// there, and the comment that hands the completeness half over to this file.
func admitThroughTheRoute(raw []byte) error {
	env, err := contract.DecodeAuthZENEnvelope(raw)
	if err != nil {
		return err
	}
	if _, mapErr := mapEnvelope(env); mapErr != nil {
		return mapErr
	}
	return nil
}

// TestTheSchemaAgreesWithTheRouteBoundary holds the published schema to the
// route's own refusals.
//
// Two boundaries that disagree about what is well formed is a class where a
// generated client happily builds a request the server refuses - or, in the
// direction that actually bit, where the SERVER accepts what the schema calls
// invalid, and the rule the schema states is enforced by nobody.
//
// The route is STRICTER than the schema by design: it evaluates one subject
// type, three action names, and refuses caller-supplied properties the contract
// merely describes. So the cases below are chosen to be ones the SCHEMA also
// decides, and the narrowing is covered by the refusal suite in
// authzen_handler_test.go rather than by pretending the two are the same set.
func TestTheSchemaAgreesWithTheRouteBoundary(t *testing.T) {
	const evaluable = `{"subject":` + okSubject + `,"action":` + okAction +
		`,"resource":` + okResource + `,"context":` + okContext + `}`

	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"neither member", `{}`},
		{"both members", `{"evaluation":` + evaluable + `,"evaluations":{"evaluations":[{}]}}`},
		{"an empty plural array", `{"evaluations":{"evaluations":[]}}`},
		{"an undeclared top-level member", `{"evaluation":` + evaluable + `,"profile":"x"}`},
		{"a singular member with no action", `{"evaluation":{"subject":` + okSubject +
			`,"resource":` + okResource + `,"context":` + okContext + `}}`},
		// The four the re-pointing exists for. Each is REQUIRED by the schema
		// and was accepted by the route, which is the disagreement the old test
		// could not see because it measured Project instead.
		{"a singular subject with no type", `{"evaluation":{"subject":{"id":"alice@corp"},"action":` + okAction +
			`,"resource":` + okResource + `,"context":` + okContext + `}}`},
		{"a singular resource with no type", `{"evaluation":{"subject":` + okSubject + `,"action":` + okAction +
			`,"resource":{"id":"llm"},"context":` + okContext + `}}`},
		{"a shared base whose subject has no type", `{"evaluations":{"subject":{"id":"alice@corp"},"action":` + okAction +
			`,"context":` + okContext + `,"evaluations":[{"resource":` + okResource + `}]}}`},
		{"an entry whose resource has no type", `{"evaluations":{"subject":` + okSubject + `,"action":` + okAction +
			`,"context":` + okContext + `,"evaluations":[{"resource":{"id":"llm"}}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := json.Unmarshal([]byte(tc.raw), &doc); err != nil {
				t.Fatalf("the fixture is not valid JSON: %v", err)
			}
			if err := admitThroughTheRoute([]byte(tc.raw)); err == nil {
				t.Errorf("the route boundary accepted %s, which the schema calls invalid; "+
					"the rule is then enforced by nobody on the request path", tc.name)
			}
			if err := contract.ValidateAgainstSchema(contract.SchemaAuthZENEnvelope, doc); err == nil {
				t.Errorf("the schema accepted %s, which the route refuses; "+
					"a generated client would build a request the server rejects", tc.name)
			}
		})
	}

	// The agreement must hold in the ACCEPTING direction too, or the two
	// boundaries could agree only by both refusing everything.
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"a singular evaluation", `{"evaluation":` + evaluable + `}`},
		{"a plural envelope inheriting the base", `{"evaluations":{"subject":` + okSubject +
			`,"action":` + okAction + `,"resource":` + okResource + `,"context":` + okContext +
			`,"evaluations":[{}]}}`},
		{"a plural entry naming its own resource", `{"evaluations":{"subject":` + okSubject +
			`,"action":` + okAction + `,"context":` + okContext +
			`,"evaluations":[{"resource":` + okResource + `}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := admitThroughTheRoute([]byte(tc.raw)); err != nil {
				t.Errorf("the route boundary refused %s: %v", tc.name, err)
			}
			var doc any
			if err := json.Unmarshal([]byte(tc.raw), &doc); err != nil {
				t.Fatalf("the fixture is not valid JSON: %v", err)
			}
			if err := contract.ValidateAgainstSchema(contract.SchemaAuthZENEnvelope, doc); err != nil {
				t.Errorf("the schema refused %s, which the route accepts: %v", tc.name, err)
			}
		})
	}
}
