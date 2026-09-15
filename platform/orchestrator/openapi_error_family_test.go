// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3901 §1 / #3896: the published document declared TWO error envelopes and
// referenced both from the same operations, so a spec-generated client got two
// incompatible error types on one endpoint.
//
// FOURTEEN operations were in that state, and THE METHOD MATTERS, because three
// plausible ones give three different answers on origin/main's document (0, 7
// and 16). The reproducible one:
//
//   On origin/main, `Unauthorized` was the ONLY reusable response carrying the
//   coded shape - it pointed at LLMProviderAPIError - while its four siblings
//   (BadRequest, NotFound, Forbidden, InternalError) all pointed at
//   ErrorResponse. Count the operations referencing `Unauthorized` TOGETHER
//   WITH at least one of those four: fourteen.
//
// The often-quoted ten is the subset pairing it with BadRequest specifically;
// the other four pair it with NotFound, Forbidden or InternalError. The
// sharpest example is not the count. Twenty-seven operations were repointed in
// total, because the fourteen are those that MIXED, not every one documented
// wrongly.
//
// An earlier version of this comment said "measured with the family sets
// below". Those sets did not exist on origin/main - that document declares no
// `Coded*` response at all - so that method returns zero, and a stated method
// that returns a different number from the one beside it is worse than no
// method.
//
// The three shapes are not merged - that would be a wire change to 602 call
// sites and would break every shipped SDK. They are NAMED families, and the
// contract is that an operation references one family throughout.
//
// This is the mechanised form of that rule. Fixing the fourteen operations
// without it would put the document back in the same state within a release,
// which is the audit's own conclusion about every other item in #3901.

package orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// flatErrorFamily is `{success, error}` - what sendErrorResponse emits.
var flatErrorFamily = map[string]bool{
	"BadRequest": true, "Unauthorized": true, "NotFound": true,
	"Forbidden": true, "InternalError": true,
}

// codedErrorFamily is `{error: {code, message}}` - what the per-handler
// writeError methods emit.
var codedErrorFamily = map[string]bool{
	"CodedBadRequest": true, "CodedUnauthorized": true, "CodedNotFound": true,
	"CodedConflict": true, "CodedForbidden": true, "CodedInternalError": true,
}

// tripletErrorFamily is `{error, code, message}` - three members at the TOP
// level, which is what workflow_control.Handler.writeError emits.
//
// #3941: the family already existed as a SCHEMA (TripletErrorResponse) and had
// no reusable RESPONSES, so the twelve workflow-control operations that emit it
// had nothing to reference and pointed at the flat BadRequest/NotFound instead.
// Naming the responses is what let those operations be repointed at the family
// their handler was measured to emit.
var tripletErrorFamily = map[string]bool{
	"TripletBadRequest": true, "TripletNotFound": true, "TripletConflict": true,
}

// TestNoOperationMixesTheTwoErrorFamilies is the guard.
func TestNoOperationMixesTheTwoErrorFamilies(t *testing.T) {
	rel := filepath.Join("..", "..", "docs", "api", "orchestrator-api.yaml")
	blob, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	// THE RESPONSE IS READ AS A FREE-FORM NODE, not as a struct with a $ref.
	//
	// R3 killed the first version on exactly this. It modelled a response as
	// `struct{ Ref string }`, so ONLY a response written as a $ref to
	// components/responses was classified and an INLINE one was invisible -
	// and `POST /api/v1/llm-providers/{name}/test` was mixing the families
	// through an inline body at the time, with this guard reporting zero. The
	// defect the guard exists for, surviving in the spelling the guard did not
	// read.
	//
	// So classification is by SHAPE now, reached three ways: a $ref to
	// components/responses, a $ref to components/schemas, or an inline schema
	// whose property set says which family it is.
	var doc struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Responses map[string]any `yaml:"responses"`
			Schemas   map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}

	// ANTI-VACUITY. A parse that read nothing finds no mixed operation and is
	// indistinguishable from a clean document. The floor is THIS DOCUMENT's
	// population: the first version used 200, taken from the 242 distinct paths
	// across all FOUR published documents, while orchestrator-api.yaml alone
	// declares far fewer. A floor derived from the wrong population fails an
	// honest parse and teaches whoever hits it to lower the number.
	if len(doc.Paths) < 120 {
		t.Fatalf("only %d paths parsed from orchestrator-api.yaml; the parse is reading nothing and "+
			"the mixed list below would be empty for the wrong reason", len(doc.Paths))
	}

	// EVERY NAMED FAMILY MEMBER MUST EXIST in components.responses. A typo or a
	// rename in the family lists silently shrinks what is classified, and the
	// shape arm would then quietly pick up some of the slack while the named
	// arm's floor fell. R3 round 2 found this check cited in a comment after an
	// earlier revision had deleted it - a citation of a guard that was not
	// there, which is the defect the same commit claimed to be fixing.
	familyMembers := append(errorFamilyNames(flatErrorFamily), errorFamilyNames(codedErrorFamily)...)
	familyMembers = append(familyMembers, errorFamilyNames(tripletErrorFamily)...)
	for _, name := range familyMembers {
		if _, ok := doc.Components.Responses[name]; !ok {
			t.Errorf("this test names %q as an error-family member and the document declares no such "+
				"components.responses entry, so nothing it appears in is actually classified", name)
		}
	}

	classify := func(node any) (family, arm string, ok bool) {
		return classifyErrorFamily(node, doc.Components.Responses, doc.Components.Schemas, 0)
	}

	var classified int
	perArm := map[string]int{}
	var mixed []string
	mixedFamiliesOf := map[string][]string{}
	for path, pathItem := range doc.Paths {
		for verb, opAny := range pathItem {
			op, isMap := opAny.(map[string]any)
			if !isMap {
				continue
			}
			responses, isMap := op["responses"].(map[string]any)
			if !isMap {
				continue
			}
			byFamily := map[string][]string{}
			for status, r := range responses {
				// ERROR STATUSES ONLY. `OrchestratorResponse` - the SUCCESS
				// envelope on many operations - also carries `success` and
				// `error` members, so classifying a 200 by shape reports the
				// success body as a member of the flat error family and every
				// operation with a coded 4xx reads as mixed. Caught by the
				// widened classifier on its first run: four of its five
				// findings named a 200.
				if !isErrorStatus(status) {
					continue
				}
				fam, arm, ok := classify(r)
				if !ok {
					continue
				}
				classified++
				perArm[arm]++
				byFamily[fam] = append(byFamily[fam], status)
			}
			if len(byFamily) > 1 {
				fams := make([]string, 0, len(byFamily))
				for f := range byFamily {
					fams = append(fams, f)
				}
				sort.Strings(fams)
				lines := make([]string, 0, len(fams))
				for _, f := range fams {
					sort.Strings(byFamily[f])
					lines = append(lines, fmt.Sprintf("      %-8s %s on %s",
						f, familyShape[f], strings.Join(byFamily[f], ", ")))
				}
				op := strings.ToUpper(verb) + " " + path
				mixedFamiliesOf[op] = fams
				mixed = append(mixed, fmt.Sprintf("%s\n%s", op, strings.Join(lines, "\n")))
			}
		}
	}

	// ANTI-VACUITY, PER ARM. A classifier that recognised nothing reports no
	// mixed operation and looks identical to a clean document.
	//
	// AN AGGREGATE FLOOR CANNOT DO THIS JOB, and R3 round 2 measured exactly
	// why: with a single `classified < 100` check, deleting the WHOLE
	// shape-inference tail moved the total from 217 to 214 and the floor stayed
	// silent - because the two $ref arms carry almost all the volume. A floor
	// advertised as protecting an arm that contributes 3 of 217 protects
	// nothing. Each arm therefore carries its own floor, derived from what the
	// document demonstrably contains rather than calibrated from a green run.
	for arm, floor := range map[string]int{
		armNamedResponse: 40, // reusable BadRequest/Unauthorized/... references
		armNamedSchema:   40, // direct $refs to ErrorResponse and friends
		armInlineShape:   2,  // bodies written inline, the arm R3 found missing
	} {
		if perArm[arm] < floor {
			t.Fatalf("the %s arm classified only %d error response(s), below its floor of %d. That arm "+
				"has stopped reading the document, and because the other arms carry the volume, the "+
				"mixed list below would be empty for the wrong reason. Per-arm totals: %v",
				arm, perArm[arm], floor, perArm)
		}
	}
	if classified < 150 {
		t.Fatalf("the classifier recognised only %d error responses across %d paths (per-arm: %v). It "+
			"is not reading the document.", classified, len(doc.Paths), perArm)
	}

	allowed := map[string]bool{}
	for _, a := range mixedFamilyAllowances() {
		fams := append([]string(nil), a.families...)
		sort.Strings(fams)
		allowed[a.operation+"|"+strings.Join(fams, "+")] = true
	}
	matched := map[string]bool{}
	var unexplained []string
	for _, m := range mixed {
		op := strings.SplitN(m, "\n", 2)[0]
		key := op + "|" + strings.Join(mixedFamiliesOf[op], "+")
		if allowed[key] {
			matched[key] = true
			continue
		}
		unexplained = append(unexplained, m)
	}
	// THE RATCHET, same shape as the route-parity allowance lists: a row that
	// matches nothing has outlived its cause and fails, so this list cannot
	// grow monotonically and quietly.
	for key := range allowed {
		if !matched[key] {
			t.Errorf("mixedFamilyAllowances has a row for %q and no operation mixes exactly that set "+
				"any more. The row's stated cause is gone - delete it, or write a new row for whatever "+
				"the operation does now. A suppression that outlives its reason is a false statement "+
				"about the code.", key)
		}
	}
	mixed = unexplained

	if len(mixed) > 0 {
		sort.Strings(mixed)
		t.Errorf("%d operation(s) reference BOTH error families, so a spec-generated client gets two "+
			"incompatible error types on one endpoint and cannot write a single deserialiser "+
			"(#3897, #3901 §1):\n    %s\n\nPick the family the handler actually emits: the flat "+
			"`{success, error}` shape is sendErrorResponse; the coded `{error: {code, message}}` shape "+
			"is the per-handler writeError methods.", len(mixed), strings.Join(mixed, "\n    "))
	}
}

const (
	familyFlat    = "flat"
	familyCoded   = "coded"
	familyTriplet = "triplet"
)

// familyShape renders each family's wire shape, so a failure says what the two
// incompatible types actually are rather than only naming them.
var familyShape = map[string]string{
	familyFlat:    "`{success, error}`         ",
	familyCoded:   "`{error:{code,message}}`   ",
	familyTriplet: "`{error, code, message}`   ",
}

// isErrorStatus reports whether a responses-map key names a failure. `default`
// counts: OpenAPI uses it for the catch-all, which in this document is always
// an error.
func isErrorStatus(status string) bool {
	if status == "default" {
		return true
	}
	return strings.HasPrefix(status, "4") || strings.HasPrefix(status, "5")
}

// classifyErrorFamily reduces one response node to an error family, following
// $refs into components/responses and components/schemas and, when neither
// applies, reading the inline schema's own property set.
//
// THE INLINE ARM IS THE POINT. A document may say the same thing three ways,
// and a guard that reads one of them is a guard with two blind spots.
func classifyErrorFamily(node any, responses, schemas map[string]any, depth int) (family, arm string, ok bool) {
	if depth > 8 {
		return "", "", false
	}
	m, isMap := node.(map[string]any)
	if !isMap {
		return "", "", false
	}
	if ref, isStr := m["$ref"].(string); isStr {
		switch {
		case strings.HasPrefix(ref, "#/components/responses/"):
			name := strings.TrimPrefix(ref, "#/components/responses/")
			if fam, known := familyOfNamedResponse(name); known {
				return fam, armNamedResponse, true
			}
			return classifyErrorFamily(responses[name], responses, schemas, depth+1)
		case strings.HasPrefix(ref, "#/components/schemas/"):
			name := strings.TrimPrefix(ref, "#/components/schemas/")
			if fam, known := familyOfNamedSchema(name); known {
				return fam, armNamedSchema, true
			}
			return classifyErrorFamily(schemas[name], responses, schemas, depth+1)
		}
		return "", "", false
	}
	// A response object: descend into its JSON media type's schema.
	if content, isMap := m["content"].(map[string]any); isMap {
		if mt, isJSON := content["application/json"].(map[string]any); isJSON {
			return classifyErrorFamily(mt["schema"], responses, schemas, depth+1)
		}
		return "", "", false
	}
	// A schema object: read its own property set and hand it to THE ONE RULE.
	props, hasProps := m["properties"].(map[string]any)
	if !hasProps {
		return "", "", false
	}
	// The `error` member's own property set, reached through any number of
	// `$ref`s. R3 round 2 found the first version blind here, which is the SAME
	// defect as round 1's, one spelling further out: `APIErrorResponse` is
	// `{error: $ref APIError}` and `APIError` is `{code, message}`; the
	// classifier read the un-dereferenced `$ref` node, found no `properties`,
	// and returned "cannot classify". Two operations on the workflow step
	// surface were mixing flat with it at the time, with the guard reporting
	// zero.
	errorChild := func(node any) (map[string]any, bool) {
		resolved := resolveSchemaNode(node, schemas, depth+1)
		em, isMap := resolved.(map[string]any)
		if !isMap {
			return nil, false
		}
		inner, hasInner := em["properties"].(map[string]any)
		return inner, hasInner
	}
	if fam, ok := familyOfShape(props, errorChild); ok {
		return fam, armInlineShape, true
	}
	return "", "", false
}

// familyOfShape IS THE ONE RULE, and it is one rule on purpose.
//
// #3941 needed the same question asked of two different things: of a SCHEMA in
// the published document ("what does this operation promise?") and of the BYTES
// a handler actually wrote ("what does it deliver?"). Two implementations of
// "what family is this" would agree in every test that exercised them together
// and could still disagree on the one shape neither author thought about -
// which is precisely the failure mode this whole issue is made of, one level
// up. So both callers reduce their input to the same two things - a property
// SET, and a way to read the `error` member's own property set - and ask here.
//
// The caller supplies `errorChild` because that is the only step that genuinely
// differs: in a schema the child is `{"properties": {...}}` behind zero or more
// `$ref`s, while on the wire the child IS the decoded object.
//
// Order is load-bearing and matches the families' definitions:
//   - `success` + `error`            -> flat, whatever else is present. The
//     orchestrator's flat envelope carries five more members (request_id,
//     redacted, policy_info, provider_info, processing_time) and must not be
//     read as "unclassifiable" for having them.
//   - `error` is an object with code+message -> coded.
//   - `error` + `code` + `message` at the top level -> triplet.
//
// Anything else returns false. Guessing at a shape this rule has no model for
// is a claim it cannot support, and a classifier that named a family for
// everything would satisfy every positive test while protecting nothing.
func familyOfShape(props map[string]any, errorChild func(any) (map[string]any, bool)) (string, bool) {
	_, hasSuccess := props["success"]
	errNode, hasError := props["error"]
	if !hasError {
		return "", false
	}
	if hasSuccess {
		return familyFlat, true
	}
	if child, ok := errorChild(errNode); ok {
		_, hasCode := child["code"]
		_, hasMessage := child["message"]
		if hasCode && hasMessage {
			return familyCoded, true
		}
	}
	if _, hasCode := props["code"]; hasCode {
		if _, hasMessage := props["message"]; hasMessage {
			return familyTriplet, true
		}
	}
	return "", false
}

// familyOfWireBody classifies the BYTES a handler wrote, through familyOfShape.
//
// The `errorChild` adapter is the whole difference from the schema caller: on
// the wire, a coded envelope's `error` member IS the `{code, message}` object,
// with no `properties` indirection and no `$ref` to follow.
func familyOfWireBody(body []byte) (string, error) {
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", fmt.Errorf("handler wrote a body that is not a JSON object (%d bytes: %.120q): %w",
			len(body), string(body), err)
	}
	fam, ok := familyOfShape(decoded, func(node any) (map[string]any, bool) {
		m, isMap := node.(map[string]any)
		return m, isMap
	})
	if !ok {
		keys := make([]string, 0, len(decoded))
		for k := range decoded {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", fmt.Errorf("handler wrote an error body in a shape no named family describes "+
			"(top-level members: %v). Either it is a NEW envelope - in which case name it, the way "+
			"TripletErrorResponse was named - or it is a defect", keys)
	}
	return fam, nil
}

// The three ways a response reaches a family. Each is counted SEPARATELY,
// because R3 round 2 proved an AGGREGATE floor cannot detect the loss of one
// arm: deleting the entire shape-inference tail moved the total from 217 to
// 214, and a floor of 100 stayed silent while the arm this guard was rewritten
// to add had stopped existing.
const (
	armNamedResponse = "named-response"
	armNamedSchema   = "named-schema"
	armInlineShape   = "inline-shape"
)

// resolveSchemaNode follows a `$ref` into components/schemas once, so a
// property whose shape is named rather than inlined can still be read.
// A node that is not a `$ref`, or whose `$ref` does not resolve, comes back
// unchanged - the caller then fails to classify it, which is the honest answer.
func resolveSchemaNode(node any, schemas map[string]any, depth int) any {
	if depth > 8 {
		return node
	}
	m, ok := node.(map[string]any)
	if !ok {
		return node
	}
	ref, isStr := m["$ref"].(string)
	if !isStr || !strings.HasPrefix(ref, "#/components/schemas/") {
		return node
	}
	target, present := schemas[strings.TrimPrefix(ref, "#/components/schemas/")]
	if !present {
		return node
	}
	return resolveSchemaNode(target, schemas, depth+1)
}

// familyOfNamedResponse and familyOfNamedSchema are the two NAMED sets. They
// are consulted first so a rename of a component is caught by
// TestNoOperationMixesTheTwoErrorFamilies' membership check rather than
// silently falling through to shape inference.
func familyOfNamedResponse(name string) (string, bool) {
	if flatErrorFamily[name] {
		return familyFlat, true
	}
	if codedErrorFamily[name] {
		return familyCoded, true
	}
	if tripletErrorFamily[name] {
		return familyTriplet, true
	}
	return "", false
}

func familyOfNamedSchema(name string) (string, bool) {
	switch name {
	case "ErrorResponse":
		return familyFlat, true
	case "TripletErrorResponse":
		// The THIRD shape, `{error, code, message}`. Named rather than folded
		// into one of the other two: the workflow control plane emits it, and
		// two operations there documented a flat 404 beside a coded 409 while
		// the handler emitted neither. Registering it here is what lets this
		// guard report a mix ACROSS three families instead of two.
		return familyTriplet, true
	case "CodedErrorResponse", "LLMProviderAPIError", "APIErrorResponse":
		// APIErrorResponse is `{error: $ref APIError}` where APIError is
		// `{code, message}` - the coded shape reached through a second $ref.
		// It is named here as well as being resolvable by shape, so a reader
		// can see the whole coded set in one place.
		// LLMProviderAPIError is the coded shape with a constrained code enum,
		// which the document now says explicitly. Classifying it as coded is
		// what stops it being a third family nobody guards.
		return familyCoded, true
	}
	return "", false
}

// mixedFamilyAllowance is one operation that legitimately answers with both
// error shapes, because its HANDLER does.
//
// A ROW HERE IS A STATEMENT ABOUT THE CODE, NOT ABOUT THE DOCUMENT. The
// document is required to describe what the handler emits; where the handler
// emits two shapes on one endpoint, describing one of them would be a lie and
// describing neither would be worse. So the row records the platform defect and
// the document stays accurate.
type mixedFamilyAllowance struct {
	operation string
	// families is the EXACT set the operation is allowed to mix, sorted. R3
	// round 2 showed a row keyed on the operation alone survives its own
	// stated cause: deleting the 429 the reason describes and making the 500
	// coded instead left the row matching, with a suppression whose reason had
	// become a false statement about the code.
	families []string
	reason   string
}

func mixedFamilyAllowances() []mixedFamilyAllowance {
	const rateLimit = "the 429 is the platform's shared RATE-LIMIT envelope - `{error:{code,message}}` " +
		"carrying an upgrade code a client switches on - while every other refusal on this operation " +
		"comes from sendErrorResponse and is `{success, error}`. So the HANDLER emits both shapes on " +
		"one endpoint and the document is describing that accurately. Collapsing the 429 into the flat " +
		"envelope would drop the code, and promoting the rest to coded is a wire change across 229 " +
		"sendErrorResponse call sites; both are API decisions rather than documentation ones. " +
		"Tracked by issue 3941."
	const stepGate = "the 404 comes from the handler's own writeError, which emits the triplet " +
		"`{error, code, message}`, while the 409 comes from writeIdempotencyKeyMismatch - a SEPARATE " +
		"writer emitting the nested `{error:{code,message,details}}` with a details object no other " +
		"envelope on this surface carries. So the handler genuinely answers one operation in two " +
		"shapes, and the document now says so accurately. It was documenting a THIRD combination " +
		"before - a flat 404 beside the nested 409 - which matched neither writer. Collapsing them " +
		"would drop the details object a client uses to reconcile the two idempotency keys. " +
		"Tracked by issue 3941."
	const overrideFreeze = "the 409 is the v11 legacy-write freeze (#4252): legacyfreeze.RefuseOverride's coded " +
		"`{error:{code,message}}` carrying LEGACY_POLICY_WRITE_FROZEN, the one code every frozen write route answers " +
		"and a client switches on, while the guards that answer before it (the agent's proxy token 403, the " +
		"per-user identity 401 through sendIdentityRequiredError, the tenant 400) are sendErrorResponse's " +
		"`{success, error}`. Collapsing the 409 into the flat envelope would drop the code, and promoting the guards " +
		"to coded changes the #3062 401 wire the plugins and suite 3062 read."
	return []mixedFamilyAllowance{
		{operation: "POST /api/v1/overrides", families: []string{familyFlat, familyCoded}, reason: overrideFreeze},
		{operation: "DELETE /api/v1/overrides/{id}", families: []string{familyFlat, familyCoded}, reason: overrideFreeze},
		{
			operation: "POST /api/v1/workflows/{workflow_id}/steps/{step_id}/gate",
			families:  []string{familyCoded, familyTriplet},
			reason:    stepGate,
		},
		{
			operation: "POST /api/v1/workflows/{workflow_id}/steps/{step_id}/complete",
			families:  []string{familyCoded, familyTriplet},
			reason:    stepGate,
		},
		{operation: "GET /api/v1/plans/{id}/cost", families: []string{familyFlat, familyCoded}, reason: rateLimit},
		{
			operation: "POST /api/v1/plans/estimate",
			// THREE families on one operation, and the tightened allowance key
			// is what surfaced the third. Beyond the 429 described above, the
			// 401 comes from resolveTenantOrFail -> writeJSONError, which emits
			// `{error, code, message}` - so this one endpoint answers in every
			// error shape the platform has. Recorded exactly rather than
			// approximated to two, because a row that understates what an
			// operation does is the suppression outliving its reason.
			families: []string{familyFlat, familyCoded, familyTriplet},
			reason:   rateLimit + " Its 401 additionally uses the triplet envelope via writeJSONError.",
		},
		{operation: "POST /api/v1/plan/execute", families: []string{familyFlat, familyCoded}, reason: rateLimit},
	}
}

// TestTheErrorFamilyClassifierReadsEverySpellingItClaimsTo is the classifier's
// own control, and it exists because the LIVE DOCUMENT is not a control.
//
// R3 round 2 removed the `$ref`-following on the `error` property - the fix for
// its own finding 1 - and every test stayed green, because by then the one live
// schema of that shape (`APIErrorResponse`) was also reachable by name. The arm
// was correct, defensive, and completely unexercised. A guard whose coverage
// depends on the document happening to contain a shape is a guard that loses
// that coverage the day somebody tidies the document.
//
// So each spelling is driven against a synthetic document instead.
func TestTheErrorFamilyClassifierReadsEverySpellingItClaimsTo(t *testing.T) {
	responses := map[string]any{
		"BadRequest": map[string]any{"description": "named response"},
	}
	schemas := map[string]any{
		"ErrorResponse": map[string]any{"description": "named schema"},
		"InnerCoded": map[string]any{"properties": map[string]any{
			"code": map[string]any{"type": "string"}, "message": map[string]any{"type": "string"},
		}},
		"RefReachedCoded": map[string]any{"properties": map[string]any{
			"error": map[string]any{"$ref": "#/components/schemas/InnerCoded"},
		}},
	}
	jsonBody := func(schema any) any {
		return map[string]any{"content": map[string]any{
			"application/json": map[string]any{"schema": schema}}}
	}

	for _, tc := range []struct {
		name       string
		node       any
		wantFamily string
		wantArm    string
	}{
		{"a $ref to a named reusable response", map[string]any{"$ref": "#/components/responses/BadRequest"}, familyFlat, armNamedResponse},
		{"a $ref to a named schema", jsonBody(map[string]any{"$ref": "#/components/schemas/ErrorResponse"}), familyFlat, armNamedSchema},
		{"an inline flat body", jsonBody(map[string]any{"properties": map[string]any{
			"success": map[string]any{"type": "boolean"}, "error": map[string]any{"type": "string"}}}), familyFlat, armInlineShape},
		{"an inline coded body", jsonBody(map[string]any{"properties": map[string]any{
			"error": map[string]any{"properties": map[string]any{
				"code": map[string]any{}, "message": map[string]any{}}}}}), familyCoded, armInlineShape},
		{"an inline triplet body", jsonBody(map[string]any{"properties": map[string]any{
			"error": map[string]any{}, "code": map[string]any{}, "message": map[string]any{}}}), familyTriplet, armInlineShape},
		// THE ARM THE LIVE DOCUMENT NO LONGER EXERCISES.
		{"a coded body whose `error` property is itself a $ref",
			jsonBody(map[string]any{"$ref": "#/components/schemas/RefReachedCoded"}), familyCoded, armInlineShape},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fam, arm, ok := classifyErrorFamily(tc.node, responses, schemas, 0)
			if !ok {
				t.Fatalf("not classified; this spelling is invisible to the guard")
			}
			if fam != tc.wantFamily {
				t.Errorf("family = %q, want %q", fam, tc.wantFamily)
			}
			if arm != tc.wantArm {
				t.Errorf("arm = %q, want %q - the per-arm anti-vacuity floors are only meaningful if "+
					"each spelling is attributed to the arm that actually read it", arm, tc.wantArm)
			}
		})
	}

	// THE OTHER HALF. A classifier that returned a family for everything would
	// satisfy every case above. These must NOT classify, because guessing at a
	// shape this walker has no model for is a claim it cannot support.
	for _, tc := range []struct {
		name string
		node any
	}{
		{"a body with no JSON media type", map[string]any{"content": map[string]any{
			"text/plain": map[string]any{"schema": map[string]any{"type": "string"}}}}},
		{"a response with no content at all", map[string]any{"description": "no body"}},
		{"an object with neither `error` nor `success`", jsonBody(map[string]any{
			"properties": map[string]any{"detail": map[string]any{"type": "string"}}})},
		{"a $ref that resolves to nothing", jsonBody(map[string]any{"$ref": "#/components/schemas/NoSuchSchema"})},
	} {
		t.Run("silent: "+tc.name, func(t *testing.T) {
			if fam, arm, ok := classifyErrorFamily(tc.node, responses, schemas, 0); ok {
				t.Errorf("classified as family=%q arm=%q; this walker has no model for that shape and "+
					"guessing is a claim it cannot support", fam, arm)
			}
		})
	}
}

// errorFamilyNames is a local helper - `sortedKeys` is already taken in this
// package by hitl_response_parity_test.go with a different value type.
func errorFamilyNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
