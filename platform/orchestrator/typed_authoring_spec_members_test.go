// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// WHAT THIS GUARD ANSWERS, AND WHY THE ANCHOR WALK CANNOT ANSWER IT.
//
// openapi_schema_parity_test.go compares a components.schemas entry against a Go
// STRUCT, through specAnchors(). Four of the five typed-policies responses below
// are built as map[string]any inside their handler, so there is no type to
// anchor; the fifth marshals a struct (authoring.SystemCorpusView) but its schema is
// written INLINE under paths, not as a component, so it cannot be anchored
// either without a spec refactor. That is why #4262's nine reported members -
// eleven, once the /system control item is read against SystemControl - reached
// five SDKs from the platform's Go code rather than from the document.
//
// So this guard reads the other end: it DRIVES each response through the real
// router and compares the keys the handler actually marshalled against the
// properties its own response schema declares. A member the platform sends and
// the document does not declare is the defect, at whatever depth it appears.
//
// The conditional members need a fixture per branch or the walk cannot see them:
// a publication whose document omits template controls (template_omissions), an
// activation read-back that fails (template_omissions_unavailable), and a batch
// admission over its ceiling naming the policy that crossed it (policy).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/license/admission"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

const specRelPath = "../../docs/api/orchestrator-api.yaml"

// specDoc is the whole document, as maps. loadSchemaSet reads components.schemas
// only, which is the half this guard cannot use: every response below declares
// its 200 body inline under paths, and the tier refusal lives under
// components.responses.
type specDoc struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas   map[string]map[string]any `yaml:"schemas"`
		Responses map[string]map[string]any `yaml:"responses"`
	} `yaml:"components"`
}

func loadSpecDoc(t *testing.T) specDoc {
	t.Helper()
	blob, err := os.ReadFile(specRelPath)
	if err != nil {
		t.Fatalf("read %s: %v", specRelPath, err)
	}
	var doc specDoc
	if err := yaml.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse %s: %v", specRelPath, err)
	}
	if len(doc.Paths) == 0 || len(doc.Components.Schemas) == 0 {
		t.Fatalf("%s parsed with no paths or no components.schemas; every assertion below would hold "+
			"over an empty document", specRelPath)
	}
	return doc
}

// jsonSchemaOf returns the schema node for one operation's response status.
func (d specDoc) jsonSchemaOf(t *testing.T, path, method, status string) map[string]any {
	t.Helper()
	op, ok := d.Paths[path]
	if !ok {
		t.Fatalf("%s declares no path %s; this guard names the routes the platform serves", specRelPath, path)
	}
	verb, ok := op[method].(map[string]any)
	if !ok {
		t.Fatalf("%s %s is not documented", strings.ToUpper(method), path)
	}
	responses, ok := verb["responses"].(map[string]any)
	if !ok {
		t.Fatalf("%s %s declares no responses", strings.ToUpper(method), path)
	}
	node, ok := responses[status].(map[string]any)
	if !ok {
		t.Fatalf("%s %s declares no %s response", strings.ToUpper(method), path, status)
	}
	return d.schemaOfResponseNode(t, node, fmt.Sprintf("%s %s %s", strings.ToUpper(method), path, status))
}

// schemaOfResponseNode digs content -> application/json -> schema, following a
// $ref into components.responses when the response is written as one.
func (d specDoc) schemaOfResponseNode(t *testing.T, node map[string]any, where string) map[string]any {
	t.Helper()
	if ref, ok := node["$ref"].(string); ok {
		const prefix = "#/components/responses/"
		if !strings.HasPrefix(ref, prefix) {
			t.Fatalf("%s: response $ref %q is not a components.responses reference", where, ref)
		}
		target, ok := d.Components.Responses[strings.TrimPrefix(ref, prefix)]
		if !ok {
			t.Fatalf("%s: %s is not in components.responses", where, ref)
		}
		node = target
	}
	content, ok := node["content"].(map[string]any)
	if !ok {
		t.Fatalf("%s declares no content", where)
	}
	body, ok := content["application/json"].(map[string]any)
	if !ok {
		t.Fatalf("%s declares no application/json body", where)
	}
	schema, ok := body["schema"].(map[string]any)
	if !ok {
		t.Fatalf("%s declares no schema for its JSON body", where)
	}
	return schema
}

// resolve follows a components.schemas $ref, once.
func (d specDoc) resolve(t *testing.T, node map[string]any) map[string]any {
	t.Helper()
	seen := 0
	for {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node
		}
		const prefix = "#/components/schemas/"
		if !strings.HasPrefix(ref, prefix) {
			t.Fatalf("$ref %q is not a components.schemas reference", ref)
		}
		target, ok := d.Components.Schemas[strings.TrimPrefix(ref, prefix)]
		if !ok {
			t.Fatalf("%s is not in components.schemas", ref)
		}
		node = target
		if seen++; seen > 16 {
			t.Fatalf("$ref chain from %q does not terminate", ref)
		}
	}
}

// declaredProperties collects a node's properties, merging allOf branches, and
// reports whether the node admits members it does not name.
func (d specDoc) declaredProperties(t *testing.T, node map[string]any) (props map[string]any, open bool) {
	t.Helper()
	node = d.resolve(t, node)
	props = map[string]any{}
	if p, ok := node["properties"].(map[string]any); ok {
		for k, v := range p {
			props[k] = v
		}
	}
	switch extra := node["additionalProperties"].(type) {
	case bool:
		open = extra
	case map[string]any:
		open = true
	}
	if all, ok := node["allOf"].([]any); ok {
		for _, branch := range all {
			b, ok := branch.(map[string]any)
			if !ok {
				continue
			}
			bp, bopen := d.declaredProperties(t, b)
			for k, v := range bp {
				props[k] = v
			}
			open = open || bopen
		}
	}
	return props, open
}

// undeclared walks a marshalled value against its schema and returns every key
// the platform sent that the document does not declare, as dotted paths.
func (d specDoc) undeclared(t *testing.T, schema map[string]any, value any, path string, out *[]string) {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		props, open := d.declaredProperties(t, schema)
		if len(props) == 0 && open {
			// A deliberately free-form object: nothing to compare against. WHICH
			// nodes may be skipped this way is pinned by
			// TestEveryOpenNodeIsOneTheGuardAllows, because a schema that
			// lost its properties would otherwise take its subtree out of
			// comparison without a sound.
			return
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child, declared := props[k]
			if !declared {
				if !open {
					*out = append(*out, path+"."+k)
				}
				continue
			}
			cs, ok := child.(map[string]any)
			if !ok {
				continue
			}
			d.undeclared(t, cs, v[k], path+"."+k, out)
		}
	case []any:
		node := d.resolve(t, schema)
		items, ok := node["items"].(map[string]any)
		if !ok {
			return
		}
		// BY SHAPE, NOT BY INDEX. The shipped corpus repeats one undeclared
		// member once per control, and a count of 817 occurrences says nothing a
		// count of 9 distinct members does not say better. The caller dedupes.
		for _, el := range v {
			d.undeclared(t, items, el, path+"[]", out)
		}
	}
}

// distinct sorts and deduplicates the walk's findings. The walk reports one
// entry per occurrence; the shipped corpus repeats a member once per control,
// and what a reader needs is the set of members, not how many rows carry them.
func distinct(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// openNodes walks a value against its schema and records every OPEN node, so
// openNodesTheGuardAllows can be asserted rather than trusted. Open means the
// schema admits members it does not name, and there are two kinds:
//
//   - no properties at all, where undeclared returns early and the whole
//     subtree goes uncompared;
//   - properties AND additionalProperties, where undeclared descends but stops
//     reporting members the document never declared.
//
// Both are recorded, because both are silent. It mirrors undeclared's descent
// exactly - same resolution, same skip condition, same visited set - and a walk
// whose two halves disagreed about what they visit would make the allowlist
// meaningless.
func (d specDoc) openNodes(t *testing.T, schema map[string]any, value any, path string, out *[]string) {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		props, open := d.declaredProperties(t, schema)
		if open {
			// Recorded whether or not it declares properties: an open node with
			// properties still stops reporting undeclared members, which is the
			// blindness this allowlist exists to pin.
			*out = append(*out, path)
			if len(props) == 0 {
				return
			}
		}
		for k, child := range props {
			cs, ok := child.(map[string]any)
			if !ok {
				continue
			}
			if sub, present := v[k]; present {
				d.openNodes(t, cs, sub, path+"."+k, out)
			}
		}
	case []any:
		node := d.resolve(t, schema)
		items, ok := node["items"].(map[string]any)
		if !ok {
			return
		}
		for _, el := range v {
			d.openNodes(t, items, el, path+"[]", out)
		}
	}
}

// typedPolicyResponse is one response this guard drives and compares.
type typedPolicyResponse struct {
	name   string
	body   func(t *testing.T) map[string]any
	schema func(t *testing.T, d specDoc) map[string]any
}

func typedPolicyResponses() []typedPolicyResponse {
	prefix := TypedAuthoringRoutePrefix
	return []typedPolicyResponse{
		{
			name: "GET /edition 200",
			body: func(t *testing.T) map[string]any {
				r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
				rr := call(t, r, http.MethodGet, prefix+"/edition", nil, gatewayHeaders())
				if rr.Code != http.StatusOK {
					t.Fatalf("edition: status=%d body=%s", rr.Code, rr.Body.String())
				}
				return decodeBody(t, rr)
			},
			schema: func(t *testing.T, d specDoc) map[string]any {
				return d.jsonSchemaOf(t, prefix+"/edition", "get", "200")
			},
		},
		{
			// The document carries none of the organization template's controls,
			// so the publication reports its omissions: the branch that produces
			// template_omissions.
			name: "POST /publish 200, with a template omission report",
			body: func(t *testing.T) map[string]any {
				r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
				rr := call(t, r, http.MethodPost, prefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
				if rr.Code != http.StatusOK {
					t.Fatalf("publish: status=%d body=%s", rr.Code, rr.Body.String())
				}
				body := decodeBody(t, rr)
				if _, ok := body["template_omissions"]; !ok {
					t.Fatalf("the publication carries no template_omissions, so this case cannot see that member: %s", rr.Body.String())
				}
				return body
			},
			schema: func(t *testing.T, d specDoc) map[string]any {
				return d.jsonSchemaOf(t, prefix+"/publish", "post", "200")
			},
		},
		{
			// THE SECOND ACTIVATION, so previous_digest is OBSERVED rather than
			// read off the struct. It is omitempty and empty only on the first
			// activation an organization ever performs, so a fixture that
			// activates once cannot see it - and a member this guard has not
			// seen is a member it cannot honestly ask the document to declare.
			name: "POST /activate 200, a second activation with a template omission report",
			body: func(t *testing.T) map[string]any {
				r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
				first, _ := publishAndActivate(t, r, communityDocument(), "the first activation")
				v2 := communityDocument()
				v2.Policy.Version = 2
				v2.Metadata.Supersedes = first
				_, body := publishAndActivate(t, r, v2, "the second version")
				if _, ok := body["template_omissions"]; !ok {
					t.Fatalf("the activation carries no template_omissions: %v", body)
				}
				act, ok := body["activation"].(map[string]any)
				if !ok {
					t.Fatalf("the activation body carries no activation record: %v", body)
				}
				if act["previous_digest"] != first {
					t.Fatalf("the second activation names previous_digest %v, want the first digest %q; "+
						"this case exists to OBSERVE that member", act["previous_digest"], first)
				}
				return body
			},
			schema: func(t *testing.T, d specDoc) map[string]any {
				return d.jsonSchemaOf(t, prefix+"/activate", "post", "200")
			},
		},
		{
			// THE ONE CASE OBSERVED AT THE WRITER RATHER THAN THROUGH THE ROUTER,
			// and the PR body says so. The read-back fails only when the store
			// cannot return an artifact the activation just wrote, and no seam
			// injects such a backend through the handler: openForSigning's
			// substitute must return a concrete *authoringstore.Store, so it can
			// supply a durable store or an error and nothing else. Building a
			// seam for a test would be a production change made for the test's
			// convenience, so this drives the writer the handler calls, exactly
			// as typed_authoring_readback_test.go does.
			name: "POST /activate 200, the read-back that fails (observed at the writer)",
			body: func(t *testing.T) map[string]any {
				profile, err := authoring.ProfileFor(authoring.EditionCommunity)
				if err != nil {
					t.Fatal(err)
				}
				store, err := authoring.NewStoreWithBackend(authoring.StaticTrust(pdp.NewTrustStore()), profile,
					readBackFailingBackend{Backend: authoring.NewMemoryBackend(), err: errors.New(plantedStoreError)})
				if err != nil {
					t.Fatal(err)
				}
				var logs bytes.Buffer
				previous := log.Writer()
				log.SetOutput(&logs)
				t.Cleanup(func() { log.SetOutput(previous) })
				body := map[string]any{"success": true}
				addActivatedTemplateOmissions(context.Background(), store, testOrg, "sha256:planted-4262-readback", body)
				if _, ok := body["template_omissions_unavailable"]; !ok {
					t.Fatalf("the failed read-back reported no template_omissions_unavailable: %v", body)
				}
				return body
			},
			schema: func(t *testing.T, d specDoc) map[string]any {
				return d.jsonSchemaOf(t, prefix+"/activate", "post", "200")
			},
		},
		{
			name: "GET /system 200",
			body: func(t *testing.T) map[string]any {
				r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
				rr := call(t, r, http.MethodGet, prefix+"/system", nil, gatewayHeaders())
				if rr.Code != http.StatusOK {
					t.Fatalf("system: status=%d body=%s", rr.Code, rr.Body.String())
				}
				return decodeBody(t, rr)
			},
			schema: func(t *testing.T, d specDoc) map[string]any {
				return d.jsonSchemaOf(t, prefix+"/system", "get", "200")
			},
		},
		{
			// A batch admission over its ceiling names the policy that crossed
			// it (admission_wiring.go), which is the only branch that fills the
			// refusal's `policy`.
			name: "POST /publish, the tier refusal naming the policy that crossed",
			body: func(t *testing.T) map[string]any {
				return tierRefusalBody(t)
			},
			schema: func(t *testing.T, d specDoc) map[string]any {
				node, ok := d.Components.Responses["TypedAuthoringTierLimit"]
				if !ok {
					t.Fatal("components.responses.TypedAuthoringTierLimit is not in the document")
				}
				return d.schemaOfResponseNode(t, node, "components.responses.TypedAuthoringTierLimit")
			},
		},
	}
}

// tierRefusalBody drives a publication into the organization-root policy
// ceiling. The ledger is pre-filled to the Community limit, so the document's
// own policies are the ones that do not fit and the refusal names the first.
func tierRefusalBody(t *testing.T) map[string]any {
	t.Helper()
	ledger := admission.NewMemoryLedger()
	limit := license.CommunityLimits.OrgPolicies
	if limit <= 0 {
		t.Fatalf("the Community org-policy ceiling is %d; this fixture needs a positive one", limit)
	}
	for i := 0; i < limit; i++ {
		if err := ledger.Record(context.Background(), admission.Key{
			OrgID: testOrg, Dimension: admission.OrgRootPolicy, PrincipalID: fmt.Sprintf("seeded.policy.%d", i),
		}, ""); err != nil {
			t.Fatalf("seeding the ledger: %v", err)
		}
	}
	if got := ledger.Rows(testOrg, admission.OrgRootPolicy); got != limit {
		t.Fatalf("the ledger holds %d admitted rows, want the ceiling %d - the fixture would not refuse", got, limit)
	}
	restore := installTestTierAdmitter(t, admission.New(ledger,
		admission.WithTierReader(func(context.Context) license.TierRead {
			return license.TierRead{Tier: license.TierCommunity}
		})))
	t.Cleanup(restore)

	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
	if rr.Code == http.StatusOK {
		t.Fatalf("the publication was admitted at the ceiling, so this case cannot see the refusal: %s", rr.Body.String())
	}
	body := decodeBody(t, rr)
	if body["reason"] != "tier_limit" {
		t.Fatalf("the refusal is %v, not the tier ceiling: %s", body["reason"], rr.Body.String())
	}
	if _, ok := body["policy"]; !ok {
		t.Fatalf("the tier refusal names no policy, so this case cannot see that member: %s", rr.Body.String())
	}
	return body
}

// TestEveryTypedPolicyResponseMemberIsDeclared is the guard.
func TestEveryTypedPolicyResponseMemberIsDeclared(t *testing.T) {
	doc := loadSpecDoc(t)
	cases := typedPolicyResponses()
	if len(cases) == 0 {
		t.Fatal("no responses to compare: the guard would pass over nothing")
	}
	var findings []string
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := c.body(t)
			if len(body) == 0 {
				t.Fatalf("%s marshalled an empty body; there is nothing to compare", c.name)
			}
			schema := c.schema(t, doc)
			var walked []string
			doc.undeclared(t, schema, body, "", &walked)
			out := distinct(walked)
			for _, m := range out {
				findings = append(findings, c.name+" sends"+m)
			}
			if len(out) > 0 {
				sort.Strings(out)
				t.Errorf("%s marshals %d member(s) the document does not declare:\n  %s\n\n"+
					"A client generated from this spec cannot read them, which is why every SDK read them from "+
					"the platform's Go code instead (#4262). Declare each on its response schema, or stop sending it.",
					c.name, len(out), strings.Join(out, "\n  "))
			}
		})
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		t.Logf("undeclared members across %d responses:\n  %s", len(cases), strings.Join(findings, "\n  "))
	}
}

// TestTheSpecMemberGuardSeesAnUndeclaredMember is the positive control: the walk
// must report a member that is not in the schema. Without it, a guard that
// resolved every schema to "open" would pass over any document at all.
func TestTheSpecMemberGuardSeesAnUndeclaredMember(t *testing.T) {
	doc := loadSpecDoc(t)
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"success": map[string]any{"type": "boolean"},
			"nested":  map[string]any{"type": "object", "properties": map[string]any{"declared": map[string]any{"type": "string"}}},
			"list": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "properties": map[string]any{"declared": map[string]any{"type": "string"}}}},
		},
	}
	body := map[string]any{
		"success": true,
		"planted": "a member no schema declares",
		"nested":  map[string]any{"declared": "x", "planted_nested": 1},
		"list":    []any{map[string]any{"declared": "y", "planted_item": true}},
	}
	var walked []string
	doc.undeclared(t, schema, body, "", &walked)
	out := distinct(walked)
	want := []string{".list[].planted_item", ".nested.planted_nested", ".planted"}
	if strings.Join(out, ",") != strings.Join(want, ",") {
		t.Fatalf("the walk reported %v; want %v - a walk that cannot see a planted member at each depth "+
			"cannot be trusted when it reports none", out, want)
	}
}

// TestTheSpecMemberGuardReadsTheDocumentItNames proves the loader is reading the
// real document rather than an empty one: the paths this guard drives must be
// present, and a response it names must declare at least one property.
func TestTheSpecMemberGuardReadsTheDocumentItNames(t *testing.T) {
	doc := loadSpecDoc(t)
	for _, c := range typedPolicyResponses() {
		schema := c.schema(t, doc)
		props, _ := doc.declaredProperties(t, schema)
		if len(props) == 0 {
			t.Errorf("%s: its schema declares no properties at all, so nothing this guard compares against is real", c.name)
		}
	}
}

// openNodesTheGuardAllows is every path whose schema is allowed to be OPEN -
// to admit members it does not name. Two things make a node open, and BOTH are
// pinned here because both are silent:
//
//   - it declares no properties and admits members, so the walk returns early
//     and its whole subtree goes uncompared;
//   - it declares properties AND admits members, so the walk descends but stops
//     reporting members the document never declared.
//
// R3 round 1 found the top-level control could not see the first. R3 round 2
// found this comment claimed the second and the test did not check it, so
// openNodes now records both.
var openNodesTheGuardAllows = map[string]bool{
	".system.document":         true,
	".system.assurance_counts": true,
	// An obligation's params are contract.Obligation.Params, a
	// map[string]string of the type's OWN parameters, so there are no member
	// names to declare and nothing for the walk to compare. This entry was
	// added because the test above demanded it: the allowlist began with the
	// two nodes I had thought of, and the run named the third.
	".system.controls[].obligations[].params": true,
}

// TestEveryOpenNodeIsOneTheGuardAllows pins that set. A new open node is a
// deliberate decision, so it fails here until it is written down. It is named
// for what it checks rather than for skipping: only one of the two kinds is
// skipped, and R3 round 4 found the old name outliving the sentences that had
// already stopped saying it.
func TestEveryOpenNodeIsOneTheGuardAllows(t *testing.T) {
	doc := loadSpecDoc(t)
	for _, c := range typedPolicyResponses() {
		var open []string
		doc.openNodes(t, c.schema(t, doc), c.body(t), "", &open)
		for _, p := range distinct(open) {
			if !openNodesTheGuardAllows[p] {
				t.Errorf("%s: %s is OPEN - its schema admits members it does not name - and it is not in the "+
					"allowlist. Either it lost its `properties` (the walk now compares nothing below it), or it "+
					"gained an `additionalProperties` (the walk descends but stops reporting members the document "+
					"never declared), or it is a new opaque member that needs declaring here with its reason.",
					c.name, p)
			}
		}
	}
}

// TestOpenNodesSeesANodeThatKeepsItsPropertiesAndAdmitsMore is the control for
// the second kind of open node (#4262), which R3 round 3 found untested: a node that declares
// properties AND admits members. undeclared descends into it and silently stops
// reporting anything the document does not declare, so openNodes must record it
// even though the walk does not skip it. The shipped corpus has no such node
// today, which is exactly why this control is synthetic - a branch nothing
// exercises is a branch nobody has tested.
func TestOpenNodesSeesANodeThatKeepsItsPropertiesAndAdmitsMore(t *testing.T) {
	// NOT loadSpecDoc: this control's schema is a literal with no $ref, so the
	// walk resolves nothing against the document. Parsing 658 KB of YAML to
	// supply an unused receiver would suggest a dependency that is not there.
	doc := specDoc{}
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"closed": map[string]any{"type": "object", "properties": map[string]any{"declared": map[string]any{"type": "string"}}},
			"openWithProps": map[string]any{
				"type":                 "object",
				"additionalProperties": true,
				"properties":           map[string]any{"declared": map[string]any{"type": "string"}},
			},
		},
	}
	body := map[string]any{
		"closed":        map[string]any{"declared": "x"},
		"openWithProps": map[string]any{"declared": "y", "undeclared_and_unreported": 1},
	}
	var open []string
	doc.openNodes(t, schema, body, "", &open)
	if got := distinct(open); len(got) != 1 || got[0] != ".openWithProps" {
		t.Fatalf("openNodes recorded %v; want exactly [.openWithProps] - a node that keeps its properties "+
			"and admits more is open, and recording only the empty-properties kind is what this control exists "+
			"to refuse", got)
	}
	// AND THE POINT OF RECORDING IT: undeclared says nothing about that member.
	var found []string
	doc.undeclared(t, schema, body, "", &found)
	if len(found) != 0 {
		t.Fatalf("undeclared reported %v; the whole reason openNodes records an open node is that undeclared "+
			"cannot report what it holds", found)
	}
}

// publishAndActivate publishes doc through the router and activates it,
// returning the digest that was activated and the activation's response body.
func publishAndActivate(t *testing.T, r *mux.Router, doc *authoring.Document, reason string) (string, map[string]any) {
	t.Helper()
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(doc), gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: status=%d body=%s", rr.Code, rr.Body.String())
	}
	digest, _ := decodeBody(t, rr)["digest"].(string)
	if digest == "" {
		t.Fatalf("publication returned no digest: %s", rr.Body.String())
	}
	rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
		typedAuthoringActivateRequest{Digest: digest, Reason: reason}, gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("activate: status=%d body=%s", rr.Code, rr.Body.String())
	}
	return digest, decodeBody(t, rr)
}
