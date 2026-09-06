// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Spec-versus-CODE parity for the two published OpenAPI documents (#3724,
// umbrella #3709). openapi_route_parity_enterprise_test.go is the other half:
// it answers "does every declared PATH exist?". This one answers "does every
// declared FIELD exist, and does every field the platform marshals appear in
// the document?".

package orchestrator

import (
	"encoding"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"axonflow/platform/agent"
	"axonflow/platform/shared/pep"
)

// WHAT THIS TEST IS FOR
//
// #3724 collected four spec-versus-code gaps that had all survived review:
//
//   - platform/shared/pep.Target had no `server` member, while the published
//     DecisionTarget schema declared one and decision_handler.go fed
//     Target.Server to capability-scoped evaluation and to `tool_server` on
//     every audit row. The blessed PEP client could not send a field the
//     contract advertised and the platform consumed.
//   - docs/api/orchestrator-api.yaml declared 6 properties on
//     PolicyEvaluationResult; the Go type carried 17. Among the eleven missing
//     was `evaluation_error`, the ONLY discriminator between "could not govern"
//     and "a policy said block".
//
// Each was found by a person reading two files side by side, which is why they
// took until a pre-cut audit to surface, and why the durable deliverable here
// is the comparison rather than the eleven properties.
//
// WHY THE FIELD SET IS DERIVED AND NOT LISTED
//
// The obvious shape - a test naming the fields it expects - has EXACTLY the
// hole it exists to close: whoever forgets a field in the schema forgets it in
// the list meant to catch that, and the test passes for the very defect it was
// written against. So the Go side is read by REFLECTION over the type the
// platform actually marshals, and the spec side is read from the document. Add
// a field to any type in the reachable graph below and this test fails until
// the document is updated. That is the property #3707's Binding.Encode has, and
// it is the one being copied.
//
// WHY THE NESTED PAIRS ARE NOT NAMED EITHER
//
// Only the ROOTS are declared (see specAnchors). Everything below them is
// paired STRUCTURALLY: the Go field `PolicyInfo *PolicyEvaluationResult` is
// compared against whatever schema the document's `policy_info` property
// resolves to, whatever either of them is called. That is what lets the walk
// compare pep.Target against DecisionTarget - two names that share no
// substring - without a naming convention doing the work, and it means a
// renamed schema or a renamed Go type cannot silently drop a pair.
//
// WHY THE UNCLASSIFIED CASE IS AN ERROR
//
// A member is compared when both sides agree it is a leaf, and descended into
// when both sides agree it is an object. There is no third arm that shrugs: a
// Go struct described by the document as an opaque object, a Go scalar
// described as a structured one, a `$ref` this walker cannot resolve, or a
// composition it cannot read is REPORTED. A default arm that passed would make
// every future shape this walker has not met invisible, which is how a census
// becomes bounded by its author.
//
// WHAT IT DOES NOT CHECK, STATED SO NOBODY INFERS IT
//
// TYPES. `type: integer` against Go int64 versus int32 is a width question this
// walker does not answer, and claiming to answer it would be worse than not.
// CARDINALITY is checked (list versus scalar), because R3 found that a document
// declaring `applied_policies` as a bare string against a Go []string passed
// silently, and a spec-generated client would have modelled it as a string.
// ORDER is not checked and is not a contract: the document is parsed into an
// unordered map.
//
// WHY IT LIVES IN platform/orchestrator
//
// It guards BOTH published documents from one file because this is the only
// package that can see every type involved without an import cycle:
// platform/orchestrator already imports platform/agent (audit_logger.go), and
// platform/agent imports platform/shared/pep, so nothing can import
// platform/orchestrator back. Splitting it in two would mean two copies of the
// walker, which is the defect class #3709 is about.
//
// TWO MORE IN-TREE MIRRORS EXIST AND THIS CANNOT REACH EITHER.
// examples/integrations/decision-mode-adapter and
// examples/integrations/decision-mode-mcp-adapter each re-declare the DTOs
// again, and each is its OWN Go module, so no test in this module can import
// them. The mcp one already diverges - ExpiresAt is a string there and a
// time.Time in the other three. A first version of this note said there was a
// THIRD mirror; review round 2 found the fourth, which is exactly why the
// count is not the guard. Recorded on #3709 rather than papered over here.

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// findingKind enumerates every way this walker can report a defect.
type findingKind string

const (
	// kindGoFieldAbsentFromSpec: the platform marshals a member the published
	// document does not declare. A spec-generated client cannot see it.
	kindGoFieldAbsentFromSpec findingKind = "go-field-absent-from-spec"

	// kindSpecPropertyAbsentFromGo: the document declares a member no Go field
	// carries. A spec-generated client sends something silently dropped, or
	// waits for something never sent. #3724 gap 1 is this shape.
	kindSpecPropertyAbsentFromGo findingKind = "spec-property-absent-from-go"

	// kindStructness: the two sides disagree about whether a member is a leaf
	// or an object, or the document says something this walker cannot read.
	// This is the DEFAULT ARM - anything the two classifiers do not both
	// recognise lands here rather than being skipped.
	kindStructness findingKind = "structness-disagreement"

	// kindCardinality: one side says LIST and the other says SCALAR. Separate
	// from kindStructness because an array of objects and a bare object are
	// both "an object" to a field-parity walk, and R3 round 1 proved both
	// directions passed silently before this existed.
	kindCardinality findingKind = "cardinality-disagreement"

	// kindAmbiguousMember: two Go fields resolve to one JSON name. encoding/json
	// decides this by DEPTH (shallower wins; equal depth drops both), and this
	// walker will not reimplement that rule - it reports instead, because a
	// member it guessed about is a member it cannot speak for.
	kindAmbiguousMember findingKind = "ambiguous-go-member"

	// kindVacuousPair: a pair where one side carries no members at all, so
	// every comparison over it would trivially hold. Reported so that a schema
	// emptied by an edit cannot make its Go type stop being checked.
	kindVacuousPair findingKind = "vacuous-pair"
)

// allFindingKinds is the registry, and it is load-bearing rather than
// documentation.
//
// R3 ROUND 1 KILLED THE FIRST VERSION OF THIS MECHANISM. The positive control
// used to range over a hardcoded slice of four kinds and `delete` from a map
// built from the same four, so its "every kind is exercised" assertion could
// never fail - a fifth kind with no planted instance passed. Now: newFinding
// PANICS on a kind that is not registered here, so a kind cannot be emitted
// without being added; and the control ranges over THIS slice, so a registered
// kind with no planted instance fails. Neither half works alone.
var allFindingKinds = []findingKind{
	kindGoFieldAbsentFromSpec,
	kindSpecPropertyAbsentFromGo,
	kindStructness,
	kindCardinality,
	kindAmbiguousMember,
	kindVacuousPair,
}

type finding struct {
	kind findingKind
	// where is the structural path from the anchor, e.g.
	// "OrchestratorResponse<->orchestrator.OrchestratorResponse.policy_info".
	where string
	msg   string
}

func (f finding) String() string { return fmt.Sprintf("[%s] %s: %s", f.kind, f.where, f.msg) }

// newFinding is the only way to build one. See allFindingKinds.
func newFinding(kind findingKind, where, msg string) finding {
	for _, k := range allFindingKinds {
		if k == kind {
			return finding{kind: kind, where: where, msg: msg}
		}
	}
	panic(fmt.Sprintf("openapi parity: finding kind %q is not registered in allFindingKinds, so "+
		"TestTheParityWalkerReportsEveryDefectItCan cannot require a planted instance for it. "+
		"Register it and plant one.", kind))
}

// ---------------------------------------------------------------------------
// The spec side
// ---------------------------------------------------------------------------

// schemaSet is components.schemas from one published document.
type schemaSet map[string]map[string]any

func loadSchemaSet(t *testing.T, rel string) schemaSet {
	t.Helper()
	raw, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	if len(doc.Components.Schemas) == 0 {
		t.Fatalf("%s declares no components.schemas; the parse is reading nothing and every "+
			"assertion below would hold over an empty document", rel)
	}
	return schemaSet(doc.Components.Schemas)
}

const schemaRefPrefix = "#/components/schemas/"

// maxSchemaDepth bounds pointer/slice/map unwrapping on the GO side, where
// there is no cycle to track (a Go type graph can be recursive, but each
// unwrap strictly reduces the type).
const maxSchemaDepth = 16

// visited tracks the schema NODES a single read has already entered, by
// identity, and is what stops a cyclic document from wedging its reader.
//
// R3 ROUND 1 built two schemas whose `allOf` referred to each other and took
// the WHOLE test binary down with a stack overflow - every unrelated test in
// this package, with no attribution. R3 ROUND 2 then proved the first repair
// was the wrong instrument twice over: a depth COUNTER left `shapeOf`'s
// recursion through `items` unbounded (still overflowed), and in `properties`
// it turned the crash into a HANG, because a counter is exponential in the
// `allOf` branching factor - 4^16 calls did not finish in twenty seconds. A
// counter bounds how DEEP you go; only a visited set bounds how MANY times you
// re-enter the same node. A document is an input, and an input must not be able
// to crash OR wedge its reader.
type visited map[*map[string]any]bool

func (v visited) enter(node map[string]any) bool {
	// Keyed on the address of the map header this call holds. Two different
	// property nodes are different maps even when they carry equal content, so
	// this only ever stops a genuine re-entry into the SAME node.
	k := &node
	for seen := range v {
		if len(*seen) == len(node) && sameNode(*seen, node) {
			return false
		}
	}
	v[k] = true
	return true
}

// sameNode reports pointer-identity of the underlying map. reflect is used
// because Go will not compare maps with ==, and a content comparison would
// wrongly merge two distinct nodes that happen to be equal.
func sameNode(a, b map[string]any) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// deref follows a `$ref` to components.schemas, as many times as needed.
// It returns the resolved node and the name it resolved through (empty for an
// inline node), plus false when a `$ref` points somewhere this walker cannot
// follow - which is REPORTED rather than treated as a leaf.
func (s schemaSet) deref(node map[string]any) (map[string]any, string, bool) {
	name := ""
	for i := 0; i < maxSchemaDepth; i++ {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node, name, true
		}
		if !strings.HasPrefix(ref, schemaRefPrefix) {
			return nil, "", false
		}
		name = strings.TrimPrefix(ref, schemaRefPrefix)
		next, ok := s[name]
		if !ok {
			return nil, "", false
		}
		node = next
	}
	return nil, "", false
}

// properties returns the declared property set of a node, merging `allOf`
// members. `allOf` is how this document attaches a description to a `$ref`
// (OrchestratorResponse.media_analysis does exactly that), so a walker that
// ignored it would read those members as having no properties and classify
// every one of them as a leaf.
//
// It returns a REASON when it could not read the whole node. R3 round 2 found
// the first version `continue`d past an `allOf` member whose `$ref` did not
// resolve, so a broken document surfaced as a Go/spec FIELD mismatch - verbatim
// the class the previous round's fix claimed to close, surviving in the reader
// that fix did not touch.
func (s schemaSet) properties(node map[string]any, seen visited) (map[string]any, string) {
	out := map[string]any{}
	if !seen.enter(node) {
		return out, "it is part of an allOf cycle, which this walker will not follow"
	}
	if props, ok := node["properties"].(map[string]any); ok {
		for k, v := range props {
			out[k] = v
		}
	}
	if all, ok := node["allOf"].([]any); ok {
		for _, m := range all {
			mm, ok := m.(map[string]any)
			if !ok {
				return out, "one of its allOf members is not a mapping"
			}
			resolved, _, ok := s.deref(mm)
			if !ok {
				return out, "one of its allOf members has a $ref this walker cannot resolve"
			}
			for _, k := range composedKeys {
				if _, present := resolved[k]; present {
					// M1: a oneOf hiding one level down, inside an allOf.
					return out, "one of its allOf members is composed with " + k +
						", which this walker does not read"
				}
			}
			inner, why := s.properties(resolved, seen)
			if why != "" {
				return out, why
			}
			for k, v := range inner {
				out[k] = v
			}
		}
	}
	return out, ""
}

// schemaShape is everything this walker can say about one property node.
type schemaShape struct {
	// object is true when the node describes something with named members.
	object bool
	// node and name are the schema to descend into when object is true.
	node map[string]any
	name string
	// list is true when the node describes an ARRAY.
	list bool
	// unreadable, when non-empty, is why this walker could not classify the
	// node at all. It is reported verbatim: R3 round 1 found the diagnostic
	// printing "the document describes this as a leaf" for a `oneOf`, an
	// over-deep `$ref` chain and a broken `$ref` alike - three causes it had
	// not observed and one of which is a broken document, not a mismatch.
	unreadable string
}

// composedKeys are the compositions this walker cannot read. They are named
// rather than ignored: a member described by a `oneOf` has a shape this walk
// has no opinion about, and silently calling it a leaf is a claim.
var composedKeys = []string{"oneOf", "anyOf", "not"}

// shapeOf classifies one property node.
//
// It carries the same `visited` set as properties(), because R3 round 2 proved
// the recursion through `items` was the half the first depth bound never
// covered: `A.items -> $ref A` still overflowed the stack.
func (s schemaSet) shapeOf(node map[string]any, seen visited) schemaShape {
	resolved, name, ok := s.deref(node)
	if !ok {
		return schemaShape{unreadable: "its $ref does not resolve to a components.schemas entry, " +
			"or the chain is deeper than this walker follows"}
	}
	for _, k := range composedKeys {
		if _, present := resolved[k]; present {
			return schemaShape{unreadable: "it is composed with " + k + ", which this walker does not read"}
		}
	}
	shape := schemaShape{}
	if rawItems, present := resolved["items"]; present {
		items, ok := rawItems.(map[string]any)
		if !ok {
			// L5: the TUPLE form, `items: [ {...}, {...} ]`. It describes a
			// positional array this walker has no model for. Reported rather
			// than silently treated as a plain list, because the preamble
			// promises no arm that shrugs.
			return schemaShape{list: true,
				unreadable: "its `items` is a list (the tuple form), which this walker does not read"}
		}
		if len(s.propertyNames(resolved)) > 0 {
			// L6: `items` AND `properties` on one node. One of them is being
			// ignored by every reader; which one is not this walker's to guess.
			return schemaShape{list: true,
				unreadable: "it declares both `items` and `properties`, so it describes an array and " +
					"an object at once"}
		}
		if !seen.enter(resolved) {
			return schemaShape{list: true,
				unreadable: "its `items` chain is cyclic, which this walker will not follow"}
		}
		shape.list = true
		inner := s.shapeOf(items, seen)
		if inner.unreadable != "" {
			return schemaShape{list: true, unreadable: inner.unreadable}
		}
		shape.object, shape.node, shape.name = inner.object, inner.node, inner.name
		return shape
	}
	if t, ok := resolved["type"].(string); ok && t == "array" {
		// `type: array` with no `items` describes a list of unspecified
		// members. It is a list, and it is not an object.
		shape.list = true
		return shape
	}
	props, why := s.properties(resolved, visited{})
	if why != "" {
		return schemaShape{unreadable: why}
	}
	if len(props) > 0 {
		shape.object, shape.node, shape.name = true, resolved, name
	}
	return shape
}

// propertyNames is the shallow property set of ONE node, used only to detect
// the items-and-properties collision above. It deliberately does not merge
// allOf: the question there is whether THIS node declares both.
func (s schemaSet) propertyNames(node map[string]any) map[string]any {
	if props, ok := node["properties"].(map[string]any); ok {
		return props
	}
	return map[string]any{}
}

// ---------------------------------------------------------------------------
// The Go side
// ---------------------------------------------------------------------------

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// wireLeafStruct reports whether a type marshals to a SCALAR, so the document
// is right to describe it without properties.
//
// DERIVED, not listed. It used to be a map holding time.Time, and R3 round 1
// pointed out that this file's own preamble condemns exactly that: any type
// with a MarshalJSON of its own would red the guard while the document was
// right. time.Time now falls out of the rule rather than being named by it.
//
// ADDRESSABILITY IS THE PART THAT IS EASY TO GET WRONG, and R3 round 2 got the
// first version on it. `reflect.PointerTo(t).Implements(...)` is true for a
// POINTER-RECEIVER-only MarshalJSON, and the first version treated that as a
// leaf - but encoding/json cannot call a pointer method on a struct FIELD held
// by value, because the value is unaddressable, so it renders the object
// instead. Reading it as a leaf makes the walker go blind on a real object.
// So a pointer-receiver method counts only when the value was reached THROUGH a
// pointer, which is exactly when encoding/json can call it.
//
// encoding.TextMarshaler is here for the same reason as json.Marshaler:
// encoding/json falls back to it and renders a string, so a type carrying only
// that is a leaf too.
func wireLeafStruct(t reflect.Type, addressable bool) bool {
	if t.Implements(jsonMarshalerType) || t.Implements(textMarshalerType) {
		return true
	}
	if !addressable {
		return false
	}
	pt := reflect.PointerTo(t)
	return pt.Implements(jsonMarshalerType) || pt.Implements(textMarshalerType)
}

// goMember is one JSON-visible member of a Go struct.
type goMember struct {
	name string
	typ  reflect.Type
}

// goMembers returns the members encoding/json would emit for t.
//
// Embedded anonymous structs with no json tag are FLATTENED, because that is
// what the encoder does: their members appear at the parent's level on the
// wire. A member name that appears TWICE after flattening is NOT resolved here
// - encoding/json decides it by depth and drops equal-depth conflicts entirely,
// and a walker that picked one would be speaking for a member the encoder may
// never emit. The duplicate is reported instead; see kindAmbiguousMember.
func goMembers(t reflect.Type) []goMember {
	var out []goMember
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		nameTag, _, _ := strings.Cut(tag, ",")
		if nameTag == "-" && !strings.Contains(tag, ",") {
			continue
		}
		if f.Anonymous && nameTag == "" {
			et := f.Type
			for et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct && !wireLeafStruct(et, f.Type.Kind() == reflect.Pointer) {
				out = append(out, goMembers(et)...)
				continue
			}
		}
		// Unexported, and NOT an embedded struct whose members were just
		// promoted. The order matters: an anonymous field of an UNEXPORTED
		// struct type reports a non-empty PkgPath (the field name is the type
		// name, which is unexported), yet encoding/json promotes its exported
		// members all the same. Testing PkgPath first - the obvious order -
		// drops that whole subtree from the census silently, which is the
		// difference between comparing a member and not knowing it exists.
		if f.PkgPath != "" {
			continue
		}
		name := nameTag
		if name == "" {
			name = f.Name
		}
		out = append(out, goMember{name: name, typ: f.Type})
	}
	return out
}

// goShape is the Go-side counterpart of schemaShape.
type goShape struct {
	object bool
	typ    reflect.Type
	list   bool
}

// shapeOfGo classifies a Go type, looking through the containers that do not
// change the member set: pointer, slice, array, and map VALUE.
//
// THE THREE CARDINALITY CASES ARE NOT THE SAME, and R3 round 2 caught two of
// them merged:
//
//   - a SLICE of uint8 is `[]byte`, which encoding/json renders as a base64
//     STRING. Not a list.
//   - an ARRAY of uint8 (`[16]byte`) renders as a JSON ARRAY of numbers, which
//     the first version excluded alongside `[]byte` because they shared an arm.
//   - a MAP renders as a JSON OBJECT whatever its value type, so
//     `map[string][]string` is not a list. The first version fell through from
//     the map arm to the slice arm and called it one.
//
// Neither is reachable in today's anchored graph; both were wrong anyway, and a
// classifier that is wrong where nothing looks is a classifier nobody can trust
// where something does.
func shapeOfGo(t reflect.Type) goShape {
	out := goShape{}
	viaPointer := false
	for i := 0; i < maxSchemaDepth; i++ {
		if wireLeafStruct(t, viaPointer) {
			return out
		}
		switch t.Kind() {
		case reflect.Pointer:
			viaPointer = true
			t = t.Elem()
		case reflect.Slice:
			if t.Elem().Kind() == reflect.Uint8 {
				return out // []byte / json.RawMessage: a base64 string.
			}
			out.list, viaPointer = true, false
			t = t.Elem()
		case reflect.Array:
			out.list, viaPointer = true, false
			t = t.Elem()
		case reflect.Map:
			// An object on the wire, never a list, whatever the value type.
			out.list, viaPointer = false, false
			t = t.Elem()
		default:
			i = maxSchemaDepth
		}
	}
	if t.Kind() == reflect.Struct && !wireLeafStruct(t, viaPointer) {
		out.object, out.typ = true, t
	}
	return out
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

// compareSchemaToType walks one (schema, Go type) pair and everything
// structurally reachable from it, appending a finding for every disagreement.
//
// reached records every pair the walk visited, keyed "<schema>|<go type>". It
// is the anti-vacuity instrument: a walk that stopped at the anchors, or never
// started, leaves it small enough to see.
func compareSchemaToType(s schemaSet, schemaName string, node map[string]any, t reflect.Type, path string, reached map[string]bool, out *[]finding) {
	shape := shapeOfGo(t)
	if !shape.object {
		*out = append(*out, newFinding(kindStructness, path,
			fmt.Sprintf("the document describes this as an object with named members and the Go type is %s, "+
				"which carries none", t)))
		return
	}
	goType := shape.typ
	key := schemaName + "|" + goType.PkgPath() + "." + goType.Name()
	if reached[key] {
		return
	}
	reached[key] = true

	specProps, whyUnreadable := s.properties(node, visited{})
	if whyUnreadable != "" {
		*out = append(*out, newFinding(kindStructness, path,
			fmt.Sprintf("%s cannot be read: %s", schemaName, whyUnreadable)))
		return
	}
	members := goMembers(goType)

	if len(specProps) == 0 || len(members) == 0 {
		*out = append(*out, newFinding(kindVacuousPair, path,
			fmt.Sprintf("%s declares %d properties and %s carries %d JSON members; a pair with an empty "+
				"side asserts nothing", schemaName, len(specProps), goType, len(members))))
		return
	}

	byName := map[string]reflect.Type{}
	var order []string
	for _, m := range members {
		if _, dup := byName[m.name]; dup {
			*out = append(*out, newFinding(kindAmbiguousMember, path+"."+m.name,
				fmt.Sprintf("%s resolves two fields to the JSON member %q. encoding/json decides this by "+
					"DEPTH - the shallower field wins, and two at equal depth are BOTH dropped - so "+
					"this walker cannot say which member, if any, reaches the wire. Give one of them "+
					"an explicit tag or stop embedding.", goType, m.name)))
			continue
		}
		byName[m.name] = m.typ
		order = append(order, m.name)
	}

	for _, name := range order {
		ft := byName[name]
		propNode, declared := specProps[name].(map[string]any)
		if !declared {
			if _, present := specProps[name]; !present {
				*out = append(*out, newFinding(kindGoFieldAbsentFromSpec, path+"."+name,
					fmt.Sprintf("%s marshals %q and %s does not declare it, so a spec-generated client "+
						"cannot see it", goType, name, schemaName)))
				continue
			}
			*out = append(*out, newFinding(kindStructness, path+"."+name,
				fmt.Sprintf("%s.%s is not a mapping, so this walker cannot classify it", schemaName, name)))
			continue
		}

		specShape := s.shapeOf(propNode, visited{})
		goSub := shapeOfGo(ft)

		// A member the document describes in a way this walker cannot read is
		// reported REGARDLESS of the Go side. Reporting it only on a mismatch
		// would mean the walker claimed to have checked a member it could not
		// read whenever the Go side happened to be a leaf.
		if specShape.unreadable != "" {
			*out = append(*out, newFinding(kindStructness, path+"."+name,
				fmt.Sprintf("the document's %q cannot be classified: %s. The Go type is %s.",
					name, specShape.unreadable, ft)))
			continue
		}

		if specShape.list != goSub.list {
			*out = append(*out, newFinding(kindCardinality, path+"."+name,
				fmt.Sprintf("the document describes %q as %s and the Go type %s is %s. A spec-generated "+
					"client would model the wrong shape for this member.",
					name, listWord(specShape.list), ft, listWord(goSub.list))))
			// NO `continue`. R3 round 2: the first version returned here, so
			// one cardinality mismatch hid every divergence in that member's
			// whole SUBTREE and shrank `reached` alongside - the anti-vacuity
			// floor quietly weakening because of a finding. Cardinality and
			// field parity are independent questions; both get answered.
		}

		switch {
		case specShape.object && goSub.object:
			childName := specShape.name
			if childName == "" {
				childName = schemaName + "." + name
			}
			compareSchemaToType(s, childName, specShape.node, ft, path+"."+name, reached, out)
		case !specShape.object && !goSub.object:
			// Leaf on both sides. Types are not compared: the document's
			// `type: integer` versus Go's int64 is a width question this
			// walker is not built to answer, and claiming to answer it would
			// be worse than not.
		default:
			*out = append(*out, newFinding(kindStructness, path+"."+name,
				fmt.Sprintf("the document describes %q as %s and the Go type %s is %s",
					name, objectWord(specShape.object), ft, objectWord(goSub.object))))
		}
	}

	for name := range specProps {
		if _, ok := byName[name]; !ok {
			*out = append(*out, newFinding(kindSpecPropertyAbsentFromGo, path+"."+name,
				fmt.Sprintf("%s declares %q and %s carries no such JSON member, so a spec-generated "+
					"client would send or expect something the platform never handles",
					schemaName, name, goType)))
		}
	}
}

func objectWord(isObject bool) string {
	if isObject {
		return "a structured object"
	}
	return "a leaf"
}

func listWord(isList bool) string {
	if isList {
		return "a list"
	}
	return "a single value"
}

// ---------------------------------------------------------------------------
// The anchors
// ---------------------------------------------------------------------------

type specAnchor struct {
	doc    string // the published document, relative to the repository root
	schema string
	typ    reflect.Type
	why    string
}

// specAnchors are the ROOTS of the walk: the envelopes a caller of the two
// governed decision surfaces actually puts on, or takes off, the wire.
//
// EVERY OTHER PAIR IS DERIVED FROM THESE, so this list is the only
// author-bounded thing in the file and the reason it is short. It is not a
// census of the two documents - #3724's own measurement found 88 name-matched
// schema/struct pairs across both, carrying ~145 individual divergences, which
// is its own lane and is reported on #3709 rather than absorbed here.
//
// BOTH MIRRORS OF EACH DECISION DTO ARE ANCHORED, and that is the point of
// listing four entries for two schemas. platform/shared/pep re-declares the
// Decision API DTOs so it stays light enough to vendor into a customer gateway
// (see its package doc), and a second mirror of a wire type is invisible to
// every unit test that exercises only one copy - #3707's dpcustodyctl/portal
// pair diverged the moment a field was added and every test passed. Comparing
// both mirrors against the SAME schema makes them agree with each other by
// construction, with no third mechanism to maintain.
func specAnchors() []specAnchor {
	agentAPI := filepath.Join("..", "..", "docs", "api", "agent-api.yaml")
	orchestratorAPI := filepath.Join("..", "..", "docs", "api", "orchestrator-api.yaml")
	return []specAnchor{
		{agentAPI, "DecideRequest", reflect.TypeOf(agent.DecideRequest{}),
			"the body POST /api/v1/decide decodes"},
		{agentAPI, "DecideRequest", reflect.TypeOf(pep.DecideRequest{}),
			"the blessed PEP client's mirror of that body - #3724 gap 1 was here"},
		{agentAPI, "DecideResponse", reflect.TypeOf(agent.DecideResponse{}),
			"the verdict POST /api/v1/decide marshals"},
		{agentAPI, "DecideResponse", reflect.TypeOf(pep.DecideResponse{}),
			"the blessed PEP client's mirror of that verdict"},
		{orchestratorAPI, "OrchestratorRequest", reflect.TypeOf(OrchestratorRequest{}),
			"the body the orchestrator's governed entry point decodes"},
		{orchestratorAPI, "OrchestratorResponse", reflect.TypeOf(OrchestratorResponse{}),
			"the envelope it marshals - reaches PolicyEvaluationResult, #3724 gap 3"},
	}
}

// TestThePublishedSchemasMatchTheTypesThePlatformMarshals is the guard.
func TestThePublishedSchemasMatchTheTypesThePlatformMarshals(t *testing.T) {
	docs := map[string]schemaSet{}
	reached := map[string]bool{}
	var findings []finding

	anchors := specAnchors()
	if len(anchors) == 0 {
		t.Fatal("no anchors: the walk would report nothing and pass")
	}

	// PER-ANCHOR descent, not a global count. R3 round 1: a single global
	// floor of len(reached) > len(anchors) is satisfied by the agent-api half
	// alone, so the WHOLE orchestrator half could stop descending and the
	// floor stayed green - which is exactly where #3724 gap 3 lives.
	for _, a := range anchors {
		s, ok := docs[a.doc]
		if !ok {
			s = loadSchemaSet(t, a.doc)
			docs[a.doc] = s
		}
		node, present := s[a.schema]
		if !present {
			t.Fatalf("%s is not in %s's components.schemas. The anchor named it because the platform "+
				"marshals %s to it; a renamed or deleted schema silently stops this walk rather than "+
				"failing it, so it fails here instead.", a.schema, a.doc, a.typ)
		}

		goType := shapeOfGo(a.typ).typ
		if goType == nil {
			t.Fatalf("anchor %s (%s) is not a struct, so it contributes no comparison at all", a.schema, a.typ)
		}
		// EACH ANCHOR IS WALKED WITH ITS OWN `reached` SET, and that is the
		// whole of the descent measurement.
		//
		// R3 round 2: measuring `len(reached) - before` over a SHARED set is
		// fail-open at zero. When an earlier anchor had already visited this
		// anchor's own pair, compareSchemaToType returns at its `reached`
		// guard, the delta is 0, the own-pair check still passes (the earlier
		// anchor set that key), and a `grew == 1` test is silent about an
		// anchor that compared nothing at all. A per-anchor set cannot be
		// confused that way: every anchor walks its whole graph, and its own
		// count is its own.
		perAnchor := map[string]bool{}
		compareSchemaToType(s, a.schema, node, a.typ, a.schema+"<->"+a.typ.String(), perAnchor, &findings)
		ownPair := a.schema + "|" + goType.PkgPath() + "." + goType.Name()
		if !perAnchor[ownPair] {
			t.Fatalf("anchor %s <-> %s was never compared (%s); the walk is not reading what this test "+
				"claims it reads", a.schema, a.typ, a.why)
		}
		// Every anchor's graph reaches at least one NESTED schema: all six
		// carry a structured member (caller_identity, target, obligations,
		// user, client, policy_info). An anchor that reached only its own pair
		// stopped descending, and its subtree - where gap 1 and gap 3 both
		// live - would be invisible.
		if len(perAnchor) < 2 {
			t.Errorf("anchor %s <-> %s reached only its own pair and descended into nothing. "+
				"#3724 gap 1 and gap 3 both live one level below an anchor.", a.schema, a.typ)
		}
		for k := range perAnchor {
			reached[k] = true
		}
	}

	if len(findings) > 0 {
		// DEDUPED, because each anchor now walks its own graph and two anchors
		// legitimately share a subtree (both DecideRequest mirrors reach
		// DecisionTarget). Reporting the same divergence twice would make the
		// count a measure of the anchor list rather than of the document.
		seenMsg := map[string]bool{}
		msgs := make([]string, 0, len(findings))
		for _, f := range findings {
			m := f.String()
			if seenMsg[m] {
				continue
			}
			seenMsg[m] = true
			msgs = append(msgs, m)
		}
		sort.Strings(msgs)
		t.Errorf("%d distinct spec-versus-code divergence(s) across %d compared pairs (#3724):\n  %s\n\n"+
			"Fix the document or the Go type. There is no exemption list: a divergence here means a "+
			"spec-generated client and this platform disagree about the wire.",
			len(msgs), len(reached), strings.Join(msgs, "\n  "))
	}
}

// ---------------------------------------------------------------------------
// The positive control
// ---------------------------------------------------------------------------
//
// The walker above is the only thing standing between a new field and a stale
// document, so it needs its own evidence that it can fail. These types and this
// synthetic document plant one instance of every defect class; the test asserts
// the walker reports each of them AND that no registered kind goes unexercised.

type plantedNested struct {
	Kept    string `json:"kept"`
	Dropped string `json:"dropped"` // absent from the synthetic document
}

type plantedLeafOnly struct {
	Value string `json:"value"`
}

type plantedEmbedded struct {
	Inherited string `json:"inherited"`
}

// PlantedTwin and PlantedOther both carry `clash`. A struct EMBEDDING both is
// how a duplicate JSON member arises in practice, and it is composed at RUNTIME
// by plantedClashType rather than declared: `go vet`'s structtag analyser
// rejects the promoted duplicate at compile time, which is a good rule and
// exactly why this defect is rare - and a control that cannot be built is not a
// control. Composing it with reflect.StructOf keeps the planted shape without
// putting a vet violation in the tree.
type PlantedTwin struct {
	Clash string `json:"clash"`
}

type PlantedOther struct {
	Clash string `json:"clash"`
}

func plantedClashType() reflect.Type {
	return reflect.StructOf([]reflect.StructField{
		{Name: "PlantedTwin", Type: reflect.TypeOf(PlantedTwin{}), Anonymous: true},
		{Name: "PlantedOther", Type: reflect.TypeOf(PlantedOther{}), Anonymous: true},
		{Name: "Real", Type: reflect.TypeOf(""), Tag: `json:"real"`},
	})
}

// plantedStamp marshals to a scalar through its own MarshalJSON, which is how
// wireLeafStruct recognises a leaf without a hand-written list.
type plantedStamp struct {
	At time.Time
}

func (p plantedStamp) MarshalJSON() ([]byte, error) { return json.Marshal(p.At) }

type plantedRoot struct {
	plantedEmbedded                 // flattened: `inherited` must appear at this level
	Scalar          string          `json:"scalar"`
	Stamp           plantedStamp    `json:"stamp"` // a struct that marshals as a leaf
	Raw             json.RawMessage `json:"raw"`   // []byte: a leaf, not a list
	Free            map[string]any  `json:"free"`  // a free-form map: a leaf
	Nested          plantedNested   `json:"nested"`
	List            []plantedNested `json:"list"` // an array of objects: descended into
	// LeafHere is a scalar the document describes as a structured object.
	LeafHere string `json:"leaf_here"`
	// ObjectHere is a struct the document describes as a leaf.
	ObjectHere plantedLeafOnly `json:"object_here"`
	// ScalarHere is a single value the document describes as an array.
	ScalarHere string `json:"scalar_here"`
	// Composed is described by a oneOf, which the walker cannot read.
	Composed string `json:"composed"`
	Skipped  string `json:"-"` // never marshalled, never compared
}

type plantedVacuous struct {
	Something string `json:"something"`
}

const plantedDocument = `
PlantedRoot:
  type: object
  properties:
    inherited: {type: string}
    scalar: {type: string}
    stamp: {type: string, format: date-time}
    raw: {type: string}
    free: {type: object, additionalProperties: true}
    nested:
      allOf:
        - $ref: '#/components/schemas/PlantedNested'
    list:
      type: array
      items: {$ref: '#/components/schemas/PlantedNested'}
    leaf_here: {$ref: '#/components/schemas/PlantedLeafOnly'}
    object_here: {type: string}
    scalar_here:
      type: array
      items: {type: string}
    composed:
      oneOf:
        - {type: string}
        - {type: integer}
    only_in_the_document: {type: string}
PlantedNested:
  type: object
  properties:
    kept: {type: string}
PlantedLeafOnly:
  type: object
  properties:
    value: {type: string}
PlantedClash:
  type: object
  properties:
    clash: {type: string}
    real: {type: string}
PlantedVacuous:
  type: object
PlantedCyclicA:
  allOf:
    - $ref: '#/components/schemas/PlantedCyclicB'
PlantedCyclicB:
  allOf:
    - $ref: '#/components/schemas/PlantedCyclicA'
PlantedCyclicItems:
  type: array
  items: {$ref: '#/components/schemas/PlantedCyclicItems'}
PlantedTupleItems:
  type: array
  items:
    - {type: string}
    - {type: integer}
PlantedItemsAndProperties:
  type: array
  items: {type: string}
  properties:
    also: {type: string}
PlantedBrokenAllOf:
  allOf:
    - $ref: '#/components/schemas/NoSuchSchema'
PlantedHiddenOneOf:
  allOf:
    - $ref: '#/components/schemas/PlantedOneOfInner'
PlantedOneOfInner:
  oneOf:
    - {type: string}
    - {type: integer}
`

func loadPlanted(t *testing.T) schemaSet {
	t.Helper()
	var out map[string]map[string]any
	if err := yaml.Unmarshal([]byte(plantedDocument), &out); err != nil {
		t.Fatalf("parse the synthetic document: %v", err)
	}
	return schemaSet(out)
}

// TestTheParityWalkerReportsEveryDefectItCan is the positive control.
//
// WHY IT RANGES OVER allFindingKinds AND NOT OVER A LITERAL. R3 round 1 killed
// the first version: it ranged over a hardcoded slice of the same four kinds
// its `want` map held, deleting unconditionally, so the "every kind is
// exercised" check could never fail and a fifth kind with no control passed.
// It now ranges over the registry itself, and newFinding panics on an
// unregistered kind - so a new kind must be registered, and a registered kind
// must be planted.
func TestTheParityWalkerReportsEveryDefectItCan(t *testing.T) {
	s := loadPlanted(t)
	reached := map[string]bool{}
	var findings []finding
	compareSchemaToType(s, "PlantedRoot", s["PlantedRoot"], reflect.TypeOf(plantedRoot{}), "planted", reached, &findings)
	compareSchemaToType(s, "PlantedClash", s["PlantedClash"], plantedClashType(), "clash", reached, &findings)
	compareSchemaToType(s, "PlantedVacuous", s["PlantedVacuous"], reflect.TypeOf(plantedVacuous{}), "vacuous", reached, &findings)

	got := map[findingKind][]string{}
	for _, f := range findings {
		got[f.kind] = append(got[f.kind], f.where)
	}

	// Every registered kind, and the exact place its planted instance must be
	// reported. A kind with no entry here fails below rather than passing.
	plantedAt := map[findingKind]string{
		kindGoFieldAbsentFromSpec:    "planted.nested.dropped",
		kindSpecPropertyAbsentFromGo: "planted.only_in_the_document",
		kindStructness:               "planted.leaf_here",
		kindCardinality:              "planted.scalar_here",
		kindAmbiguousMember:          "clash.clash",
		kindVacuousPair:              "vacuous",
	}
	for _, kind := range allFindingKinds {
		where, declared := plantedAt[kind]
		if !declared {
			t.Errorf("finding kind %s is registered in allFindingKinds and this control plants no "+
				"instance of it, so nothing proves it can fire", kind)
			continue
		}
		found := false
		for _, w := range got[kind] {
			if w == where {
				found = true
			}
		}
		if !found {
			t.Errorf("the walker did not report %s at %q. It reported %v for that kind, which means the "+
				"planted defect is no longer detected.", kind, where, got[kind])
		}
	}
	for kind := range plantedAt {
		registered := false
		for _, k := range allFindingKinds {
			if k == kind {
				registered = true
			}
		}
		if !registered {
			t.Errorf("this control plants %s and allFindingKinds does not register it", kind)
		}
	}

	// The unreadable-composition arm reports the OBSERVED cause, not a guess.
	// R3 round 1 found the diagnostic saying "the document describes this as a
	// leaf" for a oneOf, an over-deep $ref and a broken $ref alike.
	composed := ""
	for _, f := range findings {
		if f.where == "planted.composed" {
			composed = f.msg
		}
	}
	if !strings.Contains(composed, "composed with oneOf") {
		t.Errorf("the oneOf member was reported as %q; the diagnostic must name the cause it observed, "+
			"not a cause it assumed", composed)
	}

	// The OTHER direction of the same control: members the walker must NOT
	// report. `skipped` is json:"-" on the Go side and absent from the
	// document, so it must be reported by NEITHER direction; `stamp`, `raw`
	// and `free` are leaves on both sides; `inherited` matches the document
	// only because the embedded struct was flattened; `list` is an array of
	// objects that must be descended into rather than called a leaf.
	//
	// Without this half, a walker that reported EVERYTHING would satisfy every
	// assertion above.
	silent := map[string]bool{
		"planted.skipped": true, "planted.stamp": true, "planted.raw": true,
		"planted.free": true, "planted.inherited": true, "planted.list": true,
		"planted.nested.kept": true, "planted.object_here.value": true,
		"clash.real": true,
	}
	for _, f := range findings {
		if silent[f.where] {
			t.Errorf("the walker reported %s, and that member is correct on both sides. A walker that "+
				"reports correct members cannot be distinguished from one that reports defects.", f)
		}
	}

	if !reached["PlantedNested|"+reflect.TypeOf(plantedNested{}).PkgPath()+".plantedNested"] {
		t.Error("the walk never descended into PlantedNested, so its planted missing field was found by " +
			"accident rather than by the descent this walker exists for")
	}
}

// TestACyclicDocumentDoesNotCrashTheReader.
//
// R3 round 1 took the WHOLE package down with a stack overflow by giving two
// schemas `allOf` members referring to each other - every unrelated test in
// platform/orchestrator died with no attribution. A published document is an
// INPUT, and an input must never be able to crash its reader.
func TestACyclicDocumentDoesNotCrashTheReader(t *testing.T) {
	s := loadPlanted(t)
	// Returns rather than recursing forever. The assertion is that this line
	// completes at all; the empty result is the correct answer for a cycle
	// that declares no properties anywhere in it.
	props, why := s.properties(s["PlantedCyclicA"], visited{})
	if why == "" {
		t.Error("a cyclic allOf was read as if it were sound; the cycle must be REPORTED, not merged " +
			"silently into an empty property set")
	}
	if len(props) != 0 {
		t.Errorf("a cyclic allOf produced %d properties; expected none", len(props))
	}
	if _, _, ok := s.deref(map[string]any{"$ref": "#/components/schemas/DoesNotExist"}); ok {
		t.Error("deref resolved a $ref to a schema that does not exist")
	}
}

// TestTheWalkerNamesTheCauseItObserved.
//
// R3 round 1 found the diagnostic printing "the document describes this as a
// leaf" for a oneOf, an over-deep $ref chain and a broken $ref alike - three
// causes it had never looked at. Round 2 then found FOUR MORE shapes reaching
// the same silent arm: a oneOf hidden one level down inside an allOf, an
// unresolvable $ref inside an allOf (reported as a FIELD mismatch), the tuple
// form of `items`, and a node declaring both `items` and `properties`.
//
// A guard is only as wide as the syntax it matches, and each of these is one
// syntactic level below where the previous fix was applied. Each is pinned to
// the exact words the walker must say, so a future arm that quietly widens back
// into "it is a leaf" fails here.
func TestTheWalkerNamesTheCauseItObserved(t *testing.T) {
	s := loadPlanted(t)
	for _, tc := range []struct{ schema, want string }{
		{"PlantedCyclicItems", "`items` chain is cyclic"},
		{"PlantedTupleItems", "the tuple form"},
		{"PlantedItemsAndProperties", "both `items` and `properties`"},
		{"PlantedBrokenAllOf", "$ref this walker cannot resolve"},
		{"PlantedHiddenOneOf", "allOf members is composed with oneOf"},
		{"PlantedCyclicA", "allOf cycle"},
	} {
		shape := s.shapeOf(map[string]any{"$ref": schemaRefPrefix + tc.schema}, visited{})
		if shape.unreadable == "" {
			t.Errorf("%s was classified silently (object=%v list=%v); it must be reported with the "+
				"cause the walker observed", tc.schema, shape.object, shape.list)
			continue
		}
		if !strings.Contains(shape.unreadable, tc.want) {
			t.Errorf("%s was reported as %q; the diagnostic must contain %q - naming a cause it did "+
				"not observe is what round 1 found", tc.schema, shape.unreadable, tc.want)
		}
	}

	// ANTI-VACUITY: a shapeOf that returned "unreadable" for EVERYTHING would
	// satisfy every case above. A sound node must still classify cleanly.
	sound := s.shapeOf(map[string]any{"$ref": schemaRefPrefix + "PlantedNested"}, visited{})
	if sound.unreadable != "" || !sound.object {
		t.Errorf("a sound schema was reported as unreadable (%q); the arm above cannot be told apart "+
			"from a walker that reports everything", sound.unreadable)
	}
}

// TestThePlantedControlWouldPassIfTheWalkerWereBlind pins the control itself.
//
// A control that plants defects proves the walker fires; it does not prove the
// walker fires FOR THE REASON CLAIMED. This one removes the defect and asserts
// the finding disappears - the same edit in reverse - so a walker that reported
// `nested.dropped` for any reason other than its absence from the document
// fails here.
func TestThePlantedControlWouldPassIfTheWalkerWereBlind(t *testing.T) {
	s := loadPlanted(t)
	nested := s["PlantedNested"]
	props := nested["properties"].(map[string]any)
	props["dropped"] = map[string]any{"type": "string"}

	reached := map[string]bool{}
	var findings []finding
	compareSchemaToType(s, "PlantedNested", nested, reflect.TypeOf(plantedNested{}), "repaired", reached, &findings)
	for _, f := range findings {
		t.Errorf("with `dropped` declared, the walker still reported %s; it is not keying on the "+
			"document's property set", f)
	}
	if len(reached) != 1 {
		t.Fatalf("the repaired walk visited %d pairs, expected 1; it is not comparing what this test "+
			"claims it compares", len(reached))
	}
}

// TestEveryDeclaredFindingKindIsRegistered is the STATIC half, and the reason
// the dynamic half alone was not enough.
//
// R3 round 2 killed the previous claim. newFinding's panic fires only if the
// emission path RUNS during a test - so a new kind with an emission arm that
// neither published document nor the planted one reaches is invisible to the
// panic AND to the control that ranges over allFindingKinds. Proven: a
// `kindTypeWidth` const with a live emission site on a condition no document
// hits left all five parity tests green.
//
// This reads THIS FILE's source and requires every `findingKind` constant
// declared in it to appear in allFindingKinds. That is a claim about the
// declarations rather than about what happened to execute, so a kind cannot be
// declared without being registered, and - by the control - cannot be
// registered without a planted instance. The two halves together are what the
// previous version claimed on its own.
func TestEveryDeclaredFindingKindIsRegistered(t *testing.T) {
	src, err := os.ReadFile("openapi_schema_parity_test.go")
	if err != nil {
		t.Fatalf("read this file's own source: %v", err)
	}
	// `\tkindSomething findingKind = "..."` - the only shape a kind constant
	// is declared in. A declaration written another way would not be found,
	// which is why the count floor below is here.
	re := regexp.MustCompile(`(?m)^\s*(kind[A-Za-z0-9_]*)\s+findingKind\s*=\s*"([^"]+)"`)
	declared := re.FindAllStringSubmatch(string(src), -1)
	if len(declared) < len(allFindingKinds) {
		t.Fatalf("the source scan found %d findingKind declarations and allFindingKinds holds %d; the "+
			"scan is not reading the declarations it claims to read", len(declared), len(allFindingKinds))
	}
	registered := map[findingKind]bool{}
	for _, k := range allFindingKinds {
		registered[k] = true
	}
	for _, m := range declared {
		if !registered[findingKind(m[2])] {
			t.Errorf("%s (%q) is declared as a findingKind and is NOT in allFindingKinds. Nothing then "+
				"requires a planted instance for it, and newFinding's panic only fires if its emission "+
				"site happens to run - so it would ship untested.", m[1], m[2])
		}
	}
	if len(declared) != len(allFindingKinds) {
		t.Errorf("%d findingKind constants are declared and allFindingKinds holds %d; the registry must "+
			"be the whole set, not a subset", len(declared), len(allFindingKinds))
	}
}

// TestAnUnregisteredFindingKindPanics pins the registry half of the mechanism.
//
// newFinding's panic is what makes "every kind has a planted instance" a claim
// about the walker rather than about a list somebody maintains. A panic nothing
// exercises is a panic nobody knows still works.
func TestAnUnregisteredFindingKindPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("newFinding accepted an unregistered kind; a new defect class could then ship " +
				"with no planted instance and the control would still pass")
		}
		if !strings.Contains(fmt.Sprint(r), "allFindingKinds") {
			t.Errorf("the panic does not name the registry to add the kind to: %v", r)
		}
	}()
	_ = newFinding(findingKind("not-registered"), "nowhere", "unused")
}
