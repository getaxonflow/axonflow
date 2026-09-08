// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Command authzen-codegen reduces the canonical decision-contract schema to the
// language-neutral AuthZEN surface artifact that every AxonFlow SDK generates
// its wire types from.
//
// # Why an intermediate artifact rather than five schema readers
//
// The compatibility plan requires SDK types to be GENERATED from the canonical
// schema and never hand-transcribed, in five languages. Pointing five
// independently written generators at a JSON Schema document would mean five
// implementations of $ref resolution, allOf flattening and the required/optional
// rule - and five places for that logic to disagree. The disagreement would not
// look like a bug; it would look like one SDK marking a field optional that the
// others mark required, which is the same-name field-shape drift the contract
// guards exist to catch, reintroduced by the tool meant to prevent it.
//
// So the schema is reduced ONCE, here, into a flat artifact with every reference
// resolved to a named type and every field's optionality already decided. An SDK
// emitter is then a straightforward walk over types and fields, which is a thing
// four more repositories can each implement correctly.
//
// # What this command guarantees about its output
//
// The artifact is CANONICAL: byte-identical for byte-identical input. Field
// order follows the schema's declaration order rather than map iteration order,
// type order is sorted, and every literal is emitted through encoding/json
// rather than assembled by string concatenation. Regeneration is therefore a
// diff, which is what lets CI assert that the committed artifact is the one the
// current schema produces.
//
// # What it deliberately does NOT do
//
// It does not emit any language's types. The Go emitter lives in the Go SDK, the
// Python emitter in the Python SDK, and so on, each reading this artifact. That
// split is what lets every repository's CI regenerate and diff on its own,
// without a private repository in its dependency path.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
)

// ArtifactName identifies the artifact so a consumer that is handed the wrong
// file says so instead of generating from it.
const ArtifactName = "axonflow-authzen-surface"

// ArtifactVersion is the artifact FORMAT version, distinct from both the
// contract schema version and the AuthZEN profile version. It changes when the
// shape of this document changes, which is what an SDK emitter parses.
const ArtifactVersion = 1

// Surface is the language-neutral artifact.
type Surface struct {
	Artifact        string `json:"artifact"`
	ArtifactVersion int    `json:"artifact_version"`
	// Profile is the AuthZEN profile a PEP negotiates. It is read from the Go
	// constant rather than from the schema so the artifact cannot record a
	// version no build emits.
	Profile string `json:"profile"`
	// ProfileHeader is the request header the profile is negotiated with, and
	// Route is the one route the surface is served on. Both come from the Go
	// constants the agent serves, so an SDK generates the path and header it
	// calls rather than transcribing them (#3603: five hand-written copies).
	ProfileHeader string `json:"profile_header"`
	Route         Route  `json:"route"`
	// ContractSchemaVersion is the version of the contract the surface was
	// reduced from.
	ContractSchemaVersion string `json:"contract_schema_version"`
	SourceSchemaID        string `json:"source_schema_id"`
	// SourceSchemaSHA256 pins the exact document this artifact was reduced
	// from. A vendored copy in an SDK repository carries it forward, so a
	// consumer can state which schema its types correspond to rather than
	// assuming the latest.
	SourceSchemaSHA256 string `json:"source_schema_sha256"`
	Enums              []Enum `json:"enums"`
	Types              []Type `json:"types"`
}

// Route is the HTTP method and path of the surface's single route.
type Route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Enum is a closed set of string values.
type Enum struct {
	Name   string   `json:"name"`
	Doc    string   `json:"doc,omitempty"`
	Values []string `json:"values"`
}

// Type is one object shape.
type Type struct {
	Name   string  `json:"name"`
	Doc    string  `json:"doc,omitempty"`
	Fields []Field `json:"fields"`
	// ExactlyOneOf names field groups of which exactly one member may be
	// present. It carries the envelope's rule, which no per-field flag can
	// express, and which an emitter needs in order to generate a validator
	// rather than a struct that silently accepts both.
	ExactlyOneOf [][]string `json:"exactly_one_of,omitempty"`
}

// Field is one member of a type.
type Field struct {
	Name string `json:"name"`
	Doc  string `json:"doc,omitempty"`
	// Required means the server emits it unconditionally and a client must
	// send it. It is decided once, here, so no emitter re-derives it.
	Required  bool    `json:"required"`
	Type      TypeRef `json:"type"`
	MinItems  int     `json:"min_items,omitempty"`
	MinLength int     `json:"min_length,omitempty"`
	// RequiresMembers are members the REFERENCED type leaves optional but this
	// position makes mandatory. The singular envelope member is the case: a
	// plural entry may inherit a subject from the shared base, a singular one
	// has nothing to inherit from. Without this an emitter would generate a
	// validator that accepts a singular evaluation with no action, which the
	// server refuses.
	RequiresMembers []string `json:"requires_members,omitempty"`
	Const           string   `json:"const,omitempty"`
}

// TypeRef is a field's type. Kind is one of: string, bool, int, object, map,
// array, ref, enum.
type TypeRef struct {
	Kind  string   `json:"kind"`
	Ref   string   `json:"ref,omitempty"`
	Enum  string   `json:"enum,omitempty"`
	Items *TypeRef `json:"items,omitempty"`
	// Value is the value type of a map. An object whose additionalProperties
	// declare a schema is a typed map, not an opaque one, and reducing it to
	// `object` would widen a map<string,string> into a map<string,any> - the
	// SDKs would then accept values the server refuses.
	Value *TypeRef `json:"value,omitempty"`
}

func main() {
	var (
		out   = flag.String("out", "", "path to write the artifact to (default: stdout)")
		check = flag.Bool("check", false, "exit non-zero if -out is missing or differs from the generated artifact")
	)
	flag.Parse()

	raw, err := contract.SchemaDocument()
	if err != nil {
		fatalf("reading the canonical schema: %v", err)
	}
	surface, err := reduce(raw)
	if err != nil {
		fatalf("%v", err)
	}
	// Two-space indent and a trailing newline, so the artifact is reviewable in
	// a diff rather than being one line.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// The artifact carries no user text, but escaping HTML would still rewrite
	// a description containing < or & into <, making the output depend on
	// prose rather than on shape.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(surface); err != nil {
		fatalf("encoding the artifact: %v", err)
	}

	if *out == "" {
		if *check {
			fatalf("-check requires -out")
		}
		// The write is checked rather than ignored: this branch is how a
		// caller pipes the artifact somewhere, and a short write down a closed
		// pipe would otherwise exit 0 having emitted a truncated document that
		// the consumer then generates from.
		if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
			fatalf("writing the artifact to stdout: %v", err)
		}
		return
	}
	if *check {
		have, err := os.ReadFile(*out)
		if err != nil {
			fatalf("-check: reading %s: %v", *out, err)
		}
		if !bytes.Equal(have, buf.Bytes()) {
			fatalf("-check: %s is not what the current schema generates.\n"+
				"Regenerate it in the same change:\n"+
				"  go run ./cmd/authzen-codegen -out %s", *out, *out)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatalf("creating the output directory: %v", err)
	}
	if err := os.WriteFile(*out, buf.Bytes(), 0o644); err != nil {
		fatalf("writing %s: %v", *out, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "authzen-codegen: "+format+"\n", args...)
	os.Exit(1)
}

// surfaceRoots are the definitions the AuthZEN surface is the transitive
// closure of.
//
// The closure is computed rather than listed so a definition that becomes
// reachable through a new $ref is picked up automatically. Listing the whole
// set by hand is how a generator ends up one type short of the shape it
// describes.
var surfaceRoots = []string{"authzen_envelope", "authzen_response", "authzen_error"}

func reduce(rawSchema []byte) (*Surface, error) {
	var doc struct {
		ID   string                     `json:"$id"`
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(rawSchema, &doc); err != nil {
		return nil, fmt.Errorf("parsing the schema: %w", err)
	}

	sum := sha256.Sum256(rawSchema)
	s := &Surface{
		Artifact:              ArtifactName,
		ArtifactVersion:       ArtifactVersion,
		Profile:               string(contract.AuthZENProfileV1),
		ProfileHeader:         contract.AuthZENProfileHeader,
		Route:                 Route{Method: contract.AuthZENRouteMethod, Path: contract.AuthZENRoutePath},
		ContractSchemaVersion: contract.SchemaVersion,
		SourceSchemaID:        doc.ID,
		SourceSchemaSHA256:    "sha256:" + hex.EncodeToString(sum[:]),
	}

	r := &reducer{defs: doc.Defs, enums: map[string]Enum{}, seen: map[string]bool{}}
	queue := append([]string(nil), surfaceRoots...)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if r.seen[name] {
			continue
		}
		r.seen[name] = true
		t, refs, err := r.reduceType(name)
		if err != nil {
			return nil, err
		}
		s.Types = append(s.Types, *t)
		queue = append(queue, refs...)
	}

	// Types sorted by name and enums sorted by name: the queue order depends on
	// traversal, and traversal order is not a property of the contract.
	sort.Slice(s.Types, func(i, j int) bool { return s.Types[i].Name < s.Types[j].Name })
	for _, e := range r.enums {
		s.Enums = append(s.Enums, e)
	}
	sort.Slice(s.Enums, func(i, j int) bool { return s.Enums[i].Name < s.Enums[j].Name })

	if len(s.Types) == 0 {
		return nil, fmt.Errorf("the reduction produced no types; an empty artifact would generate an empty SDK surface")
	}
	return s, nil
}

type reducer struct {
	defs  map[string]json.RawMessage
	enums map[string]Enum
	seen  map[string]bool
}

// schemaNode is the subset of JSON Schema this reducer understands. Anything it
// does not understand is an error rather than a silent omission: a construct
// dropped here becomes a field the SDKs never learn about.
type schemaNode struct {
	Type                 json.RawMessage            `json:"type"`
	Ref                  string                     `json:"$ref"`
	Description          string                     `json:"description"`
	Properties           map[string]json.RawMessage `json:"properties"`
	Required             []string                   `json:"required"`
	AdditionalProperties json.RawMessage            `json:"additionalProperties"`
	Items                json.RawMessage            `json:"items"`
	Enum                 []string                   `json:"enum"`
	Const                *string                    `json:"const"`
	MinItems             int                        `json:"minItems"`
	MinLength            int                        `json:"minLength"`
	AllOf                []json.RawMessage          `json:"allOf"`
	OneOf                []json.RawMessage          `json:"oneOf"`
}

func (r *reducer) reduceType(name string) (*Type, []string, error) {
	rawDef, ok := r.defs[name]
	if !ok {
		return nil, nil, fmt.Errorf("the schema declares no definition %q", name)
	}
	var node schemaNode
	if err := json.Unmarshal(rawDef, &node); err != nil {
		return nil, nil, fmt.Errorf("parsing definition %q: %w", name, err)
	}
	if len(node.Properties) == 0 {
		return nil, nil, fmt.Errorf("definition %q declares no properties", name)
	}

	t := &Type{Name: name, Doc: node.Description}
	required := map[string]bool{}
	for _, req := range node.Required {
		required[req] = true
	}

	var refs []string
	// Declaration order, not map order: generated structs should read like the
	// schema, and map iteration would reorder them on every run.
	order, err := propertyOrder(rawDef)
	if err != nil {
		return nil, nil, fmt.Errorf("definition %q: %w", name, err)
	}
	for _, prop := range order {
		var pn schemaNode
		if err := json.Unmarshal(node.Properties[prop], &pn); err != nil {
			return nil, nil, fmt.Errorf("parsing %s/%s: %w", name, prop, err)
		}
		f := Field{
			Name:      prop,
			Doc:       pn.Description,
			Required:  required[prop],
			MinItems:  pn.MinItems,
			MinLength: pn.MinLength,
		}
		if pn.Const != nil {
			f.Const = *pn.Const
		}
		// allOf at a property position is the "reference plus extra required
		// members" construct the singular envelope member uses.
		if len(pn.AllOf) > 0 {
			ref, extra, err := reduceAllOf(pn.AllOf)
			if err != nil {
				return nil, nil, fmt.Errorf("%s/%s: %w", name, prop, err)
			}
			f.Type = TypeRef{Kind: "ref", Ref: ref}
			f.RequiresMembers = extra
			refs = append(refs, ref)
			t.Fields = append(t.Fields, f)
			continue
		}
		tr, sub, err := r.reduceRef(name+"/"+prop, pn)
		if err != nil {
			return nil, nil, err
		}
		f.Type = tr
		refs = append(refs, sub...)
		t.Fields = append(t.Fields, f)
	}

	// oneOf carrying required/not pairs is the envelope's exactly-one rule.
	if len(node.OneOf) > 0 {
		group, err := reduceExactlyOneOf(node.OneOf)
		if err != nil {
			return nil, nil, fmt.Errorf("definition %q: %w", name, err)
		}
		t.ExactlyOneOf = append(t.ExactlyOneOf, group)
	}
	return t, refs, nil
}

func (r *reducer) reduceRef(where string, pn schemaNode) (TypeRef, []string, error) {
	if pn.Ref != "" {
		ref := strings.TrimPrefix(pn.Ref, "#/$defs/")
		if ref == pn.Ref {
			return TypeRef{}, nil, fmt.Errorf("%s: unsupported reference %q", where, pn.Ref)
		}
		return TypeRef{Kind: "ref", Ref: ref}, []string{ref}, nil
	}
	if len(pn.Enum) > 0 {
		enumName := enumNameFor(where)
		r.enums[enumName] = Enum{Name: enumName, Values: append([]string(nil), pn.Enum...)}
		return TypeRef{Kind: "enum", Enum: enumName}, nil, nil
	}
	var kind string
	if len(pn.Type) > 0 {
		if err := json.Unmarshal(pn.Type, &kind); err != nil {
			return TypeRef{}, nil, fmt.Errorf("%s: a union `type` is not supported", where)
		}
	}
	switch kind {
	case "string":
		return TypeRef{Kind: "string"}, nil, nil
	case "boolean":
		return TypeRef{Kind: "bool"}, nil, nil
	case "integer":
		return TypeRef{Kind: "int"}, nil, nil
	case "object":
		// additionalProperties carrying a SCHEMA makes this a typed map. The
		// distinction is load-bearing: obligation.params is a map of string to
		// STRING, and reducing it to an opaque object would let every generated
		// SDK accept values the server refuses.
		if len(pn.AdditionalProperties) > 0 && strings.TrimSpace(string(pn.AdditionalProperties)) != "true" {
			if strings.TrimSpace(string(pn.AdditionalProperties)) == "false" {
				return TypeRef{}, nil, fmt.Errorf("%s: an object with additionalProperties:false and no properties describes only the empty object", where)
			}
			var vn schemaNode
			if err := json.Unmarshal(pn.AdditionalProperties, &vn); err != nil {
				return TypeRef{}, nil, fmt.Errorf("%s additionalProperties: %w", where, err)
			}
			val, sub, err := r.reduceRef(where+"{}", vn)
			if err != nil {
				return TypeRef{}, nil, err
			}
			return TypeRef{Kind: "map", Value: &val}, sub, nil
		}
		// No additionalProperties schema: an opaque JSON object. AuthZEN defines
		// subject/action/resource `properties` and the request `context` that
		// way on purpose, so this is a real shape rather than an
		// under-specified one.
		return TypeRef{Kind: "object"}, nil, nil
	case "array":
		if len(pn.Items) == 0 {
			return TypeRef{}, nil, fmt.Errorf("%s: an array with no items schema", where)
		}
		var items schemaNode
		if err := json.Unmarshal(pn.Items, &items); err != nil {
			return TypeRef{}, nil, fmt.Errorf("%s items: %w", where, err)
		}
		inner, sub, err := r.reduceRef(where+"[]", items)
		if err != nil {
			return TypeRef{}, nil, err
		}
		return TypeRef{Kind: "array", Items: &inner}, sub, nil
	case "":
		if pn.Const != nil {
			return TypeRef{Kind: "string"}, nil, nil
		}
		return TypeRef{}, nil, fmt.Errorf("%s: no type, no $ref, no enum and no const; "+
			"an unrecognised construct would become a field the SDKs never learn about", where)
	default:
		return TypeRef{}, nil, fmt.Errorf("%s: unsupported type %q", where, kind)
	}
}

// reduceAllOf reads the "$ref plus an extra required list" construct.
func reduceAllOf(parts []json.RawMessage) (string, []string, error) {
	var ref string
	var extra []string
	for _, p := range parts {
		var n schemaNode
		if err := json.Unmarshal(p, &n); err != nil {
			return "", nil, err
		}
		switch {
		case n.Ref != "":
			if ref != "" {
				return "", nil, fmt.Errorf("an allOf with two references is not supported")
			}
			ref = strings.TrimPrefix(n.Ref, "#/$defs/")
		case len(n.Required) > 0:
			extra = append(extra, n.Required...)
		default:
			return "", nil, fmt.Errorf("an allOf member that is neither a reference nor a required list is not supported")
		}
	}
	if ref == "" {
		return "", nil, fmt.Errorf("an allOf with no reference is not supported")
	}
	sort.Strings(extra)
	return ref, extra, nil
}

// reduceExactlyOneOf reads the envelope's oneOf into the field group it means.
//
// It insists on the `{required: [x], not: {required: [y]}}` shape rather than
// accepting any oneOf, because a oneOf this function did not understand would
// otherwise reduce to an empty group and the emitters would generate a type
// with no exactly-one rule at all - accepting both members, which is the
// malformed request the rule exists to refuse.
func reduceExactlyOneOf(parts []json.RawMessage) ([]string, error) {
	var members []string
	for _, p := range parts {
		var n struct {
			Required []string `json:"required"`
			Not      *struct {
				Required []string `json:"required"`
			} `json:"not"`
		}
		if err := json.Unmarshal(p, &n); err != nil {
			return nil, err
		}
		if len(n.Required) != 1 || n.Not == nil || len(n.Not.Required) != 1 {
			return nil, fmt.Errorf("unsupported oneOf member; expected exactly-one-of pairs")
		}
		members = append(members, n.Required[0])
	}
	if len(members) < 2 {
		return nil, fmt.Errorf("an exactly-one-of group needs at least two members, got %d", len(members))
	}
	sort.Strings(members)
	return members, nil
}

// enumNameFor derives a stable enum name from the position it was declared at.
func enumNameFor(where string) string {
	parts := strings.Split(where, "/")
	last := parts[len(parts)-1]
	switch last {
	case "state":
		return "operational_state"
	case "category":
		return "category"
	case "reason":
		return "reason_code"
	case "code":
		return "authzen_error_code"
	case "type":
		if strings.Contains(where, "obligation") {
			return "obligation_type"
		}
	case "kind":
		return "identifier_kind"
	case "authority":
		return "policy_authority"
	}
	return strings.ReplaceAll(strings.TrimPrefix(where, "authzen_"), "/", "_")
}

// propertyOrder returns the property names of a definition in the order the
// document declares them.
//
// encoding/json decodes an object into a map, which has no order, so a
// generator that iterated the map would emit fields in a different order on
// every run and the "regeneration is clean" check would fail at random. The
// token stream preserves the document's order.
func propertyOrder(rawDef json.RawMessage) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(rawDef))
	// Walk to the "properties" member at the top level of this definition.
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("definition is not an object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		if key != "properties" {
			if err := skipValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		open, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if d, ok := open.(json.Delim); !ok || d != '{' {
			return nil, fmt.Errorf("properties is not an object")
		}
		var order []string
		for dec.More() {
			nameTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			name, _ := nameTok.(string)
			order = append(order, name)
			if err := skipValue(dec); err != nil {
				return nil, err
			}
		}
		return order, nil
	}
	return nil, fmt.Errorf("definition declares no properties member")
}

// skipValue consumes exactly one JSON value from the decoder.
func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	var closing json.Delim
	switch d {
	case '{':
		closing = '}'
	case '[':
		closing = ']'
	default:
		return fmt.Errorf("unexpected delimiter %v", d)
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if dd, ok := t.(json.Delim); ok {
			switch dd {
			case d:
				depth++
			case closing:
				depth--
			}
		}
	}
	return nil
}
