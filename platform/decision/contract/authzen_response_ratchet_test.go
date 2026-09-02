package contract

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The response-surface ratchet.
//
// THE GAP THIS CLOSES. Every response-side definition in the contract schema is
// a CLOSED shape - `additionalProperties: false` on authzen_response,
// authzen_response_context, obligation, approval_requirement, approval_clause,
// identifier and authzen_error - and the SDK wire types are generated from
// surface/authzen-surface.json, which is reduced from that same schema. So an
// unknown member is not a field a Policy Enforcement Point ignores; it is a
// schema validation failure on every plane that validates, and a decode failure
// in every SDK whose generated decoder is strict.
//
// The profile header is the negotiation channel that exists to make such a
// change safe: a PEP names the profile it can read, and platform/agent refuses
// an unrecognised one with 406 rather than answering in a representation the
// caller cannot interpret. The discipline that follows is "never change a
// response shape without minting a new profile constant".
//
// Nothing enforced that discipline. The existing drift tests compare the Go
// structs against the schema in both directions and pin the schema's profile
// const to AuthZENProfileV1 - so ADDING a member to authzen_response_context,
// adding the matching Go field and regenerating the artifact passes every gate
// in this repository GREEN while hard-failing every deployed PEP. The two
// artifacts and the Go type would agree with each other perfectly; agreement
// among three things that were regenerated together is not a contract.
//
// This file is the missing anchor: the LITERAL response surface of each
// response-side shape, recorded against the profile constant that shipped it. A
// literal cannot be regenerated, so the only way to change the surface is to
// change this table, and the table is keyed by the profile string - which means
// the change is only accepted once the profile constant has moved with it.
//
// WHICH AXES ARE PINNED, AND WHY ALL FOUR.
//
// A first version of this file pinned member NAMES alone. That is one dimension
// of a four-dimensional surface, and an anti-vacuity floor cannot see a missing
// dimension: with names alone, three other breaking changes regenerated cleanly
// and passed every package in this module green.
//
//   - MEMBER NAMES. An added or removed member on a closed shape.
//   - REQUIRED-NESS per member. A required member turned optional breaks any PEP
//     whose generated decoder made it non-nullable - a Rust `decision_id: String`
//     rather than `Option<String>` fails to decode the first time the server
//     omits it. An optional member turned required breaks nothing at the PEP but
//     is a promise the server must now keep.
//   - FIELD TYPE per member. `authzen_error.request_id` moved from string to
//     integer in the schema and regenerated cleanly while contract/authzen.go
//     went on declaring `RequestID string`, so the Go server and the artifact
//     every SDK generates from described different wires, and nothing noticed.
//     (Go field TYPES are compared to the schema by no test in this repository;
//     the drift suite compares names and required-ness only. Pinning the
//     artifact's type is what makes such a move visible, not a Go-side check.)
//   - ENUM VALUES, for every enumeration reachable from the response closure. A
//     new reason_code is a value a PEP validating against its pinned copy of the
//     profile refuses outright. The artifact carries the enums; the first
//     version of this file never opened that block.
//
// Nothing else about the artifact is pinned. Documentation strings, field
// ordering, min_items/min_length and the const on `profile` are deliberately out
// of scope: none of them is a member a PEP decodes, and a ratchet that fires on
// prose gets disabled within a week.
//
// WHY NOT AN EXTENSION POINT. The obvious alternative is to open the response
// context with an `extensions` bag so additive members stop being breaking at
// all. That is deliberately NOT done here. It is a WIRE change: it alters
// contract-2026-08-29.schema.json, regenerates surface/authzen-surface.json and
// forces regenerated wire types in all five SDKs, each of which has its own
// strictness posture to re-decide. It also remains fully available later - an
// extension bag is itself an additive response member, so it can be introduced
// through exactly the mechanism this file enforces, by an ordinary profile bump.
// That makes it a v11 design decision with five repositories in scope, not a
// change to make at tag time. This ratchet is the part that costs nothing on the
// wire and can ship now.
//
// WHAT IS DELIBERATELY NOT RESTATED HERE. That the schema's profile const and
// the artifact's `profile` field equal AuthZENProfileV1 is already pinned by
// TestAuthZENSchemaEnumerationsMatchTheGoDeclarations and by
// cmd/authzen-codegen's TestArtifactCoversTheWholeSurface. Restating it would
// make this ratchet fail for a reason that is not its own - specifically, it
// would fail on the very commit that correctly bumps the profile, which is the
// one commit it must let through.

// authzenSurfaceArtifact is the committed reduction of this schema that all five
// SDKs vendor and generate their wire types from.
//
// IT IS NOT AN INDEPENDENT SECOND SOURCE, and an earlier version of this comment
// claimed it was. cmd/authzen-codegen's TestCommittedArtifactIsCurrent already
// requires the committed artifact to be BYTE-IDENTICAL to what the committed
// schema generates, in the same test sweep - so "the schema and the artifact
// disagree" describes a state no commit can reach, and the two mutation
// sub-cases that exercise it are exercising an impossible input. They are kept
// because they cost nothing and they pin the comparison's direction, but the
// property that actually protects a PEP comes from the LITERAL pin below, which
// is the one input in this file that no regeneration can produce.
//
// The artifact is read here for a different and load-bearing reason: it is the
// document that already carries required-ness, field types and enum values in
// the reduced form every SDK emits from. Reading those three axes off the
// artifact rather than re-deriving them from JSON Schema means this file does
// not carry a second implementation of the reducer that could disagree with the
// real one. That the reduction is FAITHFUL is somebody else's job and is already
// done - TestCommittedArtifactIsCurrent for byte-identity and
// TestArtifactRequiredFlagsMatchTheSchema for the required flags. What is not
// done anywhere else, and is this file's whole subject, is stopping those values
// from MOVING under an unchanged profile constant.
const authzenSurfaceArtifact = "../surface/authzen-surface.json"

// authzenResponseRoots names the response documents a PEP decodes.
//
// The scope of the ratchet is DERIVED from these rather than listed: it is the
// transitive $ref closure of each root inside the schema. That is why the pin
// below covers obligation, approval_requirement, approval_clause and identifier
// as well - they are reachable from authzen_response_context, so they are
// generated into every SDK and a member added to any of them lands on the same
// wire with the same consequence. Deriving the closure rather than enumerating
// it also means a definition that BECOMES response-side later is pulled into
// scope automatically instead of being silently unguarded.
//
// authzen_error is a second root because it is not reachable from
// authzen_response - a refusal is a separate document, deliberately not a member
// of the response - and it is nonetheless a body a PEP decodes. It is included
// with one caveat stated honestly: a refusal is emitted for a caller that never
// completed negotiation (the 406 path names the supported profiles), so a
// profile bump is not a complete remedy for a change there. That makes an
// addition to authzen_error MORE dangerous than one to the response, not less,
// and the right answer is for it to be visible rather than unguarded.
func authzenResponseRoots() []Schema {
	return []Schema{SchemaAuthZENResponse, SchemaAuthZENError}
}

// pinnedMember is one member of a pinned response shape, on every axis a PEP's
// generated decoder is built from.
//
// Type is the artifact's TypeRef rendered as a string - "string", "bool", "int",
// "object", "enum:reason_code", "ref:identifier", "array<ref:obligation>",
// "map<string>". Rendering rather than embedding the nested struct keeps the
// table one line per member and keeps a diff on it readable, which is the whole
// reason a literal pin works as a review artifact.
type pinnedMember struct {
	Name     string
	Required bool
	Type     string
}

// responseSurfacePin is everything one profile promised about the response wire.
type responseSurfacePin struct {
	// Members is the member set of each response-side definition.
	Members map[Schema][]pinnedMember
	// Enums is the value set of every enumeration reachable from those
	// definitions. Values are stored SORTED and compared as a SET: the order an
	// enumeration is declared in has no meaning on the wire, and a pin that
	// fired on a reordering would be a pin somebody deletes.
	Enums map[string][]string
	// Retires names entities - a definition or an enumeration - that THIS
	// profile deliberately removed from the response wire, each with the reason.
	//
	// It exists because a correct REMOVAL was otherwise unshippable. The
	// canonical check below refuses a row that covers less than its predecessor,
	// which is what stops the ratchet narrowing silently; but a definition that
	// genuinely left the wire must be able to leave the row, and the only escape
	// left was deleting it from the historic row - which the ratchet's own
	// failure message forbids in the same breath. Declaring the retirement makes
	// the removal an explicit, reviewable line in the diff instead of an absence.
	Retires map[string]string
}

// authzenResponseSurfaceByProfile is the pin.
//
// The keys are string LITERALS on purpose. Writing AuthZENProfileV1 here would
// make the table follow the constant, and the coupling this whole file exists
// for would silently evaporate: renaming the profile would carry the old member
// sets along under the new name. A literal key means a bumped constant no longer
// resolves, which is exactly the release valve the discipline calls for.
//
// Old profiles stay in the table as history. They cost nothing and they document
// what each shipped profile promised. Rows are ordered by their date suffix, and
// the canonical check requires that suffix so that lexical order IS chronological
// order - the newer row is compared against the older one, never the reverse.
var authzenResponseSurfaceByProfile = map[AuthZENProfile]responseSurfacePin{
	"axonflow-authzen-profile-2026-08-29": {
		Members: map[Schema][]pinnedMember{
			SchemaApprovalClause: {
				{"eligible", true, "array<ref:identifier>"},
				{"quorum", true, "int"},
			},
			SchemaApproval: {
				{"all_of", true, "array<ref:approval_clause>"},
				{"expires_at", true, "string"},
				{"separation_of_duties", true, "bool"},
			},
			SchemaAuthZENError: {
				{"code", true, "enum:authzen_error_code"},
				{"message", true, "string"},
				{"pointer", false, "string"},
				{"request_id", false, "string"},
				{"supported", false, "array<string>"},
			},
			SchemaAuthZENResponse: {
				{"context", false, "ref:authzen_response_context"},
				{"decision", true, "bool"},
			},
			SchemaAuthZENResponseContext: {
				{"approval", false, "ref:approval_requirement"},
				{"category", true, "enum:category"},
				{"decision_id", true, "string"},
				{"obligations", false, "array<ref:obligation>"},
				{"profile", true, "string"},
				{"reason", false, "enum:reason_code"},
				{"schema_version", true, "string"},
				{"state", true, "enum:operational_state"},
			},
			SchemaIdentifier: {
				{"kind", true, "enum:identifier_kind"},
				{"local", true, "string"},
				{"qualifier", false, "string"},
				{"type", true, "string"},
			},
			SchemaObligation: {
				{"mandatory", true, "bool"},
				{"params", false, "map<string>"},
				{"schema_version", true, "int"},
				{"source_policy", true, "string"},
				{"target", false, "string"},
				{"type", true, "enum:obligation_type"},
			},
		},
		Enums: map[string][]string{
			"authzen_error_code": {
				"evaluation_unavailable", "incomplete_evaluation", "malformed_envelope",
				"missing_evaluable_content", "unevaluable_attribute", "unsupported_action",
				"unsupported_resource", "unsupported_subject",
			},
			"category": {
				"allowed", "approval_required", "invalid_request", "not_permitted",
				"temporarily_unavailable",
			},
			"identifier_kind": {
				"action", "client", "group", "organization", "principal", "resource",
				"session", "tool",
			},
			"obligation_type": {
				"approval_challenge", "field_annotate", "field_hash", "field_mask",
				"field_redact", "field_remove", "field_tokenize", "immutable_audit",
				"notification", "quota_reservation", "response_filter", "route_restriction",
				"schema_transform", "step_up_authentication",
			},
			"operational_state": {"ALLOW", "CHALLENGE", "DENY", "ERROR"},
			"reason_code": {
				"approval_expired", "approval_required", "approval_unsatisfiable",
				"authoring_rejected", "binding_mismatch", "budget_exhausted",
				"delegation_depth_exceeded", "evaluation_error", "explicit_constraint",
				"invalid_input", "no_matching_permission", "obligation_conflict",
				"permitted", "schema_violation", "unknown_action", "unknown_constraint",
				"unknown_permission", "unknown_realm", "unknown_requirement",
				"unsupported_obligation",
			},
		},
	},
}

// schemaConstantNames maps a definition name to the Go constant that names it.
//
// It exists so the pasteable row a failure prints reads like the rows already in
// the table - SchemaApprovalClause rather than Schema("approval_clause"). A
// remediation whose output does not match its neighbours is a remediation
// somebody edits by hand after pasting, and a pin transcribed by hand is a pin
// that can be transcribed wrong. The mapping cannot be derived by convention:
// approval_requirement is SchemaApproval, not SchemaApprovalRequirement.
//
// TestPinnedResponseSurfacesAreCanonical asserts it covers everything the
// response closure reaches, so a definition that enters the wire cannot quietly
// fall back to the raw-string form.
var schemaConstantNames = map[Schema]string{
	SchemaRequest:                "SchemaRequest",
	SchemaDecision:               "SchemaDecision",
	SchemaObligation:             "SchemaObligation",
	SchemaTrace:                  "SchemaTrace",
	SchemaAttribute:              "SchemaAttribute",
	SchemaApproval:               "SchemaApproval",
	SchemaApprovalClause:         "SchemaApprovalClause",
	SchemaIdentifier:             "SchemaIdentifier",
	SchemaAuthZENEnvelope:        "SchemaAuthZENEnvelope",
	SchemaAuthZENRequest:         "SchemaAuthZENRequest",
	SchemaAuthZENBulk:            "SchemaAuthZENBulk",
	SchemaAuthZENSubject:         "SchemaAuthZENSubject",
	SchemaAuthZENAction:          "SchemaAuthZENAction",
	SchemaAuthZENResource:        "SchemaAuthZENResource",
	SchemaAuthZENResponse:        "SchemaAuthZENResponse",
	SchemaAuthZENError:           "SchemaAuthZENError",
	SchemaAuthZENResponseContext: "SchemaAuthZENResponseContext",
}

// responseSurfaceReport is what one evaluation of the ratchet produced.
type responseSurfaceReport struct {
	// Pinned reports whether a literal surface existed for the profile that was
	// checked. False means the profile constant has moved ahead of the table.
	// TestTheCurrentProfileIsPinned refuses that state on the shipped profile;
	// see the note there before reading this as a hole.
	Pinned bool
	// Closure is the derived response-side definition set, sorted.
	Closure []Schema
	// Observed is the member set, with required-ness and type, that each closure
	// definition carries in the artifact, sorted by member name.
	Observed map[Schema][]pinnedMember
	// ObservedEnums is the value set of each enumeration the closure reaches.
	ObservedEnums map[string][]string
	// Findings are violations. Each one is a test failure.
	Findings []string
}

// artifactTypeRef mirrors the TypeRef the codegen emits.
type artifactTypeRef struct {
	Kind  string           `json:"kind"`
	Ref   string           `json:"ref"`
	Enum  string           `json:"enum"`
	Items *artifactTypeRef `json:"items"`
	Value *artifactTypeRef `json:"value"`
}

// renderArtifactType renders a TypeRef into the pin's one-line form.
//
// A malformed reference renders to a marker rather than to something plausible:
// an array whose items are missing must not collapse to "array" and match a pin
// that meant array-of-identifier.
func renderArtifactType(t *artifactTypeRef) string {
	if t == nil {
		return "!missing"
	}
	switch t.Kind {
	case "":
		return "!missing kind"
	case "ref":
		if t.Ref == "" {
			return "!ref with no target"
		}
		return "ref:" + t.Ref
	case "enum":
		if t.Enum == "" {
			return "!enum with no name"
		}
		return "enum:" + t.Enum
	case "array":
		return "array<" + renderArtifactType(t.Items) + ">"
	case "map":
		return "map<" + renderArtifactType(t.Value) + ">"
	default:
		return t.Kind
	}
}

// enumsReachedBy collects the enumeration names a TypeRef reaches, at any depth.
func enumsReachedBy(t *artifactTypeRef, into map[string]bool) {
	if t == nil {
		return
	}
	if t.Kind == "enum" && t.Enum != "" {
		into[t.Enum] = true
	}
	enumsReachedBy(t.Items, into)
	enumsReachedBy(t.Value, into)
}

// checkAuthZENResponseSurface is the ratchet itself, expressed over its inputs
// rather than over the embedded files.
//
// It takes the schema, the artifact and the pin table as arguments so that
// TestTheResponseSurfaceRatchetCanFail can drive it with MUTATED inputs in
// process, and so TestALegalRemovalHasAGreenPath can drive it with a synthetic
// table. A gate that has never been observed to go red is a gate nobody has
// tested, and a mutant aimed at an assertion survives by construction - so the
// mutants are aimed at the documents this function reads, which is the subject
// the assertions are about.
//
// The returned error is reserved for inputs that cannot be read at all. Those
// are fatal rather than findings: a run that parsed nothing must not be able to
// report zero violations.
func checkAuthZENResponseSurface(
	schemaDoc, artifact []byte,
	profile AuthZENProfile,
	pins map[AuthZENProfile]responseSurfacePin,
) (responseSurfaceReport, error) {
	rep := responseSurfaceReport{
		Observed:      map[Schema][]pinnedMember{},
		ObservedEnums: map[string][]string{},
	}

	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(schemaDoc, &doc); err != nil {
		return rep, fmt.Errorf("parsing the schema: %w", err)
	}
	if len(doc.Defs) == 0 {
		return rep, fmt.Errorf("the schema declares no $defs; every comparison below would be vacuous")
	}

	// The derived scope: the transitive $ref closure of every root.
	closure := map[string]bool{}
	var walk func(name string) error
	walk = func(name string) error {
		if closure[name] {
			return nil
		}
		raw, ok := doc.Defs[name]
		if !ok {
			return fmt.Errorf("the schema declares no definition %q", name)
		}
		closure[name] = true
		refs, unreadable := jsonRefsIn(raw)
		for _, bad := range unreadable {
			// Recorded, never skipped. This is the one function that decides
			// SCOPE, so a reference it could not read is a shape that silently
			// leaves the ratchet - the fail-open with the largest blast radius
			// in the file.
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"definition %q carries a reference this walk cannot read: %s. The response-side closure is "+
					"derived from these references, so an unreadable one is a shape that leaves the ratchet's "+
					"scope without anything saying so.", name, bad))
		}
		for _, ref := range refs {
			if err := walk(ref); err != nil {
				return err
			}
		}
		return nil
	}
	for _, root := range authzenResponseRoots() {
		if err := walk(string(root)); err != nil {
			return rep, err
		}
	}
	// The roots alone are not a closure. authzen_response references the response
	// context, which reaches the obligation and approval shapes a PEP acts on, so
	// a walk that followed NOTHING would leave exactly the two roots in scope -
	// and every nested response shape would drop out of the pin comparison below
	// with no message anywhere. This fires the moment jsonRefsIn stops working.
	if len(closure) <= len(authzenResponseRoots()) {
		return rep, fmt.Errorf("the derived response-side closure holds %d definitions, no more than the %d roots "+
			"it was seeded with; the $ref walk followed nothing, so every nested response shape - the obligations "+
			"and approval requirements a PEP acts on - would silently leave scope", len(closure), len(authzenResponseRoots()))
	}
	closureSet := map[Schema]bool{}
	for name := range closure {
		rep.Closure = append(rep.Closure, Schema(name))
		closureSet[Schema(name)] = true
	}
	sort.Slice(rep.Closure, func(i, j int) bool { return rep.Closure[i] < rep.Closure[j] })

	// The member set each definition declares, plus the premise the ratchet
	// rests on: these shapes are CLOSED. A definition that stopped being closed
	// would make an added member harmless at the PEP and this pin pointless, so
	// the premise is asserted rather than assumed.
	declared := map[Schema]bool{}
	for _, s := range AllSchemas() {
		declared[s] = true
	}
	schemaMembers := map[Schema][]string{}
	totalMembers := 0
	for _, s := range rep.Closure {
		var def struct {
			Properties           map[string]json.RawMessage `json:"properties"`
			AdditionalProperties json.RawMessage            `json:"additionalProperties"`
		}
		if err := json.Unmarshal(doc.Defs[string(s)], &def); err != nil {
			return rep, fmt.Errorf("parsing definition %q: %w", s, err)
		}
		if len(def.Properties) == 0 {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"definition %q declares no properties; a response shape with no members is not a contract and "+
					"would make the pin for it vacuous", s))
			continue
		}
		if strings.TrimSpace(string(def.AdditionalProperties)) != "false" {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"definition %q sets additionalProperties to %q rather than false; this ratchet exists because a "+
					"response shape is CLOSED, and an open one changes what an added member costs a PEP",
				s, strings.TrimSpace(string(def.AdditionalProperties))))
		}
		if !declared[s] {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"the response-side closure reaches %q, which AllSchemas does not declare; it is on the wire but "+
					"no compiled validator covers it", s))
		}
		members := make([]string, 0, len(def.Properties))
		for name := range def.Properties {
			members = append(members, name)
		}
		sort.Strings(members)
		schemaMembers[s] = members
		totalMembers += len(members)
	}
	if totalMembers == 0 {
		return rep, fmt.Errorf("the response-side closure declares no members at all across %d definitions; "+
			"the comparison below would be vacuous", len(rep.Closure))
	}

	// The artifact. It is what the five SDKs actually generate from, and it is
	// where required-ness, field types and enum values are read from: those three
	// axes already exist in it in the reduced form an emitter consumes, so
	// re-deriving them from JSON Schema here would mean a second implementation
	// of cmd/authzen-codegen's reducer, free to disagree with the real one.
	var surface struct {
		Enums []struct {
			Name   string   `json:"name"`
			Values []string `json:"values"`
		} `json:"enums"`
		Types []struct {
			Name   string `json:"name"`
			Fields []struct {
				Name     string           `json:"name"`
				Required bool             `json:"required"`
				Type     *artifactTypeRef `json:"type"`
			} `json:"fields"`
		} `json:"types"`
	}
	if err := json.Unmarshal(artifact, &surface); err != nil {
		return rep, fmt.Errorf("parsing %s: %w", authzenSurfaceArtifact, err)
	}
	if len(surface.Types) == 0 {
		return rep, fmt.Errorf("%s describes no types; the second source would contribute nothing", authzenSurfaceArtifact)
	}
	artifactMembers := map[string][]pinnedMember{}
	artifactFieldTypes := map[string]map[string]*artifactTypeRef{}
	for _, tp := range surface.Types {
		ms := make([]pinnedMember, 0, len(tp.Fields))
		refs := map[string]*artifactTypeRef{}
		for _, f := range tp.Fields {
			ms = append(ms, pinnedMember{Name: f.Name, Required: f.Required, Type: renderArtifactType(f.Type)})
			refs[f.Name] = f.Type
		}
		sort.Slice(ms, func(i, j int) bool { return ms[i].Name < ms[j].Name })
		artifactMembers[tp.Name] = ms
		artifactFieldTypes[tp.Name] = refs
	}
	artifactEnums := map[string][]string{}
	for _, e := range surface.Enums {
		vs := append([]string(nil), e.Values...)
		sort.Strings(vs)
		artifactEnums[e.Name] = vs
	}

	for _, s := range rep.Closure {
		observed, ok := schemaMembers[s]
		if !ok {
			continue // already reported as having no properties
		}
		fields, ok := artifactMembers[string(s)]
		if !ok {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"%s describes no type %q, which the schema places on the response wire; no SDK would generate it",
				authzenSurfaceArtifact, s))
			continue
		}
		if len(fields) == 0 {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"%s describes %q with no fields; the floor for that type would be zero", authzenSurfaceArtifact, s))
			continue
		}
		names := make([]string, 0, len(fields))
		for _, f := range fields {
			names = append(names, f.Name)
		}
		if diff := describeMemberDiff(observed, names); diff != "" {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"the schema and %s disagree about %q: %s.\nThe committed artifact is what every SDK generates "+
					"from, so the SDKs and this server are describing different wires. Regenerate it in the same "+
					"change:\n  (cd platform/decision && go run ./cmd/authzen-codegen -out surface/authzen-surface.json)",
				authzenSurfaceArtifact, s, diff))
		}
		rep.Observed[s] = fields
	}

	// The enumerations the response closure reaches. Scope is derived the same
	// way the definition scope is: an enum used only by a REQUEST-side shape is
	// the caller's to widen and must not be pinned here, or the ratchet would
	// claim a coverage it has no business claiming.
	reached := map[string]bool{}
	for _, s := range rep.Closure {
		// The rendered string is for the pin; reachability needs the structure,
		// so the TypeRefs are walked rather than the rendered forms.
		for _, f := range rep.Observed[s] {
			enumsReachedBy(artifactFieldTypes[string(s)][f.Name], reached)
		}
	}
	if len(reached) == 0 {
		return rep, fmt.Errorf("the response-side closure reaches no enumeration at all; state, category, reason " +
			"and the refusal code are all enumerations, so the enum axis of the pin would be silently vacuous")
	}
	reachedNames := make([]string, 0, len(reached))
	for name := range reached {
		reachedNames = append(reachedNames, name)
	}
	sort.Strings(reachedNames)
	for _, name := range reachedNames {
		values, ok := artifactEnums[name]
		if !ok {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"a response-side field is typed as enumeration %q, which %s does not declare; every SDK would "+
					"generate a reference to a type that is not in the artifact",
				name, authzenSurfaceArtifact))
			continue
		}
		if len(values) == 0 {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"%s declares enumeration %q with no values; a closed set with no members accepts nothing",
				authzenSurfaceArtifact, name))
			continue
		}
		rep.ObservedEnums[name] = values
	}

	// The pin.
	pinned, ok := pins[profile]
	if !ok {
		// The profile constant has moved ahead of the table. That is not a
		// violation HERE: minting a new profile is precisely what this ratchet
		// exists to force, and failing on it would make the checker refuse the one
		// change it exists to permit. It is refused one level up, by
		// TestTheCurrentProfileIsPinned, which requires the shipped profile to be
		// pinned - so the bump and the new row must land in the same commit.
		return rep, nil
	}
	rep.Pinned = true

	for s := range pinned.Members {
		if !closureSet[s] {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"profile %s pins a member set for %q, which is no longer reachable from any response document. "+
					"If the shape genuinely left the response wire, that is itself a breaking change for every PEP "+
					"that decodes it: mint a new profile, add a row that omits %q, and record the removal in that "+
					"row's Retires map. Deleting it from THIS row would erase what %s promised.",
				profile, s, s, profile))
		}
	}
	for _, s := range rep.Closure {
		observed, ok := rep.Observed[s]
		if !ok {
			continue
		}
		want, ok := pinned.Members[s]
		if !ok {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"%q is reachable from a response document but no member set is pinned for it under profile %s.\n%s",
				s, profile, responseSurfaceRemediation(profile, rep)))
			continue
		}
		if diff := describeSurfaceDiff(want, observed); diff != "" {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"the response surface of %q changed under an UNCHANGED profile constant %s: %s.\n%s",
				s, profile, diff, responseSurfaceRemediation(profile, rep)))
		}
	}

	for name := range pinned.Enums {
		if !reached[name] {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"profile %s pins a value set for enumeration %q, which nothing in the response closure reaches "+
					"any more. If it genuinely left the response wire, mint a new profile, omit it from the new "+
					"row and record the removal in that row's Retires map.", profile, name))
		}
	}
	for _, name := range reachedNames {
		observed, ok := rep.ObservedEnums[name]
		if !ok {
			continue // already reported as undeclared or empty
		}
		want, ok := pinned.Enums[name]
		if !ok {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"enumeration %q is reachable from a response document but no value set is pinned for it under "+
					"profile %s.\n%s", name, profile, responseSurfaceRemediation(profile, rep)))
			continue
		}
		if diff := describeMemberDiff(want, observed); diff != "" {
			rep.Findings = append(rep.Findings, fmt.Sprintf(
				"the value set of enumeration %q changed under an UNCHANGED profile constant %s: %s.\n"+
					"A PEP validating a response against its pinned copy of this profile refuses a value the "+
					"profile did not declare, so a new enum value is as breaking as a new member.\n%s",
				name, profile, diff, responseSurfaceRemediation(profile, rep)))
		}
	}
	return rep, nil
}

// responseSurfaceRemediation is the half of a failure that tells the reader what
// to do. A ratchet whose message only says "these two lists differ" gets
// satisfied by editing the list it names, which is the one repair that must not
// be made silently.
func responseSurfaceRemediation(profile AuthZENProfile, rep responseSurfaceReport) string {
	var b strings.Builder
	b.WriteString("CHANGING THE RESPONSE SURFACE IS A BREAKING CHANGE FOR EVERY DEPLOYED PEP.\n")
	b.WriteString("That covers all four axes this table pins: a member added or removed, a member that was\n")
	b.WriteString("required becoming optional, a member's TYPE changing, and a new value in any enumeration\n")
	b.WriteString("the response reaches. Every response-side definition is closed with\n")
	b.WriteString("additionalProperties:false, and the wire types in all five SDKs are generated from\n")
	b.WriteString(authzenSurfaceArtifact + " - so an unknown member is a validation failure on any plane\n")
	b.WriteString("that validates and a decode failure in every SDK whose generated decoder is strict, a\n")
	b.WriteString("required member turned optional fails to decode in every SDK that made it non-nullable,\n")
	b.WriteString("and an unknown enum value is refused by every PEP validating against its pinned profile.\n\n")
	b.WriteString("The profile header is the only negotiation channel there is: a PEP asks for a profile it can\n")
	b.WriteString("read and platform/agent refuses an unrecognised one with 406. So a changed response surface\n")
	b.WriteString("needs a NEW PROFILE CONSTANT. Regenerating surface/authzen-surface.json is NOT enough, and\n")
	b.WriteString("neither is updating the Go struct: those three artifacts are generated from one another and\n")
	b.WriteString("will agree with each other however wrong they are.\n\n")
	b.WriteString("To ship this change:\n")
	b.WriteString("  1. mint a new AuthZENProfile constant in authzen.go and emit it from Decision.ToAuthZEN;\n")
	b.WriteString("  2. update the profile const in the schema and regenerate the artifact;\n")
	b.WriteString("  3. add a row to authzenResponseSurfaceByProfile for the new profile, KEEPING " + string(profile) + "\n")
	b.WriteString("     as history;\n")
	b.WriteString("  4. if the change REMOVES a definition or an enumeration from the response wire, omit it\n")
	b.WriteString("     from the new row and name it in that row's Retires map with the reason - do not delete\n")
	b.WriteString("     it from the historic row;\n")
	b.WriteString("  5. decide what a PEP still negotiating " + string(profile) + " receives, and pin that too.\n")
	b.WriteString("If you are certain the profile must NOT move, then the change does not belong on the response.\n\n")
	b.WriteString("The response surface currently on the wire, ready to paste as a new row:\n")
	b.WriteString(responseSurfaceLiteral(rep))
	return b.String()
}

// responseSurfaceLiteral renders the observed surface as the Go literal the
// table wants, so that recording a new profile is a paste rather than a
// transcription. A pin transcribed by hand from a failure message is a pin that
// can be transcribed wrong.
func responseSurfaceLiteral(rep responseSurfaceReport) string {
	names := make([]Schema, 0, len(rep.Observed))
	for s := range rep.Observed {
		names = append(names, s)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })

	var b strings.Builder
	b.WriteString("\t\"<the new profile string>\": {\n")
	b.WriteString("\t\tMembers: map[Schema][]pinnedMember{\n")
	for _, s := range names {
		b.WriteString(fmt.Sprintf("\t\t\t%s: {\n", schemaConstantName(s)))
		for _, m := range rep.Observed[s] {
			b.WriteString(fmt.Sprintf("\t\t\t\t{%q, %t, %q},\n", m.Name, m.Required, m.Type))
		}
		b.WriteString("\t\t\t},\n")
	}
	b.WriteString("\t\t},\n")

	enumNames := make([]string, 0, len(rep.ObservedEnums))
	for name := range rep.ObservedEnums {
		enumNames = append(enumNames, name)
	}
	sort.Strings(enumNames)
	b.WriteString("\t\tEnums: map[string][]string{\n")
	for _, name := range enumNames {
		quoted := make([]string, 0, len(rep.ObservedEnums[name]))
		for _, v := range rep.ObservedEnums[name] {
			quoted = append(quoted, fmt.Sprintf("%q", v))
		}
		b.WriteString(fmt.Sprintf("\t\t\t%q: {%s},\n", name, strings.Join(quoted, ", ")))
	}
	b.WriteString("\t\t},\n")
	b.WriteString("\t},\n")
	return b.String()
}

// schemaConstantName renders the Go constant for a definition, falling back to
// the conversion form for one the map does not know.
func schemaConstantName(s Schema) string {
	if name, ok := schemaConstantNames[s]; ok {
		return name
	}
	return fmt.Sprintf("Schema(%q)", string(s))
}

// describeMemberDiff returns "" when the two sorted sets are identical, and
// otherwise names what was added and what was removed. Naming the members
// rather than counting them is deliberate: a count that happens to match hides
// a rename, which is two breaking changes at once.
func describeMemberDiff(want, got []string) string {
	in := func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	}
	var added, removed []string
	for _, g := range got {
		if !in(want, g) {
			added = append(added, g)
		}
	}
	for _, w := range want {
		if !in(got, w) {
			removed = append(removed, w)
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return ""
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, fmt.Sprintf("added %s", strings.Join(added, ", ")))
	}
	if len(removed) > 0 {
		parts = append(parts, fmt.Sprintf("removed %s", strings.Join(removed, ", ")))
	}
	return strings.Join(parts, " and ")
}

// describeSurfaceDiff names every axis on which two pinned member sets differ.
//
// A member present on both sides is compared on required-ness and on type, not
// only on its name: those are the two changes that regenerated cleanly and
// passed every gate in this module green while breaking a deployed PEP.
func describeSurfaceDiff(want, got []pinnedMember) string {
	index := func(ms []pinnedMember) map[string]pinnedMember {
		out := map[string]pinnedMember{}
		for _, m := range ms {
			out[m.Name] = m
		}
		return out
	}
	w, g := index(want), index(got)

	var names []string
	for _, m := range got {
		names = append(names, m.Name)
	}
	sort.Strings(names)

	var wantNames, gotNames []string
	for _, m := range want {
		wantNames = append(wantNames, m.Name)
	}
	gotNames = append(gotNames, names...)
	sort.Strings(wantNames)

	var parts []string
	if diff := describeMemberDiff(wantNames, gotNames); diff != "" {
		parts = append(parts, diff)
	}
	for _, name := range names {
		wm, ok := w[name]
		if !ok {
			continue
		}
		gm := g[name]
		if wm.Required != gm.Required {
			parts = append(parts, fmt.Sprintf("%s: %s -> %s", name, requiredWord(wm.Required), requiredWord(gm.Required)))
		}
		if wm.Type != gm.Type {
			parts = append(parts, fmt.Sprintf("%s: type %s -> %s", name, wm.Type, gm.Type))
		}
	}
	return strings.Join(parts, " and ")
}

// jsonRefsIn returns every "$ref" target name inside a raw JSON value, at any
// depth, plus a description of every reference it could NOT read.
//
// Walking the raw document rather than a typed shape is what lets the closure
// follow a reference wherever it appears - inside properties, items, allOf, a
// conditional subschema - without this file having to model JSON Schema.
//
// The second return value exists because this is the function that decides
// SCOPE. An earlier version silently dropped a $ref with no "/" in it and a $ref
// that was not a string, which meant a malformed reference removed a shape from
// the ratchet with nothing anywhere saying so - a fail-open in the one place it
// costs the most. Unreadable references are now reported by the caller as
// findings rather than swallowed.
func jsonRefsIn(raw json.RawMessage) (refs []string, unreadable []string) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, []string{fmt.Sprintf("the definition is not decodable JSON: %v", err)}
	}
	var walk func(any)
	walk = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			for k, child := range n {
				if k == "$ref" {
					s, ok := child.(string)
					if !ok {
						unreadable = append(unreadable, fmt.Sprintf("a $ref whose value is %T, not a string", child))
						continue
					}
					i := strings.LastIndex(s, "/")
					if i < 0 {
						unreadable = append(unreadable, fmt.Sprintf(
							"a $ref of %q, which carries no %q separator so no definition name can be read from it", s, "/"))
						continue
					}
					name := s[i+1:]
					if name == "" {
						unreadable = append(unreadable, fmt.Sprintf("a $ref of %q, which names no definition", s))
						continue
					}
					refs = append(refs, name)
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range n {
				walk(child)
			}
		}
	}
	walk(v)
	return refs, unreadable
}

// shippedResponseSurfaceInputs reads the two committed documents.
func shippedResponseSurfaceInputs(t *testing.T) (schemaDoc, artifact []byte) {
	t.Helper()
	schemaDoc, err := SchemaDocument()
	if err != nil {
		t.Fatalf("reading the embedded schema: %v", err)
	}
	// Not a skip if it is missing. A ratchet keyed on a file that may be absent
	// and that skips when it is absent is invisible exactly where it stopped
	// running.
	artifact, err = os.ReadFile(authzenSurfaceArtifact)
	if err != nil {
		t.Fatalf("reading %s: %v", authzenSurfaceArtifact, err)
	}
	return schemaDoc, artifact
}

// TestAuthZENResponseMembersArePinnedToTheProfileConstant is the ratchet.
func TestAuthZENResponseMembersArePinnedToTheProfileConstant(t *testing.T) {
	schemaDoc, artifact := shippedResponseSurfaceInputs(t)

	rep, err := checkAuthZENResponseSurface(schemaDoc, artifact, AuthZENProfileV1, authzenResponseSurfaceByProfile)
	if err != nil {
		t.Fatalf("the response surface could not be derived, so nothing below was checked: %v", err)
	}
	for _, f := range rep.Findings {
		t.Error(f)
	}

	// Anti-vacuity, stated over the shipped documents rather than over the
	// checker's own output: both roots must have been reached, and the closure
	// must actually carry members. Without this the test above would report
	// green over a schema whose response section had been emptied.
	for _, root := range authzenResponseRoots() {
		found := false
		for _, s := range rep.Closure {
			if s == root {
				found = true
			}
		}
		if !found {
			t.Fatalf("the response root %q is not in the derived closure %v; the walk read nothing", root, rep.Closure)
		}
	}
	if len(rep.Observed) < len(rep.Closure) {
		t.Fatalf("only %d of %d closure definitions yielded a member set", len(rep.Observed), len(rep.Closure))
	}
	if len(rep.ObservedEnums) == 0 {
		t.Fatal("the closure yielded no enumeration value sets; the enum axis of the pin was not exercised")
	}

	if !rep.Pinned {
		// The profile constant has moved ahead of the table. The CHECKER tolerates
		// that, because refusing here would make it fail on the one commit it
		// exists to permit - the one that correctly bumps the profile.
		//
		// IT IS NOT A HOLE IN THE SUITE, and an earlier version of this comment
		// wrongly implied it was, describing a "residual window" between the
		// commit that bumps the profile and the commit that pins it. There is no
		// such window on a merged commit: TestTheCurrentProfileIsPinned hard-fails
		// whenever AuthZENProfileV1 is absent from the table, so the bump and the
		// new row MUST land together. Read that test before relaxing this branch;
		// a maintainer who reads this as "an unpinned profile is merely logged"
		// would delete the requirement as an over-strict precondition and open the
		// hole for real.
		//
		// The notice below is reported via t.Log and nothing louder because
		// nothing louder is available without failing: `go test` buffers a passing
		// package's output, so a write to os.Stderr from here is discarded exactly
		// as a t.Log is. Measured, not assumed.
		t.Logf("\nNOTICE: no response surface is pinned for profile %s.\n"+
			"The ratchet in authzen_response_ratchet_test.go is not constraining this profile.\n"+
			"Add a row for it in the same change (TestTheCurrentProfileIsPinned requires it):\n%s\n",
			AuthZENProfileV1, responseSurfaceLiteral(rep))
	}
}

// TestTheCurrentProfileIsPinned is the requirement that closes the window the
// checker's unpinned branch would otherwise leave open.
//
// It is a test of its own rather than a line inside the mutation gate because a
// precondition buried in another test reads as that test's setup, and gets
// relaxed by whoever is debugging that test. What it asserts is a release rule:
// the commit that bumps AuthZENProfileV1 is the same commit that records what
// the new profile promises. Between them there is nothing to compare the wire
// against.
func TestTheCurrentProfileIsPinned(t *testing.T) {
	pin, ok := authzenResponseSurfaceByProfile[AuthZENProfileV1]
	if !ok {
		t.Fatalf("profile %s is not in authzenResponseSurfaceByProfile.\n"+
			"Bumping the profile constant and pinning the surface it promises are ONE change: until the row "+
			"exists, the literal comparison in this file does not run and a response member, a required flag, a "+
			"field type or an enum value can move with nothing to compare it against.\n"+
			"Run TestAuthZENResponseMembersArePinnedToTheProfileConstant with -v; it prints the row to paste.",
			AuthZENProfileV1)
	}
	if len(pin.Members) == 0 || len(pin.Enums) == 0 {
		t.Fatalf("profile %s is in the table but pins %d definitions and %d enumerations; a row that pins "+
			"nothing satisfies the lookup above while constraining nothing",
			AuthZENProfileV1, len(pin.Members), len(pin.Enums))
	}
}

// profileNamePattern is the shape every profile string in the table must have.
//
// It is required so that LEXICAL order over the table's keys IS chronological
// order, which is what lets the canonical check below compare each row against
// its predecessor. A row keyed with a name that sorted out of order would be
// read as an ancestor of the rows that actually precede it, and the
// scope-narrowing rule would then run backwards.
var profileNamePattern = regexp.MustCompile(`^axonflow-authzen-profile-\d{4}-\d{2}-\d{2}$`)

// checkPinnedSurfaceTables is the table's own invariants, expressed over the
// table so a synthetic one can be driven through them.
func checkPinnedSurfaceTables(pins map[AuthZENProfile]responseSurfacePin) []string {
	var findings []string
	if len(pins) == 0 {
		return []string{"the pin table is empty; the ratchet would constrain nothing"}
	}

	profiles := make([]AuthZENProfile, 0, len(pins))
	for p := range pins {
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i] < profiles[j] })

	sortedNonEmpty := func(what string, xs []string) {
		if len(xs) == 0 {
			findings = append(findings, fmt.Sprintf("%s: the set is empty", what))
			return
		}
		seen := map[string]bool{}
		for i, x := range xs {
			if x == "" {
				findings = append(findings, fmt.Sprintf("%s: entry %d is empty", what, i))
			}
			if seen[x] {
				findings = append(findings, fmt.Sprintf("%s: %q is listed twice", what, x))
			}
			seen[x] = true
			if i > 0 && xs[i-1] >= x {
				findings = append(findings, fmt.Sprintf(
					"%s: entries are not sorted (%q before %q); a pin that can be reordered is a pin two "+
						"reviewers read differently", what, xs[i-1], x))
			}
		}
	}

	var prevScope []string
	var prevProfile AuthZENProfile
	for _, p := range profiles {
		pin := pins[p]
		if !profileNamePattern.MatchString(string(p)) {
			findings = append(findings, fmt.Sprintf(
				"profile key %q does not match %s; the table is ordered lexically and that is only chronological "+
					"while every key carries its date", p, profileNamePattern))
		}
		if len(pin.Members) == 0 {
			findings = append(findings, fmt.Sprintf("profile %s pins no definitions", p))
		}
		if len(pin.Enums) == 0 {
			findings = append(findings, fmt.Sprintf("profile %s pins no enumerations", p))
		}

		var scope []string
		for s, members := range pin.Members {
			scope = append(scope, string(s))
			what := fmt.Sprintf("profile %s, definition %q", p, s)
			if len(members) == 0 {
				findings = append(findings, what+": no members")
				continue
			}
			var names []string
			for _, m := range members {
				names = append(names, m.Name)
				if strings.TrimSpace(m.Type) == "" {
					findings = append(findings, fmt.Sprintf("%s, member %q: no type is pinned; the type axis "+
						"would be vacuous for it", what, m.Name))
				}
				if strings.HasPrefix(m.Type, "!") {
					findings = append(findings, fmt.Sprintf("%s, member %q: the pinned type %q is a rendering "+
						"marker, not a type; it was pasted from an artifact the renderer could not read",
						what, m.Name, m.Type))
				}
			}
			sortedNonEmpty(what, names)
		}
		for name, values := range pin.Enums {
			scope = append(scope, name)
			sortedNonEmpty(fmt.Sprintf("profile %s, enumeration %q", p, name), values)
		}
		sort.Strings(scope)

		seenScope := map[string]bool{}
		for _, name := range scope {
			if seenScope[name] {
				findings = append(findings, fmt.Sprintf(
					"profile %s pins %q both as a definition and as an enumeration; the retirement rule keys on "+
						"the name, so it could not tell which one left the wire", p, name))
			}
			seenScope[name] = true
		}

		for name, reason := range pin.Retires {
			if strings.TrimSpace(reason) == "" {
				findings = append(findings, fmt.Sprintf(
					"profile %s retires %q with no reason; a removal recorded without one is an absence with a "+
						"line number, which is what the declaration exists to replace", p, name))
			}
			if seenScope[name] {
				findings = append(findings, fmt.Sprintf(
					"profile %s retires %q and also pins it; a retirement is what lets a row STOP covering "+
						"something", p, name))
			}
		}

		if prevScope == nil {
			prevScope, prevProfile = scope, p
			continue
		}
		for _, name := range prevScope {
			if seenScope[name] {
				continue
			}
			if _, retired := pin.Retires[name]; retired {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"profile %s pins %q and profile %s does not, without retiring it; a row that covers less than "+
					"its predecessor narrows the ratchet silently. If %q genuinely left the response wire, name "+
					"it in %s's Retires map with the reason.", prevProfile, name, p, name, p))
		}
		prevInScope := map[string]bool{}
		for _, name := range prevScope {
			prevInScope[name] = true
		}
		for name := range pin.Retires {
			if !prevInScope[name] {
				findings = append(findings, fmt.Sprintf(
					"profile %s retires %q, which profile %s never pinned; a retirement of something that was "+
						"never on the wire records a removal that did not happen", p, name, prevProfile))
			}
		}
		prevScope, prevProfile = scope, p
	}
	sort.Strings(findings)
	return findings
}

// TestPinnedResponseSurfacesAreCanonical keeps the table itself honest.
//
// Every row, including the historic ones the current profile no longer resolves
// to, must be sorted, deduplicated and non-empty, and no row may cover LESS than
// its predecessor without saying so. Without this a future row could quietly
// drop authzen_response_context from its scope and the ratchet would go on
// reporting green over a shape it had stopped watching.
func TestPinnedResponseSurfacesAreCanonical(t *testing.T) {
	for _, f := range checkPinnedSurfaceTables(authzenResponseSurfaceByProfile) {
		t.Error(f)
	}

	// The pasteable row must read like the rows already committed, which means
	// every definition the response wire reaches needs its Go constant name.
	schemaDoc, artifact := shippedResponseSurfaceInputs(t)
	rep, err := checkAuthZENResponseSurface(schemaDoc, artifact, AuthZENProfileV1, authzenResponseSurfaceByProfile)
	if err != nil {
		t.Fatalf("the response surface could not be derived: %v", err)
	}
	for _, s := range rep.Closure {
		if _, ok := schemaConstantNames[s]; !ok {
			t.Errorf("the response closure reaches %q, which schemaConstantNames does not name; the row this "+
				"file prints for pasting would fall back to Schema(%q) and stop matching its neighbours", s, s)
		}
	}
	for s, name := range schemaConstantNames {
		if !strings.HasPrefix(name, "Schema") {
			t.Errorf("schemaConstantNames maps %q to %q, which is not a Schema constant", s, name)
		}
	}
}

// TestALegalRemovalHasAGreenPath proves the one operation the first version of
// this ratchet made unshippable.
//
// A definition LEAVING the response surface is a legal, if drastic, change: mint
// a profile, add a row that omits it, keep the historic row. Before the Retires
// declaration existed, that change satisfied nothing - the canonical check
// demanded every row cover the same definitions, and the checker errored on a
// pinned definition that was no longer reachable, so the only way out was
// deleting the entry from the historic row, which the ratchet's own failure
// message forbids. Both halves are exercised here: the table rule, and the
// checker driven end to end over documents where the shape really did leave.
func TestALegalRemovalHasAGreenPath(t *testing.T) {
	base := responseSurfacePin{
		Members: map[Schema][]pinnedMember{
			SchemaAuthZENResponse: {{"decision", true, "bool"}},
			SchemaIdentifier:      {{"local", true, "string"}},
		},
		Enums: map[string][]string{"category": {"allowed"}},
	}

	t.Run("a declared removal is accepted", func(t *testing.T) {
		findings := checkPinnedSurfaceTables(map[AuthZENProfile]responseSurfacePin{
			"axonflow-authzen-profile-2026-08-29": base,
			"axonflow-authzen-profile-2027-01-01": {
				Members: map[Schema][]pinnedMember{
					SchemaAuthZENResponse: {{"decision", true, "bool"}},
				},
				Enums:   map[string][]string{"category": {"allowed"}},
				Retires: map[string]string{"identifier": "the approval requirement left the response wire"},
			},
		})
		if len(findings) != 0 {
			t.Fatalf("a correct removal was refused, which is the state that made a removal unshippable:\n%s",
				strings.Join(findings, "\n"))
		}
	})

	t.Run("an UNDECLARED removal is still refused", func(t *testing.T) {
		findings := checkPinnedSurfaceTables(map[AuthZENProfile]responseSurfacePin{
			"axonflow-authzen-profile-2026-08-29": base,
			"axonflow-authzen-profile-2027-01-01": {
				Members: map[Schema][]pinnedMember{
					SchemaAuthZENResponse: {{"decision", true, "bool"}},
				},
				Enums: map[string][]string{"category": {"allowed"}},
			},
		})
		if !strings.Contains(strings.Join(findings, "\n"), "narrows the ratchet silently") {
			t.Fatalf("the escape hatch swallowed a silent narrowing; findings were:\n%s",
				strings.Join(findings, "\n"))
		}
	})

	t.Run("a retirement of something still pinned is refused", func(t *testing.T) {
		findings := checkPinnedSurfaceTables(map[AuthZENProfile]responseSurfacePin{
			"axonflow-authzen-profile-2026-08-29": base,
			"axonflow-authzen-profile-2027-01-01": {
				Members: map[Schema][]pinnedMember{
					SchemaAuthZENResponse: {{"decision", true, "bool"}},
					SchemaIdentifier:      {{"local", true, "string"}},
				},
				Enums:   map[string][]string{"category": {"allowed"}},
				Retires: map[string]string{"identifier": "claims to be gone but is right there"},
			},
		})
		if !strings.Contains(strings.Join(findings, "\n"), "retires \"identifier\" and also pins it") {
			t.Fatalf("a retirement contradicted by the same row was accepted; findings were:\n%s",
				strings.Join(findings, "\n"))
		}
	})

	t.Run("a retirement with no reason is refused", func(t *testing.T) {
		findings := checkPinnedSurfaceTables(map[AuthZENProfile]responseSurfacePin{
			"axonflow-authzen-profile-2026-08-29": base,
			"axonflow-authzen-profile-2027-01-01": {
				Members: map[Schema][]pinnedMember{
					SchemaAuthZENResponse: {{"decision", true, "bool"}},
				},
				Enums:   map[string][]string{"category": {"allowed"}},
				Retires: map[string]string{"identifier": "  "},
			},
		})
		if !strings.Contains(strings.Join(findings, "\n"), "with no reason") {
			t.Fatalf("a retirement with no reason was accepted; findings were:\n%s", strings.Join(findings, "\n"))
		}
	})

	// And end to end: the approval branch really leaves the response wire, the
	// profile is bumped, and the new row omits and retires the four entities that
	// left. The checker must report nothing.
	t.Run("the checker accepts a bumped profile whose row records the removal", func(t *testing.T) {
		schemaDoc, artifact := shippedResponseSurfaceInputs(t)
		s := removeSchemaMember(t, schemaDoc, "authzen_response_context", "approval")
		a := removeArtifactField(t, artifact, "authzen_response_context", "approval")

		newProfile := AuthZENProfile("axonflow-authzen-profile-2027-01-01")
		shipped := authzenResponseSurfaceByProfile[AuthZENProfileV1]
		next := responseSurfacePin{
			Members: map[Schema][]pinnedMember{},
			Enums:   map[string][]string{},
			Retires: map[string]string{
				"approval_requirement": "the approval branch left the response wire",
				"approval_clause":      "reachable only from approval_requirement",
				"identifier":           "reachable only from approval_clause.eligible",
				"identifier_kind":      "reachable only from identifier.kind",
			},
		}
		for sch, members := range shipped.Members {
			switch sch {
			case SchemaApproval, SchemaApprovalClause, SchemaIdentifier:
				continue
			case SchemaAuthZENResponseContext:
				var kept []pinnedMember
				for _, m := range members {
					if m.Name != "approval" {
						kept = append(kept, m)
					}
				}
				next.Members[sch] = kept
			default:
				next.Members[sch] = members
			}
		}
		for name, values := range shipped.Enums {
			if name == "identifier_kind" {
				continue
			}
			next.Enums[name] = values
		}
		pins := map[AuthZENProfile]responseSurfacePin{
			AuthZENProfileV1: shipped,
			newProfile:       next,
		}

		if findings := checkPinnedSurfaceTables(pins); len(findings) != 0 {
			t.Fatalf("the two-row table for a legal removal is not canonical:\n%s", strings.Join(findings, "\n"))
		}
		rep, err := checkAuthZENResponseSurface(s, a, newProfile, pins)
		if err != nil {
			t.Fatalf("the checker refused documents it should have evaluated: %v", err)
		}
		if !rep.Pinned {
			t.Fatal("the new profile did not resolve in the synthetic table; nothing was compared")
		}
		if len(rep.Findings) != 0 {
			t.Fatalf("a correct removal produced findings, so it is still unshippable:\n%s",
				strings.Join(rep.Findings, "\n"))
		}
		for _, s := range rep.Closure {
			if s == SchemaApproval || s == SchemaIdentifier {
				t.Fatalf("%q is still in the closure; the removal fixture did not remove it and the case above "+
					"proved nothing", s)
			}
		}
	})
}

// TestTheResponseSurfaceRatchetCanFail is the mutation gate.
//
// Every assertion above compares the shipped documents against a table that was
// written from those same documents, so all of them would stay green over a
// checker that had stopped looking. This drives the checker with MUTATED
// documents in process and asserts which ones it must reject - and, just as
// importantly, includes controls it must ACCEPT. A gate that reports a kill for
// every input is not a gate.
func TestTheResponseSurfaceRatchetCanFail(t *testing.T) {
	schemaDoc, artifact := shippedResponseSurfaceInputs(t)

	// The clean run first. A mutant that "kills" an already-red check proves
	// nothing.
	clean, err := checkAuthZENResponseSurface(schemaDoc, artifact, AuthZENProfileV1, authzenResponseSurfaceByProfile)
	if err != nil {
		t.Fatalf("the shipped documents do not evaluate: %v", err)
	}
	if len(clean.Findings) != 0 {
		t.Fatalf("the shipped documents already produce findings, so no mutation below would prove anything:\n%s",
			strings.Join(clean.Findings, "\n"))
	}
	// The shipped profile must resolve, or every mutant below would be compared
	// against nothing. That it ALWAYS resolves is the separate, named requirement
	// in TestTheCurrentProfileIsPinned; this is the local precondition.
	if !clean.Pinned {
		t.Fatalf("the shipped profile %s is unpinned, so the mutants below would not be compared against "+
			"anything; see TestTheCurrentProfileIsPinned", AuthZENProfileV1)
	}

	newProfile := AuthZENProfile("axonflow-authzen-profile-2099-01-01")
	if _, exists := authzenResponseSurfaceByProfile[newProfile]; exists {
		t.Fatalf("%s is in the pin table; the release-valve case below would not be testing a NEW profile", newProfile)
	}

	for _, tc := range []struct {
		name string
		// mutate returns the schema, the artifact and the profile to check.
		mutate func(t *testing.T) ([]byte, []byte, AuthZENProfile)
		// wantFinding is the substring the findings must mention. Empty means
		// the input must be ACCEPTED - a control that has to survive.
		wantFinding string
		// wantFindingFrom derives that substring from the SHIPPED artifact, for
		// the mutants that flip a value rather than set one. A mutant keyed on
		// an absolute value ("decision_id becomes optional") stops being a
		// mutation the day the product legitimately ships that value, and then
		// this gate fails for a reason that is not its own. Flipping whatever is
		// there, and deriving the expected message from what was there, keeps
		// the mutant a mutation whichever way the surface moves.
		wantFindingFrom func(t *testing.T) string
		// wantFatal means the checker must refuse the input outright.
		wantFatal bool
		// why records what a survivor here would mean.
		why string
	}{
		{
			name: "a member is added to the response context and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := addSchemaMember(t, schemaDoc, "authzen_response_context", "extensions")
				a := addArtifactField(t, artifact, "authzen_response_context", "extensions")
				return s, a, AuthZENProfileV1
			},
			wantFinding: "changed under an UNCHANGED profile constant",
			why:         "this is the exact defect the ratchet was built for: regenerate everything, break every PEP, stay green",
		},
		{
			name: "a member is added to a transitively reachable shape and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := addSchemaMember(t, schemaDoc, "obligation", "deadline")
				a := addArtifactField(t, artifact, "obligation", "deadline")
				return s, a, AuthZENProfileV1
			},
			wantFinding: "changed under an UNCHANGED profile constant",
			why:         "obligation is not an authzen_-prefixed shape, and it carries the instructions a PEP must not ignore",
		},
		{
			name: "a member is REMOVED and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := removeSchemaMember(t, schemaDoc, "authzen_response_context", "reason")
				a := removeArtifactField(t, artifact, "authzen_response_context", "reason")
				return s, a, AuthZENProfileV1
			},
			wantFinding: "removed reason",
			why:         "a shrinking surface breaks a PEP that requires the member, and a floor that only watches growth cannot see it",
		},
		{
			name: "a REQUIRED member's optionality flips and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := flipArtifactFieldRequired(t, artifact, "authzen_response_context", "decision_id")
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFindingFrom: func(t *testing.T) string {
				return flippedRequiredPhrase(t, artifact, "authzen_response_context", "decision_id")
			},
			why: "a Rust PEP generating `decision_id: String` rather than Option<String> fails to decode the " +
				"first response that omits it; the member NAME is unchanged, so a name-only pin cannot see it",
		},
		{
			name: "an OPTIONAL member's optionality flips and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := flipArtifactFieldRequired(t, artifact, "authzen_error", "pointer")
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFindingFrom: func(t *testing.T) string {
				return flippedRequiredPhrase(t, artifact, "authzen_error", "pointer")
			},
			why: "the axis has two directions, and a promise the server must now keep is still a changed promise",
		},
		{
			name: "a member's TYPE changes and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := flipArtifactFieldScalarType(t, artifact, "authzen_error", "request_id")
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFindingFrom: func(t *testing.T) string {
				return flippedScalarTypePhrase(t, artifact, "authzen_error", "request_id")
			},
			why: "this one regenerated cleanly while contract/authzen.go went on declaring RequestID string, so " +
				"the Go server and the artifact every SDK generates from described different wires",
		},
		{
			name: "an enum REACHABLE from the response gains a value and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := addArtifactEnumValue(t, artifact, "reason_code", "mutant_only_reason_code")
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFinding: "the value set of enumeration \"reason_code\" changed under an UNCHANGED profile constant",
			why: "a PEP validating a response against its pinned copy of the profile refuses an undeclared reason " +
				"code outright; the artifact's enums block was never opened by the first version of this file",
		},
		{
			name: "an enum reachable from the response LOSES a value and the profile is NOT bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := removeArtifactEnumValue(t, artifact, "operational_state", "CHALLENGE")
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFinding: "removed CHALLENGE",
			why:         "a value withdrawn from a closed set is a state the server can no longer describe to a PEP that branches on it",
		},
		{
			name: "the same member is added AND the profile constant is bumped",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := addSchemaMember(t, schemaDoc, "authzen_response_context", "extensions")
				a := addArtifactField(t, artifact, "authzen_response_context", "extensions")
				return s, a, newProfile
			},
			wantFinding: "",
			why:         "the release valve. A ratchet that cannot be released is a ratchet somebody deletes",
		},
		{
			name: "the schema gains a member the artifact does not have",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := addSchemaMember(t, schemaDoc, "authzen_response_context", "extensions")
				return s, artifact, AuthZENProfileV1
			},
			wantFinding: "disagree about",
			why:         "the SDKs generate from the artifact; a schema-only edit means the server and every SDK describe different wires",
		},
		{
			name: "the artifact gains a member the schema does not have",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := addArtifactField(t, artifact, "authzen_response_context", "extensions")
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFinding: "disagree about",
			why:         "a hand-edited artifact would otherwise reach five SDKs describing a member the server cannot emit",
		},
		{
			name: "the response context is opened with additionalProperties:true",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := setSchemaAdditionalProperties(t, schemaDoc, "authzen_response_context", true)
				return s, artifact, AuthZENProfileV1
			},
			wantFinding: "rather than false",
			why:         "the premise of the pin is that these shapes are closed; opening one changes what an added member costs",
		},
		{
			name: "the response context is emptied of properties",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := emptySchemaProperties(t, schemaDoc, "authzen_response_context")
				return s, artifact, AuthZENProfileV1
			},
			wantFinding: "declares no properties",
			why:         "anti-vacuity: a run that parsed a shape down to nothing must not report zero violations",
		},
		{
			name: "a $ref carries no path separator, so no definition name can be read",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := setSchemaRef(t, schemaDoc, "approval_requirement", "all_of", "approval_clause")
				return s, artifact, AuthZENProfileV1
			},
			wantFinding: "carries a reference this walk cannot read",
			why: "the reference walk decides SCOPE, so a reference it silently drops is a shape that leaves the " +
				"ratchet with nothing saying so - the largest fail-open in the file",
		},
		{
			name: "the reference walk follows nothing at all",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := replaceSchemaProperty(t, schemaDoc, "authzen_response", "context",
					map[string]any{"type": "object"})
				return s, artifact, AuthZENProfileV1
			},
			wantFatal: true,
			why: "with the roots alone in scope, every nested response shape - the obligations and approval " +
				"requirements a PEP acts on - drops out of the comparison with no message anywhere",
		},
		{
			name: "the schema has no $defs at all",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				return []byte(`{"$schema":"x"}`), artifact, AuthZENProfileV1
			},
			wantFatal: true,
			why:       "anti-vacuity: parsing nothing must be fatal, not silently clean",
		},
		{
			name: "the artifact describes no types",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				return schemaDoc, []byte(`{"types":[]}`), AuthZENProfileV1
			},
			wantFatal: true,
			why:       "anti-vacuity: the second source contributing nothing must be fatal",
		},
		{
			name: "the artifact declares no enumerations",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := dropArtifactEnums(t, artifact)
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFinding: "does not declare",
			why: "anti-vacuity for the enum axis: an artifact whose enums block vanished must not make the enum " +
				"comparison silently trivial",
		},
		{
			name: "CONTROL: a definition's prose description changes",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := setSchemaDescription(t, schemaDoc, "authzen_response_context", "a rewritten description")
				return s, artifact, AuthZENProfileV1
			},
			wantFinding: "",
			why:         "documentation is not the wire; a ratchet that fires on prose gets disabled within a week",
		},
		{
			name: "CONTROL: a field's doc string changes in the artifact",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := setArtifactFieldDoc(t, artifact, "authzen_response_context", "decision_id", "rewritten")
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFinding: "",
			why: "the three artifact-derived axes must read the artifact's SHAPE, not its prose; a pin that " +
				"fired on a doc edit would be reverted rather than understood",
		},
		{
			name: "CONTROL: a member is added to a REQUEST-side shape",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				s := addSchemaMember(t, schemaDoc, "authzen_subject", "tenant")
				a := addArtifactField(t, artifact, "authzen_subject", "tenant")
				return s, a, AuthZENProfileV1
			},
			wantFinding: "",
			why: "the request path is the caller's to widen and is guarded elsewhere; this ratchet is about what the " +
				"SERVER sends, and claiming request-side coverage it does not have would be worse than having none",
		},
		{
			name: "CONTROL: an enumeration the response closure does not reach gains a value",
			mutate: func(t *testing.T) ([]byte, []byte, AuthZENProfile) {
				a := addUnreachedArtifactEnum(t, artifact, "mutant_only_enum", []string{"one", "two"})
				return schemaDoc, a, AuthZENProfileV1
			},
			wantFinding: "",
			why: "the enum axis is scoped by REACHABILITY from the response roots, exactly as the definition axis " +
				"is; pinning every enum in the artifact would fire on a request-side change",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.wantFinding
			if tc.wantFindingFrom != nil {
				if want != "" {
					t.Fatal("this case declares both wantFinding and wantFindingFrom; only one can be the expectation")
				}
				want = tc.wantFindingFrom(t)
				if want == "" {
					t.Fatal("wantFindingFrom derived an empty expectation, which would silently turn a kill case " +
						"into a control")
				}
			}
			s, a, p := tc.mutate(t)
			rep, err := checkAuthZENResponseSurface(s, a, p, authzenResponseSurfaceByProfile)
			if tc.wantFatal {
				if err == nil {
					t.Fatalf("the checker accepted an input it must refuse outright (findings: %v).\nWhat this "+
						"survivor would mean: %s", rep.Findings, tc.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("the checker refused an input it should have evaluated: %v", err)
			}
			joined := strings.Join(rep.Findings, "\n")
			if want == "" {
				if len(rep.Findings) != 0 {
					t.Fatalf("a control was rejected:\n%s\nWhy it must survive: %s", joined, tc.why)
				}
				return
			}
			if !strings.Contains(joined, want) {
				t.Fatalf("the checker did not report %q.\nFindings were:\n%s\nWhat this survivor would mean: %s",
					want, joined, tc.why)
			}
		})
	}
}

// The mutation helpers below edit the documents structurally rather than by
// string substitution. Two definitions in this schema are worded almost
// identically, and a textual harness mutates the FIRST match - which makes a
// reported survivor a statement about the wrong site.
//
// Every helper refuses a mutant that would change nothing, so a fixture that
// stops being a mutation says so instead of passing vacuously. That is also why
// the enum mutants use values no product change can legitimately introduce
// (mutant_only_reason_code, mutant_only_enum): keying a mutant on a plausible
// future value makes the gate fail on the day someone ships that value, and the
// failure looks like a broken ratchet rather than a collided fixture.

func decodeMutant(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding for mutation: %v", err)
	}
	return v
}

func encodeMutant(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encoding a mutant: %v", err)
	}
	return raw
}

func schemaDefinition(t *testing.T, doc map[string]any, def string) map[string]any {
	t.Helper()
	defs, ok := doc["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("the schema has no $defs to mutate")
	}
	d, ok := defs[def].(map[string]any)
	if !ok {
		t.Fatalf("the schema has no definition %q to mutate", def)
	}
	return d
}

func addSchemaMember(t *testing.T, raw []byte, def, member string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	d := schemaDefinition(t, doc, def)
	props, ok := d["properties"].(map[string]any)
	if !ok {
		t.Fatalf("definition %q has no properties to add to", def)
	}
	if _, exists := props[member]; exists {
		t.Fatalf("definition %q already declares %q; the mutant would change nothing", def, member)
	}
	props[member] = map[string]any{"type": "object"}
	return encodeMutant(t, doc)
}

func removeSchemaMember(t *testing.T, raw []byte, def, member string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	d := schemaDefinition(t, doc, def)
	props, ok := d["properties"].(map[string]any)
	if !ok {
		t.Fatalf("definition %q has no properties to remove from", def)
	}
	if _, exists := props[member]; !exists {
		t.Fatalf("definition %q does not declare %q; the mutant would change nothing", def, member)
	}
	delete(props, member)
	if req, ok := d["required"].([]any); ok {
		kept := make([]any, 0, len(req))
		for _, r := range req {
			if s, _ := r.(string); s == member {
				continue
			}
			kept = append(kept, r)
		}
		d["required"] = kept
	}
	return encodeMutant(t, doc)
}

// replaceSchemaProperty swaps a property's whole subschema, which is how the
// reference walk is made to follow nothing.
func replaceSchemaProperty(t *testing.T, raw []byte, def, member string, with map[string]any) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	d := schemaDefinition(t, doc, def)
	props, ok := d["properties"].(map[string]any)
	if !ok {
		t.Fatalf("definition %q has no properties to replace in", def)
	}
	if _, exists := props[member]; !exists {
		t.Fatalf("definition %q does not declare %q; the mutant would change nothing", def, member)
	}
	props[member] = with
	return encodeMutant(t, doc)
}

// setSchemaRef rewrites the $ref reached from a property, at any depth beneath
// it, to a literal string. Passing a name with no "/" is what produces an
// unreadable reference.
func setSchemaRef(t *testing.T, raw []byte, def, member, target string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	d := schemaDefinition(t, doc, def)
	props, ok := d["properties"].(map[string]any)
	if !ok {
		t.Fatalf("definition %q has no properties to mutate", def)
	}
	prop, ok := props[member].(map[string]any)
	if !ok {
		t.Fatalf("definition %q declares no property %q to mutate", def, member)
	}
	found := false
	var walk func(any)
	walk = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			for k, child := range n {
				if k == "$ref" {
					n[k] = target
					found = true
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range n {
				walk(child)
			}
		}
	}
	walk(prop)
	if !found {
		t.Fatalf("%s/%s carries no $ref; the mutant would change nothing", def, member)
	}
	return encodeMutant(t, doc)
}

func emptySchemaProperties(t *testing.T, raw []byte, def string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	d := schemaDefinition(t, doc, def)
	if props, ok := d["properties"].(map[string]any); !ok || len(props) == 0 {
		t.Fatalf("definition %q already has no properties; the mutant would change nothing", def)
	}
	d["properties"] = map[string]any{}
	return encodeMutant(t, doc)
}

func setSchemaAdditionalProperties(t *testing.T, raw []byte, def string, v bool) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	d := schemaDefinition(t, doc, def)
	if cur, ok := d["additionalProperties"].(bool); ok && cur == v {
		t.Fatalf("definition %q already sets additionalProperties:%v; the mutant would change nothing", def, v)
	}
	d["additionalProperties"] = v
	return encodeMutant(t, doc)
}

func setSchemaDescription(t *testing.T, raw []byte, def, text string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	d := schemaDefinition(t, doc, def)
	if cur, _ := d["description"].(string); cur == text {
		t.Fatalf("definition %q already carries that description; the control would change nothing", def)
	}
	d["description"] = text
	return encodeMutant(t, doc)
}

func artifactType(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	types, ok := doc["types"].([]any)
	if !ok {
		t.Fatalf("the artifact has no types to mutate")
	}
	for _, raw := range types {
		tp, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := tp["name"].(string); n == name {
			return tp
		}
	}
	t.Fatalf("the artifact describes no type %q to mutate", name)
	return nil
}

func artifactField(t *testing.T, doc map[string]any, typeName, field string) map[string]any {
	t.Helper()
	tp := artifactType(t, doc, typeName)
	fields, ok := tp["fields"].([]any)
	if !ok {
		t.Fatalf("type %q has no fields to mutate", typeName)
	}
	for _, f := range fields {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := m["name"].(string); n == field {
			return m
		}
	}
	t.Fatalf("type %q declares no field %q to mutate", typeName, field)
	return nil
}

func addArtifactField(t *testing.T, raw []byte, typeName, field string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	tp := artifactType(t, doc, typeName)
	fields, ok := tp["fields"].([]any)
	if !ok {
		t.Fatalf("type %q has no fields to add to", typeName)
	}
	for _, f := range fields {
		if m, ok := f.(map[string]any); ok {
			if n, _ := m["name"].(string); n == field {
				t.Fatalf("type %q already declares %q; the mutant would change nothing", typeName, field)
			}
		}
	}
	tp["fields"] = append(fields, map[string]any{
		"name":     field,
		"required": false,
		"type":     map[string]any{"kind": "object"},
	})
	return encodeMutant(t, doc)
}

func removeArtifactField(t *testing.T, raw []byte, typeName, field string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	tp := artifactType(t, doc, typeName)
	fields, ok := tp["fields"].([]any)
	if !ok {
		t.Fatalf("type %q has no fields to remove from", typeName)
	}
	kept := make([]any, 0, len(fields))
	removed := false
	for _, f := range fields {
		if m, ok := f.(map[string]any); ok {
			if n, _ := m["name"].(string); n == field {
				removed = true
				continue
			}
		}
		kept = append(kept, f)
	}
	if !removed {
		t.Fatalf("type %q does not declare %q; the mutant would change nothing", typeName, field)
	}
	tp["fields"] = kept
	return encodeMutant(t, doc)
}

// flipArtifactFieldRequired inverts a field's optionality, whichever way it
// currently points, and flippedRequiredPhrase names the change the checker must
// then report. The pair is what keeps this mutant a mutation on the day the
// product legitimately moves that field.
func flipArtifactFieldRequired(t *testing.T, raw []byte, typeName, field string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	f := artifactField(t, doc, typeName, field)
	cur, _ := f["required"].(bool)
	f["required"] = !cur
	return encodeMutant(t, doc)
}

func flippedRequiredPhrase(t *testing.T, raw []byte, typeName, field string) string {
	t.Helper()
	doc := decodeMutant(t, raw)
	f := artifactField(t, doc, typeName, field)
	cur, _ := f["required"].(bool)
	return fmt.Sprintf("%s: %s -> %s", field, requiredWord(cur), requiredWord(!cur))
}

// flipArtifactFieldScalarType swaps a scalar field between string and int. Which
// two scalars they are does not matter; that the pin notices the swap does.
func flipArtifactFieldScalarType(t *testing.T, raw []byte, typeName, field string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	f := artifactField(t, doc, typeName, field)
	_, to := scalarKindFlip(t, f, typeName, field)
	f["type"] = map[string]any{"kind": to}
	return encodeMutant(t, doc)
}

func flippedScalarTypePhrase(t *testing.T, raw []byte, typeName, field string) string {
	t.Helper()
	doc := decodeMutant(t, raw)
	f := artifactField(t, doc, typeName, field)
	from, to := scalarKindFlip(t, f, typeName, field)
	return fmt.Sprintf("%s: type %s -> %s", field, from, to)
}

func scalarKindFlip(t *testing.T, f map[string]any, typeName, field string) (from, to string) {
	t.Helper()
	tr, ok := f["type"].(map[string]any)
	if !ok {
		t.Fatalf("%s/%s carries no type object to flip", typeName, field)
	}
	from, _ = tr["kind"].(string)
	if from == "" {
		t.Fatalf("%s/%s carries no type kind to flip", typeName, field)
	}
	if from == "string" {
		return from, "int"
	}
	return from, "string"
}

func setArtifactFieldDoc(t *testing.T, raw []byte, typeName, field, text string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	f := artifactField(t, doc, typeName, field)
	if cur, _ := f["doc"].(string); cur == text {
		t.Fatalf("%s/%s already carries that doc; the control would change nothing", typeName, field)
	}
	f["doc"] = text
	return encodeMutant(t, doc)
}

func artifactEnum(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	enums, ok := doc["enums"].([]any)
	if !ok {
		t.Fatalf("the artifact declares no enums to mutate")
	}
	for _, raw := range enums {
		e, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := e["name"].(string); n == name {
			return e
		}
	}
	t.Fatalf("the artifact declares no enumeration %q to mutate", name)
	return nil
}

func addArtifactEnumValue(t *testing.T, raw []byte, name, value string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	e := artifactEnum(t, doc, name)
	values, ok := e["values"].([]any)
	if !ok {
		t.Fatalf("enumeration %q declares no values", name)
	}
	for _, v := range values {
		if s, _ := v.(string); s == value {
			t.Fatalf("enumeration %q already declares %q; the mutant would change nothing", name, value)
		}
	}
	e["values"] = append(values, value)
	return encodeMutant(t, doc)
}

func removeArtifactEnumValue(t *testing.T, raw []byte, name, value string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	e := artifactEnum(t, doc, name)
	values, ok := e["values"].([]any)
	if !ok {
		t.Fatalf("enumeration %q declares no values", name)
	}
	kept := make([]any, 0, len(values))
	removed := false
	for _, v := range values {
		if s, _ := v.(string); s == value {
			removed = true
			continue
		}
		kept = append(kept, v)
	}
	if !removed {
		t.Fatalf("enumeration %q does not declare %q; the mutant would change nothing", name, value)
	}
	e["values"] = kept
	return encodeMutant(t, doc)
}

func addUnreachedArtifactEnum(t *testing.T, raw []byte, name string, values []string) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	enums, ok := doc["enums"].([]any)
	if !ok {
		t.Fatalf("the artifact declares no enums block to add to")
	}
	for _, e := range enums {
		if m, ok := e.(map[string]any); ok {
			if n, _ := m["name"].(string); n == name {
				t.Fatalf("the artifact already declares %q; the control would change nothing", name)
			}
		}
	}
	vs := make([]any, 0, len(values))
	for _, v := range values {
		vs = append(vs, v)
	}
	doc["enums"] = append(enums, map[string]any{"name": name, "values": vs})
	return encodeMutant(t, doc)
}

func dropArtifactEnums(t *testing.T, raw []byte) []byte {
	t.Helper()
	doc := decodeMutant(t, raw)
	if enums, ok := doc["enums"].([]any); !ok || len(enums) == 0 {
		t.Fatalf("the artifact already declares no enums; the mutant would change nothing")
	}
	doc["enums"] = []any{}
	return encodeMutant(t, doc)
}
