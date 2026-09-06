package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// The presence boundary for required wire members whose ABSENT reading is a
// legal value.
//
// # The defect this closes
//
// `encoding/json` cannot distinguish an omitted member from one carrying its
// type's zero value, and `DisallowUnknownFields` does not help: it refuses
// members that are EXTRA, and a member that is MISSING is exactly what it
// cannot see. For most members that is harmless, because the zero value is
// itself refused - an empty `source_policy`, a `schema_version` of 0, a
// `quorum` below 1 all fail their validator, so absence is caught by the value
// check that was going to run anyway.
//
// It is not harmless for a required BOOLEAN. `false` is a legal authored value,
// so the validator has nothing to reject, and the reading absence produces is
// the PERMISSIVE one on both members that carry this shape:
//
//   - `obligation.mandatory` absent reads as advisory, and every one of the ~11
//     combining sites in obligation.go treats advisory as "record it and
//     proceed". An obligation whose mandatory flag is dropped anywhere on the
//     path therefore does not fail loudly; it silently stops being a
//     precondition of the permit, and the audit row looks entirely normal.
//     ADR-065 invariant 8 is that a mandatory obligation the PEP cannot
//     discharge DENIES, and invariant 4 is that malformed input never becomes a
//     permit; a dropped flag defeats both without either noticing.
//   - `approval_requirement.separation_of_duties` absent reads as "no
//     separation required", which is the permissive reading of a control whose
//     entire purpose is to be restrictive.
//
// This is the class #3596 already cost production once, where an omitted bool
// in a partial update read as `false`, silently withdrew a live CAEP opt-in,
// answered 200, and audit-logged it as intended.
//
// # Why the fix is here rather than at the reads
//
// Presence is resolved ONCE, at the decode boundary, and recorded on the value.
// The combining sites keep plain `bool` and gain no nil checks: a `*bool` that
// leaked past this file would put the same three-valued question at every one
// of those sites, and the eleventh one to be written would get it wrong. The
// refusal then rides the type's ordinary `Validate`, which is already called on
// every path that composes or validates a decision, so no caller has to
// remember a new step.
//
// # Why the schema needs no change
//
// `contract-2026-08-29.schema.json` ALREADY declares both members required
// (`$defs.obligation.required` and `$defs.approval_requirement.required`). The
// contract has said so since it was written; only the Go decoder disagreed. So
// this closes a server/schema divergence rather than narrowing a published
// surface: no schema edit, no artifact regeneration, no profile bump, and
// nothing for the response-surface ratchet (#3632) to notice.

// wireAbsence is a bitset of the required members that were ABSENT (or present
// as `null`) in the JSON document a value was decoded from.
//
// A fixed-width bitset rather than a []string because an Obligation is COPIED
// BY ASSIGNMENT throughout the composition algebra - `applied := chosen`,
// `out := set[0]`, `distinct[k] = cur` - and a slice member would give every
// copy a shared backing array. Appending to one copy's absence list could then
// be visible through another, or not, depending on capacity: aliasing decided
// by an allocation. A uint8 copies with the struct and cannot alias. (It is NOT
// for comparability: Obligation carries a `Params map[string]string` and has
// never been comparable with `==`.)
//
// The zero value means "nothing was absent", which is also the right answer for
// a value constructed in Go rather than decoded - construction in Go supplies
// every member by definition, so a Go-built obligation validates exactly as it
// did before this file existed.
type wireAbsence uint8

const (
	// absentMandatory is `obligation.mandatory`, omitted.
	absentMandatory wireAbsence = 1 << iota
	// absentMandatoryNull is the same member, present as `null`.
	absentMandatoryNull
	// absentSeparationOfDuties is `approval_requirement.separation_of_duties`,
	// omitted.
	absentSeparationOfDuties
	// absentSeparationOfDutiesNull is the same member, present as `null`.
	absentSeparationOfDutiesNull
)

// A null bit PER MEMBER rather than one shared bit for the value. One shared
// bit is unambiguous only while every shape tracks exactly one member, and this
// table exists to be extended; the day a shape tracks two, a shared flag would
// report "present as null" against whichever member the scan reached first - in
// the one error whose entire job is to tell presence from absence.

// wireAbsenceMember names one tracked member for the refusal message, and the
// SHAPE that declares it.
//
// The shape is carried here rather than hardcoded at the two Validate call
// sites so that a (shape, pointer) pair can never be mismatched: a third
// tracked member added for a third shape scans the same table, and without the
// binding it could be reported under whichever shape happened to ask.
type wireAbsenceMember struct {
	bit wireAbsence
	// nullBit is set instead of bit when the member was present as `null`.
	nullBit wireAbsence
	shape   Schema
	pointer string
}

// wireAbsenceMembers is read in a fixed order so a document missing more than
// one tracked member always names the same one first.
var wireAbsenceMembers = []wireAbsenceMember{
	{absentMandatory, absentMandatoryNull, SchemaObligation, "/mandatory"},
	{absentSeparationOfDuties, absentSeparationOfDutiesNull, SchemaApproval, "/separation_of_duties"},
}

// firstMissing returns the refusal for the first absent member of this shape.
//
// It filters by shape rather than returning whichever bit is set, so the error
// cannot pair one shape's name with another's pointer.
func (a wireAbsence) firstMissing(shape Schema) (*MissingMemberError, bool) {
	for _, m := range wireAbsenceMembers {
		if m.shape != shape || a&(m.bit|m.nullBit) == 0 {
			continue
		}
		return &MissingMemberError{Shape: shape, Pointer: m.pointer, WasNull: a&m.nullBit != 0}, true
	}
	return nil, false
}

// MissingMemberError is the refusal for a document that omitted a member the
// contract declares REQUIRED.
//
// It is a TYPED error rather than a formatted string because the two things a
// caller needs from it are machine facts: which shape was refused, and which
// member was absent. A serving adapter turning this into a wire refusal needs
// the pointer to fill in, and a `fmt.Errorf` would make it parse prose to get
// it.
//
// It is deliberately NOT an AuthZENError. That type is the error contract of
// ONE route, with a closed code enumeration published in the generated surface
// artifact; obligations are validated on every plane, so a contract-level
// refusal expressed in that type would make every plane depend on the AuthZEN
// route's enumeration. A route that wants to render this as an AuthZEN refusal
// reaches it with errors.As and supplies its own code.
type MissingMemberError struct {
	// Shape is the contract shape the member belongs to.
	Shape Schema
	// Pointer is an RFC 6901 JSON Pointer naming the absent member.
	Pointer string
	// WasNull distinguishes a member present as `null` from one that was
	// omitted. Both decode to a nil pointer and both are refused, but this is
	// the one error whose entire job is to tell presence from absence, and
	// reporting "absent" for a member the document plainly carries would make
	// it wrong about exactly the thing it exists to say.
	WasNull bool
}

func (e *MissingMemberError) Error() string {
	if e == nil {
		return "<nil missing member error>"
	}
	how := "is absent from the document"
	if e.WasNull {
		how = "is present as null"
	}
	return fmt.Sprintf("%s: required member %s %s; "+
		"a member that carries no value is not the same as one carrying its zero value, and the zero value here is the permissive reading",
		e.Shape, e.Pointer, how)
}

// Prefixed returns a copy whose pointer is rooted in an enclosing document, so
// a refusal raised on a nested shape names the member's real location rather
// than its offset within its own shape.
func (e *MissingMemberError) Prefixed(prefix string) *MissingMemberError {
	if e == nil {
		return nil
	}
	return &MissingMemberError{Shape: e.Shape, Pointer: prefix + e.Pointer, WasNull: e.WasNull}
}

// strictDecode decodes one JSON document into v with unknown members refused.
//
// Every custom UnmarshalJSON in this file goes through it. A custom
// UnmarshalJSON that called json.Unmarshal directly would SILENTLY DISARM an
// enclosing decoder's DisallowUnknownFields - encoding/json hands the raw bytes
// to the method and the method's own strictness is whatever it chose - so
// adding presence tracking would have widened the boundary it was added to
// tighten. Decoding strictly here keeps the shapes at least as strict as they
// were, on every path, whether or not the enclosing decoder was strict.
func strictDecode(raw []byte, v any) error {
	// DUPLICATE MEMBERS ARE REFUSED FIRST, and this is not defence in depth.
	// encoding/json silently keeps the LAST of a repeated member, so
	// `{"mandatory":true,"mandatory":false}` decodes as ADVISORY - a document
	// that states the obligation is mandatory, and is read as the opposite,
	// which is the very reading this file exists to prevent. It also makes the
	// document mean one thing here and another to any layer that read the
	// first: a gateway, an audit log, a rate limiter.
	//
	// The envelope decoder already refuses this at the top level
	// (rejectDuplicateKeys, authzen.go). These shapes are decoded on paths that
	// never pass through it, so the check is applied here rather than assumed
	// from there.
	if err := rejectDuplicateKeys(json.NewDecoder(bytes.NewReader(raw)), "$"); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	// UseNumber is restored for the same reason. authoring.Parse - the one
	// decoder in this repo that reads a document carrying these shapes - sets
	// BOTH settings, and its own comment says UseNumber is load-bearing against
	// silent precision loss on a 64-bit literal. Neither shape has an `any`
	// member today, so it changes nothing now; the day one does, these two
	// shapes must not be the only place in a parsed document where a literal
	// goes through float64.
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Unreachable through UnmarshalJSON - encoding/json hands the method exactly
	// one syntactically complete value - and kept because strictDecode is a
	// general helper: the first caller that hands it a whole document would
	// otherwise silently accept a second one appended to the first.
	if dec.More() {
		return fmt.Errorf("trailing content after the document")
	}
	return nil
}

// obligationWire is the presence-preserving decode of an Obligation.
//
// It mirrors Obligation member for member, with the required boolean as a
// pointer so absence is visible. Keeping it unexported and converting
// immediately is what stops the pointer travelling: nothing outside this file
// ever holds one.
type obligationWire struct {
	Type   ObligationType    `json:"type"`
	Target string            `json:"target,omitempty"`
	Params map[string]string `json:"params,omitempty"`
	// Decoded as a raw message rather than a *bool so an explicit `null` can be
	// told from an omission: both produce a nil *bool, and the refusal must not
	// claim a member is absent when the document carries it.
	Mandatory     json.RawMessage `json:"mandatory"`
	SourcePolicy  string          `json:"source_policy"`
	SchemaVersion int             `json:"schema_version"`
}

// UnmarshalJSON decodes an obligation, recording whether `mandatory` was there.
//
// It does NOT refuse here. The refusal belongs to Validate, which is what every
// composition and every decision validation already calls, so the rule holds on
// paths that decode a document without going through this method as well - and
// a decoder that refused would give the caller a zero Obligation and no way to
// report which member was at fault beyond the error string.
func (o *Obligation) UnmarshalJSON(raw []byte) error {
	var w obligationWire
	if err := strictDecode(raw, &w); err != nil {
		return fmt.Errorf("obligation: %w", err)
	}
	*o = Obligation{
		Type:          w.Type,
		Target:        w.Target,
		Params:        w.Params,
		SourcePolicy:  w.SourcePolicy,
		SchemaVersion: w.SchemaVersion,
	}
	present, wasNull, err := decodeRequiredBool(w.Mandatory)
	if err != nil {
		return fmt.Errorf("obligation: mandatory: %w", err)
	}
	if present == nil {
		o.absent |= absentMandatory
		if wasNull {
			o.absent |= absentMandatoryNull
		}
		return nil
	}
	o.Mandatory = *present
	return nil
}

// decodeRequiredBool reads a tracked required boolean out of its raw bytes.
//
// It returns (nil, false, nil) for an OMITTED member, (nil, true, nil) for one
// present as `null`, and (&value, false, nil) for a real boolean. A member of
// any other JSON type is an error rather than a third kind of absence: the
// schema types both of these `boolean`, and reporting `{"mandatory": "true"}`
// as "absent" would send the caller looking for a member that is right there.
func decodeRequiredBool(raw json.RawMessage) (*bool, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return nil, true, nil
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false, err
	}
	return &v, false, nil
}

// approvalRequirementWire is the presence-preserving decode of an
// ApprovalRequirement. See obligationWire.
type approvalRequirementWire struct {
	AllOf              []ApprovalClause `json:"all_of"`
	SeparationOfDuties json.RawMessage  `json:"separation_of_duties"`
	ExpiresAt          time.Time        `json:"expires_at"`
}

// UnmarshalJSON decodes an approval requirement, recording whether
// `separation_of_duties` was there.
func (a *ApprovalRequirement) UnmarshalJSON(raw []byte) error {
	var w approvalRequirementWire
	if err := strictDecode(raw, &w); err != nil {
		return fmt.Errorf("approval requirement: %w", err)
	}
	*a = ApprovalRequirement{AllOf: w.AllOf, ExpiresAt: w.ExpiresAt}
	present, wasNull, err := decodeRequiredBool(w.SeparationOfDuties)
	if err != nil {
		return fmt.Errorf("approval requirement: separation_of_duties: %w", err)
	}
	if present == nil {
		a.absent |= absentSeparationOfDuties
		if wasNull {
			a.absent |= absentSeparationOfDutiesNull
		}
		return nil
	}
	a.SeparationOfDuties = *present
	return nil
}
