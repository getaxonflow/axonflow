package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The ADR-065 PEP capability handshake: how an EXTERNAL enforcement point tells
// the platform what it is and what it can discharge.
//
// See technical-docs/PEP_CAPABILITY_HANDSHAKE.md for the design and for the
// candidates that were rejected. What matters at this file's level:
//
// # WHY A TRANSPORT LIVES IN THE CONTRACT PACKAGE
//
// The handshake declares contract.Capability values, which is the vocabulary
// PEPProfile.Supports already matches on and the vocabulary the registry's
// PEPRecord already stores. Putting the decoder anywhere else would either
// duplicate that vocabulary or make the transport's package the one every
// consumer has to import. This file adds NO vocabulary: it is the wire
// encoding, its validator, and the projection onto the PEPProfile that already
// exists.
//
// # ABSENT IS NOT EMPTY, AT BOTH LEVELS
//
// The header being absent is no bytes at all, and the platform then behaves
// exactly as it did before this file existed. Inside the document,
// `capabilities` is REQUIRED: omitting it is malformed, and `[]` is a
// declaration that this enforcement point discharges nothing. Making the
// omission malformed rather than empty is the load-bearing choice - a handshake
// exists to declare capabilities, so one that omits the member has said
// nothing, and reading "nothing said" as "nothing can be discharged" would put
// a caller's typo and a caller's deliberate declaration on the same code path.
// That collapse is the #2958 defect this handshake exists to correct, and
// reintroducing it one level down would be the whole change wasted.
//
// # WHAT A PEP MAY DECLARE, AND WHAT IT MAY NOT
//
// A PEP may declare WHAT IT CAN DO. It may not declare WHO IT IS, WHAT EDITION
// it is, or WHAT ITS ORGANISATION IS ENTITLED TO. `pep_id` is carried so the
// server can CONFIRM it against the authenticated channel and refuse a
// mismatch; there is deliberately no `edition` member, because a Community
// build claiming Enterprise would defeat exactly the over-advertising rule that
// exists to catch it. The identity binding itself is the caller's
// responsibility and is done in the agent, where the authenticated channel is.

// PEPHandshakeHeader is the request header a declaration rides on.
//
// A HEADER rather than a body member because one governed route
// (/api/v1/access/evaluation) carries the standardised AuthZEN envelope, which
// this platform does not own and which already refuses caller-supplied
// properties by JSON Pointer. A body member would therefore need a second
// carrier for that plane, and two carriers for one fact is the drift this
// design exists to prevent.
const PEPHandshakeHeader = "X-Axonflow-PEP-Handshake"

// PEPHandshakeProfileV1 is the only handshake profile this build accepts.
//
// Matched by EXACT EQUALITY, never as a floor or a range. A build that cannot
// read the named profile must not answer as though negotiation succeeded; that
// is the same rule, for the same reason, as the 406 on an un-emittable
// X-Axonflow-AuthZEN-Profile.
const PEPHandshakeProfileV1 = 1

const (
	// MaxPEPHandshakeBytes bounds the base64 header value.
	//
	// THE TWO CAPS INTERACT AND THE PRECEDENCE IS FIXED: this one is checked
	// FIRST, on the raw header, before anything is decoded. So a document that
	// is both over-long and over-count is reported as over-long. That ordering
	// is not arbitrary - the length check is the only one that can run before
	// the platform has spent a base64 decode and a JSON parse on a hostile
	// input.
	//
	// 4096 is chosen so the COUNT cap below is reachable for realistic
	// declarations rather than shadowed by this one: 64 entries at the median
	// declared type name decode to roughly 2.4 KiB, which is about 3.2 KiB of
	// base64. At the LONGEST declared type name (step_up_authentication) the
	// byte cap fires first, which is the stated precedence rather than a gap.
	MaxPEPHandshakeBytes = 4096
	// MaxPEPHandshakeCapabilities bounds the declared set.
	//
	// 64 is above the 14 declared obligation types with room for several live
	// schema versions each - counted from contract.AllObligationTypes rather
	// than remembered, because a bound derived from a number nobody rechecked
	// is a bound that silently stops being a bound.
	//
	// Exceeding it REFUSES rather than truncating, which is the opposite of
	// what the #2958 seam list does with its surplus - and deliberately.
	// Dropping a seam capability can only make a caller look LESS capable,
	// which routes to the org's fallback posture. Dropping a handshake
	// capability makes the enforcement point look less capable too, but here
	// that produces a DENY, so a silent truncation would be a refusal the
	// operator cannot see the cause of.
	MaxPEPHandshakeCapabilities = 64
	// maxPEPHandshakeIdentifier bounds pep_id and audience before either can
	// reach a log line.
	maxPEPHandshakeIdentifier = 128
)

// pepIdentifierPattern and pepAudiencePattern bound what may appear in the two
// free-text members.
//
// THE COLON IS EXCLUDED FROM AN IDENTIFIER AND THAT IS THE POINT. `pep_id` is a
// name INSIDE the caller's credential namespace; the platform's identifier for
// the enforcement point is built by prefixing it with the authenticated
// credential, and `:` is that construction's separator. Admitting a colon would
// let a caller write `plane:decide` and have it appear inside an identifier
// that every log line, metric and capability refusal renders as text - not an
// impersonation, because the credential prefix is still there, but an
// identifier no string search can disambiguate from a real in-process plane.
//
// Lower-case, because the name is compared and rendered rather than displayed,
// and a case-folding rule would be a second rule to get wrong. The audience is
// NOT lower-cased: it is an opaque value some other system chose, and
// normalising it would change what a proof is bound to.
//
// THE AUDIENCE ADMITS `/` AND THE IDENTIFIER DOES NOT, and the asymmetry is the
// point rather than an oversight. The colon is excluded from an identifier
// because it is the SEPARATOR of the composed `client:<credential>:<name>`; the
// audience is composed into nothing, so no character in it can be mistaken for
// structure. And a URI is the canonical audience form in practice - RFC 8707
// resource indicators, every OAuth deployment - so refusing `/` would have made
// the most natural value unusable. It was: the first version excluded it, and
// an operator configuring `https://api.example.com` got a gateway adapter that
// refused to start with an error about a "capability handshake".
var (
	pepIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	pepAudiencePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
)

// PEPHandshake is what an external enforcement point declares about itself.
type PEPHandshake struct {
	// ProfileVersion is the handshake profile. Exactly PEPHandshakeProfileV1.
	ProfileVersion int `json:"profile_version"`
	// PEPID names this enforcement point WITHIN the caller's credential.
	//
	// It is not the platform's identifier and a caller cannot supply that one.
	// The platform builds `client:<authenticated credential>:<pep_id>`, so the
	// namespace is server-owned and the caller chooses only a name inside it -
	// the same shape as a path inside a chroot. Two consequences, both
	// deliberate:
	//
	//   - Naming ANOTHER credential's enforcement point is structurally
	//     impossible rather than refused by a comparison. There is no input
	//     that reaches the prefix.
	//   - Two enforcement points behind ONE credential are distinguishable. The
	//     gateway adapters are the case that forces this: `GateRequest` is
	//     body-capable and `Decide` is headers-only, and they are the same
	//     process authenticating with the same credential and declaring
	//     different capability sets.
	//
	// The alternative - carrying the full identifier and refusing a mismatch -
	// was rejected because it requires every client to PREDICT the server's own
	// derivation of the authenticated identity, which differs by auth path. A
	// contract a correct client cannot satisfy without guessing is not a
	// contract.
	PEPID string `json:"pep_id"`
	// Audience is the audience this enforcement point expects a decision proof
	// to be bound to. It is recorded and bound; it authorises nothing. Whether
	// an audience may be minted for is the Decision Proof Service's decision.
	Audience string `json:"audience"`
	// Capabilities is the EXACT set of obligation types and schema versions
	// this enforcement point can discharge.
	//
	// An empty set is a legitimate declaration and is NOT the same as an
	// absent member; see the file comment. It is non-nil after a successful
	// decode of `[]` so that a caller re-encoding the value cannot turn
	// "declares nothing" back into "declared nothing at all".
	Capabilities []Capability `json:"capabilities"`
}

// HandshakeRefusal is the typed refusal for a handshake that cannot be used.
//
// It carries an RFC 6901 JSON Pointer so an adapter rendering a wire refusal
// can name the offending member instead of parsing prose, and it carries one of
// the contract's EXISTING ReasonCode values rather than introducing a second
// refusal vocabulary.
//
// BOTH ARE REACHED THROUGH ACCESSORS, because a struct field a caller is told
// it "can branch on" and which nothing reads is a promise the type does not
// keep - the first version of this file shipped exactly that, and the wire
// carried four new reason STRINGS while the ReasonCode never left the struct.
// platform/agent carries BOTH onto its own resolution and out to the caller;
// the pointer is the machine fact the AuthZEN plane needs, where the surface's
// own error code cannot tell a malformed HEADER from a malformed body ENVELOPE.
//
// It is deliberately NOT a MissingMemberError. That type's Shape is a Schema of
// the PUBLISHED contract document, which is vendored byte-identically into five
// SDKs and describes decision-plane shapes; the handshake is a transport header
// that document does not describe. Adding a Schema value for it would either
// state that the document contains a definition it does not, or force a schema
// version bump across five repositories for a header.
type HandshakeRefusal struct {
	// Pointer names the offending member, or is empty when the document itself
	// is at fault (not base64, not JSON, too long).
	Pointer string
	// Reason is the contract reason code a caller branches on.
	Reason ReasonCode
	// Detail is the operator-facing explanation.
	Detail string
}

// Error names the HEADER, not just the member.
//
// It has to, because of where this string ends up. A refusal raised on
// /api/v1/decide is delegated from /api/v1/access/evaluation, and that surface
// renders any 4xx from the evaluator as ErrIncompleteEvaluation carrying this
// text - so on the AuthZEN plane the prose is the ONLY thing distinguishing "the
// handshake header was malformed" from "the body envelope was malformed". A
// message that named only "/capabilities" would send an operator to look at the
// envelope, which has no such member.
// ReasonCode returns the contract reason code for this refusal, or
// ReasonInvalidInput for a nil receiver.
//
// A nil receiver answers with the refusing code rather than the empty string,
// because the one caller that could hold a nil here is one that did not check
// for a refusal - and a caller that skipped the check must not be handed a
// value that reads as "no problem".
func (e *HandshakeRefusal) ReasonCode() ReasonCode {
	if e == nil || e.Reason == "" {
		return ReasonInvalidInput
	}
	return e.Reason
}

// MemberPointer returns the RFC 6901 pointer at fault, empty when the document
// itself is.
func (e *HandshakeRefusal) MemberPointer() string {
	if e == nil {
		return ""
	}
	return e.Pointer
}

func (e *HandshakeRefusal) Error() string {
	if e == nil {
		return "<nil handshake refusal>"
	}
	if e.Pointer == "" {
		return fmt.Sprintf("%s: %s", PEPHandshakeHeader, e.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", PEPHandshakeHeader, e.Pointer, e.Detail)
}

func refuse(pointer string, reason ReasonCode, format string, args ...any) *HandshakeRefusal {
	return &HandshakeRefusal{Pointer: pointer, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// pepHandshakeWire is the presence-preserving decode of a PEPHandshake.
//
// EVERY member is a json.RawMessage, not only the one whose absence is
// load-bearing. A member decoded straight into its Go type reports an omission
// as its zero value, and the refusal would then send the caller looking for a
// member that is not in the document at all - which is the one thing a
// presence-sensitive decoder must never do. Making all four uniform also means
// the next member added cannot be the one that forgot.
type pepHandshakeWire struct {
	ProfileVersion json.RawMessage `json:"profile_version"`
	PEPID          json.RawMessage `json:"pep_id"`
	Audience       json.RawMessage `json:"audience"`
	Capabilities   json.RawMessage `json:"capabilities"`
}

// DecodePEPHandshake decodes and validates one header value.
//
// The returned refusal is non-nil for EVERY input that is not a usable
// handshake. There is no path that returns a zero handshake and a nil refusal,
// because a caller reading such a pair would see an enforcement point that
// declared nothing rather than one whose declaration could not be read - the
// silent degrade-to-legacy this whole change exists to prevent.
func DecodePEPHandshake(headerValue string) (PEPHandshake, *HandshakeRefusal) {
	var out PEPHandshake
	if headerValue == "" {
		return out, refuse("", ReasonInvalidInput,
			"the %s header is present and empty; an enforcement point that has nothing to declare omits the header, and one that discharges nothing declares an empty capability list",
			PEPHandshakeHeader)
	}
	if len(headerValue) > MaxPEPHandshakeBytes {
		return out, refuse("", ReasonInvalidInput,
			"the %s header is %d bytes; this build reads at most %d",
			PEPHandshakeHeader, len(headerValue), MaxPEPHandshakeBytes)
	}
	raw, err := decodeHandshakeBase64(headerValue)
	if err != nil {
		return out, refuse("", ReasonInvalidInput,
			"the %s header is not base64: %v", PEPHandshakeHeader, err)
	}
	// A literal `null` document decodes into the struct WITHOUT error and
	// leaves every member absent, so it would otherwise be reported as
	// "/profile_version is absent" - true, but it sends the caller looking at a
	// member of a document that is not an object at all.
	if string(bytes.TrimSpace(raw)) == "null" {
		return out, refuse("", ReasonInvalidInput,
			"the %s header decodes to the literal null rather than a handshake object", PEPHandshakeHeader)
	}
	var w pepHandshakeWire
	// strictDecode is the package's own boundary decoder: it refuses DUPLICATE
	// members (encoding/json silently keeps the last, so a repeated
	// `capabilities` would decode as whichever copy came second) and refuses
	// UNKNOWN members (so a misspelled member is malformed rather than
	// silently absent, which would then read as the permissive value).
	if err := strictDecode(raw, &w); err != nil {
		return out, refuse("", ReasonInvalidInput,
			"the %s header does not decode as a handshake document: %v", PEPHandshakeHeader, err)
	}

	version, ref := decodeHandshakeInt(w.ProfileVersion, "/profile_version")
	if ref != nil {
		return out, ref
	}
	if version != PEPHandshakeProfileV1 {
		return out, refuse("/profile_version", ReasonInvalidInput,
			"the handshake declares profile version %d; this build reads profile version %d only, and matching is exact - answering a profile this build cannot read would report that negotiation succeeded",
			version, PEPHandshakeProfileV1)
	}

	pepID, ref := decodeHandshakeString(w.PEPID, "/pep_id")
	if ref != nil {
		return out, ref
	}
	if len(pepID) > maxPEPHandshakeIdentifier {
		return out, refuse("/pep_id", ReasonInvalidInput,
			"pep_id is %d bytes; this build reads at most %d", len(pepID), maxPEPHandshakeIdentifier)
	}
	if !pepIdentifierPattern.MatchString(pepID) {
		return out, refuse("/pep_id", ReasonInvalidInput,
			"pep_id %q is not of the form %s", pepID, pepIdentifierPattern)
	}

	audience, ref := decodeHandshakeString(w.Audience, "/audience")
	if ref != nil {
		return out, ref
	}
	if len(audience) > maxPEPHandshakeIdentifier {
		return out, refuse("/audience", ReasonInvalidInput,
			"audience is %d bytes; this build reads at most %d", len(audience), maxPEPHandshakeIdentifier)
	}
	if !pepAudiencePattern.MatchString(audience) {
		return out, refuse("/audience", ReasonInvalidInput,
			"audience %q is not of the form %s", audience, pepAudiencePattern)
	}

	caps, ref := decodeHandshakeCapabilities(w.Capabilities)
	if ref != nil {
		return out, ref
	}

	out = PEPHandshake{
		ProfileVersion: version,
		PEPID:          pepID,
		Audience:       audience,
		Capabilities:   caps,
	}
	if ref := out.Validate(); ref != nil {
		return PEPHandshake{}, ref
	}
	return out, nil
}

// decodeHandshakeBase64 accepts the URL-safe and the standard alphabet, padded
// or not.
//
// Leniency about the ENCODING and strictness about the SEMANTICS is the right
// split: an implementer reaching for their language's default base64 should not
// get a refusal that looks like a capability problem. What the lenience does
// NOT admit is the failure it is really guarding: RFC 7230 lets an intermediary
// join two repeated header lines with a comma, and a comma is outside every
// base64 alphabet, so a joined pair can only ever decode to malformed. That is
// why the header is base64 at all rather than raw JSON, which would join into a
// syntactically plausible document.
func decodeHandshakeBase64(v string) ([]byte, error) {
	normalized := strings.NewReplacer("-", "+", "_", "/").Replace(v)
	if raw, err := base64.StdEncoding.DecodeString(normalized); err == nil {
		return raw, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(normalized, "="))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// decodeHandshakeInt reads a required integer member, telling absent from null
// from a wrong type.
//
// THE JSON NUMBER TYPE IS PART OF THE CONTRACT, not only the value. Decoding
// into `int` refuses `1.0`, `"1"` and `1e0`, so a serializer that emits an
// integral value as a JSON float gets a refusal naming the member. That is
// deliberate - a document whose types are approximately right is one two
// implementations will read differently - but it is a real interoperability
// edge for a client whose language has a single number type, so it is stated
// here and in the OpenAPI schema rather than discovered in production.
func decodeHandshakeInt(raw json.RawMessage, pointer string) (int, *HandshakeRefusal) {
	if ref := requirePresent(raw, pointer); ref != nil {
		return 0, ref
	}
	var v int
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, refuse(pointer, ReasonInvalidInput, "is not an integer: %v", err)
	}
	return v, nil
}

// decodeHandshakeString reads a required string member.
func decodeHandshakeString(raw json.RawMessage, pointer string) (string, *HandshakeRefusal) {
	if ref := requirePresent(raw, pointer); ref != nil {
		return "", ref
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", refuse(pointer, ReasonInvalidInput, "is not a string: %v", err)
	}
	if v == "" {
		return "", refuse(pointer, ReasonInvalidInput,
			"is present and empty; every handshake member is required and none has an empty reading")
	}
	return v, nil
}

// requirePresent refuses an omitted or null member, and says which it was.
//
// The two are reported differently on purpose. Both decode to nothing, and this
// is the one check whose entire job is to tell presence from absence: telling a
// caller a member is absent when the document plainly carries it as null would
// make the refusal wrong about the only thing it exists to say.
func requirePresent(raw json.RawMessage, pointer string) *HandshakeRefusal {
	if len(raw) == 0 {
		return refuse(pointer, ReasonInvalidInput,
			"is absent from the handshake document; every member is required, and a member that carries no value is not the same as one carrying its zero value")
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return refuse(pointer, ReasonInvalidInput,
			"is present as null; every member is required, and null is not a declaration")
	}
	return nil
}

// decodeHandshakeCapabilities reads the required capability list.
//
// THE LOAD-BEARING FUNCTION OF THIS FILE. An omitted `capabilities` is
// MALFORMED and `[]` is a declaration, and the two must never collapse; see the
// file comment for why the collapse is the defect rather than a nicety.
func decodeHandshakeCapabilities(raw json.RawMessage) ([]Capability, *HandshakeRefusal) {
	if ref := requirePresent(raw, "/capabilities"); ref != nil {
		return nil, ref
	}
	// strictDecode, NOT json.Unmarshal, and the difference is a real hole this
	// closed. The enclosing document is decoded with DisallowUnknownFields, but
	// `capabilities` is a json.RawMessage, so that decoder never descends into
	// it: `{"type":"field_redact","version":1,"edition":"enterprise"}` was
	// ACCEPTED while the same member at the top level was REFUSED. Strictness
	// that stops one syntactic level down is strictness a caller reaches by
	// nesting, and "a PEP may not declare its own edition" has to hold at every
	// depth or it holds nowhere.
	var list []Capability
	if err := strictDecode(raw, &list); err != nil {
		return nil, refuse("/capabilities", ReasonInvalidInput,
			"is not a list of {type, version} objects: %v", err)
	}
	if len(list) > MaxPEPHandshakeCapabilities {
		return nil, refuse("/capabilities", ReasonInvalidInput,
			"declares %d capabilities; this build reads at most %d, and a surplus is refused rather than truncated because a truncated declaration produces a denial whose cause the operator cannot see",
			len(list), MaxPEPHandshakeCapabilities)
	}
	// Non-nil for the empty case. A nil slice would re-encode as an ABSENT
	// member, which would turn "declares nothing" back into "declared nothing
	// at all" on the next hop.
	if list == nil {
		list = []Capability{}
	}
	return SortCapabilities(list), nil
}

// Validate checks a handshake's members against the closed vocabularies.
//
// It is separate from DecodePEPHandshake so that a handshake constructed in Go
// - by a client building one to send, or by a test - is held to the same rules
// as one that arrived on the wire. A validator reachable only through the
// decoder is a validator the sending side does not have.
func (h PEPHandshake) Validate() *HandshakeRefusal {
	if h.ProfileVersion != PEPHandshakeProfileV1 {
		return refuse("/profile_version", ReasonInvalidInput,
			"is %d; this build declares profile version %d and matching is exact",
			h.ProfileVersion, PEPHandshakeProfileV1)
	}
	if h.PEPID == "" || len(h.PEPID) > maxPEPHandshakeIdentifier || !pepIdentifierPattern.MatchString(h.PEPID) {
		return refuse("/pep_id", ReasonInvalidInput,
			"%q is not a well-formed enforcement point identifier of at most %d bytes",
			h.PEPID, maxPEPHandshakeIdentifier)
	}
	if h.Audience == "" || len(h.Audience) > maxPEPHandshakeIdentifier || !pepAudiencePattern.MatchString(h.Audience) {
		return refuse("/audience", ReasonInvalidInput,
			"%q is not a well-formed audience of at most %d bytes",
			h.Audience, maxPEPHandshakeIdentifier)
	}
	if h.Capabilities == nil {
		return refuse("/capabilities", ReasonInvalidInput,
			"is absent; a handshake exists to declare capabilities, and an enforcement point that discharges nothing declares an empty list rather than omitting the member")
	}
	if len(h.Capabilities) > MaxPEPHandshakeCapabilities {
		return refuse("/capabilities", ReasonInvalidInput,
			"declares %d capabilities; this build reads at most %d",
			len(h.Capabilities), MaxPEPHandshakeCapabilities)
	}
	declared := map[ObligationType]bool{}
	for _, t := range AllObligationTypes() {
		declared[t] = true
	}
	seen := map[Capability]bool{}
	for _, c := range SortCapabilities(h.Capabilities) {
		if !declared[c.Type] {
			return refuse("/capabilities", ReasonInvalidInput,
				"names obligation type %q, which this build does not declare; a capability this build cannot name is one it cannot match, and accepting it would let an enforcement point appear capable of something neither side can identify",
				c.Type)
		}
		if c.Version <= 0 {
			// The same trap validateCapabilities closes in the registry:
			// matching is exact, so a capability at version 0 would be
			// satisfied by an obligation whose schema version nobody set, and
			// two unset fields agreeing is not evidence of anything.
			return refuse("/capabilities", ReasonInvalidInput,
				"declares %q at version %d; matching is exact, so a non-positive version would be satisfied only by an obligation whose version was never set",
				c.Type, c.Version)
		}
		if seen[c] {
			return refuse("/capabilities", ReasonInvalidInput,
				"declares %q at version %d more than once; a repeated capability is a construction defect, and accepting it would make the declared count disagree with the distinct one",
				c.Type, c.Version)
		}
		seen[c] = true
	}
	return nil
}

// Profile projects the handshake onto the enforcement profile the obligation
// algebra already consults, so what a PEP declared and what a decision is
// composed against are one table rendered twice.
func (h PEPHandshake) Profile() *PEPProfile {
	return &PEPProfile{ID: h.PEPID, Capabilities: SortCapabilities(h.Capabilities)}
}

// Encode renders a handshake as the header value.
//
// It is exported because the sending side needs it and because a test that
// hand-rolled the encoding would be testing its own encoder rather than this
// one. It validates first: an invalid handshake that encoded successfully would
// be a client shipping bytes the server is certain to refuse.
func (h PEPHandshake) Encode() (string, *HandshakeRefusal) {
	if ref := h.Validate(); ref != nil {
		return "", ref
	}
	// Marshalled from the canonical form so two clients declaring the same set
	// in a different order send the same bytes.
	raw, err := json.Marshal(PEPHandshake{
		ProfileVersion: h.ProfileVersion,
		PEPID:          h.PEPID,
		Audience:       h.Audience,
		Capabilities:   SortCapabilities(h.Capabilities),
	})
	if err != nil {
		return "", refuse("", ReasonInvalidInput, "could not be encoded: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > MaxPEPHandshakeBytes {
		return "", refuse("", ReasonInvalidInput,
			"encodes to %d bytes; the header carries at most %d", len(encoded), MaxPEPHandshakeBytes)
	}
	return encoded, nil
}

// SortCapabilities returns a NON-NIL copy in canonical (type, version) order.
//
// One implementation. The registry, the legacy plane fixture and this file all
// need the same order, and three copies of a comparator is three chances for
// one of them to disagree about what "canonical" means - which would show up as
// a capability set that hashes differently depending on which package sorted
// it. The copy is deliberate: sorting a caller's slice in place would reorder a
// PEPRecord's stored capabilities through an aliased backing array.
//
// make+copy rather than `append(nil, in...)`, and that is not style. Appending
// zero elements to a nil slice yields NIL, so an explicitly-empty capability
// set - the whole point of CapabilityDeclaredNone - would come back nil from
// the one function every caller routes it through, re-encode as an ABSENT
// member on the next hop, and collapse "declares nothing" back into "declared
// nothing at all". That is precisely the #2958 defect, reintroduced by a sort.
func SortCapabilities(in []Capability) []Capability {
	out := make([]Capability, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Version < out[j].Version
	})
	return out
}
