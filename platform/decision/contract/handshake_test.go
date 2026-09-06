package contract

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// encodeRaw renders an arbitrary JSON document as a header value, bypassing
// PEPHandshake.Encode.
//
// The tests below need to send documents Encode would REFUSE to produce - a
// missing member, an unknown member, a duplicate key. Going through Encode
// would make every negative case untestable, and a test that can only construct
// valid inputs proves nothing about a validator.
func encodeRaw(t *testing.T, doc string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(doc))
}

func validHandshakeDoc() string {
	return `{"profile_version":1,"pep_id":"sdk-go","audience":"axonflow-decision-proof",` +
		`"capabilities":[{"type":"field_redact","version":1}]}`
}

// TestAbsentCapabilitiesMemberIsMalformedAndEmptyIsADeclaration is the
// load-bearing case of the whole handshake.
//
// The #2958 defect it corrects: an enforcement point advertising an empty set
// was byte-identical on the wire to one that advertised nothing. Here the two
// are different bytes AND different outcomes, and neither is the other's
// fallback.
//
// MUTANT: change pepHandshakeWire.Capabilities from json.RawMessage to
// []Capability, or change requirePresent's `len(raw) == 0` guard to accept -
// the omitted case stops being malformed and reads as an empty declaration,
// and the first subtest dies.
func TestAbsentCapabilitiesMemberIsMalformedAndEmptyIsADeclaration(t *testing.T) {
	t.Run("omitted is malformed", func(t *testing.T) {
		_, refusal := DecodePEPHandshake(encodeRaw(t,
			`{"profile_version":1,"pep_id":"sdk-go","audience":"aud"}`))
		if refusal == nil {
			t.Fatal("an omitted capabilities member must be REFUSED; reading it as an empty declaration is the #2958 collapse one level down")
		}
		if refusal.Pointer != "/capabilities" {
			t.Errorf("pointer = %q, want /capabilities", refusal.Pointer)
		}
		if !strings.Contains(refusal.Detail, "absent") {
			t.Errorf("detail must say the member is absent, got %q", refusal.Detail)
		}
	})

	t.Run("explicit empty is a declaration", func(t *testing.T) {
		h, refusal := DecodePEPHandshake(encodeRaw(t,
			`{"profile_version":1,"pep_id":"sdk-go","audience":"aud","capabilities":[]}`))
		if refusal != nil {
			t.Fatalf("an explicitly empty capability list is a legitimate declaration, got refusal: %v", refusal)
		}
		if h.Capabilities == nil {
			t.Fatal("a declared-empty set must decode NON-NIL; a nil slice re-encodes as an ABSENT member on the next hop, which is the collapse this test exists to prevent")
		}
		if len(h.Capabilities) != 0 {
			t.Errorf("capabilities = %v, want empty", h.Capabilities)
		}
		// And it survives a round trip through JSON as `[]`, not as null.
		raw, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"capabilities":[]`) {
			t.Errorf("a declared-empty set must re-encode as [], got %s", raw)
		}
	})

	t.Run("null is refused and named as null", func(t *testing.T) {
		// A distinct byte sequence from both of the above, and the refusal must
		// not claim the member is absent when the document plainly carries it.
		_, refusal := DecodePEPHandshake(encodeRaw(t,
			`{"profile_version":1,"pep_id":"sdk-go","audience":"aud","capabilities":null}`))
		if refusal == nil {
			t.Fatal("a null capabilities member must be refused")
		}
		if !strings.Contains(refusal.Detail, "null") {
			t.Errorf("the refusal must say the member is present as NULL, not absent; got %q", refusal.Detail)
		}
	})
}

// TestSortCapabilitiesNeverReturnsNil pins the property that a one-line change
// to the sort would silently undo.
//
// MUTANT: replace make+copy with `append([]Capability(nil), in...)` - appending
// zero elements to nil yields nil, an explicitly empty set comes back nil from
// the function every caller routes it through, and this test dies.
func TestSortCapabilitiesNeverReturnsNil(t *testing.T) {
	for _, in := range [][]Capability{nil, {}, {{Type: ObFieldRedact, Version: 1}}} {
		if got := SortCapabilities(in); got == nil {
			t.Errorf("SortCapabilities(%v) = nil; an explicitly empty capability set must not become an absent member on the next hop", in)
		}
	}
}

func TestSortCapabilitiesIsCanonicalAndCopies(t *testing.T) {
	in := []Capability{
		{Type: ObImmutableAudit, Version: 2},
		{Type: ObFieldRedact, Version: 2},
		{Type: ObFieldRedact, Version: 1},
	}
	original := append([]Capability(nil), in...)
	got := SortCapabilities(in)
	want := []Capability{
		{Type: ObFieldRedact, Version: 1},
		{Type: ObFieldRedact, Version: 2},
		{Type: ObImmutableAudit, Version: 2},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
	for i := range original {
		if in[i] != original[i] {
			t.Fatalf("the caller's slice was reordered in place: %v", in)
		}
	}
}

// TestProfileVersionIsExactNotAFloor. MUTANT: change the `!=` to `<` in
// DecodePEPHandshake and this dies on the version-2 case.
func TestProfileVersionIsExactNotAFloor(t *testing.T) {
	for _, v := range []string{"0", "2", "-1"} {
		doc := `{"profile_version":` + v + `,"pep_id":"p","audience":"a","capabilities":[]}`
		_, refusal := DecodePEPHandshake(encodeRaw(t, doc))
		if refusal == nil {
			t.Errorf("profile_version %s was accepted; matching is exact, and answering a profile this build cannot read reports that negotiation succeeded", v)
			continue
		}
		if refusal.Pointer != "/profile_version" {
			t.Errorf("profile_version %s: pointer = %q, want /profile_version", v, refusal.Pointer)
		}
	}
	if _, refusal := DecodePEPHandshake(encodeRaw(t, validHandshakeDoc())); refusal != nil {
		t.Fatalf("the control (profile_version 1) was refused: %v", refusal)
	}
}

// TestCapabilityVersionMatchingHasNoFloor pins that a capability at version 0
// is refused rather than becoming a wildcard.
//
// The trap it closes is the one validateCapabilities names in the registry:
// matching is EXACT, so a capability advertised at version 0 would be satisfied
// by an obligation whose schema version nobody set, and two unset fields
// agreeing is not evidence that anything is implemented.
func TestCapabilityVersionMustBePositive(t *testing.T) {
	for _, v := range []string{"0", "-3"} {
		doc := `{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[{"type":"field_redact","version":` + v + `}]}`
		if _, refusal := DecodePEPHandshake(encodeRaw(t, doc)); refusal == nil {
			t.Errorf("a capability at version %s was accepted", v)
		}
	}
}

func TestUndeclaredObligationTypeIsRefused(t *testing.T) {
	doc := `{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[{"type":"teleport_pii","version":1}]}`
	_, refusal := DecodePEPHandshake(encodeRaw(t, doc))
	if refusal == nil {
		t.Fatal("a capability naming a type this build does not declare must be refused; a type it cannot name is one it cannot match")
	}
	if refusal.Pointer != "/capabilities" {
		t.Errorf("pointer = %q, want /capabilities", refusal.Pointer)
	}
}

func TestDuplicateCapabilityIsRefused(t *testing.T) {
	doc := `{"profile_version":1,"pep_id":"p","audience":"a","capabilities":` +
		`[{"type":"field_redact","version":1},{"type":"field_redact","version":1}]}`
	if _, refusal := DecodePEPHandshake(encodeRaw(t, doc)); refusal == nil {
		t.Fatal("a repeated capability must be refused; accepting it makes the declared count disagree with the distinct one")
	}
}

// TestUnknownAndDuplicateMembersAreRefused proves the decoder inherits the
// package's strict boundary rather than rolling its own.
//
// A misspelled member must be MALFORMED and not silently absent, and a repeated
// member must be refused rather than resolved last-wins - two parsers that
// disagree about which copy wins is a live confusion, not a nicety.
func TestUnknownAndDuplicateMembersAreRefused(t *testing.T) {
	t.Run("unknown member", func(t *testing.T) {
		doc := `{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[],"edition":"enterprise"}`
		if _, refusal := DecodePEPHandshake(encodeRaw(t, doc)); refusal == nil {
			t.Fatal("an unknown member must be refused; a PEP may declare what it can DO and never what edition it is")
		}
	})
	t.Run("duplicate member", func(t *testing.T) {
		doc := `{"profile_version":1,"pep_id":"p","audience":"a",` +
			`"capabilities":[{"type":"field_redact","version":1}],"capabilities":[]}`
		if _, refusal := DecodePEPHandshake(encodeRaw(t, doc)); refusal == nil {
			t.Fatal("a repeated member must be refused; encoding/json keeps the LAST silently, so one document would mean two things")
		}
	})
}

func TestEveryRequiredMemberIsRequired(t *testing.T) {
	for _, tc := range []struct{ doc, pointer string }{
		{`{"pep_id":"p","audience":"a","capabilities":[]}`, "/profile_version"},
		{`{"profile_version":1,"audience":"a","capabilities":[]}`, "/pep_id"},
		{`{"profile_version":1,"pep_id":"p","capabilities":[]}`, "/audience"},
		{`{"profile_version":1,"pep_id":"p","audience":"a"}`, "/capabilities"},
	} {
		_, refusal := DecodePEPHandshake(encodeRaw(t, tc.doc))
		if refusal == nil {
			t.Errorf("%s: accepted a document missing %s", tc.doc, tc.pointer)
			continue
		}
		if refusal.Pointer != tc.pointer {
			t.Errorf("%s: pointer = %q, want %q", tc.doc, refusal.Pointer, tc.pointer)
		}
	}
}

// TestPEPIDCannotSmuggleANamespaceSeparator.
//
// pep_id is a name INSIDE the caller's credential namespace and the platform
// builds `client:<credential>:<pep_id>`. A colon in the name would put a string
// like `plane:decide` inside an identifier that every log line, metric and
// capability refusal renders as text - not an impersonation, because the
// credential prefix is still there, but an identifier no string search can
// disambiguate from a real in-process plane.
//
// MUTANT: add `:` back to pepIdentifierPattern and the first two cases die.
func TestPEPIDCannotSmuggleANamespaceSeparator(t *testing.T) {
	for _, id := range []string{"plane:decide", "client:other-org", "Sdk-Go", "-leading", "has space", ""} {
		doc := `{"profile_version":1,"pep_id":"` + id + `","audience":"a","capabilities":[]}`
		if _, refusal := DecodePEPHandshake(encodeRaw(t, doc)); refusal == nil {
			t.Errorf("pep_id %q was accepted", id)
		}
	}
	// Controls: the shapes a real client sends.
	for _, id := range []string{"sdk-go", "gateway-headers-only", "n8n-plugin", "a1._-b"} {
		doc := `{"profile_version":1,"pep_id":"` + id + `","audience":"a","capabilities":[]}`
		if _, refusal := DecodePEPHandshake(encodeRaw(t, doc)); refusal != nil {
			t.Errorf("pep_id %q was refused: %v", id, refusal)
		}
	}
}

func TestAudienceIsBoundedAndNotLowerCased(t *testing.T) {
	// An audience is an opaque value some other system chose; normalising it
	// would change what a proof is bound to.
	doc := `{"profile_version":1,"pep_id":"p","audience":"AxonFlow-Proof:v1","capabilities":[]}`
	h, refusal := DecodePEPHandshake(encodeRaw(t, doc))
	if refusal != nil {
		t.Fatalf("a mixed-case audience must be accepted verbatim: %v", refusal)
	}
	if h.Audience != "AxonFlow-Proof:v1" {
		t.Errorf("audience = %q, want it carried verbatim", h.Audience)
	}
	for _, bad := range []string{"", "has space", strings.Repeat("a", 129)} {
		bad := `{"profile_version":1,"pep_id":"p","audience":"` + bad + `","capabilities":[]}`
		if _, refusal := DecodePEPHandshake(encodeRaw(t, bad)); refusal == nil {
			t.Errorf("audience %q was accepted", bad)
		}
	}
}

func TestTheDocumentItselfCanBeMalformed(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"empty header value", ""},
		{"not base64", "!!!not base64!!!"},
		{"base64 of not-json", base64.RawURLEncoding.EncodeToString([]byte("not json"))},
		{"base64 of a literal null", base64.RawURLEncoding.EncodeToString([]byte("null"))},
		{"base64 of an array", base64.RawURLEncoding.EncodeToString([]byte("[1,2]"))},
		// What RFC 7230 lets an intermediary do to two repeated header lines.
		// A comma is outside every base64 alphabet, so the join can only ever
		// decode to malformed - which is the reason the header carries base64
		// rather than raw JSON, since two raw JSON documents join into
		// something a lenient parser might accept.
		{"comma-joined pair", base64.RawURLEncoding.EncodeToString([]byte(validHandshakeDoc())) + "," +
			base64.RawURLEncoding.EncodeToString([]byte(validHandshakeDoc()))},
		{"over the byte cap", strings.Repeat("A", MaxPEPHandshakeBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, refusal := DecodePEPHandshake(tc.value); refusal == nil {
				t.Fatal("accepted a value that is not a handshake document")
			}
		})
	}
}

// TestCapabilityCountIsRefusedNotTruncated. Truncating would narrow what the
// enforcement point claims, and a narrowed claim produces a denial whose cause
// the operator cannot see.
func TestCapabilityCountIsRefusedNotTruncated(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[`)
	for i := 0; i <= MaxPEPHandshakeCapabilities; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"type":"field_redact","version":`)
		b.WriteString(itoa(i + 1))
		b.WriteString(`}`)
	}
	b.WriteString(`]}`)
	h, refusal := DecodePEPHandshake(encodeRaw(t, b.String()))
	if refusal == nil {
		t.Fatalf("an over-count declaration was accepted with %d capabilities", len(h.Capabilities))
	}
}

func itoa(i int) string {
	raw, _ := json.Marshal(i)
	return string(raw)
}

// TestEncodeDecodeRoundTripsAndRefusesAnInvalidHandshake pins that the sending
// side is held to the same rules as the receiving side. A client that could
// encode a handshake the server is certain to refuse would ship bytes nobody
// can use.
func TestEncodeDecodeRoundTrips(t *testing.T) {
	in := PEPHandshake{
		ProfileVersion: PEPHandshakeProfileV1,
		PEPID:          "sdk-go",
		Audience:       "axonflow-decision-proof",
		Capabilities: []Capability{
			{Type: ObImmutableAudit, Version: 1},
			{Type: ObFieldRedact, Version: 1},
		},
	}
	encoded, refusal := in.Encode()
	if refusal != nil {
		t.Fatalf("encode refused a valid handshake: %v", refusal)
	}
	out, decodeRefusal := DecodePEPHandshake(encoded)
	if decodeRefusal != nil {
		t.Fatalf("decode refused this package's own encoding: %v", decodeRefusal)
	}
	if out.PEPID != in.PEPID || out.Audience != in.Audience || len(out.Capabilities) != 2 {
		t.Fatalf("round trip lost data: %+v", out)
	}
	// Canonical order, so two clients declaring the same set in a different
	// order send the same bytes.
	if out.Capabilities[0].Type != ObFieldRedact {
		t.Errorf("capabilities were not canonically ordered: %v", out.Capabilities)
	}

	bad := PEPHandshake{ProfileVersion: 1, PEPID: "p", Audience: "a"} // nil capabilities
	if _, refusal := bad.Encode(); refusal == nil {
		t.Fatal("Encode must refuse a handshake with no capability list; a client that ships bytes the server is certain to refuse has a defect nobody sees until production")
	}
}

func TestDecodeAcceptsBothBase64Alphabets(t *testing.T) {
	// Leniency about the ENCODING and strictness about the SEMANTICS: an
	// implementer reaching for their language's default base64 must not get a
	// refusal that looks like a capability problem.
	doc := []byte(validHandshakeDoc())
	for _, tc := range []struct{ name, value string }{
		{"raw url", base64.RawURLEncoding.EncodeToString(doc)},
		{"padded url", base64.URLEncoding.EncodeToString(doc)},
		{"raw std", base64.RawStdEncoding.EncodeToString(doc)},
		{"padded std", base64.StdEncoding.EncodeToString(doc)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, refusal := DecodePEPHandshake(tc.value); refusal != nil {
				t.Fatalf("%s encoding was refused: %v", tc.name, refusal)
			}
		})
	}
}

func TestProfileProjectsOntoThePEPProfile(t *testing.T) {
	h := PEPHandshake{
		ProfileVersion: 1, PEPID: "sdk-go", Audience: "aud",
		Capabilities: []Capability{{Type: ObFieldRedact, Version: 1}},
	}
	p := h.Profile()
	if p == nil || p.ID != "sdk-go" {
		t.Fatalf("profile = %+v", p)
	}
	// BOTH DIRECTIONS OF THE VERSION COMPARISON, as a table, because asserting
	// only one of them is inert against the mutant that matters.
	//
	// A test checking only "an advertised v1 does not satisfy v2" SURVIVES
	// `c.Version >= o.SchemaVersion`: 1 >= 2 is false either way, so the
	// comparison is observable ONLY when the ADVERTISED version is the higher
	// one. That gap was real in the first version of this test and was found by
	// running the mutant rather than by reading the test. A PEP claiming v2
	// cannot be assumed to implement v1's semantics any more than the reverse -
	// a transform whose shape changed between versions is wrong in both
	// directions.
	for _, tc := range []struct {
		name       string
		advertised int
		asked      int
		want       bool
	}{
		{"exact at v1", 1, 1, true},
		{"advertised BELOW asked (a >= mutant SURVIVES this one)", 1, 2, false},
		{"advertised ABOVE asked (a >= mutant DIES on this one)", 2, 1, false},
		{"exact at v2", 2, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := PEPHandshake{
				ProfileVersion: 1, PEPID: "sdk-go", Audience: "aud",
				Capabilities: []Capability{{Type: ObFieldRedact, Version: tc.advertised}},
			}.Profile()
			if got := profile.Supports(Obligation{Type: ObFieldRedact, SchemaVersion: tc.asked}); got != tc.want {
				t.Errorf("advertised v%d, asked v%d: Supports = %v, want %v; version matching is EXACT in both directions",
					tc.advertised, tc.asked, got, tc.want)
			}
		})
	}
	if p.Supports(Obligation{Type: ObImmutableAudit, SchemaVersion: 1}) {
		t.Error("an undeclared type must not be supported")
	}
	// A declared-empty projection is an empty profile, never a nil one.
	empty := PEPHandshake{ProfileVersion: 1, PEPID: "p", Audience: "a", Capabilities: []Capability{}}.Profile()
	if empty == nil || empty.Capabilities == nil {
		t.Errorf("a declared-empty handshake must project a profile with an empty, non-nil capability set: %+v", empty)
	}
}

// TestMaxCapabilityCountExceedsTheDeclaredTypeCount derives the bound from the
// vocabulary rather than from a number somebody remembered.
//
// A bound that stops exceeding the thing it bounds is a bound that silently
// stopped being one, and nothing else in the tree would notice.
func TestMaxCapabilityCountExceedsTheDeclaredTypeCount(t *testing.T) {
	types := len(AllObligationTypes())
	if types == 0 {
		t.Fatal("the obligation vocabulary is empty, so this bound cannot be derived")
	}
	if MaxPEPHandshakeCapabilities <= types {
		t.Fatalf("MaxPEPHandshakeCapabilities = %d but the build declares %d obligation types; the cap must leave room for several live schema versions per type",
			MaxPEPHandshakeCapabilities, types)
	}
}

// TestStrictnessDoesNotStopAtTheCapabilityObjectBoundary.
//
// The enclosing document is decoded with DisallowUnknownFields, but
// `capabilities` is a json.RawMessage, so that decoder never descends into it.
// The first version of this file therefore REFUSED `"edition":"enterprise"` at
// the top level and ACCEPTED the identical member one object down - and "a PEP
// may not declare its own edition" is the rule that was being enforced.
//
// Strictness a caller reaches by nesting is strictness that holds nowhere.
//
// MUTANT: change decodeHandshakeCapabilities back to json.Unmarshal and the
// nested cases die while the top-level control keeps passing - which is exactly
// how the hole survived.
func TestStrictnessDoesNotStopAtTheCapabilityObjectBoundary(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{
			"unknown member at the TOP level (the control that already passed)",
			`{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[],"edition":"enterprise"}`,
		},
		{
			"the SAME member one object down",
			`{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[{"type":"field_redact","version":1,"edition":"enterprise"}]}`,
		},
		{
			"a nested member that is merely unrecognised",
			`{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[{"type":"field_redact","version":1,"trust":"high"}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, refusal := DecodePEPHandshake(encodeRaw(t, tc.doc)); refusal == nil {
				t.Fatal("an unknown member was accepted; a PEP may declare what it can DO and never what the platform already knows about it, at every depth")
			}
		})
	}

	// The CONTROL: a well-formed nested object is still accepted, so the check
	// above is about the UNKNOWN member and not about nesting being rejected.
	if _, refusal := DecodePEPHandshake(encodeRaw(t,
		`{"profile_version":1,"pep_id":"p","audience":"a","capabilities":[{"type":"field_redact","version":1}]}`)); refusal != nil {
		t.Fatalf("control failed: a well-formed capability object was refused: %v", refusal)
	}
}

// TestARefusalCarriesAReachableReasonCodeAndPointer.
//
// The type's documentation says a caller can branch on the reason code. The
// first version shipped that sentence with a field nothing read, so the wire
// carried four new reason STRINGS while the ReasonCode never left the struct.
func TestARefusalCarriesAReachableReasonCodeAndPointer(t *testing.T) {
	_, refusal := DecodePEPHandshake(encodeRaw(t, `{"profile_version":1,"pep_id":"p","audience":"a"}`))
	if refusal == nil {
		t.Fatal("fixture invalid: the document was accepted")
	}
	if got := refusal.ReasonCode(); got != ReasonInvalidInput {
		t.Errorf("ReasonCode() = %q, want %q", got, ReasonInvalidInput)
	}
	if got := refusal.MemberPointer(); got != "/capabilities" {
		t.Errorf("MemberPointer() = %q, want /capabilities", got)
	}
	// Every declared reason code must be a real one, so an adapter mapping the
	// refusal onto a wire code cannot receive something the contract does not
	// declare.
	if err := refusal.ReasonCode().Validate(); err != nil {
		t.Errorf("the refusal carries a reason code the contract does not declare: %v", err)
	}

	// A NIL receiver answers with the refusing code, never the empty string: the
	// only caller that reaches it is one that skipped the refusal check, and it
	// must not be handed a value that reads as "no problem".
	var nilRefusal *HandshakeRefusal
	if got := nilRefusal.ReasonCode(); got != ReasonInvalidInput {
		t.Errorf("a nil refusal answered %q; a caller that skipped the check must not read it as success", got)
	}
	if nilRefusal.MemberPointer() != "" {
		t.Error("a nil refusal named a member")
	}
}

// TestEveryWireMemberIsDecodedThroughAStrictBoundaryOrIntoAScalar.
//
// THE CLASS BEHIND ONE FINDING, GUARDED RATHER THAN THE INSTANCE.
//
// `pepHandshakeWire` gives every member a json.RawMessage, so strictDecode's
// DisallowUnknownFields stops at each member's boundary and does not descend.
// Round 1 of review found one consequence: `"edition":"enterprise"` was REFUSED
// at the top level and ACCEPTED inside a capability object, and the rule being
// enforced was "a PEP may not declare its own edition".
//
// The other three members turned out to be safe, and it is worth being exact
// about WHY, because the reason is not the one that would make them stay safe:
// they decode into a scalar (`int`, `string`), and a scalar has no members for
// an unknown one to hide in. That is a property of the TARGET TYPE, not of the
// decoder. The day one of them becomes an object — a structured audience, a
// profile carrying a variant — the gap returns, silently, and nothing else in
// this package would notice.
//
// So this test is DERIVED FROM THE STRUCT by reflection rather than from a hand
// list: a member added to pepHandshakeWire fails here until somebody classifies
// it. A hand list would be a census bounded by its own author.
func TestEveryWireMemberIsDecodedThroughAStrictBoundaryOrIntoAScalar(t *testing.T) {
	// How each member is decoded, and why that is safe. Add a row when you add
	// a member — and if the row would be "composite, plain json.Unmarshal",
	// that is the defect this test exists for, not a row to write.
	const (
		scalar = "decoded into a scalar; a scalar has no members for an unknown one to hide in"
		strict = "decoded through strictDecode, which refuses unknown members at this level too"
	)
	classified := map[string]string{
		"ProfileVersion": scalar,
		"PEPID":          scalar,
		"Audience":       scalar,
		"Capabilities":   strict,
	}

	typ := reflect.TypeOf(pepHandshakeWire{})
	if typ.NumField() == 0 {
		t.Fatal("the wire struct has no members, so this guard asserts nothing")
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if _, ok := classified[f.Name]; !ok {
			t.Errorf("pepHandshakeWire.%s (json %q) is not classified. Every member is a json.RawMessage, so the "+
				"enclosing strict decoder does NOT descend into it: decide whether it is decoded into a scalar "+
				"(safe by type) or through strictDecode (safe by decoder), and say which. A COMPOSITE member "+
				"decoded with a plain json.Unmarshal silently accepts unknown members one level down, which is "+
				"exactly the hole this guard exists for.", f.Name, f.Tag.Get("json"))
		}
	}
	for name := range classified {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("this guard classifies %q, which pepHandshakeWire no longer declares; a stale row makes the "+
				"guard look wider than it is", name)
		}
	}

	// The BEHAVIOURAL half, so the classification above is a claim this test can
	// falsify rather than a comment. An object where each scalar member is
	// expected must be refused, naming that member.
	for _, tc := range []struct{ pointer, doc string }{
		{"/profile_version", `{"profile_version":{"v":1,"edition":"enterprise"},"pep_id":"p","audience":"a","capabilities":[]}`},
		{"/pep_id", `{"profile_version":1,"pep_id":{"name":"p","edition":"enterprise"},"audience":"a","capabilities":[]}`},
		{"/audience", `{"profile_version":1,"pep_id":"p","audience":{"aud":"a","edition":"enterprise"},"capabilities":[]}`},
	} {
		t.Run("object where "+tc.pointer+" expects a scalar", func(t *testing.T) {
			_, refusal := DecodePEPHandshake(encodeRaw(t, tc.doc))
			if refusal == nil {
				t.Fatal("an object was accepted where a scalar is declared, so an unknown member CAN hide one level down here")
			}
			if refusal.MemberPointer() != tc.pointer {
				t.Errorf("refusal named %q, want %q", refusal.MemberPointer(), tc.pointer)
			}
		})
	}
}

// TestAnAudienceMayBeAURIButAnIdentifierMayNotCarryTheSeparator.
//
// The asymmetry between the two patterns is deliberate and worth pinning
// together, because reading either in isolation makes it look arbitrary: the
// identifier excludes `:` because that is the separator of the composed
// `client:<credential>:<name>`, and the audience is composed into nothing, so
// no character in it can be mistaken for structure.
//
// The `/` case is a real interoperability edge, not a hypothetical: a URI is
// the canonical audience form (RFC 8707 resource indicators), and the first
// version of this pattern refused it — so an operator configuring
// `AXONFLOW_PEP_AUDIENCE=https://api.example.com` got a gateway adapter that
// refused to start with an error about a "capability handshake".
func TestAnAudienceMayBeAURIButAnIdentifierMayNotCarryTheSeparator(t *testing.T) {
	for _, aud := range []string{
		"https://api.example.com",
		"https://api.example.com/v1/resource",
		"urn:axonflow:prod",
		"acme/prod",
		"axonflow-decision-proof",
	} {
		h := PEPHandshake{ProfileVersion: 1, PEPID: "sdk-go", Audience: aud, Capabilities: []Capability{}}
		if refusal := h.Validate(); refusal != nil {
			t.Errorf("audience %q was refused: %v", aud, refusal.Detail)
		}
	}
	// Still bounded: whitespace, control characters and an over-long value are
	// refused, so admitting `/` did not open the member up.
	for _, aud := range []string{"", "has space", "has\ttab", "/leading-slash", strings.Repeat("a", 129)} {
		h := PEPHandshake{ProfileVersion: 1, PEPID: "sdk-go", Audience: aud, Capabilities: []Capability{}}
		if refusal := h.Validate(); refusal == nil {
			t.Errorf("audience %q was accepted", aud)
		}
	}
	// The IDENTIFIER still refuses the separator, and now also `/` - it is
	// composed into a namespace and every character in it is structure.
	for _, id := range []string{"plane:decide", "acme/sdk-go"} {
		h := PEPHandshake{ProfileVersion: 1, PEPID: id, Audience: "aud", Capabilities: []Capability{}}
		if refusal := h.Validate(); refusal == nil {
			t.Errorf("pep_id %q was accepted; the identifier is composed and must carry no structure of its own", id)
		}
	}
}
