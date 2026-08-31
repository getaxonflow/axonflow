package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// CanonicalJSON renders a value as canonical JSON for CROSS-GATEWAY AGREEMENT.
//
// ADR-065 requires that collections are normalized, sorted and duplicate-free
// before hashing and that canonicalization fixes key order, number
// representation, unicode normalization and whitespace. Anything less and two
// gateways that agree on a decision disagree on its digest, which breaks
// replay, decision binding and cross-plane equivalence at the same time.
//
// It applies Unicode NFC normalization, which is correct HERE and wrong for
// artifact integrity. Two strings that differ only in Unicode composition are
// the same string as far as two gateways comparing a request are concerned; two
// policy bundles that differ in the bytes a compiler will read are NOT the same
// artifact, however they normalize. Use ExactJSON and ExactDigest to sign or
// pin an artifact. See ExactJSON.
//
// The gateway forwards the bytes it hashed, never a re-serialization.
func CanonicalJSON(v any) ([]byte, error) { return encodeJSON(v, true) }

// ExactJSON renders a value as canonical JSON for ARTIFACT INTEGRITY.
//
// It fixes key order, number representation and whitespace exactly as
// CanonicalJSON does, and it deliberately does NOT normalize Unicode. A
// signature or a content digest has to cover the bytes an evaluator will
// actually read: a signed payload that has been normalized is a signature over
// a projection of the artifact, and any two byte sequences that share the
// projection share the signature. For a policy bundle whose module is compiled
// raw, that is a signature bypass, not a theoretical one.
func ExactJSON(v any) ([]byte, error) { return encodeJSON(v, false) }

func encodeJSON(v any, normalize bool) ([]byte, error) {
	// The UTF-8 check runs BEFORE marshalling, and that ordering is the whole
	// point. encoding/json replaces every invalid byte with the replacement
	// character as it writes, so by the time the encoder below sees a string it
	// is already valid and every distinct invalid sequence of one length has
	// been mapped onto one output. Checking afterwards would be a check that
	// cannot fire.
	if path := firstInvalidUTF8(reflect.ValueOf(v), ""); path != "" {
		return nil, fmt.Errorf("canonical: %s is not valid UTF-8 and cannot be canonically encoded", path)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("canonical: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, tree, normalize); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Digest returns the NFC-normalizing digest of a value, for cross-gateway
// agreement about a request or a decision.
func Digest(v any) (string, error) { return digestWith(v, CanonicalJSON) }

// ExactDigest returns the byte-exact digest of a value, for signing and pinning
// an artifact.
func ExactDigest(v any) (string, error) { return digestWith(v, ExactJSON) }

func digestWith(v any, encode func(any) ([]byte, error)) (string, error) {
	b, err := encode(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// firstInvalidUTF8 walks a value and returns a description of the first string
// it finds that is not valid UTF-8, or the empty string.
func firstInvalidUTF8(v reflect.Value, path string) string {
	if path == "" {
		path = "the value"
	}
	if !v.IsValid() {
		return ""
	}
	// A nil pointer or interface marshals as null and has nothing to inspect.
	// It is checked BEFORE the marshaler branch because a nil pointer whose
	// value type implements the interface still satisfies it, and calling the
	// method on nil panics.
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return ""
		}
	}
	// A type that marshals ITSELF is opaque to the walk below: its fields are
	// not what reaches the encoder, its own output is. json.RawMessage is the
	// ordinary case, and it is a []byte, so without this it would be walked as
	// a slice of integers and any string inside it never seen.
	if v.CanInterface() {
		if m, ok := v.Interface().(json.Marshaler); ok {
			raw, err := m.MarshalJSON()
			if err != nil {
				return ""
			}
			if !utf8.Valid(raw) {
				return path + " (through its own JSON encoding)"
			}
			return ""
		}
		if m, ok := v.Interface().(encoding.TextMarshaler); ok {
			raw, err := m.MarshalText()
			if err != nil {
				return ""
			}
			if !utf8.Valid(raw) {
				return path + " (through its own text encoding)"
			}
			return ""
		}
	}
	switch v.Kind() {
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return path
		}
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return ""
		}
		return firstInvalidUTF8(v.Elem(), path)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return ""
		}
		for i := 0; i < v.Len(); i++ {
			if got := firstInvalidUTF8(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); got != "" {
				return got
			}
		}
	case reflect.Map:
		if v.IsNil() {
			return ""
		}
		for _, k := range v.MapKeys() {
			if k.Kind() == reflect.String && !utf8.ValidString(k.String()) {
				return path + " (an object key)"
			}
			if got := firstInvalidUTF8(v.MapIndex(k), fmt.Sprintf("%s[%v]", path, k)); got != "" {
				return got
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			// An EMBEDDED field of an unexported type is itself unexported,
			// and encoding/json still marshals the exported fields promoted
			// out of it. Skipping on IsExported alone therefore skips fields
			// that do reach the encoder.
			if !f.IsExported() && !f.Anonymous {
				continue
			}
			if got := firstInvalidUTF8(v.Field(i), path+"."+f.Name); got != "" {
				return got
			}
		}
	}
	return ""
}

func writeCanonical(buf *bytes.Buffer, v any, normalize bool) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		return writeCanonicalString(buf, t, normalize)
	case json.Number:
		return writeCanonicalNumber(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e, normalize); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, k, normalize); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k], normalize); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported node type %T", v)
	}
	return nil
}

// writeCanonicalString applies a fixed escaping policy and, for the
// cross-gateway encoder only, Unicode NFC normalization. Without NFC two byte
// sequences that render identically hash differently, which turns a copy-paste
// through a normalizing editor into a decision-binding mismatch.
//
// A string that is not valid UTF-8 is REFUSED rather than encoded. Go's range
// over a string yields U+FFFD for every invalid byte, so encoding one would map
// every distinct invalid sequence of the same length onto one output: "a\xffb"
// and "a\xfeb" would digest identically. A digest whose inputs collide is not a
// digest, and the correct response to an input that cannot be canonically
// represented is to say so rather than to represent it approximately.
func writeCanonicalString(buf *bytes.Buffer, s string, normalize bool) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canonical: string is not valid UTF-8 and cannot be canonically encoded")
	}
	if normalize {
		s = norm.NFC.String(s)
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// writeCanonicalNumber fixes number representation: integers render without a
// decimal point or exponent, and non-integers render in the shortest form that
// round-trips. 1, 1.0 and 1e0 therefore hash identically, which they must,
// because a policy comparing amount_cents against 500000 must not depend on how
// the caller's JSON encoder chose to spell the number.
func writeCanonicalNumber(buf *bytes.Buffer, n json.Number) error {
	if i, err := n.Int64(); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	// Beyond int64 the literal is parsed EXACTLY as a rational and, if it is an
	// integer, printed in plain decimal.
	//
	// Neither a verbatim copy nor a float64 round trip is canonical here, and
	// both were tried. A float collapses adjacent unsigned 64-bit integers, so
	// a quantity would collide with its neighbour. A verbatim copy makes the
	// digest depend on how the caller SPELLED the number: 1e19 and
	// 10000000000000000000 are one value, and one JavaScript-fronted gateway
	// emits the first while a Go one emits the second, so two gateways would
	// disagree about the binding of one request and a legitimate execution
	// would be refused for a mismatch that is a formatting difference.
	rat, ok := new(big.Rat).SetString(n.String())
	if !ok {
		return fmt.Errorf("canonical: number %q is not a valid JSON number", n.String())
	}
	// A bound on magnitude, because an exponent is three characters and the
	// decimal expansion it names is not. An evaluator that allocates a
	// gigabyte to hash one attribute has been handed a denial of service, not
	// a number.
	if exp := len(rat.Num().String()); exp > maxCanonicalDigits {
		return fmt.Errorf("canonical: number %q expands to %d digits, over the %d digit limit",
			n.String(), exp, maxCanonicalDigits)
	}
	if rat.IsInt() {
		buf.WriteString(rat.Num().String())
		return nil
	}
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("canonical: number %q is not representable: %w", n.String(), err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonical: number %q is not finite", n.String())
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

// maxCanonicalDigits bounds the decimal expansion of a number literal.
const maxCanonicalDigits = 4096

// bindingView is the reduced projection of a request that a decision binds to.
//
// It carries digests and safe identifiers, never secrets, full prompt content
// or bearer credentials. Attribute values are reduced to their state, source,
// source version and a digest of the value, so that a decision proof binds what
// the value WAS without republishing it to every proof holder.
type bindingView struct {
	RequestID    string    `json:"request_id"`
	Organization string    `json:"organization"`
	Principal    string    `json:"principal"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource"`
	ActorChain   []string  `json:"actor_chain"`
	Client       string    `json:"client,omitempty"`
	Session      string    `json:"session,omitempty"`
	ToolCall     *ToolCall `json:"tool_call,omitempty"`
	Snapshot     Snapshot  `json:"snapshot"`
	// SharedAttributes and ActorAttributes are separate STRUCTURED fields
	// rather than one flat map keyed by a joined string.
	//
	// A joined key is a collision waiting to happen whenever either operand can
	// contain the separator, and both can here: a SPIFFE subject identifier
	// carries slashes by construction and an attribute path may too. Two
	// different actors then own one map entry, one attribute is overwritten
	// before hashing, and two requests that differ in a principal attribute
	// bind identically. That is the failure this digest exists to prevent.
	SharedAttributes map[string]string  `json:"shared_attributes"`
	ActorAttributes  []actorBindingView `json:"actor_attributes"`
	EvaluatedAt      string             `json:"evaluated_at"`
}

type actorBindingView struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
}

// BindingDigest returns the digest that binds a decision to the exact request
// evaluated: organization, principal, client, session and ordered actor chain;
// action, tool, registry version, arguments digest, resource and attributes;
// and every version in the snapshot.
//
// Hashing tool arguments alone is prohibited as a binding, idempotency or
// reservation key. A reviewer who approved a 300 unit refund has not approved a
// 30000 unit refund, and a binding that covers only the arguments also fails to
// notice that the resource was reparented into a restricted space between
// decision and execution.
func (r *Request) BindingDigest() (string, error) {
	if r == nil {
		return "", fmt.Errorf("request: is nil")
	}
	view := bindingView{
		RequestID:        r.RequestID,
		Organization:     r.Organization.String(),
		Principal:        r.Principal.String(),
		Action:           r.Action.String(),
		Resource:         r.Resource.String(),
		ToolCall:         r.Context.ToolCall,
		Snapshot:         r.Snapshot,
		SharedAttributes: make(map[string]string, len(r.Attributes)),
		EvaluatedAt:      r.EvaluatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
	}
	for _, a := range r.Context.ActorChain {
		view.ActorChain = append(view.ActorChain, a.ID.String())
		hop := actorBindingView{ID: a.ID.String(), Attributes: make(map[string]string, len(a.Attributes))}
		for _, p := range a.Attributes.Paths() {
			digest, err := attributeBindingValue(a.Attributes[p])
			if err != nil {
				return "", fmt.Errorf("request: actor %q attribute %q: %w", a.ID, p, err)
			}
			hop.Attributes[p] = digest
		}
		view.ActorAttributes = append(view.ActorAttributes, hop)
	}
	if r.Context.Client != nil {
		view.Client = r.Context.Client.String()
	}
	if r.Context.Session != nil {
		view.Session = r.Context.Session.String()
	}
	for _, p := range r.Attributes.Paths() {
		digest, err := attributeBindingValue(r.Attributes[p])
		if err != nil {
			return "", fmt.Errorf("request: attribute %q: %w", p, err)
		}
		view.SharedAttributes[p] = digest
	}
	return Digest(view)
}

// Rebind re-checks a decision against the request presented at execution.
//
// A decision that crossed a process boundary is only as good as the input it
// was made on. Between the decision and the execution the caller can change an
// argument, and the resolver can report a different containment: a reviewer who
// approved one operation has not approved another, and a resource that has
// moved into a restricted space is a different resource for policy purposes.
// A mismatch is a DENY, never a re-evaluation, because a proof that does not
// match its request proves nothing about that request.
func Rebind(d *Decision, boundDigest string, req *Request) (*Decision, error) {
	if d == nil {
		return nil, fmt.Errorf("decision: is nil")
	}
	current, err := req.BindingDigest()
	if err != nil {
		return nil, err
	}
	if current == boundDigest {
		return d, nil
	}
	out := *d
	out.Authorization = AuthzDeny
	out.State = StateDeny
	out.Reason = ReasonBindingMismatch
	out.Obligations = nil
	out.Approval = nil
	detail := fmt.Sprintf("the decision was bound to %s and the request presented at execution binds to %s", boundDigest, current)
	if d.Trace != nil {
		t := *d.Trace
		t.State = out.State
		t.Reason = out.Reason
		t.Category = CategoryFor(out.Reason)
		t.Obligations = nil
		t.Remediation = detail
		out.Trace = &t
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// attributeBindingValue reduces one tagged attribute to the string the binding
// digest covers: its state, its unknown reason, its provenance class, its
// source version and a digest of its value. The VALUE itself never enters a
// binding, so a decision proof binds what an attribute was without
// republishing it to everyone who holds the proof.
func attributeBindingValue(a Attribute) (string, error) {
	valueDigest := ""
	if a.State == StateKnown {
		d, err := Digest(a.Value)
		if err != nil {
			return "", err
		}
		valueDigest = d
	}
	return strings.Join([]string{
		string(a.State), string(a.Reason), string(a.Source),
		strconv.FormatInt(a.SourceVersion, 10), valueDigest,
	}, "|"), nil
}
