package authoring

import (
	"bytes"
	"encoding/json"
	"fmt"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// APIVersion is the version of the authoring ENVELOPE. It is distinct from
// contract.SchemaVersion, which versions the decision contract, and from
// Document.Policy.Version, which is the author's own revision number.
//
// Three versions sounds like two too many until one of them has to move. The
// envelope changes when the authoring API grows a field; the contract changes
// when a decision or an obligation changes shape; the document version changes
// every time a person edits a policy. Folding any pair together would make one
// of those events force a false claim about the other.
const APIVersion = "authoring.axonflow.com/v1"

// Metadata is the authoring envelope: who wrote this document, what it is
// called, and which version of it this one was edited from.
//
// It deliberately does NOT carry the approver. An approver is a fact about a
// publication, not about a document: the same document can be published to
// staging by one approver and promoted to production by another, and recording
// the approver in the signed source would make the source change when nothing
// about the policy did.
type Metadata struct {
	// DocumentID is the stable identity of this document across versions. A
	// document is the unit of authorship for one authority root, so a version
	// bump changes Policy.Version and never this.
	DocumentID string `json:"document_id"`
	// Title is operator-facing.
	Title string `json:"title"`
	// Author is the principal that saved this version, in canonical identifier
	// form. It is carried in the SIGNED source rather than beside it because
	// separation of duties is checked against it at publication, and an
	// authorship claim that is not covered by the signature is a claim anyone
	// holding the artifact can rewrite.
	Author contract.ID `json:"author"`
	// Supersedes is the artifact digest this version was edited from, and is
	// empty only for the first version of a document. It is a DIGEST rather
	// than a version number so that "edited from" names an exact artifact: two
	// authors who both start from version 4 and both save version 5 produce
	// documents that agree on the number and disagree on the parent, and the
	// publication path can see that.
	Supersedes string `json:"supersedes,omitempty"`
}

// Document is one versioned typed authoring document.
//
// Policy is a pdp.Document carried verbatim. This layer adds an envelope and
// never restates the policy vocabulary: adding a field to pdp.Policy makes it
// authorable, renderable, publishable and diffable here with no change to this
// file, and there is no second list for a server switch and a portal control to
// drift apart across.
type Document struct {
	APIVersion string       `json:"api_version"`
	Metadata   Metadata     `json:"metadata"`
	Policy     pdp.Document `json:"policy"`
}

// Version is the author's revision number for this document.
func (d *Document) Version() int {
	if d == nil {
		return 0
	}
	return d.Policy.Version
}

// Root is the authority root this document publishes under.
func (d *Document) Root() pdp.Root {
	if d == nil {
		return ""
	}
	return d.Policy.Root
}

// NewDocument builds a validated authoring document.
//
// It is the only constructor, and it does three things a caller must not be
// trusted to remember: it stamps the envelope version, it DERIVES the realm
// interactivity the compiled bundle has to carry from the catalog rather than
// letting the caller assert it, and it validates. A document that comes back
// non-nil has passed every save-time rejection.
//
// Findings are returned alongside the error rather than only inside it, because
// warnings do not block and a portal has to render them next to the saved
// document. On rejection the document is nil and the findings say why, in the
// order a person should read them.
func NewDocument(meta Metadata, policy pdp.Document, cat *Catalog) (*Document, Findings, error) {
	if err := cat.Validate(); err != nil {
		return nil, nil, err
	}
	// The derived copy is written HERE and nowhere else. See
	// Catalog.InteractiveRealms for why the copy exists at all and
	// CodeCatalogDisagreement for what stops it drifting.
	policy.InteractiveRealms = cat.InteractiveRealms()
	d := &Document{APIVersion: APIVersion, Metadata: meta, Policy: policy}
	findings := Validate(d, cat)
	if err := findings.Error(); err != nil {
		return nil, findings, err
	}
	return d, findings, nil
}

// Render returns the byte-exact canonical encoding of a document.
//
// It uses contract.ExactJSON, not contract.CanonicalJSON, and the difference is
// a security property rather than a preference. CanonicalJSON applies Unicode
// NFC normalization, which is correct when two gateways are agreeing about one
// request and wrong for an artifact: two documents that differ in the bytes a
// compiler will read are different artifacts however they normalize. A digest
// over a normalized projection is satisfied by every byte sequence sharing that
// projection, so a two-byte edit inside a string literal could flip a
// constraint from MATCH to NO_MATCH while the document still verified against
// its signature and its digest.
func Render(d *Document) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("authoring: cannot render a nil document")
	}
	return contract.ExactJSON(d)
}

// Digest returns the byte-exact digest of a document. It is the identity a
// publication binds to and the value Metadata.Supersedes names.
func Digest(d *Document) (string, error) {
	if d == nil {
		return "", fmt.Errorf("authoring: cannot digest a nil document")
	}
	return contract.ExactDigest(d)
}

// Parse decodes a rendered document.
//
// Two decoder settings are load bearing.
//
// UseNumber keeps every numeric literal exactly as written. Without it a policy
// bound such as 4611686018427387904 decodes into a float64, loses its low bits,
// and re-renders as a DIFFERENT number: the document would round trip through
// the API with a silently changed limit, which is the precise class of loss
// "rendered back without loss" exists to forbid.
//
// DisallowUnknownFields refuses a field the model does not declare. A document
// carrying a field this build ignores is a document whose author believes
// something is in force that is not, and accepting it would make the round trip
// lossy in the direction nobody checks.
func Parse(raw []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("authoring: the document could not be parsed: %w", err)
	}
	// A second value in the stream would mean the caller handed over more than
	// one document and only the first was read.
	if dec.More() {
		return nil, fmt.Errorf("authoring: the input carries more than one JSON document")
	}
	if d.APIVersion != APIVersion {
		return nil, fmt.Errorf("authoring: document declares api_version %q, this build understands %q", d.APIVersion, APIVersion)
	}
	// The published JSON Schema is enforced HERE, at the wire boundary, and
	// nowhere else.
	//
	// That placement is the whole point of publishing one. The schema exists so
	// a plane that is not this binary, a portal editor or an import tool, knows
	// what a document may contain; a schema that describes the wire format and
	// is never checked at the wire is documentation, and documentation is not a
	// contract. Checking it here also means every path that reads a document
	// from bytes gets it, including artifact loading, without any of them
	// remembering to.
	//
	// It is a SHAPE check and not a substitute for Validate. The schema can say
	// that a condition names an operator; it cannot say that the operator
	// compares caller-supplied input against a trusted term.
	if err := ValidateAgainstSchema(&d); err != nil {
		return nil, err
	}
	return &d, nil
}
