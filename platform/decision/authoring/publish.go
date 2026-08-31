package authoring

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// PublicationProvenance is everything ADR-065 requires a policy change to
// carry: "every change has source, compiler, schema, bundle, actor, approval,
// and activation provenance".
//
// It is inside the signed view, so none of it is a claim the holder of an
// artifact can rewrite.
type PublicationProvenance struct {
	DocumentID      string        `json:"document_id"`
	DocumentVersion int           `json:"document_version"`
	Root            pdp.Root      `json:"root"`
	Author          contract.ID   `json:"author"`
	Approvers       []contract.ID `json:"approvers"`
	CompilerVersion string        `json:"compiler_version"`
	SchemaVersion   string        `json:"schema_version"`
	EnvelopeVersion string        `json:"envelope_version"`
	HelperDigest    string        `json:"helper_digest"`
	// SourceDigest is the byte-exact digest of the AUTHORING document, which is
	// the artifact a person edits and reads back.
	SourceDigest string `json:"source_digest"`
	// PolicySourceDigest is the byte-exact digest of the compiled policy body,
	// which is what the bundle's own provenance pins. Both are recorded because
	// they answer different questions: one identifies the document a reviewer
	// approved, the other identifies the input the compiler consumed.
	PolicySourceDigest string    `json:"policy_source_digest"`
	BundleDigest       string    `json:"bundle_digest"`
	Supersedes         string    `json:"supersedes,omitempty"`
	PublishedAt        time.Time `json:"published_at"`
}

// artifactView is the exact byte sequence the artifact signature covers.
//
// Source is a STRING rather than an embedded object, and that is a deliberate
// integrity choice rather than a convenience. Embedding the document as JSON
// would put its bytes through a second canonical encoding on every sign and
// every verify, so what the signature covered would be a re-encoding of the
// source rather than the source. Carrying it as an opaque string means the
// signature covers the exact bytes a portal renders back and a compiler reads,
// which is the only version of the claim worth making.
//
// It excludes the artifact digest, the key identifier and the signature, for
// the same reason pdp.Bundle's signed view does: a digest derived from this
// view cannot also be inside it, and a verifier that recomputes the digest can
// then detect an artifact whose advertised digest does not match its content.
type artifactView struct {
	APIVersion string                `json:"api_version"`
	Root       pdp.Root              `json:"root"`
	Source     string                `json:"source"`
	Bundle     *pdp.Bundle           `json:"bundle"`
	Report     GauntletReport        `json:"report"`
	Provenance PublicationProvenance `json:"provenance"`
}

// Artifact is a published, gauntlet-tested, signed, digest-pinned policy
// version.
//
// Every field is unexported and there is no exported constructor other than
// Publish and LoadArtifact. That is the structural answer to "a publication
// path that skips the gauntlet on trusted input": there is no struct literal
// anywhere, in this package or outside it, that produces an Artifact, so there
// is no second path to produce one and no caller who can decide the gauntlet
// was unnecessary this time.
type Artifact struct {
	source     []byte
	bundle     *pdp.Bundle
	report     GauntletReport
	provenance PublicationProvenance
	digest     string
	keyID      string
	signature  []byte
}

// Digest is the artifact's content digest. Activation and rollback name this
// value, never a version number, because a version number can be reused by a
// second author and a content digest cannot.
func (a *Artifact) Digest() string { return a.digest }

// Root is the authority root the artifact was signed under.
func (a *Artifact) Root() pdp.Root { return a.provenance.Root }

// Provenance returns a copy of the publication provenance.
func (a *Artifact) Provenance() PublicationProvenance {
	out := a.provenance
	out.Approvers = append([]contract.ID(nil), a.provenance.Approvers...)
	return out
}

// Report returns the gauntlet evidence the signature covers.
func (a *Artifact) Report() GauntletReport {
	return GauntletReport{Results: append([]GateResult(nil), a.report.Results...)}
}

// Bundle returns the signed policy bundle for activation.
func (a *Artifact) Bundle() *pdp.Bundle { return a.bundle }

// Source returns the exact bytes of the authoring document.
//
// This is "rendered back without loss" as an operation rather than as a
// property: what comes out is what was signed, and the round-trip gate proved
// before signing that it parses, re-renders identically, and recompiles to the
// module in this artifact.
func (a *Artifact) Source() []byte { return append([]byte(nil), a.source...) }

// Document parses the artifact's source back into a typed document.
func (a *Artifact) Document() (*Document, error) { return Parse(a.source) }

func (a *Artifact) view() artifactView {
	return artifactView{
		APIVersion: APIVersion,
		Root:       a.provenance.Root,
		Source:     string(a.source),
		Bundle:     a.bundle,
		Report:     a.report,
		Provenance: a.provenance,
	}
}

// PublishOptions carries everything a publication needs that is not in the
// document.
type PublishOptions struct {
	// Root is the authority root to publish under. It must equal the
	// document's own root: an organization permission document is
	// UNPUBLISHABLE under the system root and a system constraint document is
	// unpublishable under the organization root, which is what "permission and
	// constraint entrypoints read separate signed bundle roots" means in
	// practice.
	Root pdp.Root
	// KeyID and PrivateKey sign both the bundle and the artifact. One key for
	// both, because they are one release: a bundle signed by the system
	// authority inside an artifact signed by the organization authority would
	// be a supply chain with two answers to "who published this".
	KeyID      string
	PrivateKey ed25519.PrivateKey
	// Approvers are the reviewers who signed off on this document version. At
	// least one must differ from the author.
	Approvers []contract.ID
	// Fixtures are the author-declared cases the gauntlet runs.
	Fixtures []Fixture
	// Now stamps the publication. It is an input rather than a call to the
	// clock so that a publication is reproducible from its inputs, which is
	// what lets a test assert on a digest at all.
	Now time.Time
}

// Publish is the ONLY function that produces a signed artifact.
//
// The order is the specification from ADR-065's policy lifecycle and every step
// is load bearing:
//
//  1. validate types, authority, obligations and capabilities, against the
//     catalog, with the full save-time check set;
//  2. compile a deterministic Rego v1 bundle and run the gauntlet against THAT
//     bundle rather than a rebuild of it;
//  3. sign, with provenance covering compiler, schema, helper and source
//     digests;
//  4. pin by digest.
//
// Validation runs here even though NewDocument also runs it, because a document
// can arrive from the wire, from a store or from a migration without ever
// having passed through NewDocument. A guard at the callers is not a guard.
func Publish(ctx context.Context, d *Document, cat *Catalog, opts PublishOptions) (*Artifact, Findings, error) {
	if d == nil {
		return nil, nil, fmt.Errorf("authoring: cannot publish a nil document")
	}
	if opts.Root == "" {
		return nil, nil, fmt.Errorf("authoring: publication declares no authority root")
	}
	if opts.Root != d.Policy.Root {
		// Refused BEFORE anything is compiled or signed. A cross-root
		// publication is not a signature that fails to verify later, it is an
		// operation the control plane does not offer.
		return nil, nil, fmt.Errorf(
			"authoring: refusing to publish a %q document under the %q authority root; the roots are separate signing authorities and neither may publish the other's policy",
			d.Policy.Root, opts.Root)
	}
	if len(opts.PrivateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("authoring: publication requires an ed25519 private key")
	}
	if opts.KeyID == "" {
		return nil, nil, fmt.Errorf("authoring: publication requires a key identifier so a verifier can name the key that signed it")
	}

	findings := Validate(d, cat)
	findings = append(findings, checkSeparationOfDuties(d, opts.Approvers)...)
	findings = findings.sorted()
	if err := findings.Error(); err != nil {
		return nil, findings, err
	}

	source, err := Render(d)
	if err != nil {
		return nil, findings, err
	}
	sourceDigest, err := Digest(d)
	if err != nil {
		return nil, findings, err
	}

	bundle, report, err := runGauntlet(ctx, d, opts.Fixtures)
	if err != nil {
		return nil, findings, err
	}
	// Belt on the report itself before it is signed: a report that does not
	// satisfy its own completeness rule must never reach a signature, or every
	// later verifier is checking a document that was already wrong.
	if err := report.Passed(); err != nil {
		return nil, findings, err
	}
	if err := bundle.Sign(opts.KeyID, opts.PrivateKey); err != nil {
		return nil, findings, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	a := &Artifact{
		source: source,
		bundle: bundle,
		report: report,
		provenance: PublicationProvenance{
			DocumentID:         d.Metadata.DocumentID,
			DocumentVersion:    d.Policy.Version,
			Root:               d.Policy.Root,
			Author:             d.Metadata.Author,
			Approvers:          append([]contract.ID(nil), opts.Approvers...),
			CompilerVersion:    pdp.CompilerVersion,
			SchemaVersion:      contract.SchemaVersion,
			EnvelopeVersion:    APIVersion,
			HelperDigest:       pdp.HelperDigest(),
			SourceDigest:       sourceDigest,
			PolicySourceDigest: bundle.Provenance.SourceDigest,
			BundleDigest:       bundle.Digest,
			Supersedes:         d.Metadata.Supersedes,
			PublishedAt:        now.UTC(),
		},
	}
	digest, err := contract.ExactDigest(a.view())
	if err != nil {
		return nil, findings, fmt.Errorf("authoring: artifact digest: %w", err)
	}
	a.digest = digest
	payload, err := contract.ExactJSON(a.view())
	if err != nil {
		return nil, findings, fmt.Errorf("authoring: artifact signing payload: %w", err)
	}
	a.keyID = opts.KeyID
	a.signature = ed25519.Sign(opts.PrivateKey, payload)
	return a, findings, nil
}

// checkSeparationOfDuties refuses a publication that nobody but the author
// approved.
func checkSeparationOfDuties(d *Document, approvers []contract.ID) Findings {
	for _, ap := range approvers {
		if ap.IsZero() {
			continue
		}
		if ap.String() != d.Metadata.Author.String() {
			return nil
		}
	}
	return Findings{newFinding(CodeApproverIsAuthor, "", fmt.Sprintf(
		"the publication names %d approver(s) and none of them differs from the author %q",
		len(approvers), d.Metadata.Author))}
}

// wireArtifact is the transport form of an artifact.
type wireArtifact struct {
	APIVersion string                `json:"api_version"`
	Source     string                `json:"source"`
	Bundle     *pdp.Bundle           `json:"bundle"`
	Report     GauntletReport        `json:"report"`
	Provenance PublicationProvenance `json:"provenance"`
	Digest     string                `json:"digest"`
	KeyID      string                `json:"key_id"`
	Signature  []byte                `json:"signature"`
}

// MarshalJSON renders the artifact for transport or storage.
func (a *Artifact) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireArtifact{
		APIVersion: APIVersion,
		Source:     string(a.source),
		Bundle:     a.bundle,
		Report:     a.report,
		Provenance: a.provenance,
		Digest:     a.digest,
		KeyID:      a.keyID,
		Signature:  a.signature,
	})
}

// LoadArtifact is the only other way to obtain an Artifact, and it re-derives
// every claim rather than believing one.
//
// It verifies the signature against the trust store for the DECLARED root, so
// an artifact signed by the organization authority and relabelled as system is
// refused; it recomputes the digest; it re-lints the module; it requires every
// declared gate to be present and passed in the signed report; and it
// recompiles the carried source and requires a byte-identical module. That last
// check is the one that closes render-back loss on the load path: without it, an
// artifact whose source had been swapped for a different document would still
// verify, and a portal would render back policy that is not the policy being
// enforced.
func LoadArtifact(raw []byte, trust *pdp.TrustStore) (*Artifact, error) {
	if trust == nil {
		return nil, fmt.Errorf("authoring: loading an artifact requires a trust store")
	}
	var w wireArtifact
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("authoring: the artifact could not be parsed: %w", err)
	}
	if w.APIVersion != APIVersion {
		return nil, fmt.Errorf("authoring: artifact declares api_version %q, this build understands %q", w.APIVersion, APIVersion)
	}
	if w.Bundle == nil {
		return nil, fmt.Errorf("authoring: the artifact carries no bundle")
	}
	a := &Artifact{
		source:     []byte(w.Source),
		bundle:     w.Bundle,
		report:     w.Report,
		provenance: w.Provenance,
		digest:     w.Digest,
		keyID:      w.KeyID,
		signature:  w.Signature,
	}
	if err := a.verify(trust); err != nil {
		return nil, err
	}
	return a, nil
}

// verify re-derives every claim an artifact makes.
func (a *Artifact) verify(trust *pdp.TrustStore) error {
	root := a.provenance.Root
	pub, ok := trust.PublicKey(root, a.keyID)
	if !ok {
		return fmt.Errorf("authoring: key %q is not authorized to publish under the %q authority root", a.keyID, root)
	}
	payload, err := contract.ExactJSON(a.view())
	if err != nil {
		return fmt.Errorf("authoring: artifact verify: %w", err)
	}
	if !ed25519.Verify(pub, payload, a.signature) {
		return fmt.Errorf("authoring: the artifact signature does not verify against key %q for root %q", a.keyID, root)
	}
	digest, err := contract.ExactDigest(a.view())
	if err != nil {
		return fmt.Errorf("authoring: artifact verify digest: %w", err)
	}
	if digest != a.digest {
		return fmt.Errorf("authoring: the artifact advertises digest %s and its content digests to %s", a.digest, digest)
	}
	// The nested bundle is verified by its own signature under the same root,
	// so an artifact cannot carry someone else's bundle.
	if err := trust.Verify(a.bundle); err != nil {
		return fmt.Errorf("authoring: the carried bundle did not verify: %w", err)
	}
	if a.bundle.Root != root {
		return fmt.Errorf("authoring: the artifact declares root %q and carries a %q bundle", root, a.bundle.Root)
	}
	if err := pdp.LintBundleModule(a.bundle.Module, pdp.BundlePackage(a.bundle.Root)); err != nil {
		return fmt.Errorf("authoring: the carried module failed the bundle lint: %w", err)
	}
	if err := a.report.Passed(); err != nil {
		return fmt.Errorf("authoring: the artifact's own gauntlet report refuses it: %w", err)
	}
	doc, err := Parse(a.source)
	if err != nil {
		return fmt.Errorf("authoring: the carried source does not parse: %w", err)
	}
	module, err := pdp.Compile(&doc.Policy)
	if err != nil {
		return fmt.Errorf("authoring: the carried source does not compile: %w", err)
	}
	if module != a.bundle.Module {
		return fmt.Errorf("authoring: the carried source compiles to a different module than the carried bundle, so what renders back is not what is enforced")
	}
	sourceDigest, err := Digest(doc)
	if err != nil {
		return err
	}
	if sourceDigest != a.provenance.SourceDigest {
		return fmt.Errorf("authoring: the carried source digests to %s and the provenance claims %s", sourceDigest, a.provenance.SourceDigest)
	}
	if doc.Policy.Root != root {
		return fmt.Errorf("authoring: the carried source declares root %q and the artifact declares %q", doc.Policy.Root, root)
	}
	if doc.Policy.Version != a.provenance.DocumentVersion {
		return fmt.Errorf("authoring: the carried source is version %d and the provenance claims %d", doc.Policy.Version, a.provenance.DocumentVersion)
	}
	return nil
}
