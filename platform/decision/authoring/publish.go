// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	// SelfApprovalReason is the author's stated reason when every approver is
	// the author (PRD v11 §1.12), and empty otherwise. omitempty keeps every
	// artifact published without one byte-identical, and its digest with it.
	SelfApprovalReason string `json:"self_approval_reason,omitempty"`
	CompilerVersion    string `json:"compiler_version"`
	SchemaVersion      string `json:"schema_version"`
	EnvelopeVersion    string `json:"envelope_version"`
	HelperDigest       string `json:"helper_digest"`
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

// KeyID names the key whose signature this artifact carries.
//
// It is exported so a durable store can record WHICH key signed a row it is
// keeping. Without it, a persisted artifact's key identity is legible only by
// re-parsing the stored JSON, and a store that has to re-parse its own rows to
// index them is a store that will eventually index them wrong.
func (a *Artifact) KeyID() string { return a.keyID }

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
	// Profile is the licensed boundary this publication is bound by, and it is
	// REQUIRED. See edition.go for the two facts it carries.
	//
	// It has no default and no zero-value meaning, deliberately. The obvious
	// alternative - an empty Profile meaning "unbounded, as before" - would put
	// the boundary in the caller's hands, and this package's own rule is that a
	// guard at the callers is not a guard: the next caller is the one that will
	// not have it, and here that caller would publish an Enterprise-only
	// construct from a Community deployment while every test still passed. So
	// an unset Profile is a refusal, in the same block as an unset Root and an
	// absent signing key, and every publication states its boundary explicitly.
	//
	// It is the PROFILE and not the Edition since #3956: the duty rule depends
	// on whether the publishing process could establish its tier at all, and
	// an Edition here would have dropped that fact on the floor of this
	// function's own re-derivation.
	Profile Profile
	// Approvers are the reviewers who signed off on this document version.
	//
	// On an edition that carries separation of duties, at least one must differ
	// from the author. Below that floor the list may be empty: PRD 5.3 rules
	// compound approvals and separation of duties None / None / Full, and a
	// single-admin deployment has no second person to name. See
	// separationOfDutiesFloor for what that relaxation does and does not cover.
	Approvers []contract.ID
	// SelfApprovalReason is the author's reason for approving their own
	// publication (PRD v11 §1.12). It is signed into the provenance and written
	// on the audit row. Where separation of duties applies and the deployment
	// grants self-approval it is REQUIRED; on a publication naming any approver
	// other than the author it is refused, because it would record a
	// self-approval that did not happen.
	SelfApprovalReason string
	// selfApprovalGranted is whether the deployment granted this publication
	// self-approval. It is UNEXPORTED so that only API.PublishAdmitting can set
	// it, after asking the transport's SelfApproval: an exported flag would let
	// any caller of Publish grant itself the exception.
	selfApprovalGranted bool
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
	profile := opts.Profile
	if err := profile.validate(); err != nil {
		return nil, nil, fmt.Errorf("authoring: publication declares no usable edition: %w", err)
	}

	findings := Validate(d, cat)
	findings = append(findings, checkApproverIdentifiers(opts.Approvers)...)
	findings = append(findings, checkEditionConstructs(d, profile)...)
	// Separation of duties is an EDITION capability (PRD 5.3, None/None/Full),
	// so the check runs only where the edition carries it. The approver
	// IDENTIFIER check above is not conditional and must not become so: a
	// malformed approver is a malformed approver on every edition, and it is
	// signed into the provenance either way.
	//
	// THE TWO LINES ABOVE ARE THE ASYMMETRY, and they are adjacent on purpose.
	// checkEditionConstructs reads profile.edition, which an unestablished tier
	// folds to Community - fail-SOFT, because losing a construct loses a
	// capability. This line reads RequiresSeparationOfDuties, which an
	// unestablished tier answers true regardless of that same edition -
	// fail-CLOSED, because losing an approver loses a control. One profile,
	// two directions, because the two fallbacks are not the same fallback.
	if profile.RequiresSeparationOfDuties() {
		findings = append(findings, checkSeparationOfDuties(d, opts)...)
	}
	findings = append(findings, checkSelfApprovalReason(d, opts)...)
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
	// RECOMPUTED, not advertised (#3700). This value is signed INTO the
	// artifact's provenance, so recording the advertised one would sign "what
	// the bundle claimed" under a field a reader takes for "the digest of the
	// content". Recomputing makes the artifact's own claim true by
	// construction rather than by the order Publish happens to run in.
	bundleDigest, err := bundle.VerifiedDigest()
	if err != nil {
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
			SelfApprovalReason: strings.TrimSpace(opts.SelfApprovalReason),
			CompilerVersion:    pdp.CompilerVersion,
			SchemaVersion:      contract.SchemaVersion,
			EnvelopeVersion:    APIVersion,
			HelperDigest:       pdp.HelperDigest(),
			SourceDigest:       sourceDigest,
			PolicySourceDigest: bundle.Provenance.SourceDigest,
			BundleDigest:       bundleDigest,
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

// checkApproverIdentifiers refuses a publication whose approvers are not
// well-formed principals of the canonical vocabulary.
//
// THE FIFTH SURFACE (#3711). The four that were enforced first - a request's
// principal, a replay record's, a policy scope and pierceable_by, and an
// authoring document's author - are the ones a reader thinks of. Approvers are
// the one nobody named, and they are the worst of the five to leave open,
// because unlike the others this value is SIGNED: it goes into
// PublicationProvenance and survives LoadArtifact, so a `Robot::acme:r1`
// approver became a signed statement that a type outside the vocabulary
// approved a policy version. The portal caller happens to validate first, so
// nothing was broken in production, but the enforcement was in the caller and
// the claim was about the surface.
//
// The two rules are the same ones the policy path uses, for the same reason
// they are separate there: a well-formed identifier of the wrong kind is not
// malformed, it is in the wrong field, and the remedy differs.
func checkApproverIdentifiers(approvers []contract.ID) Findings {
	var out Findings
	for _, ap := range approvers {
		// A ZERO IDENTIFIER IS A MALFORMED APPROVER, NOT AN ABSENT ONE.
		//
		// Both this check and checkSeparationOfDuties used to SKIP it, so a
		// publication whose approver list held a zero id passed both and was
		// signed with `approvers=[::]` in the provenance - a signed statement
		// that nobody approved it, in the shape of a statement that somebody
		// did. Review found it by deleting the skip in the other function and
		// watching the whole package stay green: the third unguarded term in
		// one control, after the type and the realm.
		//
		// Refusing here makes the skip in checkSeparationOfDuties unreachable,
		// and it is left in place as the failure mode of this one rather than
		// as behaviour.
		if ap.IsZero() {
			out = append(out, newFinding(pdp.RuleMalformedIdentifier, "",
				"approvers contains a zero identifier; an empty entry in an approver list is a malformed approver, not an absent one, and a publication signed with it records that nobody approved the version"))
			continue
		}
		if ap.Kind != contract.KindPrincipal {
			out = append(out, newFinding(pdp.RuleIdentifierWrongKind, "", fmt.Sprintf(
				"approvers names a %q identifier (%s); an approver is a principal", ap.Kind, ap.String())))
			continue
		}
		if err := ap.Validate(); err != nil {
			out = append(out, newFinding(pdp.RuleMalformedIdentifier, "", fmt.Sprintf("approvers: %v", err)))
		}
	}
	return out
}

// samePerson reports whether two identifiers name the same subject.
//
// KIND, QUALIFIER AND LOCAL - AND DELIBERATELY NOT TYPE (#3876). The type is a
// CLASSIFICATION of an identity, not a component of it: `User::acme:alice` and
// `Service::acme:alice` are one person described two ways. Comparing the
// rendered form, which is what `ID.String()` gives and what this used to do,
// therefore turned one person into two, and an author could satisfy the
// two-person rule by naming themselves under a different type.
//
// The general shape is worth recognising: a comparison of a RENDERED FORM
// where the question is about IDENTITY. Ask what the equality is for. Here it
// is "is this the same person", so every field that classifies rather than
// identifies has to be left out of it.
// THE LOCAL PART IS FOLDED, on the rule the identity actually resolves under.
// The directory matches an assignment on `lower(btrim(user_email))`, so
// `User::acme:Alice` and `User::acme:alice` are one person to it and were two
// people to this comparison. That axis of the same class had already been found
// and fixed - at the customer portal, on its own inputs - which closed it for
// one caller and left it open at the control. Folding here covers every caller,
// and contract.CanonicalLocal is the single rule, delegated to rather than
// restated. Kind and qualifier are deliberately not folded; see that function.
//
// IT IS NOW ONE LINE FOR THE SAME REASON THE FOLD IS (#3878). This function
// spelled the rule out a second time, in a second module, and a second spelling
// of "are these the same person" is two answers that agree until the day one of
// them changes - which is exactly how the casing axis ended up fixed at one
// caller and open at the control. contract.SameEntity is the rule; this name
// stays because the call sites read better with it and because "person" is what
// this package's control is about.
func samePerson(a, b contract.ID) bool {
	return contract.SameEntity(a, b)
}

// everyApproverIsTheAuthor is PRD §1.12's self-approval fact: there is at
// least one approver and every one of them is the author. It compares
// IDENTITY through samePerson, never the rendered form: the author named again
// under a different principal type is still the author (#3878).
func everyApproverIsTheAuthor(author contract.ID, approvers []contract.ID) bool {
	if len(approvers) == 0 {
		return false
	}
	for _, approver := range approvers {
		if !samePerson(approver, author) {
			return false
		}
	}
	return true
}

// checkSeparationOfDuties refuses a publication that nobody but the author
// approved.
//
// This is a GOVERNANCE control rather than a hygiene check: it is the two-
// person rule for policy publication, and the only thing standing between a
// single `policy:write` holder and a signed policy version nobody else saw.
// See #3876 for what it used to be worth.
func checkSeparationOfDuties(d *Document, opts PublishOptions) Findings {
	for _, ap := range opts.Approvers {
		if ap.IsZero() {
			continue
		}
		if !samePerson(ap, d.Metadata.Author) {
			return nil
		}
	}
	// No approver differs from the author. PRD v11 §1.12 permits that as a
	// SELF-APPROVAL - the author named as the approver - only where the
	// deployment granted it for this publication, and only with a reason.
	if opts.selfApprovalGranted && everyApproverIsTheAuthor(d.Metadata.Author, opts.Approvers) {
		if strings.TrimSpace(opts.SelfApprovalReason) == "" {
			return Findings{newFinding(CodeSelfApprovalReasonRequired, "", fmt.Sprintf(
				"the author %q approves their own publication under a granted self-approval and states no reason; the reason is what the audit row records",
				d.Metadata.Author))}
		}
		return nil
	}
	return Findings{newFinding(CodeApproverIsAuthor, "", fmt.Sprintf(
		"the publication names %d approver(s) and none of them differs from the author %q",
		len(opts.Approvers), d.Metadata.Author))}
}

// checkSelfApprovalReason refuses a self-approval reason on a publication that
// names an approver other than the author. It is not edition-conditional: the
// reason is signed into provenance and written on the audit row as the
// explanation of a self-approval, and on a two-person publication it would
// record one that did not happen, on every edition.
func checkSelfApprovalReason(d *Document, opts PublishOptions) Findings {
	if strings.TrimSpace(opts.SelfApprovalReason) == "" || everyApproverIsTheAuthor(d.Metadata.Author, opts.Approvers) {
		return nil
	}
	return Findings{newFinding(CodeSelfApprovalReasonWithoutSelfApproval, "", fmt.Sprintf(
		"the publication states a self-approval reason and names an approver other than the author %q",
		d.Metadata.Author))}
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
// ErrKeyNotAuthorized reports that the trust store consulted carries no key
// under the artifact's identifier and root.
//
// IT IS A SENTINEL BECAUSE A CALLER HAS TO TELL IT FROM ITS NEIGHBOUR AND THE
// MESSAGES ARE NOT SAFE TO TELL APART. This condition and "the artifact
// signature does not verify against key %q" both name a key, so a caller
// matching on text would treat a signature mismatch - a real refusal, and the
// shape tampering takes - as the same thing as a key this process has simply
// not heard of yet. The two call for OPPOSITE responses: an unknown key may be
// one another replica authorized a moment ago and is worth re-reading the
// trust store for, while a signature that does not verify must stay refused
// however many times it is asked.
var ErrKeyNotAuthorized = errors.New("authoring: the signing key is not authorized under this authority root")

func (a *Artifact) verify(trust *pdp.TrustStore) error {
	root := a.provenance.Root
	pub, ok := trust.PublicKey(root, a.keyID)
	if !ok {
		return fmt.Errorf("%w: key %q under the %q authority root", ErrKeyNotAuthorized, a.keyID, root)
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
