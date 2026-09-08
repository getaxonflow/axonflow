// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
)

// HelperSource is the platform-owned tri-state helper module, embedded so that
// a deployed binary evaluates the helpers it was built with rather than
// whatever happens to be on disk.
//
//go:embed rego/tristate.rego
var HelperSource string

// HelperDigest returns the digest of the embedded helper module. It is part of
// bundle provenance: a bundle validated against one helper version and
// evaluated against another has not been validated.
func HelperDigest() string {
	// Hashed over the raw bytes, for the same reason the signed view is: this
	// digest pins the helper module the evaluator will compile.
	sum := sha256.Sum256([]byte(HelperSource))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BundleProvenance records everything a verifier must pin before activation.
type BundleProvenance struct {
	CompilerVersion string `json:"compiler_version"`
	SchemaVersion   string `json:"schema_version"`
	DocumentVersion int    `json:"document_version"`
	HelperDigest    string `json:"helper_digest"`
	SourceDigest    string `json:"source_digest"`
}

// Bundle is an immutable, digest-pinned policy artifact.
//
// Editing a live policy row in place is not production deployment. A bundle is
// built, signed, activated by digest and rolled back by digest, so "which
// policy produced this decision" has an answer that survives the next edit.
type Bundle struct {
	Root       Root                `json:"root"`
	Digest     string              `json:"digest"`
	Module     string              `json:"module"`
	Manifest   []PolicyDeclaration `json:"manifest"`
	Provenance BundleProvenance    `json:"provenance"`
	KeyID      string              `json:"key_id,omitempty"`
	Signature  []byte              `json:"signature,omitempty"`
}

// signedView is the exact byte sequence a signature covers. It is encoded with
// contract.ExactJSON rather than contract.CanonicalJSON: the module in it is
// compiled RAW by the runtime, so a signature over a Unicode-normalized
// projection of the module would be satisfied by any byte sequence sharing that
// projection, and a two-byte edit inside a string literal would flip a
// constraint while the bundle still verified. It deliberately
// excludes Digest, KeyID and Signature: the digest is derived from this view,
// so including it would make the signature cover a value derived from itself,
// and a verifier that recomputes the digest from the signed view can detect a
// bundle whose advertised digest does not match its content.
type signedView struct {
	Root       Root                `json:"root"`
	Module     string              `json:"module"`
	Manifest   []PolicyDeclaration `json:"manifest"`
	Provenance BundleProvenance    `json:"provenance"`
}

// BuildBundle compiles a typed authoring document into an unsigned bundle.
func BuildBundle(d *Document) (*Bundle, error) {
	module, err := Compile(d)
	if err != nil {
		return nil, err
	}
	sourceDigest, err := contract.ExactDigest(d)
	if err != nil {
		return nil, fmt.Errorf("bundle: source digest: %w", err)
	}
	b := &Bundle{
		Root:     d.Root,
		Module:   module,
		Manifest: ManifestOf(d),
		Provenance: BundleProvenance{
			CompilerVersion: CompilerVersion,
			SchemaVersion:   contract.SchemaVersion,
			DocumentVersion: d.Version,
			HelperDigest:    HelperDigest(),
			SourceDigest:    sourceDigest,
		},
	}
	digest, err := contract.ExactDigest(b.view())
	if err != nil {
		return nil, fmt.Errorf("bundle: digest: %w", err)
	}
	b.Digest = digest
	return b, nil
}

// digestMismatch is the ONE refusal a digest disagreement produces (#3700).
//
// It is a function rather than three copies of a format string because the
// refusal is the same fact wherever it is discovered, and because a caller
// that matches on the text must not have to know which site produced it.
func digestMismatch(advertised, content string) error {
	return fmt.Errorf("bundle: advertised digest %s does not match content digest %s", advertised, content)
}

// ContentDigest recomputes the digest from the bundle's signed content.
//
// It is the answer to "what does this bundle actually hash to", as opposed to
// the Digest field, which is what the bundle CLAIMS to hash to.
func (b *Bundle) ContentDigest() (string, error) {
	if b == nil {
		return "", fmt.Errorf("bundle: is nil")
	}
	digest, err := contract.ExactDigest(b.view())
	if err != nil {
		return "", fmt.Errorf("bundle: content digest: %w", err)
	}
	return digest, nil
}

// VerifiedDigest returns the digest RECOMPUTED from content, refusing a bundle
// whose advertised digest does not describe it.
//
// WHY EVERY CONSUMER CALLS THIS RATHER THAN READING .Digest (#3700). Digest is
// NOT inside view(), so it is not covered by the signature: view() is
// {Root, Module, Manifest, Provenance} and deliberately excludes the digest,
// because the digest is derived from the view and a signature over a value
// derived from itself is not well defined. A bundle whose content is genuine
// and whose advertised digest is wrong therefore carries a perfectly valid
// signature.
//
// That was safe only as long as every reader happened to sit behind
// TrustStore.Verify, which recomputes once at activation. "Happened to" is the
// problem: the property was held by an ORDERING rather than by the artifact,
// and the sharpest consequence is on the proof surface, where ADR-065 binds
// PolicyBundleDigest into a decision proof precisely so a decision can be
// attributed to the bundle that produced it. A proof carrying an advertised
// digest attributes the decision to content only because some other process
// checked it earlier.
//
// So the recomputation is now an invariant of USE. Reading .Digest directly is
// legitimate in exactly three places, each declared and asserted by
// TestEveryBundleDigestReaderIsDeclared: where it is minted, where it is
// recomputed, and in diagnostic text that carries no authority.
//
// WHAT THIS IS NOT. VerifiedDigest is not verification. It answers "the
// advertised digest describes this content" and NOTHING else: it does not
// check the signature, the key, the root authority or the provenance, and a
// bundle nobody signed passes it happily. TrustStore.Verify remains the only
// verification, and a caller that needs to know a bundle is trustworthy still
// has to go through it. The name says "verified" because the digest has been
// checked against the bytes, not because the bundle has been.
func (b *Bundle) VerifiedDigest() (string, error) {
	digest, err := b.ContentDigest()
	if err != nil {
		return "", err
	}
	if digest != b.Digest {
		return "", digestMismatch(b.Digest, digest)
	}
	return digest, nil
}

func (b *Bundle) view() signedView {
	m := append([]PolicyDeclaration(nil), b.Manifest...)
	sort.Slice(m, func(i, j int) bool { return m[i].ID < m[j].ID })
	return signedView{Root: b.Root, Module: b.Module, Manifest: m, Provenance: b.Provenance}
}

// Sign signs a bundle with a private key.
func (b *Bundle) Sign(keyID string, priv ed25519.PrivateKey) error {
	payload, err := contract.ExactJSON(b.view())
	if err != nil {
		return fmt.Errorf("bundle: sign: %w", err)
	}
	b.KeyID = keyID
	b.Signature = ed25519.Sign(priv, payload)
	return nil
}

// TrustStore maps a key identifier to the public key authorized to sign
// bundles for a root.
//
// System and organization roots have SEPARATE authority roots so that an
// organization permission cannot modify a system constraint: the two are
// different signed artifacts verified against different keys, and there is no
// operation anywhere that lets one bundle edit the other.
type TrustStore struct {
	keys map[Root]map[string]ed25519.PublicKey
}

// NewTrustStore builds an empty store.
func NewTrustStore() *TrustStore {
	return &TrustStore{keys: map[Root]map[string]ed25519.PublicKey{}}
}

// Authorize registers a signing key for a root.
func (t *TrustStore) Authorize(root Root, keyID string, pub ed25519.PublicKey) {
	if t.keys[root] == nil {
		t.keys[root] = map[string]ed25519.PublicKey{}
	}
	t.keys[root][keyID] = pub
}

// PublicKey returns the key authorized to sign for a root, if any.
//
// It exists so that the layer above can verify its own signed artifacts
// against the SAME root-scoped authority registry rather than keeping a second
// one. Two key registries would be two answers to "may this key publish under
// this root", and the separation of the system and organization authorities is
// only as strong as the weakest place that decides it.
func (t *TrustStore) PublicKey(root Root, keyID string) (ed25519.PublicKey, bool) {
	if t == nil {
		return nil, false
	}
	byRoot, ok := t.keys[root]
	if !ok {
		return nil, false
	}
	pub, ok := byRoot[keyID]
	return pub, ok
}

// Verify checks signature, provenance and digest before a bundle may be
// activated.
//
// The order matters. Signature first, because everything after it is content
// the signature attests to; then the digest, because an activation is by
// digest and a bundle whose content does not hash to its advertised digest
// cannot be pinned; then provenance, because a bundle validated against a
// different helper module or compiler has not been validated at all.
func (t *TrustStore) Verify(b *Bundle) error {
	if b == nil {
		return fmt.Errorf("bundle: is nil")
	}
	byRoot, ok := t.keys[b.Root]
	if !ok || len(byRoot) == 0 {
		return fmt.Errorf("bundle: no signing key is authorized for root %q", b.Root)
	}
	pub, ok := byRoot[b.KeyID]
	if !ok {
		return fmt.Errorf("bundle: key %q is not authorized for root %q", b.KeyID, b.Root)
	}
	payload, err := contract.ExactJSON(b.view())
	if err != nil {
		return fmt.Errorf("bundle: verify: %w", err)
	}
	if !ed25519.Verify(pub, payload, b.Signature) {
		return fmt.Errorf("bundle: signature does not verify against key %q for root %q", b.KeyID, b.Root)
	}
	digest, err := contract.ExactDigest(b.view())
	if err != nil {
		return fmt.Errorf("bundle: verify digest: %w", err)
	}
	if digest != b.Digest {
		return digestMismatch(b.Digest, digest)
	}
	if b.Provenance.HelperDigest != HelperDigest() {
		return fmt.Errorf("bundle: was validated against helper module %s, this evaluator carries %s", b.Provenance.HelperDigest, HelperDigest())
	}
	if b.Provenance.CompilerVersion != CompilerVersion {
		return fmt.Errorf("bundle: was produced by compiler %q, this evaluator carries %q", b.Provenance.CompilerVersion, CompilerVersion)
	}
	if b.Provenance.SchemaVersion != contract.SchemaVersion {
		return fmt.Errorf("bundle: declares schema version %q, this evaluator expects %q", b.Provenance.SchemaVersion, contract.SchemaVersion)
	}
	return nil
}
