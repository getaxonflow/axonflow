// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"crypto/ed25519"
	"fmt"

	"axonflow/platform/decision/pdp"
)

// THE SYSTEM-ROOT AUTHORITY (#3884, #4047)
//
// The system root is the platform's own ceiling. SYSTEM_ROOT_SIGNING_AUTHORITY.md
// decided who its authority is: the shipped corpus, identified by a digest
// compiled into this binary (arm 1). No operator key is authorized under it at
// v11.0.0, and arm 2 - an operator publication bound to shipped detector
// records - is defined and not built.
//
// That decision shipped with an ANCHOR and no AUTHORITY. pdp.NewEngine refuses a
// system bundle that is not the shipped corpus, which guards what an engine
// ENFORCES. Nothing guarded what the authoring surfaces SIGN, ADMIT and KEEP: a
// transport's API published and admitted a system-root document from any key
// its trust store authorized under pdp.RootSystem, and activation authorized a
// key into that very trust store on every dry run - the organization
// workspace's own key, in both transports (#4047). The org-root constant in
// each route was the only thing left between a caller and the platform's
// ceiling.
//
// So the authority has two halves here, and they are different TYPES rather
// than one API with a root argument, because an argument is the thing a caller
// passes wrong:
//
//   - the ORGANIZATION authority is every API a transport builds (NewAPI,
//     NewAPIWithBackend). It publishes, admits and activates under
//     pdp.RootOrganization and refuses the system root by name
//     (CodeSystemRootRequiresSystemAuthority), whatever keys its trust store
//     holds;
//   - the SYSTEM authority is SystemAuthority, below. It signs a system-root
//     bundle for the engine that enforces it, and it signs one content only: the
//     corpus this binary shipped, or a restriction of it, checked by the two
//     anchor functions NewEngine itself calls. It takes no author, no approver
//     and no document of the caller's making beyond that subset.
//
// # SEPARATION OF DUTIES ON THE SYSTEM ROOT
//
// Under arm 1 the AUTHOR of the system document is the release that built this
// binary and the SIGNER is the deployment running it, and the signer cannot
// author: any content other than the shipped corpus, or a subset of it, is
// refused. No principal on a deployment can therefore approve its own
// authorship of a platform ceiling. That is the two-person rule held
// structurally rather than by comparing identities, and it is why this type
// carries no approver list - an approver of content nobody at the deployment
// wrote would be a signed claim with no referent. Arm 2 puts a human author on
// the system root; when it is built it needs checkSeparationOfDuties on EVERY
// edition, because PRD 5.3's None/None relaxation is about an organization's
// own policy, not the platform's.
//
// # WHY NO AUTHOR-FIXTURE GAUNTLET
//
// Publish runs the gauntlet over the fixtures an author declares. A
// shipped-corpus publication has no author at the deployment, and its evidence
// is fixed where its content is - at build time: the artifact is regenerated
// from a capture of a migrated database and held byte-equal to it, and every
// legacy row's decision is compared before and after
// (platform/decision/legacycompile/system_corpus_capture_test.go). Re-running a
// gauntlet over identical bytes on every activation would add latency and no
// evidence. What IS re-checked on every signing is the one property the
// deployment could violate: that the bytes are still the shipped ones.

// CodeSystemRootRequiresSystemAuthority is the refusal an organization authoring
// surface returns for a publication, admission or activation under the system
// root. Like CodeCatalogIsFixture it is not a save-time check and is not in the
// declared check table: it refuses the operation, not a policy in the document.
const CodeSystemRootRequiresSystemAuthority = "SYSTEM_ROOT_REQUIRES_SYSTEM_AUTHORITY"

// CodeSystemContentNotShipped is SystemAuthority's refusal of a system document
// that is neither the shipped corpus nor a restriction of it.
const CodeSystemContentNotShipped = "SYSTEM_CONTENT_NOT_SHIPPED"

// SystemKeyID is the key identifier a deployment signs its system bundle under.
//
// The key MATERIAL is per process (SYSTEM_ROOT_SIGNING_AUTHORITY §3: "a
// deployment builds the bundle from the embedded source and signs it with a
// locally generated key under pdp.RootSystem"); the identifier is fixed so a
// record naming it means one thing on every deployment.
const SystemKeyID = "deployment-system-corpus"

// ErrSystemRootOutsideAuthority is the organization authority's refusal of any
// root other than its own.
type ErrSystemRootOutsideAuthority struct {
	// Operation is what was refused: publish, admit, promote or rollback.
	Operation string
	// Root is the root the operation named.
	Root pdp.Root
}

func (e *ErrSystemRootOutsideAuthority) Error() string {
	return fmt.Sprintf("%s: this authoring surface is the ORGANIZATION authority and refuses to %s under the %q root. "+
		"It publishes, admits and activates under %q only, whatever keys its trust store holds. The system root's one "+
		"authority is the corpus this binary shipped, signed for the engine that enforces it by authoring.SystemAuthority "+
		"(SYSTEM_ROOT_SIGNING_AUTHORITY.md)",
		CodeSystemRootRequiresSystemAuthority, e.Operation, e.Root, pdp.RootOrganization)
}

// Code is the machine-readable refusal.
func (e *ErrSystemRootOutsideAuthority) Code() string { return CodeSystemRootRequiresSystemAuthority }

// ErrSystemContentNotShipped is SystemAuthority's refusal. It wraps the anchor's
// own refusal, so a caller can match the pdp code with errors.As as well as this
// one.
type ErrSystemContentNotShipped struct {
	cause error
}

func (e *ErrSystemContentNotShipped) Error() string {
	return fmt.Sprintf("%s: the system authority signs the corpus this binary shipped, or a restriction of it, and "+
		"nothing else - a system document this deployment edited is a platform ceiling nobody here may author: %v",
		CodeSystemContentNotShipped, e.cause)
}

// Code is the machine-readable refusal.
func (e *ErrSystemContentNotShipped) Code() string { return CodeSystemContentNotShipped }

// Unwrap exposes the anchor's refusal.
func (e *ErrSystemContentNotShipped) Unwrap() error { return e.cause }

// SystemAuthority signs system-root bundles for this process.
type SystemAuthority struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSystemAuthority binds the system authority to a signing key.
//
// The CALLER mints the key: a key generated inside a library is a key nobody
// can account for. It must be a key that signs nothing else. Activation refuses
// one that signed the organization document it is activating beside
// (activation.RefusalSystemKeyIsOrganizationKey), because one key under both
// roots is the shape #4047 was.
func NewSystemAuthority(priv ed25519.PrivateKey) (*SystemAuthority, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("authoring: the system authority requires an ed25519 private key, got %d bytes", len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("authoring: the system authority's key has no ed25519 public half")
	}
	return &SystemAuthority{priv: priv, pub: pub}, nil
}

// PublicKey returns a copy of the verifying half of the system key.
func (s *SystemAuthority) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.pub...)
}

// SystemPublication is a signed system-root bundle, the document it was built
// from, and the anchor an engine admits it under.
type SystemPublication struct {
	Document *pdp.Document
	Bundle   *pdp.Bundle
	Anchor   pdp.SystemCorpusAnchor
	pub      ed25519.PublicKey
}

// TrustStore returns a NEW trust store authorizing exactly this publication's
// key under the system root, and nothing else.
//
// It is new on every call, and that is the fix rather than a convenience: #4047
// was an authorization written into a trust store somebody else holds - the one
// the organization's authoring surface verifies against. A caller that needs to
// verify an organization bundle beside this one adds that key to the store it
// got here, and never the other way round.
func (p *SystemPublication) TrustStore() *pdp.TrustStore {
	t := pdp.NewTrustStore()
	t.Authorize(pdp.RootSystem, SystemKeyID, p.pub)
	return t
}

// Publish signs the shipped system corpus under the system root - or, with a
// non-empty restriction, a subset of it that the restriction explains.
//
// The content is checked by the ANCHOR after the bundle is built and before it
// is signed. pdp.SystemCorpusAnchor.CheckSystemPublication runs the three
// functions NewEngine runs on a system bundle and its document - the binding of
// the document to the bundle, the subset check on the document and the anchor
// check on the bundle - so this authority refuses what an anchored engine would
// refuse, by the same code, and no signature is ever produced over content the
// engine would not activate.
func (s *SystemAuthority) Publish(doc *pdp.Document, restriction string) (*SystemPublication, error) {
	if doc == nil {
		return nil, fmt.Errorf("authoring: the system authority was handed no document")
	}
	if doc.Root != pdp.RootSystem {
		return nil, &ErrSystemContentNotShipped{cause: fmt.Errorf("the document declares root %q; the shipped corpus is the %q document", doc.Root, pdp.RootSystem)}
	}
	var (
		anchor pdp.SystemCorpusAnchor
		err    error
	)
	if restriction == "" {
		anchor, err = pdp.AnchorToShippedCorpus()
	} else {
		anchor, err = pdp.AnchorToShippedCorpusRestriction(restriction)
	}
	if err != nil {
		return nil, err
	}
	bundle, err := pdp.BuildBundle(doc)
	if err != nil {
		return nil, fmt.Errorf("authoring: building the system bundle: %w", err)
	}
	if err := anchor.CheckSystemPublication(doc, bundle); err != nil {
		return nil, &ErrSystemContentNotShipped{cause: err}
	}
	if err := bundle.Sign(SystemKeyID, s.priv); err != nil {
		return nil, fmt.Errorf("authoring: signing the system bundle: %w", err)
	}
	return &SystemPublication{Document: doc, Bundle: bundle, Anchor: anchor, pub: s.pub}, nil
}
