// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"crypto/ed25519"
	"fmt"
	"maps"
	"slices"
	"strings"

	"axonflow/platform/decision/pdp"
)

// THE ORGANIZATION COMPOSITION AUTHORITY (#4045)
//
// An organization's recorded detection override (detection_action_overrides)
// changes the action a shipped control enforces for that organization. The
// anchored engine expresses it on the two roots ADR-065 has: the system
// restriction LEAVES OUT the displaced control, which the anchor permits, and
// the organization root carries that control again with the recorded action.
// The organization root then has two sources - the document the organization
// authored and the controls its overrides re-action - and pdp.NewEngine accepts
// one bundle per root.
//
// CompositionAuthority signs that one bundle. It is a type of its own beside the
// organization authority (the authoring API) and SystemAuthority, for the reason
// those two are separate types: its content is neither authored by the
// organization nor shipped by the release, so neither of their keys signs it.
// Activation refuses a composition key that is the system key or the key that
// signed the organization's document.
//
// What it signs is bounded:
//
//   - the authored document EXACTLY as its signed bundle attests it: the
//     signature is verified against the organization's key and the document is
//     bound to the bundle by pdp.BindSourceDocument, the rule pdp.NewEngine
//     applies, and every authored policy is carried unchanged and in order;
//   - followed by the additions, none of which may take an authored policy's id;
//   - with the attribute schemas the additions read, none of which may
//     redescribe a path the authored document declares.
//
// It does not decide WHAT the additions are. Activation derives them from the
// shipped controls an override displaces, through legacycompile.ActionPolicy.
//
// The key is minted per process by the caller and never persisted, as the
// system key is: a composition is built and verified by the process that
// enforces it, and nobody else reads it.

// CompositionKeyID is the key identifier a composed organization bundle is
// signed under.
const CompositionKeyID = "deployment-organization-composition"

// The composition authority's refusals.
const (
	// CodeComposedContentUnverified refuses an authored document whose bundle
	// does not verify against the organization's key, or that is not the
	// document the bundle was compiled from.
	CodeComposedContentUnverified = "COMPOSED_CONTENT_UNVERIFIED"
	// CodeComposedPolicyIDTaken refuses an addition whose id a policy already
	// in the composition uses.
	CodeComposedPolicyIDTaken = "COMPOSED_POLICY_ID_TAKEN"
	// CodeComposedAttributeConflict refuses an attribute schema that
	// redescribes a path the composition already declares.
	CodeComposedAttributeConflict = "COMPOSED_ATTRIBUTE_SCHEMA_CONFLICT"
	// CodeComposedOmissionNotCarried refuses an omission naming a policy the
	// authored document does not carry: a composition leaves out only what the
	// organization published.
	CodeComposedOmissionNotCarried = "COMPOSED_OMISSION_NOT_CARRIED"
)

// ErrCompositionRefused is CompositionAuthority's refusal.
type ErrCompositionRefused struct {
	code   string
	detail string
	cause  error
}

func (e *ErrCompositionRefused) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.code, e.detail, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.code, e.detail)
}

// Code is the machine-readable refusal.
func (e *ErrCompositionRefused) Code() string { return e.code }

// Unwrap exposes the verification failure behind CodeComposedContentUnverified.
func (e *ErrCompositionRefused) Unwrap() error { return e.cause }

// CompositionAuthority signs composed organization-root bundles for this
// process.
type CompositionAuthority struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewCompositionAuthority binds the composition authority to a signing key the
// caller minted. It must be a key that signs nothing else.
func NewCompositionAuthority(priv ed25519.PrivateKey) (*CompositionAuthority, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("authoring: the composition authority requires an ed25519 private key, got %d bytes", len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("authoring: the composition authority's key has no ed25519 public half")
	}
	return &CompositionAuthority{priv: priv, pub: pub}, nil
}

// PublicKey returns a copy of the verifying half of the composition key.
func (c *CompositionAuthority) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), c.pub...)
}

// AuthoredSource is an organization's active document as its publication
// attests it: the document, the bundle signed over it, and the key that signed.
type AuthoredSource struct {
	Document *pdp.Document
	Bundle   *pdp.Bundle
	Key      ed25519.PublicKey
}

// Composition is a signed organization-root bundle and the document it was
// built from.
type Composition struct {
	Document *pdp.Document
	Bundle   *pdp.Bundle
}

// Compose signs the organization-root document that is the authored document,
// verified, without the policies omit names and otherwise unchanged, followed
// by additions, declaring schemas beside the authored document's attributes.
// authored is nil when the organization has no active document. omit is what
// the plane being composed does not bind of the authored document (activation's
// unboundTemplateControls); each id must name a policy the document carries, and
// an omitted id stays taken, so no addition replaces it.
func (c *CompositionAuthority) Compose(authored *AuthoredSource, omit []string, additions []pdp.Policy, schemas []pdp.AttributeSchema) (*Composition, error) {
	if len(additions) == 0 && len(omit) == 0 {
		return nil, fmt.Errorf("authoring: a composition with no additions and no omissions is the authored document itself, which activates as it was published")
	}
	doc := &pdp.Document{Root: pdp.RootOrganization}
	declared := map[string]pdp.AttributeSchema{}
	taken := map[string]bool{}
	left := make(map[string]bool, len(omit))
	for _, id := range omit {
		left[id] = true
	}
	if authored != nil {
		if authored.Document == nil || authored.Bundle == nil || len(authored.Key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("authoring: an authored source is its document, the bundle signed over it and the ed25519 key that signed it")
		}
		// The store authorizes the organization root only, so a bundle signed
		// under any other root does not verify, and the binding holds the
		// document to that bundle's root.
		trust := pdp.NewTrustStore()
		trust.Authorize(pdp.RootOrganization, authored.Bundle.KeyID, authored.Key)
		if err := trust.Verify(authored.Bundle); err != nil {
			return nil, &ErrCompositionRefused{code: CodeComposedContentUnverified,
				detail: "the authored bundle does not verify against the organization's key", cause: err}
		}
		if err := pdp.BindSourceDocument(authored.Document, authored.Bundle); err != nil {
			return nil, &ErrCompositionRefused{code: CodeComposedContentUnverified,
				detail: "the authored document is not the one its bundle was compiled from", cause: err}
		}
		doc.Version = authored.Document.Version
		doc.InteractiveRealms = maps.Clone(authored.Document.InteractiveRealms)
		doc.Attributes = append(doc.Attributes, authored.Document.Attributes...)
		for _, a := range authored.Document.Attributes {
			declared[a.Path] = a
		}
		for _, p := range authored.Document.Policies {
			taken[p.ID] = true
			if left[p.ID] {
				delete(left, p.ID)
				continue
			}
			doc.Policies = append(doc.Policies, p)
		}
	}
	if len(left) > 0 {
		return nil, &ErrCompositionRefused{code: CodeComposedOmissionNotCarried, detail: fmt.Sprintf(
			"the composition omits %s, which the authored document does not carry", strings.Join(slices.Sorted(maps.Keys(left)), ", "))}
	}
	for _, a := range schemas {
		if prev, ok := declared[a.Path]; ok {
			if prev != a {
				return nil, &ErrCompositionRefused{code: CodeComposedAttributeConflict, detail: fmt.Sprintf(
					"attribute %q is declared as %+v and an addition reads it as %+v", a.Path, prev, a)}
			}
			continue
		}
		declared[a.Path] = a
		doc.Attributes = append(doc.Attributes, a)
	}
	for _, p := range additions {
		if taken[p.ID] {
			return nil, &ErrCompositionRefused{code: CodeComposedPolicyIDTaken, detail: fmt.Sprintf(
				"policy id %q is already in the composition; an addition never replaces a policy", p.ID)}
		}
		taken[p.ID] = true
		doc.Policies = append(doc.Policies, p)
	}
	bundle, err := pdp.BuildBundle(doc)
	if err != nil {
		return nil, fmt.Errorf("authoring: building the composed organization bundle: %w", err)
	}
	if err := bundle.Sign(CompositionKeyID, c.priv); err != nil {
		return nil, fmt.Errorf("authoring: signing the composed organization bundle: %w", err)
	}
	return &Composition{Document: doc, Bundle: bundle}, nil
}
