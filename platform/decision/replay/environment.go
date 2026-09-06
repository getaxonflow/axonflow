// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// EnvironmentSchemaVersion is the environment artifact's own version. It is
// checked on load: an artifact written by a future tool is refused rather than
// partially understood, because a field this build does not know about is a
// decision input it would silently ignore.
const EnvironmentSchemaVersion = 1

// RootArtifact is one signing root's pinned material.
type RootArtifact struct {
	Root pdp.Root `json:"root"`
	// Bundle is the signed, digest-pinned policy artifact.
	Bundle *pdp.Bundle `json:"bundle"`
	// Document is the typed source document the bundle was compiled from. The
	// engine reads combiner metadata out of it - which policies are
	// pierceable, which obligations are mandatory - and binds it to the bundle
	// by digest before trusting any of it.
	Document *pdp.Document `json:"document"`
	// TrustedKeyID and TrustedPublicKey are the key the bundle's signature is
	// verified against. The PUBLIC half only: a replay artifact that could
	// sign a bundle would let anyone who has one manufacture the decision they
	// wanted to reproduce.
	TrustedKeyID     string `json:"trusted_key_id"`
	TrustedPublicKey string `json:"trusted_public_key"`
}

// Environment is everything outside the request that a decision depends on.
//
// See the package doc for why this is larger than "the bundles": the registry
// and the enforcement profile change decisions without changing a bundle, and
// an artifact that pinned only the bundles would reproduce a decision that
// happened to be right.
type Environment struct {
	SchemaVersion int            `json:"schema_version"`
	Roots         []RootArtifact `json:"roots"`
	// Registry is the action and realm registry admission runs against.
	Registry *pdp.Registry `json:"registry"`
	// PEP is the advertised enforcement profile. A nil profile is a real
	// configuration - it means the enforcement point advertised nothing - so
	// it is encoded as null rather than omitted.
	PEP *contract.PEPProfile `json:"pep"`
	// ApprovalTTLSeconds is the challenge lifetime stamped on a composed
	// approval requirement.
	ApprovalTTLSeconds int64 `json:"approval_ttl_seconds"`
	// PayloadLeaves is the canonical leaf field schema disclosure obligations
	// expand over.
	PayloadLeaves []string `json:"payload_leaves,omitempty"`
}

// Digest is the environment's identity, over the canonical exact encoding.
//
// ExactJSON rather than the normalizing encoder, for the reason the bundle's
// signed view uses it: the module inside a bundle is compiled RAW, so a digest
// over a Unicode-normalized projection would be satisfied by byte sequences
// that compile to different policies.
func (e *Environment) Digest() (string, error) {
	if e == nil {
		return "", fmt.Errorf("replay: environment is nil")
	}
	d, err := contract.ExactDigest(e)
	if err != nil {
		return "", fmt.Errorf("replay: digesting the environment: %w", err)
	}
	return d, nil
}

// Validate checks the artifact's internal consistency before anything is
// trusted. Every failure is a refusal: an environment that cannot be checked
// cannot be replayed against.
func (e *Environment) Validate() error {
	if e == nil {
		return fmt.Errorf("replay: environment is nil")
	}
	if e.SchemaVersion != EnvironmentSchemaVersion {
		return fmt.Errorf(
			"replay: environment declares schema version %d, this build understands %d; "+
				"an artifact from a different version may carry decision inputs this build would ignore",
			e.SchemaVersion, EnvironmentSchemaVersion)
	}
	if len(e.Roots) == 0 {
		return fmt.Errorf("replay: environment carries no policy roots")
	}
	if e.Registry == nil {
		return fmt.Errorf("replay: environment carries no action registry; admission cannot tell a registered action from an unregistered one")
	}
	if e.ApprovalTTLSeconds <= 0 {
		return fmt.Errorf("replay: environment declares approval TTL %ds; a non-positive lifetime is not a configuration the engine can reproduce",
			e.ApprovalTTLSeconds)
	}
	seen := map[pdp.Root]bool{}
	for i, r := range e.Roots {
		switch {
		case r.Root == "":
			return fmt.Errorf("replay: roots[%d] declares no root", i)
		case r.Bundle == nil:
			return fmt.Errorf("replay: root %q carries no bundle", r.Root)
		case r.Document == nil:
			return fmt.Errorf("replay: root %q carries no source document", r.Root)
		case r.Bundle.Root != r.Root:
			return fmt.Errorf("replay: root %q carries a bundle for root %q", r.Root, r.Bundle.Root)
		case r.Document.Root != r.Root:
			return fmt.Errorf("replay: root %q carries a source document for root %q", r.Root, r.Document.Root)
		case r.TrustedKeyID == "":
			return fmt.Errorf("replay: root %q names no trusted key", r.Root)
		case seen[r.Root]:
			return fmt.Errorf("replay: root %q appears twice", r.Root)
		}
		seen[r.Root] = true
		key, err := hex.DecodeString(r.TrustedPublicKey)
		if err != nil {
			return fmt.Errorf("replay: root %q trusted public key is not hex: %w", r.Root, err)
		}
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("replay: root %q trusted public key is %d bytes, want %d", r.Root, len(key), ed25519.PublicKeySize)
		}
	}
	return nil
}

// BundleDigests returns the loaded bundle digests by root, in root order.
func (e *Environment) BundleDigests() []Pin {
	out := make([]Pin, 0, len(e.Roots))
	for _, r := range e.Roots {
		if r.Bundle == nil {
			continue
		}
		out = append(out, Pin{Root: r.Root, Digest: r.Bundle.Digest})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Root < out[j].Root })
	return out
}

// Engine builds the shipped engine from the pinned artifacts.
//
// Every check the engine performs at activation - signature verification
// against the declared key, provenance, compiler and helper digests, and the
// document-to-bundle digest binding - runs here exactly as it does on a
// deployment. A replay that skipped them would reproduce decisions from
// artifacts a deployment would have refused to activate.
func (e *Environment) Engine(ctx context.Context) (*pdp.Engine, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	ts := pdp.NewTrustStore()
	bundles := make([]*pdp.Bundle, 0, len(e.Roots))
	docs := make([]*pdp.Document, 0, len(e.Roots))
	for _, r := range e.Roots {
		key, err := hex.DecodeString(r.TrustedPublicKey)
		if err != nil {
			return nil, fmt.Errorf("replay: root %q trusted public key: %w", r.Root, err)
		}
		ts.Authorize(r.Root, r.TrustedKeyID, ed25519.PublicKey(key))
		bundles = append(bundles, r.Bundle)
		docs = append(docs, r.Document)
	}
	engine, err := pdp.NewEngine(ctx, pdp.EngineConfig{
		Bundles:       bundles,
		Documents:     docs,
		TrustStore:    ts,
		Registry:      e.Registry,
		PEP:           e.PEP,
		ApprovalTTL:   time.Duration(e.ApprovalTTLSeconds) * time.Second,
		PayloadLeaves: e.PayloadLeaves,
	})
	if err != nil {
		return nil, fmt.Errorf("replay: activating the pinned environment: %w", err)
	}
	return engine, nil
}
