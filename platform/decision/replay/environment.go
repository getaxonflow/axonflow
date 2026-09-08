// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
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
//
// The digest is RECOMPUTED from each bundle's content, not read from its
// advertised Digest field (#3700). This is the site where that mattered most:
// CheckPins decides whether a replay environment is the one that produced a
// record by comparing these digests against the record's pins, and nothing
// upstream of here verifies the bundles - Environment.Validate checks the
// declared keys, and Engine() verifies, but a caller may call this without
// ever building an engine (cmd/decision-replay does exactly that). An
// advertised digest is not covered by the bundle signature, so this method
// was reporting a LABEL as though it were a fact about content.
//
// It did NOT make CheckPins compare equal to a record it did not produce -
// an earlier version of this comment claimed that and was wrong.
// Record.EnvironmentDigest hashes the whole Environment, bundles included, so
// any drift in content or in label already moved it and CheckPins already
// refused; see record.go, which calls the bundle pins "redundant with
// EnvironmentDigest only when nothing is wrong". What was unguarded is this
// EXPORTED method and every consumer of its output that does not also check
// the environment digest.
// THE SLICE IS PARTIAL WHEN THE ERROR IS NON-NIL, and that is a change of
// contract worth stating rather than discovering. Before #3700's round-4 fix
// this method returned nil on error, which is obviously empty; it now returns
// the pins it COULD compute so that CheckPins can still report the other
// direction, and a caller writing `pins, _ := env.BundleDigests()` gets a
// short list that looks complete. Read the error. It is an
// *UnpinnableBundlesError naming exactly which roots are missing from the
// slice and why, so a caller never has to infer that from a length.
func (e *Environment) BundleDigests() ([]Pin, error) {
	out := make([]Pin, 0, len(e.Roots))
	var refused []UnpinnableRoot
	for _, r := range e.Roots {
		if r.Bundle == nil {
			continue
		}
		digest, err := r.Bundle.VerifiedDigest()
		if err != nil {
			// EVERY unpinnable bundle is reported, not the first. Returning
			// on the first one hid the rest and, through CheckPins, hid the
			// OTHER pin mismatches too - in a function whose contract is to
			// report both directions.
			//
			// BOTH DIGESTS ARE CARRIED, not a sentence. A caller that only
			// gets prose cannot tell which roots are affected, so CheckPins
			// used to fall through and report a root the environment HOLDS as
			// a root it does not hold. The content digest is what the record
			// pinned in the common case, so naming both is what turns the
			// refusal from "your bundle is missing" into "your bundle is
			// here, with a corrupted label".
			u := UnpinnableRoot{Root: r.Root, Advertised: r.Bundle.Digest, Err: err}
			if content, cerr := r.Bundle.ContentDigest(); cerr == nil {
				u.Content = content
			}
			refused = append(refused, u)
			continue
		}
		out = append(out, Pin{Root: r.Root, Digest: digest})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Root < out[j].Root })
	if len(refused) > 0 {
		sort.Slice(refused, func(i, j int) bool { return refused[i].Root < refused[j].Root })
		return out, &UnpinnableBundlesError{Roots: refused}
	}
	return out, nil
}

// UnpinnableRoot names one root whose bundle could not be pinned, carrying
// both digests so a caller can say which of the two is the lie.
type UnpinnableRoot struct {
	Root       pdp.Root
	Advertised string
	Content    string
	Err        error
}

// UnpinnableBundlesError is what BundleDigests returns when it could not pin
// every bundle. It exists so callers can act on the ROOTS rather than parse a
// sentence: CheckPins uses it to report each affected root once, correctly,
// instead of reporting it as absent.
type UnpinnableBundlesError struct {
	Roots []UnpinnableRoot
}

func (e *UnpinnableBundlesError) Error() string {
	parts := make([]string, 0, len(e.Roots))
	for _, r := range e.Roots {
		parts = append(parts, fmt.Sprintf("root %q: %v", r.Root, r.Err))
	}
	return "replay: " + strings.Join(parts, "; ")
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
