// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package proof is the ADR-065 Decision Proof Service: a signed,
// audience-bound, single-use proof that binds the full decision snapshot
// (issue #3560, epic #3551).
//
// # Edition
//
// Every file except this one carries `//go:build enterprise`. Proof signing is
// Enterprise. This doc file is untagged so the package still exists on the
// community mirror and `go build ./...` behaves identically on both editions.
//
// # The property that makes gate 11 checkable rather than aspirational
//
// ADR-065 gate 11 is "mutate every bound field and prove verification fails".
// The obvious way to write that is a test listing the fields - and the obvious
// way for it to rot is a new field added to the binding and not to the list,
// which is the R3 finding "a proof field asserted bound but absent from the
// digest".
//
// So the canonical encoding walks the Binding struct BY REFLECTION, and the
// mutation test enumerates the same struct by reflection. A field added to
// Binding is therefore bound automatically and mutated automatically, and the
// two cannot drift apart because neither has a list. The encoder REFUSES a
// field whose type it does not know how to render rather than skipping it, so
// adding an unsupported type fails loudly at the first call instead of
// silently leaving that field unbound.
//
// # Signing authority
//
// Signing and verification are separate types with separate inputs. Signer
// needs a private key; Verifier is constructed from a KeySet of PUBLIC keys
// and has no method that can produce a signature. A PEP holds a Verifier.
// TestVerifierCannotMintOrExtendAProof pins the absence.
//
// Rotation overlap, emergency revocation, the algorithm policy and the
// audience registry live in keys.go. The operational half - KMS/HSM custody,
// distribution, on-call - is in
// technical-docs/DECISION_PROOF_KEY_MANAGEMENT.md, which is the F7 gap the
// brief names.
package proof
