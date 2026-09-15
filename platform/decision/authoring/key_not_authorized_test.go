// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"axonflow/platform/decision/pdp"
)

// TestAnUnknownKeyIsDistinguishableFromASignatureThatDoesNotVerify is why
// ErrKeyNotAuthorized is a sentinel rather than a message.
//
// A durable store retries a load ONCE when the only thing wrong was a key this
// process has not heard of yet - that is what another replica authorizing its
// signing key looks like from here, and re-reading the authorized keys is the
// right response. It must NEVER retry on a signature that does not verify:
// that is a real refusal and the shape tampering takes, and a store that
// re-read its trust and tried again would be retrying on exactly the input an
// attacker controls.
//
// The two conditions are adjacent in verify() and BOTH of their messages name
// a key, so a caller matching on text cannot separate them. This test is the
// pair that makes the separation real: one must match the sentinel, the other
// must not. Asserting only the first would pass on a sentinel that wrapped
// every verification failure, which is the confusion being prevented.
func TestAnUnknownKeyIsDistinguishableFromASignatureThatDoesNotVerify(t *testing.T) {
	art, _, _ := mustPublish(t)
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a key the trust store has never heard of matches the sentinel", func(t *testing.T) {
		empty := pdp.NewTrustStore()
		_, err := LoadArtifact(raw, empty)
		if err == nil {
			t.Fatal("an artifact loaded against a trust store authorizing nothing")
		}
		if !errors.Is(err, ErrKeyNotAuthorized) {
			t.Fatalf("an unknown key did not match ErrKeyNotAuthorized, so a caller cannot tell it from a bad signature: %v", err)
		}
	})

	t.Run("the SAME key identifier with different material does NOT match the sentinel", func(t *testing.T) {
		// The lookup SUCCEEDS here - the identifier is authorized - and it is
		// ed25519.Verify that fails. That is the case a text match would
		// confuse with the one above, and the case a reload must not retry.
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrong := pdp.NewTrustStore()
		wrong.Authorize(art.Root(), art.KeyID(), otherPub)

		_, err = LoadArtifact(raw, wrong)
		if err == nil {
			t.Fatal("an artifact verified against a trust store holding different key material for its identifier")
		}
		if errors.Is(err, ErrKeyNotAuthorized) {
			t.Fatalf("a signature that does not verify was reported as an unauthorized key. A durable store retries on that "+
				"sentinel, so this would make it re-read its trust and try again on a tampered artifact: %v", err)
		}
	})

	// THE POSITIVE CONTROL. Without it both refusals above would be satisfied
	// by an artifact that cannot load under any trust store at all.
	t.Run("and it still loads against the trust store that authorized it", func(t *testing.T) {
		_, trust, _ := mustPublish(t)
		fresh, _, _ := mustPublish(t)
		rawFresh, err := json.Marshal(fresh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := LoadArtifact(rawFresh, trust); err != nil {
			t.Fatalf("a freshly published artifact does not load against its own trust store, so the refusals above prove nothing: %v", err)
		}
	})
}
