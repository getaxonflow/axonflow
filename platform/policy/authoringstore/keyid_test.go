// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// THE REFUSAL IS THE MECHANISM, SO THE REFUSAL IS WHAT IS TESTED (#3975).
//
// A signing key identifier that does not depend on the key material is stable
// across processes while the material is not, so the second process to
// authorize under it presents a new key under an existing id - which
// AuthorizeKey refuses. Both known callers treat a failed authorization as "no
// durable store" and fall back to an in-process one, so the visible symptom is
// that durable storage works EXACTLY ONCE PER ORGANIZATION and every
// publication made before a restart is unreachable after it.
//
// That was written twice by two callers a week apart - the portal (#3962) and
// the orchestrator (#3975) - and fixed both times by deriving the id from the
// public key. KeyIDFor plus this refusal is the third fix, and it is the one
// that makes a fourth impossible rather than merely unlikely.
//
// NO DATABASE IS NEEDED, and that is a property of where the check sits: the
// fingerprint comparison happens before any statement is issued, so an
// unconnected handle is enough. If this test ever starts needing a live
// postgres, the check has moved behind the database and stopped being the
// thing that runs on every caller's first call.

// storeForKeyIDTest builds a Store over an unconnected handle.
func storeForKeyIDTest(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://unused:unused@127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open (which does not connect): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db, "org-alpha", authoring.StaticTrust(pdp.NewTrustStore()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestAuthorizeKeyRefusesAnIdentifierNotDerivedFromTheKey(t *testing.T) {
	s := storeForKeyIDTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// The exact shape both callers wrote, twice: an identifier keyed on the
	// organization alone. It is stable, it looks tidy, and it silently caps
	// durable storage at one process per organization.
	err = s.AuthorizeKey(ctx, pdp.RootOrganization, "orchestrator-org-alpha", pub, "test")
	if !errors.Is(err, ErrKeyIDNotDerivedFromKey) {
		t.Fatalf("an organization-keyed identifier was accepted (err=%v); this is the defect #3962 and #3975 both shipped, "+
			"and the refusal is what makes a third instance impossible", err)
	}
	// The refusal names its remedy. An error that says "invalid" sends the
	// caller looking for a typo rather than to KeyIDFor.
	if !strings.Contains(err.Error(), "KeyIDFor") {
		t.Errorf("the refusal does not name KeyIDFor, so it does not tell the caller what to do: %v", err)
	}
}

func TestAuthorizeKeyAcceptsADerivedIdentifier(t *testing.T) {
	s := storeForKeyIDTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// THE POSITIVE HALF, and it is not decoration: a check that refused
	// everything would pass the test above while breaking every caller. This
	// asserts the derived form gets PAST the fingerprint gate - it then fails
	// on the unconnected handle, which is a different error and the proof that
	// the gate was cleared.
	keyID := KeyIDFor("orchestrator", "org-alpha", pub)
	err = s.AuthorizeKey(context.Background(), pdp.RootOrganization, keyID, pub, "test")
	if errors.Is(err, ErrKeyIDNotDerivedFromKey) {
		t.Fatalf("KeyIDFor's own output was refused by the check that KeyIDFor exists to satisfy: %v", err)
	}
	if err == nil {
		t.Fatal("AuthorizeKey succeeded against an unconnected database, so this test proves nothing about the gate")
	}
}

func TestKeyIDForIsStableForOneKeyAndDistinctAcrossKeys(t *testing.T) {
	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// STABLE for one key: this is what makes AuthorizeKey idempotent for a
	// process re-authorizing its own key, rather than an error on every retry.
	if KeyIDFor("portal", "org-alpha", pubA) != KeyIDFor("portal", "org-alpha", pubA) {
		t.Error("KeyIDFor is not deterministic for one key, so a process re-authorizing its own key would collide with itself")
	}
	// DISTINCT across keys under the SAME organization: this is the whole
	// defect. Two processes, one org, two ephemeral keys - the identifiers must
	// differ or the second is refused and falls back.
	if KeyIDFor("portal", "org-alpha", pubA) == KeyIDFor("portal", "org-alpha", pubB) {
		t.Error("two different keys under one organization produced the same identifier; the second process would be " +
			"refused and durable storage would work exactly once per organization")
	}
	// And the organization still separates: one key authorized for two orgs is
	// two authorizations, because the rows are org-scoped.
	if KeyIDFor("portal", "org-alpha", pubA) == KeyIDFor("portal", "org-beta", pubA) {
		t.Error("the organization no longer appears in the identifier")
	}
}

// THE LEGACY IMPORTER'S FORMAT IS ACCEPTED, AND IT IS PINNED HERE (#3975).
//
// The importer is the third caller of AuthorizeKey and the only one NOT
// repointed onto KeyIDFor: it builds `"import-" + hex.EncodeToString(sha256(
// pub)[:8])`, which already derives the identifier from the material, and
// changing it would rewrite identifiers already stored on deployments. The
// rule is "the id carries the material's fingerprint", not "the id came from
// this function".
//
// THAT COMPATIBILITY IS A COINCIDENCE OF ENCODING UNTIL SOMETHING ASSERTS IT.
// The refusal compares against fmt.Sprintf("%x", …[:8]) and the importer uses
// hex.EncodeToString(…[:8]); the two agree on byte count and on lowercase hex
// TODAY. If either side changed its slice width or its encoding, the importer
// would be refused ON ITS FIRST RUN AFTER DEPLOY - a production break with a
// green board, because no test in this tree drives that binary.
//
// So the format is reproduced here exactly as the importer writes it, and
// asserted to clear the gate. This test is the reason the importer may be left
// alone.
func TestTheLegacyImportersIdentifierFormatIsAccepted(t *testing.T) {
	s := storeForKeyIDTest(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Verbatim from ee/platform/policy/cmd/axonflow-policy-import/main.go.
	sum := sha256.Sum256(pub)
	importerKeyID := "import-" + hex.EncodeToString(sum[:8])

	err = s.AuthorizeKey(context.Background(), pdp.RootOrganization, importerKeyID, pub, "import")
	if errors.Is(err, ErrKeyIDNotDerivedFromKey) {
		t.Fatalf("the legacy importer's identifier %q is REFUSED by the derivation gate. It is not repointed onto "+
			"KeyIDFor, so this is a production break on its first run after deploy, with nothing else in the tree to "+
			"catch it: %v", importerKeyID, err)
	}
	// It must fail for the unconnected handle instead - proof it cleared the gate.
	if err == nil {
		t.Fatal("AuthorizeKey succeeded against an unconnected database, so this proves nothing about the gate")
	}

	// And the two derivations agree character for character, which is the
	// property the acceptance above rests on.
	if want := "import-" + keyFingerprint(pub); importerKeyID != want {
		t.Errorf("the importer's identifier and this package's fingerprint disagree:\n  importer: %s\n  ours:     %s\n"+
			"They agree only while both use 8 bytes of SHA-256 in lowercase hex; if either side changes, the importer "+
			"is refused on its first run.", importerKeyID, want)
	}
}
