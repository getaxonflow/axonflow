// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// testSigningKey returns a deterministic Ed25519 key for tests (fixed seed).
func testSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func newSigningTracker(t *testing.T) *DecisionChainTracker {
	t.Helper()
	tr, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		SystemID:   "test/1.0.0",
		SigningKey: testSigningKey(t),
	})
	if err != nil {
		t.Fatalf("NewDecisionChainTracker: %v", err)
	}
	return tr
}

func sampleEntry(org, chain string, step int) DecisionEntry {
	return DecisionEntry{
		ChainID:          chain,
		RequestID:        uuid.New().String(),
		OrgID:            org,
		TenantID:         "tenant-1",
		ClientID:         "client-1",
		UserID:           "user-1",
		StepNumber:       step,
		DecisionType:     DecisionTypePolicyEnforcement,
		DecisionOutcome:  DecisionOutcomeApproved,
		ProcessingTimeMs: int64(10 * step),
		InputHash:        fmt.Sprintf("in-%d", step),
		OutputHash:       fmt.Sprintf("out-%d", step),
	}
}

// -----------------------------------------------------------------------------
// Chaining
// -----------------------------------------------------------------------------

func TestChainLinksAcrossNRecords(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org, chain = "org-1", "chain-A"
	const n = 7

	for i := 1; i <= n; i++ {
		if err := tr.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	res, found, err := tr.VerifyChain(ctx, org, chain)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !found {
		t.Fatal("expected chain to be found")
	}
	if !res.Valid {
		t.Fatalf("expected valid chain, got break: %s", res.BreakReason)
	}
	if res.TotalRecords != n {
		t.Errorf("TotalRecords = %d, want %d", res.TotalRecords, n)
	}
	if res.SignedRecords != n || res.UnsignedRecords != 0 {
		t.Errorf("signed=%d unsigned=%d, want %d/0", res.SignedRecords, res.UnsignedRecords, n)
	}
	if !res.LinkageValid || !res.SignaturesValid {
		t.Errorf("linkage=%v signatures=%v, want both true", res.LinkageValid, res.SignaturesValid)
	}
	if !res.AuthorshipProven {
		t.Error("expected AuthorshipProven=true for a fully-signed valid chain")
	}

	// chain_seq must be 1..n, strictly increasing; first record links to genesis.
	entries := tr.memoryChainForOrg(org, chain)
	if len(entries) != n {
		t.Fatalf("memory chain len = %d, want %d", len(entries), n)
	}
	if entries[0].PrevHash != genesisPrevHash {
		t.Errorf("first record prev_hash = %q, want genesis sentinel", entries[0].PrevHash)
	}
	for i, e := range entries {
		if e.ChainSeq != int64(i+1) {
			t.Errorf("entries[%d].ChainSeq = %d, want %d", i, e.ChainSeq, i+1)
		}
		if i > 0 {
			wantPrev := chainHashOf(entries[i-1])
			if e.PrevHash != wantPrev {
				t.Errorf("entries[%d].PrevHash does not link to previous record's chain hash", i)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Per-record signature + STANDALONE offline verification (addendum bar)
// -----------------------------------------------------------------------------

func TestSingleRecordVerifiesStandaloneOffline(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org, chain = "org-1", "chain-standalone"

	// A few records so the target is NOT the genesis record (proving we don't
	// need the rest of the chain to verify it).
	for i := 1; i <= 3; i++ {
		if err := tr.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	target := tr.memoryChainForOrg(org, chain)[1] // the middle record

	res, found, err := tr.VerifyRecord(ctx, org, target.ID)
	if err != nil || !found {
		t.Fatalf("VerifyRecord found=%v err=%v", found, err)
	}
	if !res.Valid || !res.Signed || !res.SignatureValid {
		t.Fatalf("expected valid signed record, got valid=%v signed=%v sigValid=%v reason=%s",
			res.Valid, res.Signed, res.SignatureValid, res.Reason)
	}

	// Now PROVE authorship independently, the way an external auditor would:
	// using ONLY the published public key + the record's own digest/prev_hash,
	// with no access to the tracker's private key and no other record consulted.
	keyID, pubB64 := tr.PublicSigningKey()
	if pubB64 == "" || keyID == "" {
		t.Fatal("expected a published public key")
	}
	if res.PublicKey != pubB64 {
		t.Errorf("VerifyRecord public key mismatch with PublicSigningKey")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	pub := ed25519.PublicKey(pubBytes)

	// Zero-trust digest check: the endpoint returns the exact pre-image bytes
	// that hash to record_digest. An auditor SHA-256s those bytes and confirms
	// they match record_digest, trusting neither our hash nor our endpoint's
	// digest claim. (The pre-image can also be rebuilt from raw fields per the
	// documented format.)
	preimage, err := base64.StdEncoding.DecodeString(res.DigestPreimageB64)
	if err != nil {
		t.Fatalf("decode preimage: %v", err)
	}
	if h := sha256Hex(preimage); h != res.RecordDigest {
		t.Fatalf("sha256(preimage)=%q != record_digest=%q", h, res.RecordDigest)
	}

	// Recompute the chain hash purely from the record's own fields + its stored
	// prev_hash (exactly what the verify endpoint returns), then check the sig.
	recomputed := computeChainHash(computeRecordDigest(target), target.PrevHash)
	if recomputed != res.ChainHash {
		t.Fatalf("recomputed chain hash %q != endpoint chain hash %q", recomputed, res.ChainHash)
	}
	sig, err := base64.StdEncoding.DecodeString(target.RecordSignature)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, []byte(recomputed), sig) {
		t.Fatal("standalone offline signature verification FAILED (should pass)")
	}
}

// -----------------------------------------------------------------------------
// Tamper detection (red-on-revert style: tampering MUST fail verification)
// -----------------------------------------------------------------------------

func TestTamperedRecordFailsVerification(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org, chain = "org-1", "chain-tamper"
	for i := 1; i <= 4; i++ {
		if err := tr.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	// Baseline: valid.
	if res, _, _ := tr.VerifyChain(ctx, org, chain); !res.Valid {
		t.Fatalf("baseline chain should be valid, got: %s", res.BreakReason)
	}

	// Tamper the content of record #2 directly in the store (simulating a
	// DB-level adversary flipping an "approved" decision after the fact).
	tr.mu.Lock()
	tr.memoryStore[chain][1].DecisionOutcome = DecisionOutcomeBlocked
	tamperedID := tr.memoryStore[chain][1].ID
	tr.mu.Unlock()

	// Single-record verification of the tampered record must fail.
	rres, found, _ := tr.VerifyRecord(ctx, org, tamperedID)
	if !found {
		t.Fatal("tampered record should still be found")
	}
	if rres.Valid || rres.SignatureValid {
		t.Error("tampered record passed signature verification (should fail)")
	}

	// Whole-chain verification must report the break at the tampered record.
	cres, _, _ := tr.VerifyChain(ctx, org, chain)
	if cres.Valid {
		t.Error("tampered chain passed verification (should fail)")
	}
	if cres.FirstBrokenRecordID != tamperedID {
		t.Errorf("first broken record = %q, want tampered %q", cres.FirstBrokenRecordID, tamperedID)
	}
	if cres.BreakReason == "" {
		t.Error("expected a non-empty break reason")
	}
}

func TestTamperedSignatureFailsVerification(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org, chain = "org-1", "chain-sigtamper"
	if err := tr.RecordDecision(ctx, sampleEntry(org, chain, 1)); err != nil {
		t.Fatalf("record: %v", err)
	}
	id := tr.memoryChainForOrg(org, chain)[0].ID

	// Corrupt the signature bytes.
	tr.mu.Lock()
	orig, _ := base64.StdEncoding.DecodeString(tr.memoryStore[chain][0].RecordSignature)
	orig[0] ^= 0xFF
	tr.memoryStore[chain][0].RecordSignature = base64.StdEncoding.EncodeToString(orig)
	tr.mu.Unlock()

	res, _, _ := tr.VerifyRecord(ctx, org, id)
	if res.Valid || res.SignatureValid {
		t.Error("corrupted signature passed verification (should fail)")
	}
}

// Reordering must be detected even if individual signatures are intact, because
// prev_hash linkage no longer holds.
func TestReorderingDetected(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org, chain = "org-1", "chain-reorder"
	for i := 1; i <= 3; i++ {
		if err := tr.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	tr.mu.Lock()
	tr.memoryStore[chain][1], tr.memoryStore[chain][2] = tr.memoryStore[chain][2], tr.memoryStore[chain][1]
	tr.mu.Unlock()

	res, _, _ := tr.VerifyChain(ctx, org, chain)
	if res.Valid || res.LinkageValid {
		t.Error("reordered chain passed linkage verification (should fail)")
	}
}

// -----------------------------------------------------------------------------
// Unsigned mode (no key configured)
// -----------------------------------------------------------------------------

func TestUnsignedModeChainsButDoesNotSign(t *testing.T) {
	tr, err := NewDecisionChainTracker(DecisionChainTrackerConfig{SystemID: "test/1.0.0"})
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}
	ctx := context.Background()
	const org, chain = "org-1", "chain-unsigned"
	for i := 1; i <= 3; i++ {
		if err := tr.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	// Linkage is valid; signatures absent.
	cres, found, _ := tr.VerifyChain(ctx, org, chain)
	if !found {
		t.Fatal("chain should be found")
	}
	if !cres.LinkageValid {
		t.Errorf("unsigned chain linkage should still be valid: %s", cres.BreakReason)
	}
	if cres.SignedRecords != 0 || cres.UnsignedRecords != 3 {
		t.Errorf("signed=%d unsigned=%d, want 0/3", cres.SignedRecords, cres.UnsignedRecords)
	}
	// Honest framing: an unsigned chain has no integrity violation (Valid may be
	// true) but authorship is NOT proven. The self-describing flag must say so.
	if cres.AuthorshipProven {
		t.Error("AuthorshipProven must be false for an all-unsigned chain")
	}

	// Single-record verification of an unsigned record must NOT claim validity.
	id := tr.memoryChainForOrg(org, chain)[0].ID
	rres, _, _ := tr.VerifyRecord(ctx, org, id)
	if rres.Signed || rres.Valid {
		t.Error("unsigned record must not be reported as a valid proof of authorship")
	}
	if rres.Reason == "" {
		t.Error("expected an explanatory reason for the unsigned record")
	}
}

// -----------------------------------------------------------------------------
// RLS / org isolation (memory-mode analogue) + empty OrgID rejection
// -----------------------------------------------------------------------------

func TestWriteWithoutOrgIDStillRejected(t *testing.T) {
	tr := newSigningTracker(t)
	err := tr.RecordDecision(context.Background(), DecisionEntry{
		ChainID:         "c",
		RequestID:       "r",
		DecisionType:    DecisionTypePolicyEnforcement,
		DecisionOutcome: DecisionOutcomeApproved,
		// OrgID intentionally empty
	})
	if err == nil {
		t.Fatal("expected RecordDecision to reject empty OrgID")
	}
}

func TestCrossOrgChainNotLinkable(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const chain = "shared-chain-id"
	if err := tr.RecordDecision(ctx, sampleEntry("org-A", chain, 1)); err != nil {
		t.Fatalf("record: %v", err)
	}

	// A different org cannot see / verify org-A's chain.
	_, found, err := tr.VerifyChain(ctx, "org-B", chain)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if found {
		t.Error("org-B must not be able to verify org-A's chain")
	}

	// And cannot fetch a record by id either.
	recID := tr.memoryChainForOrg("org-A", chain)[0].ID
	_, foundRec, _ := tr.VerifyRecord(ctx, "org-B", recID)
	if foundRec {
		t.Error("org-B must not be able to verify org-A's record")
	}
}

// -----------------------------------------------------------------------------
// Concurrency: parallel appends to one chain produce a valid linear chain
// -----------------------------------------------------------------------------

func TestConcurrentAppendsProduceLinearChain(t *testing.T) {
	tr := newSigningTracker(t)
	ctx := context.Background()
	const org, chain = "org-1", "chain-concurrent"
	const n = 60

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(step int) {
			defer wg.Done()
			if err := tr.RecordDecision(ctx, sampleEntry(org, chain, step)); err != nil {
				t.Errorf("record %d: %v", step, err)
			}
		}(i + 1)
	}
	wg.Wait()

	res, found, err := tr.VerifyChain(ctx, org, chain)
	if err != nil || !found {
		t.Fatalf("VerifyChain found=%v err=%v", found, err)
	}
	if res.TotalRecords != n {
		t.Fatalf("TotalRecords = %d, want %d", res.TotalRecords, n)
	}
	if !res.Valid {
		t.Fatalf("concurrent chain not valid: %s", res.BreakReason)
	}

	// chain_seq must be a permutation of 1..n with no gaps/dupes.
	seen := make(map[int64]bool)
	for _, e := range tr.memoryChainForOrg(org, chain) {
		if seen[e.ChainSeq] {
			t.Errorf("duplicate chain_seq %d", e.ChainSeq)
		}
		seen[e.ChainSeq] = true
	}
	for s := int64(1); s <= n; s++ {
		if !seen[s] {
			t.Errorf("missing chain_seq %d", s)
		}
	}
}

// -----------------------------------------------------------------------------
// Pure-helper coverage
// -----------------------------------------------------------------------------

func TestComputeRecordDigestDeterministic(t *testing.T) {
	e := sampleEntry("org-1", "chain-x", 1)
	e.ID = "fixed-id"
	e.RequestID = "fixed-req"
	e.PoliciesEvaluated = []string{"p1", "p2"}
	e.DataSources = []string{"db1"}
	a := computeRecordDigest(e)
	b := computeRecordDigest(e)
	if a != b {
		t.Fatal("computeRecordDigest is not deterministic for identical input")
	}
	// Changing any committed field changes the digest.
	e2 := e
	e2.DecisionOutcome = DecisionOutcomeBlocked
	if computeRecordDigest(e2) == a {
		t.Error("digest did not change when decision_outcome changed")
	}
	// Order of list items is significant.
	e3 := e
	e3.PoliciesEvaluated = []string{"p2", "p1"}
	if computeRecordDigest(e3) == a {
		t.Error("digest did not change when policy order changed")
	}
}

func TestDeriveSigningKeyIDStable(t *testing.T) {
	key := testSigningKey(t)
	pub := key.Public().(ed25519.PublicKey)
	id1 := deriveSigningKeyID(pub)
	id2 := deriveSigningKeyID(pub)
	if id1 != id2 {
		t.Fatal("deriveSigningKeyID not stable")
	}
	if len(id1) != 16 {
		t.Errorf("key id length = %d, want 16", len(id1))
	}
}

func TestLoadAuditSigningKeyFromEnv(t *testing.T) {
	// Unset -> nil, no error.
	t.Setenv(auditSigningKeyEnvVar, "")
	if key, _, err := LoadAuditSigningKeyFromEnv(); err != nil || key != nil {
		t.Fatalf("unset env: key=%v err=%v, want nil/nil", key, err)
	}

	// 32-byte seed (base64).
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 3)
	}
	t.Setenv(auditSigningKeyEnvVar, base64.StdEncoding.EncodeToString(seed))
	key, keyID, err := LoadAuditSigningKeyFromEnv()
	if err != nil || key == nil {
		t.Fatalf("seed env: key=%v err=%v", key, err)
	}
	if len(key) != ed25519.PrivateKeySize {
		t.Errorf("key size = %d, want %d", len(key), ed25519.PrivateKeySize)
	}
	want := deriveSigningKeyID(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if keyID != want {
		t.Errorf("keyID = %q, want %q", keyID, want)
	}

	// 64-byte full private key (raw-url base64, to exercise tolerant decode).
	full := ed25519.NewKeyFromSeed(seed)
	t.Setenv(auditSigningKeyEnvVar, base64.RawURLEncoding.EncodeToString(full))
	if k2, _, err := LoadAuditSigningKeyFromEnv(); err != nil || k2 == nil {
		t.Fatalf("full key env: k=%v err=%v", k2, err)
	}

	// Invalid length -> error.
	t.Setenv(auditSigningKeyEnvVar, base64.StdEncoding.EncodeToString([]byte("too-short")))
	if _, _, err := LoadAuditSigningKeyFromEnv(); err == nil {
		t.Error("expected error for invalid key length")
	}

	// Custom key id override.
	t.Setenv(auditSigningKeyEnvVar, base64.StdEncoding.EncodeToString(seed))
	t.Setenv(auditSigningKeyIDEnvVar, "my-key-2026")
	if _, id, err := LoadAuditSigningKeyFromEnv(); err != nil || id != "my-key-2026" {
		t.Errorf("override id = %q err=%v, want my-key-2026", id, err)
	}
}

func TestLoadAuditVerifyKeysFromEnv(t *testing.T) {
	t.Setenv(auditVerifyKeysEnvVar, "")
	if m, err := LoadAuditVerifyKeysFromEnv(); err != nil || len(m) != 0 {
		t.Fatalf("unset: m=%v err=%v, want empty/nil", m, err)
	}

	pubA := testSigningKey(t).Public().(ed25519.PublicKey)
	seedB := make([]byte, ed25519.SeedSize)
	for i := range seedB {
		seedB[i] = byte(100 - i)
	}
	pubB := ed25519.NewKeyFromSeed(seedB).Public().(ed25519.PublicKey)
	t.Setenv(auditVerifyKeysEnvVar, base64.StdEncoding.EncodeToString(pubA)+", "+base64.RawURLEncoding.EncodeToString(pubB))
	m, err := LoadAuditVerifyKeysFromEnv()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("got %d keys, want 2", len(m))
	}
	if _, ok := m[deriveSigningKeyID(pubA)]; !ok {
		t.Error("missing key A")
	}
	if _, ok := m[deriveSigningKeyID(pubB)]; !ok {
		t.Error("missing key B")
	}

	// A private key (64 bytes) or junk is rejected (must be a 32-byte public key).
	t.Setenv(auditVerifyKeysEnvVar, base64.StdEncoding.EncodeToString(testSigningKey(t)))
	if _, err := LoadAuditVerifyKeysFromEnv(); err == nil {
		t.Error("expected error for non-public-key-sized entry")
	}
}

// TestVerificationKeysCannotOverwriteSigningKey ensures a VerificationKeys
// entry sharing the current signing key's id cannot replace the real public
// key (a malformed/hostile config must not break self-verification).
func TestVerificationKeysCannotOverwriteSigningKey(t *testing.T) {
	signKey := testSigningKey(t)
	realPub := signKey.Public().(ed25519.PublicKey)
	keyID := deriveSigningKeyID(realPub)

	// A bogus public key under the SAME id as the signing key.
	bogusSeed := make([]byte, ed25519.SeedSize)
	for i := range bogusSeed {
		bogusSeed[i] = 0x55
	}
	bogusPub := ed25519.NewKeyFromSeed(bogusSeed).Public().(ed25519.PublicKey)

	tr, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		SystemID:         "t",
		SigningKey:       signKey,
		VerificationKeys: map[string]ed25519.PublicKey{keyID: bogusPub},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := context.Background()
	const org, chain = "org-1", "chain-overwrite"
	if err := tr.RecordDecision(ctx, sampleEntry(org, chain, 1)); err != nil {
		t.Fatalf("record: %v", err)
	}
	// If the bogus key had overwritten the real one, this would fail to verify.
	res, _, _ := tr.VerifyChain(ctx, org, chain)
	if !res.Valid || !res.AuthorshipProven {
		t.Fatalf("signing key public half was overwritten by a colliding VerificationKeys entry: %s", res.BreakReason)
	}
}

// TestKeyRotationVerification proves rotation works: a tracker that signs with a
// NEW key can still verify records signed by a RETIRED key, as long as the
// retired public key is retained in VerificationKeys. Without it, those records
// must report as unverifiable (never falsely valid).
func TestKeyRotationVerification(t *testing.T) {
	ctx := context.Background()
	const org, chain = "org-1", "chain-rotate"

	// Old tracker signs the records.
	oldKey := testSigningKey(t)
	oldTracker, err := NewDecisionChainTracker(DecisionChainTrackerConfig{SystemID: "t", SigningKey: oldKey})
	if err != nil {
		t.Fatalf("old tracker: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if err := oldTracker.RecordDecision(ctx, sampleEntry(org, chain, i)); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	sealed := oldTracker.memoryChainForOrg(org, chain)
	oldPub := oldKey.Public().(ed25519.PublicKey)
	oldKeyID := deriveSigningKeyID(oldPub)

	// New tracker: different signing key, but retains the old public key.
	newSeed := make([]byte, ed25519.SeedSize)
	for i := range newSeed {
		newSeed[i] = byte(200 - i)
	}
	newKey := ed25519.NewKeyFromSeed(newSeed)
	rotated, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
		SystemID:         "t",
		SigningKey:       newKey,
		VerificationKeys: map[string]ed25519.PublicKey{oldKeyID: oldPub},
	})
	if err != nil {
		t.Fatalf("rotated tracker: %v", err)
	}
	// Inject the old-key records into the rotated tracker's store.
	rotated.mu.Lock()
	rotated.memoryStore[chain] = append([]DecisionEntry(nil), sealed...)
	rotated.mu.Unlock()

	res, found, err := rotated.VerifyChain(ctx, org, chain)
	if err != nil || !found {
		t.Fatalf("VerifyChain found=%v err=%v", found, err)
	}
	if !res.Valid || !res.AuthorshipProven {
		t.Fatalf("rotated tracker should verify old-key records, got valid=%v proven=%v reason=%s",
			res.Valid, res.AuthorshipProven, res.BreakReason)
	}

	// Negative: a tracker WITHOUT the old public key cannot verify them.
	noOldKey, err := NewDecisionChainTracker(DecisionChainTrackerConfig{SystemID: "t", SigningKey: newKey})
	if err != nil {
		t.Fatalf("noOldKey tracker: %v", err)
	}
	noOldKey.mu.Lock()
	noOldKey.memoryStore[chain] = append([]DecisionEntry(nil), sealed...)
	noOldKey.mu.Unlock()
	res2, _, _ := noOldKey.VerifyChain(ctx, org, chain)
	if res2.Valid {
		t.Error("tracker without the retired key must NOT report old-key records as valid")
	}
}
