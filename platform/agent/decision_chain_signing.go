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

// =============================================================================
// Audit non-repudiation: per-record Ed25519 signing + prev_hash chain (#2722)
// =============================================================================
//
// Two independent integrity properties, layered:
//
//   1. prev_hash chain, every record commits to the chain-hash of the
//      previous record in its chain (genesis sentinel for the first). Detects
//      insertion, deletion, and reordering of records: the CHAIN proves
//      ordering and completeness.
//
//   2. per-record Ed25519 signature, every record is signed over its OWN
//      chain-hash. Because the chain-hash is derived purely from the record's
//      own fields plus its stored prev_hash, a SINGLE record can be verified
//      standalone, offline, against the published public key, with no need to
//      fetch or recompute the rest of the chain. The SIGNATURE proves
//      authorship.
//
// Threat model & honest scope: this makes the LIVE decision_chain table
// tamper-PROOF for SIGNED records, an adversary with write access to Postgres
// cannot alter a signed record (or forge a new one in a position) without the
// private key, and cannot silently drop/insert/reorder signed records without
// breaking the chain. It does NOT, on its own, prevent wholesale deletion of a
// trailing suffix of records (truncation), that is what the WORM/Object-Lock
// export path covers, and what an external anchor would harden further.
// Records written before migration 125, or while no signing key is configured,
// are hash-chained where possible but NOT signed, and verification reports them
// honestly as unsigned. This covers the decision_chain surface only; extending
// signing to the orchestrator canonical audit_logs writer is a tracked
// follow-up (see #2722 closeout), deliberately out of scope here.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

// =============================================================================
// Hashing & signing primitives (pure, deterministic, offline-reproducible)
// =============================================================================

// fieldSep / unitSep are control characters used to delimit fields and list
// items inside the digest pre-image. Using control chars that cannot appear in
// the UTF-8 values being hashed, together with explicit length prefixes,
// removes any canonicalization ambiguity (no two distinct field tuples can
// produce the same byte stream).
const (
	fieldSep = "\x1e" // record separator
	unitSep  = "\x1f" // unit separator (list items)
)

// computeRecordDigest produces a deterministic sha256 (hex) over a decision
// record's immutable, round-trip-stable fields. It is the content commitment
// the signature ultimately covers.
//
// Determinism requirements honored here:
//   - created_at is folded in as Unix microseconds (int64): Postgres TIMESTAMPTZ
//     is microsecond-resolution and timezone-normalized, so this round-trips
//     exactly (RecordDecision truncates to microseconds before this is ever
//     called).
//   - string fields use a `len:value` length prefix so concatenation is
//     unambiguous.
//   - list fields (policies_evaluated, data_sources) join with unitSep and a
//     length prefix; element ORDER is preserved (Postgres TEXT[] preserves it).
//   - chain_seq IS included so the signature also commits to the record's
//     claimed position in the chain.
//   - metadata is deliberately EXCLUDED: JSONB normalizes key order / number
//     representation on the write/read round-trip, which would make the digest
//     non-reproducible during verification. The decision's substance is already
//     committed via input_hash / output_hash / audit_hash. This exclusion is
//     documented in the non-repudiation docs.
func computeRecordDigest(e DecisionEntry) string {
	sum := sha256.Sum256([]byte(recordDigestPreimage(e)))
	return hex.EncodeToString(sum[:])
}

// recordDigestPreimage returns the exact byte string that computeRecordDigest
// hashes. It is exposed (base64) by the per-record verify endpoint so a third
// party can reproduce the digest independently: base64-decode the pre-image,
// SHA-256 it, and confirm it equals record_digest, with no trust in our hashing.
// The format is documented byte-for-byte in the non-repudiation docs:
//
//	for each field, in the fixed order below:
//	    scalar: "<label>:<len(value)>:<value>" + 0x1E
//	    list:   "<label>#<count>:<len(joined)>:<joined>" + 0x1E   (items joined by 0x1F)
//	created_at is folded as its Unix-microseconds integer; metadata is excluded.
func recordDigestPreimage(e DecisionEntry) string {
	var b strings.Builder
	w := func(label, v string) {
		b.WriteString(label)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
		b.WriteString(fieldSep)
	}
	wList := func(label string, items []string) {
		joined := strings.Join(items, unitSep)
		b.WriteString(label)
		b.WriteByte('#')
		b.WriteString(strconv.Itoa(len(items)))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(joined)))
		b.WriteByte(':')
		b.WriteString(joined)
		b.WriteString(fieldSep)
	}

	w("id", e.ID)
	w("chain_id", e.ChainID)
	w("request_id", e.RequestID)
	w("parent_request_id", e.ParentRequestID)
	w("step_number", strconv.Itoa(e.StepNumber))
	w("chain_seq", strconv.FormatInt(e.ChainSeq, 10))
	w("org_id", e.OrgID)
	w("tenant_id", e.TenantID)
	w("client_id", e.ClientID)
	w("user_id", e.UserID)
	w("decision_type", string(e.DecisionType))
	w("decision_outcome", string(e.DecisionOutcome))
	w("system_id", e.SystemID)
	w("model_provider", e.ModelProvider)
	w("model_id", e.ModelID)
	wList("policies_evaluated", e.PoliciesEvaluated)
	w("policy_triggered", e.PolicyTriggered)
	w("risk_level", string(e.RiskLevel))
	w("requires_human_review", strconv.FormatBool(e.RequiresHumanReview))
	w("processing_time_ms", strconv.FormatInt(e.ProcessingTimeMs, 10))
	w("input_hash", e.InputHash)
	w("output_hash", e.OutputHash)
	w("audit_hash", e.AuditHash)
	wList("data_sources", e.DataSources)
	w("created_at_unixmicro", strconv.FormatInt(e.CreatedAt.UTC().UnixMicro(), 10))

	return b.String()
}

// computeChainHash binds a record's content digest to its predecessor.
// chain_hash = sha256(recordDigest || '|' || prevHash). This is the value the
// NEXT record stores as its prev_hash, and the value the signature is computed
// over.
func computeChainHash(recordDigest, prevHash string) string {
	sum := sha256.Sum256([]byte(recordDigest + "|" + prevHash))
	return hex.EncodeToString(sum[:])
}

// chainHashOf is the convenience form: derive a record's chain-hash from the
// record itself (its content digest + its stored prev_hash).
func chainHashOf(e DecisionEntry) string {
	return computeChainHash(computeRecordDigest(e), e.PrevHash)
}

// deriveSigningKeyID produces a short, stable identifier for a public key:
// the first 16 hex chars of sha256(pubKey). Stored on every signed record so a
// verifier (and key rotation) can resolve the right public key.
func deriveSigningKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// sealEntry assigns the chain position (prev_hash, chain_seq) and, when a
// signing key is configured, the Ed25519 signature over the record's chain-hash.
// Callers MUST hold the per-chain serialization (in-memory mutex or DB advisory
// lock) so prevHash/seq are consistent with the chain's true tail.
func (t *DecisionChainTracker) sealEntry(e *DecisionEntry, prevHash string, seq int64) {
	e.PrevHash = prevHash
	e.ChainSeq = seq
	chainHash := computeChainHash(computeRecordDigest(*e), prevHash)
	if t.signingKey != nil {
		sig := ed25519.Sign(t.signingKey, []byte(chainHash))
		e.RecordSignature = base64.StdEncoding.EncodeToString(sig)
		e.SigningKeyID = t.signingKeyID
	} else {
		e.RecordSignature = ""
		e.SigningKeyID = ""
	}
}

// =============================================================================
// Signing key loading
// =============================================================================

// LoadAuditSigningKeyFromEnv reads the Ed25519 audit signing key from the
// environment (AXONFLOW_AUDIT_SIGNING_KEY). The value is base64 (any of the
// four common dialects) of either a 32-byte seed or a 64-byte private key.
// AXONFLOW_AUDIT_SIGNING_KEY_ID optionally overrides the derived key id.
//
// Returns (nil, "", nil) when the var is unset, the supported "hash-chain but
// do not sign" mode. Returns an error only when a value is present but invalid,
// so a typo'd key fails loudly rather than silently disabling signing.
func LoadAuditSigningKeyFromEnv() (ed25519.PrivateKey, string, error) {
	raw := strings.TrimSpace(os.Getenv(auditSigningKeyEnvVar))
	if raw == "" {
		return nil, "", nil
	}
	decoded, err := decodeBase64Tolerant(raw)
	if err != nil {
		return nil, "", fmt.Errorf("invalid %s: %w", auditSigningKeyEnvVar, err)
	}

	var key ed25519.PrivateKey
	switch len(decoded) {
	case ed25519.SeedSize: // 32-byte seed
		key = ed25519.NewKeyFromSeed(decoded)
	case ed25519.PrivateKeySize: // 64-byte private key
		key = ed25519.PrivateKey(decoded)
	default:
		return nil, "", fmt.Errorf("invalid %s: expected %d-byte seed or %d-byte private key, got %d bytes",
			auditSigningKeyEnvVar, ed25519.SeedSize, ed25519.PrivateKeySize, len(decoded))
	}

	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("invalid %s: derived public key is not Ed25519", auditSigningKeyEnvVar)
	}
	keyID := strings.TrimSpace(os.Getenv(auditSigningKeyIDEnvVar))
	if keyID == "" {
		keyID = deriveSigningKeyID(pub)
	}
	return key, keyID, nil
}

// auditVerifyKeysEnvVar holds a comma-separated list of base64 Ed25519 PUBLIC
// keys (32 bytes each) used only to verify records, never to sign. Retain a
// retired signing key's public key here after rotation so its records still
// verify. Each key's id is derived the same way as the signing key id.
const auditVerifyKeysEnvVar = "AXONFLOW_AUDIT_VERIFY_KEYS"

// LoadAuditVerifyKeysFromEnv parses AXONFLOW_AUDIT_VERIFY_KEYS into a
// keyID -> public key map. Returns an empty (non-nil) map when unset. Errors on
// any malformed entry so a typo'd rotation key fails loudly.
func LoadAuditVerifyKeysFromEnv() (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey)
	raw := strings.TrimSpace(os.Getenv(auditVerifyKeysEnvVar))
	if raw == "" {
		return out, nil
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		decoded, err := decodeBase64Tolerant(part)
		if err != nil {
			return nil, fmt.Errorf("invalid %s entry: %w", auditVerifyKeysEnvVar, err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid %s entry: expected %d-byte public key, got %d bytes",
				auditVerifyKeysEnvVar, ed25519.PublicKeySize, len(decoded))
		}
		pub := ed25519.PublicKey(decoded)
		out[deriveSigningKeyID(pub)] = pub
	}
	return out, nil
}

// decodeBase64Tolerant decodes a base64 string in any of the four common
// dialects (standard, raw-standard, URL-safe, raw-URL-safe). Mirrors the
// tolerant decoder in platform/agent/license/keygen.go so operators can paste
// whichever form their secrets store produced.
func decodeBase64Tolerant(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encs := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encs {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("not valid base64 (tried standard, raw-standard, URL-safe, raw-URL-safe)")
}

// PublicSigningKey returns the base64 (std) public key this tracker signs with
// and its key id, for publishing to external verifiers. Both empty when no key
// is configured.
func (t *DecisionChainTracker) PublicSigningKey() (keyID, publicKeyB64 string) {
	if t.signingKey == nil {
		return "", ""
	}
	pub, ok := t.signingKey.Public().(ed25519.PublicKey)
	if !ok {
		return "", ""
	}
	return t.signingKeyID, base64.StdEncoding.EncodeToString(pub)
}

// =============================================================================
// Org-scoped reads (RLS-safe) for chain tail + verification
// =============================================================================

// decisionChainColumns is the canonical projection used by every full-record
// read so the scan order is defined in exactly one place.
const decisionChainColumns = `
	id, chain_id, request_id, COALESCE(parent_request_id::text,''), step_number,
	org_id, tenant_id, COALESCE(client_id,''), COALESCE(user_id,''),
	decision_type, decision_outcome, system_id,
	COALESCE(model_provider,''), COALESCE(model_id,''),
	policies_evaluated, COALESCE(policy_triggered,''),
	risk_level, requires_human_review, COALESCE(processing_time_ms,0),
	COALESCE(input_hash,''), COALESCE(output_hash,''), COALESCE(audit_hash,''),
	data_sources, created_at,
	COALESCE(chain_seq,0), COALESCE(prev_hash,''), COALESCE(record_signature,''), COALESCE(signing_key_id,'')`

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanDecisionRow scans a row projected by decisionChainColumns into a
// DecisionEntry. Metadata is NOT selected (and not part of the signed digest).
func scanDecisionRow(s rowScanner) (DecisionEntry, error) {
	var e DecisionEntry
	var decisionType, decisionOutcome, riskLevel string
	var policies, dataSources pq.StringArray
	err := s.Scan(
		&e.ID, &e.ChainID, &e.RequestID, &e.ParentRequestID, &e.StepNumber,
		&e.OrgID, &e.TenantID, &e.ClientID, &e.UserID,
		&decisionType, &decisionOutcome, &e.SystemID,
		&e.ModelProvider, &e.ModelID,
		&policies, &e.PolicyTriggered,
		&riskLevel, &e.RequiresHumanReview, &e.ProcessingTimeMs,
		&e.InputHash, &e.OutputHash, &e.AuditHash,
		&dataSources, &e.CreatedAt,
		&e.ChainSeq, &e.PrevHash, &e.RecordSignature, &e.SigningKeyID,
	)
	if err != nil {
		return DecisionEntry{}, err
	}
	e.DecisionType = DecisionType(decisionType)
	e.DecisionOutcome = DecisionOutcome(decisionOutcome)
	e.RiskLevel = RiskLevel(riskLevel)
	e.PoliciesEvaluated = []string(policies)
	e.DataSources = []string(dataSources)
	// Normalize created_at the same way the writer did, so the verification
	// digest matches the signing digest regardless of how the driver returns
	// the timestamp's location/precision.
	e.CreatedAt = e.CreatedAt.UTC().Truncate(time.Microsecond)
	return e, nil
}

// fetchChainTailTx returns the current last record of a chain (highest
// chain_seq) inside an existing transaction. Used by recordToDB while holding
// the per-chain advisory lock. found=false for an empty chain.
func fetchChainTailTx(ctx context.Context, tx *sql.Tx, chainID string) (DecisionEntry, bool, error) {
	query := `SELECT ` + decisionChainColumns + `
		FROM decision_chain
		WHERE chain_id = $1
		ORDER BY chain_seq DESC NULLS LAST, created_at DESC, id DESC
		LIMIT 1`
	e, err := scanDecisionRow(tx.QueryRowContext(ctx, query, chainID))
	if err == sql.ErrNoRows {
		return DecisionEntry{}, false, nil
	}
	if err != nil {
		return DecisionEntry{}, false, err
	}
	return e, true, nil
}

// fetchChainEntriesOrgScoped returns all records of a chain ordered by
// chain_seq, scoped to orgID under RLS (the SELECT runs inside a WithOrgScope
// transaction so app.current_org_id is set, a chain belonging to another org
// is simply invisible, which is also what makes cross-org chains unlinkable).
func (t *DecisionChainTracker) fetchChainEntriesOrgScoped(ctx context.Context, orgID, chainID string) ([]DecisionEntry, error) {
	var out []DecisionEntry
	err := WithOrgScope(ctx, t.db, orgID, func(tx *sql.Tx) error {
		query := `SELECT ` + decisionChainColumns + `
			FROM decision_chain
			WHERE chain_id = $1
			ORDER BY chain_seq ASC NULLS FIRST, created_at ASC, id ASC`
		rows, err := tx.QueryContext(ctx, query, chainID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e, scanErr := scanDecisionRow(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// fetchRecordOrgScoped returns a single record by id, scoped to orgID under
// RLS. found=false when no such record is visible to the org.
func (t *DecisionChainTracker) fetchRecordOrgScoped(ctx context.Context, orgID, recordID string) (DecisionEntry, bool, error) {
	var e DecisionEntry
	var found bool
	err := WithOrgScope(ctx, t.db, orgID, func(tx *sql.Tx) error {
		query := `SELECT ` + decisionChainColumns + `
			FROM decision_chain WHERE id = $1 LIMIT 1`
		scanned, scanErr := scanDecisionRow(tx.QueryRowContext(ctx, query, recordID))
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		e = scanned
		found = true
		return nil
	})
	if err != nil {
		return DecisionEntry{}, false, err
	}
	return e, found, nil
}

// =============================================================================
// Verification
// =============================================================================

// ChainVerificationResult is the outcome of verifying a full decision chain:
// both the prev_hash linkage (ordering/completeness) and every per-record
// signature (authorship).
type ChainVerificationResult struct {
	ChainID      string `json:"chain_id"`
	OrgID        string `json:"org_id"`
	TotalRecords int    `json:"total_records"`
	// Valid is true when no integrity violation was detected (linkage holds and
	// every signature that exists verifies). NOTE: Valid can be true for a chain
	// with zero signed records, because nothing failed. Use AuthorshipProven for
	// the strong claim that EVERY record's authorship is cryptographically
	// proven.
	Valid bool `json:"valid"`
	// AuthorshipProven is true only when every record is signed AND all
	// signatures + linkage verify. This is the self-describing flag a consumer
	// should gate on for non-repudiation, so an all-unsigned chain (Valid=true)
	// is never mistaken for proof of authorship.
	AuthorshipProven bool `json:"authorship_proven"`
	LinkageValid     bool `json:"linkage_valid"`
	SignaturesValid  bool `json:"signatures_valid"`
	SignedRecords    int  `json:"signed_records"`
	UnsignedRecords  int  `json:"unsigned_records"`

	// First detected break (zero/empty when Valid).
	FirstBrokenSeq      int64  `json:"first_broken_seq,omitempty"`
	FirstBrokenRecordID string `json:"first_broken_record_id,omitempty"`
	BreakReason         string `json:"break_reason,omitempty"`

	// Published verification material so an auditor can independently re-verify
	// offline. SigningKeyID/PublicKey describe the tracker's current key.
	SigningKeyID string    `json:"signing_key_id,omitempty"`
	PublicKey    string    `json:"public_key,omitempty"`
	VerifiedAt   time.Time `json:"verified_at"`
}

// RecordVerificationResult is the outcome of verifying a SINGLE record
// standalone, proving its authorship from the record alone, without the rest
// of the chain.
type RecordVerificationResult struct {
	RecordID       string `json:"record_id"`
	ChainID        string `json:"chain_id"`
	OrgID          string `json:"org_id"`
	ChainSeq       int64  `json:"chain_seq"`
	Signed         bool   `json:"signed"`
	SignatureValid bool   `json:"signature_valid"`
	Valid          bool   `json:"valid"`
	Reason         string `json:"reason,omitempty"`

	// The recomputed material, so the response is independently checkable.
	// DigestPreimageB64 is the exact byte string that hashes to RecordDigest:
	// an offline verifier can base64-decode it, SHA-256 it, and confirm it
	// equals RecordDigest, then rebuild it themselves from the raw record fields
	// per the documented format, trusting neither our digest nor our endpoint.
	DigestPreimageB64 string    `json:"digest_preimage_b64"`
	RecordDigest      string    `json:"record_digest"`
	PrevHash          string    `json:"prev_hash"`
	ChainHash         string    `json:"chain_hash"`
	RecordSignature   string    `json:"record_signature,omitempty"`
	SigningKeyID      string    `json:"signing_key_id,omitempty"`
	PublicKey         string    `json:"public_key,omitempty"`
	VerifiedAt        time.Time `json:"verified_at"`
}

// verifyEntries replays an ordered slice of records: checks each prev_hash
// links to the previous record's recomputed chain-hash, and verifies each
// signed record's Ed25519 signature. Returns a populated result. now is passed
// in so callers (and tests) control VerifiedAt.
func (t *DecisionChainTracker) verifyEntries(orgID, chainID string, entries []DecisionEntry, now time.Time) ChainVerificationResult {
	res := ChainVerificationResult{
		ChainID:         chainID,
		OrgID:           orgID,
		TotalRecords:    len(entries),
		LinkageValid:    true,
		SignaturesValid: true,
		SigningKeyID:    t.signingKeyID,
		VerifiedAt:      now,
	}
	if _, pub := t.PublicSigningKey(); pub != "" {
		res.PublicKey = pub
	}

	prev := genesisPrevHash
	for _, e := range entries {
		// Linkage: this record must point at the previous record's chain-hash.
		if e.PrevHash != prev {
			res.LinkageValid = false
			res.FirstBrokenSeq = e.ChainSeq
			res.FirstBrokenRecordID = e.ID
			res.BreakReason = fmt.Sprintf("linkage break at chain_seq=%d (record %s): prev_hash does not match the previous record's chain-hash (insertion, deletion, reordering, or a pre-signing legacy record that predates migration 125)", e.ChainSeq, e.ID)
			break
		}

		digest := computeRecordDigest(e)
		chainHash := computeChainHash(digest, e.PrevHash)

		if e.SigningKeyID == "" || e.RecordSignature == "" {
			res.UnsignedRecords++
		} else {
			res.SignedRecords++
			ok, reason := t.verifySignature(e, chainHash)
			if !ok {
				res.SignaturesValid = false
				res.FirstBrokenSeq = e.ChainSeq
				res.FirstBrokenRecordID = e.ID
				res.BreakReason = fmt.Sprintf("signature break at chain_seq=%d (record %s): %s", e.ChainSeq, e.ID, reason)
				break
			}
		}
		prev = chainHash
	}

	res.Valid = res.LinkageValid && res.SignaturesValid && res.BreakReason == ""
	// Strong claim: every record signed AND everything verifies.
	res.AuthorshipProven = res.Valid && res.TotalRecords > 0 && res.SignedRecords == res.TotalRecords
	return res
}

// verifySignature checks one record's Ed25519 signature over its chain-hash
// using the public key resolved from signing_key_id.
func (t *DecisionChainTracker) verifySignature(e DecisionEntry, chainHash string) (bool, string) {
	pub, ok := t.verifyKeys[e.SigningKeyID]
	if !ok {
		return false, fmt.Sprintf("no public key available for signing_key_id=%q (cannot verify; do not trust)", e.SigningKeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(e.RecordSignature)
	if err != nil {
		return false, "record_signature is not valid base64"
	}
	if !ed25519.Verify(pub, []byte(chainHash), sig) {
		return false, "Ed25519 signature does not verify (record content or linkage altered, or wrong key)"
	}
	return true, ""
}

// VerifyChain loads a chain (org-scoped) and verifies its linkage + signatures.
// found=false when the chain has no records visible to the org.
func (t *DecisionChainTracker) VerifyChain(ctx context.Context, orgID, chainID string) (ChainVerificationResult, bool, error) {
	if orgID == "" {
		return ChainVerificationResult{}, false, fmt.Errorf("VerifyChain: orgID must be set")
	}
	var entries []DecisionEntry
	if t.useMemory {
		entries = t.memoryChainForOrg(orgID, chainID)
	} else {
		var err error
		entries, err = t.fetchChainEntriesOrgScoped(ctx, orgID, chainID)
		if err != nil {
			return ChainVerificationResult{}, false, err
		}
	}
	if len(entries) == 0 {
		return ChainVerificationResult{}, false, nil
	}
	return t.verifyEntries(orgID, chainID, entries, time.Now().UTC()), true, nil
}

// VerifyRecord proves a single record's authorship standalone: it recomputes
// the record's chain-hash from the record's own fields + its stored prev_hash,
// and verifies the signature against the published public key. No other record
// in the chain is consulted. found=false when the record is not visible to org.
func (t *DecisionChainTracker) VerifyRecord(ctx context.Context, orgID, recordID string) (RecordVerificationResult, bool, error) {
	if orgID == "" {
		return RecordVerificationResult{}, false, fmt.Errorf("VerifyRecord: orgID must be set")
	}
	var (
		e     DecisionEntry
		found bool
	)
	if t.useMemory {
		e, found = t.memoryRecordForOrg(orgID, recordID)
	} else {
		var err error
		e, found, err = t.fetchRecordOrgScoped(ctx, orgID, recordID)
		if err != nil {
			return RecordVerificationResult{}, false, err
		}
	}
	if !found {
		return RecordVerificationResult{}, false, nil
	}

	preimage := recordDigestPreimage(e)
	digest := computeRecordDigest(e)
	chainHash := computeChainHash(digest, e.PrevHash)
	res := RecordVerificationResult{
		RecordID:          e.ID,
		ChainID:           e.ChainID,
		OrgID:             orgID,
		ChainSeq:          e.ChainSeq,
		DigestPreimageB64: base64.StdEncoding.EncodeToString([]byte(preimage)),
		RecordDigest:      digest,
		PrevHash:          e.PrevHash,
		ChainHash:         chainHash,
		RecordSignature:   e.RecordSignature,
		SigningKeyID:      e.SigningKeyID,
		VerifiedAt:        time.Now().UTC(),
	}
	if pub, ok := t.verifyKeys[e.SigningKeyID]; ok {
		res.PublicKey = base64.StdEncoding.EncodeToString(pub)
	}

	if e.SigningKeyID == "" || e.RecordSignature == "" {
		res.Signed = false
		res.Valid = false
		res.Reason = "record is not signed (no audit signing key was configured when it was recorded); its authorship cannot be cryptographically proven"
		return res, true, nil
	}
	res.Signed = true
	ok, reason := t.verifySignature(e, chainHash)
	res.SignatureValid = ok
	res.Valid = ok
	if !ok {
		res.Reason = reason
	}
	return res, true, nil
}

// memoryChainForOrg returns the in-memory chain filtered to org (test mode).
func (t *DecisionChainTracker) memoryChainForOrg(orgID, chainID string) []DecisionEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []DecisionEntry
	for _, e := range t.memoryStore[chainID] {
		if e.OrgID == orgID {
			out = append(out, e)
		}
	}
	return out
}

// memoryRecordForOrg returns a single in-memory record by id, scoped to org.
func (t *DecisionChainTracker) memoryRecordForOrg(orgID, recordID string) (DecisionEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, entries := range t.memoryStore {
		for _, e := range entries {
			if e.ID == recordID && e.OrgID == orgID {
				return e, true
			}
		}
	}
	return DecisionEntry{}, false
}
