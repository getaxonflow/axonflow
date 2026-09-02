// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The TrustRealm storage codec (#3550, migration core/169).
//
// # Why there is a codec at all, rather than json.Marshal(realm)
//
// Seven of TrustRealm's fields are `int` enumerations - AssuranceClass,
// DirectorySource, InteractiveClass, RevocationSource, DelegationPolicy,
// AuthorizedPartyPolicy, CredentialAgePolicy - declared with iota. Marshalling
// those directly stores the NUMBER, and the number is not a contract: inserting
// a constant into any of those blocks silently reinterprets every stored row,
// turning (say) a SCIM directory into an external graph with no error anywhere.
// It also makes the table unreadable to an operator, who sees `"Directory": 2`.
//
// So each of them is stored by its declared NAME, rendered by the type's own
// String() method, and read back by matching against the same small candidate
// list. The lists are the single place the vocabulary is declared for storage,
// and TestEveryDeclaredEnumValueIsStorable scans a wide integer range against
// each type's own IsValid() to prove no declared value is missing from one - so
// a value added to realm.go and forgotten here is a test failure rather than a
// row that will not load.
//
// # Why an unknown stored value is an ERROR and never a default
//
// Every one of these enumerations reserves its ZERO value for "not declared",
// and Register refuses a realm that leaves one there. That is EX-47: a
// fail-open produced entirely by omission, where a falsy default reads as
// has_group_graph = false, makes an empty group closure look authoritative and
// skips every segment-scoped ceiling. A decoder that mapped an unrecognised
// string to the zero value would manufacture exactly that state from a typo.
// It refuses instead, and the realm does not load - which is UNKNOWN_REALM,
// which denies.

package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// storageFormatVersion prefixes every stored realm.
//
// It is not decoration: a change to how these fields are rendered has to be
// detectable, and a row written by a newer format read by an older binary must
// FAIL rather than be interpreted under the wrong rules. A rolling deployment
// makes that ordering ordinary rather than exotic.
const storageFormatVersion = "axonflow.trust-realm.v1"

// maxStorableIssuer bounds canonical_issuer, which is half of
// UNIQUE (org_id, canonical_issuer). See encodeRealm for why the type enforces
// a bound the index would otherwise enforce as a raw driver error.
const maxStorableIssuer = 2000

// realmRecord is the stored shape of a TrustRealm.
//
// Every field of TrustRealm appears here exactly once.
// TestEveryTrustRealmFieldSurvivesTheRoundTrip walks TrustRealm by reflection
// over a fixture in which every field is non-zero, so a field added to the
// realm and forgotten here fails rather than coming back as its zero value -
// and its zero value is "not declared", which is the state EX-47 is made of.
type realmRecord struct {
	FormatVersion string `json:"format_version"`

	RealmID         string `json:"realm_id"`
	OrgID           string `json:"org_id"`
	Kind            string `json:"kind"`
	CanonicalIssuer string `json:"canonical_issuer"`

	AcceptedSubjectTypes    []string `json:"accepted_subject_types"`
	AcceptedCredentialTypes []string `json:"accepted_credential_types"`
	Audiences               []string `json:"audiences"`

	AuthorizedPartyPolicy string   `json:"authorized_party_policy"`
	AuthorizedParties     []string `json:"authorized_parties"`

	AllowedSigningAlgorithms []string `json:"allowed_signing_algorithms"`

	ClaimMapping claimMappingRecord `json:"claim_mapping"`

	MinimumAssurance string `json:"minimum_assurance"`

	// Durations are stored as SECONDS rather than as Go's nanosecond int64.
	// Nanoseconds are a Go representation detail; seconds are what an operator
	// reading the row means, and what a future non-Go reader would expect.
	ClockSkewSeconds        int64  `json:"clock_skew_seconds"`
	CredentialAgePolicy     string `json:"credential_age_policy"`
	MaxCredentialAgeSeconds int64  `json:"max_credential_age_seconds"`

	Directory   string `json:"directory"`
	Interactive string `json:"interactive"`
	Revocation  string `json:"revocation"`

	Delegation     string   `json:"delegation"`
	DelegateRealms []string `json:"delegate_realms"`

	Enabled bool  `json:"enabled"`
	Version int64 `json:"version"`
}

type claimMappingRecord struct {
	Version      int               `json:"version"`
	SubjectClaim string            `json:"subject_claim"`
	SubjectType  string            `json:"subject_type"`
	AliasClaims  map[string]string `json:"alias_claims"`
}

// ---------------------------------------------------------------------------
// The enumeration vocabularies
// ---------------------------------------------------------------------------

// Each list declares every value of its type that may be STORED. The zero
// values are deliberately absent: "unspecified" is not a state a registered
// realm can be in, so it is not a state the store has to be able to write, and
// leaving it out means a row can never carry one.
var (
	storableAssurance = []AssuranceClass{
		AssuranceLow, AssuranceSubstantial, AssuranceHigh,
	}
	storableDirectory = []DirectorySource{
		DirectorySourceNone, DirectorySourceSCIM, DirectorySourceExternalGraph,
	}
	storableInteractive = []InteractiveClass{
		InteractiveHuman, InteractiveNonInteractive,
	}
	storableRevocation = []RevocationSource{
		RevocationSourceNone, RevocationSourceLocalStore, RevocationSourceSharedSignals,
	}
	storableDelegation = []DelegationPolicy{
		DelegationDenied, DelegationAllowList, DelegationAnyRealmInOrg,
	}
	storableAuthorizedParty = []AuthorizedPartyPolicy{
		AuthorizedPartyNotChecked, AuthorizedPartyAllowList,
	}
	storableCredentialAge = []CredentialAgePolicy{
		CredentialAgeUnbounded, CredentialAgeBounded,
	}
)

// decodeEnum resolves a stored name back to its declared value.
//
// GENERIC over the candidate list rather than a hand-written switch per type,
// so the rendering used to WRITE (the type's own String) is also the one used
// to MATCH on read. A hand-written parse table would be a second spelling of
// the vocabulary, free to drift from String() one constant at a time.
func decodeEnum[T fmt.Stringer](field, stored string, candidates []T) (T, error) {
	for _, c := range candidates {
		if c.String() == stored {
			return c, nil
		}
	}
	var zero T
	names := make([]string, 0, len(candidates))
	for _, c := range candidates {
		names = append(names, c.String())
	}
	return zero, fmt.Errorf("identity: stored realm field %s has value %q, which is not one of %s.\n"+
		"It is refused rather than defaulted: the zero value of every one of these fields means \"not declared\", and manufacturing that from an unrecognised string is EX-47 - a falsy default reads as has_group_graph=false, makes an empty group closure look authoritative, and skips every segment-scoped ceiling",
		field, stored, strings.Join(names, ", "))
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

// encodeRealm renders a realm for storage.
//
// It REFUSES a realm that would not validate. A stored realm that cannot be
// registered is a row that fails to load on every subsequent boot, and the
// failure surfaces far from the write that caused it.
func encodeRealm(r TrustRealm) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("identity: refusing to store an invalid trust realm: %w", err)
	}

	// THE ISSUER'S LENGTH IS BOUNDED HERE BECAUSE THE INDEX BOUNDS IT ANYWAY,
	// and this is the same defect as the realm-id one, one column across.
	//
	// canonical_issuer sits in UNIQUE (org_id, canonical_issuer), and a btree
	// entry cannot exceed roughly a third of a page: an incompressible ~3200
	// byte issuer fails the INSERT with
	// `index row size 3216 exceeds btree version 4 maximum 2704` - a raw
	// driver error, from a realm that Validate and this encoder both called
	// fine, and one whose reachability depends on how well the value happens
	// to COMPRESS. Bounding it here makes the refusal a property of the type
	// rather than of the data's entropy.
	//
	// maxStorableIssuer is well under the btree limit rather than at it,
	// because the index entry also carries org_id and its own overhead, and a
	// bound that sits exactly on a limit it does not control is a bound that
	// moves when something else grows.
	if len(r.CanonicalIssuer) > maxStorableIssuer {
		return nil, fmt.Errorf("identity: realm %q declares a canonical issuer of %d bytes; the maximum storable is %d, because the issuer sits in a UNIQUE btree index whose entries cannot exceed about a third of a page. Beyond that the INSERT fails with a raw index-size error, and whether it fails at all depends on how the value compresses",
			r.RealmID, len(r.CanonicalIssuer), maxStorableIssuer)
	}

	rec := realmRecord{
		FormatVersion:            storageFormatVersion,
		RealmID:                  string(r.RealmID),
		OrgID:                    r.OrgID,
		Kind:                     string(r.Kind),
		CanonicalIssuer:          r.CanonicalIssuer,
		Audiences:                append([]string(nil), r.Audiences...),
		AuthorizedPartyPolicy:    r.AuthorizedPartyPolicy.String(),
		AuthorizedParties:        append([]string(nil), r.AuthorizedParties...),
		AllowedSigningAlgorithms: append([]string(nil), r.AllowedSigningAlgorithms...),
		MinimumAssurance:         r.MinimumAssurance.String(),
		ClockSkewSeconds:         int64(r.ClockSkew / time.Second),
		CredentialAgePolicy:      r.CredentialAgePolicy.String(),
		MaxCredentialAgeSeconds:  int64(r.MaxCredentialAge / time.Second),
		Directory:                r.Directory.String(),
		Interactive:              r.Interactive.String(),
		Revocation:               r.Revocation.String(),
		Delegation:               r.Delegation.String(),
		Enabled:                  r.Enabled,
		Version:                  r.Version,
		ClaimMapping: claimMappingRecord{
			Version:      r.ClaimMapping.Version,
			SubjectClaim: r.ClaimMapping.SubjectClaim,
			SubjectType:  string(r.ClaimMapping.SubjectType),
		},
	}
	for _, s := range r.AcceptedSubjectTypes {
		rec.AcceptedSubjectTypes = append(rec.AcceptedSubjectTypes, string(s))
	}
	for _, c := range r.AcceptedCredentialTypes {
		rec.AcceptedCredentialTypes = append(rec.AcceptedCredentialTypes, string(c))
	}
	for _, d := range r.DelegateRealms {
		rec.DelegateRealms = append(rec.DelegateRealms, string(d))
	}
	if r.ClaimMapping.AliasClaims != nil {
		rec.ClaimMapping.AliasClaims = make(map[string]string, len(r.ClaimMapping.AliasClaims))
		for k, v := range r.ClaimMapping.AliasClaims {
			rec.ClaimMapping.AliasClaims[string(k)] = v
		}
	}

	// A duration that is not a whole number of seconds would be silently
	// truncated by the division above. Refuse instead: a clock skew of 1500ms
	// stored as 1s is a realm that accepts a different set of credentials
	// after a restart than before it.
	if r.ClockSkew%time.Second != 0 {
		return nil, fmt.Errorf("identity: realm %q has a clock skew of %s, which is not a whole number of seconds; storing it would truncate and the realm would accept a different set of credentials after a restart", r.RealmID, r.ClockSkew)
	}
	if r.MaxCredentialAge%time.Second != 0 {
		return nil, fmt.Errorf("identity: realm %q has a maximum credential age of %s, which is not a whole number of seconds; storing it would truncate", r.RealmID, r.MaxCredentialAge)
	}

	// INVALID UTF-8 IS REFUSED, because json.Marshal does not fail on it - it
	// silently rewrites each bad byte to U+FFFD. Measured: a canonical issuer
	// containing raw \xff\xfe encoded with err == nil and decoded back to a
	// DIFFERENT string, so the realm the registry holds and the realm the
	// store persists would declare different issuers with no error on any
	// path. An issuer is matched byte-for-byte at the EX-47 gate, so "close
	// enough" is not a category that exists here.
	if bad := firstInvalidUTF8Field(rec); bad != "" {
		return nil, fmt.Errorf("identity: realm %q has invalid UTF-8 in %s; JSON encoding would silently replace it with U+FFFD and the stored realm would declare a different value from the one in memory", r.RealmID, bad)
	}

	out, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("identity: encode trust realm %q: %w", r.RealmID, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

// decodeRealm reads a stored realm back.
//
// It ends with Validate, so a row that no longer satisfies the type's own
// rules - because a constraint tightened, or because something wrote the row
// outside this codec - is a load FAILURE rather than a realm with a field
// nobody declared.
func decodeRealm(raw []byte) (TrustRealm, error) {
	// DisallowUnknownFields, because the format version alone does not protect
	// what its comment claims.
	//
	// The version only fires if somebody remembers to BUMP it, and "I only
	// added a field" is exactly when they will not. During a rolling deploy an
	// older binary then reads a newer row, silently DROPS the field it does
	// not know, Validate (which also does not know about it) passes, and the
	// realm registers with that field at its ZERO VALUE - "not declared",
	// which is the EX-47 fail-open this whole file exists to abolish, arriving
	// through the exact door the version constant was placed in front of.
	// Measured: a row carrying an unknown key decoded with err == nil.
	//
	// Refusing an unknown key turns "someone forgot to bump the version" from
	// a silent zero value into a loud load failure, which is UNKNOWN_REALM,
	// which denies.
	// THE VERSION IS READ FIRST, on a lenient pass, because the strict pass
	// below would otherwise answer the wrong question. A row written by a
	// newer binary usually carries BOTH a bumped version and a new field, and
	// with the strict decode first the caller got a bare
	// `json: unknown field "..."` while the version message - the one that
	// explains the rolling deploy and says what to do - never fired. The
	// version is the more informative failure, so it is the one that gets to
	// speak.
	var probe struct {
		FormatVersion string `json:"format_version"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return TrustRealm{}, fmt.Errorf("identity: decode trust realm: %w", err)
	}
	if probe.FormatVersion != storageFormatVersion {
		return TrustRealm{}, fmt.Errorf("identity: stored trust realm carries format version %q, and this binary writes and reads %q.\n"+
			"It is refused rather than read under this version's rules: during a rolling deployment an older binary will meet rows a newer one wrote, and interpreting them under the wrong rules is how a realm silently changes what it accepts",
			probe.FormatVersion, storageFormatVersion)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rec realmRecord
	if err := dec.Decode(&rec); err != nil {
		return TrustRealm{}, fmt.Errorf("identity: decode trust realm: %w", err)
	}
	if rec.FormatVersion != storageFormatVersion {
		return TrustRealm{}, fmt.Errorf("identity: stored trust realm %q carries format version %q, and this binary writes and reads %q.\n"+
			"It is refused rather than read under this version's rules: during a rolling deployment an older binary will meet rows a newer one wrote, and interpreting them under the wrong rules is how a realm silently changes what it accepts",
			rec.RealmID, rec.FormatVersion, storageFormatVersion)
	}

	out := TrustRealm{
		RealmID:                  RealmID(rec.RealmID),
		OrgID:                    rec.OrgID,
		Kind:                     RealmKind(rec.Kind),
		CanonicalIssuer:          rec.CanonicalIssuer,
		Audiences:                append([]string(nil), rec.Audiences...),
		AuthorizedParties:        append([]string(nil), rec.AuthorizedParties...),
		AllowedSigningAlgorithms: append([]string(nil), rec.AllowedSigningAlgorithms...),
		ClockSkew:                time.Duration(rec.ClockSkewSeconds) * time.Second,
		MaxCredentialAge:         time.Duration(rec.MaxCredentialAgeSeconds) * time.Second,
		Enabled:                  rec.Enabled,
		Version:                  rec.Version,
		ClaimMapping: ClaimMapping{
			Version:      rec.ClaimMapping.Version,
			SubjectClaim: rec.ClaimMapping.SubjectClaim,
			SubjectType:  SubjectType(rec.ClaimMapping.SubjectType),
		},
	}
	for _, s := range rec.AcceptedSubjectTypes {
		out.AcceptedSubjectTypes = append(out.AcceptedSubjectTypes, SubjectType(s))
	}
	for _, c := range rec.AcceptedCredentialTypes {
		out.AcceptedCredentialTypes = append(out.AcceptedCredentialTypes, CredentialType(c))
	}
	for _, d := range rec.DelegateRealms {
		out.DelegateRealms = append(out.DelegateRealms, RealmID(d))
	}
	if rec.ClaimMapping.AliasClaims != nil {
		out.ClaimMapping.AliasClaims = make(map[AliasKind]string, len(rec.ClaimMapping.AliasClaims))
		for k, v := range rec.ClaimMapping.AliasClaims {
			out.ClaimMapping.AliasClaims[AliasKind(k)] = v
		}
	}

	var err error
	if out.MinimumAssurance, err = decodeEnum("minimum_assurance", rec.MinimumAssurance, storableAssurance); err != nil {
		return TrustRealm{}, err
	}
	if out.Directory, err = decodeEnum("directory", rec.Directory, storableDirectory); err != nil {
		return TrustRealm{}, err
	}
	if out.Interactive, err = decodeEnum("interactive", rec.Interactive, storableInteractive); err != nil {
		return TrustRealm{}, err
	}
	if out.Revocation, err = decodeEnum("revocation", rec.Revocation, storableRevocation); err != nil {
		return TrustRealm{}, err
	}
	if out.Delegation, err = decodeEnum("delegation", rec.Delegation, storableDelegation); err != nil {
		return TrustRealm{}, err
	}
	if out.AuthorizedPartyPolicy, err = decodeEnum("authorized_party_policy", rec.AuthorizedPartyPolicy, storableAuthorizedParty); err != nil {
		return TrustRealm{}, err
	}
	if out.CredentialAgePolicy, err = decodeEnum("credential_age_policy", rec.CredentialAgePolicy, storableCredentialAge); err != nil {
		return TrustRealm{}, err
	}

	if err := out.Validate(); err != nil {
		return TrustRealm{}, fmt.Errorf("identity: stored trust realm %q does not validate and will not be registered: %w", out.RealmID, err)
	}
	return out, nil
}

// firstInvalidUTF8Field walks the stored record by REFLECTION and names the
// first field carrying a string that is not valid UTF-8, or "" if none does.
//
// Reflection rather than a hand-written field list for the reason the round
// trip uses it: a new string field added to realmRecord and forgotten here
// would be one more place a value can change on its way to storage.
func firstInvalidUTF8Field(v any) string {
	return firstInvalidUTF8At(reflect.ValueOf(v), "")
}

func firstInvalidUTF8At(v reflect.Value, path string) string {
	switch v.Kind() {
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return path
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			name := v.Type().Field(i).Name
			if path != "" {
				name = path + "." + name
			}
			if bad := firstInvalidUTF8At(v.Field(i), name); bad != "" {
				return bad
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if bad := firstInvalidUTF8At(v.Index(i), fmt.Sprintf("%s[%d]", path, i)); bad != "" {
				return bad
			}
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if bad := firstInvalidUTF8At(k, path+" (a key)"); bad != "" {
				return bad
			}
			if bad := firstInvalidUTF8At(v.MapIndex(k), fmt.Sprintf("%s[%v]", path, k)); bad != "" {
				return bad
			}
		}
	}
	return ""
}

// sortedRealms orders realms by id, so a load produces a stable sequence
// whatever the database's row order happened to be. A registration order that
// varied between replicas would make the epoch and the issuer-collision
// diagnostics depend on it.
func sortedRealms(realms []TrustRealm) []TrustRealm {
	sort.Slice(realms, func(i, j int) bool { return realms[i].RealmID < realms[j].RealmID })
	return realms
}
