// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 canonical principals (#3556).
//
// A principal identifier is (org_id, realm_id, subject_type, subject_id). The
// organization is deliberately NOT part of the wire form: the canonical
// authorization request carries `organization` as its own field, and the
// binding between the two is enforced at admission from the AUTHENTICATED
// credential (see realm_verify.go). Parsing an organization out of a
// caller-supplied principal string is exactly the #3488 defect and this
// package provides no way to do it.
//
// WIRE FORM
//
//	<SubjectType>::<realm_id>:<subject_id>
//
// as used throughout ADR-065:
//
//	User::realm_okta:00u123
//	Group::realm_okta:security
//	Workload::realm_spiffe:spiffe://acme.example/workload/jira-bot
//
// The third example is the one that decides the parsing rule: a SPIFFE ID
// contains colons, so subject_id is NOT colon-free and a naive
// strings.Split(s, ":") corrupts it. The form stays unambiguous because
// realm_id is colon-free by construction (ValidateRealmID rejects a colon),
// so the FIRST "::" ends the type and the FIRST ":" after it ends the realm.
// Everything remaining is the subject, verbatim.
//
// # ALIASES ARE NEVER IDENTIFIERS
//
// Email, username, display name, SCIM external ID, token `sub` as presented,
// SPIFFE ID as presented, and connector account IDs are ALIASES with
// provenance. They resolve TO a principal; they are never a principal key.
// The existing per-user token path keys on a canonicalized email
// (ValidatedIdentity.Email) and that is precisely what ADR-065 invariant 3
// retires: two IdPs asserting alice@acme.example are two different subjects,
// and an email is reassignable in a way a canonical subject is not.
package identity

import (
	"fmt"
	"strings"
	"unicode"

	"axonflow/platform/decision/contract"
)

// CanonicalFormVersion identifies the canonical principal encoding. It is
// bound into decision proofs by the obligation plane (#3551) so that a change
// to what this package considers a well-formed principal invalidates old
// proofs LOUDLY, rather than two spellings silently comparing unequal.
//
// Bump this when the wire form, the admissible realm-id character set, or the
// subject-type vocabulary changes. Do not bump it for additive changes that
// cannot alter how an existing valid principal encodes.
//
// THE SUBJECT-TYPE VOCABULARY IS NO LONGER DECLARED IN THIS FILE (#3711). It
// is contract.PrincipalTypes(), and SubjectType is an alias of
// contract.PrincipalType, so a change to the vocabulary is a change in
// axonflow/platform/decision and this constant still has to move with it. Read
// that as a widening of the rule above rather than an exception to it: the
// trigger is the vocabulary changing, wherever it now lives.
//
// #3711 itself did NOT bump this, and the reason is worth stating so the next
// reader does not take the omission for an oversight. That change narrowed
// what the DECISION CONTRACT accepts - it closed contract.ID's open type regex
// to the same six - and changed nothing about what this package mints or how
// it encodes. Every principal identity produced before it is byte-identical
// after it, so no outstanding proof is invalidated and a bump would have
// invalidated every one of them for no change in meaning.
//
// identity/2 (#3709 row 3): the admissible realm-id character set narrowed
// from "any printable, colon-free, whitespace-free rune" to the decision
// contract's qualifier grammar. A principal such as `User::acme+prod:00u1`
// was well-formed under identity/1 and is refused under identity/2.
const CanonicalFormVersion = "identity/2"

// Wire-form separators. Named rather than inlined because the parse and the
// render must agree by construction, and because a test asserts the render of
// a parsed value is byte-identical to its input.
const (
	principalTypeSep  = "::"
	principalRealmSep = ":"
)

// maxPrincipalComponent bounds each component so a hostile credential cannot
// scale the memory or the log line a rejection produces. It is generous
// against real identifiers: the longest realistic subject is a SPIFFE ID or an
// Entra object path, both well under this.
const maxPrincipalComponent = 512

// SubjectType is the closed vocabulary of canonical principal kinds.
//
// It IS contract.PrincipalType - an alias, not a second type (#3711). Until
// v11 this package held its own closed set of six while the decision contract
// matched an open regex, so the canonical wire form had two definitions and
// only this one was versioned. The vocabulary now lives in the decision
// contract, the one module both sides can import (axonflow/platform requires
// axonflow/platform/decision; the reverse import is impossible), and this
// package's names are that type's names. TestTheSubjectVocabularyIsTheContractsPrincipalVocabulary
// reads both and pins them equal, so a seventh type cannot be added on one
// side alone.
//
// It is closed on purpose. An unknown subject type is an error, never a
// permissive default: a plane that accepted an unrecognized type would be
// accepting a subject whose semantics no policy author has ever seen.
type SubjectType = contract.PrincipalType

const (
	// SubjectUser is a human identity.
	SubjectUser SubjectType = contract.PrincipalUser
	// SubjectService is a non-human service account in a directory.
	SubjectService SubjectType = contract.PrincipalService
	// SubjectWorkload is a cryptographically attested workload (SPIFFE and
	// comparable schemes).
	SubjectWorkload SubjectType = contract.PrincipalWorkload
	// SubjectAgent is an AxonFlow-registered autonomous agent.
	SubjectAgent SubjectType = contract.PrincipalAgent
	// SubjectClient is an authenticated calling application. It is
	// ATTRIBUTION, not authority: ADR-065 invariant 2. A Client principal may
	// appear in an actor chain and may be audited; it must never be the
	// authority a grant is scoped to.
	SubjectClient SubjectType = contract.PrincipalClient
	// SubjectGroup is a realm-qualified directory group.
	SubjectGroup SubjectType = contract.PrincipalGroup
)

// SubjectTypes returns the admissible subject types: exactly
// contract.PrincipalTypes(), which already returns a copy, so a consumer
// cannot mutate the vocabulary through either name.
func SubjectTypes() []SubjectType {
	return contract.PrincipalTypes()
}

// RealmID identifies a TrustRealm within one organization.
//
// It is colon-free by construction. That is not cosmetic: it is what makes the
// wire form parseable when subject_id contains colons.
type RealmID string

// ValidateRealmID enforces the admissible character set for a realm id.
//
// Rejected: empty, over-long, any colon (the wire-form separator), and
// anything outside the decision contract's qualifier grammar - a leading
// letter or digit, then letters, digits, '_', '.' and '-'. Accepted: exactly
// what contract.ValidateQualifier accepts, bounded at maxPrincipalComponent.
//
// # WHY THE GRAMMAR IS THE CONTRACT'S, NOT THIS PACKAGE'S (#3709 row 3)
//
// This used to admit any printable, colon-free, whitespace-free rune, on the
// argument that realm ids are operator-chosen labels. But a realm id is also
// the QUALIFIER of every principal this package mints - realm_verify.go calls
// NewPrincipalID(realm.RealmID, ...) on every credential it admits - and the
// decision contract parses that qualifier with [A-Za-z0-9][A-Za-z0-9_.-]*.
// So an operator who named a realm `acme+prod`, `eu/central`, `realm@okta`,
// `-leading` or `réalm` minted principals every decision proof bound and the
// PDP could not parse: the dangerous direction, found by #3751's lockstep
// sweep and left declared there because narrowing this was not a v10.4.0
// change. It is now: the fix is on the permissive side, and it is a
// DELEGATION rather than a second regex, so the two cannot drift again.
// contract's rule is the one that already refuses; nothing was loosened.
//
// The colon check stays as its own refusal ahead of the grammar because its
// message names the property that matters most - the wire-form separator -
// and because ParsePrincipalID's correctness argument cites it by name.
func ValidateRealmID(id RealmID) error {
	s := string(id)
	if s == "" {
		return fmt.Errorf("identity: realm id is empty")
	}
	if len(s) > maxPrincipalComponent {
		return fmt.Errorf("identity: realm id exceeds %d bytes", maxPrincipalComponent)
	}
	if strings.Contains(s, principalRealmSep) {
		return fmt.Errorf("identity: realm id %q contains %q, which is the wire-form separator", s, principalRealmSep)
	}
	if err := contract.ValidateQualifier(s); err != nil {
		return fmt.Errorf("identity: realm id %q is refused: a realm id is the qualifier of every principal "+
			"(Type::realm:subject) and must follow the decision contract's qualifier grammar - %s: %w",
			s, contract.QualifierGrammar, err)
	}
	return nil
}

// validateSubjectID enforces the admissible character set for a subject id.
// Colons ARE allowed (SPIFFE); whitespace and non-printable runes are not.
func validateSubjectID(subject string) error {
	if subject == "" {
		return fmt.Errorf("identity: subject id is empty")
	}
	if len(subject) > maxPrincipalComponent {
		return fmt.Errorf("identity: subject id exceeds %d bytes", maxPrincipalComponent)
	}
	for _, r := range subject {
		if unicode.IsSpace(r) {
			return fmt.Errorf("identity: subject id %q contains whitespace", subject)
		}
		if !unicode.IsPrint(r) {
			return fmt.Errorf("identity: subject id %q contains a non-printable rune", subject)
		}
	}
	return nil
}

// PrincipalID is a canonical, realm-qualified principal identifier.
//
// It is a comparable struct so it can be a map key and so equality is exact
// field equality rather than string comparison. Two principals with the same
// subject id in different realms are DIFFERENT principals, which is the
// property that makes a realm collision impossible rather than merely
// unlikely.
type PrincipalID struct {
	// Realm is the trust realm the subject was asserted by.
	Realm RealmID
	// Type is the canonical subject kind.
	Type SubjectType
	// Subject is the realm's own immutable identifier for the subject. It is
	// never an email, a username, or a display name.
	Subject string
}

// NewPrincipalID builds a validated principal identifier. It is the only
// sanctioned constructor: a struct literal skips validation, so code inside
// this package that builds one from untrusted input goes through here.
func NewPrincipalID(realm RealmID, t SubjectType, subject string) (PrincipalID, error) {
	if err := ValidateRealmID(realm); err != nil {
		return PrincipalID{}, err
	}
	if !t.IsValid() {
		return PrincipalID{}, fmt.Errorf("identity: %q is not a known subject type (known: %v)", string(t), SubjectTypes())
	}
	if err := validateSubjectID(subject); err != nil {
		return PrincipalID{}, err
	}
	return PrincipalID{Realm: realm, Type: t, Subject: subject}, nil
}

// IsZero reports whether this is the zero PrincipalID.
//
// The zero value is not a principal and never matches anything. A consumer
// that treats it as a wildcard, an anonymous subject, or "the caller" has
// reintroduced the EX-47 class: an undetermined identity being read as a
// determinate, permissive fact.
func (p PrincipalID) IsZero() bool {
	return p.Realm == "" && p.Type == "" && p.Subject == ""
}

// Validate re-checks a PrincipalID that arrived as a struct value rather than
// through a constructor.
func (p PrincipalID) Validate() error {
	if p.IsZero() {
		return fmt.Errorf("identity: principal is the zero value")
	}
	_, err := NewPrincipalID(p.Realm, p.Type, p.Subject)
	return err
}

// SubjectKey returns the realm-qualified key that identifies WHO this
// principal is, with the classification left out, and whether the value has
// one at all.
//
// # THE TYPE IS A CLASSIFICATION, AND == INCLUDES IT (#3878)
//
// PrincipalID is a comparable struct, so `a == b` compares Realm, Type and
// Subject, and that is the right comparison for a NODE in a classified
// structure - a directory graph vertex, a map of entities keyed by what they
// are. It is the wrong comparison for the question "is this the same subject",
// because Type is asserted independently by whichever source produced each
// value: an actor chain's classification comes from the request's token, an
// approver pool's comes from a directory, and the same person reaches the two
// classified two ways. Comparing all three fields then answers "no" for one
// person, which is how a requester stayed eligible to approve their own
// escalation.
//
// The realm IS part of the key and is never folded. Two subjects with the same
// id in different realms are different principals; that is the property that
// makes a realm collision impossible rather than merely unlikely, and it is
// stated on the type itself.
//
// THE SUBJECT IS NOT CASE-FOLDED, and the difference from contract.ID is
// deliberate rather than an oversight. contract.CanonicalLocal folds because
// the local segment there is an email and the roles store resolves one
// case-insensitively. Subject here is the realm's own immutable identifier -
// an Okta id, a SPIFFE id - and nothing establishes case-insensitivity for
// those. Folding one because folding the other helped is how a fix becomes a
// defect.
//
// The second return is false for a value with no realm or no subject, which
// includes the zero PrincipalID. Such a value has no identity to compare and
// must never match another one; see SameSubject.
func (p PrincipalID) SubjectKey() (string, bool) {
	if p.Realm == "" || p.Subject == "" {
		return "", false
	}
	return string(p.Realm) + principalRealmSep + p.Subject, true
}

// SameSubject reports whether two principal identifiers denote the same
// subject, ignoring the classification each one carries.
//
// A value with no realm or no subject matches NOTHING, including another such
// value. The zero PrincipalID is not a principal and never matches anything;
// reading "no identity" as an identity two values share is the EX-47 shape, an
// undetermined fact read as a determinate one.
//
// # IT FOLDS SubjectGroup TOO, AND THAT IS THE SAFE DIRECTION EVERYWHERE IT IS
// USED
//
// A Group is a SET of subjects rather than a subject, so `Group::r:x` and
// `User::r:x` are arguably two things and not one - which is the sharpest
// question that can be asked of this function. Folding them here is
// nonetheless correct at every site that calls it, because at every one of
// them the fold points the SAFE way: self-exclusion strikes out one more
// candidate approver, the eligible-set collapse counts one fewer, and
// AdmitChain refuses a Group hop outright before reaching any comparison. A
// control that recognises too many things as the requester refuses; one that
// recognises too few approves.
//
// Where merging them WOULD be wrong - the normalized directory graph, where a
// group has members and a subject does not - the code does not use this. It
// keys on the whole PrincipalID, and
// TestTheDirectoryGraphKeepsASubjectAndAGroupOfTheSameIdApart drives exactly
// this pair through both: SameSubject calls them one subject and the graph
// refuses to answer for the group where it answers for the subject.
//
// Use this to ask WHO. Use == to ask which classified entry.
func (p PrincipalID) SameSubject(other PrincipalID) bool {
	a, ok := p.SubjectKey()
	if !ok {
		return false
	}
	b, ok := other.SubjectKey()
	if !ok {
		return false
	}
	return a == b
}

// String renders the canonical wire form. A PrincipalID built by a constructor
// always round-trips: ParsePrincipalID(p.String()) == p.
func (p PrincipalID) String() string {
	return string(p.Type) + principalTypeSep + string(p.Realm) + principalRealmSep + p.Subject
}

// ParsePrincipalID parses the canonical wire form.
//
// It splits on the FIRST "::" and then on the FIRST ":" of the remainder;
// everything after that is the subject verbatim, colons included. A bare or
// unqualified identifier ("security", "00u123") is a hard error and is never
// completed with a default realm: a defaulted realm is the EX-47 fail-open.
func ParsePrincipalID(s string) (PrincipalID, error) {
	typePart, rest, found := strings.Cut(s, principalTypeSep)
	if !found {
		return PrincipalID{}, fmt.Errorf(
			"identity: %q is not a canonical principal: expected %q, got a bare identifier (a bare id is never completed with a default realm)",
			s, "<SubjectType>::<realm_id>:<subject_id>")
	}
	realmPart, subjectPart, found := strings.Cut(rest, principalRealmSep)
	if !found {
		return PrincipalID{}, fmt.Errorf(
			"identity: %q is not a canonical principal: no %q separating realm from subject",
			s, principalRealmSep)
	}
	return NewPrincipalID(RealmID(realmPart), SubjectType(typePart), subjectPart)
}

// MustParsePrincipalID is ParsePrincipalID for fixtures and package-level
// vars. It panics on a malformed input and must not be used on request data.
func MustParsePrincipalID(s string) PrincipalID {
	p, err := ParsePrincipalID(s)
	if err != nil {
		panic(err)
	}
	return p
}

// AliasKind names a non-canonical identifier that resolves TO a principal.
//
// Every value here is something a system somewhere treats as an identity and
// that ADR-065 invariant 3 says is not one. The type exists so that carrying
// an alias is an explicit, provenance-bearing act rather than an accident of
// passing a string.
type AliasKind string

const (
	// AliasEmail is a mail address. Reassignable, and not unique across
	// realms.
	AliasEmail AliasKind = "email"
	// AliasUsername is a login name, including an HTTP Basic username. The
	// #3333 defect is an unvalidated Basic username reaching policy as an
	// identity; this package can carry it only as an alias.
	AliasUsername AliasKind = "username"
	// AliasDisplayName is a human-readable label. Not unique at all.
	AliasDisplayName AliasKind = "display_name"
	// AliasSCIMExternalID is the provider's externalId attribute.
	AliasSCIMExternalID AliasKind = "scim_external_id"
	// AliasTokenSubject is the raw `sub` claim as presented, before realm
	// qualification.
	AliasTokenSubject AliasKind = "token_sub"
	// AliasSPIFFEID is a SPIFFE ID as presented.
	AliasSPIFFEID AliasKind = "spiffe_id"
	// AliasConnectorAccountID is a downstream connector's account identifier.
	AliasConnectorAccountID AliasKind = "connector_account_id"
)

// Provenance records where a policy-visible fact came from. ADR-065 requires
// every attribute to carry it, and requires policy to consult provenance
// rather than trusting a value's presence.
type Provenance string

const (
	// ProvenanceAuthentication means the fact was established by verifying a
	// credential.
	ProvenanceAuthentication Provenance = "authentication"
	// ProvenanceDirectory means the fact came from the normalized directory
	// graph.
	ProvenanceDirectory Provenance = "directory"
	// ProvenanceResource means the fact came from resolving the target
	// resource.
	ProvenanceResource Provenance = "resource"
	// ProvenancePlatform means AxonFlow itself asserts the fact.
	ProvenancePlatform Provenance = "platform"
	// ProvenanceDetector means a detector produced the fact.
	ProvenanceDetector Provenance = "detector"
	// ProvenanceCallerSupplied means the caller sent it. A caller-supplied
	// fact is never authority; it is retained so a trace can show what was
	// claimed and rejected.
	ProvenanceCallerSupplied Provenance = "caller_supplied"
)

// Alias is a non-canonical identifier bound to a canonical principal, with the
// provenance that makes it interpretable.
//
// Note the direction: an Alias names its Principal. There is no map from an
// alias string to a principal in this package, and adding one would be the
// point at which an email becomes an identifier again. Resolution from an
// alias belongs to a realm's claim mapping, which is realm-scoped and
// therefore cannot collide across realms.
type Alias struct {
	// Principal is the canonical subject this alias denotes.
	Principal PrincipalID
	// Kind names what sort of alias this is.
	Kind AliasKind
	// Value is the alias text, as asserted by its source.
	Value string
	// Provenance records how the binding was established.
	Provenance Provenance
	// SourceVersion is the source's own version for the record that carried
	// this alias, so a stale binding is detectable.
	SourceVersion string
}
