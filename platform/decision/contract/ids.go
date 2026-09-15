// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import (
	"fmt"
	"regexp"
	"strings"
)

// Kind is the class of entity an identifier names. It is not the entity type
// string itself: many resource types share the kind "resource".
//
// The kind decides whether an identifier carries a realm or connector
// qualifier, which is the only thing that makes parsing unambiguous. A
// principal identifier is (org, realm, subject type, subject id) per ADR-065,
// so it is qualified; an action identifier is a single canonical name from the
// action registry, so it is not. Deciding qualification from the kind rather
// than from the presence of a colon is deliberate: a SPIFFE subject id contains
// colons of its own, and "split on the last colon" would silently reinterpret
// spiffe://acme.example/workload/jira-bot.
type Kind string

const (
	// KindOrganization names the customer isolation boundary (ADR-052).
	KindOrganization Kind = "organization"
	// KindPrincipal names a user, service, workload, agent or client subject.
	KindPrincipal Kind = "principal"
	// KindGroup names a realm-qualified directory group.
	KindGroup Kind = "group"
	// KindResource names a business entity inside a connector or realm.
	KindResource Kind = "resource"
	// KindAction names a registered action.
	KindAction Kind = "action"
	// KindTool names a registered tool in the tool registry.
	KindTool Kind = "tool"
	// KindClient names the authenticated application or credential.
	KindClient Kind = "client"
	// KindSession names one caller session.
	KindSession Kind = "session"
)

// qualifiedKinds lists the kinds whose identifiers carry a qualifier segment.
// Everything else is unqualified. Keeping this as data rather than as a switch
// means the round-trip test can enumerate it.
var qualifiedKinds = map[Kind]bool{
	KindOrganization: false,
	KindPrincipal:    true,
	KindGroup:        true,
	KindResource:     true,
	KindAction:       false,
	KindTool:         false,
	KindClient:       false,
	KindSession:      false,
}

// AllKinds returns every declared kind in a stable order. Tests enumerate it so
// that adding a kind without deciding its qualification fails loudly.
func AllKinds() []Kind {
	return []Kind{
		KindOrganization, KindPrincipal, KindGroup, KindResource,
		KindAction, KindTool, KindClient, KindSession,
	}
}

// IsQualifiedKind reports whether identifiers of this kind carry a qualifier.
func IsQualifiedKind(k Kind) (bool, error) {
	q, ok := qualifiedKinds[k]
	if !ok {
		return false, fmt.Errorf("contract: unknown identifier kind %q", k)
	}
	return q, nil
}

var (
	// A type segment is a CamelCase-ish token. It never contains a colon, so
	// the "::" separator can be located without ambiguity.
	typeSegmentRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)
	// A qualifier is a realm or connector identifier. It may not contain a
	// colon, which is what makes "Type::qualifier:local" parseable when local
	// itself contains colons.
	qualifierRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
)

// QualifierGrammar is the qualifier rule as a reader would state it. It is
// the text every refusal carries, so an operator naming a realm learns the
// rule from the error rather than from this file.
const QualifierGrammar = "a letter or digit, then letters, digits, '_', '.' or '-' ([A-Za-z0-9][A-Za-z0-9_.-]*); " +
	"never ':', which separates the qualifier from the local segment of a Type::qualifier:local identifier"

// ValidateQualifier reports whether s is a legal qualifier - the realm of a
// principal, the connector of a resource - under the ONE grammar the wire
// contract parses with.
//
// It is exported for the producer side (#3709 row 3): identity.ValidateRealmID
// admits the realm ids that later become the qualifier of every principal a
// decision proof binds, and until it delegated here it kept its own, wider
// rule (any printable, colon-free, whitespace-free rune). An operator who
// named a realm `acme+prod` minted principals the PDP refused to parse. One
// grammar, defined here because this is the module the wire form belongs to
// and the module identity may import; the reverse import is impossible.
func ValidateQualifier(s string) error {
	if !qualifierRe.MatchString(s) {
		return fmt.Errorf("contract: qualifier %q does not match the qualifier grammar: %s", s, QualifierGrammar)
	}
	return nil
}

// PrincipalType is the closed vocabulary of principal types - the type segment
// of a KindPrincipal identifier.
//
// THIS IS THE ONE DEFINITION (#3711). Until v11 the same `Type::realm:subject`
// form had two: platform/shared/identity's closed set of six, which is what
// every decision proof binds through identity.CanonicalFormVersion, and this
// package's open type-segment regex, which is what the PDP consulted. So
// `Robot::okta-prod:00u1` was a hard error to one and a valid, decided request
// to the other, and the versioned guarantee ("a change to the canonical form
// invalidates outstanding proofs loudly") covered only the half the PDP did not
// read. The vocabulary lives HERE because of the module direction:
// axonflow/platform requires axonflow/platform/decision and identity already
// imports this package, so this is the only place both can read.
// identity.SubjectType is an alias of this type and identity.SubjectTypes()
// returns exactly PrincipalTypes(); a test in identity reads both and pins them
// equal, so a seventh type is added in one place or the build says otherwise.
//
// It is closed on purpose. An unknown type is an error, never a permissive
// default: a plane that accepted an unrecognised type would be accepting a
// subject whose semantics no policy author has ever seen.
type PrincipalType string

const (
	// PrincipalUser is a human identity.
	PrincipalUser PrincipalType = "User"
	// PrincipalService is a non-human service account in a directory.
	PrincipalService PrincipalType = "Service"
	// PrincipalWorkload is a cryptographically attested workload (SPIFFE and
	// comparable schemes).
	PrincipalWorkload PrincipalType = "Workload"
	// PrincipalAgent is an AxonFlow-registered autonomous agent.
	PrincipalAgent PrincipalType = "Agent"
	// PrincipalClient is an authenticated calling application. It is
	// ATTRIBUTION, not authority: ADR-065 invariant 2. A Client principal may
	// appear in an actor chain and may be audited; it must never be the
	// authority a grant is scoped to.
	PrincipalClient PrincipalType = "Client"
	// PrincipalGroup is a realm-qualified directory group.
	PrincipalGroup PrincipalType = "Group"
)

// principalTypes is the admissible set, in a stable order for diagnostics.
var principalTypes = []PrincipalType{
	PrincipalUser, PrincipalService, PrincipalWorkload, PrincipalAgent, PrincipalClient, PrincipalGroup,
}

// IsValid reports whether t is a member of the closed vocabulary.
func (t PrincipalType) IsValid() bool {
	for _, known := range principalTypes {
		if t == known {
			return true
		}
	}
	return false
}

// PrincipalTypes returns a copy of the admissible principal types, in a stable
// order. Callers get a copy so a consumer cannot mutate the vocabulary.
func PrincipalTypes() []PrincipalType {
	out := make([]PrincipalType, len(principalTypes))
	copy(out, principalTypes)
	return out
}

// ID is a canonical identifier. Display names, emails, token claims, connector
// names and aliases are never identifiers (ADR-065 invariant 3).
type ID struct {
	// Kind is the entity class. It is carried on the value rather than
	// inferred, because two kinds can share a type string across connectors.
	Kind Kind `json:"kind"`
	// Type is the entity type, for example "User", "Agent", "JiraIssue".
	//
	// For KindPrincipal it is a member of PrincipalTypes() and nothing else;
	// Validate enforces that and the published schema
	// (contract/schema/contract-2026-08-29.schema.json, $defs/identifier)
	// carries the same six as an enum conditioned on kind. For every other
	// kind it is an open CamelCase-ish segment: resource types are named by
	// connectors, and the registry, not this package, decides which exist.
	//
	// BREAKING IN v11 (#3711). Before this the principal type was open here
	// and closed only in platform/shared/identity, so `Robot::okta-prod:00u1`
	// was accepted by the PDP and refused by every identity path. Closing it
	// rejects artifacts the wire accepted, which no shipped constructor ever
	// produced (the census is in the #3711 PR body: every non-test constructor
	// passes one of the six).
	//
	// FIVE SURFACES CARRY THE CLOSURE, and they are named because a claim
	// about "everywhere" is the kind that turns out to be false - as this
	// comment demonstrated by saying FOUR while a fifth was being added in the
	// same change:
	//   - a REQUEST, through Engine.Decide -> req.Validate -> ID.Validate;
	//   - a REPLAY RECORD, by the same path;
	//   - a POLICY SCOPE, through pdp.Document.Validate, which validates every
	//     identifier a policy names and its kind (the compiler reads
	//     Scope.Principals through ID.String() with no Kind and no Validate,
	//     so nothing else could catch it);
	//   - an AUTHORING DOCUMENT, through authoring-v1.schema.json's
	//     $defs/principal_type, enforced at NewDocument and at Parse;
	//   - a PUBLICATION'S APPROVERS, through authoring.Publish. The fifth, the
	//     one nobody named, and the only one whose value is SIGNED: it goes
	//     into PublicationProvenance and survives LoadArtifact, so an
	//     out-of-vocabulary approver was a signed statement rather than a
	//     rejected input.
	// identity.CanonicalFormVersion does NOT move for this: the canonical FORM
	// identity mints is unchanged, identity already refused these types, so no
	// outstanding proof binds a principal this closes out.
	Type string `json:"type"`
	// Qualifier is the realm or connector identifier for qualified kinds and
	// is empty for unqualified kinds.
	Qualifier string `json:"qualifier,omitempty"`
	// Local is the subject, resource, or action identifier within the
	// qualifier. It may contain colons for qualified kinds.
	Local string `json:"local"`
}

// String renders the canonical wire form: "Type::local" for unqualified kinds
// and "Type::qualifier:local" for qualified kinds.
func (id ID) String() string {
	if id.Qualifier == "" {
		return id.Type + "::" + id.Local
	}
	return id.Type + "::" + id.Qualifier + ":" + id.Local
}

// IsZero reports whether the identifier is unset.
func (id ID) IsZero() bool {
	return id.Type == "" && id.Qualifier == "" && id.Local == "" && id.Kind == ""
}

// Validate checks the identifier against the rules for its kind.
func (id ID) Validate() error {
	qualified, err := IsQualifiedKind(id.Kind)
	if err != nil {
		return err
	}
	if !typeSegmentRe.MatchString(id.Type) {
		return fmt.Errorf("contract: %s identifier has invalid type segment %q", id.Kind, id.Type)
	}
	if id.Kind == KindPrincipal && !PrincipalType(id.Type).IsValid() {
		return fmt.Errorf("contract: principal identifier declares type %q, which is not one of %v (#3711: the principal vocabulary is closed and shared with platform/shared/identity)", id.Type, principalTypes)
	}
	if id.Local == "" {
		return fmt.Errorf("contract: %s identifier %q has an empty local segment", id.Kind, id.Type)
	}
	if strings.TrimSpace(id.Local) != id.Local {
		return fmt.Errorf("contract: %s identifier local segment %q has leading or trailing whitespace", id.Kind, id.Local)
	}
	if strings.ContainsAny(id.Local, "\x00\n\r\t") {
		return fmt.Errorf("contract: %s identifier local segment %q contains a control character", id.Kind, id.Local)
	}
	if qualified {
		if err := ValidateQualifier(id.Qualifier); err != nil {
			return fmt.Errorf("contract: %s identifier requires a colon-free qualifier, got %q: %w", id.Kind, id.Qualifier, err)
		}
	} else if id.Qualifier != "" {
		return fmt.Errorf("contract: %s identifier must not carry a qualifier, got %q", id.Kind, id.Qualifier)
	}
	if !qualified && strings.Contains(id.Local, ":") {
		// An unqualified local segment containing a colon would re-parse as a
		// qualified identifier of a different kind. Reject rather than accept
		// an identifier whose meaning depends on who parses it.
		return fmt.Errorf("contract: %s identifier local segment %q must not contain a colon", id.Kind, id.Local)
	}
	return nil
}

// ParseID parses the canonical wire form for a known kind.
//
// Parsing is kind-directed on purpose. The separator "::" is located at its
// FIRST occurrence and the qualifier is taken up to the FIRST following colon;
// everything after that belongs to the local segment verbatim. That is what
// keeps a SPIFFE subject id such as spiffe://acme.example/workload/jira-bot
// intact instead of being re-split at one of its own colons.
func ParseID(kind Kind, s string) (ID, error) {
	qualified, err := IsQualifiedKind(kind)
	if err != nil {
		return ID{}, err
	}
	sep := strings.Index(s, "::")
	if sep < 0 {
		return ID{}, fmt.Errorf("contract: %s identifier %q is missing the \"::\" separator", kind, s)
	}
	id := ID{Kind: kind, Type: s[:sep]}
	rest := s[sep+2:]
	if qualified {
		colon := strings.Index(rest, ":")
		if colon < 0 {
			return ID{}, fmt.Errorf("contract: %s identifier %q is missing the realm qualifier", kind, s)
		}
		id.Qualifier = rest[:colon]
		id.Local = rest[colon+1:]
	} else {
		id.Local = rest
	}
	if err := id.Validate(); err != nil {
		return ID{}, err
	}
	return id, nil
}

// MustParseID is ParseID for package-level fixtures and panics on error.
func MustParseID(kind Kind, s string) ID {
	id, err := ParseID(kind, s)
	if err != nil {
		panic(err)
	}
	return id
}

// CanonicalLocal folds an identifier's local segment to the form the identity
// actually resolves under.
//
// THE DIRECTORY IS CASE-INSENSITIVE AND A SIGNATURE IS NOT, WHICH IS THE WHOLE
// PROBLEM. The roles store matches an assignment on `lower(btrim(user_email))`,
// so `Alice@acme.example` and `alice@acme.example` are one person to it, while
// every byte comparison downstream sees two. An SSO deployment carries whatever
// spelling the identity provider asserted, and a provenance record keeps the
// string as typed.
//
// IT LIVES HERE, IN THE MODULE BOTH SIDES IMPORT, and that placement is the
// point rather than an accident. The rule previously existed once as
// identity.CanonicalEmail, applied by the customer portal to its own inputs -
// a fix at ONE CALLER of a control rather than at the control. That closes the
// hole for the caller that remembers and leaves it open for every other one,
// and it is why separation of duties was still defeatable on this axis after
// the casing bug had been diagnosed, written up and fixed. A second folding
// rule elsewhere would be a second answer to "are these the same person", and
// the two would disagree the day either changed; identity.CanonicalEmail now
// delegates here, with a lockstep test.
//
// LOCAL ONLY. Kind and qualifier are NOT folded: the case-insensitivity
// established by the roles store is a property of an email local part, and
// nothing establishes it for a realm identifier, where two spellings could
// legitimately be two realms. Folding a field because folding another one
// helped is how a fix becomes a defect.
func CanonicalLocal(local string) string {
	return strings.ToLower(strings.TrimSpace(local))
}

// identityKeySep separates the fields of an identity key.
//
// It is a record separator rather than a colon or a slash because those occur
// in real local segments (a SPIFFE id carries both). Validate does not reject
// \x1e inside a local segment, so a caller CAN put one there - and it still
// cannot forge a key, because the local segment is LAST and the three fields
// ahead of it draw from grammars that admit no \x1e (Kind is a closed
// vocabulary, Type matches typeSegmentRe, Qualifier matches the qualifier
// grammar). The first three splits are therefore unambiguous whatever the
// local segment contains. TestAnIdentityKeyCannotBeForgedThroughTheLocalSegment
// drives that rather than leaving it as an argument.
const identityKeySep = "\x1e"

// IdentityKey returns the key two identifiers share exactly when they denote
// the SAME ENTITY.
//
// # WHY THE TYPE IS DROPPED FOR A PRINCIPAL AND KEPT FOR EVERYTHING ELSE
//
// For KindPrincipal, Type is the subject's CLASSIFICATION - User, Service,
// Agent - asserted by whatever minted the identifier. It is a fact ABOUT a
// person, not a component of who they are, and the same person reaches two
// different surfaces classified two different ways: a token says Service where
// a directory says User. Comparing the rendered form therefore turns one person
// into two, which is #3876 (an author approved their own policy publication)
// and #3878 (a requester stayed eligible to approve their own escalation).
//
// For every other kind, Type names the entity CLASS of a distinct entity: a
// JiraIssue "ABC-1" and a JiraProject "ABC-1" are two resources that happen to
// share a local segment, and the registry keys its catalog on the rendered form
// precisely because the rendered form IS the identifier there. Dropping the type
// for those would merge two entities, which is the same defect pointing the
// other way.
//
// So the rule is one rule with one branch, stated once here, rather than a
// judgement made again at each call site - which is how instances 1 to 5 of
// this class arrived. The same reasoning governs the local fold: CanonicalLocal
// exists because the roles store resolves an email case-insensitively, and that
// is a property of a principal's local segment. It is NOT applied to a resource
// or action local segment, where nothing establishes case-insensitivity and two
// spellings may be two entities.
//
// THE BRANCH IS ON KIND, NOT ON TYPE, so a KindGroup identifier keeps its type
// while a KindPrincipal whose type happens to be "Group" does not. That is not
// an inconsistency: a group named as its own KIND is a different entity class
// from a principal, and a principal typed Group is a principal the caller has
// classified. The second fold only ever makes an identity control STRICTER -
// one more candidate recognised as the author, one fewer counted as a distinct
// approver - which is the direction a control must fail in. The site where
// merging a group with a subject WOULD be wrong is the normalized directory
// graph, and that keys on the whole identifier rather than on this.
//
// The key is stable across processes and is safe to use as a map key. It is NOT
// a wire form and must not be persisted or compared against a stored String().
func (id ID) IdentityKey() string {
	if id.Kind == KindPrincipal {
		return string(id.Kind) + identityKeySep +
			identityKeySep + id.Qualifier +
			identityKeySep + CanonicalLocal(id.Local)
	}
	return string(id.Kind) + identityKeySep + id.Type +
		identityKeySep + id.Qualifier +
		identityKeySep + id.Local
}

// SameEntity reports whether two identifiers denote the same entity.
//
// A ZERO IDENTIFIER MATCHES NOTHING, INCLUDING ANOTHER ZERO. "No identifier" is
// not an identity two values can share; reading it as one is the shape in which
// an absent value becomes a determinate, permissive fact. Every current caller
// validates its inputs before reaching here, so the guard is a floor rather
// than a live branch - TestSameEntityRefusesTheZeroIdentifier drives it, and
// the authoring control's own suite pins that a zero approver is refused
// upstream with its own reason code.
func SameEntity(a, b ID) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	return a.IdentityKey() == b.IdentityKey()
}
