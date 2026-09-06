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

// ID is a canonical identifier. Display names, emails, token claims, connector
// names and aliases are never identifiers (ADR-065 invariant 3).
type ID struct {
	// Kind is the entity class. It is carried on the value rather than
	// inferred, because two kinds can share a type string across connectors.
	Kind Kind `json:"kind"`
	// Type is the entity type, for example "User", "Agent", "JiraIssue".
	//
	// FOR KindPrincipal THIS IS DELIBERATELY OPEN, AND THE CLOSED CHECK LIVES
	// SOMEWHERE ELSE (#3711). identity.SubjectType in
	// platform/shared/identity/principal.go is the closed vocabulary of six -
	// User, Service, Workload, Agent, Client, Group - and it is the VERSIONED
	// definition: identity.CanonicalFormVersion is bound into every decision
	// proof as proof.Binding.IdentityCanonicalFormVersion, so a change to the
	// canonical principal form invalidates outstanding proofs loudly instead of
	// two spellings of one principal silently comparing unequal. This regex is
	// not that vocabulary and must never be read as it: `Robot::okta-prod:00u1`
	// is a valid identifier here and a hard error there.
	//
	// THE OPENNESS IS A MODULE FACT, NOT A PREFERENCE. axonflow/platform/decision
	// is a separate Go module with a deliberately minimal dependency set, and
	// axonflow/platform depends on IT (platform/shared/planeshadow imports this
	// package). Importing identity from here would invert that, so the
	// vocabulary cannot be shared as code and the two grammars are held
	// together by a test that can see both instead:
	// platform/shared/identity/principal_contract_lockstep_test.go sweeps them
	// over one corpus in both directions and requires every disagreement to
	// match a DECLARED class carrying a reason and a disposition. The type
	// vocabulary is one of four; the other three (component length, realm
	// charset, subject charset) are filed on #3709.
	//
	// THE CENSUS BEHIND THE v11.0.0 DISPOSITION, STATED PRECISELY. No Go
	// CONSTRUCTOR in this tree emits a principal type outside the six: the only
	// live producers are legacycompile/shadow (a literal "User") and the
	// conformance fixtures. A DECODED principal is a different matter, and the
	// reason is THIS REGEX rather than a missing check.
	//
	// An earlier version of this comment said the decode paths reach the engine
	// "without calling Validate". That is false and was caught in review:
	// Engine.Decide calls req.Validate, which calls ID.Validate on the
	// principal. What Validate does NOT do is consult a vocabulary - it matches
	// the open regex above - so a request naming `Robot::okta-prod:00u1` is
	// VALID today and is decided. The distinction matters because a maintainer
	// who believed the first version would "fix" it by adding a Validate call
	// and close nothing.
	//
	// The paths that carry a decoded principal are replay records
	// (replay.LoadRecord -> Replay -> Engine.Decide; Record.Validate does not
	// reach the embedded Request, and Engine.Decide's own Validate is the open
	// check above), compiled policy scopes (pdp.compileScope reads
	// ID.String() with no Kind and no Validate at all), and authoring documents
	// (which check Kind only). The published schema
	// (contract/schema/contract-2026-08-29.schema.json, $defs/identifier)
	// carries this regex verbatim and no enum of six. So closing this set would
	// REJECT artifacts every one of those paths accepts today, which is why it
	// is a wire break and not a tidy-up.
	//
	// If you close it here, that lockstep test fails and you must reconcile the
	// two definitions there rather than growing a second vocabulary in this
	// package.
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
