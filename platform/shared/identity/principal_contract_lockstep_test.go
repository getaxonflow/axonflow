// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"regexp"
	"strings"
	"testing"
	"unicode"

	"axonflow/platform/decision/contract"
)

// WHY THIS FILE EXISTS (#3711, umbrella #3709)
//
// `Type::qualifier:local` has TWO implementations in this tree, and until this
// file nothing held them together:
//
//   - identity.PrincipalID (principal.go) - the VERSIONED one. Its
//     CanonicalFormVersion is bound into every decision proof as
//     proof.Binding.IdentityCanonicalFormVersion, precisely so that a change to
//     the canonical form invalidates outstanding proofs LOUDLY instead of two
//     spellings of one principal silently comparing unequal.
//   - contract.ID (platform/decision/contract/ids.go) - the one the PDP
//     consults, carrying no version of its own.
//
// A guarantee written against a form with two definitions, only one of which
// the guarantee versions, is worth what the OTHER definition happens to do. So
// the two are compared here, over the same corpus, in both directions.
//
// WHY THE FIX IS A LOCKSTEP TEST AND NOT AN IMPORT
//
// The obvious repair - have contract.ID derive its type set from SubjectType -
// is not available, and the reason is structural rather than stylistic.
// platform/decision is a SEPARATE Go module with a deliberately minimal
// dependency set, and axonflow/platform depends on IT (planeshadow imports
// contract). An import the other way would invert that. The vocabulary
// therefore cannot be shared as code, and the honest alternatives were: state
// in contract's own source that its type segment is deliberately open and name
// where the closed check lives, and hold the two grammars together with a test
// that can see both. This file is the second half; the first is the block above
// contract.ID.Type.
//
// WHY THIS PINS THAT A SECOND DEFINITION CANNOT APPEAR
//
// TestTheTypeVocabularyDivergenceIsStillTheOneThatMatters asserts contract's
// CURRENT behaviour in both directions - it accepts a type outside the closed
// vocabulary, and identity does not. So a future change that gives contract its
// own principal-type vocabulary does not land quietly: it fails here, and
// whoever makes it has to come to this file and reconcile the two. The
// divergence is a pinned fact rather than a paragraph.
//
// AND WHY IT IS NOT THE ONLY ONE. The first version of this file asserted that
// the type vocabulary was the ONE divergence, and passed - because its corpus
// was drawn from inside the intersection of the two grammars. An independent
// sweep found three more. Every divergence is now DECLARED with a reason and a
// disposition, every declared one must be exercised, and an undeclared one is
// an error; see declaredDivergences.

// lockstepRealms are realm ids that must render and parse identically on both
// sides. They deliberately include the punctuation ValidateRealmID admits.
var lockstepRealms = []RealmID{"security", "acme-prod", "eu.central_1", "r-1"}

// lockstepSubjects include the shapes that BREAK a naive parser. A SPIFFE id
// and an LDAP DN both contain the separator character, which is the whole
// reason both implementations split on the FIRST colon and take the rest
// verbatim; a corpus without them would agree trivially.
var lockstepSubjects = []string{
	"00u1abcd",
	"spiffe://acme.example/workload/jira-bot",
	"CN=alice,OU=eng,DC=acme,DC=example",
	"a:b:c",
	"urn:ietf:params:scim:schemas:core:2.0:User",
}

// TestTheTwoCanonicalPrincipalRenderersAgreeByteForByte.
//
// The vocabulary is DERIVED from SubjectTypes() rather than listed, so a
// seventh subject type is covered on the day it lands rather than on the day
// somebody remembers this file.
func TestTheTwoCanonicalPrincipalRenderersAgreeByteForByte(t *testing.T) {
	types := SubjectTypes()
	if len(types) < 6 {
		t.Fatalf("SubjectTypes() returned %d types; the sweep below is reading nothing", len(types))
	}
	compared := 0
	for _, st := range types {
		for _, realm := range lockstepRealms {
			for _, subject := range lockstepSubjects {
				p, err := NewPrincipalID(realm, st, subject)
				if err != nil {
					t.Fatalf("NewPrincipalID(%q, %q, %q): %v", realm, st, subject, err)
				}
				cid := contract.ID{
					Kind:      contract.KindPrincipal,
					Type:      string(st),
					Qualifier: string(realm),
					Local:     subject,
				}
				if err := cid.Validate(); err != nil {
					t.Errorf("contract refuses a principal identity produced: %v", err)
					continue
				}
				if p.String() != cid.String() {
					t.Errorf("the two canonical forms disagree:\n  identity: %q\n  contract: %q\n"+
						"proof.Binding.IdentityCanonicalFormVersion versions the identity one, so a "+
						"disagreement means the PDP compares a spelling no proof binds.",
						p.String(), cid.String())
				}

				// Each parser must read the OTHER's output back to the same
				// three components. Byte equality of the rendering says
				// nothing about where each side puts the split.
				gotContract, err := contract.ParseID(contract.KindPrincipal, p.String())
				if err != nil {
					t.Errorf("contract cannot parse identity's canonical form %q: %v", p.String(), err)
				} else if gotContract.Type != string(st) || gotContract.Qualifier != string(realm) || gotContract.Local != subject {
					t.Errorf("contract splits identity's %q into (%q, %q, %q); identity means (%q, %q, %q)",
						p.String(), gotContract.Type, gotContract.Qualifier, gotContract.Local, st, realm, subject)
				}
				gotIdentity, err := ParsePrincipalID(cid.String())
				if err != nil {
					t.Errorf("identity cannot parse contract's canonical form %q: %v", cid.String(), err)
				} else if gotIdentity != p {
					t.Errorf("identity reads contract's %q back as %#v, not %#v", cid.String(), gotIdentity, p)
				}
				compared++
			}
		}
	}
	// ANTI-VACUITY, derived from the corpus rather than from a green run: the
	// sweep must have covered every combination it enumerates. A loop that
	// `continue`d past its body would leave this short.
	if want := len(types) * len(lockstepRealms) * len(lockstepSubjects); compared != want {
		t.Fatalf("compared %d principals, the corpus declares %d; the sweep skipped cases", compared, want)
	}
}

// ---------------------------------------------------------------------------
// The declared divergences
// ---------------------------------------------------------------------------
//
// R3 ROUND 1 KILLED THE CLAIM THIS SECTION ORIGINALLY MADE, AND THE CORRECTION
// IS THE POINT OF ITS PRESENT SHAPE.
//
// It used to assert that the two grammars "differ in exactly one respect", the
// type vocabulary, and it passed - because the corpus above was picked from
// inside the intersection of the two. An independent sweep of the whole
// component space found THREE more divergence classes, one of them in the
// dangerous direction: identity MINTED realm ids the PDP cannot parse (closed
// by #3709 row 3; see declaredDivergences). A test
// named for "the only divergence" that cannot fail when a fourth appears is a
// claim about its author's imagination, not about the code.
//
// So the divergences are now DECLARED as data, every declared one must be
// exercised by the corpus (a class nothing hits is a stale exemption, and it
// fails here), and any disagreement matching NO declared class is an error.
// That is the same discipline as the anchored spec walker in #3724: the
// unclassified case is reported, never shrugged at.

// divergenceClass is one KNOWN, reasoned way the two grammars disagree.
//
// direction is load-bearing. "contract accepts, identity refuses" and "identity
// accepts, contract refuses" are opposite failures: the first is a principal
// the PDP will evaluate and no proof can bind; the second is a principal a
// proof binds that the PDP cannot parse at all.
type divergenceClass struct {
	name        string
	direction   divergenceDirection
	why         string
	disposition string
	// applies reports whether this class explains a disagreement about the
	// given components. It tests the STRUCTURAL property, not the outcome, so a
	// class cannot absorb a disagreement it does not describe.
	applies func(typ, realm, subject string) bool
}

type divergenceDirection int

const (
	contractAcceptsIdentityRefuses divergenceDirection = iota
	identityAcceptsContractRefuses
)

func (d divergenceDirection) String() string {
	if d == contractAcceptsIdentityRefuses {
		return "contract accepts / identity refuses"
	}
	return "identity accepts / contract refuses"
}

// contractTypeSegmentRe RESTATES contract's type-segment regex.
//
// It is used only to CLASSIFY a disagreement the two implementations actually
// produced - never to decide whether one exists. A drifted copy here can
// therefore only make a real disagreement unclassified, which fails, and can
// never hide one. The alternative, exporting it from contract, would put a
// test's convenience into a wire-contract package's public surface. (The
// qualifier regex used to be restated beside it for the realm-charset class;
// that class is closed by #3709 row 3 and contract.ValidateQualifier is now
// the ONE grammar, so the restatement went with it.)
var contractTypeSegmentRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)

// identityComponentMax mirrors identity's own maxPrincipalComponent, which is
// unexported. Same argument as above: classification only.
const identityComponentMax = 512

func hasNonPrintOrSpace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

// contractRejectedControl are the ONLY four characters contract refuses inside
// a local segment, alongside a leading/trailing-whitespace check.
const contractRejectedControl = "\x00\n\r\t"

// declaredDivergences is the whole of what the two grammars are allowed to
// disagree about. Adding a row is a decision that needs a disposition; removing
// the last input that exercises one fails the coverage assertion below.
//
// THE realm-charset CLASS WAS HERE AND IS GONE (#3709 row 3). It was the
// dangerous direction - identity minted realm ids contract could not parse -
// and it is closed on the permissive side: ValidateRealmID now DELEGATES to
// contract.ValidateQualifier, so the seven realm probes that exercised the
// class (`acme+prod`, `eu/central`, `realm@okta`, `réalm`, `-leading`,
// `_leading`, `.leading`) are agreements now, and they stay in probeRealms so
// the sweep keeps proving it. Re-declaring the class would fail the
// stale-exemption check below, which is the intended shape: a fixed
// divergence cannot quietly become an exemption again.
func declaredDivergences() []divergenceClass {
	return []divergenceClass{
		{
			name:      "type-vocabulary",
			direction: contractAcceptsIdentityRefuses,
			why: "contract's type segment is an open regex and identity's is a closed set of six. " +
				"A type outside the six names a subject whose semantics no policy author has seen, " +
				"and the PDP would evaluate it.",
			disposition: "v11.0.0 on #3711: closing contract's set rejects a principal the wire has " +
				"always accepted, which is a wire break.",
			applies: func(typ, _, _ string) bool {
				return contractTypeSegmentRe.MatchString(typ) && !SubjectType(typ).IsValid()
			},
		},
		{
			name:      "component-length",
			direction: contractAcceptsIdentityRefuses,
			why: "identity caps every component at 512 bytes so a hostile credential cannot scale " +
				"the memory or the log line a rejection produces; contract has no length bound at all, " +
				"so the PDP will parse a megabyte-long subject identity refuses.",
			disposition: "FILED on #3709. A bound on contract is additive for every real identifier " +
				"(the longest realistic subject is a SPIFFE id or an Entra object path, both far " +
				"under 512) but is still a refusal the wire did not have.",
			applies: func(_, realm, subject string) bool {
				return len(realm) > identityComponentMax || len(subject) > identityComponentMax
			},
		},
		{
			name:      "subject-charset",
			direction: contractAcceptsIdentityRefuses,
			why: "contract refuses only \\x00 \\n \\r \\t inside a local segment plus leading and " +
				"trailing whitespace; identity refuses EVERY non-printable and EVERY space rune. So " +
				"contract admits an interior ESC (the actual ANSI-injection character), NBSP, " +
				"zero-width space, and the RTL override that makes one identifier render as another.",
			disposition: "FILED on #3709. The gap is in contract, and closing it is a refusal the " +
				"wire did not have.",
			applies: func(_, _, subject string) bool {
				return hasNonPrintOrSpace(subject) &&
					!strings.ContainsAny(subject, contractRejectedControl) &&
					strings.TrimSpace(subject) == subject
			},
		},
	}
}

// The corpus is a full CROSS PRODUCT, not one deviation at a time.
//
// It carried two unused "known-good base" constants and a comment claiming
// attributability from single deviations; review round 2 pointed out that the
// loop below is a cross product and the comment claimed a property the corpus
// does not have. Overlapping classes therefore exist by construction - an
// out-of-vocabulary type with a whitespace subject trips two - and first-match
// wins. That is sound because every class predicate is a STRUCTURAL test, so a
// class can only claim a disagreement whose cause it actually describes, and
// because each axis is exercised alongside in-vocabulary types and short realms
// (deleting any one class reds this test, which is asserted below).
var (
	probeTypes = []string{
		"User", "Group", // inside the closed vocabulary
		"Robot", "Machine.v2", "A-b_c", // legal contract segments, outside the six
	}
	probeRealms = []string{
		"security", "acme-prod", "eu.central_1", "r-1", "A1", // both accept
		"acme+prod", "eu/central", "realm@okta", "réalm", "-leading", "_leading", ".leading", // both refuse since #3709 row 3; identity minted them before
		"se:curity", // a colon-bearing realm: BOTH re-split it, so it is a well-formed
		// identifier for a DIFFERENT realm rather than a malformed one. Present so the
		// classifier is exercised on a wire string whose components are not the ones
		// this corpus wrote - the case review round 2 found reported UNDECLARED.
		strings.Repeat("a", identityComponentMax+1), // over-long
	}
	probeSubjects = []string{
		"00u1abcd", "spiffe://acme.example/workload/jira-bot",
		"CN=alice,OU=eng,DC=acme,DC=example", "a:b:c",
		"urn:ietf:params:scim:schemas:core:2.0:User", // both accept
		"00u 1", "00u 1", "00u​1", "00u‮1", "00u　1", "00u\x1b[31m1", "00u\x071",
		// LEADING whitespace, which contract refuses in a local segment and
		// identity refuses too - so on its own it is an AGREEMENT. It earns its
		// place paired with the colon-bearing realm: the wire string then
		// re-splits so the SUBJECT the parsers hold has the space in the
		// middle, where contract accepts it and identity does not. That is the
		// one shape where classifying on the components as WRITTEN reports a
		// declared divergence as undeclared, and without it the splitter fix is
		// unobservable - measured, by reverting the fix and watching this test
		// stay green.
		" 00u1",
		strings.Repeat("s", identityComponentMax+1),
	}
)

// splitCanonicalPrincipal reproduces the split BOTH implementations perform:
// the first "::", then the first ":" of the remainder, with everything after
// that the subject verbatim. It is used only to attribute a disagreement the
// two parsers already produced, never to decide whether one exists.
func splitCanonicalPrincipal(wire string) (typ, realm, subject string) {
	typ, rest, found := strings.Cut(wire, "::")
	if !found {
		return wire, "", ""
	}
	realm, subject, found = strings.Cut(rest, ":")
	if !found {
		return typ, rest, ""
	}
	return typ, realm, subject
}

// TestEveryDisagreementBetweenTheTwoGrammarsIsDeclared.
//
// The sweep is a cross product with one deviation per axis, so 5 x 13 x 13
// principals are put through BOTH implementations and every disagreement must
// match a declared class in the declared DIRECTION.
func TestEveryDisagreementBetweenTheTwoGrammarsIsDeclared(t *testing.T) {
	classes := declaredDivergences()
	exercised := map[string]int{}
	agreements, disagreements := 0, 0

	for _, typ := range probeTypes {
		for _, realm := range probeRealms {
			for _, subject := range probeSubjects {
				wire := typ + "::" + realm + ":" + subject
				_, contractErr := contract.ParseID(contract.KindPrincipal, wire)
				_, identityErr := ParsePrincipalID(wire)
				if (contractErr == nil) == (identityErr == nil) {
					agreements++
					continue
				}
				disagreements++
				dir := contractAcceptsIdentityRefuses
				if contractErr != nil {
					dir = identityAcceptsContractRefuses
				}
				// CLASSIFY ON WHAT THE PARSERS SAW, not on the components as
				// written. Both implementations split the wire string at the
				// FIRST "::" and the FIRST following ":", so a realm carrying a
				// colon reaches them as a different (realm, subject) pair -
				// `User::a:b: a` is realm "a", subject "b: a" to both. Review
				// round 2 proved the as-written form makes a DECLARED
				// divergence report as UNDECLARED, because the predicate is
				// then answering a question about a string neither parser ever
				// held. It fails loud rather than silently, but a guard that
				// reds on a divergence it has already declared is one somebody
				// will widen a class to silence.
				pTyp, pRealm, pSubject := splitCanonicalPrincipal(wire)
				matched := ""
				for _, c := range classes {
					if c.direction == dir && c.applies(pTyp, pRealm, pSubject) {
						matched = c.name
						break
					}
				}
				if matched == "" {
					t.Errorf("UNDECLARED divergence (%s) for type=%q realm=%q subject=%q\n"+
						"  contract: %v\n  identity: %v\n"+
						"No declared class explains it. One of the two implementations of the canonical "+
						"principal form has moved, and only one of them is versioned by "+
						"proof.Binding.IdentityCanonicalFormVersion. Declare it with a disposition or "+
						"fix it - do not widen a class to absorb it.",
						dir, typ, realm, subject, contractErr, identityErr)
					continue
				}
				exercised[matched]++
			}
		}
	}

	// ANTI-VACUITY 1: a declared class no input exercises is a STALE exemption -
	// it silently excuses a disagreement that may no longer exist, or may have
	// been fixed. Either way it must be removed rather than left standing.
	for _, c := range classes {
		if exercised[c.name] == 0 {
			t.Errorf("declared divergence %q was not exercised by any input. Either the corpus stopped "+
				"covering it or the divergence is gone; a class nothing hits excuses whatever it "+
				"happens to match next.\n  why: %s\n  disposition: %s", c.name, c.why, c.disposition)
		}
	}
	// ANTI-VACUITY 2: the sweep must contain BOTH outcomes. A corpus that
	// disagreed everywhere, or nowhere, would satisfy the loop above while
	// measuring nothing.
	if agreements == 0 || disagreements == 0 {
		t.Fatalf("the sweep produced %d agreements and %d disagreements; a corpus with an empty side "+
			"is not a comparison", agreements, disagreements)
	}
	if want := len(probeTypes) * len(probeRealms) * len(probeSubjects); agreements+disagreements != want {
		t.Fatalf("classified %d of %d inputs", agreements+disagreements, want)
	}
}

// malformedPrincipal is one input BOTH implementations must refuse, and the
// reason refusing it matters.
type malformedPrincipal struct {
	wire string
	why  string
}

// malformedPrincipals are the inputs on which the two grammars must agree to
// REFUSE. The sweep above proves no UNDECLARED disagreement exists; this proves
// the agreement is on the right answer. Both are needed: two implementations
// that accepted everything would agree perfectly.
var malformedPrincipals = []malformedPrincipal{
	{"00u1abcd", "a bare identifier, never completed with a default realm - the EX-47 fail-open"},
	{"User::00u1abcd", "no separator between realm and subject"},
	{"User::security:", "an empty subject"},
	{"User::security: 00u1", "a subject with leading whitespace is a second spelling of one principal"},
	{"User::security:00u1 ", "a subject with trailing whitespace, same reason"},
	{"User::security:00u\n1", "a newline in the subject terminates a log record and forges the next"},
	{"User::security:00u\x001", "a NUL in the subject"},
	{"User::\x00:00u1", "a NUL in the realm"},
	{"::security:00u1", "an empty type segment"},
	{"1User::security:00u1", "a type segment that does not start with a letter"},
	{"User::acme+prod:00u1", "a realm outside the qualifier grammar - identity minted this before #3709 row 3 and the PDP could not parse it"},
	{"User::-leading:00u1", "a realm starting with '-', which the qualifier grammar refuses"},
	{"User::réalm:00u1", "a non-ASCII realm, printable and therefore admitted by the old ValidateRealmID"},
}

// TestTheTypeVocabularyDivergenceIsStillTheOneThatMatters.
//
// The type vocabulary is the divergence #3711 is ABOUT, and it is asserted
// directly as well as through the sweep: a class predicate proves a
// disagreement is explained, and this proves the specific disagreement is still
// there and still in the direction the disposition assumes.
//
// If contract ever closes its vocabulary - dispositioned to v11.0.0 - this
// fails and the author has to come here to remove it, which is what stops a
// SECOND vocabulary appearing in contract quietly.
func TestTheTypeVocabularyDivergenceIsStillTheOneThatMatters(t *testing.T) {
	const outsideVocabulary = "Robot::security:r1"

	if _, err := contract.ParseID(contract.KindPrincipal, outsideVocabulary); err != nil {
		t.Errorf("contract now REFUSES %q (%v). Its type segment used to be an open regex, and this "+
			"test is the record of that. If contract has closed its vocabulary, delete this assertion "+
			"and reconcile the two definitions - do not widen the regex to make this pass.",
			outsideVocabulary, err)
	}
	if _, err := ParsePrincipalID(outsideVocabulary); err == nil {
		t.Errorf("identity now ACCEPTS %q. The closed vocabulary is the point: an unknown subject type "+
			"is a subject whose semantics no policy author has ever seen.", outsideVocabulary)
	}

	// A COLON-BEARING REALM IS A CONSTRUCTION-TIME PROPERTY, NOT A PARSE-TIME
	// ONE, and the first run of this file is what established that.
	//
	// `User::se:curity:00u1` was in the malformed corpus below on the reasoning
	// that a colon in the realm re-splits the identifier. Both implementations
	// ACCEPT it, and both are right to: they split at the FIRST colon, so the
	// input reads as realm "se", subject "curity:00u1", unambiguously and
	// identically on both sides. The string is not a malformed identifier - it
	// is a well-formed identifier for a different realm. What must be
	// impossible is PRODUCING it, and that is asserted here instead.
	if _, err := NewPrincipalID("se:curity", SubjectUser, "00u1"); err == nil {
		t.Error("identity accepted a realm containing a colon; a realm id must be colon-free or the " +
			"wire form cannot be split back into the components it was built from")
	}
	colonRealm := contract.ID{Kind: contract.KindPrincipal, Type: "User", Qualifier: "se:curity", Local: "00u1"}
	if err := colonRealm.Validate(); err == nil {
		t.Error("contract accepted a qualifier containing a colon; the same argument applies on the " +
			"PDP side, and a divergence here means one implementation can mint an identifier the " +
			"other reads as a different principal")
	}

	if len(malformedPrincipals) < 13 {
		t.Fatalf("the malformed corpus holds %d inputs; it was written with 13 and a shrunk corpus "+
			"asserts less while still passing", len(malformedPrincipals))
	}
	for _, m := range malformedPrincipals {
		_, contractErr := contract.ParseID(contract.KindPrincipal, m.wire)
		_, identityErr := ParsePrincipalID(m.wire)
		switch {
		case contractErr == nil && identityErr == nil:
			t.Errorf("both implementations ACCEPT %q, and neither should: %s", m.wire, m.why)
		case contractErr == nil:
			t.Errorf("contract accepts %q and identity refuses it (%v). %s\n"+
				"The PDP would evaluate a principal no proof can bind.", m.wire, identityErr, m.why)
		case identityErr == nil:
			t.Errorf("identity accepts %q and contract refuses it (%v). %s\n"+
				"A principal a proof binds would be unevaluable by the PDP.", m.wire, contractErr, m.why)
		}
	}
}

// TestTheClosedVocabularyIsExpressibleInTheOpenOne.
//
// The two are only comparable at all while every closed subject type is a legal
// contract type segment. A seventh type spelled with a character contract's
// regex refuses - a space, a slash, a leading digit - would make that type
// unrepresentable on the PDP side, and the failure would appear as an
// unparseable principal at runtime rather than here.
func TestTheClosedVocabularyIsExpressibleInTheOpenOne(t *testing.T) {
	types := SubjectTypes()
	if len(types) < 6 {
		t.Fatalf("SubjectTypes() returned %d types; this sweep is reading nothing", len(types))
	}
	for _, st := range types {
		id := contract.ID{
			Kind:      contract.KindPrincipal,
			Type:      string(st),
			Qualifier: "security",
			Local:     "00u1",
		}
		if err := id.Validate(); err != nil {
			t.Errorf("SubjectType %q is not a legal contract type segment: %v.\n"+
				"Every canonical principal must be expressible on the PDP side, or the type is "+
				"unusable the moment a request carries it.", st, err)
		}
		if strings.Contains(string(st), ":") {
			t.Errorf("SubjectType %q contains a colon; both parsers locate the separator by scanning "+
				"for one, so such a type would re-split every identifier that carried it", st)
		}
	}
}
