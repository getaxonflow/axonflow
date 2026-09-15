// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
)

// THE DETECTOR REGISTRY (#3884, under #3786)
//
// ADR-065's amendment of 2026-09-07 rules that detection stays inside the one
// policy model, with no second policy family and no second authoring surface.
// A detection rule is therefore an ordinary typed policy of authority
// `inspection`, and what this file adds is the thing such a policy REFERS to:
// the platform-shipped detector, its implementation class, its version, and
// the enforcement planes on which its implementation actually gates.
//
// # WHY A RECORD AT ALL, WHEN THE PATTERN COULD LIVE IN THE POLICY
//
// It could not. `legacycompile.DetectorSignalPath` establishes that a legacy
// pattern compiles to a NAMED detector whose verdict the policy reads as an
// ordinary tri-state attribute, precisely so ADR-065's condition language
// never acquires a regex operator. So a policy names a detector and the
// detector is a separate thing with a separate lifecycle. Before this file
// that separate thing existed only as a description
// (`detectors_census.tsv`) with, in the words of #3884, "no runtime consumer".
//
// # THE PROPERTY THIS FILE EXISTS FOR: CLASS IS PLANE-DEPENDENT
//
// The single most expensive way to get this wrong is to treat the
// implementation class as a global property of a detector. It is not. The
// shared engine's `EvaluateRequest`/`EvaluateResponse` build a
// `PatternEvaluator` that consults the loader-resolved validator; the tier
// engine's `EvaluatePolicy` called `re.MatchString` and returned until #3963.
// On the one plane whose only static call site was the second - `proxy_tier`,
// retired with the tier engine by #4253 - every one of the twenty algorithmic
// detectors ran as a bare regex: the Luhn
// check did not gate `sys_pii_credit_card` there, and the Aadhaar label
// requirement did not gate `sys_pii_aadhaar` there. Since #3968 every walk on
// both engines reaches the regex through `sharedpolicy.ScanAccepted`, so the
// class is uniform by construction; the plane sets below stay because what a
// plane declares is still the thing a policy is checked against.
//
// A record therefore declares THREE plane sets rather than one, and the
// difference between them is the whole point:
//
//	Planes        every plane the detector is evaluated on at all
//	GatingPlanes  planes where its implementation gates EVERY evaluation
//	MixedPlanes   planes where some call sites gate and some do not
//
// and `BarePlanes` is what is left: the planes where the implementation is
// present in the binary and does not run. `Catalog.CheckDetectorSelection`
// refuses an inspection policy that selects a plane which cannot run the
// implementation it depends on.
//
// THE DIRECTION IS OVER-DETECTION, NOT UNDER-DETECTION, AND THAT CORRECTION
// MATTERS (#3963). A validator can only REMOVE a match: `PatternEvaluator`'s
// two call sites both discard the match when it returns false, and there is no
// path by which one adds a match the pattern did not produce. So a plane that
// consults no validator reports a SUPERSET of what a gated plane reports - on
// `proxy_tier` before #3963 any sixteen-digit string was a credit card - and the shipped
// corpus's own header calls validators "filters that improve accuracy". The
// plane over-blocks with false positives; it does not miss detections. Earlier
// framings of this, including the brief this file was written from, called it a
// "downgrade", which implies weaker enforcement and is wrong in direction.
//
// `MixedPlanes` is separate from `BarePlanes` and neither is folded into the
// other, because they have different remedies. A bare plane is a plane whose
// evaluator does not consult validators. A mixed plane is a plane NAME that
// covers two phases of one handler - `policy_test` carries both an
// `EvaluateRequest` site and an `EvaluatePolicy` site - so the remedy is to
// split the plane, which is a defect in the legacy plane taxonomy rather than
// in any detector.

// DetectorID is a platform-stable detector identifier.
//
// It is the SAME string the compiled policy's attribute path encodes:
// `legacycompile.DetectorSignalPath` renders `signal.detector.<encoded id>`,
// and `DetectorSignalPath` below is the one derivation of that path, which
// legacycompile delegates to. Keying the registry on anything else would give
// one detector two names - the one a policy reads and the one the registry
// holds - and nothing would notice until a lookup silently missed.
//
// It is a plain string rather than a `contract.ID` deliberately. A
// `contract.ID` names a SUBJECT of a decision - a principal, an action, a
// resource, a tool - and every `contract.Kind` is enumerated by
// `contract.AllKinds()` and consulted by the identifier vocabulary rules. A
// detector is not a subject; it is a named attribute the condition language
// reads. Minting a kind for it would put a non-subject into the identifier
// vocabulary that `principal_vocabulary_test.go` and the admission path range
// over.
type DetectorID string

// String renders the identifier.
func (d DetectorID) String() string { return string(d) }

// DetectorSignalPath is the attribute path a policy reads to learn this
// detector's verdict.
//
// This is the ONE derivation. `legacycompile.DetectorSignalPath` delegates to
// it rather than spelling it a second time: two spellings of one encoding are
// two answers that agree until the day one of them changes, and the failure
// would be a policy reading an attribute path no enforcement point ever
// populates - a permanently UNKNOWN detector, which under ADR-065 makes every
// constraint that reads it Indeterminate.
func (d DetectorID) SignalPath() string {
	return DetectorSignalPrefix + EncodePathSegment(string(d))
}

// DetectorSignalPrefix is the one spelling of the attribute-path prefix a
// detector's verdict is published under.
//
// It is exported because it was spelled three times - here, in the migration
// tool's dynamic-side path builder, and in the shadow harness's "is this a
// detector path" test - and a prefix that disagrees with itself in one of
// three places produces a policy reading an attribute nothing populates,
// which under ADR-065 is a permanently UNKNOWN detector.
const DetectorSignalPrefix = "signal.detector."

// EncodePathSegment renders an identifier as one attribute-path segment,
// BIJECTIVELY. It is exported so that the migration tool's own identifier
// encoding is this one rather than a second spelling of it.
//
// Injectivity is not decoration. A non-self-delimiting escape (hex-escaping
// only the illegal runes, say) lets two distinct identifiers produce one path:
// the two rows then share one detector signal, one overwrites the other's
// verdict in map order, and the same pinned inputs classify differently
// between runs. "_" is the only escape introducer and it is always escaped,
// so no encoded form is reachable from two identifiers.
func EncodePathSegment(in string) string {
	var b strings.Builder
	for _, r := range in {
		switch {
		case r == '_':
			b.WriteString("__")
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteString("_" + strconv.FormatInt(int64(r), 16) + "_")
		}
	}
	return b.String()
}

// DetectorClass is the implementation class the operator's 2026-09-06 boundary
// names.
//
// It is three-valued with an invalid zero for the reason `TagGovernance` is:
// the zero value would otherwise read as one of the real classes, and the
// class decides whether a customer may edit the thing that computes the
// verdict.
type DetectorClass int

const (
	// DetectorClassUnspecified is the zero value and is never valid.
	DetectorClassUnspecified DetectorClass = iota
	// DetectorClassPattern is a declarative pattern detector: the pattern IS
	// the data, and a customer may add their own.
	DetectorClassPattern
	// DetectorClassAlgorithmic is code with a version and a conformance case -
	// a checksum, a context window, a jurisdiction rule. A customer controls
	// where it applies, never what it computes.
	DetectorClassAlgorithmic
	// DetectorClassNotADetector inspects no content. It is a plain verdict
	// rule and becomes a grant, a ceiling or a requirement rather than an
	// inspection.
	DetectorClassNotADetector
)

// String renders the class in the census's own vocabulary.
func (c DetectorClass) String() string {
	switch c {
	case DetectorClassPattern:
		return "pattern"
	case DetectorClassAlgorithmic:
		return "algorithmic"
	case DetectorClassNotADetector:
		return "not_a_detector"
	case DetectorClassUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("DetectorClass(%d)", int(c))
	}
}

// IsValid reports whether the class is a declared member.
func (c DetectorClass) IsValid() bool {
	switch c {
	case DetectorClassPattern, DetectorClassAlgorithmic, DetectorClassNotADetector:
		return true
	default:
		return false
	}
}

// AllDetectorClasses returns every declared class in a stable order.
func AllDetectorClasses() []DetectorClass {
	return []DetectorClass{DetectorClassPattern, DetectorClassAlgorithmic, DetectorClassNotADetector}
}

// ParseDetectorClass reads the census vocabulary.
func ParseDetectorClass(s string) (DetectorClass, error) {
	for _, c := range AllDetectorClasses() {
		if c.String() == s {
			return c, nil
		}
	}
	return DetectorClassUnspecified, fmt.Errorf("registry: %q is not a declared detector class", s)
}

// PatternDialect is the pattern language a class (a) record's pattern is
// written in.
//
// It is declared rather than assumed. Every shipped pattern is RE2 today by
// accident of Go's `regexp`, and an undeclared dialect is how a second engine
// - one with backtracking, and therefore with a denial-of-service profile the
// first does not have - arrives without anybody deciding to admit it.
type PatternDialect int

const (
	// PatternDialectUnspecified is the zero value and is never valid on a
	// pattern record.
	PatternDialectUnspecified PatternDialect = iota
	// PatternDialectRE2 is Go's `regexp` language.
	PatternDialectRE2
)

// String renders the dialect.
func (p PatternDialect) String() string {
	switch p {
	case PatternDialectRE2:
		return "re2"
	case PatternDialectUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("PatternDialect(%d)", int(p))
	}
}

// IsValid reports whether the dialect is a declared member.
func (p PatternDialect) IsValid() bool { return p == PatternDialectRE2 }

// Emit is what a detector contributes to a decision when it fires.
//
// ADR-065's inspection authority is advisory - it may only lower - so an emit
// is a statement about what the policy that reads this detector does, not a
// second decision algebra.
type Emit string

const (
	// EmitSignal contributes a weighted signal.
	EmitSignal Emit = "Signal"
	// EmitDeny denies.
	EmitDeny Emit = "Deny"
	// EmitEscalate raises an approval requirement. No platform-shipped
	// detector reaches it today: `eu_ai_act_high_value_transaction` is the
	// only `require_approval` legacy row and ADR-065 approval needs an
	// eligible pool and a quorum, neither of which `static_policies` stores.
	EmitEscalate Emit = "Escalate"
)

// AllEmits returns every declared emit in a stable order.
func AllEmits() []Emit { return []Emit{EmitDeny, EmitEscalate, EmitSignal} }

// IsValid reports whether the emit is a declared member.
func (e Emit) IsValid() bool {
	for _, k := range AllEmits() {
		if k == e {
			return true
		}
	}
	return false
}

// DetectorRecord is one platform-shipped or organization-added detector.
//
// Registration is CREATE-ONLY, for the reason `RegisterAction` is: a
// detector's class and implementation are a policy channel. Reclassifying
// `sys_pii_singapore_nric` from algorithmic to pattern disarms a checksum on
// every document that selects it, with no document edited and nothing to see
// in any policy. A class or implementation change is a version bump and a new
// record, never an edit.
type DetectorRecord struct {
	// ID is the platform-stable detector identifier.
	ID DetectorID `json:"id"`
	// Name is the operator-facing name.
	Name string `json:"name"`
	// Class is the implementation class.
	Class DetectorClass `json:"class"`
	// Version is the IMPLEMENTATION version. It is bumped by the platform and
	// never by a customer, and a document may pin it.
	Version int `json:"version"`
	// ImplEvidence names the tests that drive this version's implementation
	// against the running binary, in the `path::Symbol` form the legacy plane
	// table's evidence column uses. It is required on an algorithmic record
	// and refused on a pattern record.
	//
	// WHY THIS AND NOT AN AXC CONFORMANCE CASE, WHICH IS WHAT THE DESIGN
	// PROPOSED. The registry plane's conformance machinery is PACKAGE-LOCAL by
	// construction: a case names a `TestFile` relative to this package, a
	// registry test asserts that test exists in this package's source, and
	// `TestMain` fails the package when a case is never marked. Every
	// algorithmic detector's implementation is in `platform/shared/policy`,
	// which is a DIFFERENT GO MODULE that `platform/decision` does not and
	// must not depend on. Allocating AXC-400..499 here would therefore take a
	// range and leave all three mechanisms unable to reach the cases in it - a
	// promise with nothing behind it, which reads to the next reader as a
	// solved problem.
	//
	// So the record names the evidence instead, and
	// `TestEveryAlgorithmicDetectorNamesEvidenceThatExists` holds each name to
	// a test that is present in the tree. That is mechanism 1 of the same
	// machinery, applied across a module boundary by reading a file rather
	// than by importing a package.
	//
	// REVISIT WHEN: a detector implementation moves into `platform/decision`.
	// On that day its cases can be ordinary AXC entries under the existing
	// machinery and this field is the thing to retire.
	ImplEvidence []string `json:"impl_evidence,omitempty"`

	// PatternDigest identifies a class (a) record's pattern without carrying
	// it. The census renders it `re2:sha256:<12 hex>`; the pattern itself
	// lives in the document, which is where a customer edits it.
	PatternDigest string `json:"pattern_digest,omitempty"`
	// Dialect is the pattern language. Required on a pattern record.
	Dialect PatternDialect `json:"dialect,omitempty"`

	// Impl names the Go symbol a class (b) record's verdict comes from, in the
	// `path::Symbol` form the audit-coverage allowlist uses. It is DERIVED
	// from the running binary through `runtime.FuncForPC` where the census is
	// produced, so it cannot cite a symbol that has moved or does not exist.
	Impl string `json:"impl,omitempty"`

	// Category is the legacy policy category the detector was seeded under. It
	// is carried because the detection-posture fold is keyed on it and because
	// twelve live rows carry a category the shared enum does not declare.
	Category string `json:"category,omitempty"`

	// THREE FIELDS THE DESIGN NAMES AND THIS RECORD DELIBERATELY DOES NOT
	// CARRY: `Jurisdiction`, `DefaultThreshold` and `DefaultScope`.
	//
	// The census has no column for any of them. Jurisdiction could be spelled
	// out of a category name - `pii-singapore` is plainly SG - and that is
	// exactly the derivation this whole registry exists to refuse: the class
	// is derived from the code that runs rather than from what a row is
	// CALLED, and a jurisdiction read off a category spelling would be the
	// same defect wearing a different field. `compliance-masfeat` and
	// `compliance-rbi` are the rows where the spelling stops working.
	//
	// A declared-but-always-empty field is worse than an absent one, because
	// the first consumer reads empty as "global" and that is a fail-open. They
	// return when the census gains the columns, which is a change to the
	// census's derivation rather than to this file.

	// DefaultEmit is the emit set the shipped corpus carries, as a SET rather
	// than a single value.
	//
	// It is a set because twelve shipped rows emit differently depending on
	// which plane asked - the legacy row's two read paths resolve to different
	// actions - and collapsing that to one value is a DECISION that either
	// strengthens or weakens twelve controls. A single field here would make
	// that decision silently, at parse time, with nobody's name on it.
	DefaultEmit []Emit `json:"default_emit,omitempty"`
	// DefaultObligations are the obligation types the shipped corpus attaches.
	DefaultObligations []contract.ObligationType `json:"default_obligations,omitempty"`

	// Planes are every enforcement plane the detector is evaluated on.
	Planes []string `json:"planes"`
	// GatingPlanes are the planes on which the implementation gates EVERY
	// evaluation. For a pattern record this equals Planes, because the pattern
	// is the implementation and both engines run it identically.
	GatingPlanes []string `json:"gating_planes"`
	// MixedPlanes are planes whose NAME covers call sites that do not agree:
	// some gate and some do not. Kept separate from the bare planes because
	// the remedy is to split the plane, not to change the detector.
	MixedPlanes []string `json:"mixed_planes,omitempty"`

	// Editions are the builds that contain the implementation. It is a SET
	// rather than one value because most shipped detectors are in every build
	// and a single field would have to spell that as a sentinel.
	//
	// It is a static property of shipped code and NOT an entitlement: ADR-066
	// is categorical that the deterministic PDP cannot read one, and
	// `platform/decision` is a separate Go module precisely so that is
	// checkable at the source level.
	//
	// NOTHING READS IT OUTSIDE THIS PACKAGE YET, AND SAYING SO IS THE POINT.
	// The intended consumers are bundle assembly - so a bundle built for a
	// deployment never references a detector that deployment's binaries do not
	// contain - and the PEP capability handshake, so an enforcement point that
	// cannot run a detector is refused rather than silently skipping it.
	// Neither exists. An earlier version of this comment stated both as
	// settled guarantees, which is the same defect this file warns about
	// eighty lines up for `ImplEvidence`: a promise with nothing behind it
	// reads to the next reader as a solved problem. The PDP must never ask,
	// whichever of them arrives first.
	Editions []Edition `json:"editions"`

	// Enabled is whether the shipped corpus ships this detector switched on.
	// The nine disabled integration rows import as disabled documents rather
	// than vanishing, so the field is carried rather than filtered on.
	Enabled bool `json:"enabled"`

	// Exception is the census's own note on this row, empty when it carries
	// none. Thirty rows carry one and they are the rows a reader must not
	// discover for themselves.
	Exception string `json:"exception,omitempty"`
}

// BarePlanes are the planes on which this detector runs with its
// implementation present in the binary and NOT consulted.
//
// For a pattern record it is always empty. For an algorithmic record these are
// the planes where the detector matches on its pattern alone, and where it
// therefore fires MORE often than a gated plane rather than less (#3963).
func (d DetectorRecord) BarePlanes() []string {
	gating := map[string]bool{}
	for _, p := range d.GatingPlanes {
		gating[p] = true
	}
	for _, p := range d.MixedPlanes {
		gating[p] = true
	}
	var out []string
	for _, p := range d.Planes {
		if !gating[p] {
			out = append(out, p)
		}
	}
	return sortedStrings(out)
}

// GatesOn reports whether the implementation gates every evaluation on a
// plane.
func (d DetectorRecord) GatesOn(plane string) bool {
	for _, p := range d.GatingPlanes {
		if p == plane {
			return true
		}
	}
	return false
}

// Validate checks one record in isolation.
//
// Cross-record rules - whether a plane is a declared enforcement plane,
// whether an obligation type is one the contract declares - belong to the
// catalog and are not repeated here.
func (d DetectorRecord) Validate() Findings {
	subject := d.ID.String()
	var out Findings
	if d.ID == "" {
		return out.errorf(CodeDetectorIdentifierInvalid, "(empty detector id)",
			"a detector record carries an identifier; the empty one would key the registry on a value every unfilled field also produces")
	}
	if strings.TrimSpace(string(d.ID)) != string(d.ID) {
		out = out.errorf(CodeDetectorIdentifierInvalid, subject,
			"detector identifier %q has surrounding whitespace; it is embedded in an attribute path and a trimmed and untrimmed spelling would be two detectors", d.ID)
	}
	if !d.Class.IsValid() {
		out = out.errorf(CodeDetectorClassNotDeclared, subject,
			"implementation class is %s; the class decides whether a customer may edit what computes the verdict, and an unfilled class reads as one of the real answers", d.Class)
	}
	if d.Version <= 0 {
		out = out.errorf(CodeDetectorVersionInvalid, subject,
			"implementation version is %d; a document pins a version, and version zero would pin the value an unset field also carries", d.Version)
	}
	if len(d.Editions) == 0 {
		out = out.errorf(CodeEditionNotDeclared, subject,
			"the record names no edition; a bundle assembled for a deployment must not reference a detector that deployment's binaries do not contain, and that question has no answer for a detector that declares no build")
	}
	for _, e := range d.Editions {
		if !e.IsValid() {
			out = out.errorf(CodeEditionNotDeclared, subject, "edition %s is not a declared build", e)
		}
	}
	switch d.Class {
	case DetectorClassPattern:
		if !d.Dialect.IsValid() {
			out = out.errorf(CodeDetectorDialectNotDeclared, subject,
				"pattern dialect is %s; every shipped pattern is RE2 by accident of Go's regexp, and an undeclared dialect is how a backtracking engine arrives without anybody admitting it", d.Dialect)
		}
		if d.PatternDigest == "" {
			out = out.errorf(CodeDetectorImplementationMissing, subject,
				"a pattern detector carries a pattern digest; without one the record identifies no pattern and a version bump would pin nothing")
		}
		if d.Impl != "" {
			out = out.errorf(CodeDetectorImplementationMissing, subject,
				"a pattern detector names implementation %q; the pattern IS the implementation, and naming a Go symbol beside it would make the record claim a gate the evaluator does not apply", d.Impl)
		}
		if len(d.ImplEvidence) > 0 {
			out = out.errorf(CodeDetectorConformanceMissing, subject,
				"a pattern detector names implementation evidence %v; a pattern's behaviour is its pattern, which the digest already pins, so a test named here would be a test about regexp rather than about this detector", d.ImplEvidence)
		}
	case DetectorClassNotADetector:
		// A not-a-detector row inspects no content, so it has neither a
		// pattern nor an implementation and there is nothing for either to
		// gate. Without this arm such a record registered with no digest, no
		// implementation and no evidence, entirely unchecked - and
		// `deriveGatingPlanes` gave it an empty gating set, which
		// `CheckDetectorSelection` then reported as a bare pattern, naming an
		// implementation that was the empty string. Unreachable from today's
		// census (zero such rows) and reachable through the exported
		// `RecordFor` and `AllDetectorClasses`.
		if d.PatternDigest != "" || d.Impl != "" || len(d.ImplEvidence) > 0 {
			out = out.errorf(CodeDetectorImplementationMissing, subject,
				"a not-a-detector record carries a pattern digest, an implementation or evidence; it inspects no content, so there is nothing for any of them to describe")
		}
		if len(d.Planes) > 0 {
			out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
				"a not-a-detector record declares plane(s) %v; it inspects no content, so it has no detector verdict for a plane to produce and a policy must not select it by plane at all", d.Planes)
		}
	case DetectorClassAlgorithmic:
		if d.Impl == "" {
			out = out.errorf(CodeDetectorImplementationMissing, subject,
				"an algorithmic detector names the Go symbol its verdict comes from; without it the class is a claim with nothing behind it")
		}
		if len(d.ImplEvidence) == 0 {
			out = out.errorf(CodeDetectorConformanceMissing, subject,
				"an algorithmic detector names at least one test that drives its implementation; its behaviour is code that moves under documents nobody edited, and a version with no evidence is a version nobody can check")
		}
		for _, e := range d.ImplEvidence {
			if _, _, ok := strings.Cut(e, "::"); !ok {
				out = out.errorf(CodeDetectorConformanceMissing, subject,
					"implementation evidence %q is not in the path::Symbol form; a bare name cannot be located and a check that cannot locate it passes on every spelling", e)
			}
		}
	}
	// AN ENABLED DETECTOR EVALUATES SOMEWHERE. A DISABLED ONE DOES NOT, AND
	// THAT IS NOT THE SAME AS ABSENT.
	//
	// Nine shipped rows are the disabled integration seeds, excluded by the
	// legacy readers' own predicate: they evaluate on no plane at all and they
	// must be REGISTERED so that enabling one is a configuration change rather
	// than the arrival of a control nothing described. So an empty plane list
	// is legitimate exactly when the detector is disabled, and an enabled
	// detector with no plane is a control the portal lists and nothing runs.
	if d.Enabled && len(d.Planes) == 0 {
		out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
			"the detector is enabled and declares no enforcement plane; a control that is listed and evaluated nowhere is the defect this registry exists to make impossible")
	}
	if !d.Enabled && len(d.Planes) > 0 {
		out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
			"the detector is disabled and declares plane(s) %v; a disabled detector is excluded by the legacy readers' own predicate and evaluates nowhere, so a plane list here claims enforcement that does not happen", d.Planes)
	}
	planes := map[string]bool{}
	for _, p := range d.Planes {
		planes[p] = true
	}
	for _, p := range d.GatingPlanes {
		if !planes[p] {
			out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
				"plane %q is declared as gating and is not one of the planes the detector is evaluated on", p)
		}
	}
	for _, p := range d.MixedPlanes {
		if !planes[p] {
			out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
				"plane %q is declared as mixed and is not one of the planes the detector is evaluated on", p)
		}
	}
	for _, p := range d.GatingPlanes {
		for _, m := range d.MixedPlanes {
			if p == m {
				out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
					"plane %q is declared both fully gating and mixed; the two are exclusive and a plane in both would satisfy a selection check that must refuse it", p)
			}
		}
	}
	// A PATTERN detector gates wherever it runs, on both engines, because the
	// pattern is what both engines run. A record claiming otherwise has either
	// mis-derived its planes or mis-derived its class, and both are worth
	// refusing rather than projecting.
	if d.Class == DetectorClassPattern {
		if bare := d.BarePlanes(); len(bare) > 0 {
			out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
				"a pattern detector declares plane(s) %v on which its implementation does not gate; a pattern IS the implementation and both legacy engines run it identically, so this record has mis-derived either its planes or its class", bare)
		}
	}
	for _, e := range d.DefaultEmit {
		if !e.IsValid() {
			out = out.errorf(CodeDetectorEmitNotDeclared, subject,
				"default emit %q is not one of Signal, Deny or Escalate", e)
		}
	}
	return out
}

// clone returns a deep copy.
//
// Every accessor and every store goes through it, for the reason
// `ActionRecord.clone` does: the catalog is the authority for these values and
// nothing outside it may hold a writable reference to them. A caller able to
// append to `GatingPlanes` after registration could make a bare plane claim a
// gate, past the check that would have refused it.
func (d DetectorRecord) clone() DetectorRecord {
	out := d
	out.ImplEvidence = sortedStrings(d.ImplEvidence)
	out.Editions = append([]Edition(nil), d.Editions...)
	sort.Slice(out.Editions, func(i, j int) bool { return out.Editions[i] < out.Editions[j] })
	out.Planes = sortedStrings(d.Planes)
	out.GatingPlanes = sortedStrings(d.GatingPlanes)
	out.MixedPlanes = sortedStrings(d.MixedPlanes)
	out.DefaultEmit = append([]Emit(nil), d.DefaultEmit...)
	sort.Slice(out.DefaultEmit, func(i, j int) bool { return out.DefaultEmit[i] < out.DefaultEmit[j] })
	out.DefaultObligations = append([]contract.ObligationType(nil), d.DefaultObligations...)
	sort.Slice(out.DefaultObligations, func(i, j int) bool { return out.DefaultObligations[i] < out.DefaultObligations[j] })
	return out
}

// RegisterDetector declares one detector.
//
// Create-only, for the reason RegisterAction is. There is no `ApplyClassChange`
// counterpart to `ApplyTagChange` and there deliberately is not: a governed tag
// change is a change to which actions a policy reaches, which an approval
// reference can justify; a class change is a change to what the verdict MEANS,
// and the model for that is a new version of the implementation, which is a new
// record.
func (c *Catalog) RegisterDetector(d DetectorRecord) error {
	key := d.ID.String()
	f := d.Validate()
	if _, exists := c.detectors[key]; exists {
		f = f.errorf(CodeAlreadyRegistered, key,
			"detector %q is already registered; registration is create-only, and a change to its class or implementation is a version bump rather than an edit", key)
	}
	f = append(f, c.crossCheckDetector(d)...)
	if err := f.Err(); err != nil {
		return err
	}
	stored := d.clone()
	c.detectors[key] = stored
	c.record(EventDetectorRegistered, SeverityInfo, key,
		"registered class=%s version=%d editions=%v gating on %v, bare on %v, mixed on %v",
		d.Class, d.Version, stored.Editions, stored.GatingPlanes, stored.BarePlanes(), stored.MixedPlanes)
	return nil
}

// crossCheckDetector applies the rules that need the rest of the catalog.
func (c *Catalog) crossCheckDetector(d DetectorRecord) Findings {
	subject := d.ID.String()
	var out Findings
	// THE PLANE HALF OF THE RULE `DetectorRecord.Validate`'S HEADER DEFERS TO
	// THIS FUNCTION. It said "whether a plane is a declared enforcement plane
	// ... belongs to the catalog" and only the obligation half was implemented,
	// so a record could declare a plane that exists nowhere and
	// `CheckDetectorSelection` would then treat it as known. The declared set
	// is the legacy plane table's, which this package already embeds.
	declaredPlanes, err := ParseLegacyPlanes(LegacyPlaneFile)
	if err != nil {
		out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
			"the legacy plane table cannot be parsed, so no detector's planes can be checked against it: %v", err)
		return out
	}
	known := map[string]bool{}
	for _, r := range declaredPlanes {
		known[r.Plane] = true
	}
	for _, p := range d.Planes {
		if !known[p] {
			out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
				"the record declares plane %q, which is not a declared enforcement plane. A policy selecting it would be told the detector runs there, and nothing enforces anything on a plane that does not exist", p)
		}
	}
	declared := map[contract.ObligationType]bool{}
	for _, t := range contract.AllObligationTypes() {
		declared[t] = true
	}
	for _, o := range d.DefaultObligations {
		if !declared[o] {
			out = out.errorf(CodeObligationTypeUndeclared, subject,
				"default obligation %q is not an obligation type the contract declares", o)
		}
	}
	return out
}

// Detector returns a registered detector by identifier.
func (c *Catalog) Detector(id DetectorID) (DetectorRecord, bool) {
	d, ok := c.detectors[id.String()]
	if !ok {
		return DetectorRecord{}, false
	}
	return d.clone(), true
}

// Detectors returns every registered detector in identifier order.
func (c *Catalog) Detectors() []DetectorRecord {
	out := make([]DetectorRecord, 0, len(c.detectors))
	for _, key := range sortedKeys(c.detectors) {
		out = append(out, c.detectors[key].clone())
	}
	return out
}

// CheckDetectorSelection refuses an inspection policy that selects a detector
// on a plane which cannot run that detector's implementation.
//
// This is the mechanical form of the census's warning. Twenty shipped
// detectors are algorithmic, and until #3963 all twenty listed `proxy_tier`,
// whose only static call site was the tier engine's `EvaluatePolicy` - a call
// to `re.MatchString` with no validator anywhere in the package. An inspection
// policy that selected `proxy_tier` and depended on the Luhn check was
// therefore satisfied by any sixteen digits, and nothing in the policy, the
// document or the bundle said so. #4253 retired the plane with the engine.
//
// It refuses rather than warns, and the two refusals carry different codes,
// because the remedies differ: a bare plane needs the policy narrowed or the
// evaluator changed; a mixed plane needs the plane SPLIT, which is a defect in
// the legacy plane taxonomy rather than in the policy or the detector.
//
// # THIS REFUSAL IS EXPECTED TO BECOME OBSOLETE, AND #3963 IS WHY
//
// The bare-plane arm is the correct handling for a genuine capability gap and
// the WRONG handling for an unwired one. The tier engine's omission is the
// second: the validators are plain exported package-level functions with no
// receiver, no handle and no state, in a package the agent already depends on,
// so there is no interface to implement and nothing to thread - nobody wired
// it. The operator has ruled (#3963) that the inconsistency is closed rather
// than accommodated. On the day the tier engine resolved the validator through
// the same real function the loader and the evaluator use (#3963), an
// algorithmic detector DID gate on `proxy_tier`, `BarePlanes()` went empty for
// all twenty, and this arm stopped firing on its own. It has had no shipped
// instance since, and stays for the next plane that gains a bare site.
//
// The derivation above must survive that change and the refusal need not: what
// makes the difference visible at all is `GatingPlanes` being a property of the
// DETECTOR rather than a copy of the census's per-plane column. A guard whose
// justification dies quietly is how the next person re-derives all of this.
//
// AND THAT FIX IS NOT PURELY A TIGHTENING, WHICH IS THE PART THAT WILL SURPRISE
// SOMEBODY. Several shipped validators are CONTEXT-GATED: `ValidatePassport`,
// `ValidateDOB` and the Singapore label validators read a label immediately
// preceding the match and return false without it, and `ValidateAadhaar`
// requires the label in the left context or in the match itself. The shared
// engine can supply that window because its scan - since #3968 the single
// `sharedpolicy.ScanAccepted` - has every occurrence's LOCATION; `re.MatchString`
// has none. So a naive wiring - resolving the
// validator and passing an empty context - makes those rows reject everything
// on `proxy_tier`, which would have REMOVED detections rather than tightening them.
// SETTLED AT EIGHT ROWS FROM SEVEN VALIDATORS, and the way that number moved
// is worth more than the number:
//
//	four   counted from validator names, by inspection
//	five   the same count corrected for one validator serving two rows
//	seven  measured here, one match under two contexts, over all twenty rows
//	eight  measured by #3963's lane after rebuilding its own instrument
//
// None of the first three came from driving the code. The eight:
//
//	eu_gdpr_passport_detection   label must immediately precede the value
//	sys_pii_passport             the same validator, a second row
//	sys_pii_dob                  label must immediately precede the value
//	sys_pii_aadhaar              label required in the context OR in the match
//	sys_pii_singapore_nric       label required
//	sys_pii_singapore_fin        label required
//	sys_pii_singapore_postal     label required
//	sys_pii_singapore_uen        label required
//
// TWO INSTRUMENTS DISAGREED AND BOTH WERE INCOMPLETE, WHICH IS THE PART TO
// CARRY. The other lane's harness drove only validators present in a
// hand-written map, so it held the listed ones honest and was structurally
// blind to an unlisted one - a list-based test wearing a behavioural coat -
// which is how Aadhaar and Singapore NRIC went missing from its count. Mine
// missed `sys_pii_singapore_fin` for the opposite reason: the probe failed the
// FIN FORM check before context was ever consulted, so it was refused with a
// label and without one. That row was recorded as UNMEASURED rather than placed
// on either side, and the unmeasured bucket is what made it findable. A
// two-bucket classification where a third state is possible is how a row
// disappears. `sys_pii_booking_ref` is a ninth row that stops matching, by a
// different mechanism again: algorithmic by accident, falling to the
// `pii-global` default `ValidateCreditCard`, which rejects every non-card
// string.
//
// Whoever builds #3963 owes a before/after over the real corpus in BOTH
// directions, not only over the false positives that stop firing.
func (c *Catalog) CheckDetectorSelection(id DetectorID, planes []string) Findings {
	subject := id.String()
	d, ok := c.detectors[subject]
	if !ok {
		return Findings{}.errorf(CodeUnknownDetector, subject,
			"policy selects detector %q, which is not registered; a policy naming an unregistered detector reads an attribute path no enforcement point populates, and an UNKNOWN detector makes every constraint that reads it Indeterminate", subject)
	}
	// A pattern detector gates on every plane it runs on, so nothing here can
	// refuse one. That is not an exemption, it is the derivation in
	// DetectorRecord.Validate holding: BarePlanes is empty for a pattern
	// record by a rule that refuses a record where it is not.
	if d.Class == DetectorClassNotADetector {
		// ITS OWN CODE. Reporting this as CodeUnknownDetector would tell a
		// caller the catalog does not hold the identifier, which is false -
		// it holds it and it inspects no content - and a caller counting that
		// code could not separate "you named something that does not exist"
		// from "you selected by plane a thing that has no per-plane verdict".
		return Findings{}.errorf(CodeDetectorSelectsANonDetector, subject,
			"policy selects %q by plane, and that record inspects no content: it is a plain verdict rule that becomes a grant, a ceiling or a requirement, so it has no detector verdict on any plane. Reporting a bare pattern here would describe a validator gap that does not exist", subject)
	}
	var out Findings
	bare := map[string]bool{}
	for _, p := range d.BarePlanes() {
		bare[p] = true
	}
	mixed := map[string]bool{}
	for _, p := range d.MixedPlanes {
		mixed[p] = true
	}
	known := map[string]bool{}
	for _, p := range d.Planes {
		known[p] = true
	}
	// DEDUPLICATED. `Record.Planes` genuinely repeats a plane when one handler
	// registers two call sites on it - `mcp` appears twice for
	// `drop_table_prevention` - and a caller passing that list straight
	// through would get the same refusal twice, which then reads as two planes
	// in any count taken over the findings.
	for _, p := range dedupedSorted(planes) {
		switch {
		case bare[p]:
			out = out.errorf(CodeDetectorPlaneCannotGate, subject,
				"the policy selects plane %q, where detector %q runs as a bare pattern: its implementation (%s) is in the binary and that plane's evaluator does not consult it, so the policy would be satisfied by a pattern match the algorithm rejects",
				p, subject, d.Impl)
		case mixed[p]:
			out = out.errorf(CodeDetectorPlanePartiallyGates, subject,
				"the policy selects plane %q, whose name covers call sites that do not agree: the implementation of detector %q gates one phase there and the bare pattern decides the other, so the plane can neither be relied on nor refused as a whole. The remedy is to split the plane, one name per handler phase",
				p, subject)
		case !d.Enabled:
			// A DISABLED detector and an UNDECLARED plane produce the same
			// empty plane set, and telling the two apart is the difference
			// between "your policy names the wrong plane" and "the control you
			// selected is switched off in this corpus". Nine shipped rows are
			// in the second state.
			out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
				"the policy selects plane %q and detector %q is disabled in the shipped corpus, so it is evaluated nowhere and its verdict is UNKNOWN on every plane rather than false. Enabling it is a configuration change, not a policy change", p, subject)
		case !known[p]:
			out = out.errorf(CodeDetectorPlanesNotDeclared, subject,
				"the policy selects plane %q, on which detector %q is not evaluated at all; the detector's verdict is UNKNOWN there rather than false", p, subject)
		}
	}
	return out
}

// dedupedSorted returns the distinct members in a stable order.
func dedupedSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return sortedStrings(out)
}
