// ADR-065 registry-plane conformance corpus (#3558, acceptance gate 14).
//
// ID ALLOCATION. Conformance case identifiers are AXC-NNN. AXC-001 through
// AXC-199 belong to the decision core, AXC-200 through AXC-299 to the identity
// plane, and AXC-300 through AXC-399 are the registry plane's. Nothing outside
// this package may allocate in that range.
//
// The three mechanisms are the ones the identity plane established in #3570,
// reproduced here rather than reinvented, because each catches something the
// others cannot:
//
//  1. Every case names the Go test that executes it, and a registry test
//     asserts that test exists in this package's source.
//  2. Every executing test calls MarkConformanceCase, and TestMain fails the
//     package if a case was never marked. This is the one that catches a test
//     that still exists and still passes but no longer exercises its case.
//  3. The registry test asserts the identifier range, uniqueness, and that
//     every case either names a source case or is explicitly new.
//
// Mechanism 2 is suppressed under a -run filter, because a filtered run
// legitimately executes a subset. CI runs the package unfiltered.

package registry

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ConformanceCase is one executable registry-plane conformance case.
type ConformanceCase struct {
	// ID is the AXC-3NN identifier the disposition ledger's coverage column
	// cites.
	ID string
	// Title is a one-line description.
	Title string
	// SourceCases are the source-specification cases this covers. Empty means
	// the case has no source counterpart, which is legitimate: the registry is
	// an ADR-065 addition and most of what it refuses the source proposal
	// permitted.
	SourceCases []string
	// Asserts states the property in the form a reviewer checks the test
	// against.
	Asserts string
	// TestName is the Go test function that executes it.
	TestName string
	// TestFile is the file that test lives in, relative to this package.
	TestFile string
}

// registryConformanceCases is the corpus.
var registryConformanceCases = []ConformanceCase{
	{
		ID: "AXC-300", Title: "An unregistered tool is refused before any policy loads",
		SourceCases: []string{"EX-36"},
		Asserts: "ResolveTool on an unregistered tool identifier answers ResolutionUnknownTool with contract.ReasonUnknownAction, " +
			"which is distinguishable from a registered action that has no matching permission.",
		TestName: "TestUnregisteredToolIsRefusedBeforePolicy", TestFile: "tool_test.go",
	},
	{
		ID: "AXC-301", Title: "Tool schema drift invalidates the mapping",
		SourceCases: []string{"EX-36"},
		Asserts: "A tool called at a registry version other than the one its mapping was registered against resolves to " +
			"ResolutionSchemaDrift rather than producing a request from a mapping that no longer describes the schema.",
		TestName: "TestToolSchemaDriftInvalidatesTheMapping", TestFile: "tool_test.go",
	},
	{
		ID: "AXC-302", Title: "A tool bound to an unregistered action is unregisterable",
		SourceCases: []string{"EX-36"},
		Asserts: "RegisterTool refuses a tool whose action is not in the catalog, which is where a tool with no declared " +
			"posture is refused, because posture lives on the action.",
		TestName: "TestToolBoundToAnUnregisteredActionIsRefused", TestFile: "tool_test.go",
	},
	{
		ID: "AXC-303", Title: "An action whose required argument is undeclared is unregisterable",
		SourceCases: []string{"EX-37"},
		Asserts: "RegisterAction refuses a record requiring an argument its own schema does not declare, so the admission-time " +
			"schema violation can never be caused by the registry rather than by the caller.",
		TestName: "TestActionWithAnUndeclaredRequiredArgumentIsRefused", TestFile: "action_test.go",
	},
	{
		ID: "AXC-304", Title: "The projected registry carries the declared argument schema",
		SourceCases: []string{"EX-37"},
		Asserts: "PDPRegistry projects the catalog's argument schema, required arguments and risk classes verbatim, so the " +
			"schema a request is admitted against is the schema somebody registered.",
		TestName: "TestProjectionCarriesTheDeclaredSchema", TestFile: "catalog_test.go",
	},
	{
		ID: "AXC-305", Title: "A recursive resource type without a bounded depth is unregisterable",
		SourceCases: []string{"EX-43"},
		Asserts: "RegisterResourceType refuses a recursive type whose maximum depth is not positive, because an unbounded " +
			"closure cannot be truncated and therefore cannot fail closed.",
		TestName: "TestRecursiveResourceTypeRequiresABoundedDepth", TestFile: "resource_test.go",
	},
	{
		ID: "AXC-306", Title: "A non-recursive resource type carrying a depth is unregisterable",
		SourceCases: []string{"EX-43"},
		Asserts: "RegisterResourceType refuses a non-recursive type that declares a maximum depth, because the two fields " +
			"disagree and reading either as authoritative would be a guess.",
		TestName: "TestNonRecursiveResourceTypeRefusesADepth", TestFile: "resource_test.go",
	},
	{
		ID: "AXC-307", Title: "A containment scope over a non-recursive type is refused at save time",
		SourceCases: []string{"EX-43"},
		Asserts: "CheckContainmentScope answers SCOPE_REQUIRES_RECURSION for a non-recursive type and UNKNOWN_RESOURCE_TYPE " +
			"for one the catalog does not hold, never nil.",
		TestName: "TestContainmentScopeRequiresRecursion", TestFile: "resource_test.go",
	},
	{
		ID: "AXC-308", Title: "An undeclared ancestor level is refused at save time",
		Asserts: "CheckAncestorLevel answers LEVEL_NOT_DECLARED for a level the type does not declare, which is the only place " +
			"it can be caught: at runtime the level resolves to authoritatively absent, so the policy never matches and never errors.",
		TestName: "TestUndeclaredAncestorLevelIsRefused", TestFile: "resource_test.go",
	},
	{
		ID: "AXC-309", Title: "An enforcement point in an undeclared realm is unregisterable",
		SourceCases: []string{"EX-46"},
		Asserts: "RegisterPEP refuses a record whose realm the catalog does not declare, and refuses one that declares no realm " +
			"at all, so no plane can authenticate as something no policy can be scoped to.",
		TestName: "TestEnforcementPointRealmMustBeDeclared", TestFile: "pep_test.go",
	},
	{
		ID: "AXC-310", Title: "A missing obligation type fails the capability check",
		Asserts: "SupportsObligation answers CapabilityTypeUnsupported for an enforcement point that advertises other types, " +
			"and Supported is false.",
		TestName: "TestCapabilityCheckRefusesAnUnsupportedType", TestFile: "pep_test.go",
	},
	{
		ID: "AXC-311", Title: "A version mismatch fails the capability check",
		Asserts: "SupportsObligation answers CapabilityVersionUnsupported when the type is advertised at other versions only. " +
			"Matching is exact in both directions: a newer advertised version does not satisfy an older obligation.",
		TestName: "TestCapabilityCheckMatchesTheVersionExactly", TestFile: "pep_test.go",
	},
	{
		ID: "AXC-312", Title: "An absent record is distinguishable from a declared-empty capability set",
		Asserts: "SupportsObligation answers CapabilityNoRecord for an unregistered enforcement point and CapabilityDeclaredNone " +
			"for a registered one advertising nothing. Both refuse, and the two statuses never collapse.",
		TestName: "TestAbsentRecordIsDistinguishableFromDeclaredEmpty", TestFile: "pep_test.go",
	},
	{
		ID: "AXC-313", Title: "Publication refuses an undischargeable mandatory obligation",
		Asserts: "CheckPublication refuses a mandatory obligation any named enforcement point cannot discharge, so the capability " +
			"is proved before the policy ships rather than by the first caller through it.",
		TestName: "TestPublicationRefusesAnUndischargeableObligation", TestFile: "pep_test.go",
	},
	{
		ID: "AXC-314", Title: "A community enforcement point cannot advertise an Enterprise-only family",
		Asserts: "RegisterPEP refuses a community record advertising an obligation in an Enterprise-only family, because " +
			"over-advertising is the dangerous direction: the decision is issued on the strength of the claim.",
		TestName: "TestCommunityEnforcementPointCannotAdvertiseEnterpriseFamilies", TestFile: "pep_test.go",
	},
	{
		ID: "AXC-315", Title: "An action missing either posture axis is unregisterable",
		Asserts: "RegisterAction refuses a record with no unmatched value, one with no on_error value, and one with neither, " +
			"each with POSTURE_NOT_DECLARED naming the missing axis.",
		TestName: "TestBothPostureAxesAreMandatory", TestFile: "posture_test.go",
	},
	{
		ID: "AXC-316", Title: "A permissive unmatched posture needs a live compatibility exception",
		Asserts: "RegisterAction refuses unmatched=permit with no registered exception, refuses one whose exception is missing " +
			"an owner, metric, expiry or removal issue, and refuses one whose exception has expired.",
		TestName: "TestPermissivePostureNeedsALiveException", TestFile: "posture_test.go",
	},
	{
		ID: "AXC-317", Title: "The compatibility posture is unavailable for a high-risk action",
		Asserts: "RegisterAction refuses unmatched=permit on a privileged, irreversible or data-egress action even with a " +
			"complete unexpired exception.",
		TestName: "TestCompatibilityPostureIsUnavailableForHighRiskActions", TestFile: "posture_test.go",
	},
	{
		ID: "AXC-318", Title: "A permissive error posture is refused under every exception",
		Asserts: "RegisterAction refuses on_error=permit whether or not a complete compatibility exception names the action, " +
			"because a permissive error posture converts an outage into a widening of access.",
		TestName: "TestPermissiveErrorPostureHasNoExceptionPath", TestFile: "posture_test.go",
	},
	{
		ID: "AXC-319", Title: "An undeclared posture cannot reach an evaluator",
		Asserts: "PDPRegistry refuses to project a catalog carrying any blocking finding, so there is no path from a record " +
			"with an undeclared posture to a running engine even when the catalog was not assembled through RegisterAction.",
		TestName: "TestProjectionRefusesAnInvalidCatalog", TestFile: "catalog_test.go",
	},
	{
		ID: "AXC-320", Title: "Deny is not a declarable unmatched posture",
		Asserts: "RegisterAction refuses unmatched=deny: under the four-valued outcome deny means an explicit constraint " +
			"matched, and the fail-closed seed is not_applicable, which reaches the same PEP state with the honest reason.",
		TestName: "TestUnmatchedPostureCannotForgeAnExplicitConstraint", TestFile: "posture_test.go",
	},
	{
		ID: "AXC-321", Title: "Removing a governed tag raises an alarm",
		Asserts: "ApplyTagChange emits GOVERNED_TAG_REMOVED at SeverityAlarm, naming the tag, the actor, the approval and the " +
			"owner, because every constraint selecting on that tag stops matching with nothing to see in any policy.",
		TestName: "TestGovernedTagRemovalRaisesAnAlarm", TestFile: "tag_test.go",
	},
	{
		ID: "AXC-322", Title: "Adding a governed tag raises an alarm",
		Asserts: "ApplyTagChange emits GOVERNED_TAG_ADDED at SeverityAlarm, because a tag addition arms every permission " +
			"selecting on it, which is the mirror image of the removal case and equally invisible in the policy set.",
		TestName: "TestGovernedTagAdditionRaisesAnAlarm", TestFile: "tag_test.go",
	},
	{
		ID: "AXC-323", Title: "A governed-tag change without approval is refused",
		Asserts: "ApplyTagChange refuses a change moving a governed tag with no approval reference, and accepts the same " +
			"change over an ungoverned tag, so the requirement tracks governance rather than the operation.",
		TestName: "TestGovernedTagChangeRequiresApproval", TestFile: "tag_test.go",
	},
	{
		ID: "AXC-324", Title: "Re-registration cannot bypass the tag change path",
		Asserts: "RegisterAction refuses an identifier already registered, so a caller cannot drop a governed tag by " +
			"re-registering the action and thereby raise no alarm.",
		TestName: "TestRegistrationIsCreateOnly", TestFile: "catalog_test.go",
	},
	{
		ID: "AXC-325", Title: "An action tag outside the vocabulary is unregisterable",
		Asserts: "RegisterAction refuses a tag the catalog's vocabulary does not declare, so a policy channel cannot exist " +
			"without an owner and a governance class.",
		TestName: "TestActionTagsMustBeInTheVocabulary", TestFile: "tag_test.go",
	},
	{
		ID: "AXC-326", Title: "An undeclared risk class is unregisterable",
		Asserts: "RegisterAction refuses a record leaving any of irreversible, spend, data_egress or privileged unspecified, " +
			"because each one is read by a rule for which the unfilled value is the permissive answer.",
		TestName: "TestEveryRiskClassIsDeclared", TestFile: "action_test.go",
	},
	{
		ID: "AXC-327", Title: "The legacy plane fixture agrees with the shadow-diff census",
		Asserts: "Every enforcement plane in the checked-in fixture is a plane the shadow-diff harness declares, every declared " +
			"plane has an Enterprise row, and no plane the harness records as unimplemented is registered as an enforcement point.",
		TestName: "TestLegacyPlaneFixtureAgreesWithTheShadowCensus", TestFile: "legacy_plane_census_test.go",
	},
	// AXC-328 .. AXC-335: the external enforcement point (#3704). Every case
	// below is about an EXTERNAL PEP - one that arrives on the wire rather than
	// being seeded from the legacy plane fixture - which is the whole surface
	// the capability handshake adds.
	{
		ID: "AXC-328", Title: "An external enforcement point's identifier is built from the channel, never from the document",
		SourceCases: []string{"EX-46"},
		Asserts: "ExternalPEPID composes the AUTHENTICATED credential with a caller-supplied name, so two credentials naming the same " +
			"enforcement point produce different identifiers and no document can reach another credential's namespace; two call paths " +
			"behind one credential stay distinguishable, and the identifier never collides with the in-process plane prefix.",
		TestName: "TestExternalPEPIdentifierIsBuiltFromTheChannelNotTheDocument", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-329", Title: "An external enforcement point in an undeclared realm cannot be admitted",
		SourceCases: []string{"EX-46"},
		Asserts: "AdmitExternalPEP refuses against a catalog that has not declared the external realm, and admits the identical record " +
			"against one that has - so a deployment cannot acquire external enforcement points without declaring the realm they authenticate as.",
		TestName: "TestAdmitExternalPEPRequiresADeclaredRealm", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-330", Title: "Admission is not registration, so a repeat declaration is not a collision",
		Asserts: "AdmitExternalPEP accepts the same record repeatedly and stores nothing, so the create-only rule that protects the " +
			"governed-tag change path cannot refuse the second request from one enforcement point, and no stored declaration can answer " +
			"for a request from a different instance of it.",
		TestName: "TestAdmissionIsNotRegistrationAndRepeatsAreFine", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-331", Title: "An unadmitted enforcement point value refuses and is recognisable as a defect",
		Asserts: "The zero ExternalPEP projects a nil profile and answers with a status that is not a declared member, never " +
			"CapabilityDeclaredNone - a construction defect must fail closed AND stay distinguishable from an enforcement point that " +
			"declared it discharges nothing.",
		TestName: "TestUnadmittedExternalPEPRefusesAndIsRecognisableAsADefect", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-332", Title: "Every capability status an external declaration can produce, and the two that must not collapse",
		Asserts: "SupportsObligation answers DeclaredNone, TypeUnsupported, VersionUnsupported and Supported for the four declarations " +
			"that produce them, through the same checkCapability the registered path uses; and the empty-declaration and unsupported-type " +
			"answers differ in BOTH status and prose, which a build collapsing them would still pass if only 'it was refused' were asserted.",
		TestName: "TestExternalCapabilityStatusPerWireState", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-333", Title: "Over-advertising is split for an external point and refused for a registered one",
		Asserts: "SplitOverAdvertised drops an Enterprise-only family from a community declaration and keeps it for an Enterprise one, " +
			"leaves an undeclared obligation type in the kept set for validateCapabilities to own, and PEPRecord.Validate still refuses " +
			"a REGISTERED community record advertising the same family - one predicate, two remedies.",
		TestName: "TestOverAdvertisementIsSplitNotIgnored", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-334", Title: "An external record derives identity and edition rather than reading them from the wire",
		Asserts: "ExternalPEPRecordFrom builds the identifier from the credential and takes the edition from its caller, the same " +
			"handshake under two derived editions produces two different records, and the encoded handshake carries no edition, realm, " +
			"tier or license member for a caller to set.",
		TestName: "TestExternalRecordDerivesIdentityAndEditionRatherThanTakingThem", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-335", Title: "A declared-empty capability set renders as an empty list, never as an absent member",
		Asserts: "PEPRecord.Profile and the registered-path round trip render a declared-empty capability set as \"capabilities\":[] " +
			"rather than null, so the one enforcement point that says it discharges nothing is not serialised as one that said nothing " +
			"at all - the collapse clone's own comment forbids and the #2958 defect this package corrects.",
		TestName: "TestDeclaredEmptyProfileRendersAsAnEmptyListNotNull", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-336", Title: "Admission refuses its degenerate inputs rather than panicking or admitting",
		Asserts: "AdmitExternalPEP on a nil catalog and on a record declaring no realm both REFUSE and produce no admitted value, " +
			"and declaring the external realm is idempotent - these arms are reached by construction rather than by a wire value, " +
			"so nothing on the request path would exercise them.",
		TestName: "TestAdmissionRefusesTheDegenerateInputsRatherThanPanicking", TestFile: "external_pep_test.go",
	},
	{
		ID: "AXC-337", Title: "An admitted enforcement point hands out copies, not its own state",
		Asserts: "ExternalPEP.Record returns a deep copy, so a holder cannot reorder or extend what the enforcement point declared " +
			"after admission validated it, and Profile projects the admitted capabilities onto a PEPProfile that supports them.",
		TestName: "TestAdmittedAccessorsHandOutCopiesAndAProfile", TestFile: "external_pep_test.go",
	},
}

// RegistryConformanceCases returns a copy of the corpus.
//
// A copy, because a caller mutating the package's own slice would make the
// corpus a function of test execution order. The identity plane's registry test
// found exactly that by mutating the first element and re-reading.
func RegistryConformanceCases() []ConformanceCase {
	return append([]ConformanceCase(nil), registryConformanceCases...)
}

// CoverageBySourceCase returns, for each source case, the registry-plane case
// identifiers covering it, sorted.
//
// It is what the disposition ledger's coverage cells are compared against. The
// cells are edited by hand and the corpus is edited in code, and nothing else
// compares them.
func CoverageBySourceCase() map[string][]string {
	out := map[string][]string{}
	for _, c := range registryConformanceCases {
		for _, src := range c.SourceCases {
			out[src] = append(out[src], c.ID)
		}
	}
	for src := range out {
		sort.Strings(out[src])
	}
	return out
}

var (
	markedMu sync.Mutex
	marked   = map[string]bool{}
)

// MarkConformanceCase records that a case executed.
//
// It panics on an identifier the corpus does not declare. A typo in a mark
// would otherwise satisfy nothing while looking like coverage, and the case it
// meant to mark would be reported as never executed with no clue why.
func MarkConformanceCase(id string) {
	if !conformanceCaseDeclared(id) {
		panic(fmt.Sprintf("registry: %q is not a declared conformance case", id))
	}
	markedMu.Lock()
	defer markedMu.Unlock()
	marked[id] = true
}

func conformanceCaseDeclared(id string) bool {
	for _, c := range registryConformanceCases {
		if c.ID == id {
			return true
		}
	}
	return false
}

// UnmarkedConformanceCases returns the declared cases that never executed.
func UnmarkedConformanceCases() []string {
	markedMu.Lock()
	defer markedMu.Unlock()
	var out []string
	for _, c := range registryConformanceCases {
		if !marked[c.ID] {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

// registryCaseIDPattern is the allocated range for this plane, and
// sourceCaseIDPattern is the source proposal's own identifier form.
var (
	registryCaseIDPattern = regexp.MustCompile(`^AXC-3\d{2}$`)
	sourceCaseIDPattern   = regexp.MustCompile(`^EX-\d{2}$`)
)

// ConformanceCorpusProblems returns every structural defect in the corpus.
//
// It is a function rather than a test body so the corpus self-test and the
// acceptance test drive one implementation. The identity plane's ledger guard
// records what happens otherwise: the gate reimplements the rules inline, the
// self-test exercises a separate copy, and rules can be disabled with the suite
// green.
func ConformanceCorpusProblems(cases []ConformanceCase) []string {
	var out []string
	seen := map[string]int{}
	for i, c := range cases {
		if !registryCaseIDPattern.MatchString(c.ID) {
			out = append(out, fmt.Sprintf("case %q is outside the registry plane's AXC-3NN range", c.ID))
		}
		if prev, dup := seen[c.ID]; dup {
			out = append(out, fmt.Sprintf("case %q at index %d duplicates index %d", c.ID, i, prev))
		}
		seen[c.ID] = i
		if strings.TrimSpace(c.Title) == "" {
			out = append(out, fmt.Sprintf("case %q has no title", c.ID))
		}
		// A short assertion is not an assertion. A reviewer checking a test
		// against its case needs the property stated, and "it works" is a
		// sentence that fits any test.
		if len(c.Asserts) < 60 {
			out = append(out, fmt.Sprintf("case %q states its property in %d characters, which is not reviewable", c.ID, len(c.Asserts)))
		}
		if c.TestName == "" || !strings.HasPrefix(c.TestName, "Test") {
			out = append(out, fmt.Sprintf("case %q names test %q, which is not a Go test function name", c.ID, c.TestName))
		}
		if !strings.HasSuffix(c.TestFile, "_test.go") {
			out = append(out, fmt.Sprintf("case %q names test file %q, which is not a Go test file", c.ID, c.TestFile))
		}
		for _, src := range c.SourceCases {
			if !sourceCaseIDPattern.MatchString(src) {
				out = append(out, fmt.Sprintf("case %q cites source case %q, which is not of the form EX-NN", c.ID, src))
			}
		}
	}
	sort.Strings(out)
	return out
}
