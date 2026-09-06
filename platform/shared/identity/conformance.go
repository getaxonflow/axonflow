// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 identity-plane conformance corpus (#3550, acceptance gate 14).
//
// ADR-065 requires a 47-row disposition ledger over the source specification's
// cases, in which every source case records its disposition and the executable
// conformance cases that cover it. That ledger and the decision-core cases
// live with the conformance suite (platform/decision/conformance); the
// IDENTITY-plane cases are declared here and executed by this package's tests,
// so a case can never be listed as covered by a test that does not exist.
//
// ID ALLOCATION. Conformance case IDs are AXC-NNN. AXC-001 through AXC-199
// belong to the decision core; AXC-200 through AXC-299 are the identity
// plane's and nothing outside this package may allocate in that range.
//
// # WHY THE REGISTRY IS EXECUTABLE RATHER THAN A DOCUMENT
//
// A conformance list that is only a document drifts silently: a case is
// renamed, a test is deleted, or a case is added and never wired, and the list
// still reads as complete. Three mechanisms stop that here, and each catches
// something the others do not:
//
//  1. Every case names the Go test that executes it, and a registry test
//     asserts that test exists in this package's source.
//  2. Every executing test calls MarkConformanceCase, and TestMain fails the
//     package if a case applicable to this edition was never marked. This is
//     the one that catches a test that exists but no longer exercises its
//     case, which mechanism 1 cannot see.
//  3. The registry test asserts the ID range, uniqueness, and that every case
//     names at least one source case or is explicitly marked as new.
//
// Mechanism 2 is suppressed when the test binary was invoked with a -run
// filter, because a filtered run legitimately executes a subset. CI runs the
// package unfiltered, which is where the check is meant to bite.
package identity

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ConformanceEdition records which builds a conformance case applies to.
type ConformanceEdition int

const (
	// ConformanceAnyEdition applies to community and Enterprise builds alike.
	ConformanceAnyEdition ConformanceEdition = iota
	// ConformanceEnterpriseOnly applies only where the directory graph and
	// SCIM ingestion are compiled in.
	ConformanceEnterpriseOnly
)

// String renders the edition.
func (e ConformanceEdition) String() string {
	if e == ConformanceEnterpriseOnly {
		return "enterprise"
	}
	return "any"
}

// ConformanceCase is one executable identity-plane conformance case.
type ConformanceCase struct {
	// ID is the AXC-2NN identifier. It is what the disposition ledger's
	// coverage_case_ids column cites.
	ID string
	// Title is a one-line description.
	Title string
	// SourceCases are the source-specification cases this covers, if any.
	// Empty means the case has no source counterpart, which is legitimate:
	// ADR-065 corrects and extends the source model.
	SourceCases []string
	// Asserts states the property, in the form a reviewer can check the test
	// against.
	Asserts string
	// Edition records which builds execute it.
	Edition ConformanceEdition
	// TestName is the Go test function that executes it.
	TestName string
	// TestFile is the file that test lives in, relative to this package.
	//
	// It is recorded rather than searched for, because the community sync
	// REMOVES the enterprise half of every build-tag pair: in the published
	// mirror an Enterprise-only case's file is not on disk at all, and a
	// registry check that merely searched every file for the function name
	// could not tell "correctly absent in the mirror" from "misspelled or
	// deleted". Naming the file makes that distinction exact.
	TestFile string
}

// identityConformanceCases is the corpus. It is a package-level var rather
// than a function body so the registry test can range over exactly what
// IdentityConformanceCases returns.
var identityConformanceCases = []ConformanceCase{
	// Realm declaration and the EX-47 fail-open by omission.
	{
		ID: "AXC-200", Edition: ConformanceAnyEdition,
		Title:       "Validly signed credential from an undeclared issuer denies with UNKNOWN_REALM",
		SourceCases: []string{"EX-47"},
		Asserts:     "A credential whose signature verifies but whose issuer has no declared realm in the authenticated organization yields Deny(UNKNOWN_REALM) and never reaches any later check.",
		TestName:    "TestVerifyCredentialDeniesUndeclaredIssuer",
		TestFile:    "realm_verify_test.go",
	},
	{
		ID: "AXC-201", Edition: ConformanceAnyEdition,
		Title:       "A realm cannot be registered with an undeclared directory source",
		SourceCases: []string{"EX-47", "EX-45"},
		Asserts:     "TrustRealm.Validate refuses every tri-state left at its zero value, so no registered realm can hold a falsy default that reads as has_group_graph = false.",
		TestName:    "TestRealmValidateRefusesEveryUndeclaredTriState",
		TestFile:    "realm_registry_test.go",
	},
	{
		ID: "AXC-202", Edition: ConformanceAnyEdition,
		Title:    "A realm declared in another organization is UNKNOWN_REALM here",
		Asserts:  "Realm lookup is org-scoped on both the id and the issuer index, so one organization's declaration never answers for another's credential.",
		TestName: "TestRealmLookupIsOrganizationScoped",
		TestFile: "realm_registry_test.go",
	},
	{
		ID: "AXC-203", Edition: ConformanceAnyEdition,
		Title:       "Identical subject strings in two realms are different principals",
		SourceCases: []string{"EX-47"},
		Asserts:     "PrincipalID equality includes the realm, so the same subject id asserted by two realms never collides, in equality or as a map key.",
		TestName:    "TestPrincipalIDsDoNotCollideAcrossRealms",
		TestFile:    "principal_canonical_test.go",
	},
	{
		ID: "AXC-204", Edition: ConformanceAnyEdition,
		Title:    "Canonical principal round-trips, including a subject containing colons",
		Asserts:  "ParsePrincipalID splits on the first :: and then the first :, so a SPIFFE subject id survives verbatim and String round-trips byte for byte.",
		TestName: "TestPrincipalIDRoundTrip",
		TestFile: "principal_canonical_test.go",
	},
	{
		ID: "AXC-205", Edition: ConformanceAnyEdition,
		Title:       "A bare, unqualified identifier is refused and never given a default realm",
		SourceCases: []string{"EX-47"},
		Asserts:     "ParsePrincipalID rejects a bare group or subject name rather than completing it with any realm.",
		TestName:    "TestParsePrincipalIDRefusesBareIdentifiers",
		TestFile:    "principal_canonical_test.go",
	},
	{
		ID: "AXC-206", Edition: ConformanceAnyEdition,
		Title:    "A realm may not use one claim as both canonical subject and alias",
		Asserts:  "TrustRealm.Validate refuses a claim mapping whose subject claim is also mapped as an alias, closing the configuration route to an email being an identifier.",
		TestName: "TestRealmValidateRefusesAliasAsSubjectClaim",
		TestFile: "realm_registry_test.go",
	},

	{
		ID: "AXC-277", Edition: ConformanceAnyEdition,
		Title:       "Every tri-state is validated by membership, not by inequality against its zero value",
		SourceCases: []string{"EX-47"},
		Asserts:     "An out-of-range value for any tri-state is refused at validation and at registration; an inequality check admits every value but the zero one, and DirectorySource(99).HasGroupGraph() is false, which is the permissive default the tri-state abolishes.",
		TestName:    "TestEveryTriStateIsValidatedByMembershipNotInequality",
		TestFile:    "realm_registry_test.go",
	},
	{
		ID: "AXC-278", Edition: ConformanceAnyEdition,
		Title:    "A realm re-registration must advance its version",
		Asserts:  "A no-graph closure derives its recorded source version from the realm's, so two materially different declarations sharing a version would be indistinguishable in a decision proof and in replay.",
		TestName: "TestRealmVersionMustAdvanceOnReRegistration",
		TestFile: "realm_registry_test.go",
	},

	// Organization binding, transferred from #3488.
	{
		ID: "AXC-210", Edition: ConformanceAnyEdition,
		Title:    "A wrong but non-empty organization claim is refused, not narrowed to organization-only",
		Asserts:  "A credential asserting an organization other than the authenticated one yields Deny(ORG_BINDING_MISMATCH); it is not ignored, and no empty-but-successful resolution is produced.",
		TestName: "TestOrgBindingRefusesWrongButNonEmptyOrgClaim",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-211", Edition: ConformanceAnyEdition,
		Title:    "A credential carrying no organization claim binds to the authenticated organization",
		Asserts:  "Absence of an organization claim is not a mismatch; the realm lookup already scoped the credential to the authenticated organization.",
		TestName: "TestOrgBindingAcceptsAbsentOrgClaim",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-212", Edition: ConformanceAnyEdition,
		Title:    "An empty organization claim is distinguishable from an absent one",
		Asserts:  "HasAssertedOrg separates the two, so a credential asserting the empty organization is refused while one asserting none is admitted.",
		TestName: "TestOrgBindingDistinguishesEmptyClaimFromAbsentClaim",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-213", Edition: ConformanceAnyEdition,
		Title:    "A request with no authenticated organization is refused",
		Asserts:  "Verification refuses before any lookup when there is no authenticated organization to bind the subject to.",
		TestName: "TestVerifyCredentialRefusesWithoutAuthenticatedOrg",
		TestFile: "realm_verify_test.go",
	},

	// Credential policy.
	{
		ID: "AXC-220", Edition: ConformanceAnyEdition,
		Title:    "Unsupported algorithms, audiences, authorized parties and credential types reject before policy",
		Asserts:  "Each rejects with its own reason code, and an empty azp against a realm that pins azp rejects rather than passing.",
		TestName: "TestVerifyCredentialRejectsRealmPolicyViolations",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-221", Edition: ConformanceAnyEdition,
		Title:    "Expiry, not-yet-valid, missing expiry and maximum age reject, with skew applied",
		Asserts:  "A credential with no expiry is refused rather than treated as non-expiring, and a realm bounding age refuses a credential carrying no issuance time.",
		TestName: "TestVerifyCredentialTimeChecks",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-222", Edition: ConformanceAnyEdition,
		Title:    "Assurance below the realm minimum rejects, and an unspecified assurance never satisfies a minimum",
		Asserts:  "AssuranceUnspecified ranks below every declared class, so a credential attesting nothing fails every realm floor.",
		TestName: "TestVerifyCredentialAssurance",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-223", Edition: ConformanceAnyEdition,
		Title:    "A revocation outage is Indeterminate and never masks a determinate refusal",
		Asserts:  "Revocation runs last: a credential that is both wrong-audience and unverifiable-for-revocation reports AUDIENCE_REJECTED, and a revoked credential denies while an unreachable source is indeterminate.",
		TestName: "TestVerifyCredentialRevocation",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-224", Edition: ConformanceAnyEdition,
		Title:    "A credential that did not have its signature verified is refused",
		Asserts:  "SignatureVerified false, which is the zero value, refuses; the realm-policy layer never passes unverified material.",
		TestName: "TestVerifyCredentialRefusesUnverifiedSignature",
		TestFile: "realm_verify_test.go",
	},
	{
		ID: "AXC-225", Edition: ConformanceAnyEdition,
		Title:    "An alias is never substituted for a missing canonical subject",
		Asserts:  "A credential carrying an email but no subject claim value yields SUBJECT_MISSING, and admitted aliases are recorded with authentication provenance rather than becoming keys.",
		TestName: "TestSubjectMissingIsNotFilledFromAnAlias",
		TestFile: "realm_verify_test.go",
	},

	{
		ID: "AXC-272", Edition: ConformanceAnyEdition,
		Title:    "A credential carrying an organization it is not marked as asserting is refused",
		Asserts:  "HasAssertedOrg and AssertedOrgID must agree; an adapter that populates the string and forgets the flag cannot skip the organization-binding check, which no later step could see.",
		TestName: "TestInconsistentOrgAssertionIsRefused",
		TestFile: "realm_verify_test.go",
	},

	{
		ID: "AXC-279", Edition: ConformanceAnyEdition,
		Title:       "An ordered enum is checked for membership before it is compared",
		SourceCases: []string{"EX-47"},
		Asserts:     "A credential's assurance class is refused when out of range at EITHER end; an unrecognized class above the declared range would otherwise satisfy every realm minimum by ordinary integer comparison, while declared classes at or above the floor are still admitted.",
		TestName:    "TestAnOrderedEnumIsCheckedForMembershipBeforeItIsCompared",
		TestFile:    "realm_verify_test.go",
	},

	// Actor chains and attenuation.
	{
		ID: "AXC-230", Edition: ConformanceAnyEdition,
		Title:       "Adding an actor hop cannot widen authority",
		SourceCases: []string{"EX-27"},
		Asserts:     "Effective authority is the meet across hops, so for any chain of length one or more and any additional hop, the result is a subset of the shorter chain's result.",
		TestName:    "TestAddingAnActorHopCannotWidenAuthority",
		TestFile:    "actor_chain_meet_test.go",
	},
	{
		ID: "AXC-231", Edition: ConformanceAnyEdition,
		Title:       "The confused deputy is denied: a more privileged agent does not lift its principal's limit",
		SourceCases: []string{"EX-27"},
		Asserts:     "A chain whose root lacks a capability and whose agent holds it yields an effective authority without that capability.",
		TestName:    "TestConfusedDeputyMeetAcrossHeterogeneousRealms",
		TestFile:    "actor_chain_meet_test.go",
	},
	{
		ID: "AXC-232", Edition: ConformanceAnyEdition,
		Title:    "An empty chain authorizes nothing, and MeetAll over no hops is empty rather than universal",
		Asserts:  "AdmitChain refuses an empty chain and MeetAll returns the empty authority for an empty input, so the identity element of intersection is not constructible.",
		TestName: "TestEmptyChainAuthorizesNothing",
		TestFile: "actor_chain_meet_test.go",
	},
	{
		ID: "AXC-233", Edition: ConformanceAnyEdition,
		Title:    "Chain cycles, excessive depth, unknown and disabled hop realms fail closed",
		Asserts:  "Each yields its own reason code, and an unknown realm on a non-root hop is refused exactly as on the root.",
		TestName: "TestAdmitChainFailsClosed",
		TestFile: "actor_chain_meet_test.go",
	},
	{
		ID: "AXC-234", Edition: ConformanceAnyEdition,
		Title:    "Cross-realm delegation is permitted only where the delegator's realm declares it",
		Asserts:  "Chains spanning realms are ordinary, so the check is the delegator realm's declared policy, not a same-realm requirement.",
		TestName: "TestAdmitChainCrossRealmDelegationPolicy",
		TestFile: "actor_chain_meet_test.go",
	},
	{
		ID: "AXC-235", Edition: ConformanceAnyEdition,
		Title:    "A Client credential cannot be the authority a request is evaluated for",
		Asserts:  "A Client principal at the chain root is refused; it remains admissible as an intermediary hop, where it constrains the meet without being the subject.",
		TestName: "TestClientIsAttributionNotAuthority",
		TestFile: "actor_chain_meet_test.go",
	},
	{
		ID: "AXC-236", Edition: ConformanceAnyEdition,
		Title:    "RFC 8693 act nesting is reversed into root-first order on ingestion",
		Asserts:  "ActorChainFromRFC8693 reverses, so the in-memory chain's root is the original subject regardless of the wire nesting.",
		TestName: "TestActorChainFromRFC8693IsRootFirst",
		TestFile: "actor_chain_meet_test.go",
	},

	{
		ID: "AXC-237", Edition: ConformanceAnyEdition,
		Title:       "Every hop's credential is verified before any chain-level check",
		SourceCases: []string{"EX-27"},
		Asserts:     "VerifyChain composes per-credential facts (audience, expiry, revocation) with per-chain facts (cycle, depth) in that order, so a revoked hop is reported rather than hidden behind a chain defect, and a refused chain returns no partially verified hops.",
		TestName:    "TestVerifyChainFailsClosedOnAnyHop",
		TestFile:    "chain_verify_test.go",
	},
	{
		ID: "AXC-238", Edition: ConformanceAnyEdition,
		Title:    "Human, agent, workload, service and client principals each have an executable authentication and delegation fixture",
		Asserts:  "Each kind is driven through a real admission and through a chain, rather than appearing only in a negative test; the Client kind is admitted as an intermediary and refused at the root.",
		TestName: "TestEveryPrincipalKindHasAnExecutableFixture",
		TestFile: "chain_verify_test.go",
	},

	{
		ID: "AXC-273", Edition: ConformanceAnyEdition,
		Title:    "The delegation-depth bound is applied before any credential is verified",
		Asserts:  "A chain longer than the bound is refused with zero revocation-source round trips, so the bound limits work as well as correctness, while an admissible chain still verifies every hop.",
		TestName: "TestVerifyChainBoundsWorkBeforeVerifyingCredentials",
		TestFile: "chain_verify_test.go",
	},

	// Group closure.
	{
		ID: "AXC-240", Edition: ConformanceEnterpriseOnly,
		Title:       "A cyclic group graph terminates with a complete, untruncated closure and a cycle alarm",
		SourceCases: []string{"EX-13"},
		Asserts:     "The closure of a cyclic digraph is well defined: the resolved set is complete, truncated is false, and GROUP_CYCLE_DETECTED names the loop members.",
		TestName:    "TestClosureOverACyclicGraph",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-241", Edition: ConformanceEnterpriseOnly,
		Title:    "A diamond is not reported as a cycle",
		Asserts:  "A revisit is only a cycle when the revisited node is an ancestor on the path that reached it; two groups sharing a parent raise no warning.",
		TestName: "TestClosureDoesNotReportADiamondAsACycle",
		TestFile: "directory_closure_test.go",
	},
	{
		ID: "AXC-242", Edition: ConformanceEnterpriseOnly,
		Title:       "A truncated closure is Indeterminate and yields no group set",
		SourceCases: []string{"EX-14"},
		Asserts:     "Hitting the depth, group or fan-out bound produces TRUNCATED, AuthoritativeGroups refuses, and MustBeAuthoritative reports CLOSURE_TRUNCATED.",
		TestName:    "TestClosureTruncationIsIndeterminate",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-243", Edition: ConformanceAnyEdition,
		Title:       "An empty closure from a realm with no group graph is authoritative",
		SourceCases: []string{"EX-45"},
		Asserts:     "The state is read from the realm's declared directory source, so a cloud-IAM service account resolves to an authoritative empty set rather than being permanently indeterminate.",
		TestName:    "TestNoGraphRealmIsAuthoritativeEmpty",
		TestFile:    "directory_states_test.go",
	},
	{
		ID: "AXC-244", Edition: ConformanceAnyEdition,
		Title:       "A realm that declares a group graph never resolves to an authoritative empty set when the graph cannot be read",
		SourceCases: []string{"EX-14", "EX-45"},
		Asserts:     "An outage, a missing snapshot, and a build with no directory integration all produce UNREACHABLE, which is the direction EX-45 and the SCIM-outage rule must not share.",
		TestName:    "TestGraphRealmOutageIsUnreachableNotEmpty",
		TestFile:    "directory_states_test.go",
	},
	{
		ID: "AXC-245", Edition: ConformanceEnterpriseOnly,
		Title:       "Truncation is reported from unfinished work, not from the loop counter",
		SourceCases: []string{"EX-14"},
		Asserts:     "A graph whose deepest group sits exactly at MaxDepth resolves as authoritative; the source specification's depth > MAX_DEPTH formula would report it truncated, and the test pins the difference.",
		TestName:    "TestClosureDoesNotReportTruncationWhenTheGraphEndsAtTheBound",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-246", Edition: ConformanceEnterpriseOnly,
		Title:       "Every resolved group carries a shortest witness path",
		SourceCases: []string{"EX-12"},
		Asserts:     "Breadth-first traversal records the shortest route from the subject to each group, and depth plays no part in the decision, only in the explanation.",
		TestName:    "TestClosureEmitsShortestWitnessPaths",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-247", Edition: ConformanceAnyEdition,
		Title:    "The zero ClosureState and the zero ClosureResult are not authoritative",
		Asserts:  "An unpopulated result reports Indeterminate through MustBeAuthoritative and yields no group set, so a forgotten assignment cannot read as no memberships.",
		TestName: "TestZeroClosureResultIsNotAuthoritative",
		TestFile: "directory_states_test.go",
	},
	{
		ID: "AXC-248", Edition: ConformanceEnterpriseOnly,
		Title:    "A closure is refused when the subject's realm is not the realm the closure was requested against",
		Asserts:  "Resolving a subject from one realm against another realm's graph reports UNREACHABLE rather than an empty set from the wrong directory.",
		TestName: "TestClosureRefusesRealmMismatch",
		TestFile: "directory_closure_test.go",
	},

	// SCIM ingestion.
	{
		ID: "AXC-249", Edition: ConformanceAnyEdition,
		Title:       "A closure renders as the PDP's tri-state attribute, with an outage and a bound carrying different reasons",
		SourceCases: []string{"EX-14", "EX-45"},
		Asserts:     "Authoritative and no-graph render as a known group array, truncated and unreachable as unknown with distinct reasons, and the zero result as unknown rather than known-empty.",
		TestName:    "TestGroupsAttributeIsTheTriStateThePDPConsumes",
		TestFile:    "directory_states_test.go",
	},
	{
		ID: "AXC-264", Edition: ConformanceAnyEdition,
		Title:       "A zero or underspecified TrustRealm never produces an authoritative closure",
		SourceCases: []string{"EX-47", "EX-45"},
		Asserts:     "A realm-registry lookup MISS returns a zero TrustRealm whose DirectorySource is Unspecified; every resolver refuses it as unreachable rather than reading it as a realm with no group graph, which would be EX-47 reached through the resolver instead of the credential.",
		TestName:    "TestAZeroRealmNeverProducesAnAuthoritativeClosure",
		TestFile:    "directory_states_test.go",
	},
	{
		ID: "AXC-265", Edition: ConformanceEnterpriseOnly,
		Title:       "A subject with more direct memberships than the fan-out bound truncates",
		SourceCases: []string{"EX-14"},
		Asserts:     "The clamp on the subject's own expansion sets truncation, so a subject in more groups than MaxFanOut does not silently lose groups and read as authoritative; exactly at the bound is not truncated.",
		TestName:    "TestClosureTruncatesOnSubjectLevelFanOut",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-266", Edition: ConformanceEnterpriseOnly,
		Title:       "A cycle lying off every witness path is still alarmed",
		SourceCases: []string{"EX-13"},
		Asserts:     "A completeness pass over the resolved subgraph finds cycles whose members are all reachable by shorter routes than the loop, while a diamond and an acyclic graph still raise nothing.",
		TestName:    "TestClosureAlarmsACycleThatLiesOffEveryWitnessPath",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-267", Edition: ConformanceEnterpriseOnly,
		Title:    "A group re-queued across levels appears in the closure exactly once",
		Asserts:  "The visited filter is load-bearing when a node is in the frontier AND a parent of an earlier node in that same frontier; without it the closure duplicates and the reported depth inflates.",
		TestName: "TestClosureDoesNotDuplicateAcrossLevels",
		TestFile: "directory_closure_test.go",
	},
	{
		ID: "AXC-268", Edition: ConformanceEnterpriseOnly,
		Title:    "A re-asserted membership does not count twice toward the fan-out bound",
		Asserts:  "Adjacency is de-duplicated at load, so a provider re-stating one membership cannot trip a spurious truncation, while distinct memberships past the bound still do.",
		TestName: "TestDuplicateAdjacencyDoesNotInflateFanOut",
		TestFile: "directory_closure_test.go",
	},
	{
		ID: "AXC-274", Edition: ConformanceEnterpriseOnly,
		Title:       "The exported graph closure guards itself against a subject from another realm",
		SourceCases: []string{"EX-47"},
		Asserts:     "DirectoryGraph.Closure refuses an out-of-realm subject rather than resolving it to an authoritative empty set, while an in-realm subject the graph does not contain still resolves authoritatively empty.",
		TestName:    "TestGraphClosureGuardsItselfAgainstAForeignSubject",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-275", Edition: ConformanceEnterpriseOnly,
		Title:       "Loop detection names every group on a loop, deterministically, bounded by the closure",
		SourceCases: []string{"EX-13"},
		Asserts:     "Strongly connected components are reported, so two loops sharing an edge and twenty loops through one node name all their groups; a diamond and an acyclic graph stay quiet; groups outside the resolved subgraph are never named; and the rendered warnings are identical across runs.",
		TestName:    "TestLoopDetectionNamesEveryGroupOnALoop",
		TestFile:    "directory_closure_test.go",
	},
	{
		ID: "AXC-276", Edition: ConformanceEnterpriseOnly,
		Title:    "A directory entity must declare a recognized entity type",
		Asserts:  "The zero and any unrecognized DirectoryEntityType is refused at load, rather than being admitted with its group-versus-subject consistency unexamined.",
		TestName: "TestEntityTypeMustBeADeclaredValue",
		TestFile: "directory_closure_test.go",
	},
	{
		ID: "AXC-250", Edition: ConformanceEnterpriseOnly,
		Title:    "Provider nesting support is declared, never inferred",
		Asserts:  "Ingestion and graph loading both refuse an undeclared nesting capability, and neither default is chosen silently.",
		TestName: "TestSCIMIngestRefusesUndeclaredNesting",
		TestFile: "directory_scim_test.go",
	},
	{
		ID: "AXC-251", Edition: ConformanceEnterpriseOnly,
		Title:    "A provider that does not define nesting cannot have nesting inferred on its behalf",
		Asserts:  "A group-in-group member from a provider declaring no nesting is refused as a capability-versus-data disagreement rather than resolved either way.",
		TestName: "TestSCIMIngestRefusesNestedMembershipFromANonNestingProvider",
		TestFile: "directory_scim_test.go",
	},
	{
		ID: "AXC-252", Edition: ConformanceEnterpriseOnly,
		Title:    "Canonical identifiers come from the provider id, never from an email or display name",
		Asserts:  "Two users sharing an email map to different principals, and a group's canonical id is its provider id while its display name is only an attribute.",
		TestName: "TestSCIMIngestUsesProviderIDsNotAliases",
		TestFile: "directory_scim_test.go",
	},
	{
		ID: "AXC-253", Edition: ConformanceEnterpriseOnly,
		Title:    "A deactivated directory user contributes no memberships but still resolves authoritatively",
		Asserts:  "The entity is emitted with active=false and its edges are dropped, so the closure is an authoritative empty set rather than an unknown subject.",
		TestName: "TestSCIMIngestDropsDeactivatedUserEdges",
		TestFile: "directory_scim_test.go",
	},
	{
		ID: "AXC-254", Edition: ConformanceEnterpriseOnly,
		Title:    "Membership disagreement between the two provider views is reported in both directions",
		Asserts:  "A membership on the user resource only and one on the group resource only are both reported, and the declared policy decides whether the export is refused.",
		TestName: "TestSCIMIngestReportsMembershipDisagreement",
		TestFile: "directory_scim_test.go",
	},
	{
		ID: "AXC-255", Edition: ConformanceEnterpriseOnly,
		Title:    "Cross-realm and orphan edges are quarantined and never traversed",
		Asserts:  "The loader records both classes with a reason rather than dropping them silently, and neither contributes to a closure.",
		TestName: "TestGraphQuarantinesCrossRealmAndOrphanEdges",
		TestFile: "directory_closure_test.go",
	},
	{
		ID: "AXC-256", Edition: ConformanceAnyEdition,
		Title:    "An attribute with no declared maximum age is not a usable policy input",
		Asserts:  "Freshness is a tri-state; undeclared is not fresh, and a stale attribute is unknown rather than its last known value.",
		TestName: "TestAttributeFreshnessIsTriState",
		TestFile: "directory_states_test.go",
	},

	// Graph deletion and invalidation (ADR-065 acceptance gate 7, #3689).
	//
	// Every other graph case closes over ONE snapshot. These three are about
	// the difference between two, which is where a deletion and an
	// invalidation live and where both fail in the direction that grants
	// access. AXC-253 covers DEACTIVATION, which is not deletion: a
	// deactivated entity is still in the export.
	{
		ID: "AXC-257", Edition: ConformanceEnterpriseOnly,
		Title:    "A group deleted from the directory leaves no decision reachable through it",
		Asserts:  "After a re-export without the group, the closure drops it and a permission scoped to it no longer permits; a PARTIAL export that deletes the entity and leaves its membership row quarantines the orphan edge, reports it, and still does not resolve the deleted group back in.",
		TestName: "TestDeletingAGroupLeavesNoDecisionReachableThroughIt",
		TestFile: "directory_deletion_test.go",
	},
	{
		ID: "AXC-258", Edition: ConformanceEnterpriseOnly,
		Title:    "A revoked membership drops exactly the ancestors that edge reached",
		Asserts:  "Both failure directions are asserted in one closure: an ancestor reachable only through the revoked edge must go (under-propagation is fail-open), and an ancestor a surviving edge still reaches must stay (over-propagation breaks access nobody changed).",
		TestName: "TestDeletingOneMembershipEdgeDropsOnlyTheAncestorsItReached",
		TestFile: "directory_deletion_test.go",
	},
	{
		ID: "AXC-259", Edition: ConformanceEnterpriseOnly,
		Title:    "A new directory snapshot invalidates the one it replaces",
		Asserts:  "SetGraph replaces rather than installs-once; a resolution during an outage refuses even though the last good snapshot is retained; and recovery resumes on the CURRENT snapshot, not the retained one. SourceVersion is asserted at every step, because a group set alone cannot distinguish reading the new snapshot from reading a stale one that agrees.",
		TestName: "TestANewDirectorySnapshotInvalidatesTheOneItReplaces",
		TestFile: "directory_deletion_test.go",
	},

	{
		ID: "AXC-269", Edition: ConformanceEnterpriseOnly,
		Title:    "A self-inconsistent SCIM export is refused rather than resolved silently",
		Asserts:  "Duplicate user or group records, a malformed identifier in the read-only user view, and an undeclared user-groups view are each refused; a provider that declares the view absent is ingested with the scan skipped.",
		TestName: "TestSCIMIngestRefusesSelfInconsistentExports",
		TestFile: "directory_scim_test.go",
	},

	// Approver pools and realm interactivity.
	{
		ID: "AXC-260", Edition: ConformanceAnyEdition,
		Title:       "An approver pool in a non-interactive realm is refused at authoring time",
		SourceCases: []string{"EX-46"},
		Asserts:     "Validation names every offending member, so a policy naming a service-account pool never becomes a live escalation that parks until timeout.",
		TestName:    "TestApproverPoolValidationRefusesNonInteractiveRealms",
		TestFile:    "approver_realm_test.go",
	},
	{
		ID: "AXC-261", Edition: ConformanceAnyEdition,
		Title:       "At runtime a pool with no answerable member is ESCALATION_UNREACHABLE",
		SourceCases: []string{"EX-46"},
		Asserts:     "Eligibility is counted over interactive members only, so members that cannot answer never inflate the count; the same fact is re-checked at runtime because a realm can be reconfigured after a policy is saved.",
		TestName:    "TestInteractiveMembersCollapsesAnUnanswerablePool",
		TestFile:    "approver_realm_test.go",
	},
	{
		ID: "AXC-262", Edition: ConformanceAnyEdition,
		Title:    "Separation of duties excludes every member of the requesting chain, not only its root",
		Asserts:  "An approver appearing anywhere in the actor chain is excluded, and a pool emptied by exclusion is distinguishable from one emptied by an unanswerable realm.",
		TestName: "TestEligibleApproversExcludeTheWholeChain",
		TestFile: "approver_realm_test.go",
	},
	{
		ID: "AXC-270", Edition: ConformanceAnyEdition,
		Title:       "An admission about an approver pool names no principal",
		SourceCases: []string{"EX-46"},
		Asserts:     "Pool admissions carry the zero principal rather than an arbitrary member, so a consumer cannot attribute a record to a principal that self-exclusion removed from the returned set.",
		TestName:    "TestPoolAdmissionsNameNoPrincipal",
		TestFile:    "approver_realm_test.go",
	},
	{
		ID: "AXC-271", Edition: ConformanceAnyEdition,
		Title:       "An unanswerable pool is reported before a malformed quorum, never masked by it",
		SourceCases: []string{"EX-46"},
		Asserts:     "The pool is examined before the quorum, so a pool nobody can answer reports ESCALATION_UNREACHABLE at every quorum including zero, while a malformed quorum on an answerable pool still gets its own refusal.",
		TestName:    "TestUnanswerablePoolIsNeverMaskedByAMalformedQuorum",
		TestFile:    "approver_quorum_test.go",
	},
	{
		ID: "AXC-263", Edition: ConformanceAnyEdition,
		Title:       "An unanswerable pool and an under-quorum one are separate terminal outcomes",
		SourceCases: []string{"EX-46"},
		Asserts:     "ESCALATION_UNREACHABLE and QUORUM_UNREACHABLE are distinct codes because the remedies differ, a non-positive quorum is refused rather than trivially satisfied, and an unresolvable registry is indeterminate rather than a denial.",
		TestName:    "TestApproverQuorumSeparatesUnreachableFromUnderQuorum",
		TestFile:    "approver_quorum_test.go",
	},

	// Per-organization compatibility mode (#3550, session ADR65-I): the
	// release plan's "shadow enabled per org", composed INSIDE the single
	// mode read rather than beside it.
	{
		ID: "AXC-280", Edition: ConformanceAnyEdition,
		Title:    "The resolved mode is the organization's record when one exists, else the process flag, in every cell",
		Asserts:  "Across the full product of process mode {off, shadow, enforce} and record {absent, off, shadow, enforce}, the outcome's mode, evaluation, refusal and counterfactual all follow the record when present and the process flag when absent; a record wins in both the raising and the lowering direction.",
		TestName: "TestCompatOrgModeCompositionMatrix",
		TestFile: "compat_org_mode_test.go",
	},
	{
		ID: "AXC-281", Edition: ConformanceAnyEdition,
		Title:    "A per-organization record affects only that organization",
		Asserts:  "On a process-off deployment, an organization with a shadow record is evaluated and recorded while an organization with no record is not evaluated, not recorded and reports mode off - the absent-record leg is byte-identical to the process-wide behaviour.",
		TestName: "TestCompatOrgModeAppliesOnlyToTheRecordedOrganization",
		TestFile: "compat_org_mode_test.go",
	},
	{
		ID: "AXC-282", Edition: ConformanceAnyEdition,
		Title:    "The mode is consulted at exactly one site, with the organization's record as an input to it",
		Asserts:  "An AST census of every non-test file in the package, under both build tags, finds the process-mode field and the per-organization source read only inside effectiveMode (and the diagnostics accessor Mode); any other reader is named by file and line. The compatmutation harness plants a second reader to prove the census can fail.",
		TestName: "TestCompatModeIsConsultedAtExactlyOneSite",
		TestFile: "compat_org_mode_test.go",
	},
	{
		ID: "AXC-283", Edition: ConformanceAnyEdition,
		Title:    "An undeclared recorded mode is a read failure, never a mode",
		Asserts:  "A source answering with a value outside the declared modes (the zero value, 99, -1) is treated as a failed read: the process mode applies, nothing is evaluated or recorded, and the fall-back is counted. Membership, not inequality against the zero value.",
		TestName: "TestCompatOrgModeRefusesAnUndeclaredRecordedValue",
		TestFile: "compat_org_mode_test.go",
	},
	{
		ID: "AXC-284", Edition: ConformanceAnyEdition,
		Title:    "A record that cannot be read falls back to the deployment's declaration and is counted",
		Asserts:  "When the per-organization source errors, the process mode applies in both directions (a process-enforce deployment still enforces; a process-off one stays off) and OrgModeFailures increments, so an organization silently running in the process mode is visible.",
		TestName: "TestCompatOrgModeReadFailureFallsBackToTheProcessMode",
		TestFile: "compat_org_mode_test.go",
	},
	{
		ID: "AXC-285", Edition: ConformanceEnterpriseOnly,
		Title:    "The settings store serves the last successfully read row through an outage, never an absence",
		Asserts:  "After one successful read, a storage failure serves that row for both the mode and the CAEP opt-in, counts the failure, and memoizes it for the TTL; a failure with no prior read returns the error rather than presenting the outage as 'no record' or 'not opted in'.",
		TestName: "TestOrgSettingsStoreServesTheLastGoodRowThroughAnOutage",
		TestFile: "compat_org_settings_test.go",
	},

	// The Shared Signals / CAEP push receiver (#3550, session ADR65-I): the
	// endpoint that gives compat_caep.go's intake a transmitter, and HasCAEP
	// a setter.
	{
		ID: "AXC-286", Edition: ConformanceEnterpriseOnly,
		Title:       "A SET from an undeclared issuer is refused before any key is fetched",
		SourceCases: []string{"EX-47"},
		Asserts:     "A push whose iss resolves to no realm in the authenticated organization is refused as invalid_issuer with zero fetches of any key set and nothing invalidated: the undeclared issuer is refused for being undeclared, at zero cost, before signature verification.",
		TestName:    "TestCAEPPushUndeclaredIssuerIsRefusedBeforeAnyKeyIsFetched",
		TestFile:    "compat_caep_push_test.go",
	},
	{
		ID: "AXC-287", Edition: ConformanceEnterpriseOnly,
		Title:    "A SET must name the organization's configured receiver audience",
		Asserts:  "A validly signed SET whose aud does not name the organization's configured audience - another receiver's, an array without it, absent, malformed - is refused as invalid_audience; an array that names it is accepted.",
		TestName: "TestCAEPPushRefusesTheWrongAudience",
		TestFile: "compat_caep_push_test.go",
	},
	{
		ID: "AXC-288", Edition: ConformanceEnterpriseOnly,
		Title:    "A SET is verified against the realm's own key set",
		Asserts:  "A SET signed by a key outside the realm's JWKS is refused as invalid_key at the signature stage and invalidates nothing; the key set is the JWKS URI of the same SSO configuration the realm was derived from.",
		TestName: "TestCAEPPushRefusesABadSignature",
		TestFile: "compat_caep_push_test.go",
	},
	{
		ID: "AXC-289", Edition: ConformanceEnterpriseOnly,
		Title:    "A Shared Signals subject is a canonical principal or it is refused",
		Asserts:  "Only the iss_sub format (directly, or as a complex subject's user member) whose iss is the realm's own issuer becomes a principal; email, phone_number, opaque, a foreign iss_sub, an empty sub, a formatless object and a bare string are refused and invalidate nothing. ADR-065 invariant 3 at the endpoint.",
		TestName: "TestCAEPPushRefusesAnAliasSubject",
		TestFile: "compat_caep_push_test.go",
	},
	{
		ID: "AXC-290", Edition: ConformanceEnterpriseOnly,
		Title:    "A failed invalidation is not acknowledged",
		Asserts:  "A valid SET whose invalidation hook fails is answered 503 temporarily_unavailable (retryable), its jti is not remembered, and the redelivery after the hook recovers is applied rather than deduplicated away.",
		TestName: "TestCAEPPushFailedInvalidationIsNotAcknowledged",
		TestFile: "compat_caep_push_test.go",
	},
	{
		ID: "AXC-291", Edition: ConformanceEnterpriseOnly,
		Title:    "A realm that has not opted into Shared Signals receives nothing",
		Asserts:  "A validly signed SET for a declared realm whose revocation source is not shared signals is refused as access_denied without any key fetch or invalidation; HasCAEP is per organization and comes from the settings row, not from code.",
		TestName: "TestCAEPPushRefusesARealmThatDidNotOptIn",
		TestFile: "compat_caep_push_test.go",
	},
	{
		ID: "AXC-292", Edition: ConformanceEnterpriseOnly,
		Title:    "A push affects only the organization the caller authenticated as",
		Asserts:  "The same perfectly signed SET delivered under another organization's credential is refused (its issuer is undeclared there), and a push with no authenticated organization is refused as access_denied; the SET's own claims name no tenant and are never consulted for one.",
		TestName: "TestCAEPPushIsScopedToTheAuthenticatedOrganization",
		TestFile: "compat_caep_push_test.go",
	},
	{
		ID: "AXC-293", Edition: ConformanceEnterpriseOnly,
		Title:    "A redelivered SET is acknowledged without being re-applied",
		Asserts:  "The jti is remembered inside a bounded window: a second delivery of the same SET is 202 and invalidates nothing further, a different jti for the same subject is applied, and a SET with no jti is refused.",
		TestName: "TestCAEPPushRedeliveryIsAcknowledgedWithoutReapplying",
		TestFile: "compat_caep_push_test.go",
	},

	// The outage-wording gate's ARGUMENT (#3596 R3, finding 1). The gate
	// itself is one line; what these cases pin is that it is asked about the
	// REQUEST'S organization at every caller, which is what makes a
	// per-organization shadow legible to an operator instead of reading as a
	// deployment-wide forgery.
	{
		ID: "AXC-294", Edition: ConformanceEnterpriseOnly,
		Title:    "The outage-wording gate is resolved per organization, not from the process flag",
		Asserts:  "On one adapter whose process mode disagrees with an organization's record, outageSentinelsActive answers differently for the recorded organization and for one with no record, in both the raising and the lowering direction; the key is trimmed as the adapter trims it, and an uninstalled adapter is off for every organization.",
		TestName: "TestOutageSentinelsAreResolvedPerOrganization",
		TestFile: "compat_org_mode_gate_test.go",
	},
	{
		ID: "AXC-295", Edition: ConformanceEnterpriseOnly,
		Title:    "The OIDC verifier asks the gate about the request's organization",
		Asserts:  "Driven through oidcVerifier.Validate with a process-off adapter and one organization recorded shadow, an unreachable JWKS wraps ErrJWKSUnavailable for the recorded organization and keeps main's ErrTokenInvalid wrap for one with no record - so neither a constant argument nor an empty one can produce both answers.",
		TestName: "TestOIDCVerifierOutageWordingIsResolvedPerOrganization",
		TestFile: "compat_org_mode_gate_test.go",
	},
	{
		ID: "AXC-296", Edition: ConformanceEnterpriseOnly,
		Title:    "The HS256 validator asks the gate about the request's organization",
		Asserts:  "Driven through ResolveToken on the revocation-outage leg with a process-off adapter and one organization recorded shadow, the recorded organization's 401 carries the reclassification while the unrecorded organization's body is main's bytes.",
		TestName: "TestHS256OutageWordingIsResolvedPerOrganization",
		TestFile: "compat_org_mode_gate_test.go",
	},

	// The two Shared Signals refusal stages that no test and no mutant
	// reached (#3596 R3, finding 2).
	{
		ID: "AXC-297", Edition: ConformanceEnterpriseOnly,
		Title:    "A disabled realm receives no Shared Signals events",
		Asserts:  "A validly signed SET whose issuer resolves to a DISABLED realm is refused as invalid_issuer at the realm_disabled stage, before any key set is fetched and with nothing invalidated; disabling a realm withdraws its event stream rather than only its authentication.",
		TestName: "TestCAEPPushRefusesADisabledRealm",
		TestFile: "compat_caep_push_test.go",
	},
	{
		ID: "AXC-298", Edition: ConformanceEnterpriseOnly,
		Title:    "A realm source that cannot answer is an outage, never an undeclared issuer",
		Asserts:  "When EnsureRealms fails, the push is refused 503 temporarily_unavailable at the realms_unavailable stage so the transmitter redelivers; presenting it as a terminal 400 invalid_issuer would drop every revocation delivered during the outage permanently.",
		TestName: "TestCAEPPushRealmSourceOutageIsRetryable",
		TestFile: "compat_caep_push_test.go",
	},
}

// IdentityConformanceCases returns the identity-plane conformance corpus.
//
// The disposition ledger's coverage_case_ids column cites these IDs. Returned
// as a copy so a consumer cannot mutate the corpus.
func IdentityConformanceCases() []ConformanceCase {
	out := make([]ConformanceCase, len(identityConformanceCases))
	copy(out, identityConformanceCases)
	return out
}

// CoverageBySourceCase maps each source-specification case to the identity
// conformance case IDs covering it, sorted.
//
// This is the exact input for the ledger's coverage_case_ids cells, so the
// values a reviewer checks against the TSV are computed from the corpus rather
// than transcribed by hand.
func CoverageBySourceCase() map[string][]string {
	out := make(map[string][]string)
	for _, c := range identityConformanceCases {
		for _, src := range c.SourceCases {
			out[src] = append(out[src], c.ID)
		}
	}
	for src := range out {
		sort.Strings(out[src])
	}
	return out
}

// conformanceMarks records which cases actually executed in this test binary.
var conformanceMarks = struct {
	mu     sync.Mutex
	marked map[string]bool
}{marked: make(map[string]bool)}

// MarkConformanceCase records that the named conformance case executed.
//
// Exported because it is called from _test.go files in this package, and Go
// test files can call unexported identifiers, but keeping it exported
// documents it as part of the corpus contract rather than an internal detail.
// It panics on an unknown ID: a test citing a case that is not in the corpus is
// claiming coverage that the ledger cannot see.
func MarkConformanceCase(id string) {
	known := false
	for _, c := range identityConformanceCases {
		if c.ID == id {
			known = true
			break
		}
	}
	if !known {
		panic(fmt.Sprintf("identity: conformance case %q is not in the corpus", id))
	}
	conformanceMarks.mu.Lock()
	defer conformanceMarks.mu.Unlock()
	conformanceMarks.marked[id] = true
}

// UnmarkedConformanceCases returns the cases applicable to this build that no
// test marked, sorted. enterpriseBuild says which edition is running.
func UnmarkedConformanceCases(enterpriseBuild bool) []string {
	conformanceMarks.mu.Lock()
	defer conformanceMarks.mu.Unlock()
	var out []string
	for _, c := range identityConformanceCases {
		if c.Edition == ConformanceEnterpriseOnly && !enterpriseBuild {
			continue
		}
		if !conformanceMarks.marked[c.ID] {
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

// ConformanceCorpusSummary renders the corpus for a PR body or an operator
// report: one line per case, stable order.
func ConformanceCorpusSummary() string {
	var b strings.Builder
	for _, c := range identityConformanceCases {
		src := "-"
		if len(c.SourceCases) > 0 {
			src = strings.Join(c.SourceCases, ",")
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", c.ID, src, c.Edition, c.Title)
	}
	return b.String()
}
