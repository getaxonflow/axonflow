// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"strings"
	"testing"
)

// licenceGranting registers a LicenseTierSource answering tier for the rest of
// the test, so a case can vary the LICENCE axis independently of the mode.
//
// Until #3709 row 1 this helper built an UNSIGNED key that the package's own
// payload parser accepted - which was the defect, not a test convenience. The
// package no longer reads AXONFLOW_LICENSE_KEY at all; it asks the registered
// verified source, and the source is what a test now controls. What "verified"
// means is pinned where the real source is registered:
// platform/agent/license_tier_source_test.go drives the real validator with a
// forged, an expired and a valid key.
func licenceGranting(t *testing.T, tier string) {
	t.Helper()
	SetLicenseTierSource(func(context.Context) string { return tier })
	t.Cleanup(func() { SetLicenseTierSource(nil) })
}

// setDeployment sets both inputs for one case.
//
// DEPLOYMENT_MODE="" models UNSET exactly: os.Getenv returns "" for both, so
// the code under test cannot distinguish them and neither can this test. That
// equivalence is the same one infrastructure/cloudformation states in its own
// comment on the variable.
func setDeployment(t *testing.T, mode, licenceTier string) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", mode)
	// The environment variable is set too, so a parser of the key returning
	// to this package would be reading a value that DISAGREES with the source
	// and the relevant test reds; the source is what decides.
	t.Setenv("AXONFLOW_LICENSE_KEY", "")
	licenceGranting(t, licenceTier)
}

// TestResolveConnectorLimitTierByDeploymentMode pins all four input classes of
// #3713, with no licence key, so each row measures the DEPLOYMENT_MODE axis
// alone.
//
// Every row marked "#3713" returned "enterprise" - unlimited custom-policy
// connectors - before the fix, and fails on the pre-fix classifier. The
// enterprise rows are the unchanged control: a fix that narrowed those would be
// revoking limits customers pay for, and this table is what says it did not.
func TestResolveConnectorLimitTierByDeploymentMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		// 1. The community mode. Unchanged by #3713.
		{"community", "community", "community"},

		// 2. Unset. Unchanged by #3713 - it was already on the community side
		//    here, which is itself the opposite of what isCommunityMode does
		//    with an unset value (#3128). Pinned so the fix provably did not
		//    move it while consolidating onto deploymode.
		{"unset", "", "community"},

		// 3. The two modes #3713 is about. Both are non-paying deployments
		//    that drew the Enterprise limit purely because their names are not
		//    the string "community".
		{"community-saas #3713 was enterprise", "community-saas", "community"},
		{"evaluation #3713 was enterprise", "evaluation", "community"},

		// 4. Unrecognised values. Before the fix a typo in DEPLOYMENT_MODE was
		//    worth a purchased Enterprise licence. Note "Community" and
		//    " community": deploymode.Resolve is exact by design, so these are
		//    unrecognised rather than community, and the fail-closed direction
		//    is what makes that safe.
		{"unrecognised typo #3713 was enterprise", "comunity", "community"},
		{"unrecognised case #3713 was enterprise", "Community", "community"},
		{"unrecognised space #3713 was enterprise", " community", "community"},
		{"unrecognised plausible #3713 was enterprise", "saas-eu", "community"},

		// 5. Genuinely Enterprise-entitled deployments, including both
		//    aliases. Unchanged, and the control for the rows above.
		{"saas", "saas", "enterprise"},
		{"in-vpc-enterprise", "in-vpc-enterprise", "enterprise"},
		{"in-vpc-banking", "in-vpc-banking", "enterprise"},
		{"in-vpc-healthcare", "in-vpc-healthcare", "enterprise"},
		{"in-vpc-travel", "in-vpc-travel", "enterprise"},
		{"alias enterprise", "enterprise", "enterprise"},
		{"alias invpc", "invpc", "enterprise"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setDeployment(t, tt.mode, "")
			if got := resolveConnectorLimitTier(); got != tt.want {
				t.Errorf("resolveConnectorLimitTier() with DEPLOYMENT_MODE=%q = %q, want %q",
					tt.mode, got, tt.want)
			}
		})
	}
}

// TestResolveConnectorLimitTierLicenceKeyPathUnchanged pins the half of the
// classifier #3713 did NOT touch.
//
// The fix changes which deployments REACH the licence key, not what it decides
// once reached. SIX of these EIGHT rows already passed before the fix; TWO
// changed - community-saas and evaluation - and both changed from "never
// consults the licence key" to "consults it like every other non-Enterprise
// deployment". (Round 1 corrected this count from a wrong "three of seven" and
// made it stale in the same commit by adding the eighth row. Measured against
// the pre-fix classifier on the final tree: 2 of 8 fail.)
func TestResolveConnectorLimitTierLicenceKeyPathUnchanged(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		licence string
		want    string
	}{
		{"enterprise licence in community mode", "community", "Enterprise", "enterprise"},
		{"evaluation licence in community mode", "community", "Evaluation", "evaluation"},
		{"tier is lower-cased", "community", "PLUS", "plus"},

		// A key the verifier refuses grants NOTHING, and the source says so
		// with "". Until #3709 row 1 an unparseable key fell back to
		// "evaluation" - five connectors for a malformed string - and #3749
		// pinned that as a pre-existing widening it did not alter. It is
		// altered now: the free Evaluation tier is granted by a signed
		// Evaluation licence, not by a key that fails to parse.
		{"a refused key grants nothing", "community", "", "community"},

		// An Enterprise-entitled mode returns before the source is asked,
		// so a junk key cannot demote a paying deployment.
		{"enterprise mode ignores the licence axis", "saas", "", "enterprise"},

		// The row #3713 changed: community-saas now consults the key.
		{"community-saas now reaches the licence key", "community-saas", "Evaluation", "evaluation"},

		// THE HEADLINE ROW. Everything else in this PR is downstream of the
		// claim that the mode named `evaluation` can finally receive the
		// Evaluation tier, and until R3 round 1 nothing asserted it: the only
		// `evaluation` row anywhere carried NO licence key, where "community"
		// is the right answer both for "falls through to the licence key" and
		// for "hard-coded to community". It landed on the cheaper signal.
		// Planting `if deploymode.Current() == "evaluation" { return "community" }`
		// one frame later than the original defect left the whole suite AND
		// the lint green.
		{"evaluation mode reaches the Evaluation tier", "evaluation", "Evaluation", "evaluation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setDeployment(t, tt.mode, tt.licence)
			if got := resolveConnectorLimitTier(); got != tt.want {
				t.Errorf("resolveConnectorLimitTier() mode=%q = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

// TestTheMeasuredLiveFleetKeepsItsEntitlement encodes the fleet measurement
// that decided this change ships in v10.4.0 rather than behind a grace path.
//
// Measured 2026-09-04 against the live account, per RUNNING task definition:
// the community-SaaS agent runs DEPLOYMENT_MODE=community-saas and carries an
// AXONFLOW_LICENSE_KEY whose payload names tier "Enterprise". So the deployment
// this change moves off the mode-based Enterprise answer lands back on
// "enterprise" through the licence key, and its effective limit is unchanged.
//
// This is the honest statement of what the fix does and does not do: it does
// not revoke the live fleet's unlimited connectors. It changes them from
// granted because a string was not "community" - the same grant a typo received
// - to granted by a licence key naming a tier.
//
// State that precisely and no further. Until #3709 row 1 this path did NOT
// verify the key - the payload's `tier` was read with no signature check and
// no expiry check - so an EXPIRED or REVOKED Enterprise key kept answering
// "enterprise" here. It is verified now: the tier comes from the registered
// license.GetCurrentTier, and the live community-SaaS key was re-measured on
// 2026-09-04 through the repo's own validator (keygen -validate): Valid,
// Enterprise, expires 2027-05-21. So the fleet lands on "enterprise" through
// the VERIFIED read, and this test models that with a source granting
// Enterprise.
//
// # THIS TEST PASSES ON BOTH SIDES OF THE FIX, AND THAT IS ITS JOB
//
// Measured: it passes against the pre-fix classifier too. It is an INVARIANCE
// pin, not a fix-detector - the fix-detectors are the two tables above. A day
// when this one fails on the pre-fix tree is a day the change has altered a
// running deployment's entitlement, which is the outcome the whole measurement
// exists to prevent.
func TestTheMeasuredLiveFleetKeepsItsEntitlement(t *testing.T) {
	setDeployment(t, "community-saas", "Enterprise")
	if got := resolveConnectorLimitTier(); got != "enterprise" {
		t.Fatalf("resolveConnectorLimitTier() = %q, want enterprise.\n"+
			"The live community-SaaS fleet holds an Enterprise-tier licence key; if this "+
			"returns anything else, shipping this change narrows a running deployment's "+
			"entitlement and the PR body's safety argument no longer holds.", got)
	}
}

// TestEnforceCustomPolicyConnectorLimitTruncatesCommunitySaas is the call site,
// not the predicate.
//
// resolveConnectorLimitTier is package-private and returns a string; what
// reaches an operator is a silently shortened connector list. This test proves
// the classifier change actually arrives at the truncation, which is the
// consequence the fleet measurement was about - and it is the test that fails
// loudly if someone ever "fixes" the tier without checking what consumes it.
func TestEnforceCustomPolicyConnectorLimitTruncatesCommunitySaas(t *testing.T) {
	setDeployment(t, "community-saas", "")

	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = []string{"postgres", "mysql", "redis", "snowflake"}

	got := EnforceCustomPolicyConnectorLimit(config)

	// MaxCustomPolicyConnectorsCommunity, read from the config rather than
	// spelled as 2, so this asserts the limit that is in force rather than a
	// constant copied from it.
	want := config.MaxCustomPolicyConnectorsCommunity
	// SHAPE GUARD FIRST, then the assertion.
	//
	// `len(got) == want` alone is satisfied BOTH by "truncated to the ceiling"
	// and by "returned unchanged because the input was already at or under it",
	// so it cannot tell a working ceiling from one that never fires. Round 1
	// fixed that by ALSO requiring `len(got) < len(input)` - and R3 round 2
	// showed that form reds a CORRECT implementation the moment the fixture
	// sits exactly at the ceiling, with a diagnosis ("want N AND fewer than N")
	// that cannot be satisfied. The input's shape is a property of the TEST, so
	// it is asserted as a test bug up front, and the outcome is then a plain
	// equality.
	if len(config.EnabledConnectors) <= want {
		t.Fatalf("test bug: the fixture has %d connectors and the ceiling is %d, so a "+
			"correct implementation truncates nothing and this test asserts nothing",
			len(config.EnabledConnectors), want)
	}
	if len(got) != want {
		t.Fatalf("EnforceCustomPolicyConnectorLimit() kept %d connectors (%v), want %d of %d.\n"+
			"Before #3713 community-saas resolved to the enterprise tier and all %d were kept.",
			len(got), got, want, len(config.EnabledConnectors), len(config.EnabledConnectors))
	}
	if len(got) < 2 || got[0] != "postgres" || got[1] != "mysql" {
		t.Errorf("truncation is not FIFO over MCP_DYNAMIC_POLICIES_CONNECTORS: got %v", got)
	}

	// The same input under an Enterprise-entitled mode keeps everything. Without
	// this arm the assertion above would also pass for a function that always
	// truncated, whatever the mode.
	setDeployment(t, "saas", "")
	if all := EnforceCustomPolicyConnectorLimit(config); len(all) != len(config.EnabledConnectors) {
		t.Errorf("EnforceCustomPolicyConnectorLimit() under DEPLOYMENT_MODE=saas kept %d of %d; "+
			"an Enterprise deployment must be unlimited", len(all), len(config.EnabledConnectors))
	}
}

// TestTheMeasuredLiveFleetShapeTruncatesNothing is the second, independent
// reason this change is safe to ship, and it is independent of the licence key.
//
// Measured 2026-09-04: MCP_DYNAMIC_POLICIES_CONNECTORS is empty on every
// running task in the account, on both the community-SaaS and production-US
// stacks - it is not set from `secrets` or `environmentFiles` either, and
// NewDynamicPolicyEvaluatorFromEnv is the only writer of EnabledConnectors. An
// empty list means len(EnabledConnectors) > limit is 0 > 2, so no tier can
// truncate anything. Even if the licence key were downgraded tomorrow, this
// deployment shape loses nothing.
//
// The first two assertions are an INVARIANCE pin: they pass on both sides of
// the fix, which is what they are for. On their own they would also be close to
// vacuous - "an empty list came back empty" is true of almost any
// implementation, including one with no connector limit at all - so the ARMED
// arm below establishes that the limit really is in force for this exact tier
// and mode, and that emptiness is therefore what spares the fleet rather than a
// limit that could never fire.
//
// Measured: the ARMED arm makes this test as a whole FAIL on the pre-fix
// classifier, because community-saas resolved to the enterprise tier and
// nothing truncated. So it is both anti-vacuity cover for the invariance and a
// fix-detector in its own right.
func TestTheMeasuredLiveFleetShapeTruncatesNothing(t *testing.T) {
	setDeployment(t, "community-saas", "")

	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = nil // as measured on every running task

	if got := EnforceCustomPolicyConnectorLimit(config); len(got) != 0 {
		t.Fatalf("EnforceCustomPolicyConnectorLimit() = %v on the measured live shape, want empty", got)
	}
	if err := ValidateCustomPolicyConnectorLimit(config); err != nil {
		t.Fatalf("ValidateCustomPolicyConnectorLimit() = %v on the measured live shape, want nil; "+
			"UpdateConfig would start refusing configuration on the live fleet", err)
	}

	// ARMED: the same tier and mode, one connector over the limit, must
	// truncate. Without this, the assertions above would pass identically for a
	// build in which the connector limit had been removed altogether - and the
	// conclusion "the live fleet is safe because its list is empty" would be
	// resting on a limit that could not fire for any list.
	armed := config
	armed.EnabledConnectors = []string{"a", "b", "c"}
	if len(armed.EnabledConnectors) <= armed.MaxCustomPolicyConnectorsCommunity {
		t.Fatalf("test bug: the armed fixture has %d connectors and the ceiling is %d, so it "+
			"cannot demonstrate that the ceiling fires",
			len(armed.EnabledConnectors), armed.MaxCustomPolicyConnectorsCommunity)
	}
	if got := EnforceCustomPolicyConnectorLimit(armed); len(got) != armed.MaxCustomPolicyConnectorsCommunity {
		t.Fatalf("the community limit is not armed under DEPLOYMENT_MODE=community-saas: "+
			"%d connectors produced %d, want %d. The empty-list result above proves nothing "+
			"while this is true.", len(armed.EnabledConnectors), len(got),
			armed.MaxCustomPolicyConnectorsCommunity)
	}
}

// TestValidateCustomPolicyConnectorLimitRejectsCommunitySaasOverLimit covers
// the OTHER consumer of the classifier.
//
// EnforceCustomPolicyConnectorLimit truncates silently; this one returns an
// error, and it is reached from UpdateConfig. A change to the classifier moves
// both, so both are pinned - fixing one and assuming the other followed is the
// shape that leaves half a behaviour change untested.
func TestValidateCustomPolicyConnectorLimitRejectsCommunitySaasOverLimit(t *testing.T) {
	setDeployment(t, "community-saas", "")

	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = []string{"postgres", "mysql", "redis"}

	err := ValidateCustomPolicyConnectorLimit(config)
	if err == nil {
		t.Fatal("ValidateCustomPolicyConnectorLimit() = nil for 3 connectors under " +
			"DEPLOYMENT_MODE=community-saas; before #3713 that mode resolved to the " +
			"enterprise tier and returned nil unconditionally")
	}
	if !strings.Contains(err.Error(), "community") {
		t.Errorf("error names the wrong tier, so an operator is told to fix the wrong thing: %v", err)
	}

	setDeployment(t, "saas", "")
	if err := ValidateCustomPolicyConnectorLimit(config); err != nil {
		t.Errorf("ValidateCustomPolicyConnectorLimit() = %v under DEPLOYMENT_MODE=saas; "+
			"an Enterprise deployment must be unlimited", err)
	}
}

// TestUnrecognisedModeCannotBuyTheEnterpriseLimit is the fail-closed direction
// carried all the way to the consumer.
//
// The predicate-level row is in TestResolveConnectorLimitTierByDeploymentMode.
// This one exists because the direction that matters is not "the string
// changed" but "a misspelled environment variable no longer hands out an
// unlimited paid entitlement", and only the consumer can say that.
func TestUnrecognisedModeCannotBuyTheEnterpriseLimit(t *testing.T) {
	setDeployment(t, "in-vpc-enterprsie", "") // transposed, as a typo actually looks

	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = []string{"postgres", "mysql", "redis", "snowflake"}

	if len(config.EnabledConnectors) <= config.MaxCustomPolicyConnectorsCommunity {
		t.Fatalf("test bug: fixture of %d is not over the ceiling of %d",
			len(config.EnabledConnectors), config.MaxCustomPolicyConnectorsCommunity)
	}
	got := EnforceCustomPolicyConnectorLimit(config)
	if len(got) != config.MaxCustomPolicyConnectorsCommunity {
		t.Fatalf("a typo in DEPLOYMENT_MODE kept %d of %d connectors, want %d; "+
			"an unvalidated string is still worth a purchased licence",
			len(got), len(config.EnabledConnectors), config.MaxCustomPolicyConnectorsCommunity)
	}
}

// TestPaidTiersAreNotHeldToTheCommunityCeiling is R3 round 1's HIGH finding.
//
// resolveConnectorLimitTier lower-cases whatever the licence payload names, and
// license.TierProfessional / TierEnterprisePlus are the strings "Professional"
// and "Plus". Neither was a case in the two switches that applied the ceiling,
// so both fell into `default` - the COMMUNITY limit of 2 - while
// license.GetTierLimits, the authority, maps all three paid tiers onto
// EnterpriseLimits with CustomPolicyConnectors = -1.
//
// This was latent before #3713 because only `community` and unset reached the
// licence-key path at all. #3713 routes community-saas, evaluation and every
// unrecognised mode onto it too, so the fix ARMED it: a paying Professional
// deployment whose DEPLOYMENT_MODE had a capital letter would have gone from
// unlimited to 2 connectors, truncated SILENTLY. A change that narrows an
// entitlement has to enumerate who it narrows.
func TestPaidTiersAreNotHeldToTheCommunityCeiling(t *testing.T) {
	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = []string{"a", "b", "c", "d", "e", "f"}

	for _, tier := range []string{"Enterprise", "Professional", "Plus"} {
		t.Run(tier, func(t *testing.T) {
			setDeployment(t, "community-saas", tier)
			got := EnforceCustomPolicyConnectorLimit(config)
			if len(got) != len(config.EnabledConnectors) {
				t.Errorf("a %s licence kept %d of %d connectors; license.GetTierLimits maps "+
					"TierProfessional, TierEnterprise and TierEnterprisePlus alike onto "+
					"EnterpriseLimits (CustomPolicyConnectors = -1), so holding this tier to "+
					"the community ceiling truncates a paying deployment",
					tier, len(got), len(config.EnabledConnectors))
			}
			if err := ValidateCustomPolicyConnectorLimit(config); err != nil {
				t.Errorf("a %s licence was refused by the validating consumer: %v", tier, err)
			}
		})
	}

	// The control: an unrecognised tier still gets the community ceiling, so the
	// arms above are not passing because the ceiling stopped applying at all.
	t.Run("unrecognised tier still fails closed", func(t *testing.T) {
		setDeployment(t, "community-saas", "Platinum")
		if got := EnforceCustomPolicyConnectorLimit(config); len(got) != config.MaxCustomPolicyConnectorsCommunity {
			t.Errorf("an unrecognised tier kept %d connectors, want the community ceiling %d",
				len(got), config.MaxCustomPolicyConnectorsCommunity)
		}
	})
}

// TestOneTierMappingNotThree pins that the exported method and BOTH consumers
// cannot disagree.
//
// Before #3713 there were three mappings: the switch in
// ValidateCustomPolicyConnectorLimit, the byte-identical one in
// EnforceCustomPolicyConnectorLimit, and the exported
// CustomPolicyConnectorLimitForTier - which DISAGREED with both, reading `Plus`
// and `Professional` as unlimited where they fell through to 2. It had zero
// callers, so nothing surfaced the disagreement; "unreferenced" is not
// "harmless" when the next caller picks whichever copy they find first.
//
// # ROUND 1'S VERSION WAS A TAUTOLOGY ON ONE BRANCH
//
// It computed `want := kept` and only overwrote it when the exported value was
// -1 or below the fixture length - so any exported value at or above the
// fixture length compared `kept` against ITSELF. R3 round 2 planted a genuine
// re-split (the exported method returning 9 for `evaluation` while the
// consumers apply 5) and it SURVIVED on both build tags: an exported API
// advertising a HIGHER limit than is enforced, which is the exact scenario the
// doc above warns about. The expectation is now DERIVED from the exported value
// for every case, with no branch that compares an observation to itself.
func TestOneTierMappingNotThree(t *testing.T) {
	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = []string{"a", "b", "c", "d", "e", "f"}
	n := len(config.EnabledConnectors)

	for _, tier := range []string{"enterprise", "Enterprise", "professional", "Professional",
		"plus", "Plus", "evaluation", "Evaluation", "community", "Community", "nonsense"} {
		t.Run(tier, func(t *testing.T) {
			exported := config.CustomPolicyConnectorLimitForTier(tier)

			// What the consumers must keep, derived from the exported answer
			// alone. Unlimited and any non-positive limit mean no ceiling;
			// otherwise the ceiling truncates to it when the input exceeds it.
			want := n
			if exported > 0 && exported < n {
				want = exported
			}

			setDeployment(t, "community-saas", tier)
			if kept := len(EnforceCustomPolicyConnectorLimit(config)); kept != want {
				t.Errorf("tier %q: the exported mapping says %d, so the consumer should keep %d, "+
					"but EnforceCustomPolicyConnectorLimit kept %d; the mappings disagree again",
					tier, exported, want, kept)
			}

			// The OTHER consumer, which round 1 never exercised despite this
			// test claiming to pin "the two consumers".
			err := ValidateCustomPolicyConnectorLimit(config)
			if want < n && err == nil {
				t.Errorf("tier %q: the exported mapping says %d but "+
					"ValidateCustomPolicyConnectorLimit accepted %d connectors", tier, exported, n)
			}
			if want == n && err != nil {
				t.Errorf("tier %q: the exported mapping says %d (no ceiling at %d connectors) "+
					"but ValidateCustomPolicyConnectorLimit refused: %v", tier, exported, n, err)
			}
		})
	}
}

// TestZeroValuedLimitsMeanNoCeilingForTheConsumers pins the contract R3 round 2
// caught the round-1 consolidation silently changing.
//
// The two switches originally read config.Max… RAW, so a field left at its zero
// value fell through their `limit > 0` guard and meant NO CEILING. Round 1's
// consolidation reused the exported method's default-substituting fallback and
// thereby moved a zero-valued config from unlimited to a ceiling of 2 - making
// UpdateConfig REFUSE a configuration it had previously accepted. Unreachable
// in-tree, because every config starts from DefaultDynamicPolicyConfig; not
// unreachable for an external caller of these exported functions, nor for JSON
// that omits the field.
//
// The exported method keeps its documented default. The consumers keep the raw
// read. This test is what stops the two being "simplified" together again.
func TestZeroValuedLimitsMeanNoCeilingForTheConsumers(t *testing.T) {
	setDeployment(t, "community", "")

	bare := DynamicPolicyConfig{EnabledConnectors: []string{"a", "b", "c", "d", "e"}}
	if got := EnforceCustomPolicyConnectorLimit(bare); len(got) != len(bare.EnabledConnectors) {
		t.Errorf("a config with the limit fields unset kept %d of %d connectors; the consumers "+
			"read the field RAW, so an unset field means no ceiling, not a ceiling of 2",
			len(got), len(bare.EnabledConnectors))
	}
	if err := ValidateCustomPolicyConnectorLimit(bare); err != nil {
		t.Errorf("ValidateCustomPolicyConnectorLimit refused a config it accepted before the "+
			"consolidation: %v", err)
	}

	// A negative field is equally "no ceiling" for the consumers.
	neg := bare
	neg.MaxCustomPolicyConnectorsCommunity = -5
	if got := EnforceCustomPolicyConnectorLimit(neg); len(got) != len(neg.EnabledConnectors) {
		t.Errorf("a negative limit field truncated to %d; it must mean no ceiling", len(got))
	}

	// The EXPORTED method, by contrast, still substitutes its documented
	// defaults - the behaviour it has always had.
	if got := bare.CustomPolicyConnectorLimitForTier("community"); got != 2 {
		t.Errorf("CustomPolicyConnectorLimitForTier(community) on an unset config = %d, want its "+
			"documented default 2", got)
	}
	if got := bare.CustomPolicyConnectorLimitForTier("evaluation"); got != 5 {
		t.Errorf("CustomPolicyConnectorLimitForTier(evaluation) on an unset config = %d, want 5", got)
	}
}

// TestNilReceiverDoesNotPanic pins the exported method against a regression the
// round-1 consolidation introduced.
//
// The body it replaced returned before touching the receiver for the four paid
// spellings, so `(*DynamicPolicyConfig)(nil).CustomPolicyConnectorLimitForTier("enterprise")`
// returned -1. Round 1 dereferenced unconditionally and turned that into a
// panic - a crash newly reachable through an exported method in a
// source-available repo.
func TestNilReceiverDoesNotPanic(t *testing.T) {
	var nilCfg *DynamicPolicyConfig
	for tier, want := range map[string]int{
		"enterprise": UnlimitedCustomPolicyConnectors,
		"Plus":       UnlimitedCustomPolicyConnectors,
		"evaluation": 5,
		"community":  2,
		"nonsense":   2,
	} {
		if got := nilCfg.CustomPolicyConnectorLimitForTier(tier); got != want {
			t.Errorf("nil receiver, tier %q = %d, want %d", tier, got, want)
		}
	}
}

// TestEvaluationModeReceivesTheEvaluationCeiling carries the headline claim to
// the CONSUMER, where it is about a NUMBER rather than a string.
//
// The predicate row above proves the tier resolves to "evaluation". This proves
// the ceiling that arrives is FIVE and not two - which is the whole of "the one
// mode named for the Evaluation limit was the one mode that could not receive
// it". A test that only asserted the tier string would still pass if the
// evaluation arm of the limit mapping were deleted.
//
// The two controls matter as much as the assertion. Without a licence key the
// same mode gets the COMMUNITY ceiling, because a self-asserted mode name must
// not raise a limit on its own; and before #3713 the same input got NEITHER,
// because the mode resolved to the enterprise tier and nothing truncated.
func TestEvaluationModeReceivesTheEvaluationCeiling(t *testing.T) {
	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = []string{"a", "b", "c", "d", "e", "f"} // six, one over the Evaluation ceiling

	want := config.MaxCustomPolicyConnectorsEvaluation
	// BOTH shape guards run BEFORE the assertion. Round 1 put the second one
	// after a t.Fatalf that excluded its own input, so it could never diagnose
	// the case it was written for - the "assertion after a Fatalf" class, in the
	// commit that claimed to fix that class elsewhere.
	if want <= config.MaxCustomPolicyConnectorsCommunity {
		t.Fatalf("test bug: the Evaluation ceiling (%d) is not above the Community one (%d), so this "+
			"test cannot tell them apart and would pass for a build that ignored the licence key",
			want, config.MaxCustomPolicyConnectorsCommunity)
	}
	if len(config.EnabledConnectors) <= want {
		t.Fatalf("test bug: the fixture has %d connectors and the Evaluation ceiling is %d, so a "+
			"correct implementation truncates nothing here",
			len(config.EnabledConnectors), want)
	}

	setDeployment(t, "evaluation", "Evaluation")
	got := EnforceCustomPolicyConnectorLimit(config)
	if len(got) != want {
		t.Fatalf("DEPLOYMENT_MODE=evaluation with an Evaluation licence kept %d of %d connectors, "+
			"want %d. Before #3713 that mode resolved to the enterprise tier and all %d survived; "+
			"the Evaluation ceiling was unreachable from the mode named for it.",
			len(got), len(config.EnabledConnectors), want, len(config.EnabledConnectors))
	}

	// CONTROL 1 - the mode name alone does not buy the ceiling.
	setDeployment(t, "evaluation", "")
	if bare := EnforceCustomPolicyConnectorLimit(config); len(bare) != config.MaxCustomPolicyConnectorsCommunity {
		t.Errorf("DEPLOYMENT_MODE=evaluation with NO licence kept %d connectors, want the community "+
			"ceiling %d: a self-asserted mode name must not raise a limit",
			len(bare), config.MaxCustomPolicyConnectorsCommunity)
	}

	// CONTROL 2 - an Enterprise-entitled mode is still unlimited with the same
	// six connectors, so the truncation above is the ceiling and not the input.
	setDeployment(t, "saas", "")
	if all := EnforceCustomPolicyConnectorLimit(config); len(all) != len(config.EnabledConnectors) {
		t.Errorf("DEPLOYMENT_MODE=saas kept %d of %d", len(all), len(config.EnabledConnectors))
	}
}
