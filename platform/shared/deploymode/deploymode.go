// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package deploymode holds the ONE definition of what each DEPLOYMENT_MODE
// means: which migration categories it applies, and therefore which tables a
// deployment running under it actually has.
//
// # WHY THIS IS A SHARED PACKAGE AND NOT A COPY
//
// The map below used to live in platform/agent/migration_helpers.go, where it
// is the input to getMigrationPaths - the function that decides which
// migrations/<category>/ directories are applied, and hence which tables
// exist. Nothing outside package agent could ask it a question, so a second
// process that needed to know "does this deployment have the enterprise
// schema" had two options: import package agent (which the orchestrator
// cannot), or restate the answer.
//
// Restating it is the defect this package exists to prevent. A predicate
// derived from a SECOND list of modes disagrees with the migration selector
// on exactly the day someone adds a mode to one and not the other, and the
// symptom is a process querying a table its own deployment never created.
// platform/agent/migration_helpers.go now aliases these values rather than
// declaring its own, so there is one list and one meaning.
//
// # THE TWO AXES, AND WHY BOTH LIVE HERE (#3713)
//
// DEPLOYMENT_MODE decides two different things, and they answer differently:
//
//   - SCHEMA - which migration categories a deployment applies, and therefore
//     which tables it has. AppliesCategory, AppliesEnterpriseSchema.
//
//   - RUNTIME POSTURE - whether the process runs the Community posture, in
//     which authentication and licence validation are bypassed; and whether it
//     runs the community-SaaS posture, which is its own thing again.
//     IsCommunityPosture, IsCommunitySaasPosture and their Current* forms.
//
// The two columns:
//
//	| DEPLOYMENT_MODE      | enterprise schema | Community posture |
//	|----------------------|-------------------|-------------------|
//	| "" (unset)           | no  (see Unset)   | no  (fails closed)|
//	| "community"          | no                | YES               |
//	| "evaluation"         | no                | no                |
//	| "community-saas"     | no                | no                |
//	| "saas", in-vpc-*     | yes               | no                |
//
// THE ROW THAT MATTERS IS THE FIRST, and it is the open, measured issue #3128:
// unset selects the `community` SCHEMA while getting the enterprise runtime
// posture. Three inputs have the community schema without the Community
// posture - unset, `evaluation` and `community-saas` - and only two of those
// are among the ten RECOGNISED spellings, because unset is resolved by Resolve
// rather than declared as a mode. (Counting the columns as merely unequal gives
// eight of ten, which is a true number that measures nothing interesting: it
// counts `saas` too, where "enterprise schema, enterprise posture" is exactly
// what anyone would expect.)
//
// The table is not prose - deploymode_test.go computes both columns for every
// recognised spelling and requires this partition, and
// TestUnsetDisagreesAcrossTheTwoAxes covers the unset row the table cannot.
//
// Until #3713 the posture half had no home. It was written out at each site
// that needed it: TWICE byte-identically, as
// `os.Getenv("DEPLOYMENT_MODE") == "community"` in platform/agent/run.go and
// platform/orchestrator/run.go; a THIRD time in platform/shared/corspolicy
// spelled through local constants (`os.Getenv(deploymentModeEnv) ==
// communityMode`), which is why scripts/lint-deployment-mode.sh - which greps
// for the literal - never saw it and never allow-listed it; and a FOURTH time
// in platform/agent/dev_token_handler.go with deliberately different semantics.
// So the disagreement above was invisible: no file held both answers, and the
// only way to notice that unset means opposite things was to have read both
// halves of the tree. Putting the two axes in one package is the fix - not
// because they agree, but because they do not.
//
// # WHAT IT STILL DOES NOT DECIDE
//
//   - Which BUILD is running - platform/shared/edition. The community-SaaS
//     fleet runs the enterprise-tagged binary, so no value here answers it.
//   - What a customer is ENTITLED to - the licence, never this variable.
package deploymode

import (
	"os"
	"sort"
)

// EnvDeploymentMode is the variable every deployment surface sets.
const EnvDeploymentMode = "DEPLOYMENT_MODE"

// CategoryEnterprise is the migrations/enterprise/ directory: the tables that
// exist only on a deployment that applies the Enterprise schema.
const CategoryEnterprise = "enterprise"

// ModeCommunity and ModeCommunitySaas are the two canonical modes that select a
// RUNTIME POSTURE of their own. They are spelled here once and used both as
// keys of canonicalModes below and by the posture predicates, so the schema
// half and the posture half cannot come to disagree about how the mode is
// spelled - which is the narrowest version of the defect #3713 fixed.
const (
	ModeCommunity     = "community"
	ModeCommunitySaas = "community-saas"
)

// canonicalModes maps every RECOGNISED DEPLOYMENT_MODE to the migration
// categories it loads, in apply order, as slash-separated paths relative to
// the migrations/ root.
//
// This map is the ONLY definition of "recognised". A value that is neither a
// key here nor a key of Aliases is REFUSED - getMigrationPaths returns an
// error and the agent refuses to boot. It does not fall through to the widest
// set, which is what shipped before #3167: `enterprise` - the value our own
// docker-compose.enterprise.yml has always defaulted to - was not a case, so
// every self-hosted enterprise stack silently applied the SaaS set, including
// all three industry verticals it never asked for.
var canonicalModes = map[string][]string{
	ModeCommunity:       {"core"},
	"evaluation":        {"core"},
	ModeCommunitySaas:   {"core", "community-saas"},
	"in-vpc-enterprise": {"core", "enterprise"},
	"in-vpc-healthcare": {"core", "enterprise", "industry/healthcare"},
	"in-vpc-banking":    {"core", "enterprise", "industry/banking"},
	"in-vpc-travel":     {"core", "enterprise", "industry/travel"},
	"saas":              {"core", "enterprise", "industry/healthcare", "industry/banking", "industry/travel"},
}

// aliases maps accepted non-canonical spellings onto a canonical mode. An
// alias is recognised; anything outside these two maps is not.
//
//   - "invpc"      predates the in-vpc-<vertical> split and is still accepted
//     by the marketplace CloudFormation template's AllowedValues.
//   - "enterprise" is what docker-compose.enterprise.yml, docker-compose.test.yml
//     and docker/docker-compose.base.yaml default to, and what
//     scripts/setup-e2e-testing.sh writes into .env. It denotes a single-tenant
//     self-hosted enterprise deployment, which is in-vpc-enterprise. (#3167)
var aliases = map[string]string{
	"invpc":      "in-vpc-enterprise",
	"enterprise": "in-vpc-enterprise",
}

// Unset is what an EMPTY DEPLOYMENT_MODE resolves to for SCHEMA selection.
//
// It is `community`, unchanged since before #3167. See
// platform/agent/migration_helpers.go's unsetDeploymentMode, which aliases
// this, for the full argument and for why the divergence from
// isCommunityMode() is issue #3128 rather than a bug fixed here.
const Unset = "community"

// # THE THREE NORMALISATION RULES FOR DEPLOYMENT_MODE, IN ONE PLACE (#3637 item 7)
//
// Every site that reads the variable applies one of three rules, and each rule
// is deliberate. They are listed here so the next author picks one ON PURPOSE
// rather than inheriting whichever file they happen to be editing. None of the
// three is a security defect: the fail-closed sites (admin auth, the dev-token
// gate) refuse an unknown value regardless of how they spell the known ones.
//
//   - EXACT (no trim, no case-fold): this package's Resolve and the schema
//     predicates; platform/agent/run.go; platform/orchestrator/run.go and its
//     llm/bootstrap.go; platform/shared/policy/dynamic_evaluator.go;
//     ee/platform/customer-portal/config/deployment.go and
//     api/provision_admin_password.go. Reason: the string selects the database
//     SCHEMA, and normalising it would silently accept a value the operator
//     did not write (see Resolve below).
//   - TRIM ONLY: ee/platform/customer-portal/middleware/admin_auth.go. Reason:
//     the ENVIRONMENT=" production" incident - a leading space in a task
//     definition turned a production check into a non-production one. The mode
//     is trimmed and then matched exactly; the fail-closed default stands.
//   - TRIM + LOWER-CASE: platform/agent/dev_token_handler.go. Reason: a
//     fail-closed gate that must NOT inherit its accepting set from the helper
//     that disables auth (#2541), allow-listed in scripts/lint-deployment-mode.sh
//     with that justification. It widens what it ACCEPTS as a known mode; it
//     never widens what it permits.
//
// Adding a fourth rule is a decision to record here first.
//
// Resolve maps a raw DEPLOYMENT_MODE value onto a canonical mode, and reports
// whether the value was recognised at all.
//
// The value is matched EXACTLY - not trimmed, not case-folded - because this
// string selects the database schema, and normalising it would silently accept
// a value the operator did not write.
func Resolve(raw string) (mode string, recognised bool) {
	if raw == "" {
		return Unset, true
	}
	if canonical, ok := aliases[raw]; ok {
		return canonical, true
	}
	if _, ok := canonicalModes[raw]; ok {
		return raw, true
	}
	return "", false
}

// RecognisedModes returns every accepted DEPLOYMENT_MODE spelling - canonical
// names and aliases - sorted.
func RecognisedModes() []string {
	out := make([]string, 0, len(canonicalModes)+len(aliases))
	for m := range canonicalModes {
		out = append(out, m)
	}
	for m := range aliases {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// AppliesCategory reports whether a deployment running under the raw
// DEPLOYMENT_MODE value applies the named migration category, and therefore
// whether the tables that category creates can exist there.
//
// # THE UNRECOGNISED CASE ANSWERS YES, DELIBERATELY
//
// An unrecognised value makes the agent refuse to boot (getMigrationPaths
// returns an error), so no deployment reaches steady state with one. The
// orchestrator does not validate the value, and for it the choice is between
// two wrongs: answering NO would stop it consulting a table that may well
// exist, silently running every organization in the process mode while its
// records say otherwise. Answering YES restores exactly the behaviour that
// shipped before this predicate existed - a read that fails, is counted, is
// logged once per TTL window, and falls back to the process mode. The second
// is recoverable and the first is silent, so this answers YES.
func AppliesCategory(raw, category string) bool {
	mode, recognised := Resolve(raw)
	if !recognised {
		return true
	}
	for _, c := range canonicalModes[mode] {
		if c == category {
			return true
		}
	}
	return false
}

// Current returns this process's raw DEPLOYMENT_MODE value.
//
// It is the ONE env read of the variable in this package, and this file is on
// scripts/lint-deployment-mode.sh's allow-list because of it. Every other
// package asks its question through Current or through a predicate below,
// rather than reading the variable itself - which is what the lint exists to
// enforce, and why the read is spelled with the literal the lint greps for
// rather than with EnvDeploymentMode.
func Current() string {
	return os.Getenv("DEPLOYMENT_MODE")
}

// CanonicalModes returns a COPY of the mode-to-categories map.
//
// A copy, not the map itself. These were package-private to platform/agent
// before #3602 moved them here; exporting the map object would let any package
// in the tree mutate the migration selector's own input at runtime, and the
// selector decides which database schema a deployment applies. The cost is one
// allocation at the two init-time call sites that take it.
func CanonicalModes() map[string][]string {
	out := make(map[string][]string, len(canonicalModes))
	for mode, cats := range canonicalModes {
		out[mode] = append([]string(nil), cats...)
	}
	return out
}

// Aliases returns a COPY of the alias map, for the reason CanonicalModes gives.
func Aliases() map[string]string {
	out := make(map[string]string, len(aliases))
	for k, v := range aliases {
		out[k] = v
	}
	return out
}

// AppliesEnterpriseSchema reports whether THIS process's deployment applies
// migrations/enterprise/, read from the environment.
//
// It is the question a caller asks before wiring a store over an
// Enterprise-only table. It is deliberately NOT "is this an enterprise
// BUILD": the build tag decides which code compiles, and DEPLOYMENT_MODE
// decides which schema was applied. The community-saas fleet runs the
// enterprise-tagged binary against the `community-saas` schema, so the two
// answers differ there - which is the whole reason this function exists.
func AppliesEnterpriseSchema() bool {
	return AppliesCategory(Current(), CategoryEnterprise)
}

// IsCommunityPosture reports whether raw selects the Community RUNTIME posture.
//
// Community posture bypasses licence validation AND authentication
// (platform/agent/authenticator.go returns a synthetic identity with no
// credential), skips the MCP connector permission check, auto-approves
// require_approval policies and lets a request body assert its own tenant. It
// is the single most permissive posture the platform has.
//
// # THE ACCEPTING SET IS EXACTLY ONE TOKEN, AND THAT IS THE WHOLE CONTRACT
//
//	| DEPLOYMENT_MODE        | Community posture? |
//	|------------------------|--------------------|
//	| "community"            | YES                |
//	| "" (unset)             | no                 |
//	| any other known mode   | no                 |
//	| " community"           | no                 |
//	| "Community"            | no                 |
//	| anything unrecognised  | no                 |
//
// #3096: `raw == ""` used to be in the true set, so a deployment that simply
// never set DEPLOYMENT_MODE - a bare `docker run` of the published image
// (neither Dockerfile sets a default), `go run ./platform/agent` - silently ran
// with authentication disabled. The burden of proof is now inverted: the
// permissive posture must be ASKED for by name, and everything else, including
// the empty string, gets the enterprise posture. That is the same fail-open-on-
// unset shape #2287/#3068 fixed in the portal's isAdminAuthRequired.
//
// # WHY THIS DOES NOT GO THROUGH Resolve
//
// Resolve accepts aliases and would accept any future alias of `community`.
// Here every widening of the accepting set DISABLES authentication and there is
// no dominating rule, so the set is the canonical token and nothing else - not
// trimmed, not case-folded, not aliased. " community" therefore fails closed,
// and fails LOUDLY, because the agent then demands a licence it was not given.
// TestNoAliasSelectsAPosture holds the alias half of that: if an alias onto
// `community` is ever declared, the schema half would accept it here and the
// posture half would not, and that test fails until the decision is made.
func IsCommunityPosture(raw string) bool {
	return raw == ModeCommunity
}

// IsCommunitySaasPosture reports whether raw selects the community-SaaS
// posture: the shared, AxonFlow-operated multi-tenant server
// (try.getaxonflow.com). No Ed25519 licence, but registration credentials ARE
// required; rate limits are enforced; Ollama is the only permitted LLM.
//
// It is deliberately NOT a member of IsCommunityPosture's true set. A csaas
// deployment is its own mode, and treating the two as one gate would re-enable
// the feature surfaces csaas explicitly disables - and would disable
// authentication on a server that is on the public internet.
//
// The accepting set is exactly one token, for IsCommunityPosture's reason.
func IsCommunitySaasPosture(raw string) bool {
	return raw == ModeCommunitySaas
}

// CurrentIsCommunityPosture reports IsCommunityPosture for THIS process.
//
// This is the function every caller wants; the raw form exists so the contract
// can be tested without an environment. Before #3713 there was no such
// function, and the four call sites that needed the answer each wrote the
// comparison out - two byte-identically, a third through local constants that
// hid it from the lint, and a fourth with deliberately different semantics.
func CurrentIsCommunityPosture() bool {
	return IsCommunityPosture(Current())
}

// CurrentIsCommunitySaasPosture reports IsCommunitySaasPosture for THIS
// process. Three sites wrote this comparison out before #3713.
func CurrentIsCommunitySaasPosture() bool {
	return IsCommunitySaasPosture(Current())
}

// =============================================================================
// The ENTITLEMENT axis (#3713)
// =============================================================================

// enterpriseEntitledModes names, for every CANONICAL mode, whether a deployment
// running under it is entitled to Enterprise resource limits by the shape of
// the deployment itself rather than by an AXONFLOW_LICENSE_KEY.
//
// # THIS IS A THIRD AXIS, AND IT IS NOT THE SCHEMA ONE
//
// DEPLOYMENT_MODE already answers two different questions in this package: which
// migration categories apply (AppliesCategory - "can this table exist"), and
// which runtime posture is in force. This map answers a third: "what has been
// paid for". The three coincide on most inputs and are not the same question,
// which is exactly the trap #3713 was:
// platform/shared/policy.resolveConnectorLimitTier asked "is the mode string
// literally community or empty" and treated every other answer as Enterprise,
// so `community-saas` and `evaluation` - neither of which is an Enterprise
// deployment under any axis - received unlimited custom-policy connectors, and
// so did a typo.
//
// # WHY IT IS A DECLARED TABLE AND NOT DERIVED FROM canonicalModes
//
// The derivation is available and tempting: every mode entitled here is also a
// mode whose categories include CategoryEnterprise, so
// `AppliesCategory(mode, CategoryEnterprise)` returns this map today, for free,
// and stays total by construction. It is deliberately NOT used.
//
// AppliesEnterpriseSchema's own doc comment is the argument. It exists because
// the schema answer and the edition answer already disagree - the community-saas
// fleet runs the Enterprise-tagged binary against the community-saas schema - so
// borrowing one axis to answer another is a known defect shape here, not a
// hypothetical. Deriving entitlement from the migration categories would mean
// that the day a mode gains one Enterprise-only TABLE it silently gains
// unlimited Enterprise LIMITS, decided by whoever edited the migration
// selector. The cost of declaring it is this map and the totality test that
// keeps it complete; the benefit is that moving a mode across the entitlement
// line has to be typed on purpose.
//
// TestTheEntitlementAndSchemaAxesAgreeToday pins the coincidence, so the two
// tables cannot drift apart unnoticed either: they agree on every recognised
// mode today, and the day they must not, that test is where it gets said.
//
// # THE UNRECOGNISED CASE ANSWERS NO, AND THAT IS THE OPPOSITE OF AppliesCategory
//
// AppliesCategory answers YES for an unrecognised value, deliberately, and its
// comment gives the reason: for a schema READ the recoverable wrong is to try
// the table and fail. Entitlement has no such symmetry. The permissive answer
// grants a paid limit to a value nobody validated - before #3713 a misspelled
// DEPLOYMENT_MODE was indistinguishable from a purchased Enterprise licence -
// so this axis fails CLOSED and an unrecognised mode gets nothing here. It can
// still be entitled by a licence key - which is a NARROWER grant than a mode
// string but, on the connector-limit path at least, not a verified one: see the
// "WHAT THE LICENCE KEY IS AND IS NOT" note on
// platform/shared/policy.resolveConnectorLimitTier before repeating the claim
// that a licence key is the checked surface.
//
// Every canonical mode must appear. A mode present in canonicalModes and absent
// here resolves to false, which is the safe direction, and
// TestEveryCanonicalModeHasAnEntitlement fails until it is classified.
var enterpriseEntitledModes = map[string]bool{
	// Not entitled by deployment shape. Each of these is entitled, if at all,
	// by an AXONFLOW_LICENSE_KEY - which is how the free Evaluation tier is
	// granted ("get a free Evaluation license for 5 connectors"), and the
	// reason `evaluation` does not entitle itself by name.
	"community":      false,
	"evaluation":     false,
	"community-saas": false,
	// Entitled by the deployment contract. These are single-tenant or
	// first-party Enterprise deployments; there is no free spelling of them.
	"in-vpc-enterprise": true,
	"in-vpc-healthcare": true,
	"in-vpc-banking":    true,
	"in-vpc-travel":     true,
	"saas":              true,
}

// IsEnterpriseEntitled reports whether a deployment running under the raw
// DEPLOYMENT_MODE value is entitled to Enterprise resource limits by virtue of
// the deployment mode alone.
//
// It is NOT the whole entitlement answer: a caller that returns early on true
// must still consult AXONFLOW_LICENSE_KEY on false, because that is where the
// Community and Evaluation tiers are distinguished. It answers only the half
// that DEPLOYMENT_MODE can answer.
//
// Aliases resolve first, so `enterprise` and `invpc` answer for
// in-vpc-enterprise. An unrecognised value answers false; see the map's
// comment for why this axis inverts AppliesCategory's choice.
func IsEnterpriseEntitled(raw string) bool {
	mode, recognised := Resolve(raw)
	if !recognised {
		return false
	}
	return enterpriseEntitledModes[mode]
}

// CurrentIsEnterpriseEntitled applies IsEnterpriseEntitled to THIS process's
// DEPLOYMENT_MODE.
func CurrentIsEnterpriseEntitled() bool {
	return IsEnterpriseEntitled(Current())
}
