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
// # WHAT IT DOES NOT DECIDE
//
// It does not decide the RUNTIME posture. isCommunityMode() in
// platform/agent/run.go and platform/orchestrator/run.go answers that, it
// fails CLOSED on an unset value, and the divergence between the two - unset
// selects the `community` SCHEMA while the runtime posture is the enterprise
// one - is the open, measured issue #3128. This package describes the schema
// half only, which is the half that answers "can this table exist".
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
	"community":         {"core"},
	"evaluation":        {"core"},
	"community-saas":    {"core", "community-saas"},
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
