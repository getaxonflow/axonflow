// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// Orchestrator-side wiring of the ADR-065 identity compatibility adapters
// (#3550).
//
// # WHY THE ORCHESTRATOR NEEDS ITS OWN
//
// The census of auth entry points does not stop at the agent binary. The
// orchestrator binds a caller's principal from the trust-gated identity
// headers in applyAuthoritativePrincipal, and that binding drives
// audit_logs.user_email on every verdict this plane records and the ADR-044
// override scoping. Leaving it unadapted would mean the flag is honored on the
// agent and ignored here, which is precisely the "consulted in some planes and
// not others" failure the adapter's single-entry design exists to prevent.
//
// # WHY IT DECLARES ONLY THE BUILT-IN REALMS
//
// The orchestrator verifies no credential of its own. Its callers reach it
// over an HMAC-signed internal hop (requireInternalProxyAuth), and the
// per-user identity it reads has already been established and gated upstream.
// So there is no tenant OIDC configuration to derive a realm from here, and
// the OIDC realm source is deliberately absent rather than duplicated: two
// processes independently deriving the same realm from the same table is two
// registrations that can disagree about a version.

// headerUserID is the upstream-asserted stable user identifier.
//
// It is a local constant rather than a shared one because there is no shared
// one: the agent holds the spelling in platform/agent/identity_trust.go's
// unexported identityHeaderUserID, and the orchestrator already reads the
// companion X-User-Email header as a literal in five other files. Introducing
// a shared constant is worth doing and is worth doing as its own change, where
// every existing literal moves with it.
const headerUserID = "X-User-ID"

// orchestratorCompatDeployment records what this process wired.
var orchestratorCompatDeployment sharedidentity.BuiltinRealmDeployment

// noteOrchestratorDirectoryWired records that a SCIM-backed directory is
// available in this process, so the realms that can carry one declare
// DirectorySourceSCIM rather than the positive "this realm has no group
// graph".
func noteOrchestratorDirectoryWired() {
	orchestratorCompatDeployment.HasDirectory = true
}

// initIdentityCompat parses the configured mode, assembles the adapter and
// installs it process-wide. Fatal on an unrecognized mode, for the reason
// spelled out on the agent's copy: an operator who typed "enfore" believes
// their deployment enforces.
//
// # THE PER-ORGANIZATION MODE IS WIRED HERE TOO (session ADR65-I)
//
// This plane observes and does not act (observeCompatPrincipal), but it
// RECORDS under a mode, and the release plan's gate is stated per plane. If
// the agent resolved an organization's mode from its record and this plane
// resolved it from the process flag alone, the same organization would read
// mode=shadow in one container's log and mode=off in the other's, which is
// the "consulted in some planes and not others" failure in a new coat. Both
// binaries therefore read the SAME table through the SAME store. Reading
// one settings row from two processes is not the two-registrations problem
// that keeps the OIDC realm source off this plane: nothing is registered,
// and the row has one writer.
func initIdentityCompat() {
	boot, err := sharedidentity.BootstrapCompat(sharedidentity.CompatBootstrapConfig{
		RawMode:           os.Getenv(sharedidentity.EnvCompatMode),
		RawEnforceReasons: os.Getenv(sharedidentity.EnvEnforceReasons),
		Deployment:        orchestratorCompatDeployment,
		Component:         "orchestrator",
		OrgModes:          orchestratorOrgModeSource(),
	})
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	boot.InstallProcessCompat("orchestrator")
}

// orchestratorOrgModeSource builds the per-organization settings store over
// this process's database, or returns nil where none can exist.
//
// Enterprise-only by construction: the community constructor returns
// ErrEnterpriseOnly, which is SKIPPED. A nil source means the process mode is
// the whole answer, which is #3582's behaviour and the correct one for a
// build with no organization-management surface. Any OTHER construction
// failure is fatal: a deployment that HAS the store's table and could not
// open a store for it would silently run every organization in the process
// mode while its records say otherwise.
func orchestratorOrgModeSource() sharedidentity.CompatOrgModeSource {
	if usageDB == nil {
		return nil
	}
	store, err := sharedidentity.NewDBOrgIdentitySettingsStore(usageDB)
	switch {
	case err == nil:
		return store
	case errors.Is(err, sharedidentity.ErrEnterpriseOnly):
		return nil
	default:
		log.Fatalf("❌ identity compat: per-organization settings store could not be built: %v", err)
		return nil
	}
}

// observeCompatPrincipal runs the trusted-header adapter for a request whose
// principal applyAuthoritativePrincipal has just bound, and DELIBERATELY DOES
// NOT ACT ON THE RESULT.
//
// # WHY THIS PLANE OBSERVES AND DOES NOT ENFORCE
//
// The first version of this change cleared u.Email and u.Role on a refusal,
// on the argument that an empty actor is already this plane's fail-closed
// state. That argument is false, and a shipped default policy falsifies it:
// policy_defaults.go declares
//
//	{Field: "user.role", Operator: "equals", Value: "evaluation"} -> modify_risk
//
// and db_dynamic_policies.go resolves user.role from req.User.Role. Clearing
// the role makes that condition evaluate FALSE, so the risk modifier is not
// applied and the request is scored lower than it would have been. An empty
// actor is fail-closed for allowlist-shaped conditions (not_equals, not_in)
// and fail-OPEN for the deny-or-escalate-on-role shape, and both ship as
// defaults. The same is true of u.Email.
//
// Clearing u.Role is additionally wrong on its own terms: it arrives on
// X-Axonflow-User-Role, which applyAuthoritativePrincipal's own contract says
// is set ONLY from a cryptographically validated per-user token. A refusal
// about the trusted-header credential would be destroying an identity fact
// established by a different and stronger one.
//
// So this plane records and does nothing. That is NOT the "flag consulted in
// some planes and not others" failure the adapter's design prevents: the
// adapter is still called at the one function that binds this plane's
// principal, its verdict is recorded under the same mode as everywhere else,
// and the refusal is discarded HERE, visibly, with a reason - rather than by a
// call site that forgot to check. The enforcement point for this credential is
// the AGENT (authenticateMCPSession), which refuses before the header is ever
// forwarded; under the default posture the agent strips it entirely.
//
// The function returns nothing on purpose. There is no value for a caller to
// act on, so no future edit can start acting on one without changing the
// signature and reading this.
func observeCompatPrincipal(r *http.Request, u *UserContext, orgID string) {
	if u == nil {
		return
	}
	if strings.TrimSpace(orgID) == "" {
		// No authenticated organization to scope a realm lookup to. The
		// adapter would record this as an adapter-side DEFECT, once per
		// governed request, on any deployment or hop that does not stamp
		// X-Org-ID - telling an operator to fix a wiring bug that is not one.
		// A question that cannot be asked is not a divergence.
		return
	}
	// The headers are read AFTER applyAuthoritativePrincipal has bound them,
	// from the same source, so the counterfactual describes the identity this
	// plane actually acted on rather than a second, independently-derived one.
	//
	// `accepted` matches the agent's spelling (either header surviving the
	// gate), and so does the skip above, so one logical path's counterfactuals
	// are comparable across the two planes.
	headerID := r.Header.Get(headerUserID)
	if headerID == "" && u.Email == "" {
		// NOTHING WAS ASSERTED, so there is no credential decision to compare
		// against - and under the default posture the agent strips both
		// headers, which makes this EVERY governed request. Recording it would
		// put one agreement per request into the denominator an operator reads
		// to decide whether enforce is safe. The agent's trusted-header site
		// skips the same shape for the same reason; without this the two
		// planes' counterfactuals are not comparable, which is what this
		// adapter exists to make them.
		return
	}
	_ = sharedidentity.CompatResolve(r.Context(), sharedidentity.TrustedHeaderLegacyAuth(
		orgID,
		headerID,
		u.Email,
		headerID != "" || u.Email != "",
		"",
		time.Now(),
	))
}
