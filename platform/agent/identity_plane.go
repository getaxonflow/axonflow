// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"axonflow/platform/agent/license/admission"
	"context"
	"log"
	"strings"

	sharedidentity "axonflow/platform/shared/identity"
)

// initIdentityPlane assembles the identity plane: the subject admission the
// enforcing planes admit each request's subject through, held in
// identityAdmission. What this process wired, from which the built-in realms
// are derived, is subject admission's and lives in identity_admission.go.
//
// A construction failure is fatal: a deployment whose realms could not be
// assembled cannot admit anyone, and a process that started anyway would
// refuse every request for a reason nothing at boot had said.
func initIdentityPlane() {
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{
		Deployment:        identityDeployment,
		ExtraRealmSources: identityExtraRealmSources,
		Revocations:       identityRevocationOracle(),
	})
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	// The admission is held: the anchored enforcer admits each request's
	// subject through it, and RegisterCAEPReceiver verifies a SET's issuer
	// against its registry.
	identityAdmission = boot
}

// admitUserToken is the SINGLE production entry point for the HS256 per-user
// token path: it validates the token and admits the validated human principal
// against the licence's tier ceiling (#3593).
//
// # WHY THIS EXISTS RATHER THAN AN ADMISSION IN ResolveUser
//
// validateUserToken has TWO production callers: ResolveUser, and
// resolveAuditReadAuthority (audit_verification_authority.go), which uses a
// per-user token to decide TENANT-WIDE AUDIT READ. An admission at one of them
// would leave the other admitting a principal the ceiling refuses, on the one
// surface where it buys read-scope elevation.
//
// validateUserToken's own signature cannot carry the authenticated
// organization (it takes the credential TENANT, which is a different
// identifier) and it has some thirty test callers, so the admission lives here
// instead, in the one function both production paths must traverse. That is
// only a guarantee if nothing else calls validateUserToken directly, which is
// not a matter of discipline: TestValidateUserTokenHasExactlyOneProductionCaller
// walks the package AST and fails when a second one appears.
func admitUserToken(authenticatedOrgID, tokenString, expectedTenantID string) (*User, error) {
	user, err := validateUserToken(tokenString, expectedTenantID)

	// Only the enterprise HS256 branch presents a credential. Community and
	// community-SaaS synthesize a fixed user from no credential at all, so
	// there is no human principal to admit; their client credential is
	// admitted in Authenticate.
	if isCommunityMode() || isCommunitySaasMode() {
		return user, err
	}
	// A TOKEN STAMPED WITH THE PER-USER MINT'S ISSUER IS HELD TO THE PER-USER
	// TOKEN'S CLAIM RULE (#4311). validateUserToken verifies the signature and
	// nothing the mint always stamps, so a correctly signed per-user token with
	// no email was admitted here and decided as a verified user, while the fleet
	// validator refused the same token. The rule is the fleet validator's own,
	// and authenticatedOrgID is the authenticated credential's organization,
	// never a header. It runs before the org-less return below, so a deployment
	// with no authenticated organization refuses such a token, as the fleet
	// validator does. A token without the mint's issuer is the tenant token kind
	// and keeps its handling.
	if err == nil && user != nil && sharedidentity.IsMintedUserToken(user.TokenClaims) {
		if _, _, claimErr := sharedidentity.CheckMintedUserTokenClaims(user.TokenClaims, authenticatedOrgID); claimErr != nil {
			return nil, claimErr
		}
	}
	// No authenticated organization means there is no organization to admit
	// a principal of: an org-less deployment is one running without ORG_ID,
	// and authResultPrincipal skips an org-less AuthResult for the same reason.
	if strings.TrimSpace(authenticatedOrgID) == "" {
		return user, err
	}
	// A VALIDATED per-user token is a HUMAN PRINCIPAL of the authenticated
	// organization. The key is the canonical email the audit path stamps,
	// lower-cased and trimmed, so two spellings of one address are one
	// principal.
	if err == nil && user != nil {
		if refusal := admitPrincipal(context.Background(), admission.HumanPrincipal, authenticatedOrgID, canonicalPrincipalEmail(user.Email)); refusal != nil {
			return nil, refusal
		}
	}
	return user, err
}
