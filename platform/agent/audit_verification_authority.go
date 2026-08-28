// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

// The authority gate on the audit-chain verification routes (#2914).
//
// # What was wrong, stated at the severity it actually has
//
// The three routes in audit_verification_handler.go were registered behind
// apiAuthMiddleware and nothing else, so ANY authenticated member of an
// organization could verify - and thereby enumerate - audit chains and records
// by id within that organization. #2914 is explicit that this is a
// LEAST-PRIVILEGE and metadata-disclosure finding, not a secret leak: the
// public key is public by definition, the per-record signature is meant to be
// shareable (that is what non-repudiation verification is FOR), no private key
// material is exposed, and the reads were already org-scoped. What a
// low-privilege member could learn is each record's decision_type, risk_level
// and chain linkage from the digest pre-image, which is compliance evidence and
// belongs with the roles that already hold compliance-read authority.
//
// # Why this predicate and not a new mechanism
//
// The house rule is that a site wanting "may this caller read across users in
// this tenant?" ASKS the shared predicate rather than string-comparing a role
// (identity.RoleCanReadTenant, and the #3001 record of what a literal
// `== "admin"` compare cost when it excluded owner). This gate is exactly that
// question: chain verification is a cross-user READ over the organization's
// audit trail, so it is gated on the same predicate the read layer uses to
// grant tenant-wide audit reads, and adding a role to that tier is one edit in
// one place.
//
// It is deliberately NOT identity.RoleIsAdministrative (admin + owner). That
// predicate answers "is this caller an org ADMINISTRATOR", and it excludes
// policy_admin - the read-everything, change-nothing-identity tier (#2993),
// which is precisely the compliance reader this evidence exists for. Gating on
// it would refuse the role most likely to be doing the verifying.
//
// It is also NOT the X-Admin-API-Key mechanism #2914 mentions as an existing
// option. That key is the customer-portal ADMIN API's deployment-wide
// credential (#2287/#2324); it carries no per-user identity, so using it here
// would replace "any org member" with "anyone holding one shared secret", which
// is not least privilege, and it would put a portal-plane credential on an
// agent-plane route.
//
// # The three postures
//
//  1. Community mode: allowed. Community is a no-auth, single-operator
//     deployment - authenticator.go resolves every caller to one local
//     developer with role admin - so a role gate there would refuse nobody and
//     could only break local verification. This mirrors sessionCanReadTenant's
//     community short circuit on the MCP plane, so the two planes agree.
//
//  2. An internal service (AuthKindInternalService - a caller holding
//     AXONFLOW_INTERNAL_SERVICE_SECRET, i.e. the customer-portal or the
//     orchestrator): allowed ONLY when it ASSERTS administrative authority with
//     identity.HeaderAdminAuthority. That is the established trusted-plane
//     shape (platform/shared/identity/readscope.go): a service that has already
//     authorized its caller as an administrator under its own access model says
//     so in a header, and the header is honoured only over a proof of the
//     internal-service channel. Requiring the assertion rather than trusting the
//     channel alone is what keeps this least-privilege: a portal that surfaces
//     verification to a viewer must not be able to do so by accident.
//
//     The assertion is checked ONLY on this auth kind, which is what makes it
//     unforgeable here. identity.NeverClientAssertableHeaders is stripped by the
//     agent's proxy Director, but that strip runs on the PROXY path, not on this
//     API plane - so a client-supplied X-Axonflow-Admin-Authority does reach
//     this handler. It is ignored, because an ordinary credential authenticates
//     as AuthKindEnterprise (or community-saas) and never reaches this branch.
//
//  3. Everything else (an enterprise credential, community-saas): a VALIDATED
//     per-user token whose role satisfies identity.RoleCanReadTenant. No token
//     is a refusal, not a fallback: the whole point is that the shared
//     org:license credential no longer suffices.
//
// # The token must belong to the credential's own scope
//
// validateUserToken does NOT check that the token's tenancy matches the
// authenticated credential's - every existing call site enforces that binding
// itself (gateway_handlers.go, decision_handler.go). This one does too, and it
// matters more here than there: without it, a privileged token minted in org A
// presented alongside org B's credential would authorize a chain read that is
// SCOPED TO ORG B, because the handlers take the org from the credential
// context and never from the token.

import (
	"context"
	"net/http"
	"strings"

	sharedidentity "axonflow/platform/shared/identity"
)

// auditVerifyDenyMessage is the single refusal sentence the three routes share.
//
// It names the authority required and how to present it, because a 403 a caller
// cannot act on produces a support ticket rather than a fix. It deliberately
// does NOT echo the role the caller actually holds: on a refusal path that is
// an answer about somebody's identity given to whoever asked.
const auditVerifyDenyMessage = "audit chain verification requires compliance read authority over this organization: " +
	"present a validated per-user token whose role is admin, owner or policy_admin (X-User-Token, or Authorization: Bearer), " +
	"or call from an internal service asserting administrative authority"

// auditVerificationAuthorized reports whether r may read audit-chain proofs.
//
// It is fail-closed by construction: every branch that cannot positively
// establish authority returns false, and the default is false.
func auditVerificationAuthorized(r *http.Request) bool {
	if r == nil {
		return false
	}
	// (1) Community: a single-operator deployment with no authentication at all.
	if isCommunityMode() {
		return true
	}

	ctx := r.Context()

	// (2) A trusted internal service that ASSERTS administrative authority.
	if AuthKindFromContext(ctx) == AuthKindInternalService {
		return sharedidentity.AdminAuthorityFromHeader(r.Header.Get(sharedidentity.HeaderAdminAuthority))
	}

	// (3) A validated per-user token carrying a tenant-wide read role.
	token := extractPerUserToken(r)
	if token == "" {
		return false
	}
	// The credential's own client identity, which is what a token omitting
	// tenant_id inherits (validateUserToken's tenant-inherit path).
	credentialTenant := ClientIDFromContext(ctx)
	if credentialTenant == "" {
		credentialTenant = TenantIDFromContext(ctx)
	}
	user, err := validateUserToken(token, credentialTenant)
	if err != nil || user == nil {
		return false
	}
	// The token must belong to the SAME scope the read will run under. The
	// handlers take the org from the credential context, so a token from
	// another org would otherwise authorize a read of this credential's org.
	if !sameScopeToken(user, ctx) {
		return false
	}
	return sharedidentity.RoleCanReadTenant(user.Role)
}

// sameScopeToken reports whether a validated per-user token was issued for the
// same organization (and, where both name one, the same tenancy) as the
// credential that authenticated this request.
//
// The ORG comparison is mandatory and has no absent-value escape: an empty
// org on either side fails, because "no org" is not a match, it is an
// unanswerable question, and the read that follows is org-scoped.
//
// The TENANT comparison is applied only when the token names one. A token
// minted without a tenant_id claim inherits the credential's tenancy inside
// validateUserToken, so the values are equal by construction in that case; a
// token that names a DIFFERENT tenancy is a mismatch and is refused.
func sameScopeToken(user *User, ctx context.Context) bool {
	if user == nil {
		return false
	}
	org := strings.TrimSpace(OrgIDFromContext(ctx))
	if org == "" || !strings.EqualFold(strings.TrimSpace(user.OrgID), org) {
		return false
	}
	credentialTenant := strings.TrimSpace(ClientIDFromContext(ctx))
	if credentialTenant == "" {
		credentialTenant = strings.TrimSpace(TenantIDFromContext(ctx))
	}
	tokenTenant := strings.TrimSpace(user.TenantID)
	if tokenTenant != "" && credentialTenant != "" && !strings.EqualFold(tokenTenant, credentialTenant) {
		return false
	}
	return true
}
