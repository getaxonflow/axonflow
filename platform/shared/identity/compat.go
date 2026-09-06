// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 legacy-credential compatibility adapters (#3550, session ADR65-F).
//
// #3570 landed the identity plane with no production caller. This file is the
// bridge: it takes what one of the four legacy credential paths (HS256 JWT,
// OIDC, API credential, trusted header) already established and runs it
// through RealmRegistry verification, producing a canonical (realm, subject)
// principal - WITHOUT changing what the legacy path decided.
//
// # THE SHADOW/ENFORCE SPLIT, STATED ONCE FOR ALL FOUR ADAPTERS
//
// There are exactly three modes and they are the same for every path:
//
//	off      Resolve does nothing at all. It reads no clock, touches no
//	         registry, and calls no recorder. This is the default.
//
//	         With a per-organization source wired (Enterprise), "off" is
//	         the resolved mode for THIS organization: the one thing Resolve
//	         does before deciding that is ask the source whether the
//	         organization has a record, which is a memoized in-process read
//	         (compat_org_settings.go) and produces nothing observable.
//
//	         The precise claim is about the DECISION, not about every
//	         instruction executed: each call site builds its LegacyAuth as an
//	         ARGUMENT, so that construction (a clock read, a small map, a
//	         slice) runs whatever the mode. Nothing it produces is observed,
//	         stored, forwarded or logged, so no request, response, audit row
//	         or downstream body differs - which is the guarantee that matters
//	         and the one the runtime suite measures. Hoisting the builders
//	         behind a per-call-site mode check would buy those allocations
//	         back at the price of reintroducing the mode-at-the-caller shape
//	         this design exists to remove, which is a bad trade.
//	shadow   the adapter evaluates and RECORDS the counterfactual. The legacy
//	         accept/reject decision is returned to the caller verbatim. A
//	         refusal is a log/metric line, never an HTTP status.
//	enforce  the adapter evaluates, records, AND refuses - but only in one
//	         direction (see the invariant below).
//
// # THE ONE-DIRECTION INVARIANT
//
// THIS ADAPTER CAN ONLY EVER REFUSE. It has no path that turns a legacy
// rejection into an acceptance, in any mode: Resolve produces a *CompatRefusal
// or nothing, and a refusal is the only ACTIONABLE field it returns. So the
// worst a misconfigured enforce deployment can do is deny requests legacy
// would have served; it can never serve one legacy would have denied.
//
// The precise statement is that there is no actionable admission, not that the
// verdict is invisible. CompatOutcome.Subject IS exported and, in shadow, does
// carry a full AcceptAdmission with a canonical principal - because the
// recorder and the tests need it. A call site COULD read it and admit on
// identity-plane say-so. Nothing in this package does, no production caller
// does, and the field is diagnostic: it is the answer to "what would the
// identity plane have said", never an instruction. If that ever needs to be
// structural rather than stated, the move is to unexport it behind an accessor
// that returns only what a recorder consumes.
//
// # WHY THE MODE IS READ HERE AND NOWHERE ELSE
//
// The failure this shape exists to prevent is "the flag is consulted in some
// planes and not others". Every call site does exactly this:
//
//	if ref := identity.CompatResolve(ctx, in).Refusal(); ref != nil { … }
//
// No call site reads the mode, and none can: CompatOutcome.refusal is
// unexported and is constructed in exactly one place, inside Resolve, under
// the mode check. A call site that forgets the mode cannot exist, because
// there is no mode for it to forget. This is the same reasoning as
// [[feedback_a_guard_at_the_callers_is_not_a_guard]]: the guard lives in the
// function that owns the invariant.
//
// One other function in this package consults the mode, and it decides no
// admission: outageSentinelsActive gates whether validator errors for
// key-material and revocation outages carry their dedicated sentinels or the
// pre-#3550 ErrTokenInvalid wrap. Both wordings REJECT on every branch in
// every mode, so no value of the mode can change an accept/reject decision
// through it; what it protects is the flag-off guarantee that the
// caller-visible error bytes and errors.Is semantics are exactly main's. It
// consults the mode THROUGH effectiveMode, for the request's organization
// (see below), so the wording an organization's validators emit and the
// verdict its adapter records can never disagree about which mode that
// organization is in.
//
// # THE PER-ORGANIZATION AXIS COMPOSES INSIDE THAT ONE READ (session ADR65-I)
//
// The release plan promises shadow "enabled per org", and the process-wide
// flag cannot deliver it: it shadows every organization on the deployment or
// none. The per-organization axis is therefore added INSIDE the single read
// rather than beside it. The mode a request runs in is
//
//	effectiveMode(process flag, the organization's record)
//	  = the record's mode, when the organization has one
//	  = the process flag,   when it has none (or none can be read)
//
// and that composition lives in exactly one function, effectiveMode, which
// is the only reader of both the process flag and the record source. Resolve
// calls it once, stamps the result on the outcome, and every later decision
// (refusalFor, record) reads the outcome. There is still exactly one
// consultation site; it now has two inputs. compat_org_mode.go holds the
// composition and its proof: an AST test that enumerates every read of the
// two fields across the package and fails on a second site, and a mutant
// that plants one to prove the test can fail.
package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EnvCompatMode names the environment variable selecting the adapter mode.
// Absent or empty means off.
const EnvCompatMode = "AXONFLOW_IDENTITY_COMPAT_MODE"

// CompatRefusalCode is the single machine-readable code every identity-plane
// refusal carries, on every plane and in every rendering.
//
// IT LIVES HERE, NOT IN package agent, AND THAT WAS THE BUG. An earlier
// revision declared it beside the agent's call sites, so the SHARED choke
// point (ResolveToken) structurally could not use it - and that is the fifth
// rendering. An operator filtering on this code during an enforce rollout
// would have missed every refusal from the fleet path, which is exactly the
// conflation the constant was introduced to end.
//
// The conflation it ends: an identity-plane refusal previously shared
// "invalid_user_token" with a tampered signature, so "my realm configuration
// is wrong" and "someone is forging tokens" were indistinguishable.
const CompatRefusalCode = "identity_realm_refused"

// EnvEnforceReasons narrows what enforce mode refuses, to a comma-separated
// allow-list of AdmissionReason codes. Empty means every reason.
//
// # WHY THE ALL-OR-NOTHING SWITCH IS NOT ENOUGH
//
// Mode is process-wide, and the divergences this plane surfaces are per-(org,
// path) CONSTANTS rather than tail events: a plugin fleet asserting only an
// email produces SUBJECT_MISSING on every request it ever makes, and an org
// with no enabled SSO row produces UNKNOWN_REALM on all of its token traffic.
// So an operator who has cleared their undeclared issuers and their org claims
// still cannot turn enforce on, because doing so also turns on the one
// divergence they have not cleared, across their whole fleet, at once.
//
// The allow-list is the axis that makes a staged rollout possible without
// per-org state: enforce the reasons you have driven to zero in shadow, keep
// recording the rest. It can only ever NARROW what enforce refuses - an empty
// or absent value is the full set, and a reason not on the list is recorded
// exactly as it would be in shadow.
const EnvEnforceReasons = "AXONFLOW_IDENTITY_COMPAT_ENFORCE_REASONS"

// CompatMode is the tri-state selecting what the adapters do.
//
// It is a tri-state validated by MEMBERSHIP, not by inequality against its
// zero value, for the reason DirectorySource.IsValid spells out: a check of
// the form `m != CompatModeUnspecified` admits every other out-of-range value,
// and CompatMode(99) would then fall through whichever branch happens to be
// last. Here membership additionally decides which direction an unrecognized
// value fails, and it fails towards OFF: an adapter that enforces on a value
// nobody declared would take a deployment's authentication down on a typo.
type CompatMode int

const (
	// CompatModeUnspecified is the zero value. NewCompatAdapter refuses it, so
	// no constructed adapter holds it.
	CompatModeUnspecified CompatMode = iota
	// CompatModeOff evaluates nothing. The default.
	CompatModeOff
	// CompatModeShadow evaluates and records, and never refuses.
	CompatModeShadow
	// CompatModeEnforce evaluates, records, and refuses a request the legacy
	// path accepted and the identity plane does not.
	CompatModeEnforce
)

// IsValid reports whether m is one of the declared modes.
func (m CompatMode) IsValid() bool {
	switch m {
	case CompatModeOff, CompatModeShadow, CompatModeEnforce:
		return true
	default:
		return false
	}
}

// evaluates reports whether this mode runs the identity plane at all.
//
// It is a POSITIVE membership test, deliberately not `m != CompatModeOff`.
// The two differ on every out-of-range value, and the difference is the whole
// safety argument: with inequality, CompatMode(99) evaluates and (below) is
// then only one more inequality away from enforcing.
func (m CompatMode) evaluates() bool {
	return m == CompatModeShadow || m == CompatModeEnforce
}

// enforces reports whether this mode may produce a refusal. Positive
// membership on the single value that enforces, for the same reason.
func (m CompatMode) enforces() bool { return m == CompatModeEnforce }

// String renders the mode.
func (m CompatMode) String() string {
	switch m {
	case CompatModeOff:
		return "off"
	case CompatModeShadow:
		return "shadow"
	case CompatModeEnforce:
		return "enforce"
	case CompatModeUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("CompatMode(%d)", int(m))
	}
}

// ParseEnforceReasons parses the comma-separated allow-list.
//
// An unrecognized reason code is an ERROR, not a silently dropped entry: an
// operator who typed ORG_BINDING_MISMATH believes they are enforcing it, and a
// list that quietly ignored the typo would enforce nothing while reading as
// though it enforced one thing. Same reasoning as ParseCompatMode.
func ParseEnforceReasons(raw string) ([]AdmissionReason, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []AdmissionReason
	for _, field := range strings.Split(raw, ",") {
		name := AdmissionReason(strings.ToUpper(strings.TrimSpace(field)))
		if name == "" {
			continue
		}
		if !enforceableReasons[name] {
			return nil, fmt.Errorf(
				"identity: %s names reason %q, which is not one this plane can refuse on; the enforceable reasons are %v",
				EnvEnforceReasons, name, enforceableReasonNames())
		}
		out = append(out, name)
	}
	return out, nil
}

// enforceableReasons is the closed set a deployment may list.
//
// It is the reasons an adapter can actually produce for a legacy-ACCEPTED
// credential, which is the only shape that enforces. Listing a reason outside
// it would silently enforce nothing.
var enforceableReasons = map[AdmissionReason]bool{
	ReasonUnknownRealm:              true,
	ReasonRealmDisabled:             true,
	ReasonOrgBindingMismatch:        true,
	ReasonUnsupportedCredentialType: true,
	ReasonUnsupportedAlgorithm:      true,
	ReasonAudienceRejected:          true,
	ReasonAuthorizedPartyRejected:   true,
	ReasonSubjectTypeRejected:       true,
	ReasonCredentialExpired:         true,
	ReasonCredentialNotYetValid:     true,
	ReasonCredentialTooOld:          true,
	ReasonAssuranceInsufficient:     true,
	ReasonCredentialRevoked:         true,
	ReasonRevocationUnavailable:     true,
	ReasonSubjectMissing:            true,
	ReasonMalformedPrincipal:        true,
	ReasonKeyMaterialUnavailable:    true,
	ReasonIdentityInternalError:     true,
}

// enforceableReasonNames returns the closed set, sorted, for an error message.
func enforceableReasonNames() []string {
	out := make([]string, 0, len(enforceableReasons))
	for r := range enforceableReasons {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}

// ParseCompatMode maps the configured string to a mode.
//
// An empty value is off - that is the unconfigured deployment, and it is the
// only spelling of "off by omission" this function accepts. Anything else that
// is not a declared mode is an ERROR, not a silent off: an operator who typed
// "enfore" believes their deployment enforces, and a shim that quietly
// disabled itself would leave them believing it for as long as it took to
// notice. The wiring turns that error into a refusal to boot.
func ParseCompatMode(raw string) (CompatMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return CompatModeOff, nil
	case "off", "false", "0", "disabled":
		return CompatModeOff, nil
	case "shadow":
		return CompatModeShadow, nil
	case "enforce":
		return CompatModeEnforce, nil
	default:
		return CompatModeUnspecified, fmt.Errorf(
			"identity: %s=%q is not a recognized mode (off, shadow, enforce); refusing to guess, because guessing 'off' would leave an operator believing the identity plane is enforcing when it is not",
			EnvCompatMode, raw)
	}
}

// LegacyPath names which legacy credential path presented the credential. It
// is a closed vocabulary: an unrecognized path is an adapter bug, and Resolve
// refuses to evaluate one rather than attribute a counterfactual to a path
// name no dashboard has a row for.
type LegacyPath string

const (
	// LegacyPathHS256 is the AxonFlow HS256 bearer-JWT path: the agent's
	// validateUserToken and the fleet plane's Path A validator.
	LegacyPathHS256 LegacyPath = "hs256"
	// LegacyPathOIDC is the IdP-issued OIDC path: the fleet plane's Path B
	// verifier and the customer-portal interactive SSO login.
	LegacyPathOIDC LegacyPath = "oidc"
	// LegacyPathAPICredential is an AxonFlow-issued client credential: the
	// Ed25519 license key, the bcrypt API key, the community-SaaS
	// registration secret, and the internal-service HMAC token.
	LegacyPathAPICredential LegacyPath = "api_credential"
	// LegacyPathTrustedHeader is an upstream-asserted identity header
	// (X-User-Email / X-User-ID) honored only under the #2896 trust gate.
	LegacyPathTrustedHeader LegacyPath = "trusted_header"
)

var legacyPaths = []LegacyPath{
	LegacyPathHS256, LegacyPathOIDC, LegacyPathAPICredential, LegacyPathTrustedHeader,
}

// IsValid reports whether p is a declared legacy path.
func (p LegacyPath) IsValid() bool {
	for _, known := range legacyPaths {
		if p == known {
			return true
		}
	}
	return false
}

// LegacyDecision is what the legacy path decided BEFORE the adapter ran.
//
// A tri-state rather than a bool, and validated by membership, because the
// zero value of a bool is "rejected", and a caller that forgot to set it would
// silently turn every request into the one comparison that can never produce a
// divergence worth acting on. The zero value here is refused instead.
type LegacyDecision int

const (
	// LegacyDecisionUnspecified is the zero value and is refused.
	LegacyDecisionUnspecified LegacyDecision = iota
	// LegacyDecisionAccepted means the legacy path authenticated the caller.
	LegacyDecisionAccepted
	// LegacyDecisionRejected means the legacy path refused the caller.
	LegacyDecisionRejected
)

// IsValid reports whether d is one of the declared decisions.
func (d LegacyDecision) IsValid() bool {
	switch d {
	case LegacyDecisionAccepted, LegacyDecisionRejected:
		return true
	default:
		return false
	}
}

// String renders the decision.
func (d LegacyDecision) String() string {
	switch d {
	case LegacyDecisionAccepted:
		return "accepted"
	case LegacyDecisionRejected:
		return "rejected"
	case LegacyDecisionUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("LegacyDecision(%d)", int(d))
	}
}

// CompatDivergence classifies the legacy decision against the identity
// plane's. It is the shadow phase's whole output.
type CompatDivergence string

const (
	// DivergenceNotEvaluated means the adapter did not run: mode off, or an
	// adapter-side input defect. It is NOT "no divergence" - nothing was
	// compared - and the two are kept apart so a dashboard cannot read a
	// switched-off deployment as a clean one.
	DivergenceNotEvaluated CompatDivergence = "not_evaluated"
	// DivergenceNone means both planes agreed.
	DivergenceNone CompatDivergence = "none"
	// DivergenceIdentityRefused means legacy accepted and the identity plane
	// DENIED. This is the expected, actionable shadow finding: EX-47's
	// undeclared issuer, a wrong-but-non-empty org claim, an audience the
	// realm does not accept.
	DivergenceIdentityRefused CompatDivergence = "identity_refused"
	// DivergenceIdentityIndeterminate means legacy accepted and the identity
	// plane could not tell - a revocation outage, unavailable key material, a
	// realm source that could not be read. Distinct from a refusal because the
	// remedy is an outage fix, not a configuration change.
	DivergenceIdentityIndeterminate CompatDivergence = "identity_indeterminate"
	// DivergenceIdentityAdmittedLegacyRejected means legacy REJECTED and the
	// identity plane admitted. It must be unreachable: the adapter only ever
	// feeds the identity plane a credential the legacy path already verified,
	// and a rejected credential reaches VerifyCredential with
	// SignatureVerified false, which is a Deny. If this is ever recorded, the
	// adapter itself is laundering an unverified credential, which is strictly
	// worse than any divergence in the other direction - hence its own code.
	DivergenceIdentityAdmittedLegacyRejected CompatDivergence = "identity_admitted_legacy_rejected"
	// DivergenceAdapterDefect means the adapter could not evaluate because its
	// own input was malformed. It never enforces (see Resolve).
	DivergenceAdapterDefect CompatDivergence = "adapter_defect"
)

// LegacyAuth is one legacy authentication outcome, decomposed into what the
// identity plane needs to form its own opinion about the same request.
type LegacyAuth struct {
	// Path names the legacy credential path.
	Path LegacyPath
	// AuthenticatedOrgID is the organization the CREDENTIAL authenticated as,
	// established upstream. Never a claim out of the credential under
	// verification and never a caller-supplied header.
	AuthenticatedOrgID string
	// Decision is what the legacy path decided.
	Decision LegacyDecision
	// LegacyReason is why the legacy path refused, for the counterfactual
	// record.
	//
	// It is a REASON rather than a credential, but it is not free of values
	// read out of one: a validator's error text can quote a claim it rejected
	// (the HS256 validator names the token's org_id on a mismatch), and the
	// OIDC arm wraps the parser's own message. It is sanitized before it is
	// logged and it never carries a secret, a signature or a bearer token.
	LegacyReason string
	// Credential is the realm-verification input. When Claims is non-nil the
	// adapter OVERWRITES Subject and Aliases from the realm's claim mapping
	// (see Claims); every other field is the caller's.
	Credential Credential
	// Claims is the verified claim set for claim-bearing credentials (HS256,
	// OIDC), nil for the others.
	//
	// When it is non-nil, the realm's ClaimMapping - not the caller - decides
	// which claim is the canonical subject and which are aliases. A caller
	// cannot pre-set Credential.Subject and have it honored, because that is
	// exactly the route by which "the configured subject claim was absent, so
	// we used the email" gets reintroduced one adapter at a time. ADR-065
	// invariant 3 is enforced here, not asked for.
	Claims map[string]any
	// UnverifiableReason records that the legacy path could not REACH a
	// verdict about this credential, and names why. Empty for every ordinary
	// accept and every ordinary reject.
	//
	// It exists so that "your IdP is unreachable" does not reach the operator
	// as "this credential's signature did not verify". Without it, a JWKS
	// outage records as SIGNATURE_NOT_VERIFIED, which is the wording for a
	// forgery and sends an operator to the wrong investigation.
	//
	// It is tightly constrained and can only ever make the adapter MORE
	// conservative: compatUnverifiableReasons is a two-element allow-list, the
	// outcome it produces is always Indeterminate, and Indeterminate is never
	// an admission. A caller cannot use it to manufacture an acceptance
	// because the adapter has no acceptance to manufacture (see the file doc's
	// one-direction invariant). A value outside the allow-list, or one paired
	// with an accepted decision, is an adapter defect and refuses to evaluate.
	UnverifiableReason AdmissionReason

	// Synthetic marks a request driven by AxonFlow's own observation-window
	// canary rather than by a tenant (#3602).
	//
	// # WHY THE OBSERVATION GATE NEEDS IT
	//
	// A canary exists to give the shadow window a denominator, so its
	// comparisons MUST count towards coverage - a path only the canary
	// exercises is still an exercised path. But they must be excludable from
	// any volume floor, or "this deployment saw 3,000 comparisons" turns into
	// a statement about our own probe rather than about production traffic.
	// Both readings are needed, so the fact is a LABEL, not a filter.
	//
	// # ITS FORGERY DIRECTION IS SAFE, WHICH IS WHY A HEADER CAN CARRY IT
	//
	// Call sites set it from a request header, which is caller-assertable. A
	// tenant that tagged its own traffic synthetic would EXCLUDE that traffic
	// from the volume floors - making the coverage gate harder to satisfy, not
	// easier. It cannot manufacture coverage, because a synthetic comparison
	// is still a comparison and still lands in the same divergence class. It
	// decides nothing about admission and is never read by VerifyCredential.
	Synthetic bool
}

// SyntheticProbeHeader is the request header AxonFlow's own canary sets to
// mark a comparison as synthetic. See LegacyAuth.Synthetic for why a
// caller-assertable channel is acceptable for this one fact.
const SyntheticProbeHeader = "X-Axonflow-Synthetic-Probe"

// IsSyntheticProbeHeader reports whether a header value marks a synthetic
// probe.
//
// A POSITIVE membership test on the two spellings the canary sends, not
// "non-empty": a header echoed back by a proxy, or one a caller set to "0" or
// "false" meaning to turn it OFF, must not read as true.
func IsSyntheticProbeHeader(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// compatUnverifiableReasons is the closed set a legacy path may report as
// "could not reach a verdict". Both are Indeterminate outcomes in the identity
// plane's own vocabulary, and neither is a Deny - a legacy path that DID reach
// a verdict reports it through Decision, not here.
var compatUnverifiableReasons = map[AdmissionReason]bool{
	ReasonKeyMaterialUnavailable: true,
	ReasonRevocationUnavailable:  true,
}

// CompatRefusal is the ONLY actionable output of the adapter. It exists only
// when the mode enforces, the legacy path accepted, and the identity plane did
// not. It is a pointer so that "no refusal" is a nil check a call site cannot
// get subtly wrong.
type CompatRefusal struct {
	// Path is the legacy path whose credential was refused.
	Path LegacyPath
	// State is the identity plane's state (Deny or Indeterminate; never
	// Accept, which does not produce a refusal).
	State AdmissionState
	// Reason is the identity plane's stable reason code.
	Reason AdmissionReason
	// Detail is the identity plane's human-readable detail. It is built from
	// realm configuration and reason codes, never from credential material.
	Detail string
}

// Error renders the refusal. CompatRefusal implements error so a call site can
// wrap it without inventing its own wording.
func (r *CompatRefusal) Error() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("identity compat (%s): %s %s: %s", r.Path, r.State, r.Reason, r.Detail)
}

// CompatOutcome is what Resolve returns.
//
// Refusal is deliberately an unexported field behind an accessor: a value of
// this type constructed outside the package can never carry one, so a call
// site cannot be handed an enforcement decision by anything but Resolve.
type CompatOutcome struct {
	// Mode is the mode the adapter ran in.
	Mode CompatMode
	// Path echoes the input path.
	Path LegacyPath
	// Evaluated reports whether the adapter reached a verdict about this
	// credential. It is TRUE on the two branches that short-circuit realm
	// verification (a realm-source outage, and a legacy path that could not
	// verify), because both produce an outcome the adapter stands behind and
	// both can carry a refusal - an enforced 401 recorded as "not evaluated"
	// is a contradiction a dashboard would have to explain. It is false only
	// under mode off and on an adapter-side input defect, where the adapter
	// deliberately has no opinion.
	Evaluated bool
	// Subject is the identity plane's verdict. Zero unless Evaluated.
	Subject VerifiedSubject
	// Divergence classifies the two planes against each other.
	Divergence CompatDivergence

	refusal *CompatRefusal
}

// Refusal returns the enforcement decision, or nil. It is the only field a
// call site may act on.
func (o CompatOutcome) Refusal() *CompatRefusal { return o.refusal }

// CounterfactualRecorder receives every evaluated outcome. A shadow phase that
// records nothing is a shadow phase that has not run, so NewCompatAdapter
// refuses a nil recorder.
type CounterfactualRecorder interface {
	// RecordCounterfactual is called exactly once per evaluated Resolve, in
	// both shadow and enforce mode. Implementations must not block: this runs
	// on the authentication path.
	RecordCounterfactual(ctx context.Context, rec Counterfactual)
}

// Counterfactual is one recorded comparison. Every field is either a reason
// code, a configuration identifier, or a canonical principal - never a token,
// a secret, a header value, or a raw claim.
type Counterfactual struct {
	// Mode is the mode that produced this record.
	Mode CompatMode
	// Component names the binary that recorded it. Two processes bind a
	// principal and both log under the same [IDENTITY-COMPAT] prefix, so
	// without this a divergence cannot be attributed to a plane except by
	// which container's log it came from - and the release plan's gate is
	// stated per plane.
	Component string
	// Path is the legacy credential path.
	Path LegacyPath
	// OrgID is the authenticated organization.
	OrgID string
	// LegacyDecision is what the legacy path decided.
	LegacyDecision LegacyDecision
	// LegacyReason is why, when it refused.
	LegacyReason string
	// IdentityState is the identity plane's state.
	IdentityState AdmissionState
	// IdentityReason is the identity plane's reason code.
	IdentityReason AdmissionReason
	// IdentityDetail is the identity plane's human-readable explanation.
	//
	// IT IS THE FIELD THAT MAKES A SHADOW PHASE ACTIONABLE, and an earlier
	// revision dropped it on the floor while two call-site comments justified
	// keeping it off a 401 by saying it was "in the counterfactual record,
	// which is where an operator looks". It was not in the record at all.
	// UNKNOWN_REALM without it says some issuer is undeclared and not WHICH,
	// and finding the undeclared issuers is the entire EX-47 exercise.
	//
	// It is built from realm configuration and reason codes and is sanitized
	// before it is logged. It is deliberately NOT surfaced to a caller: see
	// the reason-code-only rendering at every refusal site.
	IdentityDetail string
	// Divergence is the classification.
	Divergence CompatDivergence
	// RealmID is the realm that accepted the credential, empty when none did.
	RealmID RealmID
	// Principal is the canonical principal in wire form, empty unless the
	// identity plane admitted. A canonical principal is a realm-qualified
	// identifier the operator declared; it is not credential material.
	Principal string
	// IdentityEpoch is the registry epoch at evaluation time.
	IdentityEpoch int64
	// Enforced reports whether this record's refusal was applied to the
	// request. False for every shadow record.
	Enforced bool
	// Synthetic echoes LegacyAuth.Synthetic: this comparison was driven by
	// AxonFlow's own observation-window canary (#3602).
	Synthetic bool
}

// FailOpenDirection says which way an admission difference runs.
//
// # WHY THIS EXISTS ALONGSIDE CompatDivergence
//
// The divergence classes already distinguish the two directions, but they do
// it by NAME - identity_refused versus identity_admitted_legacy_rejected - and
// an operator scanning a dashboard has to know which of those two is the
// dangerous one. Gate 18 is specifically about fail-OPEN differences, so the
// direction gets its own axis, and the safe direction can be read at a glance
// rather than decoded.
//
// The spellings are IDENTICAL to shadow.FailOpenDirection in
// platform/decision/legacycompile/shadow/classify.go, deliberately: the CI
// gate's summary line and the production metric describe the same property,
// and two vocabularies for one property is how a dashboard and a gate come to
// disagree about whether the window is clean.
type FailOpenDirection string

const (
	// FailOpenNone means the two planes agree on admission.
	FailOpenNone FailOpenDirection = "none"
	// FailOpenLegacyPermitted means legacy admitted and the identity plane did
	// not. The SAFE direction: the new plane is stricter. It is what enforce
	// mode would act on.
	FailOpenLegacyPermitted FailOpenDirection = "legacy_permitted_new_denied"
	// FailOpenNewPermitted means the identity plane admitted a credential
	// legacy REJECTED. The fail-open direction, and the one gate 18 names.
	// Unreachable by construction (compat_paths.go sets SignatureVerified from
	// the legacy decision), which is exactly why it gets its own axis: an
	// unreachable class that starts moving must be impossible to miss.
	FailOpenNewPermitted FailOpenDirection = "new_permitted_legacy_denied"
)

// FailOpen reports which way this record's difference runs.
//
// It is derived from the two ADMISSION decisions rather than from the
// divergence class, so a divergence class added later cannot silently land in
// "none": the identity side is a closed tri-state and IsAdmitted is its only
// sanctioned reader.
func (c Counterfactual) FailOpen() FailOpenDirection {
	legacyAdmitted := c.LegacyDecision == LegacyDecisionAccepted
	identityAdmitted := c.IdentityState.IsAdmitted()
	switch {
	case legacyAdmitted == identityAdmitted:
		return FailOpenNone
	case legacyAdmitted:
		return FailOpenLegacyPermitted
	default:
		return FailOpenNewPermitted
	}
}

// CompatRealmSource registers an organization's trust realms into the registry
// on demand. It is separate from the registry so that where realms COME from
// (built-in deployment realms today, a persisted table in a later PR) can
// change without touching the adapter.
type CompatRealmSource interface {
	// EnsureRealms registers orgID's realms, idempotently. It must be safe to
	// call on every request. An error means the organization's realms could
	// not be established, which is an outage, not an empty realm set.
	EnsureRealms(ctx context.Context, orgID string) error
}

// CompatAdapter bridges one legacy path's outcome into the identity plane.
//
// One adapter serves all four paths. They differ only in how their credential
// is built (compat_paths.go), never in how the verdict is reached, recorded or
// enforced - which is what makes "an adapter path that enforces in shadow"
// impossible to introduce in one path without introducing it in all four.
type CompatAdapter struct {
	component string
	// enforceReasons narrows what enforce refuses. Nil means every reason.
	enforceReasons map[AdmissionReason]bool
	// paths narrows which legacy credential paths evaluate at all (#3634).
	//
	// NIL MEANS EVERY PATH, which is the unset deployment and therefore almost
	// every deployment. It is read through CompatPathEvaluates rather than
	// indexed directly, because a bare `a.paths[p]` reads nil as FALSE and
	// would silently stop evaluating everything on a deployment that
	// configured nothing - the failure the fatal parse exists to prevent,
	// arriving by the one route that produces no error at all.
	paths       map[LegacyPath]bool
	registry    *RealmRegistry
	realms      CompatRealmSource
	revocations RevocationOracle
	recorder    CounterfactualRecorder
	// processMode is the deployment-wide mode from AXONFLOW_IDENTITY_COMPAT_MODE.
	//
	// IT IS READ IN EXACTLY ONE FUNCTION, effectiveMode, and nowhere else in
	// this package (Mode, the diagnostics accessor, reports it and decides
	// nothing). The name is deliberately unique so that
	// TestCompatModeIsConsultedAtExactlyOneSite can find every read of it
	// syntactically, in every file of the package, under both build tags.
	processMode CompatMode
	// orgModes is the per-organization override source (#3550, session
	// ADR65-I). Nil means the process mode is the whole answer, which is
	// every community build and every deployment with no settings store.
	// Read in exactly the same one function as processMode.
	orgModes CompatOrgModeSource
	now      func() time.Time
	// orgModeFailures counts org-record reads that failed and fell back to
	// the process mode. Exposed through OrgModeFailures so a test or an
	// operator command can tell "no org has a record" from "the records could
	// not be read".
	orgModeFailures atomic.Uint64
}

// CompatAdapterOption customizes the adapter.
type CompatAdapterOption func(*CompatAdapter)

// WithCompatClock overrides the clock. Test seam only.
func WithCompatClock(now func() time.Time) CompatAdapterOption {
	return func(a *CompatAdapter) {
		if now != nil {
			a.now = now
		}
	}
}

// WithCompatComponent names the binary this adapter runs in, so a
// counterfactual can be attributed to a plane rather than to whichever
// container's log it was read from.
func WithCompatComponent(component string) CompatAdapterOption {
	return func(a *CompatAdapter) { a.component = component }
}

// WithCompatEnforceReasons narrows what enforce mode refuses. An empty or nil
// set means every reason, which is the default. See EnvEnforceReasons.
func WithCompatEnforceReasons(reasons []AdmissionReason) CompatAdapterOption {
	return func(a *CompatAdapter) {
		if len(reasons) == 0 {
			a.enforceReasons = nil
			return
		}
		set := make(map[AdmissionReason]bool, len(reasons))
		for _, r := range reasons {
			set[r] = true
		}
		a.enforceReasons = set
	}
}

// WithCompatPaths narrows which legacy credential paths evaluate (#3634).
//
// An empty or nil set means EVERY path, which is the default and the only
// complete window. A narrowed set is a deliberate, temporary posture: the paths
// it omits take the same early return an off mode takes, so they record nothing
// and refuse nothing, and gate 18's coverage for them stops accruing while it
// is in place.
func WithCompatPaths(paths map[LegacyPath]bool) CompatAdapterOption {
	return func(a *CompatAdapter) {
		if len(paths) == 0 {
			a.paths = nil
			return
		}
		set := make(map[LegacyPath]bool, len(paths))
		for p, on := range paths {
			if on {
				set[p] = true
			}
		}
		// A set whose every entry was false is a narrowing that names nothing,
		// and storing it would evaluate no path at all. Nil is the honest
		// reading and matches the parser, which refuses that input outright.
		if len(set) == 0 {
			a.paths = nil
			return
		}
		a.paths = set
	}
}

// WithCompatRevocations wires the revocation oracle consulted for realms that
// declare a revocation source. Absent it, such a realm yields
// Indeterminate(REVOCATION_UNAVAILABLE) - which is correct and is why this is
// an option rather than a required argument: a deployment whose realms all
// declare RevocationSourceNone needs no oracle.
func WithCompatRevocations(o RevocationOracle) CompatAdapterOption {
	return func(a *CompatAdapter) { a.revocations = o }
}

// NewCompatAdapter builds an adapter.
//
// It refuses every argument whose absence would make the adapter quietly
// useless or quietly wrong: an unrecognized mode, a nil registry (nothing to
// verify against), a nil realm source (no realm would ever be declared, so
// every credential would be UNKNOWN_REALM and the shadow would be pure noise),
// and a nil recorder (a shadow phase that records nothing).
func NewCompatAdapter(
	mode CompatMode,
	registry *RealmRegistry,
	realms CompatRealmSource,
	recorder CounterfactualRecorder,
	opts ...CompatAdapterOption,
) (*CompatAdapter, error) {
	if !mode.IsValid() {
		return nil, fmt.Errorf("identity: compat adapter mode %s is not a declared mode", mode)
	}
	if registry == nil {
		return nil, fmt.Errorf("identity: compat adapter requires a realm registry")
	}
	if realms == nil {
		return nil, fmt.Errorf("identity: compat adapter requires a realm source; without one every credential is UNKNOWN_REALM and the shadow records nothing an operator can act on")
	}
	if reason := recorderRecordsNothing(recorder); reason != "" {
		return nil, fmt.Errorf("identity: compat adapter requires a counterfactual recorder that records something: %s", reason)
	}
	a := &CompatAdapter{
		registry:    registry,
		realms:      realms,
		recorder:    recorder,
		processMode: mode,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// recorderRecordsNothing returns a non-empty reason when this recorder is one
// of the shapes that construct successfully and then record NOTHING, which is
// the exact state the constructor exists to refuse.
//
// AN EARLIER VERSION USED reflect.ValueOf(recorder).IsZero() AND WAS WRONG IN
// BOTH DIRECTIONS. For a slice, IsZero is IsNil, so it caught only
// `var m MultiCounterfactualRecorder` - the ACCIDENTAL spelling - while
// `MultiCounterfactualRecorder{}`, the spelling anyone writing a fan-out
// actually types, sailed through. And it REFUSED a legitimate stateless
// recorder: a `type MetricsRecorder struct{}` with a value receiver, emitting
// counters, is a zero value that records perfectly well.
//
// So the test is on the SHAPES that cannot record, named one at a time, rather
// than on a reflective proxy for them.
func recorderRecordsNothing(recorder CounterfactualRecorder) string {
	if recorder == nil {
		return "no recorder was supplied"
	}
	switch r := recorder.(type) {
	case *LogCounterfactualRecorder:
		if r == nil {
			return "the log recorder is a typed nil, whose RecordCounterfactual returns immediately"
		}
	case MultiCounterfactualRecorder:
		// Both a nil slice and an empty one iterate nothing, and so does a
		// fan-out whose every member is nil. Nil-SKIPPING inside a non-empty
		// fan-out is a deliberate feature (an edition that wires no metrics
		// recorder); a fan-out with nothing BUT nils is not.
		for _, member := range r {
			if member != nil && recorderRecordsNothing(member) == "" {
				return ""
			}
		}
		return "the fan-out has no member that records anything"
	}
	return ""
}

// Mode reports the adapter's PROCESS-WIDE mode. For diagnostics and startup
// logging only - no call site may branch on it (see the file doc), and it is
// not the mode a request ran in: that is CompatOutcome.Mode, which composes
// this value with the organization's record (see effectiveMode).
func (a *CompatAdapter) Mode() CompatMode {
	if a == nil {
		return CompatModeOff
	}
	return a.processMode
}

// Resolve is THE single entry function for every legacy path.
//
// A nil adapter is off, so an unwired deployment needs no nil check at any
// call site.
func (a *CompatAdapter) Resolve(ctx context.Context, in LegacyAuth) CompatOutcome {
	if a == nil {
		return CompatOutcome{Mode: CompatModeOff, Path: in.Path, Divergence: DivergenceNotEvaluated}
	}

	// The organization is TRIMMED ONCE, here, and the trimmed value is what
	// every lookup and every record uses. Validating a trimmed value and then
	// keying on the raw one makes " acme" and "acme" two realm namespaces,
	// two registry entries and two halves of one organization's shadow data.
	// It is trimmed BEFORE the mode is resolved because the mode is now a
	// per-organization fact, and " acme" must not resolve to a different mode
	// than "acme".
	in.AuthenticatedOrgID = strings.TrimSpace(in.AuthenticatedOrgID)

	// THE PER-PATH LEVER (#3634), CHECKED BEFORE THE MODE IS EVEN READ.
	//
	// A path taken out of the configured set evaluates as `off` FOR THAT PATH
	// ONLY, and it takes the identical early return the mode-off branch takes
	// below: no clock read, no registry touch, no recorder call, no
	// allocation. That sameness is the point rather than a convenience - "off
	// for this path" has to mean exactly what "off" means, or the lever would
	// be a third posture with its own behaviour to reason about, and an
	// operator reaching for it during an incident would be trying something
	// new at the worst moment.
	//
	// It is deliberately ABOVE effectiveMode: the mode read can touch the
	// per-organization settings store, and a path an operator has switched off
	// should not be able to fail on a database lookup it was excluded from.
	if !CompatPathEvaluates(a.paths, in.Path) {
		return CompatOutcome{Mode: CompatModeOff, Path: in.Path, Divergence: DivergenceNotEvaluated}
	}

	// THE ONE MODE READ. `mode` is a local from here down: every branch below
	// stamps it on its outcome and refusalFor/record read it back off the
	// outcome, so nothing after this line consults the adapter's fields for a
	// mode. effectiveMode is the single function that does.
	mode := a.effectiveMode(ctx, in.AuthenticatedOrgID)
	if !mode.evaluates() {
		// Mode off. Nothing below this line runs: no clock read, no registry
		// touch, no recorder call, no allocation. This is the whole of the
		// "flag off is byte-identical" guarantee, and with a per-organization
		// source wired it holds for every organization whose resolved mode is
		// off - which, absent a record, is every organization.
		return CompatOutcome{Mode: mode, Path: in.Path, Divergence: DivergenceNotEvaluated}
	}

	// Adapter-side input defects. These are OUR bug, not the caller's, and
	// they deliberately do not enforce: refusing a request because this
	// package was handed a malformed LegacyAuth would take authentication down
	// for a defect the operator cannot fix. They are recorded loudly instead,
	// under their own divergence code, so "the adapter is broken" can never be
	// read off a dashboard as "the two planes agree".
	if defect := validateLegacyAuth(in); defect != "" {
		out := CompatOutcome{Mode: mode, Path: in.Path, Divergence: DivergenceAdapterDefect}
		out.Subject = VerifiedSubject{Admission: IndeterminateAdmission(ReasonIdentityInternalError, defect)}
		a.record(ctx, in, out)
		return out
	}

	// Realms first. A realm source that cannot answer is an outage, and an
	// outage is Indeterminate - never an empty realm set, which would present
	// as UNKNOWN_REALM and send an operator to declare a realm that already
	// exists.
	realmCtx, cancelRealms := boundedRealmContext(ctx)
	realmErr := a.realms.EnsureRealms(realmCtx, in.AuthenticatedOrgID)
	cancelRealms()
	if realmErr != nil && !a.issuerIsDeclared(in) {
		// The realm source could not answer AND this credential's issuer does
		// not resolve, so nothing can be said about it.
		//
		// THE ISSUER CHECK IS WHAT KEEPS ONE SOURCE'S FAILURE FROM TAKING DOWN
		// THE OTHERS. A realm source is a chain: the built-ins register once
		// and never fail again, while the tenant OIDC source reads a database
		// row on a TTL and can fail for reasons that have nothing to do with
		// the credential in hand. Without this, one unreadable
		// sso_configurations row refused EVERY path for that organization
		// under enforce - the client credential, the internal-service hop and
		// the HS256 token included, none of which involves OIDC.
		//
		// It is not a fail-open: a resolved issuer means that realm's full
		// declaration is registered and VerifyCredential applies all of it. A
		// credential whose issuer is genuinely undeclared still cannot be
		// distinguished from one whose realm could not be read, which is why
		// that case stays Indeterminate rather than becoming UNKNOWN_REALM.
		out := CompatOutcome{Mode: mode, Path: in.Path, Evaluated: true}
		out.Subject = VerifiedSubject{Admission: IndeterminateAdmission(
			ReasonIdentityInternalError,
			fmt.Sprintf("the organization's trust realms could not be established: %v", realmErr))}
		out.Divergence = classifyDivergence(in.Decision, out.Subject.Admission.State)
		out.refusal = a.refusalFor(in, out)
		a.record(ctx, in, out)
		return out
	}

	// A legacy path that could not reach a verdict short-circuits realm
	// verification. Running it anyway would produce SIGNATURE_NOT_VERIFIED -
	// technically true, since nothing verified the signature, and the wrong
	// answer to give an operator whose IdP is down. validateLegacyAuth has
	// already established that this can only be an Indeterminate cause paired
	// with a legacy rejection, so this branch can never widen anything.
	if in.UnverifiableReason != "" {
		out := CompatOutcome{Mode: mode, Path: in.Path, Evaluated: true}
		out.Subject = VerifiedSubject{Admission: IndeterminateAdmission(
			in.UnverifiableReason,
			fmt.Sprintf("the %s path could not obtain what it needed to verify the credential", in.Path))}
		out.Divergence = classifyDivergence(in.Decision, out.Subject.Admission.State)
		out.refusal = a.refusalFor(in, out)
		a.record(ctx, in, out)
		return out
	}

	cred, mappingRealm, mappingFound := a.completeCredential(in)
	subject := VerifyCredential(a.registry, in.AuthenticatedOrgID, cred, a.now(), a.revocations)

	// THE CLAIM MAPPING AND THE VERIFICATION CAME FROM TWO SEPARATE LOOKUPS.
	//
	// completeCredential reads the realm to learn which claim is canonical;
	// VerifyCredential reads it again, under its own lock, together with the
	// epoch. realm_verify.go argues at length that the realm and the epoch
	// must be read under ONE lock, and this adapter reintroduces exactly that
	// window one frame up: a concurrent re-registration between the two reads
	// would extract the subject with the OLD mapping and then stamp the NEW
	// epoch onto it, so a proof that should be detectably stale reads as
	// current.
	//
	// Rather than restructure a merged API, the two are compared. A
	// disagreement is Indeterminate: the subject in hand was mapped by a
	// declaration that is no longer the live one, and re-deriving it here
	// would just race again.
	if mappingFound && subject.Admission.State.IsAdmitted() &&
		(subject.Realm.Version != mappingRealm.Version ||
			subject.Realm.ClaimMapping.Version != mappingRealm.ClaimMapping.Version) {
		out := CompatOutcome{Mode: mode, Path: in.Path, Evaluated: true}
		out.Subject = VerifiedSubject{Admission: IndeterminateAdmission(
			ReasonIdentityInternalError,
			"the realm was re-declared between reading its claim mapping and verifying against it; the subject was mapped by a declaration that is no longer live")}
		out.Divergence = classifyDivergence(in.Decision, out.Subject.Admission.State)
		out.refusal = a.refusalFor(in, out)
		a.record(ctx, in, out)
		return out
	}

	out := CompatOutcome{
		Mode:       mode,
		Path:       in.Path,
		Evaluated:  true,
		Subject:    subject,
		Divergence: classifyDivergence(in.Decision, subject.Admission.State),
	}
	out.refusal = a.refusalFor(in, out)
	a.record(ctx, in, out)
	return out
}

// validateLegacyAuth returns a non-empty description of an adapter-side input
// defect, or "".
func validateLegacyAuth(in LegacyAuth) string {
	if !in.Path.IsValid() {
		return fmt.Sprintf("legacy path %q is not one of the declared paths %v", in.Path, legacyPaths)
	}
	if !in.Decision.IsValid() {
		return fmt.Sprintf("legacy decision %s is not one of the declared decisions; a caller that leaves it at its zero value would compare against a rejection it never made", in.Decision)
	}
	if strings.TrimSpace(in.AuthenticatedOrgID) == "" {
		// VerifyCredential would also refuse this, with ORG_BINDING_MISMATCH.
		// It is caught here instead because an empty authenticated org on THIS
		// side means the call site did not pass one, which is an adapter
		// wiring defect, not a property of the caller's credential - and
		// attributing it to the caller would send an operator to inspect
		// tokens that are fine.
		return "the call site passed no authenticated organization; the identity plane cannot bind a subject without one"
	}
	if in.Claims == nil {
		// Every one of the four paths presents a claim set, including the two
		// that carry no JWT (their asserted values are presented under the
		// pseudo-claim keys the built-in realms name). A nil map would make
		// completeCredential a no-op and leave the subject wherever the caller
		// put it, which is the next check.
		return "the call site presented no claim set; the canonical subject is taken from the realm's claim mapping, so there is nothing to map"
	}
	if in.Credential.Subject != "" {
		// THE CALLER MAY NOT SUPPLY A SUBJECT. completeCredential overwrites
		// it from the realm's mapping, so a supplied value is either ignored
		// (harmless but misleading) or, if the realm lookup misses, carried
		// through to a refusal that names it. Refusing it outright is what
		// keeps "an alias is never an identifier" a property of this package
		// rather than of each builder's discipline.
		return "the call site supplied a canonical subject; the subject is taken from the realm's claim mapping and never from the adapter's caller"
	}
	if in.UnverifiableReason != "" {
		if !compatUnverifiableReasons[in.UnverifiableReason] {
			return fmt.Sprintf(
				"legacy path reported unverifiable reason %q, which is not one of the reasons a legacy path may report; only an Indeterminate cause may be reported this way",
				in.UnverifiableReason)
		}
		if in.Decision != LegacyDecisionRejected {
			// A path that could not verify a credential cannot also have
			// accepted it. Allowing the pair would let an accepted request be
			// recorded as an outage, which is the one combination that would
			// make the shadow's outage rate meaningless.
			return fmt.Sprintf(
				"legacy path reported unverifiable reason %q alongside decision %s; a path that could not reach a verdict did not accept the credential",
				in.UnverifiableReason, in.Decision)
		}
	}
	return ""
}

// completeCredential fills the claim-derived fields of the credential from the
// realm's claim mapping.
//
// It looks the realm up by issuer to read the mapping, and on a MISS it
// returns the credential unchanged: VerifyCredential owns the UNKNOWN_REALM
// refusal and its wording, and duplicating that decision here is how two
// spellings of the same refusal start to drift.
func (a *CompatAdapter) completeCredential(in LegacyAuth) (Credential, TrustRealm, bool) {
	cred := in.Credential
	if in.Claims == nil {
		return cred, TrustRealm{}, false
	}
	realm, ok := a.registry.LookupByIssuer(in.AuthenticatedOrgID, cred.Issuer)
	if !ok {
		return cred, TrustRealm{}, false
	}
	// The mapping is authoritative for claim-bearing credentials. A
	// caller-supplied Subject is discarded, INCLUDING when the mapped claim is
	// absent - an absent subject claim must produce SUBJECT_MISSING, never a
	// fallback to whatever the caller happened to put there.
	cred.Subject = claimStringFromMap(in.Claims, realm.ClaimMapping.SubjectClaim)
	cred.Aliases = aliasesFromClaims(in.Claims, realm.ClaimMapping.AliasClaims)
	return cred, realm, true
}

// issuerIsDeclared reports whether this credential's issuer already resolves to
// a registered realm, so a failure elsewhere in the realm-source chain does not
// have to refuse it. A credential with no claim set carries no issuer to
// resolve and is not covered.
func (a *CompatAdapter) issuerIsDeclared(in LegacyAuth) bool {
	if strings.TrimSpace(in.Credential.Issuer) == "" {
		return false
	}
	_, ok := a.registry.LookupByIssuer(in.AuthenticatedOrgID, in.Credential.Issuer)
	return ok
}

// claimStringFromMap reads a string claim. A non-string value reads as absent:
// a claim the realm named as the canonical subject, delivered as a number or
// an object, is not a subject this plane can key on, and coercing it would
// make two different JSON shapes produce the same principal.
func claimStringFromMap(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// aliasesFromClaims collects the alias values for the alias kinds the realm
// declared a claim for. Kinds the realm did not map are not collected;
// buildAliases would drop them anyway, and collecting them here would put
// undeclared claim values into a struct that is logged.
func aliasesFromClaims(claims map[string]any, aliasClaims map[AliasKind]string) map[AliasKind]string {
	if len(aliasClaims) == 0 {
		return nil
	}
	var out map[AliasKind]string
	for kind, claim := range aliasClaims {
		v := claimStringFromMap(claims, claim)
		if v == "" {
			continue
		}
		if out == nil {
			out = make(map[AliasKind]string, len(aliasClaims))
		}
		out[kind] = v
	}
	return out
}

// classifyDivergence compares the two planes.
//
// The identity state is tested with IsAdmitted, never `!= AdmissionDeny`:
// Indeterminate and the zero value are both non-admissions, and treating
// either as agreement is the fail-open this classification exists to make
// visible.
func classifyDivergence(legacy LegacyDecision, identity AdmissionState) CompatDivergence {
	admitted := identity.IsAdmitted()
	switch legacy {
	case LegacyDecisionAccepted:
		switch {
		case admitted:
			return DivergenceNone
		case identity == AdmissionDeny:
			return DivergenceIdentityRefused
		default:
			// Indeterminate, and the zero value, which no constructor
			// produces. Both are "could not tell", never "agreed".
			return DivergenceIdentityIndeterminate
		}
	case LegacyDecisionRejected:
		if admitted {
			return DivergenceIdentityAdmittedLegacyRejected
		}
		return DivergenceNone
	default:
		// Unreachable: validateLegacyAuth refuses an undeclared decision
		// before this runs. Classified as a defect rather than as agreement,
		// so a future caller that reaches it is visible instead of silent.
		return DivergenceAdapterDefect
	}
}

// refusalFor builds the enforcement decision. It is the ONLY constructor of a
// *CompatRefusal in this package, and every condition that must hold for a
// request to be refused is in this one function:
//
//   - the mode enforces (positive membership on the single enforcing value),
//   - the legacy path ACCEPTED (so enforcement can only ever narrow; a legacy
//     rejection is already a refusal and needs nothing from us),
//   - the identity plane did NOT admit.
//
// Everything else - every shadow evaluation, every agreement, every
// adapter-side defect - returns nil.
//
// THE MODE IS READ OFF THE OUTCOME, NOT OFF THE ADAPTER. Resolve resolved it
// once for this organization and stamped it there; reading a.processMode here
// instead would be a second consultation site that ignores the organization's
// record, which is exactly the shape the AST guard exists to refuse.
func (a *CompatAdapter) refusalFor(in LegacyAuth, out CompatOutcome) *CompatRefusal {
	if !out.Mode.enforces() {
		return nil
	}
	if in.Decision != LegacyDecisionAccepted {
		return nil
	}
	if out.Subject.Admission.State.IsAdmitted() {
		return nil
	}
	if a.enforceReasons != nil && !a.enforceReasons[out.Subject.Admission.Reason] {
		// A reason the operator has not opted into enforcing. Recorded exactly
		// as it would be in shadow, and not applied. This can only NARROW: an
		// unset allow-list is nil and every reason passes.
		return nil
	}
	return &CompatRefusal{
		Path:   in.Path,
		State:  out.Subject.Admission.State,
		Reason: out.Subject.Admission.Reason,
		Detail: out.Subject.Admission.Detail,
	}
}

// record emits the counterfactual. It runs for every evaluation, in both
// shadow and enforce mode, including the adapter-defect case.
func (a *CompatAdapter) record(ctx context.Context, in LegacyAuth, out CompatOutcome) {
	rec := Counterfactual{
		// The resolved mode for THIS organization, so a record from an
		// organization shadowing under a process-wide off reads mode=shadow
		// and can be told apart from the deployment's default.
		Mode:           out.Mode,
		Component:      a.component,
		Path:           in.Path,
		OrgID:          in.AuthenticatedOrgID,
		LegacyDecision: in.Decision,
		LegacyReason:   in.LegacyReason,
		IdentityState:  out.Subject.Admission.State,
		IdentityReason: out.Subject.Admission.Reason,
		IdentityDetail: out.Subject.Admission.Detail,
		Divergence:     out.Divergence,
		RealmID:        out.Subject.Realm.RealmID,
		IdentityEpoch:  out.Subject.IdentityEpoch,
		Enforced:       out.refusal != nil,
		Synthetic:      in.Synthetic,
	}
	if out.Subject.Admission.State.IsAdmitted() {
		rec.Principal = out.Subject.Admission.Principal.String()
	}
	a.recorder.RecordCounterfactual(ctx, rec)
}

// --- process-wide adapter ---
//
// The adapter is a process singleton because the mode is a deployment
// property, not a per-request one. It is set once at boot and read on the
// authentication path.

var (
	processCompatMu sync.RWMutex
	processCompat   *CompatAdapter
)

// SetProcessCompatAdapter installs the process adapter. Passing nil clears it,
// which is off.
func SetProcessCompatAdapter(a *CompatAdapter) {
	processCompatMu.Lock()
	defer processCompatMu.Unlock()
	processCompat = a
}

// ProcessCompatAdapter returns the installed adapter, or nil.
func ProcessCompatAdapter() *CompatAdapter {
	processCompatMu.RLock()
	defer processCompatMu.RUnlock()
	return processCompat
}

// CompatResolve runs the process adapter. This is what every call site calls,
// and the only thing it may do with the result is read Refusal().
func CompatResolve(ctx context.Context, in LegacyAuth) CompatOutcome {
	return ProcessCompatAdapter().Resolve(ctx, in)
}
