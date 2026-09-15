// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// THE ANCHORED ENGINE'S ENFORCING SEAMS (#3895 PR-A2, #3564; PRD v11 §1).
//
// The ADR-065 anchored engine is the only author of the verdict on every scope
// wired here: decide, the MCP response pass (mcp_response_enforcing_seam.go),
// the gateway pre-check (gateway_request_enforcing_seam.go), /api/request's
// Phase 1 (proxy_request_enforcing_seam.go) and the OpenAI-compatible route
// (openai_compat_handler.go). There is no decision mode (PRD v11 §1.1): nothing
// selects the legacy engine instead, per process or per organization. All of
// them run through ONE enforcer, built here, and every single-phase request
// pass through ONE request path, enforceRequestPass. The active-document read,
// the per-(scope, organization) activation, the identity plane's subject
// admission and the request normalization are the same code for every scope;
// a scope supplies only how its request maps onto the call and how the
// decision maps back onto its wire. A later plane is a scope and a mapping,
// never a second seam.
//
// The properties every scope inherits:
//
//   - An organization with an ACTIVE typed document is decided by the shipped
//     corpus restricted to the scope plus that document. An organization that
//     has published nothing is decided by the shipped corpus plus the
//     deployment's baseline permission pack, composed per process
//     (activation.Inputs.Organization, PRD v11 §1.4). Every request is the
//     anchored engine's, and the wire and the audit row name the bundle that
//     decided it by digest (policy_bundle).
//   - Its detector inputs are the evaluation's own detector facts (the shared
//     engine's Observation), and a detector the plane did not run is ABSENT,
//     which the engine reads as UNKNOWN. Nothing is ever supplied as a
//     fabricated false.
//   - Its subject is admitted by the identity plane. A verified user is the
//     principal (SubjectAdmitter.AdmitDecisionSubject). A request that carries no
//     user identity - every request on a deployment that verifies none, and
//     every OpenAI-compatible request - is evaluated for its authenticated
//     client credential (SubjectAdmitter.AdmitCredentialSubject; ADR-065
//     invariant 2 as amended 2026-09-11 (third), PRD v11 §1.6). A presented
//     user token that did not verify is refused, never replaced by the
//     credential. The wire and the audit row carry the admitted principal's
//     type as subject_type.
//   - An organization's recorded detection overrides reach the engine (#4045):
//     activation folds them into the scope's restriction and the organization
//     root, and a cached engine is rebuilt when they change.
//   - Every failure fails CLOSED naming the cause - the active document, the
//     recorded overrides, the activation, the subject, the request and the
//     engine - and none falls back to the legacy engine.
//
// Edition: community-visible, no build tag. The decision model is
// community_core (ADR-066 driver 3). What differs by edition is upstream of
// this file - which realms can verify a per-user identity - and it decides only
// which door a request's subject is admitted through.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/authoringedition"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	// decisionEngineAnchored is the `engine` value a decision record and a
	// response carry for a verdict the anchored engine authored
	// (anchoredenforcer.EngineAnchored).
	decisionEngineAnchored = anchoredenforcer.EngineAnchored

	// responseRedactionEndpoint discharges a response-phase redact_pii
	// obligation: a field_redact an organization document aims at a response.*
	// field, which a pre-call plane cannot redact itself, so the PEP is told to
	// fan out to the response gate after the call - the phase the Decision API
	// contract already declares for exactly this.
	responseRedactionEndpoint = "/api/v1/mcp/check-output"
)

// decideSeamScope is the enforcement scope the decide plane's seam cuts over:
// the whole plane, which evaluates one phase.
var decideSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")

// enforcingSeam is one scope with an enforcing seam in this binary, and what
// the wire that seam answers on hands to an enforcement point that declares it
// (#4046).
type enforcingSeam struct {
	scope    legacycompile.EnforcementScope
	delivers []contract.Capability
}

// enforcingSeams is every enforcing seam this binary wires - the registration
// the enforcer, /health and enforceRequestPass all read. The enforcer builds
// each scope's engine with exactly this delivery, so what activation is told a
// seam delivers is stated once, beside the seam list:
//
//   - decide returns its decision over the Decision API, so it delivers that
//     wire's vocabulary - the table wireObligationsFor is driven by;
//   - the gateway pre-check answers requires_redaction, which is that
//     vocabulary's request-phase redact_pii told as an instruction, so it
//     delivers the same capability, and staticPolicyResult refuses the
//     redaction it cannot tell;
//   - the MCP response pass masks inline and returns content, never an
//     obligation, so it delivers nothing to its caller; the field_redact it
//     composes is discharged by the mcp plane's registered profile;
//   - /api/request's Phase 1 and the OpenAI-compatible route forward the
//     request or refuse it and tell their caller no obligation, so they
//     deliver nothing;
//   - the MCP request pass hands its caller no obligation either: check-input
//     and check_policy discharge a redaction themselves by returning the
//     statement masked, and the connector routes, which execute the statement
//     in this process, refuse one (mcp_request_enforcing_seam.go). Like the
//     response pass, its field_redact is discharged by the mcp plane's
//     registered profile.
//
// TestEveryEnforcingSeamActivatesOnBothEditions activates every entry against
// the shipped corpus, so a seam whose restriction it cannot discharge is
// refused in CI rather than on the first request.
//
// Every entry's delivery is legacycompile.ScopeDeliveries (#4131), including
// the four that deliver nothing: the one statement of what each scope's wire
// hands a declaring caller, which the corpus build's template split, this list
// and both authoring dry runs all read. TestEverySeamDeliversWhatScopeDeliveriesStates
// holds each entry to it by value, whatever the spelling.
var enforcingSeams = []enforcingSeam{
	{scope: decideSeamScope, delivers: legacycompile.ScopeDeliveries(decideSeamScope)},
	{scope: gatewayRequestSeamScope, delivers: legacycompile.ScopeDeliveries(gatewayRequestSeamScope)},
	{scope: mcpRequestSeamScope, delivers: legacycompile.ScopeDeliveries(mcpRequestSeamScope)},
	{scope: mcpResponseSeamScope, delivers: legacycompile.ScopeDeliveries(mcpResponseSeamScope)},
	{scope: proxyRequestSeamScope, delivers: legacycompile.ScopeDeliveries(proxyRequestSeamScope)},
	{scope: openaiCompatibleSeamScope, delivers: legacycompile.ScopeDeliveries(openaiCompatibleSeamScope)},
}

// seamFor is the enforcing seam registered for scope in this binary.
func seamFor(scope legacycompile.EnforcementScope) (enforcingSeam, bool) {
	for _, s := range enforcingSeams {
		if s.scope == scope {
			return s, true
		}
	}
	return enforcingSeam{}, false
}

// seamDelivers is what the seam registered for scope delivers; nil for a scope
// with no seam, which delivers nothing whatever its legacy handler answers.
func seamDelivers(scope legacycompile.EnforcementScope) []contract.Capability {
	s, _ := seamFor(scope)
	return s.delivers
}

// Causes a request fails CLOSED with: the shared enforcer's vocabulary
// (anchoredenforcer), under this package's names.
const (
	enforceCauseNotWired            = anchoredenforcer.CauseNotWired
	enforceCauseActiveDocument      = anchoredenforcer.CauseActiveDocument
	enforceCauseOverrides           = anchoredenforcer.CauseOverrides
	enforceCauseActivation          = anchoredenforcer.CauseActivation
	enforceCauseCapability          = anchoredenforcer.CauseCapability
	enforceCauseSubjectUnverifiable = anchoredenforcer.CauseSubjectUnverifiable
	enforceCauseRequest             = anchoredenforcer.CauseRequest
	enforceCauseEvaluation          = anchoredenforcer.CauseEvaluation
	enforceCauseObligation          = anchoredenforcer.CauseObligation
)

// enforceReasonBudgetExceeded is the `reason` label for a refusal a request
// pass's gates add AFTER the engine decided: the budget check, which is not a
// policy verdict. It has its own name because counting it under the engine's
// reason renders as {verdict=deny, reason=permitted} - a contradiction on a
// dashboard, and indistinguishable from a policy denial by the one label an
// operator filters on. The vocabulary stays closed: this is one more member.
const enforceReasonBudgetExceeded = "budget_exceeded"

// enforceCauseMessages is the stable half of each cause's refusal message
// (anchoredenforcer.CauseMessages).
var enforceCauseMessages = anchoredenforcer.CauseMessages

// anchoredEnforceDecisions counts every decision on an enforcing scope
// (anchoredenforcer.Decisions, registered by that package).
var anchoredEnforceDecisions = anchoredenforcer.Decisions

// --- the organization's active document ---

// activeDocumentSource is the seam's read of an organization's ACTIVE typed
// document (anchoredenforcer.ActiveDocumentSource).
type activeDocumentSource = anchoredenforcer.ActiveDocumentSource

// newDurableActiveDocuments reads the active document from the typed-authoring
// tables (anchoredenforcer.NewDurableActiveDocuments).
func newDurableActiveDocuments(db *sql.DB) *anchoredenforcer.DurableActiveDocuments {
	return anchoredenforcer.NewDurableActiveDocuments(db)
}

// --- the enforcer ---

// anchoredEnforcer is the process enforcer: the shared anchoredenforcer.Enforcer,
// with this package's request shapes (evaluate) and the Decision API mapping
// (decideRequestPass) as its methods. One instance serves every scope.
type anchoredEnforcer struct {
	*anchoredenforcer.Enforcer
}

// newAnchoredEnforcer builds the process enforcer with what only this process
// supplies: its recorded detection overrides, what each seam it registers
// delivers, and the edition boundary resolved from its licence.
func newAnchoredEnforcer(
	documents activeDocumentSource,
	vocabulary func() (*authoringcatalog.Snapshot, error),
	identity *sharedidentity.SubjectAdmitter,
	identityEpoch func() int64,
) (*anchoredEnforcer, error) {
	e, err := anchoredenforcer.New(documents, vocabulary, identity, identityEpoch, anchoredenforcer.Options{
		Overrides:       recordedAnchoredOverrides,
		Delivers:        seamDelivers,
		EditionBoundary: seamEditionBoundary,
	})
	if err != nil {
		return nil, err
	}
	return &anchoredEnforcer{Enforcer: e}, nil
}

// seamEditionBoundary is the edition boundary every activation this process
// builds is gated by, at the door publication cannot guard: the deployment's
// authoring profile, and whether the construct check may refuse.
//
// GATED, unlike the transports' dry run. An activation error on this path is
// HTTP 503 on /api/v1/decide and a withheld MCP response, so it must not fire
// for a deployment that merely cannot establish its tier, nor for one whose
// operator has declared a licence transition and is winding down deliberately
// (#4094). EnforcesConstructBoundary is that question, asked once, by the one
// resolver. It is resolved HERE, in the process that holds the licence, and
// handed to the shared enforcer (the #3956 deployment guard).
func seamEditionBoundary(ctx context.Context) (authoring.Profile, bool) {
	edition := authoringedition.Resolve(ctx)
	return edition.Profile, edition.EnforcesConstructBoundary()
}

// anchoredEnforcerInstance is the process enforcer, nil when none was wired.
var anchoredEnforcerInstance atomic.Pointer[anchoredEnforcer]

// memoizedDeploymentVocabulary resolves the deployment vocabulary on first use
// and memoizes a success only (anchoredenforcer.MemoizedDeploymentVocabulary).
func memoizedDeploymentVocabulary(resolve func() (*authoringcatalog.Snapshot, error)) func() (*authoringcatalog.Snapshot, error) {
	return anchoredenforcer.MemoizedDeploymentVocabulary(resolve)
}

// resolveDeploymentVocabulary resolves the deployment vocabulary for what this
// process has wired. The enforcer memoizes it on first use; the policy-pack
// install reads it once at boot, for the realms a person can answer in.
func resolveDeploymentVocabulary() (*authoringcatalog.Snapshot, error) {
	return authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, identityDeployment)
}

// installAnchoredEnforcer wires the process enforcer, or says why it cannot.
//
// THE VOCABULARY IS THE DEPLOYMENT'S, NOT AXONFLOW_TYPED_AUTHORING_CATALOG'S.
// An organization can only have an active document that activated against the
// deployment vocabulary - activation refuses a fixture (CATALOG_IS_FIXTURE) - so
// the enforcer resolves that vocabulary directly, and a process whose catalog
// variable is unset still enforces what another process activated. It is
// resolved lazily, so what this process wired (a SCIM directory decides whether
// the built-in realms carry a group graph) is settled before it is read.
func installAnchoredEnforcer(db *sql.DB, boot *sharedidentity.AdmissionBootstrap) error {
	if db == nil {
		return errors.New("the anchored engine authors every enforcing plane's verdict and reads each organization's typed policy from the database, and this process has no database")
	}
	if boot == nil || boot.Admitter == nil || boot.Registry == nil {
		return errors.New("the anchored engine authors every enforcing plane's verdict and admits each request's subject through the identity plane, and the identity plane is not bootstrapped in this process")
	}
	e, err := newAnchoredEnforcer(
		newDurableActiveDocuments(db),
		memoizedDeploymentVocabulary(resolveDeploymentVocabulary),
		boot.Admitter,
		boot.Registry.Epoch,
	)
	if err != nil {
		return err
	}
	// The installed policy packs, instantiated for the realms this deployment
	// mints principals in. A pack whose approver pool would name nobody refuses
	// the process here rather than every request later.
	if e.Packs, err = instantiatePolicyPacks(installedPolicyPacks); err != nil {
		return err
	}
	anchoredEnforcerInstance.Store(e)
	return nil
}

// activationFor returns the organization's anchored engine for one scope
// (anchoredenforcer.Enforcer.ActivationFor).
func (e *anchoredEnforcer) activationFor(ctx context.Context, scope legacycompile.EnforcementScope, orgID, digest string, assigned legacycompile.CategoryActions) (*activation.Activation, error) {
	return e.ActivationFor(ctx, scope, orgID, digest, assigned)
}

// anchoredCall is one request an enforcing seam hands the anchored engine.
type anchoredCall struct {
	scope     legacycompile.EnforcementScope
	orgID     string
	requestID string
	// action is the registered action's local name; actionErr, when set, says
	// why the plane could not name one, and the request fails closed on it.
	action    string
	actionErr error
	// subject builds the credential the identity plane admits, and says which
	// door it is admitted through.
	subject func(now time.Time) (decisionSubject, bool)
	// query is the content the action is evaluated over (args.query).
	query string
	// observation is the evaluation's detector facts; nil when the shared
	// engine evaluated nothing, and then every detector is ABSENT.
	observation *sharedpolicy.Observation
	// emptyContent says the content is empty, so a content detector's answer is
	// determined without running it (see anchoredRequest).
	emptyContent bool
	// pep is the admitted handshake's profile, nil when none was admitted.
	pep *contract.PEPProfile
	// facts are attributes the seam's own reader of the request states
	// (anchoredenforcer.Call.Facts). No agent seam states any: each hands the
	// engine its detector facts through the observation alone
	// (TestNoAgentSeamStatesFactsOnItsCall).
	facts contract.AttributeSet
}

// decisionSubject is the credential a request presents to the identity plane
// and the door it is admitted through.
type decisionSubject struct {
	legacy sharedidentity.CredentialPrincipal
	// credential says the request carries no user identity, so its
	// authenticated client credential is the principal
	// (SubjectAdmitter.AdmitCredentialSubject).
	credential bool
}

// userIdentity is what a request's per-user identity is, as the subject
// builder needs to know it (callerUserIdentity).
type userIdentity int

const (
	// userAbsent: the request carries no user identity this deployment would
	// verify, so its client credential is the principal.
	userAbsent userIdentity = iota
	// userVerified: a per-user token was presented and verified.
	userVerified
	// userUnverified: a per-user token this deployment verifies was presented
	// and did NOT verify. It is refused, never replaced by the credential.
	userUnverified
)

// anchoredVerdict is the enforcer's answer for one call. Exactly one of these
// holds: the request failed closed (unavailable); the identity plane refused
// its subject (refusal); or the engine decided (decision).
type anchoredVerdict struct {
	unavailable string
	act         *activation.Activation
	refusal     *sharedidentity.Admission
	decision    *contract.Decision
	// subjectType is the admitted principal's type (User, Client, Service),
	// set whenever the identity plane admitted one.
	subjectType string
}

// requestSubject is the credential a request authenticated by this agent
// presents to the identity plane: the verified user token when the caller
// holds one, and the authenticated client credential when the request carries
// no user identity. It is the one builder every seam reached through the
// agent's own authentication uses.
//
// A PRESENTED TOKEN THAT DID NOT VERIFY IS NEVER THE ABSENCE OF ONE. Every
// handler in front of a seam refuses such a token at authentication, and this
// builder holds the same line itself rather than trusting them: the token goes
// to the user door, which refuses it, and the credential is never admitted in
// its place (PRD v11 §1.6: admission is for the absence of a user identity,
// never for a bad one).
func requestSubject(orgID string, auth *AuthResult, user *User, identity userIdentity) func(time.Time) (decisionSubject, bool) {
	return func(now time.Time) (decisionSubject, bool) {
		switch identity {
		case userVerified:
			return decisionSubject{legacy: sharedidentity.HS256Principal(orgID, userTokenClaims(user, nil), true, "")}, true
		case userUnverified:
			return decisionSubject{legacy: sharedidentity.HS256Principal(orgID, nil, false, "")}, true
		default:
			legacy, ok := authResultPrincipal(auth, now)
			return decisionSubject{legacy: legacy, credential: true}, ok
		}
	}
}

// failClosed logs why a request could not get an anchored verdict
// (anchoredenforcer.FailClosed).
func failClosed(scope legacycompile.EnforcementScope, orgID, cause string, err error) {
	anchoredenforcer.FailClosed(scope, orgID, cause, err)
}

// evaluate is the enforcer's one decision path (anchoredenforcer.Enforcer.Evaluate)
// over this package's call and verdict shapes. Every field crosses in both
// directions, and TestTheAgentCallShapesMirrorTheSharedEnforcer holds each pair
// of shapes to the same fields.
func (e *anchoredEnforcer) evaluate(ctx context.Context, call anchoredCall) anchoredVerdict {
	v := e.Evaluate(ctx, sharedCall(call))
	return anchoredVerdict{unavailable: v.Unavailable, act: v.Act, refusal: v.Refusal, decision: v.Decision, subjectType: v.SubjectType}
}

// sharedCall is the shared enforcer's call for this package's: every field
// crosses, the facts set unchanged (TestEvaluateCarriesTheCallsFactsToTheSharedEnforcer).
func sharedCall(call anchoredCall) anchoredenforcer.Call {
	shared := anchoredenforcer.Call{
		Scope: call.scope, OrgID: call.orgID, RequestID: call.requestID,
		Action: call.action, ActionErr: call.actionErr,
		Query: call.query, Observation: call.observation, EmptyContent: call.emptyContent, PEP: call.pep,
		Facts: call.facts,
	}
	if call.subject != nil {
		shared.Subject = func(now time.Time) (anchoredenforcer.Subject, bool) {
			s, ok := call.subject(now)
			return anchoredenforcer.Subject{Principal: s.legacy, Credential: s.credential}, ok
		}
	}
	return shared
}

// recordAnchoredEnforcement counts one decision on an enforcing scope
// (anchoredenforcer.RecordEnforcement).
func recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {
	anchoredenforcer.RecordEnforcement(scope, engine, verdict, reason)
}

// --- the request passes: decide, and the planes that share its shape ---

// requestPassInput is what a single-phase request pass knows when its seam
// runs: handleDecide, the gateway pre-check, /api/request's Phase 1 and the
// OpenAI-compatible route.
type requestPassInput struct {
	orgID string
	// decisionID names the request the decision is taken for.
	decisionID string
	// stage is the Decision API stage the request is evaluated as, which names
	// its registered action (decideActionForStage).
	stage string
	query string
	auth  *AuthResult
	user  *User
	// userIdentity is callerUserIdentity for this request.
	userIdentity userIdentity
	// observation is the pass's detector facts; nil when the shared engine
	// evaluated nothing, and then every detector is ABSENT.
	observation *sharedpolicy.Observation
	// pep is the admitted handshake's profile, nil when none was admitted.
	pep *contract.PEPProfile
	// validatorRedactions names the pre-seam checksum validators that require
	// this request's content redacted: a critical identifier no shipped control
	// detects, under the organization's pii=redact override. See
	// attachValidatorRedactions.
	validatorRedactions []string
	// subject, when set, is the credential the request presents in place of the
	// one auth, user and userIdentity describe: an MCP server session, whose
	// principal is the per-user token a validator accepted when the session was
	// created, or its client credential (sessionSubject).
	subject func(time.Time) (decisionSubject, bool)
}

// requestPassEnforcement is the seam's answer for one request, rendered on the
// Decision API's vocabulary. A pass that answers on another wire projects it
// onto that wire (staticPolicyResult).
type requestPassEnforcement struct {
	// engine is the engine that authored the verdict: always the anchored
	// engine, set when the pass begins (enforceRequestPass).
	engine string
	// subjectType is the admitted principal's type, empty when the request was
	// refused before a subject was admitted.
	subjectType string
	// unavailable is non-empty when the anchored engine could not produce a
	// verdict; the handler answers 503 and decides nothing.
	unavailable string

	verdict            string
	reasons            []string
	obligations        []DecisionObligation
	evaluatedPolicies  []string
	blockingPolicyID   string
	blockingPolicyTier string
	reasonCode         string
	policyBundle       string
	// policyPacks names the installed policy packs that bound on this scope,
	// as the wire and the audit row carry them (`policy_packs`, PRD v11 §1.9).
	policyPacks []string
	// policyIdentities names each of evaluatedPolicies, in its order: its
	// display name, whose it is, and the version it was published at (PRD v11
	// §1.14). documentVersion is the active organization document's published
	// version, zero under the implicit baseline. actionName is the
	// operator-facing name of the action the request was evaluated as, for the
	// audit row.
	policyIdentities []PolicyIdentity
	documentVersion  int
	actionName       string

	// legacyValidators records each validator whose redaction the seam carried,
	// or refused because the caller could not discharge it, for the wire and
	// the audit row.
	legacyValidators []LegacyValidatorAction

	// undischarged is what an invariant-8 refusal could not discharge: the
	// engine's trace names it, or a validator's obligation is it. The handler
	// names the admitted enforcement point's capability gap from it
	// (applyAnchoredCapabilityRefusal); nil on every other verdict.
	undischarged []contract.Obligation

	// decision and act are the engine's decision and the activation that took
	// it, set whenever the engine decided. A pass that discharges a redaction
	// itself - the MCP request pass masks the statement it hands back - reads
	// what to mask off them, never off the rendering above.
	decision *contract.Decision
	act      *activation.Activation
}

// enforceRequestPass is THE ONE PATH a single-phase request pass's verdict is
// authored on. The scope is the caller's own; a scope with no seam registered
// in this binary, or a process with no enforcer, fails closed rather than
// letting the legacy engine's answer stand.
func enforceRequestPass(ctx context.Context, scope legacycompile.EnforcementScope, in requestPassInput) requestPassEnforcement {
	out := requestPassEnforcement{engine: decisionEngineAnchored}
	e := anchoredEnforcerInstance.Load()
	if _, wired := seamFor(scope); e == nil || !wired {
		out.unavailable = enforceCauseNotWired
		failClosed(scope, in.orgID, enforceCauseNotWired, fmt.Errorf("%s has no enforcer wired in this process", scope))
		return out
	}
	return e.decideRequestPass(ctx, scope, in, out)
}

// decideRequestPass maps one request on scope onto the enforcer and its answer
// back onto the Decision API.
func (e *anchoredEnforcer) decideRequestPass(ctx context.Context, scope legacycompile.EnforcementScope, in requestPassInput, out requestPassEnforcement) requestPassEnforcement {
	call := anchoredCall{
		scope: scope, orgID: in.orgID, requestID: in.decisionID,
		subject: requestSubject(in.orgID, in.auth, in.user, in.userIdentity),
		query:   in.query, observation: in.observation, pep: in.pep,
	}
	if in.subject != nil {
		call.subject = in.subject
	}
	local, ok := decideActionForStage(in.stage)
	if ok {
		call.action = local
	} else {
		call.actionErr = fmt.Errorf("stage %q maps to no registered action", in.stage)
	}
	v := e.evaluate(ctx, call)
	out.subjectType = v.subjectType
	if v.act != nil {
		out.actionName = v.act.ActionName(call.action)
	}
	switch {
	case v.unavailable != "":
		out.unavailable = v.unavailable
		return out
	case v.refusal != nil:
		// A determinate refusal of this request's subject.
		out.verdict = VerdictDeny
		out.reasonCode = strings.ToLower(string(v.refusal.Reason))
		out.reasons = []string{fmt.Sprintf("%s: %s", out.reasonCode, v.refusal.Detail)}
		out.carryActivation(v.act, []string{})
		return out
	}
	dec := v.decision
	if len(in.validatorRedactions) > 0 && dec.State == contract.StateAllow {
		attached, records, refused, refusal := attachValidatorRedactions(dec, v.act, in.pep, in.validatorRedactions)
		out.legacyValidators = records
		if refusal != "" {
			out.verdict = VerdictDeny
			out.reasonCode = string(contract.ReasonUnsupportedObligation)
			out.reasons = []string{refusal}
			out.undischarged = []contract.Obligation{refused}
			out.carryActivation(v.act, anchoredEvaluatedPolicies(dec.Determining))
			out.blockingPolicyID, out.blockingPolicyTier = refused.SourcePolicy, "system"
			return out
		}
		dec = attached
	}
	out.decision, out.act = dec, v.act
	return mapAnchoredDecision(out, dec, v.act)
}

// attachValidatorRedactions carries a pre-seam checksum validator's redaction
// requirement onto an anchored ALLOW as a mandatory field_redact obligation. It
// is a STOPGAP: #4122 (W3-H) makes the validators detector facts the engine
// decides from, and this goes with it. Until then a validator finds identifiers
// no shipped control detects (an Indonesian NIK, an Aadhaar), so without it an
// organization's recorded pii=redact override is detected, recorded and then
// dropped from the verdict: an allow with no obligation, and the identifier
// forwarded unredacted.
//
// The obligation is judged by the SAME rule the engine applies to its own
// mandatory obligations after composing them (contract.composeSet): the
// effective profile - the admitted handshake's, or the engine-wide profile the
// activation built the engine with when none was admitted - must Support it.
// Not activation.DischargeSurface, which also counts what the scope delivers
// itself: that is activation's guard, and it would allow a caller the engine
// refuses. A caller that cannot discharge it is refused unsupported_obligation
// (ADR-065 invariant 8) naming the validator, and the refused obligation is
// returned so the handler can name the enforcement point's capability gap; a
// caller that can is handed it,
// rendered by wireObligationsFor like any other. When the engine's allow
// already carries a mandatory request-content redaction, the requirement is
// met and nothing is added. Every validator is recorded as redaction_required
// in legacy_validators, and ONLY there: evaluated_policies is captioned with
// the controls the engine applied, and a checksum validator is not one of
// them.
func attachValidatorRedactions(dec *contract.Decision, act *activation.Activation, pep *contract.PEPProfile, validators []string) (*contract.Decision, []LegacyValidatorAction, contract.Obligation, string) {
	if pep == nil {
		pep = act.PEP
	}
	attached := *dec
	attached.Obligations = append([]contract.Obligation(nil), dec.Obligations...)
	records := make([]LegacyValidatorAction, 0, len(validators))
	for _, name := range validators {
		records = append(records, LegacyValidatorAction{Validator: name, Action: legacyActionRedactionRequired})
	}
	// Already met: the engine attached a mandatory request-content redaction and
	// applied invariant 8 to it, so this caller can discharge it, and a second
	// identical instruction would only be redundant.
	for _, o := range dec.Obligations {
		if o.Type == contract.ObFieldRedact && o.Mandatory && !redactsResponse(o, act.Scope) {
			return dec, records, contract.Obligation{}, ""
		}
	}
	for _, name := range validators {
		o := contract.Obligation{
			Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true,
			SourcePolicy: legacyValidatorPolicyIDs[name], SchemaVersion: validatorRedactionSchemaVersion(),
		}
		if !pep.Supports(o) {
			return dec, records, o, fmt.Sprintf("%s: the mandatory %s obligation the %s checksum validator requires cannot be discharged by this enforcement point",
				contract.ReasonUnsupportedObligation, o.CapabilityOf(), name)
		}
		attached.Obligations = append(attached.Obligations, o)
	}
	return &attached, records, contract.Obligation{}, ""
}

// validatorRedactionSchemaVersion is the field_redact version the Decision API
// carries, read from its closed vocabulary: the obligation is one this wire
// hands an enforcement point, so its identity is the wire's. Zero if the wire
// ever stopped carrying field_redact, which no surface discharges, so the
// request is refused rather than allowed without the redaction.
func validatorRedactionSchemaVersion() int {
	for _, w := range contract.DecisionWireObligations() {
		if w.Capability.Type == contract.ObFieldRedact {
			return w.Capability.Version
		}
	}
	return 0
}

// decideActionForStage maps a /decide stage onto its registered action by
// inverting the AuthZEN adapter's closed table, which
// TestTheDeploymentActionsAreTheAdaptersActions welds to the deployment
// vocabulary. It is read, never restated.
func decideActionForStage(stage string) (string, bool) {
	for action, s := range authzenActionStage {
		if s == stage {
			return action, true
		}
	}
	return "", false
}

// mapAnchoredDecision renders an anchored decision onto the Decision API.
//
// A CHALLENGE IS A DENY WITH REASON approval_required, NAMING THE PLANE (PRD v11
// §1.13). No plane rendered here holds a request for approval, so the engine's
// challenge answers the reason that says an approval is what is missing, and
// the plane it arrived on, so a caller can tell a missing approval from a
// policy refusal. Answering needs_approval with no queue entry would be the
// invisible dead end #3509 removed from the legacy path, strictly worse than a
// refusal a caller can see.
//
// AN UNKNOWN CONSTRAINT IS NAMED (#4227, PRD v11 §1.14). A refusal because a
// constraint could not be evaluated lists that constraint first in the evaluated
// policies, the binding one first, and adds a reason per constraint naming
// whose it is and the attribute it could not establish. The first reason stays
// the bare code.
func mapAnchoredDecision(out requestPassEnforcement, dec *contract.Decision, act *activation.Activation) requestPassEnforcement {
	out.reasonCode = string(dec.Reason)
	unknown := unknownConstraints(dec)
	out.carryActivation(act, decidingPolicies(dec))
	switch dec.State {
	case contract.StateAllow:
		obligations, refusal := wireObligationsFor(dec.Obligations, act.Scope)
		if refusal != "" {
			out.verdict = VerdictDeny
			out.reasonCode = string(contract.ReasonUnsupportedObligation)
			out.reasons = []string{refusal}
			return out
		}
		out.verdict = VerdictAllow
		out.obligations = obligations
		out.reasons = advisoryReasons(dec)
	case contract.StateChallenge:
		out.verdict = VerdictDeny
		out.reasonCode = string(contract.ReasonApprovalRequired)
		out.reasons = []string{approvalRequiredReason(act.Scope)}
	default:
		out.verdict = VerdictDeny
		out.reasons = append([]string{string(dec.Reason)}, unknownConstraintReasons(act, unknown)...)
		if dec.Reason == contract.ReasonUnsupportedObligation && dec.Trace != nil {
			out.undischarged = dec.Trace.Undischarged
		}
	}
	if out.verdict == VerdictDeny {
		blocking := blockingConstraint(dec.Determining, unknown)
		if blocking != "" {
			out.blockingPolicyID = blocking
		}
		// The top-blocked-policies series keys a deny on its blocking policy,
		// and a deny with none on the first policy it names (decide's
		// fallback): an unknown_requirement deny names the permissions that
		// matched. Either gets the same bounded tier, so an organization's own
		// id never becomes a label.
		keyed := blocking
		if keyed == "" && len(out.evaluatedPolicies) > 0 {
			keyed = out.evaluatedPolicies[0]
		}
		if keyed != "" {
			out.blockingPolicyTier = anchoredPolicyTier(keyed)
		}
	}
	return out
}

// anchoredPolicyTier is the tier the top-blocked-policies series keys a policy
// on. A shipped control - or the replacement an organization's recorded
// override carries for one (#4045), whose id is derived from it - is a bounded
// id set the series may carry ("system"). Anything else is the organization's
// or a pack's, which the series collapses to tenant_custom ("organization").
func anchoredPolicyTier(id string) string {
	if strings.HasPrefix(strings.TrimPrefix(id, activation.OverridePolicyIDPrefix), "corpus:") {
		return "system"
	}
	return "organization"
}

// The decision-naming helpers every seam that names a decision reads
// (anchoredenforcer), under this package's names.

func approvalRequiredReason(scope legacycompile.EnforcementScope) string {
	return anchoredenforcer.ApprovalRequiredReason(scope)
}

func unknownConstraints(dec *contract.Decision) []contract.UnknownPolicy {
	return anchoredenforcer.UnknownConstraints(dec)
}

func decidingPolicies(dec *contract.Decision) []string {
	return anchoredenforcer.DecidingPolicies(dec)
}

func blockingConstraint(d contract.Determining, unknown []contract.UnknownPolicy) string {
	return anchoredenforcer.BlockingConstraint(d, unknown)
}

func unknownConstraintReasons(act *activation.Activation, unknown []contract.UnknownPolicy) []string {
	return anchoredenforcer.UnknownConstraintReasons(act, unknown)
}

func anchoredEvaluatedPolicies(d contract.Determining) []string {
	return anchoredenforcer.EvaluatedPolicies(d)
}

// carryActivation records which policy set decided and which of its policies
// decided: the bundle and the packs composed into it, the organization
// document's published version, and each evaluated policy's identity in
// evaluated order (PRD v11 §1.14). Usually the policies that decided are the
// ones that matched. On an indeterminate deny they are the constraints that
// could not be evaluated, binding first, then what matched (#4227).
func (out *requestPassEnforcement) carryActivation(act *activation.Activation, evaluated []string) {
	out.policyBundle, out.policyPacks, out.documentVersion = act.PolicyBundle, act.PackRefs(), act.DocumentVersion
	out.evaluatedPolicies = evaluated
	out.policyIdentities = anchoredPolicyIdentities(act, evaluated)
}

// anchoredPolicyIdentities names each id as the activation that decided it
// activated it; an id it did not activate is named by its identifier alone.
func anchoredPolicyIdentities(act *activation.Activation, ids []string) []PolicyIdentity {
	out := make([]PolicyIdentity, 0, len(ids))
	for _, id := range ids {
		p, _ := act.Identity(id)
		out = append(out, PolicyIdentity{ID: p.ID, Name: p.Name, Source: string(p.Source), Version: p.Version})
	}
	return out
}

// advisoryReasons names every requirement or inspection that MATCHED and put no
// obligation on the wire (#2965): an advisory notification the wire drops, or an
// immutable_audit the audit row discharges. Without it such a match is a bare
// allow - no obligation and no reason - and a caller cannot tell a matched
// control from a clean request. A clean request names nothing. Always non-nil,
// so the body carries [] and never null.
func advisoryReasons(dec *contract.Decision) []string {
	onWire := map[string]bool{}
	for _, o := range dec.Obligations {
		if o.Type == contract.ObImmutableAudit {
			continue
		}
		if _, carried := contract.DecisionWireNameFor(o); carried {
			onWire[o.SourcePolicy] = true
		}
	}
	reasons := []string{}
	for _, set := range [][]string{dec.Determining.MatchedRequirement, dec.Determining.MatchedInspections} {
		for _, id := range set {
			if !onWire[id] {
				reasons = append(reasons, fmt.Sprintf("policy %s matched; it is advisory, so no obligation is handed to the caller", id))
			}
		}
	}
	return reasons
}

// wireObligationsFor renders the composed obligation set onto the Decision
// API's obligation vocabulary, or names the mandatory one it cannot carry.
//
// immutable_audit is DISCHARGED by this handler's own audit row and decision
// chain entry, so it is not handed to the enforcement point. An obligation is
// carried when contract.DecisionWireObligations names its exact type and schema
// version - the same table activation reads to decide what this scope delivers
// (#4046), so the renderer and the activation guard cannot disagree. An
// advisory obligation the wire cannot express is dropped - the engine already
// records it - while a MANDATORY one refuses the request: telling an
// enforcement point to allow without telling it what it must do is the
// fail-open invariant 8 exists to forbid.
func wireObligationsFor(obligations []contract.Obligation, scope legacycompile.EnforcementScope) ([]DecisionObligation, string) {
	out := []DecisionObligation{}
	for _, o := range obligations {
		if o.Type == contract.ObImmutableAudit {
			continue
		}
		name, carried := contract.DecisionWireNameFor(o)
		switch {
		case carried && name == ObligationRedactPII:
			out = append(out, redactObligationFor(o, scope))
		case carried:
			// Unreachable while the vocabulary and this switch agree, which
			// TestTheDecisionWireRendersExactlyItsVocabulary holds. Refused
			// rather than dropped: the table says the wire carries it, and
			// silently not carrying it would be the fail-open above.
			return nil, fmt.Sprintf("%s: the %s obligation attached by %s is in the Decision API's vocabulary as %q, and this seam renders no such obligation",
				contract.ReasonUnsupportedObligation, o.CapabilityOf(), o.SourcePolicy, name)
		case !o.Mandatory:
			continue
		default:
			return nil, fmt.Sprintf("%s: the mandatory %s obligation attached by %s has no Decision API representation, so an enforcement point could not be told to discharge it",
				contract.ReasonUnsupportedObligation, o.CapabilityOf(), o.SourcePolicy)
		}
	}
	return out, ""
}

// redactObligationFor renders a field_redact as redact_pii, fulfilled on the
// phase whose content it targets. legacycompile.DefaultContentTarget is the
// content the scope evaluated, so it is fulfilled on the scope's content phase
// (#4046): decide asks its caller to mask the request, as the legacy engine
// does. Any other target is fulfilled where it lives - a response.* field
// after the call, everything else on the request.
func redactObligationFor(o contract.Obligation, scope legacycompile.EnforcementScope) DecisionObligation {
	detail := fmt.Sprintf("field_redact %s required by %s", o.Target, o.SourcePolicy)
	if redactsResponse(o, scope) {
		return DecisionObligation{
			Type:   ObligationRedactPII,
			Detail: detail,
			Fulfillment: &ObligationFulfillment{
				Endpoint:     responseRedactionEndpoint,
				Method:       http.MethodPost,
				Phase:        ObligationPhaseResponse,
				ContentTypes: requestRedactionContentTypes(),
			},
		}
	}
	return newRedactPIIObligation(detail)
}

// redactsResponse reports whether a field_redact is fulfilled on the RESPONSE
// phase: its target names a response path, or it is the default content target
// on a scope whose content is the response.
func redactsResponse(o contract.Obligation, scope legacycompile.EnforcementScope) bool {
	if o.Target == legacycompile.DefaultContentTarget {
		return scope.ContentPhase() == legacycompile.PhaseResponse
	}
	return strings.HasPrefix(o.Target, "response.")
}

// capabilityScopedDetail renders an evaluation's capability scoping (#2801) for
// an audit row: the tool that scoped detectors out, and which. Nil when it
// scoped out none, so nothing is written.
func capabilityScopedDetail(s *sharedpolicy.CapabilityScoping) map[string]interface{} {
	if s == nil || len(s.Detectors) == 0 {
		return nil
	}
	return map[string]interface{}{"tool": s.Tool, "detectors": s.Detectors}
}

// observationOf is a request evaluation's detector facts, nil when the shared
// engine did not evaluate (no engine wired, or detection disabled for the
// organization) - in which case every detector is absent from the anchored
// request and reads UNKNOWN there.
func observationOf(r *sharedpolicy.RequestResult) *sharedpolicy.Observation {
	if r == nil {
		return nil
	}
	return r.Observation
}

// requestPassWires names each legacy-shaped request pass in a refusal its wire
// cannot express. A scope absent from this table has no such wire.
var requestPassWires = map[legacycompile.EnforcementScope]string{
	gatewayRequestSeamScope:   gatewayPreCheckWire,
	proxyRequestSeamScope:     proxyRequestWire,
	openaiCompatibleSeamScope: openaiCompatibleWire,
	mcpRequestSeamScope:       mcpConnectorRouteWire,
}

// wireTellsRequestRedaction reports whether a scope's wire can instruct its
// caller to redact the request - the pre-check's requires_redaction.
//
// IT IS DERIVED FROM WHAT THE SEAM DECLARES IT DELIVERS, not written at the
// call site. The two are the same fact - a wire that can tell a caller to
// discharge a field_redact is a wire that delivers field_redact - and stating
// it twice is how the declaration activation reads and the instruction the
// caller gets come apart.
//
// THE PHASE IS PART OF THE SAME DERIVATION. A capability is a (type, version)
// pair and says nothing about WHEN the obligation is discharged, so the scope's
// own content phase decides too: a pass that evaluates the request can instruct
// a redaction of the request, and nothing else. Without this the two axes would
// be stated in different places - the type derived here, the phase written into
// staticPolicyResult - which is the coming-apart this function exists to stop.
//
// THE RESIDUAL, STATED: activation's discharge guard matches on (type, version)
// alone, so a control whose mandatory field_redact targets a response.* field
// can still ACTIVATE on a scope whose wire then refuses it at request time. That
// is fail-closed, no shipped control binds it (the restriction carries no
// mandatory obligation at all), and narrowing the guard by phase is #4046's
// family rather than this seam's.
func wireTellsRequestRedaction(scope legacycompile.EnforcementScope) bool {
	if scope.ContentPhase() != legacycompile.PhaseRequest {
		return false
	}
	for _, c := range seamDelivers(scope) {
		if c == (contract.Capability{Type: contract.ObFieldRedact, Version: 1}) {
			return true
		}
	}
	return false
}

// staticPolicyResult renders a request pass the anchored engine decided as the
// StaticPolicyResult a legacy-shaped handler reads after its own policy
// evaluation, with the reason code the decision is recorded under.
//
// The scope decides both halves of the rendering: the wire's name in a refusal,
// and whether that wire can instruct a redaction of the request - the gateway
// pre-check's requires_redaction, which is the request-phase redact_pii this
// rendering carries and the same instruction the legacy engine gives. A
// redaction the wire cannot tell, and any obligation fulfilled after the call,
// REFUSES the request rather than letting it proceed with nobody told to
// discharge it (ADR-065 invariant 8). The refusal withholds the instruction too.
func (d requestPassEnforcement) staticPolicyResult(scope legacycompile.EnforcementScope) (*StaticPolicyResult, string) {
	wire, tellsRequestRedaction := requestPassWires[scope], wireTellsRequestRedaction(scope)
	result := &StaticPolicyResult{Blocked: d.verdict == VerdictDeny, TriggeredPolicies: d.evaluatedPolicies}
	if result.Blocked {
		result.Reason = strings.Join(d.reasons, "; ")
		return result, d.reasonCode
	}
	for _, o := range d.obligations {
		if tellsRequestRedaction && o.Type == ObligationRedactPII && o.Fulfillment != nil && o.Fulfillment.Phase == ObligationPhaseRequest {
			result.RequiresRedaction = true
			continue
		}
		phase := "no"
		if o.Fulfillment != nil {
			phase = "the " + o.Fulfillment.Phase
		}
		return &StaticPolicyResult{
			Blocked:           true,
			TriggeredPolicies: d.evaluatedPolicies,
			Reason: fmt.Sprintf("%s: the %s obligation (%s) is fulfilled on %s phase, and %s cannot tell its caller to discharge it",
				contract.ReasonUnsupportedObligation, o.Type, o.Detail, phase, wire),
		}, string(contract.ReasonUnsupportedObligation)
	}
	return result, d.reasonCode
}

// violationFeedsCircuitBreaker reports whether a deny with this reason code is
// recorded against the circuit breaker. A refusal because the caller cannot
// discharge a mandatory obligation (ADR-065 invariant 8, unsupported_obligation)
// is a seam-capability outcome, not a policy violation by the caller: the same
// content from a caller that declared the capability is allowed with the
// obligation. Recording it would circuit-break a client after twenty such
// requests by default (AXONFLOW_CB_POLICY_VIOLATION_THRESHOLD), which is the
// rule #2958 already holds for its fallback gate (#3564).
//
// Nor is an indeterminate deny: a constraint (unknown_constraint) or a
// requirement (unknown_requirement) that could not be evaluated. That is a data
// or availability outcome - an attribute nothing supplied, a detector with no
// engine to run it - not a violation by the caller. An unknown_constraint deny
// named no policy before #4227, so no plane recorded it, and naming the
// constraint must not start recording it. An unknown_requirement deny names the
// permissions that matched and was recorded against them: the same outcome,
// counted by mistake (#4227). Recorded, twenty such requests by default lock
// the client out of every plane.
//
// Nor are three more refusals that are not the caller's doing (#4246):
//   - approval_required: the engine asked for a person's approval and the
//     plane has no approval hold (PRD v11 §1.13). Recorded, a client whose
//     requests need approval is locked out while it waits for one.
//   - obligation_conflict: the obligations the matched policies attach
//     conflict, which is how the policies were authored, not what the
//     caller sent.
//   - evaluation_error: the request could not be evaluated. The platform
//     failed, not the caller. /api/request's segment fail-closed deny was
//     this class too, until #4253 removed the route's segment gate.
//
// The deny itself is unchanged: the caller still gets its reason and the
// site's audit row still records it; only the breaker feed stops.
func violationFeedsCircuitBreaker(reasonCode string) bool {
	switch contract.ReasonCode(reasonCode) {
	case contract.ReasonUnsupportedObligation, contract.ReasonUnknownConstraint, contract.ReasonUnknownRequirement,
		contract.ReasonApprovalRequired, contract.ReasonObligationConflict, contract.ReasonEvaluationError:
		return false
	}
	return true
}

// --- posture: /health ---

// decisionPostureHealth is /health's `decision` member: the scopes whose
// verdict the anchored engine authors in this process (PRD v11 §5.1). It is nil
// - and the member OMITTED, never null - only on a process with no enforcer,
// which a serving agent is not: wiring one is fatal at boot (wireEnforcingSeams).
func decisionPostureHealth() map[string]interface{} {
	if anchoredEnforcerInstance.Load() == nil {
		return nil
	}
	names := make([]string, 0, len(enforcingSeams))
	for _, s := range enforcingSeams {
		names = append(names, s.scope.String())
	}
	sort.Strings(names)
	return map[string]interface{}{"enforcing_planes": names}
}

// deploymentCanVerifyUserIdentity reports whether this deployment mode has ANY
// path that verifies a per-user identity. It is the one predicate
// callerHasVerifiedUserIdentity and callerUserIdentity read, so the two cannot
// disagree: community and community-SaaS synthesize a fixed user from no
// credential, and nothing else there produces a user subject, so every request
// there is evaluated for its client credential.
func deploymentCanVerifyUserIdentity() bool {
	return !isCommunityMode() && !isCommunitySaasMode()
}
