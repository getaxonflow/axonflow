// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package anchoredenforcer is the anchored engine's enforcer, shared by every
// process that authors a verdict on an enforcing scope (PRD v11 §1.1).
//
// The active-document read, the per-(scope, organization) activation, the
// identity plane's subject admission and the request normalization are the same
// code for every scope and every process. A process supplies only what it alone
// can read (Options): an organization's recorded detection overrides, what each
// of its scopes' wires delivers, and the deployment's edition boundary, which is
// resolved from the licence in the process that holds it. Each seam maps its
// request onto a Call and the Verdict back onto its own wire.
//
// It moved here from platform/agent without a change in behaviour, so that the
// orchestrator's planes are decided by the same enforcer as the agent's rather
// than by a second copy of it.
//
// Edition: community-visible, no build tag. The decision model is
// community_core (ADR-066 driver 3).
package anchoredenforcer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	"axonflow/platform/policy/authoringstore"
	sharedidentity "axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	// EngineAnchored is the `engine` value a decision record and a
	// response carry for a verdict the anchored engine authored - every verdict
	// on an enforcing scope. Since #4253 it is the only value: no enforcing scope
	// carries a legacy verdict.
	EngineAnchored = "anchored"

	// maxEnforcedOrganizations bounds the per-organization caches below. They
	// hold one store handle per organization and one built engine per
	// (scope, organization); exceeding the bound costs a rebuild, never a wrong
	// answer.
	maxEnforcedOrganizations = 1024
)

// Causes a request fails CLOSED with. Each is a metric label value and the
// stable half of the refusal's message; the underlying error is logged, never
// returned, because it can name storage and realm configuration a caller has no
// business reading.
const (
	CauseNotWired       = "enforcer_not_wired"
	CauseActiveDocument = "active_document_unreadable"
	CauseOverrides      = "detection_overrides_unreadable"
	CauseActivation     = "activation_failed"
	// CauseCapability is an activation refused because the active
	// document spends a construct this deployment's edition does not carry
	// (#3592). It is SEPARATE from CauseActivation deliberately: that
	// cause covers a document that could not be activated for any reason -
	// an unreadable bundle, a signature that does not verify, an anchor that
	// does not match - and an operator watching the counter cannot act on a
	// label that means all of those at once. This one says "this
	// organization's licence no longer carries what its document spends",
	// which is an upgrade conversation rather than an incident.
	CauseCapability          = "capability_requires_upgrade"
	CauseSubjectUnverifiable = "subject_unverifiable"
	CauseRequest             = "request_unbuildable"
	CauseEvaluation          = "evaluation_failed"
	CauseObligation          = "obligation_undischargeable"
)

// CauseForActivation names WHY an activation failed, so the counter
// says something an operator can act on.
//
// ActivationFor wraps what activation.Activate returns, so this reads the chain
// with errors.As rather than asserting on the value: a type assertion would
// match the bare refusal in a test and nothing in production, which is the
// shape that makes a distinction look implemented while every real refusal
// keeps the generic label.
//
// Everything that is not the edition boundary stays CauseActivation. The
// default direction matters: a new activation refusal added later is reported
// as an activation failure, which is true if uninformative, rather than being
// mislabelled a licence problem and sending an operator to buy something.
func CauseForActivation(err error) string {
	var refusal *activation.CapabilityRefusal
	if errors.As(err, &refusal) {
		return CauseCapability
	}
	return CauseActivation
}

var CauseMessages = map[string]string{
	CauseNotWired:            "no policy enforcer is wired in this process for this plane",
	CauseActiveDocument:      "this organization's active policy document could not be read",
	CauseOverrides:           "this organization's recorded detection overrides could not be read into the policy engine",
	CauseActivation:          "this organization's policy could not be activated",
	CauseCapability:          "this organization's active policy document spends a construct this deployment's edition does not carry; upgrade the deployment, or withdraw the document",
	CauseSubjectUnverifiable: "the identity plane could not establish the request's subject",
	CauseRequest:             "the request could not be normalized for the policy engine",
	CauseEvaluation:          "the policy engine could not evaluate the request",
	CauseObligation:          "an obligation the policy engine attached could not be discharged",
}

// Decisions makes every decision on an enforcing scope
// COUNTABLE PER SCOPE: which scope, which engine authored it, the verdict and
// why.
//
// IT CARRIES NO org_id LABEL. Until v11 it did, because only an organization
// that had opted into enforce produced a series, so the label was bounded by
// the organizations an operator had switched. With no mode every
// organization's every decision lands here, so an org_id label would be
// bounded by nothing but the organization count - community-SaaS mints one per
// evaluator. The per-organization record is the decision's audit row, which
// carries the engine, the subject type and the policy bundle.
var Decisions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_decision_enforce_decisions_total",
		Help: "Decisions on an enforcing scope, by enforcement scope (plane, or plane:phase), the engine that authored the verdict (anchored; since #4253 no other engine authors one on an enforcing scope), the verdict (allow|deny|needs_approval|unavailable) and the reason",
	},
	[]string{"plane", "engine", "verdict", "reason"},
)

func init() {
	_ = prometheus.Register(Decisions)
}

// --- the organization's active document ---

// ActiveDocumentSource is the seam's read of an organization's ACTIVE typed
// document. Every read runs inside rls.WithOrgScope in the durable
// implementation, so a read made without the organization GUC cannot silently
// return nothing for everyone.
type ActiveDocumentSource interface {
	// ActiveTip returns the digest of the organization root's ACTIVE document
	// and its latest activation's sequence number (its policy epoch). An empty
	// digest with a nil error means nothing is active - nothing was ever
	// activated, or the organization withdrew its document (PRD v11 §1.15) -
	// and the root is decided by the implicit baseline.
	ActiveTip(ctx context.Context, orgID string) (digest string, policyEpoch int64, err error)
	// Load returns the VERIFIED artifact stored under digest and a trust store
	// PRIVATE to the caller, because activation authorizes the process's system
	// key into the store it is given.
	Load(ctx context.Context, orgID, digest string) (*authoring.Artifact, *pdp.TrustStore, error)
}

// DurableActiveDocuments reads the active document from the typed-authoring
// tables (migrations/core/176) through authoringstore, verifying and never
// signing.
type DurableActiveDocuments struct {
	db     *sql.DB
	mu     sync.Mutex
	stores map[string]*authoringstore.Store
}

func NewDurableActiveDocuments(db *sql.DB) *DurableActiveDocuments {
	return &DurableActiveDocuments{db: db, stores: map[string]*authoringstore.Store{}}
}

// storeFor opens a verifying store per organization once. A failed open is not
// cached, so a transient database error costs one retry per request rather than
// the organization's enforcement for the life of the process.
func (d *DurableActiveDocuments) storeFor(ctx context.Context, orgID string) (*authoringstore.Store, error) {
	d.mu.Lock()
	if s, ok := d.stores[orgID]; ok {
		d.mu.Unlock()
		return s, nil
	}
	d.mu.Unlock()
	s, _, err := authoringstore.OpenForVerifying(ctx, d.db, pdp.RootOrganization, orgID)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.stores) >= maxEnforcedOrganizations {
		d.stores = map[string]*authoringstore.Store{}
	}
	d.stores[orgID] = s
	return s, nil
}

func (d *DurableActiveDocuments) ActiveTip(ctx context.Context, orgID string) (string, int64, error) {
	s, err := d.storeFor(ctx, orgID)
	if err != nil {
		return "", 0, err
	}
	return s.ActiveTip(ctx, pdp.RootOrganization)
}

func (d *DurableActiveDocuments) Load(ctx context.Context, orgID, digest string) (*authoring.Artifact, *pdp.TrustStore, error) {
	s, err := d.storeFor(ctx, orgID)
	if err != nil {
		return nil, nil, err
	}
	art, ok, err := s.GetArtifact(ctx, pdp.RootOrganization, digest)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("the organization's latest activation names digest %s and no stored artifact carries it", digest)
	}
	trust, err := s.LoadTrust(ctx, pdp.RootOrganization)
	if err != nil {
		return nil, nil, err
	}
	return art, trust, nil
}

// --- the enforcer ---

// Enforcer builds and caches the anchored engine per enforcement scope
// and organization, and decides with it. One instance serves every scope.
type Enforcer struct {
	documents  ActiveDocumentSource
	vocabulary func() (*authoringcatalog.Snapshot, error)
	identity   *sharedidentity.SubjectAdmitter
	// identityEpoch is the realm registry's epoch, stamped onto every request
	// snapshot so a decision says which realm declarations it was taken under.
	identityEpoch func() int64
	// system signs this process's restrictions of the shipped corpus, one per
	// scope. Its key is minted here and never persisted: a key minted per
	// process signs a bundle only this process verifies
	// (SYSTEM_ROOT_SIGNING_AUTHORITY §3), and it is never an organization's
	// signing key (#4047).
	system *authoring.SystemAuthority
	// composition signs an organization root this process composes: one whose
	// recorded overrides re-action shipped controls (#4045), and the implicit
	// baseline of an organization that has published nothing (PRD v11 §1.4).
	// Its key is minted here beside the system key, never persisted, and never
	// an organization's key.
	composition *authoring.CompositionAuthority
	// overrides reads an organization's recorded detection overrides as the
	// plane's legacy engine assigns them; an error fails the request closed.
	overrides func(ctx context.Context, orgID string) (legacycompile.CategoryActions, error)
	// delivers is what each scope's wire hands an enforcement point that declares
	// it (#4046): activation refuses a scope whose restriction it cannot
	// discharge. The process supplies it from its own seam registration.
	delivers func(scope legacycompile.EnforcementScope) []contract.Capability
	// editionBoundary is the deployment's authoring profile, and whether this
	// process may refuse a document that spends a construct its edition does not
	// carry. The process that holds the licence resolves it; this package never
	// reads a licence.
	editionBoundary func(ctx context.Context) (authoring.Profile, bool)
	now             func() time.Time
	// Packs are the policy packs this deployment installed, instantiated for
	// its realms once, at install (policy_packs.go), and composed by every
	// activation beside the baseline pack (PRD v11 §1.9).
	Packs []activation.InstalledPack

	mu          sync.Mutex
	activations map[enforcedKey]enforcedActivation
}

// enforcedKey names one cached engine. Two scopes of one organization bind
// different restrictions of the corpus, so they are two engines.
type enforcedKey struct {
	scope legacycompile.EnforcementScope
	orgID string
}

type enforcedActivation struct {
	// digest is the active document's, empty for the implicit baseline.
	digest string
	// overrides is the digest of the recorded overrides the engine folded,
	// empty when none was recorded.
	overrides string
	// packs is the installed pack set the activation composed
	// (installedPackKey): an activation built under another set is not the
	// one to reuse, whenever the enforcer's packs were set.
	packs string
	act   *activation.Activation
}

// installedPackKey is the installed pack set as the activation memo keys it,
// each pack by its ref (<pack id>@<pack document digest>), in install order.
func installedPackKey(packs []activation.InstalledPack) string {
	refs := make([]string, len(packs))
	for i, p := range packs {
		refs[i] = p.Ref()
	}
	return strings.Join(refs, ",")
}

// Options are the pieces of an enforcer only the process that runs it can
// supply.
type Options struct {
	// Overrides reads an organization's recorded detection overrides as the
	// plane's legacy engine assigns them; an error fails the request closed. Nil
	// means none is recorded.
	Overrides func(ctx context.Context, orgID string) (legacycompile.CategoryActions, error)
	// Delivers is what each scope's wire delivers, for every seam the process
	// registers (legacycompile.ScopeDeliveries). Nil delivers nothing on any
	// scope.
	Delivers func(scope legacycompile.EnforcementScope) []contract.Capability
	// EditionBoundary resolves the deployment's authoring profile and whether an
	// activation may refuse a construct outside the edition. It is REQUIRED:
	// neither answer is a safe default.
	EditionBoundary func(ctx context.Context) (authoring.Profile, bool)
}

// New builds an enforcer over an organization's active-document source, the
// deployment vocabulary, the identity plane's subject admitter and its realm
// epoch, minting this process's system and composition signing keys.
func New(
	documents ActiveDocumentSource,
	vocabulary func() (*authoringcatalog.Snapshot, error),
	identity *sharedidentity.SubjectAdmitter,
	identityEpoch func() int64,
	opts Options,
) (*Enforcer, error) {
	if documents == nil || vocabulary == nil || identity == nil || identityEpoch == nil {
		return nil, errors.New("anchored enforcer: an active-document source, a vocabulary, a subject admitter and a realm epoch are all required")
	}
	if opts.EditionBoundary == nil {
		return nil, errors.New("anchored enforcer: an edition boundary is required; an activation must know whether it may refuse a construct outside the deployment's edition")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("anchored enforcer: minting the system corpus signing key: %w", err)
	}
	system, err := authoring.NewSystemAuthority(priv)
	if err != nil {
		return nil, fmt.Errorf("anchored enforcer: %w", err)
	}
	_, compositionPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("anchored enforcer: minting the organization composition signing key: %w", err)
	}
	composition, err := authoring.NewCompositionAuthority(compositionPriv)
	if err != nil {
		return nil, fmt.Errorf("anchored enforcer: %w", err)
	}
	overrides := opts.Overrides
	if overrides == nil {
		overrides = func(context.Context, string) (legacycompile.CategoryActions, error) { return nil, nil }
	}
	delivers := opts.Delivers
	if delivers == nil {
		delivers = func(legacycompile.EnforcementScope) []contract.Capability { return nil }
	}
	return &Enforcer{
		documents: documents, vocabulary: vocabulary, identity: identity, identityEpoch: identityEpoch,
		system:          system,
		composition:     composition,
		overrides:       overrides,
		delivers:        delivers,
		editionBoundary: opts.EditionBoundary,
		now:             func() time.Time { return time.Now().UTC() },
		activations:     map[enforcedKey]enforcedActivation{},
	}, nil
}

// MemoizedDeploymentVocabulary resolves the deployment vocabulary on first use
// and memoizes a success only, for the orchestrator route's reason: a transient
// failure at the first request must not freeze the wrong vocabulary (and the
// wrong catalog digest) until a restart.
func MemoizedDeploymentVocabulary(resolve func() (*authoringcatalog.Snapshot, error)) func() (*authoringcatalog.Snapshot, error) {
	var (
		mu   sync.Mutex
		snap *authoringcatalog.Snapshot
	)
	return func() (*authoringcatalog.Snapshot, error) {
		mu.Lock()
		defer mu.Unlock()
		if snap != nil {
			return snap, nil
		}
		s, err := resolve()
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, errors.New("the deployment vocabulary resolved to nothing")
		}
		snap = s
		return s, nil
	}
}

// ActivationFor returns the organization's anchored engine for one scope, the
// active digest - empty for an organization that has published nothing - and
// the organization's recorded overrides, building it when either changes. A
// rollback reinstates an earlier digest, which is a change here, so it takes
// effect on the next request; so does a first publication, which replaces the
// implicit baseline, and an override recorded or deleted, once the override
// cache serves it (#4045).
func (e *Enforcer) ActivationFor(ctx context.Context, scope legacycompile.EnforcementScope, orgID, digest string, assigned legacycompile.CategoryActions) (*activation.Activation, error) {
	overrides := ""
	if len(assigned) > 0 {
		d, err := contract.ExactDigest(assigned)
		if err != nil {
			return nil, fmt.Errorf("digesting the recorded detection overrides: %w", err)
		}
		overrides = d
	}
	packs := installedPackKey(e.Packs)
	key := enforcedKey{scope: scope, orgID: orgID}
	e.mu.Lock()
	if c, ok := e.activations[key]; ok && c.digest == digest && c.overrides == overrides && c.packs == packs {
		e.mu.Unlock()
		return c.act, nil
	}
	e.mu.Unlock()

	snap, err := e.vocabulary()
	if err != nil {
		return nil, fmt.Errorf("resolving the deployment vocabulary: %w", err)
	}
	// No active document: the organization root is the implicit baseline, which
	// activation composes, and there is no organization key to read.
	var art *authoring.Artifact
	trust := pdp.NewTrustStore()
	if digest != "" {
		if art, trust, err = e.documents.Load(ctx, orgID, digest); err != nil {
			return nil, fmt.Errorf("loading the active document: %w", err)
		}
	}
	// The edition boundary, at the door publication cannot guard. A document
	// can reach this store without passing through authoring at all - the
	// importer takes its edition from an operator flag, and core/176 grants the
	// application role INSERT on typed_policy_artifacts - so the engine asks
	// the question here too.
	//
	// GATED, unlike the transports' dry run. An activation error on this path
	// is HTTP 503 on /api/v1/decide and a withheld MCP response, so it must not
	// fire for a deployment that merely cannot establish its tier, nor for one
	// whose operator has declared a licence transition and is winding down
	// deliberately (#4094). EnforcesConstructBoundary is that question, asked
	// once, by the one resolver, in the process that holds the licence and
	// supplies editionBoundary.
	profile, refuseOutsideEdition := e.editionBoundary(ctx)
	act, err := activation.Activate(ctx, activation.Inputs{
		Snapshot:     snap,
		Organization: art,
		Trust:        trust,
		System:       e.system,
		// The organization's recorded detection overrides and the authority
		// that signs the organization root they compose into (#4045) - and the
		// implicit baseline, when no document is active.
		OrganizationID: orgID,
		Overrides:      assigned,
		Composition:    e.composition,
		Plane:          string(scope.Plane),
		Phase:          scope.Phase,
		// The edition boundary and the gate that decides whether it may refuse
		// here (#3592). Both are additions beside #4045's fields, not instead
		// of them: the overrides say WHAT this organization enforces, and these
		// say whether this deployment may enforce a document that spends a
		// construct its edition does not carry.
		Profile:                        profile,
		RefuseConstructsOutsideEdition: refuseOutsideEdition,
		// What this scope's seam hands to a caller that declares it (#4046):
		// activation refuses a scope whose restriction it cannot discharge.
		Delivers: e.delivers(scope),
		// The deployment's installed policy packs (PRD v11 §1.9).
		Packs: e.Packs,
	})
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.activations) >= maxEnforcedOrganizations {
		e.activations = map[enforcedKey]enforcedActivation{}
	}
	e.activations[key] = enforcedActivation{digest: digest, overrides: overrides, packs: packs, act: act}
	return act, nil
}

// Call is one request an enforcing seam hands the anchored engine.
type Call struct {
	Scope     legacycompile.EnforcementScope
	OrgID     string
	RequestID string
	// action is the registered action's local name; actionErr, when set, says
	// why the plane could not name one, and the request fails closed on it.
	Action    string
	ActionErr error
	// subject builds the credential the identity plane admits, and says which
	// door it is admitted through.
	Subject func(now time.Time) (Subject, bool)
	// query is the content the action is evaluated over (args.query).
	Query string
	// observation is the evaluation's detector facts; nil when the shared
	// engine evaluated nothing, and then every detector is ABSENT.
	Observation *sharedpolicy.Observation
	// emptyContent says the content is empty, so a content detector's answer is
	// determined without running it (see anchoredRequest).
	EmptyContent bool
	// pep is the admitted handshake's profile, nil when none was admitted.
	PEP *contract.PEPProfile
	// Facts are attributes the seam's own reader of the request states beside
	// what the enforcer builds (#4254): a plane whose facts come from a producer
	// rather than from a detector observation hands them over here. A fact never
	// replaces what the enforcer builds itself (mergeFacts). Nil for a seam that
	// states none, which then gets exactly the request it got before.
	Facts contract.AttributeSet
}

// Subject is the credential a request presents to the identity plane
// and the door it is admitted through.
type Subject struct {
	Principal sharedidentity.CredentialPrincipal
	// credential says the request carries no user identity, so its
	// authenticated client credential is the principal
	// (SubjectAdmitter.AdmitCredentialSubject).
	Credential bool
}

// Verdict is the enforcer's answer for one call. Exactly one of these
// holds: the request failed closed (unavailable); the identity plane refused
// its subject (refusal); or the engine decided (decision).
type Verdict struct {
	Unavailable string
	Act         *activation.Activation
	Refusal     *sharedidentity.Admission
	Decision    *contract.Decision
	// subjectType is the admitted principal's type (User, Client, Service),
	// set whenever the identity plane admitted one.
	SubjectType string
}

// FailClosed logs why a request could not get an anchored verdict.
func FailClosed(scope legacycompile.EnforcementScope, orgID, cause string, err error) {
	log.Printf("[ANCHORED-ENFORCE] scope=%s org=%s failing closed (%s): %s", scope, logutil.Sanitize(orgID), cause, logutil.Sanitize(err.Error()))
}

// Evaluate is the enforcer's one decision path, in the order every scope
// shares: the active document, the recorded overrides, the scope's engine, the
// action, the subject, the request, the engine.
func (e *Enforcer) Evaluate(ctx context.Context, call Call) Verdict {
	var v Verdict
	fail := func(cause string, err error) Verdict {
		v.Unavailable = cause
		FailClosed(call.Scope, call.OrgID, cause, err)
		return v
	}
	// An empty digest is an organization with no active document - it has
	// published nothing, or withdrew what it had - decided by the implicit
	// baseline (ActivationFor).
	digest, epoch, err := e.documents.ActiveTip(ctx, call.OrgID)
	if err != nil {
		return fail(CauseActiveDocument, err)
	}
	if call.ActionErr != nil {
		return fail(CauseRequest, call.ActionErr)
	}
	// An override that cannot be read fails closed: the legacy engine's read
	// substitutes no override on an error, which here would enforce the shipped
	// action the organization recorded a change to (#4045).
	assigned, err := e.overrides(ctx, call.OrgID)
	if err != nil {
		return fail(CauseOverrides, err)
	}
	act, err := e.ActivationFor(ctx, call.Scope, call.OrgID, digest, assigned)
	if err != nil {
		return fail(CauseForActivation(err), err)
	}
	v.Act = act
	action, err := contract.ParseID(contract.KindAction, "Action::"+call.Action)
	if err != nil {
		return fail(CauseRequest, err)
	}
	entry, ok := act.Snapshot.Catalog.Actions[action.String()]
	if !ok {
		return fail(CauseRequest, fmt.Errorf("action %s is not in the deployment vocabulary", action))
	}

	principal, subjectType, adm := e.subjectFor(ctx, call, entry.MaxDelegationDepth)
	switch {
	case adm.State == sharedidentity.AdmissionDeny:
		// A determinate refusal of this request's subject: a user token that
		// did not verify, or a credential its realm does not admit.
		v.Refusal = &adm
		return v
	case !adm.State.IsAdmitted():
		return fail(CauseSubjectUnverifiable, errors.New(adm.String()))
	}
	v.SubjectType = subjectType

	req, err := anchoredRequest(act, entry, action, principal, call, epoch, e.identityEpoch(), e.now())
	if err != nil {
		return fail(CauseRequest, err)
	}
	dec, err := act.Engine.DecideWith(ctx, req, pdp.DecideOptions{PEP: call.PEP})
	if err != nil {
		return fail(CauseEvaluation, err)
	}
	v.Decision = dec
	return v
}

// subjectFor admits the call's subject through the identity plane's door for
// it, and returns the admitted principal and its type.
func (e *Enforcer) subjectFor(ctx context.Context, call Call, maxDepth int) (contract.ID, string, sharedidentity.Admission) {
	var subject Subject
	ok := false
	if call.Subject != nil {
		subject, ok = call.Subject(e.now())
	}
	if !ok {
		return contract.ID{}, "", sharedidentity.IndeterminateAdmission(sharedidentity.ReasonIdentityInternalError,
			"the request carries no authenticated organization and auth kind the identity plane can verify")
	}
	admit := e.identity.AdmitDecisionSubject
	if subject.Credential {
		admit = e.identity.AdmitCredentialSubject
	}
	chain, adm := admit(ctx, subject.Principal, maxDepth)
	if !adm.State.IsAdmitted() {
		return contract.ID{}, "", adm
	}
	root, _ := chain.Root()
	id, err := contract.ParseID(contract.KindPrincipal, root.String())
	if err != nil {
		return contract.ID{}, "", sharedidentity.IndeterminateAdmission(sharedidentity.ReasonIdentityInternalError,
			fmt.Sprintf("the admitted principal %s is not a decision-contract identifier: %v", root, err))
	}
	return id, string(root.Type), adm
}

// anchoredRequest normalizes one call for the anchored engine.
//
// Four tri-state choices, each the honest one:
//   - args.query is KNOWN; every other argument the action declares is ABSENT,
//     because the plane has no field for it and the caller therefore
//     positively supplied none;
//   - a detector the evaluation RAN is KNOWN at what it found;
//   - on EMPTY content, a detector signal an activated policy reads that the
//     evaluation did not run is KNOWN false: a content detector over no content
//     has a determined answer, so this states a fact about the content, not
//     about a detector nobody ran (#3564);
//   - otherwise a detector it did not run is left out, which the engine reads
//     as UNKNOWN - never a fabricated false.
func anchoredRequest(
	act *activation.Activation,
	entry pdp.ActionEntry,
	action, principal contract.ID,
	call Call,
	policyEpoch, identityEpoch int64,
	now time.Time,
) (*contract.Request, error) {
	org, err := contract.ParseID(contract.KindOrganization, "Organization::"+call.OrgID)
	if err != nil {
		return nil, fmt.Errorf("organization: %w", err)
	}
	resource, err := contract.ParseID(contract.KindResource, "Request::self:"+call.RequestID)
	if err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}
	tags := make([]any, 0, len(entry.Tags))
	for _, tag := range entry.Tags {
		tags = append(tags, tag)
	}
	shared := contract.AttributeSet{
		"action.id":                              contract.Known(action.String(), contract.ProvPlatform, 1, now),
		"action.tags":                            contract.Known(tags, contract.ProvPlatform, 1, now),
		"args." + authoringcatalog.ArgumentQuery: contract.Known(call.Query, contract.ProvCaller, 1, now),
	}
	for name := range entry.Arguments {
		if name == authoringcatalog.ArgumentQuery {
			continue
		}
		shared["args."+name] = contract.Absent(contract.ProvCaller, 1, now)
	}
	// built is every path the enforcer states itself for this request, which a
	// seam's fact never replaces: the action, its tags, the query, and each
	// detector stated below.
	built := map[string]bool{"action.id": true, "action.tags": true, "args." + authoringcatalog.ArgumentQuery: true}
	if call.Observation != nil {
		for _, row := range call.Observation.Rows {
			if !row.Ran {
				continue
			}
			path := registry.DetectorID(row.PolicyID).SignalPath()
			shared[path] = contract.Known(row.Matched, contract.ProvDetector, 1, now)
			built[path] = true
		}
	}
	if call.EmptyContent {
		for _, path := range act.DetectorSignalPaths() {
			if _, known := shared[path]; !known {
				shared[path] = contract.Known(false, contract.ProvDetector, 1, now)
				built[path] = true
			}
		}
	}
	actor := contract.AttributeSet{"principal.id": contract.Known(principal.String(), contract.ProvAuthentication, 1, now)}
	if err := mergeFacts(shared, actor, built, call.Facts); err != nil {
		return nil, err
	}
	return &contract.Request{
		RequestID:    call.RequestID,
		Organization: org,
		Principal:    principal,
		Action:       action,
		Resource:     resource,
		Context: contract.Context{ActorChain: []contract.Actor{{
			ID:         principal,
			Attributes: actor,
		}}},
		Snapshot:    act.RequestSnapshot(identityEpoch, 0, policyEpoch),
		Attributes:  shared,
		EvaluatedAt: now,
	}, nil
}

// mergeFacts adds a seam's facts (Call.Facts) to the request the enforcer
// normalized, or refuses them.
//
// A fact at a path the enforcer builds is refused, naming the path, and never
// taken: action.* and the query are the plane's own record of what is being
// decided, principal.id is the admitted subject, and a detector the enforcer
// stated came from this evaluation's observation or its empty content. Evaluate
// refuses the request as CauseRequest.
//
// A declared argument the enforcer marks ABSENT may be stated. ABSENT says the
// plane has no field for it; a seam whose reader of the request supplies one
// would make that statement false, so its fact is KNOWN instead.
//
// A principal fact describes the subject, so it goes on the root actor, where
// the contract requires identity attributes to live; every other fact is shared.
// Only the principal attributes in seamPrincipalFacts may be stated.
func mergeFacts(shared, actor contract.AttributeSet, built map[string]bool, facts contract.AttributeSet) error {
	for _, path := range facts.Paths() {
		if built[path] || strings.HasPrefix(path, "action.") || path == "principal.id" {
			return fmt.Errorf("the seam stated a fact at %s, a path the enforcer builds itself and never lets a fact replace", path)
		}
		if contract.NamespaceOf(path) == contract.NsPrincipal {
			if !seamPrincipalFacts[path] {
				return fmt.Errorf("the seam stated a fact at %s, a principal attribute no seam may state: the identity plane is the authority for the admitted subject", path)
			}
			actor[path] = facts[path]
			continue
		}
		shared[path] = facts[path]
	}
	return nil
}

// seamPrincipalFacts are the principal attributes a seam may state (R3 A-M1).
// A principal fact describes the admitted subject, and the identity plane is its
// authority: a seam that stated another would place a request-bound field, such
// as a role or a tenant read from the request, beside the principal the identity
// plane admitted, with authentication provenance. principal.region, which the
// dynamic fact producer states ABSENT, is the only one.
var seamPrincipalFacts = map[string]bool{"principal.region": true}

// RecordEnforcement counts one decision on an enforcing scope.
func RecordEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {
	Decisions.WithLabelValues(scope.String(), engine, verdict, reason).Inc()
}

// CachedActivation is one engine an enforcer holds: the scope and organization
// it was activated for, and the activation.
type CachedActivation struct {
	Scope      legacycompile.EnforcementScope
	OrgID      string
	Activation *activation.Activation
}

// CachedActivations is a snapshot of the engines the enforcer holds, for a
// caller that reads what a request BUILT rather than what it answered.
func (e *Enforcer) CachedActivations() []CachedActivation {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]CachedActivation, 0, len(e.activations))
	for key, cached := range e.activations {
		out = append(out, CachedActivation{Scope: key.scope, OrgID: key.orgID, Activation: cached.act})
	}
	return out
}
