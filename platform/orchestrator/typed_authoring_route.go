// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The COMMUNITY typed-authoring write route (#3907).
//
// # The gap this closes, stated precisely, because the obvious statement of it
// # is wrong
//
// The edition ladder gives Community 20 customer-authored policies and
// Evaluation 50 (#3906). Before this file there was no way to spend one on a
// deployment without the Enterprise portal, and the reason is not the one the
// issue title suggests:
//
//   - it was NOT the store. platform/decision/authoring.Store is in-process on
//     every edition and always has been; there is no document table for
//     Enterprise either. Durability is #3776/#3880's, not this file's.
//   - it was NOT only the route. Even given one, publication refused any
//     document whose approver set did not contain somebody other than the
//     author, and activation refused any actor who was not a recorded approver.
//     PRD section 5.3 rules separation of duties None / None / Full, so those
//     refusals were an Enterprise capability applied to every edition, and a
//     single-administrator deployment could not have published through this
//     route on the day it was written.
//
// So the fix is three things that only work together: the edition profile in
// platform/decision/authoring (which constructs, and whether two people are
// required), this route, and the ladder's numbers keyed on what a customer
// writes. Any one alone is dead code.
//
// # Why the ORCHESTRATOR, and not the agent, and not a CLI
//
// The orchestrator already owns customer policy writes. /api/v1/policies is
// here, the tier admission wiring for policy creation is here
// (admission_wiring.go), and the org-scoped session every write runs inside is
// here. Putting the new write path anywhere else would mean a deployment has
// two services that write policy and one tier ledger between them.
//
// The agent is the gateway: it is the enforcement plane, and an authoring
// control plane behind it would put policy authorship on the request path.
//
// A CLI is NOT an alternative to this, and the reason is mechanical rather
// than architectural: platform/cmd/axonctl is a SEPARATE GO MODULE with its own
// go.mod, requiring only cobra, and it takes no dependency on the platform
// module at all. A CLI that authored typed policy would therefore either
// acquire the whole decision module as a dependency, or be an HTTP client of
// this route. The second is what #3907's CLI bullet becomes, and it is
// sequenced after this rather than dropped.
//
// # Why the portal is now the SECOND client of the library rather than the only
//
// ee/platform/customer-portal/api/typed_authoring.go is unchanged in what it
// does. It is Enterprise, it stays Enterprise, and #3907 explicitly does not
// propose a Community portal. What changes is that platform/decision/authoring
// is no longer reachable from exactly one transport under ee/.
package orchestrator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent"
	"axonflow/platform/agent/license"
	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
	"axonflow/platform/shared/activationinputs"
	"axonflow/platform/shared/authoringedition"
	"axonflow/platform/shared/authoringvocabulary"
	"axonflow/platform/shared/detectionposture"
	"axonflow/platform/shared/identity"
)

// TypedAuthoringRoutePrefix is the one prefix this handler owns.
const TypedAuthoringRoutePrefix = "/api/v1/typed-policies"

const (
	// maxTypedAuthoringWorkspaces bounds the per-organization authoring planes
	// this process holds. Each carries an in-process store and a signing key,
	// so an unbounded map is a memory leak keyed on a request header.
	maxTypedAuthoringWorkspaces = 32
	// maxTypedAuthoringArtifactsPerOrg bounds one workspace's admitted
	// artifacts. It is a MEMORY bound and is deliberately not the tier limit:
	// the tier limit counts DOCUMENTS through the admission ledger and is a
	// commercial ceiling, while this counts artifacts in this process's heap
	// and would be here on an unlimited tier too.
	maxTypedAuthoringArtifactsPerOrg = 256
	// typedAuthoringMaxRequestBytes bounds a document body.
	typedAuthoringMaxRequestBytes = 512 << 10
)

// typedAuthoringRoot is the ONE authority root this surface publishes under.
//
// It is a constant and never a request field. pdp.RootSystem is the platform's
// own authority - "an organization policy can grant only within system
// constraints and can never modify them" - so a customer-facing route able to
// publish there would be a customer editing the platform's ceiling. Publish
// refuses a cross-root publication before anything is compiled, so this is
// belt and braces; it is a constant here so there is no field to forget.
//
// NOTE, because #3906 is easy to misread: the root is fixed, and that is NOT
// the edition boundary. Every customer-authored policy on every edition is
// organization-root. What differs by edition is which constructs the document
// may use, which authoring.Profile carries.
const typedAuthoringRoot = pdp.RootOrganization

// typedAuthoringAuthorRealm is the realm of a subject this route accepts as an
// author.
//
// A principal is <SubjectType>::<realm>:<subject>, and the realm names WHO
// ASSERTED the subject. The caller reaching this route was authenticated by the
// agent gateway, which stamps X-User-ID on the proxied request - the trust-gated
// identity-header path (#2896). So the honest realm is that one. It is carried
// into the SIGNED document source as metadata.author, which is why it is a
// declared constant with a reason rather than whatever string was to hand.
var typedAuthoringAuthorRealm = identity.BuiltinRealmTrustedHeader

// TypedAuthoringRouteHandler serves the community typed-authoring surface.
type TypedAuthoringRouteHandler struct {
	// catalogValue is the RAW environment value, captured at construction.
	// The vocabulary it names is resolved lazily; see vocabulary().
	catalogValue string
	// deploymentFor describes this process's identity plane to the resolver.
	// It is a function, not a value, for the ordering reason vocabulary()
	// states.
	deploymentFor func() authoringvocabulary.CatalogDeployment

	// THE VOCABULARY IS RESOLVED LAZILY, ON FIRST USE (#3895).
	//
	// The realm attributes an authoring catalog carries are derived from what
	// this process WIRED - whether a SCIM-backed directory exists decides
	// whether the built-in minted and trusted-header realms have a group graph -
	// so the resolution must not run before that is settled.
	//
	// IT IS ORDERING-PROOF BY CONSTRUCTION, NOT A FIX FOR A DEFECT THAT EXISTED.
	// An earlier version of this comment claimed run.go declared the directory
	// AFTER building this handler, and cited two line numbers as a measurement.
	// That was wrong, and wrong in an instructive way: it compared POSITIONS in
	// the file across two different functions. Traced instead - Run() calls
	// initializeComponents() first, and initSegmentPolicyGate is inside it - the
	// directory is already declared by the time this handler is built, so
	// resolving at construction would have been correct today.
	//
	// Lazy is still the right shape, for the reason that survives the
	// correction: it does not depend on that order STAYING true. A future edit
	// that moves the handler's construction earlier, or the directory's
	// declaration later, would otherwise give both directory-backed realms
	// HasGroupGraph=false - warning GROUP_SCOPE_WITHOUT_GRAPH on policies that
	// match perfectly well, and giving that deployment a different catalog
	// DIGEST from an identically configured one. Being unable to break is worth
	// more than being currently unbroken.
	//
	// What the constructor still does is VALIDATE the environment value, so a
	// typo is a boot-time log line rather than a surprise at the first
	// publication.
	//
	// A FAILED resolution is NOT cached; see vocabulary().
	// vocabMu guards the three fields below and NOTHING ELSE.
	//
	// IT IS A SECOND MUTEX ON PURPOSE, and the first version of this used `mu`
	// and DEADLOCKED: workspaceFor holds `mu` for the whole workspace lookup and
	// calls vocabulary() inside it, and a sync.Mutex is not reentrant, so the
	// orchestrator package's tests hung until the 10-minute timeout. The two are
	// genuinely different state - one is a process-lifetime resolution, the
	// other a per-organization cache - and giving them one lock coupled a cheap
	// read to a map the request path mutates.
	//
	// resolved is set only on a SUCCESSFUL resolution; see vocabulary().
	vocabMu  sync.Mutex
	resolved bool
	snap     *authoringcatalog.Snapshot
	snapErr  error

	// profileFor resolves the deployment's authoring boundary. It is a field so
	// a test can present Community, Evaluation and Enterprise without touching
	// the process environment, and it is READ PER REQUEST rather than captured
	// at construction: a licence that expires while the process runs must
	// narrow the boundary at the next publication, not at the next restart.
	//
	// It resolves a PROFILE and not an Edition (#3956). The boundary is two
	// facts - which edition, and whether this process could establish that it
	// is that edition - and the second decides the duty rule. While this field
	// produced an Edition, each of the three call sites below rebuilt a profile
	// from it and every one of them dropped that second fact.
	profileFor func(context.Context) authoring.Profile

	// openForSigning is authoringstore.OpenForSigning, as a field for the same
	// reason profileFor is one: a test must be able to present a FAILING
	// durable open without touching a database. The transient-failure path is
	// the one that shipped broken - a blip cached the in-process fallback for
	// the life of the process - and it cannot be driven through a real handle,
	// because a bad handle fails every time rather than once.
	openForSigning func(context.Context, *sql.DB, pdp.Root, string, string, ed25519.PublicKey, string) (*authoringstore.Store, authoring.TrustSource, string, error)

	// db is the orchestrator's application-role connection, or nil.
	//
	// NIL IS A REAL STATE, NOT AN EDGE CASE: run.go leaves usageDB nil when
	// DATABASE_URL is unset or the connection failed, and this route is
	// registered unconditionally on every edition. A nil handle means the
	// in-process store, which is what shipped before #3975 - so the fallback is
	// the OLD behaviour rather than a new failure mode, and the /edition
	// endpoint reports which one is in force instead of assuming.
	//
	// It is live by the time this handler is constructed: run.go calls
	// initializeComponents() at line 637, which opens usageDB, and builds the
	// router at 654. There is no window in which a request can arrive before
	// the handle exists.
	db *sql.DB

	mu         sync.Mutex
	workspaces map[string]*typedAuthoringWorkspace
}

// typedAuthoringWorkspace is one organization's authoring plane.
//
// ONE PER ORGANIZATION, KEYED BY THE GATEWAY-STAMPED ORG, is what makes tenant
// isolation structural rather than checked: another organization's artifacts
// are not reachable from this request even in principle, because the map lookup
// that produces the store takes its key from the header the gateway stamps from
// the validated licence and from nowhere else. No handler here accepts an
// organization in a path, a query or a body.
type typedAuthoringWorkspace struct {
	api   *authoring.API
	keyID string
	priv  ed25519.PrivateKey
	// edition is the edition the api was built for. A workspace is rebuilt when
	// the deployment's edition changes under it; see workspaceFor.
	profile authoring.Profile
	// durable records whether this workspace was built over the postgres
	// backend or the in-process one.
	//
	// RECORDED RATHER THAN ASSUMED, for the reason the portal's copy states:
	// a status field that cannot observe the thing it names is worse than no
	// field, because it is believed. `"persistence": "process"` was a literal
	// on that surface and kept saying "process" after the durable store was
	// wired - and would have kept saying it if the wiring silently failed.
	durable bool
	// degraded marks a workspace built while a CONFIGURED database could not be
	// reached. It is not the same as `!durable`: a deployment with no database
	// is legitimately in-process, while this one was promised durability and
	// did not get it. Writes are refused here rather than accepted into memory.
	degraded bool
	// activationInputs is what this workspace's activator dry-runs with. It is
	// a field, not only a closure, so the ONE definition the activator calls is
	// the one a test can inspect: the system authority's key must not be the
	// workspace's signing key, and the trust it reads must be left as it was
	// (#4047).
	activationInputs func(context.Context) (activation.Inputs, error)
	digests          map[string]struct{}
	lastUsed         time.Time
}

// NewTypedAuthoringRouteHandler builds the handler.
//
// Unset or empty is the deployment vocabulary (PRD §1.5). An unrecognised
// value makes the handler UNAVAILABLE rather than fatal: an orchestrator that
// refuses to boot because one variable is misspelled takes every other route
// down with it, and the endpoints here answer 503 naming the variable instead.
// (The portal, which serves nothing but a UI, refuses boot on the same value.)
func NewTypedAuthoringRouteHandler(db *sql.DB, deploymentFor func() authoringvocabulary.CatalogDeployment) *TypedAuthoringRouteHandler {
	h := &TypedAuthoringRouteHandler{
		db:             db,
		catalogValue:   os.Getenv(authoringcatalog.Env),
		deploymentFor:  deploymentFor,
		workspaces:     map[string]*typedAuthoringWorkspace{},
		profileFor:     deploymentProfile,
		openForSigning: authoringstore.OpenForSigning,
	}
	if h.deploymentFor == nil {
		h.deploymentFor = func() authoringvocabulary.CatalogDeployment { return authoringvocabulary.CatalogDeployment{} }
	}
	// BOOT-TIME VALIDATION OF THE VALUE, not of the vocabulary. It reports a
	// typo at the moment an operator can still connect it to what they typed,
	// without building a registry against realm attributes this process has
	// not finished declaring.
	if v, err := authoringcatalog.Value(h.catalogValue); err != nil {
		log.Printf("[TypedAuthoring] typed authoring will be UNAVAILABLE on this deployment: %v", err)
	} else {
		log.Printf("[TypedAuthoring] %s resolves to %q; the vocabulary is built on first use, after this process has "+
			"finished declaring what it wired", authoringcatalog.Env, v)
	}
	return h
}

// vocabulary resolves this deployment's authoring vocabulary, once.
//
// It returns (nil, nil) for an unconfigured deployment - the 503 case - and an
// error for a value or a deployment the resolver refuses. See the struct's
// `once` field for why this is lazy.
func (h *TypedAuthoringRouteHandler) vocabulary() (*authoringcatalog.Snapshot, error) {
	h.vocabMu.Lock()
	defer h.vocabMu.Unlock()
	if h.resolved {
		return h.snap, h.snapErr
	}
	func() {
		// DEFAULTED HERE, NOT ONLY IN THE CONSTRUCTOR. A handler built as a
		// struct literal - which several tests do, and which nothing forbids -
		// carries a nil accessor, and the constructor's default never runs for
		// it. Relying on the constructor is the "a guard at the callers is not a
		// guard" shape: this is the one place the value is read, so this is
		// where its absence is answered. An empty deployment declares no
		// directory, which is the honest reading of "this process told us
		// nothing".
		deployment := authoringvocabulary.CatalogDeployment{}
		if h.deploymentFor != nil {
			deployment = h.deploymentFor()
		}
		h.snap, h.snapErr = authoringvocabulary.ResolveCatalogValue(h.catalogValue, deployment)
		// A FAILURE IS NOT MEMOISED. DeploymentFromDatabase derives the realm
		// attributes from a resolver built over the database; if that fails
		// transiently at the first request, caching the failure would freeze the
		// wrong vocabulary - and therefore the wrong catalog DIGEST - until a
		// restart. That is the same reproducibility failure the lazy resolution
		// exists to avoid, moved from boot to first request. A success is
		// memoised, because the vocabulary is deployment state and re-deriving
		// it per request would be a registry build on the authoring path.
		h.resolved = h.snapErr == nil
		switch {
		case h.snapErr != nil:
			log.Printf("[TypedAuthoring] the typed-authoring vocabulary could not be resolved, so the surface is "+
				"UNAVAILABLE on this deployment: %v", h.snapErr)
		case h.snap != nil:
			log.Printf("[TypedAuthoring] vocabulary resolved: source=%s fixture=%t digest=%s registry_version=%d "+
				"(%d action(s), %d realm(s), %d resource type(s))",
				h.snap.Source, h.snap.Fixture, h.snap.Digest, h.snap.RegistryVersion,
				len(h.snap.Catalog.Actions), len(h.snap.Catalog.Realms), len(h.snap.Catalog.ResourceTypes))
		}
	}()
	return h.snap, h.snapErr
}

// deploymentProfile resolves this deployment's authoring boundary.
//
// It is a function rather than a captured value because the read is memoised
// downstream and because a licence can EXPIRE mid-process: an expired or forged
// key stops establishing a tier, so a deployment whose licence lapses narrows
// to the Community construct set - and gains the second-approver requirement -
// at its next publication rather than keeping Enterprise constructs until
// somebody restarts it.
//
// THE RESOLUTION IS NOT PERFORMED HERE. It was, in two bytes-identical copies,
// one in this file and one in the portal's - and the portal's process was the
// one that never received AXONFLOW_LICENSE_KEY, which no amount of correctness
// in this copy could have said anything about. authoringedition.Resolve is the
// one read; see its package doc.
func deploymentProfile(ctx context.Context) authoring.Profile {
	return authoringedition.Resolve(ctx).Profile
}

// Available reports whether this deployment has a typed-authoring vocabulary.
// It RESOLVES the vocabulary if nothing has yet, so a caller asking at boot
// gets the same answer a request would - see vocabulary() for why nothing at
// boot should ask.
func (h *TypedAuthoringRouteHandler) Available() bool {
	snap, err := h.vocabulary()
	return err == nil && snap != nil
}

// RegisterRoutes registers the surface.
//
// THE PREFIX GUARD IS REGISTERED UNCONDITIONALLY, including when the handler is
// unavailable, and that is deliberate. Without it an unenumerated verb or a
// mistyped sub-path falls through to whatever else the router matches, and a
// caller learns nothing; with it, every request under this prefix gets an
// answer from the surface that owns it. It is also what makes the availability
// answer reachable at all on a deployment with no catalog configured.
// THE PATHS ARE STRING LITERALS AND MUST STAY LITERALS, even though a prefix
// constant sits right above them. Two censuses walk this package's syntax tree
// to answer questions no reader can answer reliably - the portal's
// orchestrator-proxy allowlist and the policy-route gate coverage guard - and
// each REFUSES a non-literal path by name, because a route they cannot resolve
// is a route nobody classified. Writing `TypedAuthoringRoutePrefix + "/publish"`
// is more DRY and makes both guards report this file as unauditable.
//
// The constant is not therefore decorative: TestTheRegisteredPathsAllCarryThePrefix
// holds every literal below to it, so the two cannot drift.
func (h *TypedAuthoringRouteHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/typed-policies/edition", h.handleEdition).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/api/v1/typed-policies/validate", h.handleValidate).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/api/v1/typed-policies/publish", h.handlePublish).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/api/v1/typed-policies/activate", h.handleActivate).Methods(http.MethodPost, http.MethodOptions)
	r.HandleFunc("/api/v1/typed-policies/active", h.handleActive).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/api/v1/typed-policies/active/summary", h.handleActiveSummary).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/api/v1/typed-policies/system", h.handleSystem).Methods(http.MethodGet, http.MethodOptions)
	r.PathPrefix("/api/v1/typed-policies").HandlerFunc(h.handleUnenumerated)
	log.Printf("[TypedAuthoring] community typed-authoring routes registered under %s (%s=%q; the vocabulary resolves on first use)",
		TypedAuthoringRoutePrefix, authoringcatalog.Env, h.catalogValue)
}

// ---------------------------------------------------------------------------
// Wire envelopes
// ---------------------------------------------------------------------------

// typedAuthoringDocumentRequest carries a candidate document.
//
// The document field is authoring.Document itself, NOT a mirror of it. A mirror
// would be a second declaration of the policy vocabulary, and the first field
// added to pdp.Policy that this route forgot would be a field an author could
// not write and could not see was missing.
type typedAuthoringDocumentRequest struct {
	Document *authoring.Document `json:"document"`
	Fixtures []authoring.Fixture `json:"fixtures,omitempty"`
}

type typedAuthoringActivateRequest struct {
	Digest string `json:"digest"`
	Reason string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleEdition answers what this deployment may author BEFORE an author tries.
//
// It exists because a Community deployment has no UI to grey a control out in.
// Without it the only way to learn that an edition does not carry an obligation
// family is to write a policy using one and read the refusal, which is a
// boundary discovered one rejection at a time.
func (h *TypedAuthoringRouteHandler) handleEdition(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	snap, ok := h.requireAvailable(w)
	if !ok {
		return
	}
	profile := h.profileFor(r.Context())
	limits := license.GetTierLimits(license.ReadCurrentTier(r.Context()).Tier)

	// THE PERSISTENCE POSTURE, in #3962's vocabulary rather than a second one.
	//
	// Same key names and same two values the portal's settings endpoint
	// reports, because an operator comparing two surfaces of one deployment
	// must not have to translate. DERIVED FROM THE WORKSPACE THIS ORG ACTUALLY
	// HAS, through the same call the write paths make, so the reported posture
	// is the one a publish would really get rather than a guess at it.
	//
	// "process" is precise and narrow: THIS orchestrator process. "database"
	// means the artifact and its activation history are in postgres and outlive
	// the process. A resolution failure reports "process", which is the honest
	// answer - the write path would fall back the same way.
	// THREE VALUES, BECAUSE THERE ARE THREE STATES. "process" is a deployment
	// with no database configured - legitimate, and what shipped before #3975.
	// "unavailable" is a deployment that HAS one and could not reach it:
	// promised durability and not given it, writes and the active-document
	// read refused with 503 storage_unavailable (#4255), other reads still
	// served. Folding the second into the first would report an outage as a
	// design choice.
	persistence := "process"
	if orgID := strings.TrimSpace(r.Header.Get("X-Org-ID")); orgID != "" {
		if ws, werr := h.workspaceFor(r.Context(), orgID); werr == nil {
			switch {
			case ws.durable:
				persistence = "database"
			case ws.degraded:
				persistence = "unavailable"
			}
		}
	}
	typedAuthoringJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"catalog": snap.Source,
		// The vocabulary's IDENTITY, not only its name. An author reading a
		// refusal needs to know which snapshot refused them, and the same
		// digest is what a decision and a proof carry.
		"catalog_digest":   snap.Digest,
		"registry_version": snap.RegistryVersion,
		"catalog_fixture":  snap.Fixture,
		"root":             string(typedAuthoringRoot),
		"constructs":       profile.Constructs(),
		"persistence":      persistence,
		// REPORTED SEPARATELY BECAUSE IT IS A DIFFERENT FACT, and conflating
		// them would overstate what durability buys. The artifact and its
		// activation history outlive the process; the PRIVATE half of the key
		// that signed it does not - each process mints its own and records only
		// the public half. So a restart cannot invalidate what was already
		// signed (every authorized public key is loaded back) and cannot
		// re-sign with the old key. "process" here is true even when
		// persistence is "database".
		"signing_key_custody": "process",
		// The ceiling is reported beside the constructs because they are the
		// two halves of one question: what may I write, and how much of it.
		"max_documents": limits.OrgPolicies,
	})
}

// handleValidate returns the save-time findings for a candidate document.
//
// It runs Validate and NOT Publish, so it is edition-INDEPENDENT on purpose: an
// author must get the same well-formedness answer on every edition, and the
// entitlement question belongs at the moment a document would become a signed
// artifact. A validate endpoint that also applied the edition boundary would
// make an author unable to tell a malformed policy from an unlicensed one.
func (h *TypedAuthoringRouteHandler) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	snap, ok := h.requireAvailable(w)
	if !ok {
		return
	}
	_, author, ok := h.callerIdentity(w, r)
	if !ok {
		return
	}
	req, ok := h.decodeDocument(w, r)
	if !ok {
		return
	}
	_, findings, _ := h.rebuild(req.Document, author, snap.Catalog)
	typedAuthoringJSON(w, http.StatusOK, map[string]any{
		"success":  !findings.Rejected(),
		"findings": findings,
	})
}

// rebuild reconstructs a document through authoring.NewDocument.
//
// THE ROUTE NEVER PUBLISHES OR VALIDATES THE STRUCT THAT ARRIVED ON THE WIRE,
// and that is a correctness rule rather than tidiness. authoring.NewDocument is
// the only constructor, and it DERIVES pdp.Document.InteractiveRealms from the
// catalog instead of letting a caller assert it. That field decides whether an
// approval obligation can ever be answered - an approval pool that resolves
// only in a non-interactive realm can never be discharged, which is what
// POOL_NOT_INTERACTIVE refuses at save time - so a request that supplied its
// own value would be telling this deployment which of its realms contain
// people. CatalogAgreement refuses a document whose copy disagrees, which is
// how the first version of this handler was caught: it passed the wire struct
// straight through and every publication was refused for a disagreement the
// CALLER had no way to resolve, since the derived value is not theirs to send.
//
// The author is stamped here for the same reason and in the same place: it is
// inside the signed source, so it must be this process's answer rather than
// the request's, and it must be set BEFORE the document is constructed rather
// than patched onto it afterwards.
func (h *TypedAuthoringRouteHandler) rebuild(in *authoring.Document, author contract.ID, cat *authoring.Catalog) (*authoring.Document, authoring.Findings, error) {
	d := *in
	d.Metadata.Author = author
	return authoring.NewDocument(d, cat)
}

// handlePublish admits the document against the tier ceiling and publishes it.
//
// ORDER: ADMIT FIRST, THEN PUBLISH. Both orders are defensible and the choice
// is stated rather than left to be inferred.
//
// Admitting first means a document that fails validation has still consumed its
// ledger row. That is the same shape the legacy create path already has -
// validateTierForCreate admits by policy NAME before the row is written - and
// it is idempotent on the document id, so an author iterating on one document
// spends one slot however many attempts it takes. It also means an author who
// is over the ceiling is told so immediately rather than after a full compile
// and gauntlet run against a document that was never going to be admitted.
//
// The cost is that a document id admitted and then abandoned holds a slot. That
// is the honest price of a reserved name and it is the same price the legacy
// path charges; releasing it would need a deletion path through an APPEND-ONLY
// ledger, which is a different design and not one to invent here.
func (h *TypedAuthoringRouteHandler) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	snap, ok := h.requireAvailable(w)
	if !ok {
		return
	}
	orgID, author, ok := h.callerIdentity(w, r)
	if !ok {
		return
	}
	req, ok := h.decodeDocument(w, r)
	if !ok {
		return
	}

	docID := strings.TrimSpace(req.Document.Metadata.DocumentID)
	if docID == "" {
		typedAuthoringJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "reason": "document_id_required",
			"error": "a document carries a stable identity across its versions; a publication without one could " +
				"not be superseded by its own next version",
		})
		return
	}

	// THE DOCUMENT IS REBUILT BEFORE ANYTHING IS COUNTED, and the order is
	// load bearing twice over.
	//
	// It admits from the REBUILT document rather than from the wire struct, so
	// the set of rules counted is by construction the set of rules published.
	// Admitting `req.Document.Policy.Policies` happened to be the same list
	// today, because rebuild carries the policy set verbatim - but "happened to
	// be the same" is the coupling that breaks silently the first time rebuild
	// transforms anything, and it would break by counting one population and
	// enforcing another.
	//
	// And it means an INVALID document spends no capacity. NewDocument runs the
	// full save-time check set, so a document that cannot be saved is refused
	// before a single ledger row is written for it - which matters because the
	// ledger is append-only and a row spent on a document that never existed is
	// not recoverable.
	//
	// THE AUTHOR IS THE CALLER, AND THE REQUEST CANNOT SAY OTHERWISE - stamped
	// inside rebuild, along with the catalog-derived realm facts. See rebuild.
	doc, findings, err := h.rebuild(req.Document, author, snap.Catalog)
	if err != nil {
		typedAuthoringJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"success": false, "reason": "document_refused",
			"error": err.Error(), "findings": findings,
		})
		return
	}

	// THE WORKSPACE COMES FIRST, AND THE ORDER IS THE POINT.
	//
	// This block used to sit BELOW the admission loop, so a publication refused
	// for a reason that has nothing to do with the caller - a storage outage, or
	// this process's in-memory artifact cap - had already spent ledger
	// admissions on its way to being refused. principal_admissions is
	// append-only with no release, so those slots do not come back.
	//
	// #3973 has since ruled the general form and implemented it: the ledger
	// records what happened, not what was attempted. Admission no longer runs
	// before publication at all, so this block is no longer the only thing
	// standing between a caller and a slot spent on our outage - but it stays
	// first, because refusing early for a reason the caller cannot act on is
	// still cheaper than judging the document and then refusing.
	//
	// TWO CONSEQUENCES, STATED RATHER THAN DISCOVERED.
	//
	// [1] workspace_limit and artifact_cap now precede tier_limit. That is the
	// order we want - a refusal the caller did not cause should not cost the
	// caller a slot.
	//
	// [2] Building a workspace MINTS A SIGNING KEY AND RECORDS ITS PUBLIC HALF,
	// so an organization whose publication is about to be refused for the tier
	// ceiling now writes a typed_policy_signing_keys row where it previously
	// wrote none. It is bounded and it is the smaller cost: one row per
	// (organization, process), because the workspace is then cached and every
	// later request in this process reuses it - the same rate as an
	// organization that publishes successfully, which has always written one.
	// It is not bounded across restarts, but that is a property of per-process
	// keys rather than of this ordering, and LoadTrust needs every one of them
	// to verify artifacts signed by an earlier process.
	ws, ok := h.requireWorkspace(r.Context(), w, orgID)
	if !ok {
		return
	}
	if refuseIfStorageDegraded(w, ws) {
		return
	}
	if len(ws.digests) >= maxTypedAuthoringArtifactsPerOrg {
		typedAuthoringJSON(w, http.StatusTooManyRequests, map[string]any{
			"success": false, "reason": "artifact_cap",
			"error": fmt.Sprintf("this process holds the cap of %d admitted artifacts for this organization. "+
				"This is a MEMORY bound on an in-process store, not the edition's document ceiling, and it is "+
				"cleared by a restart. It is a bound on THIS PROCESS's admitted set, not on what is stored: since "+
				"#3975 the artifacts themselves are in postgres and survive", maxTypedAuthoringArtifactsPerOrg),
		})
		return
	}

	// THE TIER CEILING, THROUGH THE ONE ADMISSION PATH IN THIS BINARY.
	//
	// # The unit is a POLICY, not a document, and the difference is the whole
	// # value of the number
	//
	// The ladder says "customer-authored typed policies: 20 / 50 / unlimited"
	// (PRD section 6), and that row ABSORBED the old "active tenant policies"
	// row, whose unit was a legacy table row - one policy. So a policy is what
	// it counts.
	//
	// The first version of this admitted the DOCUMENT ID, which was wrong and
	// wrong in the direction that is hard to see: a ceiling that never binds.
	// Store.Promote refuses "to promote document %q over active document %q
	// under one authority root; a root carries ONE document", so an
	// organization has exactly one active document - and W1-C measured the
	// consequence on the import path, 25 legacy rows folding into ONE document
	// carrying 25 rules, nothing refused. Counted in envelopes, 20 means
	// "unlimited"; the number would have been in the limits table, in the
	// matrix, in the census and on the edition endpoint, and enforced nowhere.
	//
	// #3893 had already said so - "count ACTIVE rule entries transactionally,
	// not document envelopes or lifetime identifiers" - and the envelope half
	// of that sentence is the half this originally missed.
	//
	// # What is still divergent from #3893, stated rather than absorbed
	//
	// LIFETIME, not ACTIVE. principal_admissions is append-only by design, so
	// removing a policy from the document does not return its slot, and two
	// documents using different policy ids spend capacity twice even though
	// only one of them can be active. Making it active-count means a counter
	// that can DECREASE, which an append-only ledger cannot be, and a second
	// counter beside the one enforcing package is the shape ADR-066 exists to
	// prevent. It is a real divergence and it is #3893's to rule on.
	//
	// # No partial admission on a refused publication (#3973)
	//
	// THIS PARAGRAPH USED TO DEFEND THE DEFECT. It said rules were admitted one
	// at a time, so a document over the ceiling left the rules before the
	// boundary admitted, and called that survivable because admission is
	// idempotent on the key: an author who trims and retries reuses those ids.
	//
	// The argument was wrong about the case it was written for. Idempotence lets
	// an author reuse ids they ALREADY HOLD; it does not give back capacity, and
	// against an append-only ledger the slots were spent. Driven on a booted
	// Community stack: a 21-policy document refused at a ceiling of 20 left 19
	// rows behind, so the organization sat at 20 of 20 with nothing in force and
	// could not publish even the smaller document the refusal asked for.
	//
	// Admission is now ONE all-or-nothing call, made after the document has been
	// judged and before the artifact is stored. A refused publication - for the
	// ceiling, for the edition boundary, for separation of duties, for a
	// signature, or for our own storage - writes no ledger row and stores no
	// artifact.
	// THE IDENTIFIERS ARE COLLECTED HERE AND ADMITTED BELOW, AFTER THE DOCUMENT
	// HAS BEEN JUDGED. That split is #3973.
	//
	// The ledger is append-only, so a row spent on a publication that is then
	// refused never comes back. Admitting before publication meant every refusal
	// raised INSIDE Publish - the edition boundary, separation of duties, a
	// signature failure - had already spent capacity on its way to refusing, and
	// a document refused at the ceiling left the policies before the boundary
	// admitted. An organization that overshot once was then at its ceiling with
	// nothing in force, unable to publish even the smaller document the refusal
	// told it to publish.
	//
	// What remains here is only the check that cannot wait: an empty identifier
	// is refused with its own status rather than being carried into a batch. The
	// duplicate-id and empty-selector rules run inside Publish, so nothing
	// unnamed can reach the ledger from below either.
	ruleIDs := make([]string, 0, len(doc.Policy.Policies))
	for _, pol := range doc.Policy.Policies {
		ruleID := strings.TrimSpace(pol.ID)
		if ruleID == "" {
			typedAuthoringJSON(w, http.StatusBadRequest, map[string]any{
				"success": false, "reason": "policy_id_required",
				"error": "every policy in the document needs an identifier: it is what the edition's ceiling is " +
					"counted on, and what makes re-publishing the same rule spend nothing",
			})
			return
		}
		ruleIDs = append(ruleIDs, ruleID)
	}

	art, findings, err := ws.api.PublishAdmitting(r.Context(), doc, authoring.PublishOptions{
		Root:       typedAuthoringRoot,
		KeyID:      ws.keyID,
		PrivateKey: ws.priv,
		Fixtures:   req.Fixtures,
		// NO APPROVERS, and no field by which the request could name one.
		//
		// On Community and Evaluation there are none to name: PRD 5.3 rules
		// separation of duties None / None / Full, and inventing a second
		// identity for a single administrator would be exactly the fabrication
		// #3893 warned against. On ENTERPRISE this route therefore cannot
		// publish at all - Publish refuses, naming APPROVER_IS_AUTHOR - and
		// that is the correct outcome rather than a gap: an Enterprise
		// deployment has the portal, which resolves approvers against the
		// organization's own directory through the roles service. A second
		// approver-resolution path here would be a second opinion on who may
		// approve a policy.
		//
		// The Edition is set by api.Publish from the surface's own profile and
		// cannot be named by a request; see authoring.API.Publish.
	}, func(ctx context.Context, _ *authoring.Artifact) error {
		// RUNS ONLY IF THE DOCUMENT WAS ACCEPTED, AND BEFORE THE ARTIFACT IS
		// STORED. An error here refuses the publication and stores nothing, so a
		// refusal at the ceiling leaves neither a ledger row nor an artifact -
		// which is what stops a refused publication from producing a durable
		// document that could still be activated.
		return admitOrgRootPolicies(ctx, orgID, ruleIDs)
	})
	if err != nil {
		// THE ADMISSION REFUSAL IS NOT A PUBLICATION REFUSAL, and it arrives
		// through the same error now that it runs inside the publish call. A
		// ceiling reported as 422 publication_refused would tell an author their
		// document was wrong when their document was fine.
		var tierErr *TierValidationError
		if errors.As(err, &tierErr) {
			if tierErr.RetryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(tierErr.RetryAfter.Seconds())))
			}
			body := map[string]any{
				"success": false, "reason": "tier_limit", "code": tierErr.Code,
				"error": tierErr.Message,
			}
			// The policy that crossed the boundary, when the refusal names one.
			// An outage refusal does not: no particular policy is at fault, and
			// naming one would send the author to edit an innocent rule.
			if tierErr.Policy != "" {
				body["policy"] = tierErr.Policy
			}
			typedAuthoringJSON(w, tierErr.HTTPStatus(), body)
			return
		}
		typedAuthoringJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"success": false, "reason": "publication_refused",
			"error": err.Error(), "findings": findings,
		})
		return
	}
	ws.digests[art.Digest()] = struct{}{}
	body := map[string]any{
		"success":  true,
		"digest":   art.Digest(),
		"version":  art.Provenance().DocumentVersion,
		"findings": findings,
	}
	if report, err := activation.ReportArtifactTemplateOmissions(art); err != nil {
		body["template_omissions_unavailable"] = err.Error()
	} else if report != nil {
		body["template_omissions"] = report
	}
	typedAuthoringJSON(w, http.StatusOK, body)
}

// handleActivate promotes a published digest.
func (h *TypedAuthoringRouteHandler) handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	if _, ok := h.requireAvailable(w); !ok {
		return
	}
	orgID, actor, ok := h.callerIdentity(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, typedAuthoringMaxRequestBytes)
	var req typedAuthoringActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		typedAuthoringJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "reason": "malformed_request", "error": err.Error(),
		})
		return
	}
	ws, ok := h.requireWorkspace(r.Context(), w, orgID)
	if !ok {
		return
	}
	if refuseIfStorageDegraded(w, ws) {
		return
	}
	act, err := ws.api.Promote(r.Context(), typedAuthoringRoot, strings.TrimSpace(req.Digest), actor, time.Now(), req.Reason)
	if err != nil {
		// 409, not 400. Every refusal Promote can produce is about the STATE of
		// the root - the digest is not admitted, the version does not advance,
		// the parent is not the active digest, the actor may not activate this
		// version - rather than about the shape of the request, and a caller
		// told 400 would edit its request rather than reload the active version.
		typedAuthoringJSON(w, http.StatusConflict, map[string]any{
			"success": false, "reason": "activation_refused", "error": err.Error(),
		})
		return
	}
	body := map[string]any{"success": true, "activation": act}
	addActivatedTemplateOmissions(r.Context(), ws.api.Store(), orgID, strings.TrimSpace(req.Digest), body)
	typedAuthoringJSON(w, http.StatusOK, body)
}

// addActivatedTemplateOmissions adds the activated artifact's template
// omissions to an activation's success body. The activation has already
// happened, so a read-back that fails keeps the 200 and says so in a fixed
// sentence; the store's error goes to the log only (#4271), where it had been
// written into the success body.
func addActivatedTemplateOmissions(ctx context.Context, store *authoring.Store, orgID, digest string, body map[string]any) {
	art, ok, err := store.Get(ctx, typedAuthoringRoot, digest)
	if err != nil || !ok {
		log.Printf("[TypedAuthoring] org %s: the activated artifact %s could not be read back (found=%v): %v", orgID, digest, ok, err)
		body["template_omissions_unavailable"] = "the activated artifact could not be read back, so its template omissions are not reported; the activation stands."
		return
	}
	if report, err := activation.ReportArtifactTemplateOmissions(art); err != nil {
		body["template_omissions_unavailable"] = err.Error()
	} else if report != nil {
		body["template_omissions"] = report
	}
}

// handleActive renders the source of the document currently in force.
//
// This is the operator-facing half of "rendered back without loss": what comes
// back is the byte sequence that was signed, which parses, re-renders
// identically, and recompiles to the module being enforced.
func (h *TypedAuthoringRouteHandler) handleActive(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	if _, ok := h.requireAvailable(w); !ok {
		return
	}
	orgID, _, ok := h.callerIdentity(w, r)
	if !ok {
		return
	}
	ws, ok := h.requireWorkspace(r.Context(), w, orgID)
	if !ok {
		return
	}
	// A DEGRADED workspace cannot say what is active (#4255). Its durable store
	// could not be opened, so it holds the empty in-process store in that
	// store's place and is never cached: reading it could only ever answer
	// "nothing active". The first request after a restart, an eviction or an
	// edition rebuild reaches here while the database is down.
	if ws.degraded {
		log.Printf("[TypedAuthoring] org %s: the active document was not read: this organization's durable store could not be opened", orgID)
		writeActiveStorageUnavailable(w)
		return
	}
	source, err := ws.api.Render(r.Context(), typedAuthoringRoot)
	if errors.Is(err, authoring.ErrNothingActive) {
		typedAuthoringJSON(w, http.StatusNotFound, map[string]any{
			"success": false, "reason": "nothing_active", "error": err.Error(),
		})
		return
	}
	if errors.Is(err, authoringstore.ErrSigningKeyNotLoaded) {
		// Signed by a key this replica has not loaded, and the reload that would
		// load it was deferred (#4255). The key may be one another replica
		// authorized moments ago, or one not authorized at all. A retry after the
		// floor usually settles which, though under concurrent reads a retry can
		// land inside another read's floor and answer 503 again.
		log.Printf("[TypedAuthoring] org %s: the active document's signing key is not loaded on this replica: %v", orgID, err)
		writeActiveKeyNotLoaded(w)
		return
	}
	if errors.Is(err, authoringstore.ErrArtifactUnverifiable) {
		// The store answered, and what it holds as active does not verify
		// (#4255): a key de-authorized, or a signature, digest or module that no
		// longer holds. That is an integrity fault, not a storage outage, so it
		// is not storage_unavailable. (A key another replica authorized moments
		// ago is ErrSigningKeyNotLoaded, answered above.) The verification error
		// goes to the log only.
		log.Printf("[TypedAuthoring] org %s: the active document did not verify on load: %v", orgID, err)
		writeActiveUnverifiable(w)
		return
	}
	if err != nil {
		// A store that could not be read is NOT "nothing active" (#4255): every
		// SDK maps that 404 to "no active document", so answering it here told an
		// operator their organization had no policy in force during a database
		// blip. The store's own error goes to the log only: it can name the
		// database.
		log.Printf("[TypedAuthoring] org %s: the active document could not be read: %v", orgID, err)
		writeActiveStorageUnavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(source)
}

// writeActiveStorageUnavailable is /active's answer when what is active cannot
// be known because the store cannot be used (#4255): refuseIfStorageDegraded's
// reason, with a read's own sentence. The caller logs the cause, and nothing of
// the cause is written here.
func writeActiveStorageUnavailable(w http.ResponseWriter) {
	typedAuthoringJSON(w, http.StatusServiceUnavailable, map[string]any{
		"success": false, "reason": "storage_unavailable",
		"error": "this deployment's typed-authoring store could not be read, so what is active on this " +
			"organization is not known. The read is refused rather than answered as nothing active; retry " +
			"once the database is reachable.",
	})
}

// writeActiveKeyNotLoaded is a read of what is active refused because the
// active document's signing key is not loaded on this replica (#4255).
func writeActiveKeyNotLoaded(w http.ResponseWriter) {
	typedAuthoringJSON(w, http.StatusServiceUnavailable, map[string]any{
		"success": false, "reason": "key_not_loaded",
		"error": "the signing key of the document active on this organization is not loaded on this replica; " +
			"retry in a few seconds.",
	})
}

// writeActiveUnverifiable is a read of what is active refused because the
// active document does not verify on load (#4255).
func writeActiveUnverifiable(w http.ResponseWriter) {
	typedAuthoringJSON(w, http.StatusInternalServerError, map[string]any{
		"success": false, "reason": "active_unverifiable",
		"error": "the document active on this organization does not verify on this orchestrator: its signing key " +
			"may have been de-authorized, or its signature or content no longer holds. A document that verifies " +
			"must be activated.",
	})
}

// typedAuthoringSummaryResponse is the summary route's 200.
type typedAuthoringSummaryResponse struct {
	Success bool `json:"success"`
	activationinputs.Summary
}

// handleActiveSummary counts the policies in force on this organization on the
// decide scope, by whose each is (#4152). The count comes from
// activationinputs.ActiveSummary, which the portal's route calls too, so the
// two cannot give different answers.
//
// It refuses wherever /active refuses (#4255). A degraded workspace, or a store
// that could not be read, answers 503 storage_unavailable and never a count of
// the implicit baseline, which would tell an operator their document is not in
// force. Nothing active is NOT a refusal: the organization root is then the
// implicit baseline, which is enforced, so it is counted.
func (h *TypedAuthoringRouteHandler) handleActiveSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	if _, ok := h.requireAvailable(w); !ok {
		return
	}
	orgID, _, ok := h.callerIdentity(w, r)
	if !ok {
		return
	}
	ws, ok := h.requireWorkspace(r.Context(), w, orgID)
	if !ok {
		return
	}
	if ws.degraded {
		log.Printf("[TypedAuthoring] org %s: the policies in force were not counted: this organization's durable store could not be opened", orgID)
		writeActiveStorageUnavailable(w)
		return
	}
	art, found, err := ws.api.Store().Active(r.Context(), typedAuthoringRoot)
	switch {
	case errors.Is(err, authoringstore.ErrSigningKeyNotLoaded):
		log.Printf("[TypedAuthoring] org %s: the policies in force were not counted: the active document's signing key is not loaded on this replica: %v", orgID, err)
		writeActiveKeyNotLoaded(w)
		return
	case errors.Is(err, authoringstore.ErrArtifactUnverifiable):
		log.Printf("[TypedAuthoring] org %s: the policies in force were not counted: the active document did not verify on load: %v", orgID, err)
		writeActiveUnverifiable(w)
		return
	case err != nil:
		log.Printf("[TypedAuthoring] org %s: the policies in force were not counted: the active document could not be read: %v", orgID, err)
		writeActiveStorageUnavailable(w)
		return
	}
	if !found {
		art = nil
	}
	// The edition boundary is gated as the agent's enforcing seam gates it, and
	// resolved here, in the deployed process whose licence it reads.
	summary, err := activationinputs.ActiveSummary(r.Context(), ws.activationInputs, art,
		authoringedition.Resolve(r.Context()).EnforcesConstructBoundary())
	if err != nil {
		// The activation's own error goes to the log only: it can name a
		// database, as the recorded posture's read does.
		log.Printf("[TypedAuthoring] org %s: the policies in force could not be counted: %v", orgID, err)
		typedAuthoringJSON(w, http.StatusServiceUnavailable, map[string]any{
			"success": false, "reason": "summary_unavailable",
			"error": "what is in force on this organization could not be counted just now; retry in a few seconds, " +
				"and report it if it persists.",
		})
		return
	}
	typedAuthoringJSON(w, http.StatusOK, typedAuthoringSummaryResponse{Success: true, Summary: summary})
}

// handleUnenumerated answers anything else under the prefix.
func (h *TypedAuthoringRouteHandler) handleUnenumerated(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	typedAuthoringJSON(w, http.StatusNotFound, map[string]any{
		"success": false, "reason": "no_such_endpoint",
		"error": "this typed-authoring surface serves /edition, /validate, /publish, /activate, /active, /active/summary and a read-only /system",
	})
}

// ---------------------------------------------------------------------------
// Shared request handling
// ---------------------------------------------------------------------------

func (h *TypedAuthoringRouteHandler) requireAvailable(w http.ResponseWriter) (*authoringcatalog.Snapshot, bool) {
	snap, err := h.vocabulary()
	if err == nil && snap != nil {
		return snap, true
	}
	// Unset is the deployment vocabulary (PRD §1.5), so this is an
	// unrecognised value or a deployment vocabulary this process could not
	// build, and the error names which. Refusing rather than validating against
	// an empty catalog, which would refuse every policy for naming an
	// unregistered action.
	detail := "this deployment's typed-authoring vocabulary could not be resolved"
	if err != nil {
		detail += ": " + err.Error()
	}
	typedAuthoringJSON(w, http.StatusServiceUnavailable, map[string]any{
		"success": false, "reason": "catalog_not_configured", "error": detail,
	})
	return nil, false
}

// callerIdentity resolves the organization and the author from the headers the
// agent gateway stamps.
//
// BOTH COME FROM THE GATEWAY AND NEITHER FROM THE BODY. X-Org-ID is stamped
// from the validated licence on every proxied request, and X-User-ID from the
// authenticated caller. The alternative - taking either from the document -
// would let a caller author into another organization, or sign a document under
// somebody else's name.
func (h *TypedAuthoringRouteHandler) callerIdentity(w http.ResponseWriter, r *http.Request) (string, contract.ID, bool) {
	// The edition decides whether the author may fall back to the authenticated
	// client; see below. An unresolvable edition takes the strict path rather
	// than the permissive one.
	profile := h.profileFor(r.Context())
	orgID := strings.TrimSpace(r.Header.Get("X-Org-ID"))
	if orgID == "" {
		typedAuthoringJSON(w, http.StatusUnauthorized, map[string]any{
			"success": false, "reason": "org_not_stamped",
			"error": "this request carries no organization. The agent gateway stamps X-Org-ID from the validated " +
				"licence on every proxied request; a direct call to the orchestrator bypasses that and is refused " +
				"rather than defaulted, because the default would be some other organization's policy",
		})
		return "", contract.ID{}, false
	}
	// THE AUTHOR, WITH A FALLBACK THAT IS NOT A WEAKENING.
	//
	// X-User-ID is the per-user identity, and it is CLIENT-ASSERTABLE: the
	// agent's #2896 trust gate forwards it only on a deployment that has
	// declared its identity source trusted, and STRIPS it otherwise. A route
	// that required it would therefore refuse every publication on a default
	// deployment - which is most Community deployments, the population this
	// whole change exists for.
	//
	// So when it is absent the author is the AUTHENTICATED CLIENT, taken from
	// X-Client-ID, which the proxy sets from the validated credential and which
	// no caller can forge. The two are told apart by their REALM and their
	// TYPE, which is what those fields are for: a per-user author is a User in
	// the trusted-header realm, and a credential author is a Client in the
	// api-credential realm. A reader of the signed provenance can therefore see
	// which of the two asserted the subject rather than having to assume.
	//
	// A Client principal is the right shape for this and ADR-065 says so:
	// SubjectClient is "ATTRIBUTION, not authority ... may appear in an actor
	// chain and may be audited; it must never be the authority a grant is
	// scoped to". The author field is attribution - it records who wrote the
	// document - and it is never the authority a policy is scoped to, which is
	// carried by the document's own root and scope.
	// THE FALLBACK IS RESTRICTED TO EDITIONS WITHOUT SEPARATION OF DUTIES, and
	// the reason is a hazard that cannot arise today.
	//
	// Where the two-person rule applies, an author who is a CLIENT CREDENTIAL
	// and an approver who is a directory USER are different principals - the
	// comparison is over subject, realm and type, and it answers correctly -
	// but they may be the same PERSON, holding the credential and their own
	// login. The two-person rule is about people. That is the same axis error
	// #3876 fixed one step along: it compared a rendered TYPE where it meant
	// subject; this would compare SUBJECT where the rule means human.
	//
	// It is NOT reachable today, and the reason is worth stating because it is
	// the reason this guard is here rather than a comment saying it is fine:
	// this route sets no Approvers at all and offers no field for one, so on an
	// edition carrying separation of duties every publication is refused with
	// APPROVER_IS_AUTHOR before the author is compared with anybody
	// (TestEnterpriseCannotPublishThroughThisRouteAndTheRefusalSaysWhy). The
	// safety therefore rests on a DISTANT design choice - "this transport
	// happens to name no approver" - and the first person to add an approver
	// field here would make the hazard live without touching this function.
	// A guard at the callers is not a guard.
	//
	// So the fallback exists exactly where its justification does: a Community
	// or Evaluation deployment cannot stamp a user, and is also the deployment
	// where no duty rule compares the author with anyone. Above that floor an
	// absent user identity is refused, and the refusal says what to configure.
	subject := strings.TrimSpace(r.Header.Get("X-User-ID"))
	realm, subjectType := typedAuthoringAuthorRealm, identity.SubjectUser
	if subject == "" && !profile.RequiresSeparationOfDuties() {
		subject = strings.TrimSpace(r.Header.Get("X-Client-ID"))
		realm, subjectType = identity.BuiltinRealmAPICredential, identity.SubjectClient
	}
	if subject == "" {
		typedAuthoringJSON(w, http.StatusUnauthorized, map[string]any{
			"success": false, "reason": "author_not_stamped",
			"error": "this request names no author, and the author is carried inside the SIGNED policy source. " +
				"An unattributed policy version defeats the audit trail that makes an activation reviewable at all. " +
				"On an edition WITHOUT separation of duties the authenticated client (X-Client-ID, stamped by the " +
				"gateway from the validated credential) is accepted, so a request without one did not come through " +
				"the gateway. On an edition WITH it, only a per-user identity (X-User-ID) will do, and the agent's " +
				"identity trust gate strips that header unless this deployment declares its identity source " +
				"trusted - a credential cannot stand in for a person where the two-person rule applies",
		})
		return "", contract.ID{}, false
	}
	author, err := typedAuthoringAuthor(realm, subjectType, subject)
	if err != nil {
		typedAuthoringJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "reason": "author_not_canonical",
			"error": "this caller cannot be rendered as a canonical principal, and the author is carried in the " +
				"signed policy source: " + err.Error(),
		})
		return "", contract.ID{}, false
	}
	return orgID, author, true
}

// typedAuthoringAuthor renders a gateway-stamped subject as a canonical
// principal in the realm that asserted it.
func typedAuthoringAuthor(realm identity.RealmID, t identity.SubjectType, subject string) (contract.ID, error) {
	pid, err := identity.NewPrincipalID(realm, t, subject)
	if err != nil {
		return contract.ID{}, err
	}
	id := contract.ID{
		Kind:      contract.KindPrincipal,
		Type:      string(pid.Type),
		Qualifier: string(pid.Realm),
		Local:     pid.Subject,
	}
	if err := id.Validate(); err != nil {
		return contract.ID{}, err
	}
	return id, nil
}

func (h *TypedAuthoringRouteHandler) decodeDocument(w http.ResponseWriter, r *http.Request) (typedAuthoringDocumentRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, typedAuthoringMaxRequestBytes)
	var req typedAuthoringDocumentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		typedAuthoringJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "reason": "malformed_request", "error": err.Error(),
		})
		return req, false
	}
	if req.Document == nil {
		typedAuthoringJSON(w, http.StatusBadRequest, map[string]any{
			"success": false, "reason": "document_required",
			"error": "the request carries no document",
		})
		return req, false
	}
	return req, true
}

// refuseIfStorageDegraded answers 503 when a CONFIGURED durable store could not
// be reached, and reports whether it did.
//
// WRITES ONLY. The one read a degraded workspace could serve, the active
// document, is refused by handleActive instead (#4255): the in-process store a
// degraded workspace holds is empty, so it could only answer "nothing active".
// /edition still answers, and marks the posture explicitly, so nothing mistakes
// an in-process view for a durable one.
//
// What shipped instead was to accept the publish into memory and return 200.
// That loses the write on the next restart: #3975's own symptom, arriving
// through nothing worse than a transient database error.
func refuseIfStorageDegraded(w http.ResponseWriter, ws *typedAuthoringWorkspace) bool {
	if ws == nil || !ws.degraded {
		return false
	}
	typedAuthoringJSON(w, http.StatusServiceUnavailable, map[string]any{
		"success": false, "reason": "storage_unavailable",
		"error": "this deployment has a database configured for typed authoring and it could not be reached, so a " +
			"publication would be kept in memory and lost on the next restart. The write is refused rather than " +
			"accepted into a store that cannot keep it; retry once the database is reachable.",
	})
	return true
}

func (h *TypedAuthoringRouteHandler) requireWorkspace(ctx context.Context, w http.ResponseWriter, orgID string) (*typedAuthoringWorkspace, bool) {
	ws, err := h.workspaceFor(ctx, orgID)
	if err != nil {
		log.Printf("[TypedAuthoring] workspace refused for org %s: %v", orgID, err)
		typedAuthoringJSON(w, http.StatusTooManyRequests, map[string]any{
			"success": false, "reason": "workspace_limit", "error": err.Error(),
		})
		return nil, false
	}
	return ws, true
}

// workspaceFor returns this organization's authoring plane, creating it on
// first use.
//
// A WORKSPACE IS REBUILT WHEN THE DEPLOYMENT'S EDITION CHANGES UNDER IT. The
// authoring.API binds its edition at construction - deliberately, so a request
// cannot name one - which means a cached workspace would keep the boundary that
// was in force when it was first touched. A licence that expires mid-process
// resolves to Community at the next read, and the workspace built while it was
// valid would go on accepting Enterprise constructs until a restart. Comparing
// here costs one map read per request and closes that window.
func (h *TypedAuthoringRouteHandler) workspaceFor(ctx context.Context, orgID string) (*typedAuthoringWorkspace, error) {
	profile := h.profileFor(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	if ws, ok := h.workspaces[orgID]; ok {
		if ws.profile == profile {
			ws.lastUsed = time.Now()
			return ws, nil
		}
		log.Printf("[TypedAuthoring] the deployment's edition changed from %s to %s; rebuilding the authoring plane for org %s. "+
			"The WORKSPACE is rebuilt; the artifacts are NOT dropped - since #3975 they are in postgres and outlive "+
			"it, so a policy admitted under a wider edition stays active under a narrower one (#3993, S10 #3895) - and a "+
			"narrower edition must not inherit a store built under a wider one", ws.profile.Edition(), profile.Edition(), orgID)
		delete(h.workspaces, orgID)
	}
	if len(h.workspaces) >= maxTypedAuthoringWorkspaces {
		if evicted := h.evictAnEmptyWorkspaceLocked(); evicted == "" {
			return nil, fmt.Errorf(
				"this orchestrator holds typed-authoring workspaces for %d organizations, every one of them holding "+
					"published artifacts, so none can be evicted. The artifacts themselves are durable since #3975; this "+
					"cap is on WORKSPACES held in memory, and "+
					"release; durable storage is tracked separately", maxTypedAuthoringWorkspaces)
		}
	}
	snap, err := h.vocabulary()
	if err != nil || snap == nil {
		// Unreachable through the handlers, which all pass requireAvailable
		// first. Stated rather than assumed: a workspace built against no
		// vocabulary would validate every policy against an empty catalog.
		return nil, fmt.Errorf("this deployment declares no typed-authoring vocabulary")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("a signing key could not be generated: %w", err)
	}
	// THE KEY IDENTIFIER IS DERIVED FROM THE KEY, NOT FROM THE ORGANIZATION.
	//
	// It was `fmt.Sprintf("orchestrator-%s", orgID)`, and that made the durable
	// store work EXACTLY ONCE per organization, ever. Each workspace build mints
	// a fresh ephemeral key; with the identifier fixed per org, the second
	// process to build one presents the same id with different material, which
	// AuthorizeKey refuses BY DESIGN (ErrKeyAlreadyAuthorized - the read-back
	// exists to stop one process silently taking over another's identity). The
	// whole chain then failed, the workspace fell back to the in-process store,
	// and a publication made before a restart was unreachable after it - #3975's
	// own symptom, reintroduced by the fix for it.
	//
	// Driven: on a booted community stack the pre-restart posture was
	// persistence=database and the post-restart read 404'd, with the orchestrator
	// logging "durable store unavailable ... that key identifier is already
	// authorized".
	//
	// Deriving it from the public key makes AuthorizeKey idempotent for a process
	// re-authorizing its OWN key, and lets every process record its own alongside
	// the others - which is what LoadTrust returns, so an artifact signed by one
	// process verifies in another. This mirrors the portal's derivation, which
	// already carried this reasoning; copying its call SEQUENCE without its key
	// naming is what produced the defect above.
	keyID := authoringstore.KeyIDFor("orchestrator", orgID, pub)
	minted := pdp.NewTrustStore()
	minted.Authorize(typedAuthoringRoot, keyID, pub)
	// THE SOURCE, not a snapshot. Static until the durable open replaces it
	// with the one the store itself reads, so the API, authoring.Store and the
	// backend all hold ONE object rather than three copies of a moving fact.
	trust := authoring.StaticTrust(minted)

	// THE DURABLE PATH (#3975). Every step must succeed before this workspace
	// claims durability, and the order is the portal's for the reason its own
	// comment gives: authoringstore.New only validates its arguments and never
	// touches the database, so setting durable from it alone would mark a
	// workspace durable whose signing key was recorded NOWHERE - rows that
	// survive the process and cannot be loaded by it, which reads as data loss
	// rather than as a stated limit.
	//
	// LoadTrust then replaces the trust store with EVERY authorized key, not
	// just this process's, so an artifact signed by an earlier process - or by
	// another replica - still verifies here. That is the whole point of
	// persisting the public half, and it is why the store is rebuilt over the
	// loaded trust rather than the minted one.
	var backend authoring.Backend
	durable, degraded := false, false
	if h.db != nil {
		open := h.openForSigning
		if open == nil {
			open = authoringstore.OpenForSigning
		}
		store, loaded, _, serr := open(
			ctx, h.db, typedAuthoringRoot, orgID, "orchestrator", pub, "orchestrator")
		if serr == nil {
			backend, trust, durable = store, loaded, true
		} else {
			// ONCE A DATABASE IS CONFIGURED, PERSISTENCE IS NOT OPTIONAL.
			//
			// This used to fall back to the in-process store and cache that
			// workspace, so a single transient database error - a restart, a
			// failover, a connection blip - permanently downgraded the
			// organization for the life of the process. A publish then returned
			// 200 into memory and was lost on the next restart: #3975's own
			// symptom, reachable through nothing worse than a hiccup, and
			// invisible to every test because they drive a healthy backend or
			// no backend at all.
			degraded = true
			log.Printf("[TypedAuthoring] org %s: the configured durable store could not be opened; writes will be REFUSED and this workspace is not cached, so the next request retries: %v", orgID, serr)
		}
	}

	api, err := authoring.NewAPIWithBackend(snap.Catalog, trust, profile, backend)
	if err != nil {
		return nil, fmt.Errorf("the authoring plane could not be built: %w", err)
	}
	// THE PRODUCTION ACTIVATION CHECK (#3895). Promote and rollback now build
	// the engine that WOULD enforce the candidate and refuse if it cannot be
	// built: a fixture vocabulary, a blanket permission, or a system corpus
	// this binary did not ship. Without it a document could become active on a
	// deployment whose engine refuses to load it, and the refusal would arrive
	// at the first request instead of at the activation.
	//
	// THE SYSTEM KEY IS MINTED SEPARATELY (#4047). It used to be this
	// workspace's own signing key, and activation authorized it under the
	// system root in the trust store this workspace verifies against - so a
	// dry run left the organization's key able to sign a system-root artifact
	// this workspace would admit. Activation now refuses that key by name
	// (activation.RefusalSystemKeyIsOrganizationKey) and writes nothing into the
	// caller's store. Nothing here activates anything: Activate builds an engine
	// and discards it.
	// THE COMPOSITION KEY IS MINTED BESIDE IT, never persisted and never an
	// organization's key: every organization root composes the deployment's
	// baseline permission pack (PRD v11 §1.4), so the dry run composes and signs
	// one as the agent's enforcer does, and judges the document as it will be
	// enforced. Both keys come from the one builder of an organization's
	// activation inputs (platform/shared/activationinputs).
	system, composition, err := activationinputs.NewAuthorities()
	if err != nil {
		return nil, err
	}
	// THE DRY RUN'S INPUTS, for the decide plane: decide returns its decision
	// over the Decision API, and the dry run builds the engine exactly as the
	// agent's decide seam does (#4046), from the one statement of what decide's
	// wire delivers (legacycompile.ScopeDeliveries, #4131).
	//
	// The trust store is READ PER ACTIVATION through #3991's TrustSource, never
	// captured: the durable open replaces the source's store with one carrying
	// every authorized key, and a captured pre-open store would refuse an
	// activation another replica signed.
	//
	// The edition boundary, at ADR-066 chokepoint 2, is the workspace's own
	// licence-derived profile - the one Publish already applied - so promote and
	// rollback ask the same question publication asked, of a document that may
	// not have come through publication at all. UNCONDITIONAL here, and gated at
	// the enforcement seam: a refusal on this path is a sentence an author reads
	// while choosing what to write; the same refusal at the seam would be a 503.
	//
	// THE ORGANIZATION'S RECORDED POSTURE (#4045) is read per dry run through
	// recordedPosture: the dry run judges the document under the posture the
	// enforcing seam folds, and fails closed as the seam does.
	inputs := activationinputs.Builder{
		Snapshot: snap, Trust: trust, System: system, Composition: composition,
		Profile: profile, RefuseConstructsOutsideEdition: true,
		OrganizationID: orgID, Posture: h.recordedPosture,
	}.Source(legacycompile.PlaneDecide, "")
	api = api.WithActivator(activation.Activator(inputs))
	ws := &typedAuthoringWorkspace{
		api: api, keyID: keyID, priv: priv, profile: profile,
		durable: durable, degraded: degraded, activationInputs: inputs,
		digests: map[string]struct{}{}, lastUsed: time.Now(),
	}
	// NOT CACHED WHEN DEGRADED. Caching it is what made a transient failure
	// permanent; leaving it uncached costs one rebuild per request while the
	// database is unreachable, which is the correct price for not silently
	// serving a store that loses writes.
	if !degraded {
		h.workspaces[orgID] = ws
	}
	return ws, nil
}

// recordedPosture is orgID's recorded detection posture in the anchored
// engine's key (#4045), read per activation dry run and uncached, through the agent's RLS-scoped read: the dry run
// judges a document under the posture it will be enforced under, and fails
// closed - as the agent's enforcing seam does - when that posture cannot be
// read. A handler with no database has none recorded.
func (h *TypedAuthoringRouteHandler) recordedPosture(ctx context.Context, orgID string) (legacycompile.CategoryActions, error) {
	if h.db == nil {
		return nil, nil
	}
	read, err := agent.NewDetectionOverrideRepository(h.db).ReadOrgOverrides(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("the organization's recorded detection posture could not be read for the activation dry run: %w", err)
	}
	recorded := make(map[string]string, len(read))
	for category, action := range read {
		recorded[category] = string(action)
	}
	return detectionposture.AnchoredCategoryActions(recorded)
}

// evictAnEmptyWorkspaceLocked drops the least recently used workspace that has
// published nothing, and returns the org it belonged to (empty when none
// qualifies). A workspace holding artifacts is NEVER evicted: they do not
// survive a restart, but that is a stated limit of this release rather than
// something a cache is entitled to do on its own while the process is up.
func (h *TypedAuthoringRouteHandler) evictAnEmptyWorkspaceLocked() string {
	victim := ""
	var oldest time.Time
	for org, ws := range h.workspaces {
		if len(ws.digests) > 0 {
			continue
		}
		if victim == "" || ws.lastUsed.Before(oldest) {
			victim, oldest = org, ws.lastUsed
		}
	}
	if victim != "" {
		delete(h.workspaces, victim)
		log.Printf("[TypedAuthoring] evicted the idle, empty workspace for org %s to stay within the %d-workspace cap",
			victim, maxTypedAuthoringWorkspaces)
	}
	return victim
}

func typedAuthoringCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-User-ID, X-Org-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func typedAuthoringJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
