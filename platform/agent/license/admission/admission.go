// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"axonflow/platform/agent/license"
)

// Dimension names what is being admitted. The string is the metric label, the
// audit field and, for the three LEDGER dimensions, the ledger's `dimension`
// column - whose CHECK constraint in migrations/core/171 therefore names
// three values and not four. Node is the fourth and lives in node_leases: it
// is a concurrency fact, not a lifetime one, and Admit routes it there before
// the ledger is touched.
type Dimension string

const (
	// HumanPrincipal is a per-user identity resolved from a per-user token
	// (the canonical email the identity plane stamps). Placeholder identities
	// the agent synthesizes for token-less requests are NOT principals.
	HumanPrincipal Dimension = "human_principal"
	// ServicePrincipal is an API credential or tenant identity: the client id
	// the client-credential boundary authenticates.
	ServicePrincipal Dimension = "service_principal"
	// Node is an agent instance, keyed by its stable node identity. Unlike
	// the other three it is a CONCURRENCY dimension answered by node_leases
	// (NodeLeases), not a lifetime one answered by the ledger.
	Node Dimension = "node"
	// OrgRootPolicy is an organization-root policy, keyed by policy id.
	OrgRootPolicy Dimension = "org_root_policy"
)

// Dimensions is the closed set. The first three are the ledger's, in the order
// its CHECK constraint names them; Node is the lease store's.
func Dimensions() []Dimension {
	return []Dimension{HumanPrincipal, ServicePrincipal, OrgRootPolicy, Node}
}

// Valid reports whether d is one of the four dimensions.
func (d Dimension) Valid() bool {
	switch d {
	case HumanPrincipal, ServicePrincipal, Node, OrgRootPolicy:
		return true
	}
	return false
}

// Code is the wire error code for a refusal on this dimension:
// ERR_TIER_LIMIT_HUMAN_PRINCIPAL and so on. Distinct from every
// authentication code the agent emits (those are lower-case words such as
// invalid_credentials), so a client or a log grep cannot confuse the two.
func (d Dimension) Code() string {
	return "ERR_TIER_LIMIT_" + strings.ToUpper(string(d))
}

// Limit returns the ceiling this dimension reads from a limits table:
// -1 unlimited, 0 none, >0 a bound. The ONE place a dimension is mapped to
// its field, so adding a dimension is one case here and one field there.
func (d Dimension) Limit(l license.TierLimits) int {
	switch d {
	case HumanPrincipal:
		return l.MaxHumanPrincipals
	case ServicePrincipal:
		return l.MaxServicePrincipals
	case Node:
		return l.MaxNodes
	case OrgRootPolicy:
		return l.OrgPolicies
	}
	// Unreachable for a Valid dimension; Admit refuses an invalid one before
	// reading a limit. 0 rather than -1 so a future dimension that forgets
	// its case fails CLOSED (admits nothing) instead of open.
	return 0
}

// Refusal reasons: the metric label and the audit field. Closed set.
const (
	// ReasonOverLimit: the organization holds `limit` admitted principals on
	// this dimension already.
	ReasonOverLimit = "over_limit"
	// ReasonDependencyUnreachable: the principal is not in the seen-set and
	// the ledger could not be asked. Retry later; it is not a limit.
	ReasonDependencyUnreachable = "dependency_unreachable"
)

// Reasons is the closed set of refusal reasons.
func Reasons() []string { return []string{ReasonOverLimit, ReasonDependencyUnreachable} }

// Source names which branch of Admit answered.
type Source string

const (
	SourceUnlimitedTier  Source = "unlimited_tier"
	SourceSeenSet        Source = "seen_set"
	SourceLedgerExisting Source = "ledger_existing"
	SourceLedgerAdmitted Source = "ledger_admitted"
	SourceRefused        Source = "refused"
)

// Licence states, derived from license.TierRead. Named so a refusal can say
// which one applied; an expired licence is a case with its own row in every
// test table, not a flavour of "community".
const (
	LicenceValid    = "valid"
	LicenceAbsent   = "absent"
	LicenceExpired  = "expired"
	LicenceRejected = "rejected" // forged, malformed, unknown tier, invalid
)

// HTTPStatus is the status every HTTP refusal carries: 402 Payment Required.
//
// Chosen over 429 because a tier limit is a COMMERCIAL ceiling, not a rate:
// the client that hits it has nothing to wait for, and SDK retry loops treat
// 429 as transient. 402 already means "this deployment's entitlement does not
// cover the request" in this codebase (budget exhaustion in the gateway
// pre-check and clientRequestHandler), and both of those pair it with an
// audit row, which is the shape this refusal copies. The outage refusal keeps
// the same status so there is ONE status for "tier admission refused" and the
// reason field carries the difference; it adds Retry-After (RetryAfter) since
// that one IS retryable.
const HTTPStatus = http.StatusPaymentRequired

// RetryAfter is the Retry-After the outage refusal carries.
const RetryAfter = 30 * time.Second

// DefaultTierMemoTTL is how long one verified tier read is reused.
//
// WHY A MEMO AT ALL. Admit runs on the authentication path of every governed
// request, and the verified read it needs is not free on the build that
// matters: the enterprise ValidateLicense consults a TTL cache, the COMMUNITY
// one does not, so on a community binary holding an Evaluation key every call
// is a fresh Ed25519 verify - measured at ~29.5 us/op on an M4 Pro by
// BenchmarkReadCurrentTierWithAKey, twice per request. The answer it recomputes
// cannot change within a process except by the clock crossing the licence's
// expiry: AXONFLOW_LICENSE_KEY is read from the process environment and the
// verification is pure.
//
// SO THE ONE THING THE TTL BOUNDS IS EXPIRY LATENCY: a licence that expires
// while the process runs is noticed within a minute rather than on the next
// request. That is the deliberate trade, and it is stated here rather than
// left for a reader to infer from a cache. Set WithTierMemoTTL(0) to disable
// the memo entirely; the admission's own tests that vary a licence per call do
// exactly that.
const DefaultTierMemoTTL = time.Minute

// MaxBackgroundWriters is how many worker goroutines drain the background
// write queue, and BackgroundQueueDepth is how deep that queue is.
//
// WHY A QUEUE AND NOT A SEMAPHORE. The first version of the bound (R3 round 2,
// N5) took a slot per write and DROPPED the write when no slot was free. That
// bounds goroutines, but it bounds RECORDS by the same number, and on the
// unlimited tier a record is what makes a later licence lapse survivable - so
// a busy Enterprise deployment recorded only as many principals as it had
// slots and a lapse still refused established users, just fewer of them. It
// degraded exactly where the deployment was large, which is where it matters.
// Measured: `go test -run TestADowngradeFromAnUnlimitedTierIsGraceful -cpu=1`
// recorded 32 of 40 principals, six runs out of six, 32 being the slot count.
//
// A queue separates the two bounds: the worker count bounds concurrency, the
// queue depth bounds memory, and a write is dropped only when the queue itself
// is full - which is a real backlog rather than an artefact of arithmetic.
//
// HOW A DROP HEALS, AND WHY NOT BY UN-MARKING. A dropped or failed write is
// remembered in the SEPARATE bounded retry set (Admitter.retry, also
// BackgroundQueueDepth entries), and the next request for that principal
// enqueues it again. It does NOT un-mark the principal in the seen-set, which
// was the obvious implementation and is wrong: the seen-set is not only a
// dedupe cache, it is the thing that lets an already-admitted principal keep
// working while the ledger is unreachable (step 2 of the decision). Un-marking
// to make a retry work would hand that principal to step 5 if its tier had
// meanwhile degraded to Community - an established principal refused during an
// outage, produced by the mechanism added to make drops safe. The safety memo
// only ever grows; the debt is carried beside it.
const (
	MaxBackgroundWriters = 32
	BackgroundQueueDepth = 1024
)

// DefaultLedgerTimeout bounds every ledger and lease-store call. A store that
// does not answer inside it is UNREACHABLE for this decision: the request is
// refused (or, for a node, reported) as ReasonDependencyUnreachable rather
// than held. A paused database (a `docker pause`, a hung primary during
// failover) leaves TCP connections that neither error nor answer for minutes,
// and a driver's context cancellation may itself need a connection, so the
// wait is bounded here, by a select, whatever the driver does.
const DefaultLedgerTimeout = 5 * time.Second

// DefaultSeenSetCap bounds the in-memory seen-set. Sized for the largest
// limited organization (Evaluation: 75 humans + 25 services) many times over
// with room for the multi-organization SaaS shape, and small enough that a
// process warming it at boot reads one bounded query per organization.
const DefaultSeenSetCap = 10_000

// Request is one admission question. Every field is required except Licence.
type Request struct {
	Dimension   Dimension
	OrgID       string
	PrincipalID string
	// Licence is the verified tier read the caller already holds. Nil means
	// "read it now" through the Admitter's reader (license.ReadCurrentTier by
	// default). A caller that has it passes it so one request is one read.
	Licence *license.TierRead
}

// Decision is Admit's answer. A refusal is a Decision with Allowed=false and a
// Reason; an error return is reserved for a malformed Request.
type Decision struct {
	Allowed     bool
	Dimension   Dimension
	OrgID       string
	PrincipalID string
	// Tier is the tier the limit was read for; Edition is its metric-label
	// form (lower case). LicenceState names how the tier was arrived at.
	Tier         license.Tier
	Edition      string
	LicenceState string
	// Limit is the ceiling read (-1 unlimited). Count is the number of
	// principals admitted on (org, dimension) when the ledger was consulted,
	// or -1 when it was not.
	Limit int
	Count int
	// Reason and Code are set on a refusal only.
	Reason string
	Code   string
	// Source names the branch that answered; SeenSetAnswered is true when the
	// in-memory set decided (no I/O happened).
	Source          Source
	SeenSetAnswered bool
	// RetryAfter is non-zero only for ReasonDependencyUnreachable.
	RetryAfter time.Duration
}

// Message is the human-readable refusal text. It names the code so every
// wire format that carries only a message still carries the code.
func (d Decision) Message() string {
	if d.Allowed {
		return ""
	}
	subject := string(d.Dimension)
	switch d.Reason {
	case ReasonDependencyUnreachable:
		if d.Dimension == Node {
			// A node has no seen-set, so this reads for BOTH a node that has
			// never held a lease and one that is simply failing to renew - and
			// the wiring logs it verbatim on every heartbeat during an outage.
			// Saying "has not been admitted before" there would be false for
			// the running node it is describing.
			return fmt.Sprintf("%s: the node lease store cannot be reached, so this node's lease could not be taken or renewed; "+
				"a node already serving keeps serving. Retrying in %d seconds.",
				d.Code, int(d.RetryAfter.Seconds()))
		}
		return fmt.Sprintf("%s: this %s has not been admitted before and the admission ledger cannot be reached to admit it; "+
			"principals already admitted are unaffected. Retry in %d seconds.",
			d.Code, subject, int(d.RetryAfter.Seconds()))
	default:
		lic := ""
		switch d.LicenceState {
		case LicenceExpired:
			lic = " (the licence has EXPIRED, so Community limits apply)"
		case LicenceRejected:
			lic = " (the licence key was REFUSED by the verified read, so Community limits apply)"
		}
		if d.Dimension == Node {
			return fmt.Sprintf("%s: the %s edition runs at most %d node(s) per organization and %d other node(s) hold an unexpired lease%s. "+
				"A recreated node under a new id is admitted once the old lease expires (%s); set AXONFLOW_NODE_ID to keep one identity across restarts. "+
				"Upgrade at https://getaxonflow.com/enterprise",
				d.Code, d.Edition, d.Limit, d.Count, lic, NodeLeaseTTL)
		}
		return fmt.Sprintf("%s: the %s edition admits at most %d %s(s) per organization and %d are already admitted%s. "+
			"Upgrade at https://getaxonflow.com/enterprise",
			d.Code, d.Edition, d.Limit, subject, d.Count, lic)
	}
}

// Wire is the JSON body of an HTTP refusal.
type Wire struct {
	Code         string `json:"code"`
	Dimension    string `json:"dimension"`
	Reason       string `json:"reason"`
	Edition      string `json:"edition"`
	LicenceState string `json:"licence_state"`
	Limit        int    `json:"limit"`
	Count        int    `json:"count"`
	Message      string `json:"message"`
}

// Wire renders the refusal for an HTTP body.
func (d Decision) Wire() Wire {
	return Wire{
		Code: d.Code, Dimension: string(d.Dimension), Reason: d.Reason, Edition: d.Edition,
		LicenceState: d.LicenceState, Limit: d.Limit, Count: d.Count, Message: d.Message(),
	}
}

// ErrInvalidRequest is returned (wrapped) for a Request Admit cannot answer:
// an unknown dimension, an empty or blank org, an empty or blank principal.
var ErrInvalidRequest = errors.New("admission: invalid request")

// Outcome is what a Ledger reports for an atomic admit-under-limit.
type Outcome struct {
	// Admitted: a row was written by this call.
	Admitted bool
	// Existing: the row was already there (a replay); nothing was written.
	Existing bool
	// Count: rows on (org, dimension) BEFORE this call.
	Count int
}

// Key identifies one ledger row.
type Key struct {
	OrgID       string
	Dimension   Dimension
	PrincipalID string
}

// Ledger is the append-only table. The Postgres implementation is
// PostgresLedger; tests use a counting fake.
type Ledger interface {
	// Exists reports whether the key has a row.
	Exists(ctx context.Context, k Key) (bool, error)
	// AdmitUnderLimit inserts the key if fewer than limit rows exist on
	// (org, dimension), atomically with respect to other callers on the same
	// pair. A key already present reports Existing and writes nothing.
	AdmitUnderLimit(ctx context.Context, k Key, limit int, licenceFingerprint string) (Outcome, error)
	// Recent returns up to n keys for org, newest first, for warming.
	Recent(ctx context.Context, orgID string, n int) ([]Key, error)
	// Record inserts the key with no limit check, for the telemetry write an
	// unlimited tier makes off the request path. A key already present is not
	// an error.
	Record(ctx context.Context, k Key, licenceFingerprint string) error
}

// AuditSink receives one call per refusal. A sink must never block the
// decision: it logs and drops on failure.
type AuditSink interface {
	RecordRefusal(ctx context.Context, d Decision)
}

// Health is what /health and the wiring read.
type Health struct {
	// LedgerHealthy is false after a ledger error until the next success.
	LedgerHealthy bool      `json:"ledger_healthy"`
	LastError     string    `json:"last_error,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	SeenSetSize   int       `json:"seen_set_size"`
	SeenSetCap    int       `json:"seen_set_cap"`
	Warmed        bool      `json:"warmed"`
}

// Admitter holds the one decision. Construct with New.
type Admitter struct {
	ledger      Ledger
	leases      NodeLeases
	audit       AuditSink
	reader      func(context.Context) license.TierRead
	limits      func(license.Tier) license.TierLimits
	fingerprint string
	seen        *seenSet
	timeout     time.Duration

	// The memoised tier read. See DefaultTierMemoTTL.
	memoTTL   time.Duration
	now       func() time.Time
	memoMu    sync.Mutex
	memoRead  license.TierRead
	memoAt    time.Time
	memoOK    bool
	tierReads atomic.Int64
	recording sync.WaitGroup
	work      chan backgroundWrite
	done      chan struct{}
	workOnce  sync.Once
	closeMu   sync.RWMutex
	closed    bool
	// retry holds principals whose telemetry record did not land, so the next
	// request for them enqueues again. It is SEPARATE from seen, which is
	// never un-marked; see recordUnlimited for why that separation is the
	// difference between a self-healing drop and a refused principal.
	// IT IS BOUNDED, at BackgroundQueueDepth, and the bound is deliberate. The
	// seen-set may grow because forgetting an ADMISSION is what costs a
	// principal its grace; forgetting a DEBT costs only the retry, and the
	// alternative is a structure whose growth is proportional to traffic for
	// as long as the store is unavailable - precisely when the process can
	// least afford it. So it is an LRU: past the cap the oldest debt is
	// dropped, that principal is treated as recorded and is not retried, and
	// the eviction is COUNTED on
	// axonflow_tier_admission_background_drops_total{reason="debt_evicted"},
	// so a deployment losing retries at scale can see it. (Asked by the v11
	// master one layer below the queue; the answer was already the LRU, and
	// this is it said out loud with a counter behind it.)
	retry     *seenSet
	workClose sync.Once

	healthMu    sync.Mutex
	lastErr     string
	lastErrAt   time.Time
	lastOKAt    time.Time
	healthy     atomic.Bool
	warmed      atomic.Bool
	ledgerCalls atomic.Int64
}

// Option configures New.
type Option func(*Admitter)

// WithTierReader replaces license.ReadCurrentTier. Tests use it to present a
// valid, expired, forged or absent licence without touching the environment.
func WithTierReader(r func(context.Context) license.TierRead) Option {
	return func(a *Admitter) { a.reader = r }
}

// WithLimits replaces license.GetTierLimits. Tests use it to plant 0, -1 and
// small positive bounds on every dimension.
func WithLimits(f func(license.Tier) license.TierLimits) Option {
	return func(a *Admitter) { a.limits = f }
}

// WithNodeLeases installs the concurrency store the node dimension reads
// (PostgresNodeLeases in production). Without it every node admission on a
// limited tier is ReasonDependencyUnreachable, which the wiring treats as
// "boot and keep serving" per the node ruling.
func WithNodeLeases(nl NodeLeases) Option { return func(a *Admitter) { a.leases = nl } }

// WithAuditSink installs the refusal audit writer.
func WithAuditSink(s AuditSink) Option { return func(a *Admitter) { a.audit = s } }

// WithLicenceFingerprint records the deployment licence's fingerprint on every
// row written. Never the key itself; the wiring passes a hash, which is what
// LicenceFingerprint produces.
func WithLicenceFingerprint(fp string) Option { return func(a *Admitter) { a.fingerprint = fp } }

// LicenceFingerprint is what a ledger row records about the licence held when
// it was written: the first 16 hex characters of the key's SHA-256, never the
// key. Empty for an empty or blank key.
//
// It lives here rather than in each wiring because BOTH wirings write to the
// same ledger, and two implementations of "what we store about the licence"
// would eventually disagree about the length, the encoding or the trimming -
// producing rows that look like different licences for one deployment.
func LicenceFingerprint(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// WithTierMemoTTL sets how long one verified tier read is reused; 0 disables
// the memo, so every Admit reads the licence again.
func WithTierMemoTTL(d time.Duration) Option { return func(a *Admitter) { a.memoTTL = d } }

// WithClock replaces the memo's clock. Intended for tests.
func WithClock(now func() time.Time) Option { return func(a *Admitter) { a.now = now } }

// WithLedgerTimeout bounds every store call (default DefaultLedgerTimeout).
func WithLedgerTimeout(d time.Duration) Option { return func(a *Admitter) { a.timeout = d } }

// WithSeenSetCap bounds the in-memory set (default DefaultSeenSetCap).
func WithSeenSetCap(n int) Option { return func(a *Admitter) { a.seen = newSeenSet(n) } }

// New builds an Admitter over ledger. A nil ledger is permitted and means
// "no ledger": every new principal on a limited tier is refused with
// ReasonDependencyUnreachable, which is the ruling's posture, and the wiring
// is expected to replace it with a real one.
func New(ledger Ledger, opts ...Option) *Admitter {
	a := &Admitter{
		ledger:  ledger,
		reader:  license.ReadCurrentTier,
		limits:  license.GetTierLimits,
		seen:    newSeenSet(DefaultSeenSetCap),
		timeout: DefaultLedgerTimeout,
		memoTTL: DefaultTierMemoTTL,
		now:     time.Now,
		work:    make(chan backgroundWrite, BackgroundQueueDepth),
		done:    make(chan struct{}),
		retry:   newSeenSet(BackgroundQueueDepth),
	}
	for _, o := range opts {
		o(a)
	}
	a.healthy.Store(ledger != nil)
	return a
}

// LedgerCalls reports how many times the ledger was asked anything. Tests use
// it to prove the unlimited branch made zero calls.
func (a *Admitter) LedgerCalls() int64 { return a.ledgerCalls.Load() }

// Health reports the ledger and seen-set state.
func (a *Admitter) Health() Health {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()
	return Health{
		LedgerHealthy: a.healthy.Load(),
		LastError:     a.lastErr,
		LastErrorAt:   a.lastErrAt,
		LastSuccessAt: a.lastOKAt,
		SeenSetSize:   a.seen.Len(),
		SeenSetCap:    a.seen.Cap(),
		Warmed:        a.warmed.Load(),
	}
}

func (a *Admitter) noteLedgerError(err error) {
	a.healthMu.Lock()
	a.lastErr = err.Error()
	a.lastErrAt = time.Now()
	a.healthMu.Unlock()
	if a.healthy.Swap(false) {
		log.Printf("[admission] the admission ledger became UNREACHABLE: %v. Principals already admitted keep working; "+
			"a principal never seen before is refused with reason=%s until the ledger answers again.", err, ReasonDependencyUnreachable)
	}
	ledgerHealthyGauge.Set(0)
}

func (a *Admitter) noteLedgerSuccess() {
	a.healthMu.Lock()
	a.lastOKAt = time.Now()
	a.healthMu.Unlock()
	if !a.healthy.Swap(true) {
		log.Printf("[admission] the admission ledger is reachable again")
	}
	ledgerHealthyGauge.Set(1)
}

// Warm loads the newest rows for each organization into the seen-set. It is
// called at boot by the wiring and retried until it succeeds; a failure is
// reported through Health and is NOT fatal, because a deployment whose ledger
// is down at boot must still serve the principals it can prove.
func (a *Admitter) Warm(ctx context.Context, orgIDs ...string) (int, error) {
	if a.ledger == nil {
		return 0, errors.New("admission: no ledger to warm from")
	}
	loaded := 0
	for _, org := range orgIDs {
		if strings.TrimSpace(org) == "" {
			continue
		}
		a.ledgerCalls.Add(1)
		keys, err := bounded(ctx, a.timeout, func(c context.Context) ([]Key, error) { return a.ledger.Recent(c, org, a.seen.Cap()) })
		if err != nil {
			// A cancelled warm is a shutdown, not an unreachable ledger.
			a.noteLedgerError(err)
			return loaded, fmt.Errorf("admission: warm %q: %w", org, err)
		}
		a.noteLedgerSuccess()
		// Oldest first so the newest end up most-recently-used and survive a
		// cap that is smaller than the organization's history.
		for i := len(keys) - 1; i >= 0; i-- {
			a.seen.Add(keys[i])
			loaded++
		}
	}
	a.warmed.Store(true)
	return loaded, nil
}

// Admit is the one decision. See the package documentation for the order of
// its branches; each numbered step there is a labelled block here.
func (a *Admitter) Admit(ctx context.Context, req Request) (Decision, error) {
	if !req.Dimension.Valid() {
		return Decision{}, fmt.Errorf("%w: unknown dimension %q", ErrInvalidRequest, string(req.Dimension))
	}
	if strings.TrimSpace(req.OrgID) == "" {
		return Decision{}, fmt.Errorf("%w: empty org id", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.PrincipalID) == "" {
		return Decision{}, fmt.Errorf("%w: empty principal id", ErrInvalidRequest)
	}

	read := license.TierRead{}
	if req.Licence != nil {
		read = *req.Licence
	} else {
		read = a.currentTier(ctx)
	}
	tier := read.Tier
	if tier == "" {
		// A zero TierRead is "no licence" in every reader; treat it as the
		// reader would, never as unlimited.
		tier = license.TierCommunity
	}
	limit := req.Dimension.Limit(a.limits(tier))

	d := Decision{
		Dimension:    req.Dimension,
		OrgID:        req.OrgID,
		PrincipalID:  req.PrincipalID,
		Tier:         tier,
		Edition:      editionLabel(tier),
		LicenceState: licenceState(read),
		Limit:        limit,
		Count:        -1,
	}

	// Step 1: unlimited tiers return here, before any I/O ON THE REQUEST PATH.
	//
	// They still RECORD, asynchronously and best-effort, which is the
	// operator's ruling of 2026-09-07 in its own words: "the ledger still
	// records for telemetry and the qualification profile; a recording failure
	// is logged and dropped, never surfaced to the request". An earlier draft
	// of this package skipped recording entirely, and R3 round 1 found what
	// that costs: with an empty ledger, the moment a licence expires or is
	// downgraded EVERY principal is new, so on a 200-user deployment the first
	// 25 to arrive are admitted and the other 175 are refused - the opposite of
	// "a principal already admitted keeps working". Recording here makes the
	// downgrade graceful without putting a store call in front of a single
	// Enterprise request.
	if limit < 0 {
		d.Allowed = true
		d.Source = SourceUnlimitedTier
		admissionsTotal.WithLabelValues(string(d.Dimension), d.Edition, string(d.Source)).Inc()
		a.recordUnlimited(d)
		return d, nil
	}

	// The node dimension is a CONCURRENCY question and is answered by the
	// lease store on every call (each call IS the heartbeat), never by the
	// seen-set or the ledger: a node has no local memory of itself, and an
	// unreachable store is reported as ReasonDependencyUnreachable for the
	// wiring to treat as "boot and keep serving, retry", not as a refusal to
	// run (master ruling, 2026-09-08).
	if req.Dimension == Node {
		return a.admitNode(ctx, d), nil
	}

	key := Key{OrgID: req.OrgID, Dimension: req.Dimension, PrincipalID: req.PrincipalID}

	// Step 2: the seen-set answers without I/O.
	if a.seen.Has(key) {
		d.Allowed = true
		d.Source = SourceSeenSet
		d.SeenSetAnswered = true
		admissionsTotal.WithLabelValues(string(d.Dimension), d.Edition, string(d.Source)).Inc()
		return d, nil
	}

	// Step 3: the ledger may already hold it (another process admitted it, or
	// the seen-set evicted it).
	if a.ledger == nil {
		return a.refuse(ctx, d, ReasonDependencyUnreachable, errors.New("no ledger configured")), nil
	}
	a.ledgerCalls.Add(1)
	exists, err := bounded(ctx, a.timeout, func(c context.Context) (bool, error) { return a.ledger.Exists(c, key) })
	if err != nil {
		a.noteLedgerError(err)
		// A LIMIT OF ZERO ADMITS NOTHING NEW, WHATEVER THE STORE SAYS, so the
		// honest reason is the ceiling and not "retry in 30 seconds". The
		// dimension this fires for is org_root_policy, whose ceiling is 0 on
		// both limited tiers: telling an author to retry a request that can
		// never succeed is worse than telling them the edition does not author
		// organization-root policies. R3 round 1, M7.
		if limit == 0 {
			return a.refuse(ctx, d, ReasonOverLimit, err), nil
		}
		return a.refuse(ctx, d, ReasonDependencyUnreachable, err), nil
	}
	a.noteLedgerSuccess()
	if exists {
		a.seen.Add(key)
		d.Allowed = true
		d.Source = SourceLedgerExisting
		admissionsTotal.WithLabelValues(string(d.Dimension), d.Edition, string(d.Source)).Inc()
		return d, nil
	}

	// Step 4: a NEW principal is admitted only under the limit, atomically.
	a.ledgerCalls.Add(1)
	out, err := bounded(ctx, a.timeout, func(c context.Context) (Outcome, error) {
		return a.ledger.AdmitUnderLimit(c, key, limit, a.fingerprint)
	})
	if err != nil {
		a.noteLedgerError(err)
		return a.refuse(ctx, d, ReasonDependencyUnreachable, err), nil
	}
	a.noteLedgerSuccess()
	d.Count = out.Count
	switch {
	case out.Admitted:
		a.seen.Add(key)
		d.Allowed = true
		d.Source = SourceLedgerAdmitted
	case out.Existing:
		// A concurrent admit of the same principal won the race; that is an
		// admission, not a refusal.
		a.seen.Add(key)
		d.Allowed = true
		d.Source = SourceLedgerExisting
	default:
		return a.refuse(ctx, d, ReasonOverLimit, nil), nil
	}
	admissionsTotal.WithLabelValues(string(d.Dimension), d.Edition, string(d.Source)).Inc()
	return d, nil
}

// admitNode renews (or takes) this node's lease under the limit. See
// NodeLeases for the semantics; the only refusal on a POSITIVE answer is
// "the limit is full of OTHER unexpired leases".
func (a *Admitter) admitNode(ctx context.Context, d Decision) Decision {
	if a.leases == nil {
		return a.refuse(ctx, d, ReasonDependencyUnreachable, errors.New("no node lease store configured"))
	}
	a.ledgerCalls.Add(1)
	out, err := bounded(ctx, a.timeout, func(c context.Context) (Outcome, error) {
		return a.leases.Renew(c, d.OrgID, d.PrincipalID, NodeLeaseTTL, d.Limit)
	})
	if err != nil {
		a.noteLedgerError(err)
		return a.refuse(ctx, d, ReasonDependencyUnreachable, err)
	}
	a.noteLedgerSuccess()
	d.Count = out.Count
	switch {
	case out.Admitted:
		d.Allowed = true
		d.Source = SourceLedgerAdmitted
	case out.Existing:
		d.Allowed = true
		d.Source = SourceLedgerExisting
	default:
		return a.refuse(ctx, d, ReasonOverLimit, nil)
	}
	admissionsTotal.WithLabelValues(string(d.Dimension), d.Edition, string(d.Source)).Inc()
	return d
}

// refuse fills the refusal fields, counts it and writes the audit row.
func (a *Admitter) refuse(ctx context.Context, d Decision, reason string, cause error) Decision {
	d.Allowed = false
	d.Source = SourceRefused
	d.Reason = reason
	d.Code = d.Dimension.Code()
	if reason == ReasonDependencyUnreachable {
		d.RetryAfter = RetryAfter
	}
	refusalsTotal.WithLabelValues(string(d.Dimension), d.Edition, reason).Inc()
	if cause != nil {
		log.Printf("[admission] REFUSED %s principal=%q org=%q reason=%s (%v)", d.Dimension, d.PrincipalID, d.OrgID, reason, cause)
	} else {
		log.Printf("[admission] REFUSED %s principal=%q org=%q reason=%s limit=%d count=%d edition=%s licence=%s",
			d.Dimension, d.PrincipalID, d.OrgID, reason, d.Limit, d.Count, d.Edition, d.LicenceState)
	}
	if a.audit != nil {
		// OFF THE REQUEST PATH, because the sink's own contract says a refusal
		// must never wait on it and because the worst case is precisely the one
		// it reports: during a ledger outage the audit INSERT goes to the same
		// unreachable database, so an inline write would add its own bound to
		// every refusal (R3 round 1, M6). The refusal has already been decided
		// and counted; the row is a record of it, not part of it.
		// Queued for the same reason as the telemetry write: during an
		// over-limit storm this would otherwise be one goroutine per refused
		// request, each living up to the sink's own bound against a store that
		// may already be the problem. A row the queue cannot take is counted
		// and dropped - unlike a telemetry record it has nothing to retry
		// against, because the refusal it describes has already happened.
		// enqueue counts its own drops, so the caller cannot file a shutdown
		// as a backlog (or read the dimension off the wrong field).
		_ = a.enqueue(backgroundWrite{sink: a.audit, dec: d, ctx: context.WithoutCancel(ctx)})
	}
	return d
}

// currentTier is the memoised verified read. See DefaultTierMemoTTL.
func (a *Admitter) currentTier(ctx context.Context) license.TierRead {
	if a.memoTTL <= 0 {
		a.tierReads.Add(1)
		return a.reader(ctx)
	}
	a.memoMu.Lock()
	defer a.memoMu.Unlock()
	if a.memoOK && a.now().Sub(a.memoAt) < a.memoTTL {
		return a.memoRead
	}
	a.tierReads.Add(1)
	a.memoRead = a.reader(ctx)
	a.memoAt = a.now()
	a.memoOK = true
	return a.memoRead
}

// TierReads reports how many times the licence was actually read. Tests use it
// to prove the memo holds and that it expires.
func (a *Admitter) TierReads() int64 { return a.tierReads.Load() }

// editionLabel folds a tier onto the closed edition label set. Only limited
// tiers can refuse, but the admissions counter carries every tier, so the set
// is the four self-hosted names plus "other" for the SaaS plugin tiers.
func editionLabel(t license.Tier) string {
	switch t {
	case license.TierCommunity:
		return "community"
	case license.TierEvaluation:
		return "evaluation"
	case license.TierProfessional:
		return "professional"
	case license.TierEnterprise, license.TierEnterprisePlus:
		return "enterprise"
	}
	return "other"
}

// Editions is the closed edition label set, for the label-domain census.
func Editions() []string {
	return []string{"community", "evaluation", "professional", "enterprise", "other"}
}

// licenceState folds a TierRead onto the four named states.
func licenceState(r license.TierRead) string {
	switch {
	case !r.KeyPresent:
		return LicenceAbsent
	case r.Rejected && r.ReasonClass == license.TierReadRejectedExpired:
		return LicenceExpired
	case r.Rejected:
		return LicenceRejected
	}
	return LicenceValid
}

// ErrLedgerTimeout is the cause carried by a refusal whose store call did not
// answer inside the timeout.
var ErrLedgerTimeout = errors.New("admission: store call timed out")

// bounded runs fn with a deadline and returns ErrLedgerTimeout when it does
// not answer in time. The call runs in its own goroutine so the wait is
// bounded by THIS select even if the driver ignores the context; a call that
// answers late is discarded (the goroutine returns when the driver does).
func bounded[T any](ctx context.Context, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	if timeout <= 0 {
		return fn(ctx)
	}
	// THE STORE CALL GETS ITS OWN DEADLINE, DETACHED FROM THE CALLER'S.
	//
	// It used to inherit the request context, and that made the resulting
	// error AMBIGUOUS AT THE SOURCE: a client hanging up, a caller whose own
	// deadline was shorter than ours, and the store genuinely not answering
	// all arrived as the same done context. Every way of classifying that was
	// wrong in one direction or the other - call it client behaviour and a
	// real outage goes unrecorded for exactly the callers most likely to meet
	// it; call it unreachable and a tight-deadline caller poisons the health
	// gauge. Detaching removes the ambiguity rather than arbitrating it: our
	// timeout is unambiguously ours, so an error here is always a statement
	// about the store. (Raised by the v11 master on this lane, after R3
	// rounds 1 and 2 had found both wrong classifications in turn.)
	//
	// The caller is not held by the detachment: this returns as soon as either
	// side finishes, and the caller's own context still governs what it does
	// next.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := fn(cctx)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		cancel()
		return r.v, r.err
	case <-cctx.Done():
		go func() { <-done; cancel() }()
		var zero T
		return zero, fmt.Errorf("%w after %v: %v", ErrLedgerTimeout, timeout, cctx.Err())
	}
}

// A NOTE ON A CALLER THAT GOES AWAY, because two review rounds argued about it
// and the answer turned out to be a design change rather than a rule.
//
// A client can disconnect, or carry a deadline shorter than
// DefaultLedgerTimeout, at any point in an admission. That used to matter,
// because the store call inherited the caller's context and its failure was
// therefore indistinguishable from the store being unreachable. It no longer
// does: bounded detaches, so the store either answers, fails, or exceeds OUR
// deadline - each a true statement about the store, and each deserving its
// metric, its audit row and its health transition. A caller that has gone
// simply does not read the answer.

// recordUnlimited records an admission on an unlimited tier, off the request
// path. See the unlimited branch of Admit for why.
//
// The seen-set is the dedupe: one write per principal per process, not one per
// request. Only the two PRINCIPAL dimensions are recorded - a node is a
// concurrency fact whose lease is re-taken on the next heartbeat, and an
// organization-root policy is not re-created by a downgrade, so neither has a
// downgrade to be graceful about.
func (a *Admitter) recordUnlimited(d Decision) {
	if a.ledger == nil {
		return
	}
	// ONLY the two principal dimensions, deliberately. The recording exists so
	// a licence lapse does not refuse principals the deployment was already
	// serving, and that only works for a dimension that is re-admitted on
	// every request. A node is a lease, not a ledger row at all; an
	// organization-root policy is admitted once at CREATE and never again, so
	// a row for it would buy nothing after a lapse. Anything asserting that an
	// Enterprise deployment accumulates org_root_policy rows is wrong -
	// TestOnlyThePrincipalDimensionsRecordOnAnUnlimitedTier pins the counts.
	//
	// REVISIT WHEN: org_root_policy stops being 0 on both limited tiers. The
	// exclusion is only free because a downgrade lands on a ceiling of 0,
	// where a recorded row would change nothing - every name is refused
	// either way. Give Evaluation a non-zero org-root limit and the
	// graceful-downgrade argument applies to this dimension too, so the filter
	// here has to move with the ruled value rather than after it.
	if d.Dimension != HumanPrincipal && d.Dimension != ServicePrincipal {
		return
	}
	key := Key{OrgID: d.OrgID, Dimension: d.Dimension, PrincipalID: d.PrincipalID}
	// THE SEEN-SET IS NEVER UN-MARKED, AND THE RETRY LIVES IN ITS OWN SET.
	//
	// The obvious way to make a dropped record self-healing is to un-mark the
	// principal so its next request enqueues again. That is WRONG here, and the
	// reason is the fail-closed-for-new rule (the v11 master's condition on
	// this fix). The seen-set is SHARED: the unlimited path writes it and a
	// LIMITED check reads it. A deployment whose licence expires mid-process
	// crosses from one to the other - which is the whole reason the unlimited
	// tier records at all - and at that moment the seen-set is the only thing
	// between an established principal and a dependency_unreachable refusal.
	// Un-marking on a failed write would hand exactly that principal the
	// refusal this design exists to prevent, during an outage, when the ledger
	// cannot answer either.
	//
	// So the seen-set only grows (LRU eviction aside) and the DEBT is tracked
	// separately: a principal is enqueued when it is new or when it is owed a
	// retry, and the debt clears when the write lands.
	if a.seen.Has(key) && !a.retry.Has(key) {
		return
	}
	a.seen.Add(key)
	if !a.enqueue(backgroundWrite{record: true, key: key, dim: d.Dimension}) {
		// The DEBT is still the caller's business - enqueue counts, it does
		// not know the principal is owed a retry.
		a.retry.Add(key)
	}
}

// dimension is which dimension a queued write concerns, from whichever field
// this kind of write populates: recordUnlimited fills key and dim, the refusal
// audit write fills neither and carries it on dec. Every label site goes
// through here, because reading the field directly is how the panic handler
// came to emit dimension="" on the audit half (R3 round 2, MINOR-R2-5).
// atCapacityReason is the drop reason for a full queue, which differs by kind
// only so an operator can see which of the two writes is being shed.
func (w backgroundWrite) atCapacityReason() string {
	if w.record {
		return "at_capacity"
	}
	return "audit_at_capacity"
}

func (w backgroundWrite) dimension() Dimension {
	if w.record {
		return w.dim
	}
	return w.dec.Dimension
}

// backgroundWrite is one queued off-request-path write: either a telemetry
// record for an unlimited tier, or a refusal's audit row.
type backgroundWrite struct {
	record bool
	key    Key
	dim    Dimension
	sink   AuditSink
	dec    Decision
	ctx    context.Context
}

// enqueue offers a write to the queue without blocking, starting the worker
// pool on first use. It reports whether the write was accepted.
//
// THE QUEUE IS NEVER CLOSED, AND THAT IS THE POINT. Closing it from Close()
// while enqueue() sends is `panic: send on closed channel` - and a `default:`
// arm does NOT save a send on a closed channel, which is what made the first
// version look safe. It was reachable in the shipped agent on every SIGTERM:
// run.go's shutdown is a FLUSH and not a graceful server drain, so the
// listener is still accepting while the deferred shutdownTierAdmission runs,
// and the deferred authDB.Close() that unwinds after it guarantees every later
// admission is dependency_unreachable - a refusal, which wants an audit row,
// which enqueues. Found by the independent R3 with a stack trace.
//
// So shutdown flips a flag under a lock instead, the workers stop on their own
// `done` channel, and a write offered after Close is a counted drop rather
// than a crash.
func (a *Admitter) enqueue(w backgroundWrite) bool {
	a.workOnce.Do(func() {
		for i := 0; i < MaxBackgroundWriters; i++ {
			go a.backgroundWorker()
		}
	})
	// Held for READ across the send, and for WRITE around the flag flip in
	// Close, so there is no check-then-send window.
	a.closeMu.RLock()
	defer a.closeMu.RUnlock()
	if a.closed {
		// Counted HERE, under its own reason, because the two call sites
		// cannot tell this apart from a full queue and would file it as
		// at_capacity / audit_at_capacity. The outcome is the same - the write
		// is dropped - but the cause is the opposite, and an operator reading
		// at_capacity after a SIGTERM sizes the queue to fix a shutdown.
		backgroundDropsTotal.WithLabelValues(string(w.dimension()), "shutting_down").Inc()
		return false
	}
	a.recording.Add(1)
	select {
	case a.work <- w:
		return true
	default:
		a.recording.Done()
		backgroundDropsTotal.WithLabelValues(string(w.dimension()), w.atCapacityReason()).Inc()
		return false
	}
}

// backgroundWorker drains the queue. One of MaxBackgroundWriters.
func (a *Admitter) backgroundWorker() {
	for {
		var w backgroundWrite
		select {
		case w = <-a.work:
		case <-a.done:
			// Drain whatever is already queued, then stop. Close waits on the
			// WaitGroup before signalling here, so this is belt and braces.
			select {
			case w = <-a.work:
			default:
				return
			}
		}
		func() {
			defer a.recording.Done()
			// A panic in a store implementation must not take the process
			// down. These writes are off the request path and carry telemetry
			// and audit rows, so the correct cost of a bad one is a counted
			// drop, not an agent that stops serving traffic. Without this the
			// blast radius of a nil map or a bad driver in Record or Write is
			// the whole binary, on the goroutine furthest from the request
			// that caused it.
			//
			// The debt is deliberately NOT recorded here. A panic is a bug,
			// not a transient, so re-enqueuing the same input on the next
			// request for that principal would panic again on a loop; the
			// counter and the log are the signal, and they name the dimension.
			defer func() {
				if r := recover(); r != nil {
					// The two kinds of write carry the dimension in DIFFERENT
					// fields, and the first version of this read had them the
					// wrong way round: recordUnlimited sets both key and dim,
					// while the refusal audit write sets neither and carries
					// the dimension on dec. So the audit half emitted
					// dimension="" - outside this counter's closed domain, on
					// the branch a panic is most likely to reach, since an
					// AuditSink is the more exotic of the two stores.
					dim := w.dimension()
					backgroundDropsTotal.WithLabelValues(string(dim), "panicked").Inc()
					log.Printf("[admission] background write panicked for dimension=%s and was dropped: %v", dim, r)
				}
			}()
			if w.record {
				ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
				defer cancel()
				if err := a.ledger.Record(ctx, w.key, a.fingerprint); err != nil {
					// Counted, logged, and the DEBT recorded so the next
					// request for this principal enqueues it again. The
					// seen-set itself is left alone - see recordUnlimited for
					// why removing from it would be the wrong repair.
					if a.retry.add(w.key) {
						backgroundDropsTotal.WithLabelValues(string(w.dim), "debt_evicted").Inc()
					}
					backgroundDropsTotal.WithLabelValues(string(w.dim), "write_failed").Inc()
					log.Printf("[admission] telemetry record dropped for %s %q on an unlimited tier: %v", w.dim, w.key.PrincipalID, err)
					return
				}
				a.retry.Remove(w.key)
				return
			}
			w.sink.RecordRefusal(w.ctx, w.dec)
		}()
	}
}

// WithBackgroundQueueDepth sets the background write queue's depth. Tests set
// it to 1 to make the full-queue path deterministic.
func WithBackgroundQueueDepth(n int) Option {
	return func(a *Admitter) {
		if n < 1 {
			n = 1
		}
		a.work = make(chan backgroundWrite, n)
	}
}

// Close stops accepting background writes and drains the queue, giving up when
// ctx expires. It returns the number of writes still queued when it gave up.
//
// WHAT HAPPENS IF A PROCESS DIES WITHOUT IT, stated rather than left to be
// discovered (the v11 master's condition on this design). A queued telemetry
// record is a principal that IS in this process's seen-set and is NOT in the
// ledger. Losing it costs exactly one thing: after a restart that principal is
// new again, so if the licence has ALSO lapsed in the meantime it counts
// against the new ceiling. It costs nothing while the tier stays unlimited,
// because an unlimited tier never reads the ledger for a decision, and it
// cannot cause a refusal in the running process, because the seen-set outlives
// the queue. The exposure is therefore "an ungraceful stop AND a licence
// change", which is worth a bounded drain and not worth blocking a shutdown
// on: hence a deadline, and a count returned rather than an error swallowed.
func (a *Admitter) Close(ctx context.Context) int {
	// Stop accepting FIRST, under the write lock, so no send can be in flight
	// past this point. The queue itself is never closed; see enqueue.
	a.closeMu.Lock()
	a.closed = true
	a.closeMu.Unlock()
	drained := make(chan struct{})
	go func() { a.recording.Wait(); close(drained) }()
	select {
	case <-drained:
		a.workClose.Do(func() { close(a.done) })
		return 0
	case <-ctx.Done():
		left := len(a.work)
		a.workClose.Do(func() { close(a.done) })
		if left > 0 {
			log.Printf("[admission] shutdown gave up with %d background write(s) still queued; those principals stay in this process's "+
				"seen-set but are absent from the ledger, so after a restart they are new again", left)
		}
		return left
	}
}

// WaitForRecording blocks until every in-flight background write (an
// unlimited-tier record, a refusal audit row) has finished. For tests and a
// graceful shutdown; production never waits on telemetry.
func (a *Admitter) WaitForRecording() { a.recording.Wait() }
