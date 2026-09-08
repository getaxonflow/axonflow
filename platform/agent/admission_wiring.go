// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/agent/license/admission"
	sharedidentity "axonflow/platform/shared/identity"
)

// This file is the agent's ONE call site of admission.Admit (#3593). Every
// path that brings a principal into existence reaches admitPrincipal:
//
//	service_principal  Authenticate             (authenticator.go) - the one
//	                                            function every client-credential
//	                                            path traverses
//	human_principal    adaptedValidateUserToken (identity_compat.go) - the HS256
//	                                            per-user token's single entry
//	                   resolveTokenAdmitted     (below) - the shared validator
//	                                            suite's single entry on the
//	                                            proxied REST and MCP planes
//	node               admitNodeAtBoot          (below) - this agent's own node,
//	                                            at boot and on every heartbeat
//
// platform/agent/license/admission/callsite_census_test.go walks this
// package's AST and fails if Admit is called anywhere else, if any of the
// functions above stops calling admitPrincipal, or if
// sharedidentity.ResolveToken gains a caller other than resolveTokenAdmitted.
//
// THE UNWIRED WINDOW. tierAdmitter is set by initTierAdmission from run.go
// once the application-role pool is open, which is AFTER initServerImmediately
// starts answering requests. A request in that window finds no admitter. It is
// ALLOWED and counted on axonflow_tier_admission_unwired_total{dimension}, and
// logged once per dimension. That is the same posture the verified licence read
// takes for an unregistered source
// (axonflow_license_tier_source_unregistered_total): a default that is visible
// on every scrape rather than a refusal of every principal during a window the
// deployment cannot avoid.
//
// The window is the ONLY way to reach the default. There is no deployment that
// "never opens a database" and goes on serving: the agent's no-database arm is
// fatal, and the orchestrator's policy-authoring handlers are built in the same
// block as its admitter, so with no database they answer 503 rather than an
// unlimited yes. TestNoDatabaseMeansNoServingRatherThanNoLimit and
// TestOrgRootAuthoringCannotOutliveItsAdmitter pin those two facts, because
// otherwise unsetting DATABASE_URL would be a one-variable bypass of every
// limit in #3593. TestRunWiresTierAdmissionOnTheDatabasePath pins that run.go
// wires it, and the runtime-e2e suite proves the shipped binary refuses the
// 26th principal, which it could not do unwired.

var tierAdmitter atomic.Pointer[admission.Admitter]

// This counter covers the BOOT WINDOW and nothing else, because there is no
// database-free way to serve either dimension. An agent started with no
// DATABASE_URL does not run degraded, it refuses to start (run.go: "DATABASE_URL
// is required"), and the orchestrator's policy-authoring routes answer 503
// "Policy API not initialized - database connection required" because
// policyAPIHandler is constructed inside the same usageDB != nil block that
// wires the admitter. TestNoDatabaseMeansNoServingRatherThanNoLimit pins both,
// so "unset DATABASE_URL" cannot become a way to serve traffic with the scale
// limits switched off without turning that test red.
var admissionUnwiredTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_tier_admission_unwired_total",
	Help: "Principal admissions that found no admitter wired during the boot window and were allowed by default, by dimension.",
}, []string{"dimension"})

var admissionSkippedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_tier_admission_skipped_total",
	Help: "Principal admissions skipped because the request carried no organization or no principal to admit, by dimension and which was missing.",
}, []string{"dimension", "missing"})

var admissionUnwiredLogged sync.Map

func init() {
	for _, d := range admission.Dimensions() {
		admissionUnwiredTotal.WithLabelValues(string(d)).Add(0)
		for _, m := range []string{"org", "principal"} {
			admissionSkippedTotal.WithLabelValues(string(d), m).Add(0)
		}
	}
}

// tierLimitRefusal is the error a principal path returns when the principal
// was refused by the tier limit, so ResolveUser and the two token planes can
// render it as the 402 it is rather than as the 401 an invalid token gets.
// errors.As on it is the discriminator; the message already carries the code.
type tierLimitRefusal struct {
	Decision admission.Decision
}

func (e *tierLimitRefusal) Error() string { return e.Decision.Message() }

// AuthError renders the refusal for the AuthError-carrying planes.
func (e *tierLimitRefusal) AuthError() *AuthError {
	ae := &AuthError{
		Code:       e.Decision.Code,
		Message:    e.Decision.Message(),
		HTTPStatus: admission.HTTPStatus,
	}
	if e.Decision.RetryAfter > 0 {
		ae.RetryAfter = strconv.Itoa(int(e.Decision.RetryAfter.Seconds()))
	}
	return ae
}

// asTierLimitRefusal reports whether err is (or wraps) a tier-limit refusal.
func asTierLimitRefusal(err error) (*tierLimitRefusal, bool) {
	var ref *tierLimitRefusal
	if errors.As(err, &ref) {
		return ref, true
	}
	return nil, false
}

// isTierLimitAuthError reports whether an AuthError is a tier-limit refusal,
// for handlers that write their own audit marker on user-resolution failures
// and must not file a refusal under user_token_rejected.
func isTierLimitAuthError(err *AuthError) bool {
	return err != nil && strings.HasPrefix(err.Code, "ERR_TIER_LIMIT_")
}

// writeTierLimitRefusal renders a refusal on a raw-JSON plane: 402, the
// structured body (admission.Wire) and Retry-After when the refusal is the
// outage one.
func writeTierLimitRefusal(w http.ResponseWriter, ref *tierLimitRefusal) {
	w.Header().Set("Content-Type", "application/json")
	if ref.Decision.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(ref.Decision.RetryAfter.Seconds())))
	}
	w.WriteHeader(admission.HTTPStatus)
	_ = json.NewEncoder(w).Encode(ref.Decision.Wire())
}

// canonicalPrincipalEmail is the key a human principal is admitted under:
// the identity plane's canonical form (lower-cased, trimmed), so two
// spellings of one address are one principal.
func canonicalPrincipalEmail(email string) string {
	return sharedidentity.CanonicalEmail(email)
}

// admitPrincipal is the ONE call site of admission.Admit in this package. A
// nil return is an admission (or a counted skip); a non-nil return is the
// refusal, ready for the wire through AuthError() or writeTierLimitRefusal.
func admitPrincipal(ctx context.Context, dim admission.Dimension, orgID, principalID string) *tierLimitRefusal {
	if strings.TrimSpace(orgID) == "" {
		admissionSkippedTotal.WithLabelValues(string(dim), "org").Inc()
		return nil
	}
	if strings.TrimSpace(principalID) == "" {
		admissionSkippedTotal.WithLabelValues(string(dim), "principal").Inc()
		return nil
	}
	a := tierAdmitter.Load()
	if a == nil {
		admissionUnwiredTotal.WithLabelValues(string(dim)).Inc()
		if _, seen := admissionUnwiredLogged.LoadOrStore(dim, struct{}{}); !seen {
			log.Printf("[admission] no admitter wired yet for dimension=%s; principals are admitted by default until the "+
				"database-connected boot path wires the ledger (counted on axonflow_tier_admission_unwired_total). "+
				"This is the boot window only: a process with no database refuses to serve rather than serving unlimited.", dim)
		}
		return nil
	}
	dec, err := a.Admit(ctx, admission.Request{Dimension: dim, OrgID: orgID, PrincipalID: principalID})
	if err != nil {
		// Only ErrInvalidRequest reaches here, and both blank inputs were
		// handled above; an unknown dimension is a programming error at the
		// call site. Refuse rather than admit: a decision the package could
		// not make is not an admission.
		log.Printf("[admission] Admit returned an error for dimension=%s org=%q: %v", dim, orgID, err)
		return &tierLimitRefusal{Decision: admission.Decision{
			Dimension: dim, OrgID: orgID, PrincipalID: principalID, Code: dim.Code(),
			Reason: admission.ReasonDependencyUnreachable, RetryAfter: admission.RetryAfter,
		}}
	}
	if dec.Allowed {
		return nil
	}
	return &tierLimitRefusal{Decision: dec}
}

// resolveTokenAdmitted is the single caller of sharedidentity.ResolveToken in
// this package: the proxied REST plane and the MCP plane both resolve their
// per-user token through it, so a validated human identity is admitted on the
// tier limit at the same choke point the compat adapter observes. The
// synthetic-probe tag is stamped here, once, for the same reason.
func resolveTokenAdmitted(ctx context.Context, orgID, token string, synthetic bool) (*sharedidentity.ValidatedIdentity, error) {
	vid, err := sharedidentity.ResolveToken(sharedidentity.ContextWithSyntheticProbe(ctx, synthetic), orgID, token)
	if err != nil || vid == nil {
		return vid, err
	}
	if ref := admitPrincipal(ctx, admission.HumanPrincipal, orgID, canonicalPrincipalEmail(vid.Email)); ref != nil {
		return nil, ref
	}
	return vid, nil
}

// initTierAdmission wires the ledger, the node lease store, the audit sink and
// the licence fingerprint over the application-role pool, and starts warming
// the seen-set for the deployment's organizations. Called once from run.go on
// the database-connected path.
func initTierAdmission(db *sql.DB, orgIDs ...string) *admission.Admitter {
	a := admission.New(
		admission.NewPostgresLedger(db),
		admission.WithNodeLeases(admission.NewPostgresNodeLeases(db)),
		admission.WithAuditSink(admission.NewDBAuditSink(db)),
		admission.WithLicenceFingerprint(admission.LicenceFingerprint(os.Getenv("AXONFLOW_LICENSE_KEY"))),
	)
	tierAdmitter.Store(a)
	// Resolve the node identity HERE rather than leaving it to whichever call
	// happens first. It is lazily memoised, and its failure mode is a log line
	// - "node identity is EPHEMERAL, the data directory is not writable" - that
	// an operator needs at boot, next to the rest of the wiring, not minutes
	// later interleaved with request logs (or never, on a process whose first
	// caller is a /health scrape nobody reads).
	nodeIdentity()
	go warmTierAdmissionUntilItSucceeds(a, orgIDs)
	log.Printf("[admission] tier admission wired over the application pool (ledger principal_admissions, leases node_leases, seen-set cap %d)", admission.DefaultSeenSetCap)
	return a
}

// warmTierAdmissionUntilItSucceeds retries the warm with backoff so a ledger
// that is down at boot is not down forever from this process's point of view.
func warmTierAdmissionUntilItSucceeds(a *admission.Admitter, orgIDs []string) {
	backoff := 2 * time.Second
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		n, err := a.Warm(ctx, orgIDs...)
		cancel()
		if err == nil {
			log.Printf("[admission] seen-set warmed with %d admission(s) for %d organization(s)", n, len(orgIDs))
			return
		}
		log.Printf("[admission] seen-set warm failed (%v); retrying in %v. Until it succeeds every principal is new to this process, and on a limited tier a new principal is refused while the ledger is unreachable.", err, backoff)
		time.Sleep(backoff)
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// Node identity (master ruling, 2026-09-08): AXONFLOW_NODE_ID when set, else
// an id generated ONCE and persisted under the agent's data directory, so a
// restart on the same volume is the same node and a genuinely new replica is
// a new node. NEVER the hostname: ECS tasks and Kubernetes pods get a fresh
// one on every recreate, which would make a routine redeploy read as a second
// node.
const (
	envNodeID      = "AXONFLOW_NODE_ID"
	envDataDir     = "AXONFLOW_DATA_DIR"
	defaultDataDir = "/var/lib/axonflow"
	nodeIDFile     = "node-id"
)

var (
	nodeIdentityOnce sync.Once
	nodeIdentityVal  string
)

// nodeIdentity resolves the node id once per process.
func nodeIdentity() string {
	nodeIdentityOnce.Do(func() { nodeIdentityVal = resolveNodeIdentity(os.Getenv(envNodeID), os.Getenv(envDataDir)) })
	return nodeIdentityVal
}

// resolveNodeIdentity is nodeIdentity with its inputs as parameters, so the
// persisted-file path can be exercised against a temporary directory.
func resolveNodeIdentity(envID, dataDir string) string {
	if id := strings.TrimSpace(envID); id != "" {
		return id
	}
	if strings.TrimSpace(dataDir) == "" {
		dataDir = defaultDataDir
	}
	path := filepath.Join(dataDir, nodeIDFile)
	if raw, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(raw)); id != "" {
			return id
		}
	}
	id := "node-" + uuid.NewString()
	if err := os.MkdirAll(dataDir, 0o750); err == nil {
		if err := os.WriteFile(path, []byte(id+"\n"), 0o640); err == nil {
			log.Printf("[admission] node identity %q generated and persisted at %s", id, path)
			return id
		}
	}
	log.Printf("[admission] node identity %q is EPHEMERAL: %s is not writable. A restart will present a NEW node until this one's lease "+
		"expires (%v); mount a volume at %s or set %s to keep one identity across restarts.",
		id, path, admission.NodeLeaseTTL, dataDir, envNodeID)
	return id
}

// nodeBootWait bounds how long the node admission waits for a foreign lease to
// expire before refusing to run.
//
// IT IS THE BOOT HALF OF ONE POLICY WHOSE OTHER HALF IS
// nodeOverLimitBeatsBeforeGivingUp (ten beats, five minutes, below). The two
// numbers differ because the situations do: at BOOT nothing is being served
// yet, so waiting is free and the budget is generous; while RUNNING this node
// is serving traffic, so the question is how long a genuine two-node overlap
// may persist, and the answer is as short as the lease TTL allows. Read them
// together - changing one without the other splits a single policy into two
// unrelated numbers.
//
// IT IS FIFTEEN MINUTES, NOT ONE LEASE TTL, and the reason is a rolling
// deploy. The clock that matters is not this process's boot: it is the OLD
// node's last heartbeat, which keeps ADVANCING while the old task lives. ECS
// and Kubernetes both start the replacement before draining the incumbent, and
// `/health` answers as soon as initServerImmediately runs, so the orchestrator
// may consider the new task healthy and only then begin draining the old one -
// after which its lease still counts for a further NodeLeaseTTL. A budget of
// one TTL measured from boot is therefore routinely too short, and its failure
// mode is the worst one available: log.Fatalf, a failed deploy, and a restart
// loop that repeats the same race. Fifteen minutes covers a slow drain; a
// deployment that has genuinely run two nodes for fifteen minutes is not a
// deploy in progress. R3 round 1, H2.
//
// The common case never reaches here at all: with a persistent data directory
// (docker-compose.yml mounts one) or AXONFLOW_NODE_ID set, a recreated node
// presents the SAME identity and simply renews its own lease.
const nodeBootWait = 15 * time.Minute

// nodeBootRetry is how often the wait re-asks.
const nodeBootRetry = 10 * time.Second

// admitNodeAtBoot admits this agent as a node of the deployment organization
// and starts the heartbeat that renews the lease.
//
// The rule (master, 2026-09-08): refuse to run ONLY on a POSITIVE answer -
// another node holds an unexpired lease while the limit is 1 - and even then
// only after waiting up to nodeBootWait for that lease to expire. An
// unreachable lease store boots and keeps serving: it is counted and audited
// as dependency_unreachable by the package, and the heartbeat retries. A node
// has no local seen-set, so refusing on "unknown" would turn every database
// blip into a boot loop on the one node Community is allowed.
//
// IT RUNS IN ITS OWN GOROUTINE AND DOES NOT BLOCK BOOT. An earlier version was
// called inline from Run, which meant a deployment waiting for a foreign lease
// stalled every later initialisation step - the audit manager included - while
// `/health` had already been answering since initServerImmediately. The
// process either becomes a legitimate node or exits; it does not sit half
// initialised pretending otherwise. R3 round 1, H2.
func admitNodeAtBoot(ctx context.Context, orgID string) {
	go admitNodeAndHeartbeat(ctx, orgID)
}

func admitNodeAndHeartbeat(ctx context.Context, orgID string) {
	id := nodeIdentity()
	deadline := time.Now().Add(nodeBootWait)
	for {
		ref := admitPrincipal(ctx, admission.Node, orgID, id)
		switch {
		case ref == nil:
			log.Printf("[admission] node %q admitted for org %q", id, orgID)
			runNodeHeartbeat(orgID, id)
			return
		case ref.Decision.Reason == admission.ReasonDependencyUnreachable:
			log.Printf("[admission] node %q: lease store unreachable (%s). Serving anyway; the heartbeat retries every %v.",
				id, ref.Decision.Message(), admission.NodeHeartbeatInterval)
			runNodeHeartbeat(orgID, id)
			return
		case time.Now().Before(deadline):
			log.Printf("[admission] node %q not admitted for org %q: %s. Another node holds the lease; waiting up to %v more for it to expire "+
				"(a rolling deploy resolves this as soon as the previous node stops heartbeating). This process is already serving.",
				id, orgID, ref.Decision.Message(), time.Until(deadline).Round(time.Second))
			time.Sleep(nodeBootRetry)
		default:
			log.Fatalf("[admission] REFUSING TO RUN: node %q is over the licence tier's node limit for org %q after waiting %v: %s. "+
				"If this is the SAME node under a new identity, set %s to the id it was admitted under (or mount a volume at %s so the id persists); "+
				"if it is a second node, the Community edition is single-node and Evaluation or Enterprise lifts the limit.",
				id, orgID, nodeBootWait, ref.Decision.Message(), envNodeID, defaultDataDir)
		}
	}
}

// nodeOverLimitBeatsBeforeGivingUp is how many CONSECUTIVE positive
// over_limit answers the heartbeat tolerates before it stops the process.
//
// It exists because the two refusal reasons must not be treated alike, which
// the first version of this loop did (independent R3, MAJOR-2). An
// UNREACHABLE store means "keep serving" - that is the whole availability
// ruling. A positive OVER_LIMIT answer means another node holds the only
// lease, and continuing to serve on it is the split brain persisting until
// somebody restarts this process rather than until the partition heals. Ten
// beats is five minutes: longer than one lease TTL, so a single lost race or
// a slow renewal cannot kill a healthy node, and short enough that a genuine
// overlap ends on its own.
const nodeOverLimitBeatsBeforeGivingUp = 10

// runNodeHeartbeat renews this node's lease every NodeHeartbeatInterval.
//
// An unreachable store never stops the node: it is logged, counted by the
// package, and tried again at the next beat. A SUSTAINED over_limit answer
// does stop it - see nodeOverLimitBeatsBeforeGivingUp - because that is the
// only thing that bounds a post-partition overlap by anything other than an
// operator noticing.
func runNodeHeartbeat(orgID, id string) {
	ticker := time.NewTicker(admission.NodeHeartbeatInterval)
	defer ticker.Stop()
	overLimitBeats := 0
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ref := admitPrincipal(ctx, admission.Node, orgID, id)
		cancel()
		var stop bool
		overLimitBeats, stop = nextOverLimitBeats(overLimitBeats, ref)
		switch {
		case stop:
			log.Fatalf("[admission] STOPPING: node %q has been over the licence tier's node limit for %d consecutive heartbeats (%v): %s. "+
				"Another node holds the lease; two nodes serving one single-node licence is the state this bound exists to end. "+
				"If this is the SAME node under a new identity, set %s (or mount a volume at %s so the id persists).",
				id, overLimitBeats, time.Duration(overLimitBeats)*admission.NodeHeartbeatInterval,
				ref.Decision.Message(), envNodeID, defaultDataDir)
		case ref == nil:
			// Renewed.
		case overLimitBeats == 0:
			log.Printf("[admission] node %q heartbeat did not renew its lease (%s: %s); this node keeps serving and retries in %v",
				id, ref.Decision.Reason, ref.Decision.Message(), admission.NodeHeartbeatInterval)
		default:
			log.Printf("[admission] node %q lost its lease to another node (%s). Beat %d of %d before this process stops; "+
				"if the other node is stale its lease expires within %v and this resolves itself.",
				id, ref.Decision.Message(), overLimitBeats, nodeOverLimitBeatsBeforeGivingUp, admission.NodeLeaseTTL)
		}
	}
}

// nextOverLimitBeats is the heartbeat's whole decision, extracted from the loop
// so it can be tested: the loop itself is a ticker plus a log.Fatalf and cannot
// be driven from a test.
//
// It exists because the MAJOR-2 remedy - discriminate the two refusal reasons,
// count only CONSECUTIVE over-limit answers, and stop at the tenth - was two
// `if`s and a counter that nothing turned red on. A "simplify the heartbeat
// logging" edit that collapsed them back would silently restore the unbounded
// two-node overlap the bound exists to end.
//
// The CONSECUTIVE property is the subtle half. A `dependency_unreachable` beat
// RESETS the count rather than being ignored, because a node that cannot reach
// the lease store has not been told it is over the limit - it has been told
// nothing. That means a flapping link defers the stop indefinitely, which is
// the deliberate choice: the availability posture says an unreachable store
// never stops a running node, and only a positive, sustained "another node
// holds your lease" does.
// See nodeBootWait for the boot half of the same policy: fifteen minutes there
// because nothing is being served yet, five minutes here because it is.
func nextOverLimitBeats(prev int, ref *tierLimitRefusal) (beats int, stop bool) {
	if ref == nil {
		return 0, false // the lease renewed
	}
	if ref.Decision.Reason != admission.ReasonOverLimit {
		return 0, false // told nothing, not told "over limit"
	}
	beats = prev + 1
	return beats, beats >= nodeOverLimitBeatsBeforeGivingUp
}

// shutdownTierAdmission drains the background write queue on the way out,
// bounded so a slow store cannot hold the shutdown.
//
// WHAT IS AT STAKE, because it is small and specific: a queued telemetry
// record is a principal that IS in this process's seen-set and is NOT yet in
// the ledger. Losing it costs nothing while the tier stays unlimited, and
// costs that principal its grace if the licence ALSO lapses before the next
// start. Draining is cheap, so it is worth doing; waiting on it is not, so it
// has a deadline. See Admitter.Close.
func shutdownTierAdmission() {
	a := tierAdmitter.Load()
	if a == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if left := a.Close(ctx); left > 0 {
		log.Printf("[admission] shutdown: %d background write(s) abandoned", left)
	}
}

// tierAdmissionHealth is what /health reports under tier_admission.
func tierAdmissionHealth() map[string]interface{} {
	a := tierAdmitter.Load()
	if a == nil {
		// Reachable only during the boot window: this process refuses to
		// start without a database, so an unwired admitter on a serving
		// agent means "not yet", never "never".
		return map[string]interface{}{
			"wired":     false,
			"enforcing": false,
			"cause":     "boot",
			"note":      "the ledger is not wired yet; principals are admitted by default until the database-connected boot path wires it",
		}
	}
	h := a.Health()
	out := map[string]interface{}{
		"wired":          true,
		"enforcing":      true,
		"ledger":         "healthy",
		"warmed":         h.Warmed,
		"seen_set_size":  h.SeenSetSize,
		"seen_set_cap":   h.SeenSetCap,
		"last_success":   h.LastSuccessAt,
		"last_error":     h.LastError,
		"last_error_at":  h.LastErrorAt,
		"refusal_status": admission.HTTPStatus,
		"node_id":        nodeIdentity(),
	}
	if !h.LedgerHealthy {
		out["ledger"] = "degraded"
	}
	return out
}
