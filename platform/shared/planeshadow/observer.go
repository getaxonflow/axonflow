// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
	"axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"

	"github.com/prometheus/client_golang/prometheus"
)

// maxWorlds bounds the resident compiled evaluation environments.
//
// Each one holds an OPA engine over a signed bundle, so the bound is memory
// rather than correctness: exceeding it costs a rebuild, never a wrong answer.
// Twelve planes times a handful of active organizations is the ordinary
// working set; the cap is generous enough that an eviction means either a very
// large tenant count or a policy set being edited in a loop, both of which are
// visible on axonflow_decision_shadow_bundle_builds_total.
const maxWorlds = 256

// observeTimeout bounds one worker's evaluation.
//
// It exists because the worker holds a queue slot: an evaluation that hangs
// does not delay any request, but it does stop the queue draining, and a
// stalled queue turns into dropped observations, which is a hole in a
// denominator rather than an outage. Bounded, counted, and never propagated to
// a caller.
const observeTimeout = 10 * time.Second

// Observer is the process-wide shadow. One per binary.
type Observer struct {
	component string
	cfg       Config
	worlds    *worldCache
	recorder  Recorder

	// orgModes is the per-organization mode source. Nil means the process mode
	// is the whole answer, which is every community build and every deployment
	// with no settings store.
	//
	// IT AND processMode ARE READ IN EXACTLY ONE FUNCTION, effectiveMode.
	// TestShadowModeIsConsultedAtExactlyOneSite enumerates every selector on
	// both across every file in this package and fails on a second reader,
	// exactly as #3596's census does for the identity axis. The failure that
	// discipline prevents is "the flag is honored on some planes and not
	// others", which is indistinguishable from a clean window.
	orgModes identity.DecisionShadowModeSource

	// processMode is the deployment-wide mode from AXONFLOW_DECISION_SHADOW_MODE.
	//
	// IT IS A FIELD OF ITS OWN RATHER THAN cfg.Mode, and that is what makes the
	// census exact. Config carries the mode ALONGSIDE the plane list, the
	// sampling rate and the pool sizing, so a census keyed on `cfg` would fire
	// on every read of the sampling rate - and the only way to keep it quiet
	// would be to permit the functions that read those, which is exactly the
	// permission a genuine second mode read would then hide behind.
	//
	// The name is deliberately unique in the package so
	// TestShadowModeIsConsultedAtExactlyOneSite can find every read of it
	// syntactically, in every file, under both build tags. Mode() reports it
	// and decides nothing.
	processMode Mode

	// compileOpts are the deployment-level compilation options every bundle is
	// built with. They are read once, when the cache is constructed.
	compileOpts legacycompile.Options

	// couldObserve is the CHEAP GATE the engines read before building an
	// Observation at all, and it is a strict OVER-APPROXIMATION of "some
	// organization on this deployment is shadowing".
	//
	// It is a precomputed bool rather than a mode read, so it is not a second
	// consultation site: it is set once at construction from
	// `records(process) || orgModes != nil` and never again. Both directions
	// matter. It can be true while every organization resolves to off - which
	// costs an Observation build that is then discarded, and nothing else. It
	// can NEVER be false while some organization resolves to shadow, because
	// the only way a record can raise an organization above a process-off
	// deployment is through orgModes, and orgModes being non-nil forces this
	// true. TestCouldObserveIsAStrictOverApproximation asserts exactly that.
	couldObserve atomic.Bool

	queue   chan Observation
	seq     atomic.Uint64
	stop    chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup

	orgModeFailures atomic.Uint64
	dropped         atomic.Uint64
}

// OrgModeSource is the per-organization mode source this package consumes. It
// is an alias of the identity contract rather than a second interface, so the
// one store that answers both axes satisfies both by construction and a
// binary's wiring cannot accidentally hand the shadow a different store than
// the identity plane reads.
type OrgModeSource = identity.DecisionShadowModeSource

// Option customizes an Observer.
type Option func(*Observer)

// WithComponent names the binary this observer runs in, so a difference can be
// attributed to a plane rather than to whichever container's log it was read
// from.
func WithComponent(name string) Option {
	return func(o *Observer) { o.component = name }
}

// WithOrgModes wires the per-organization mode source. Nil (the default, and
// every community build) means the process mode is the whole answer.
func WithOrgModes(src identity.DecisionShadowModeSource) Option {
	return func(o *Observer) { o.orgModes = src }
}

// WithCompileOptions sets the deployment-level compilation options - the trust
// realm segment groups are qualified with, the content root a legacy static
// redaction targets, the approver pools a require_approval row compiles
// against.
//
// They are deployment configuration rather than defaults BOTH sides can pick
// independently: the realm and the field-path mapping change the identifiers
// the request must use, and a corpus built against different options silently
// drops every segment-scoped constraint from the ADR-065 side while the legacy
// side still applies it.
func WithCompileOptions(opts legacycompile.Options) Option {
	return func(o *Observer) { o.compileOpts = opts }
}

// NewObserver builds the shadow.
//
// It refuses every argument whose absence would make the observer quietly
// useless or quietly wrong: an unusable mode, a nil row source (nothing to
// compile a bundle from, so every observation would be a build failure), and a
// nil recorder (a shadow phase that records nothing is a shadow phase that has
// not run). identity.NewCompatAdapter's argument, and the same failures.
func NewObserver(cfg Config, rows RowSource, recorder Recorder, opts ...Option) (*Observer, error) {
	if !identity.DecisionShadowModeIsStorable(cfg.Mode) {
		return nil, fmt.Errorf("planeshadow: mode %s is not usable on this axis; the storable modes are %v", cfg.Mode, identity.DecisionShadowModeNames())
	}
	if cfg.SampleRate <= 0 || cfg.SampleRate > 1 {
		return nil, fmt.Errorf("planeshadow: sample rate %v is outside (0, 1]", cfg.SampleRate)
	}
	if rows == nil {
		return nil, fmt.Errorf("planeshadow: a row source is required; without one no bundle can be compiled and every observation would fail to build")
	}
	if reason := recorderRecordsNothing(recorder); reason != "" {
		return nil, fmt.Errorf("planeshadow: a recorder that records something is required: %s", reason)
	}
	o := &Observer{
		component:   "unknown",
		cfg:         cfg,
		processMode: cfg.Mode,
		recorder:    recorder,
		queue:       make(chan Observation, cfg.QueueDepth),
		stop:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(o)
	}
	o.worlds = newWorldCache(rows, o.compileOpts, maxWorlds)
	// Read from the LOCAL cfg and the field set by the options, once, here.
	// See Observer.couldObserve for why this over-approximation is safe in
	// exactly one direction.
	o.couldObserve.Store(records(cfg.Mode) || o.orgModes != nil)
	for i := 0; i < cfg.Workers; i++ {
		o.wg.Add(1)
		go o.work()
	}
	return o, nil
}

// Enabled reports whether any observation on this process could ever become a
// comparison. See Observer.couldObserve for the over-approximation argument.
func (o *Observer) Enabled() bool { return o != nil && o.couldObserve.Load() }

// HasPerOrgSource reports whether a per-organization mode source is wired.
//
// A separate one-line accessor rather than an inline nil check, for the reason
// identity.processModeForLog exists: the AST census's "exactly one reader"
// statement has to stay literally true, and a startup log line saying which
// modes can apply is not a reason to add a second reader of the field.
func (o *Observer) HasPerOrgSource() bool {
	return o != nil && o.orgModes != nil
}

// Mode reports the DEPLOYMENT-WIDE mode. For diagnostics and startup logging
// only - no call site may branch on it, and it is not the mode an observation
// ran in: that is Comparison.Mode, which composes this value with the
// organization's record (see effectiveMode).
func (o *Observer) Mode() Mode {
	if o == nil {
		return identity.CompatModeOff
	}
	return o.processMode
}

// effectiveMode is THE ONE FUNCTION THAT READS THE MODE.
//
// It composes the deployment flag with the organization's record through
// identity.EffectiveMode - the SAME function CompatAdapter.effectiveMode calls,
// not a copy of its rule. #3596 argued that composition once (the record wins
// in both directions; absent means the process flag; unreadable means the
// process flag, counted), and a second axis restating it would be one edit away
// from disagreeing with it.
//
// enforce is clamped here as well as refused at parse and by the column's
// CHECK. Three fences, and the third exists because the first two govern
// writes: a row restored from a backup, or written by a later migration, has
// passed neither.
func (o *Observer) effectiveMode(ctx context.Context, orgID string) Mode {
	process := o.processMode
	if o.orgModes == nil || orgID == "" {
		return process
	}
	// THE REQUEST'S CANCELLATION IS DROPPED, DELIBERATELY.
	//
	// This is a CONFIGURATION read, not request work, and its result is
	// MEMOIZED IN A SHARED STORE. A client disconnect mid-refresh would
	// otherwise be cached as a read failure for the whole TTL window - and
	// that entry is the one the IDENTITY axis reads too, so one cancelled
	// request would move a whole organization onto the process mode on both
	// axes for up to a minute. The deadline below is what bounds the call;
	// the caller's cancellation is not.
	octx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	record, found, err := o.orgModes.OrgDecisionShadowMode(octx, orgID)
	if err != nil {
		o.noteOrgModeFailure(orgID, err)
		return process
	}
	mode, err := identity.EffectiveMode(process, record, found)
	if err != nil {
		o.noteOrgModeFailure(orgID, err)
		return process
	}
	if !identity.DecisionShadowModeIsStorable(mode) {
		o.noteOrgModeFailure(orgID, fmt.Errorf("the recorded mode %s is not one this axis may hold; the decision plane has no authority before v11", mode))
		return process
	}
	return mode
}

func (o *Observer) noteOrgModeFailure(orgID string, err error) {
	o.orgModeFailures.Add(1)
	shadowOrgModeFailures.Inc()
	log.Printf("[DECISION-SHADOW] component=%s org=%s per-org shadow mode unavailable, using the process mode: %s",
		logutil.Sanitize(o.component), logutil.Sanitize(orgID), logutil.Sanitize(err.Error()))
}

// OrgModeFailures reports how many per-organization mode reads fell back.
func (o *Observer) OrgModeFailures() uint64 {
	if o == nil {
		return 0
	}
	return o.orgModeFailures.Load()
}

// Dropped reports how many observations the queue refused.
func (o *Observer) Dropped() uint64 {
	if o == nil {
		return 0
	}
	return o.dropped.Load()
}

// Observe offers one plane's evaluation to the shadow.
//
// IT RETURNS NOTHING, AND THAT IS THE NON-ENFORCEMENT GUARANTEE. There is no
// value for a call site to read, so no call site can act on the shadow's
// opinion; making one able to would take a new API and a visible diff. See the
// package doc.
//
// A nil Observer is off, so an unwired deployment needs no nil check at any
// call site.
func (o *Observer) Observe(ctx context.Context, obs Observation) {
	if o == nil || !o.couldObserve.Load() {
		return
	}
	start := time.Now()

	// THE ONE MODE READ, resolved for THIS organization.
	//
	// IT IS THE ONE PART OF Observe THAT IS NOT FREE, AND SAYING SO MATTERS.
	// On a per-organization deployment this consults a TTL-memoized store,
	// which is a map read under a mutex on all but the first request for an
	// organization in each window - and on THAT request it is a bounded
	// database round trip, on the request path, inside the policy engine.
	//
	// It is not moved to the worker, and the reason is the denominator: the
	// mode is what decides whether to record, so resolving it later would
	// enqueue every non-participating organization's traffic and let it
	// displace the participating one's under backpressure. A deployment where
	// one org in a hundred shadows would spend 99% of its queue on
	// observations it then discards. The cost is therefore paid here, bounded,
	// measured by shadowEnqueueLatency, and stated in the operator docs
	// rather than described as free. Everything below
	// reads the local. An organization whose resolved mode does not record is
	// not in the window at all - it is not a hole in a denominator, so it is
	// deliberately not counted as a disposition: counting it would put every
	// request of every non-participating tenant into the series an operator
	// reads to size the window.
	// A CALL SITE THAT NAMED AN ORG SCOPE AND NO ORG ID CANNOT BE RESOLVED
	// PER-ORGANIZATION, AND THAT MUST BE COUNTED RATHER THAN INFERRED.
	//
	// effectiveMode falls back to the process mode when OrgID is empty, which
	// is the right answer for a plane that genuinely has no organization - and
	// exactly the wrong one for a site that HAS an organization and did not
	// pass it. Three sites shipped that way (both MCP response passes and the
	// only cowork_ingest evaluation), and the failure is silent in both
	// directions: a per-org enablement never reaches them, a per-org exemption
	// never releases them, and no series moves either way.
	//
	// The condition is deliberately narrow. It fires only when a per-org source
	// is wired (otherwise the process flag IS the whole answer and an empty
	// OrgID is not a defect) and only when the site named a scope, which is a
	// site that knows which organization it is serving.
	// HasPerOrgSource rather than an inline `o.orgModes != nil`, for the reason
	// that accessor exists: the AST census's "exactly one reader" statement has
	// to stay literally true, and permitting a second selector here is the
	// loophole a genuine second mode read would hide behind. Measured - the
	// census caught the inline version.
	if o.HasPerOrgSource() && obs.OrgScope != "" && obs.OrgID == "" {
		NoteRefused(obs.Plane, "the call site named an org scope but no org id, so the per-organization "+
			"decision-shadow mode cannot be resolved for it and the process mode would silently decide; "+
			"set EvalOptions.OrgID at this site (#3564)")
		return
	}

	mode := o.effectiveMode(ctx, obs.OrgID)
	if !records(mode) {
		// NOT A HOLE IN THE DENOMINATOR - this organization is not in the
		// window at all - so it is not counted as a disposition. But the
		// REQUEST-PATH COST was still paid: effectiveMode above is a memoized
		// read and, once per organization per TTL window, a bounded database
		// round trip. On the documented rollout shape (process mode off, one
		// organization shadowing) this is 99% of requests, and leaving the
		// histogram unobserved here made the metric blind to exactly the
		// population that pays the most for the feature while recording
		// nothing.
		//
		// A separate label keeps the two populations from being averaged
		// together: `recorded="false"` is the cost of deciding not to record.
		shadowEnqueueLatency.WithLabelValues(planeLabel(string(obs.Plane)), "false").Observe(time.Since(start).Seconds())
		return
	}

	plane := string(obs.Plane)
	if defect := obs.Validate(); defect != "" {
		// OUR defect, not the caller's request being unusual. Recorded loudly
		// rather than dropped: an observation that silently disappears is a
		// hole in a denominator an operator is reading as complete.
		shadowObservations.WithLabelValues(planeLabel(plane), dispositionRefused).Inc()
		log.Printf("[DECISION-SHADOW] component=%s refusing an observation: %s",
			logutil.Sanitize(o.component), logutil.Sanitize(defect))
		return
	}
	if !o.cfg.Observes(obs.Plane) {
		shadowObservations.WithLabelValues(plane, dispositionPlaneDisabled).Inc()
		return
	}
	if obs.Legacy.EvaluationError {
		// The plane could not evaluate at all - a policy-load failure, a
		// segment-resolution failure. That is an availability failure and not
		// a policy verdict, and comparing it against a PDP decision would
		// report a difference the migration did not cause. Counted, never
		// compared.
		shadowObservations.WithLabelValues(plane, dispositionEvaluationErr).Inc()
		return
	}
	if o.cfg.SampleRate < 1 && rand.Float64() >= o.cfg.SampleRate {
		shadowObservations.WithLabelValues(plane, dispositionSampledOut).Inc()
		return
	}

	obs.mode = mode
	obs.seq = o.seq.Add(1)
	select {
	case o.queue <- obs:
	default:
		// NEVER BLOCKS A REQUEST. A full queue means the pool cannot keep up,
		// which costs evidence and must never cost latency.
		o.dropped.Add(1)
		shadowObservations.WithLabelValues(plane, dispositionDropped).Inc()
	}
	shadowEnqueueLatency.WithLabelValues(plane, "true").Observe(time.Since(start).Seconds())
}

// NoteRefused counts an observation a CALL SITE could not even build, and logs
// why.
//
// It exists because a call site that returns before reaching Observe leaves no
// trace: no counter moves, and the only signal is a log line nobody greps.
// This package's whole claim is that "every hole in the denominator is counted
// and exported, not inferred", and a site that short-circuits ahead of
// Validate breaks it in the shape that is hardest to notice - the plane's
// series simply stops growing while the others look healthy.
//
// It is the same disposition Validate produces, deliberately: from an
// operator's view "the call site could not name its plane" and "the
// observation named a plane that cannot be" are one problem with one fix.
func NoteRefused(plane legacycompile.Plane, reason string) {
	shadowObservations.WithLabelValues(planeLabel(string(plane)), dispositionRefused).Inc()
	log.Printf("[DECISION-SHADOW] refusing an observation on plane %q: %s",
		logutil.Sanitize(string(plane)), logutil.Sanitize(reason))
}

// NoteRefusedFor is NoteRefused for a call site that knows its organization.
//
// IT EXISTS BECAUSE THE UNSCOPED FORM CONTAMINATES THE DENOMINATOR. Observe
// argues at length that an organization whose resolved mode does not record is
// not in the window at all and must not appear in these series - and then the
// two Note helpers incremented them unconditionally, from call sites reached
// BEFORE Observe. On a deployment with the process mode off, an org source
// wired and no organization opted in, every dynamic evaluation using
// modify_risk incremented `not_comparable` forever, for tenants that are not in
// the window, in the five counters presented as the window's denominator.
//
// The mode is resolved through the SAME effectiveMode call the rest of the
// package uses, so this is not a second consultation site and the census test
// still finds exactly one.
func NoteRefusedFor(ctx context.Context, orgID string, plane legacycompile.Plane, reason string) {
	if !ProcessObserver().participates(ctx, orgID) {
		return
	}
	NoteRefused(plane, reason)
}

// NotComparableCounter returns the not-comparable counter for one plane.
//
// It exists because NoteNotComparable's only effects are a counter and a log
// line, so a test asserting that a call site TOOK that branch has nothing else
// to read - and a branch nothing can observe is a branch a mutant survives.
//
// It hands back the COLLECTOR rather than a float so that
// prometheus/client_golang/prometheus/testutil stays out of the production
// binary: a caller that wants the value uses testutil in its own test file.
func NotComparableCounter(plane legacycompile.Plane) prometheus.Counter {
	return shadowObservations.WithLabelValues(planeLabel(string(plane)), dispositionNotComparable)
}

// RefusedCounter is NotComparableCounter for the `refused` disposition, and
// exists for the same reason: a call site that refuses has no effect a test can
// read except this counter, so a guard without it is a guard a mutant survives.
//
// The two are deliberately separate accessors rather than one taking a
// disposition string. A test that can pass any string can pass the WRONG one
// and still be green against a call site that counted the other - which is the
// exact confusion between "a defect in a call site" and "an ordinary
// incomparable pair" that emit's guard ORDER exists to keep apart.
func RefusedCounter(plane legacycompile.Plane) prometheus.Counter {
	return shadowObservations.WithLabelValues(planeLabel(string(plane)), dispositionRefused)
}

// NoteNotComparable counts an observation a call site knows cannot be compared,
// and logs why.
//
// Some pairs are uncomparable for a reason only the CALL SITE can see. The
// dynamic engine's modify_risk mutates a condition field mid-evaluation, so
// one evaluation can read one field at two values; a request carries one value
// per attribute, and whichever we sent, some row would be evaluated against a
// number the legacy engine never showed it. Classifying that would put a
// difference the harness manufactured into the numerator gate 18 is read from.
//
// It shares the disposition the worker uses for a stale policy set, which is
// the right grouping: both are "the two sides could not be asked the same
// question", and both are ordinary rather than defects.
func NoteNotComparable(plane legacycompile.Plane, reason string) {
	shadowObservations.WithLabelValues(planeLabel(string(plane)), dispositionNotComparable).Inc()
	log.Printf("[DECISION-SHADOW] plane=%s observation not comparable: %s",
		logutil.Sanitize(string(plane)), logutil.Sanitize(reason))
}

// NoteNotComparableFor is NoteNotComparable for a call site that knows its
// organization. See NoteRefusedFor for why the unscoped form is not enough.
func NoteNotComparableFor(ctx context.Context, orgID string, plane legacycompile.Plane, reason string) {
	if !ProcessObserver().participates(ctx, orgID) {
		return
	}
	NoteNotComparable(plane, reason)
}

// participates reports whether this organization is in the window, using the
// package's single mode-resolution site.
//
// It is the same two questions Observe asks before it counts anything: is the
// observer wired and could it observe at all, and does THIS organization's
// resolved mode record.
func (o *Observer) participates(ctx context.Context, orgID string) bool {
	if o == nil || !o.couldObserve.Load() {
		return false
	}
	return records(o.effectiveMode(ctx, orgID))
}

// planeLabel keeps an unattributed observation out of the per-plane series
// rather than inventing a plane for it.
func planeLabel(p string) string {
	if p == "" {
		return "unattributed"
	}
	return p
}

// work drains the queue. Every evaluation here happens AFTER the plane's
// response was decided.
func (o *Observer) work() {
	defer o.wg.Done()
	for {
		select {
		case <-o.stop:
			return
		case obs := <-o.queue:
			o.evaluate(obs)
		}
	}
}

// evaluate performs the ADR-065 half and classifies the pair.
//
// IT RECOVERS FROM A PANIC, AND THAT IS PART OF THE NON-ENFORCEMENT
// GUARANTEE RATHER THAN DEFENSIVE HABIT.
//
// Everything below runs on a worker goroutine: the legacy compiler, a Rego
// render, a bundle build-sign-verify, an OPA engine start, and an OPA
// evaluation - the last two inside a dependency this tree acquired in this
// same change. A panic in any of them, on a goroutine with no recovery, ends
// the PROCESS. The whole argument for turning this on is that a recorded-only
// observability feature cannot affect the request path, and a shadow that can
// crash the agent for every tenant falsifies that argument in the most direct
// way available - it is a claim about DECISIONS that says nothing about
// AVAILABILITY unless this exists.
//
// Every error return below is already treated as non-fatal and counted; the
// panic path was the one hole in that discipline. It is counted under its own
// disposition rather than folded into evaluate_failed, because "the shadow
// panicked" and "the shadow could not compile a bundle" send an operator to
// different places.
//
// The recovery is on evaluate rather than on work, so the WORKER survives and
// keeps draining: a pool that lost a goroutine per panic would degrade into
// dropped observations, which is a hole in a denominator rather than a visible
// failure.
func (o *Observer) evaluate(obs Observation) {
	plane := string(obs.Plane)
	started := time.Now()
	defer func() {
		if r := recover(); r != nil {
			shadowObservations.WithLabelValues(planeLabel(plane), dispositionPanicked).Inc()
			log.Printf("[DECISION-SHADOW] component=%s plane=%s PANIC recovered on the shadow worker; the request path is unaffected and this observation is lost: %v\n%s",
				logutil.Sanitize(o.component), logutil.Sanitize(plane), r, debug.Stack())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), observeTimeout)
	defer cancel()

	post := posture(obs.Posture)
	world, comp, err := o.worlds.worldFor(ctx, obs, post)
	if err != nil {
		var nc *ErrNotComparable
		if errors.As(err, &nc) {
			shadowObservations.WithLabelValues(plane, dispositionNotComparable).Inc()
			shadowBundleBuilds.WithLabelValues(plane, "not_comparable").Inc()
			return
		}
		shadowObservations.WithLabelValues(plane, dispositionEvaluateFailed).Inc()
		shadowBundleBuilds.WithLabelValues(plane, "error").Inc()
		log.Printf("[DECISION-SHADOW] component=%s plane=%s could not build an evaluation environment: %s",
			logutil.Sanitize(o.component), logutil.Sanitize(plane), logutil.Sanitize(err.Error()))
		return
	}
	shadowBundleBuilds.WithLabelValues(plane, "ok").Inc()

	c := caseFor(obs, caseID(obs.Plane, obs.Phase, obs.seq), comp.opts)
	req, err := c.Request(comp.report, world.BundleDigest)
	if err != nil {
		shadowObservations.WithLabelValues(plane, dispositionEvaluateFailed).Inc()
		log.Printf("[DECISION-SHADOW] component=%s plane=%s could not build a canonical request: %s",
			logutil.Sanitize(o.component), logutil.Sanitize(plane), logutil.Sanitize(err.Error()))
		return
	}
	dec, err := world.Engine.Decide(ctx, req)
	if err != nil {
		shadowObservations.WithLabelValues(plane, dispositionEvaluateFailed).Inc()
		log.Printf("[DECISION-SHADOW] component=%s plane=%s PDP evaluation failed: %s",
			logutil.Sanitize(o.component), logutil.Sanitize(plane), logutil.Sanitize(err.Error()))
		return
	}
	nv, err := shadow.FromDecision(dec)
	if err != nil {
		shadowObservations.WithLabelValues(plane, dispositionEvaluateFailed).Inc()
		return
	}
	lv := legacyVerdictFor(obs, comp.opts.ContentTarget)

	rec := shadow.Classify(shadow.ClassifyInput{
		Case: c, Legacy: lv, New: nv, Decision: dec, Report: comp.report,
	})
	shadowObservations.WithLabelValues(plane, dispositionCompared).Inc()
	shadowLatency.WithLabelValues(plane).Observe(time.Since(started).Seconds())

	o.recorder.RecordComparison(ctx, Comparison{
		Component:      o.component,
		Mode:           obs.mode,
		Plane:          obs.Plane,
		Phase:          obs.Phase,
		OrgID:          obs.OrgID,
		OrgScope:       obs.OrgScope,
		Tool:           obs.Action,
		SampleRate:     o.cfg.SampleRate,
		Record:         rec,
		BundleDigest:   world.BundleDigest,
		PolicySnapshot: obs.Snapshot(),
		// THE THREE RESET STAMPS (#3564 round 2). Read from package-level
		// values computed at init, never passed in: a caller that could choose
		// its own evaluator version could report a window as unbroken across
		// the change that broke it.
		EvaluatorVersion: evaluatorVersion,
		AdapterVersion:   adapterVersion,
		SiteVersion:      obs.SiteVersion,
	})
}

// Shutdown stops the workers and waits for in-flight evaluations.
//
// It drains what is already queued rather than discarding it: those
// observations are evidence, the process is going away anyway, and the bound
// is the workers' own timeout.
func (o *Observer) Shutdown(ctx context.Context) error {
	if o == nil {
		return nil
	}
	o.stopped.Do(func() { close(o.stop) })
	done := make(chan struct{})
	go func() { o.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- the process observer ---
//
// The observer is a process singleton because the mode is a deployment
// property. It is set once at boot and read on the evaluation path.

var (
	processMu       sync.RWMutex
	processObserver *Observer
)

// SetProcessObserver installs the process observer. Passing nil clears it,
// which is off.
func SetProcessObserver(o *Observer) {
	processMu.Lock()
	defer processMu.Unlock()
	processObserver = o
}

// ProcessObserver returns the installed observer, or nil.
func ProcessObserver() *Observer {
	processMu.RLock()
	defer processMu.RUnlock()
	return processObserver
}

// Enabled is the cheap gate the evaluators read before building an
// Observation. See Observer.couldObserve.
func Enabled() bool { return ProcessObserver().Enabled() }

// Observe runs the process observer. This is what every evaluator calls, and
// there is nothing it can do with the result, because there is no result.
func Observe(ctx context.Context, obs Observation) { ProcessObserver().Observe(ctx, obs) }
