package agent

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/decision/contract"
)

// POST /api/v1/access/evaluation is the AuthZEN-native authorization surface.
//
// # One route, both shapes
//
// The body is the AuthZEN ENVELOPE, which carries either a singular
// `evaluation` or a plural `evaluations`. AuthZEN's own API convention is two
// paths with two body shapes; AxonFlow's contract defines one envelope whose
// two members are mutually exclusive (contract/authzen.go), and the conformance
// cases AXC-013/014 are written against that envelope. Following the contract
// keeps one decoder, one schema definition and one generated type per SDK
// rather than two of each, and the exactly-one-member rule is enforced by the
// decoder, the JSON Schema and every generated client alike.
//
// A plural envelope yields ONE decision, not a list. Its entries are
// preconditions of a single operation, so they MEET: one denied entry denies
// the operation. Returning a list would invite a caller to act on the entry it
// liked.
//
// # Why this delegates rather than evaluates
//
// The handler builds a legacy DecideRequest per entry and runs it through
// handleDecide - the actual POST /api/v1/decide handler - rather than
// reimplementing the evaluation. handleDecide is ~2,000 lines of impersonation
// checks, circuit breaking, kill switches, PII handling, audit writes and
// metrics, and the release constraint is that this route answers with the SAME
// evaluation. Any reimplementation would be a second copy of that logic that
// drifts on the first change to either; delegating makes divergence structurally
// impossible rather than merely unlikely.
//
// The cost is one JSON encode/decode per entry across an in-process call. That
// is deliberate: correctness of the shared verdict is worth more than the
// allocation, and it keeps /api/v1/decide byte-stable because nothing about it
// changed.

// authzenHandlerPath is the route this handler is registered on. Its VALUE is
// owned by the contract - contract.AuthZENRoutePath, which the SDKs generate
// from (#3603) - and TestAuthZENHandlerPathIsTheContractsRoute fails the
// moment the two differ. It is spelled as a literal here rather than as
// `= contract.AuthZENRoutePath` because platform/shared/capability derives the
// served URL space by scanning route registrations and resolves only
// package-local constants; a cross-package constant is an UNRESOLVED site that
// would need a route_exemption, and an exemption for the surface's one route is
// worse than a guarded copy.
const authzenHandlerPath = "/api/v1/access/evaluation"

// authzenProfileHeader is how a Policy Enforcement Point negotiates the AxonFlow
// profile.
//
// AuthZEN 1.0's response is a bare boolean. What AxonFlow adds - the
// four-valued state, the obligations, the safe reason - rides in the response
// context and is returned ONLY to a caller that asked for it by version. It
// does NOT include an approval challenge - see the rendering site below and
// capabilities.go for why this adapter cannot produce one (#3631). This
// sentence promised it until then, which made it the third copy of a promise
// nothing kept.
//
// A PEP that did not negotiate cannot act on an obligation, and handing it a
// partial interpretation it will ignore is worse than handing it the boolean it
// understands.
//
// THE ONE THING NEGOTIATION CHANGES BESIDES THE SHAPE. An evaluation that would
// otherwise be ALLOW but carries a MANDATORY obligation is answered `false` to a
// caller that did not negotiate - see renderAuthZENOutcome. The obligation is a
// precondition of the permission and it rides in the context this caller does
// not receive, so `true` would hand out a permission whose condition the PEP
// never sees. Everything else about a bare caller is unchanged: an allow
// carrying no mandatory obligation is still `true`.
//
// ABSENT AND UNRECOGNISED ARE DIFFERENT ANSWERS, and the difference is the same
// fail-open class the adapter exists to prevent. A caller that sent NO header
// asked for AuthZEN 1.0 and gets exactly that: the boolean. A caller that sent
// `axonflow-authzen-profile-2099-01-01` asked for a rendering this build cannot
// produce, and answering it with a bare `{"decision":true}` tells it the
// negotiation succeeded. A PEP negotiating a later profile against an older
// server would then proceed on an allow whose mandatory obligation it never
// saw. So a non-empty profile this build does not emit is REFUSED, naming the
// version it does emit, which is a renegotiation the caller can act on.
const authzenProfileHeader = contract.AuthZENProfileHeader

// PlaneAccessEvaluation is the audit plane discriminator for this surface.
//
// It is its OWN plane rather than reusing PlaneDecision, even though the
// evaluation is shared, because the plane column answers "which surface did
// this decision come in through". Folding AuthZEN traffic into `decision` would
// make the adoption of this surface unmeasurable and would leave the v11
// cutover unable to tell which callers had migrated.
//
// WHAT THIS IS NOT: shadow instrumentation. The plane is written to the audit
// row and that is the whole of it. `legacycompile` has no runtime reachability
// yet and lane A (#3552) owns that work; this constant is the discriminator
// such a comparison would key on, not evidence that one is running.
const PlaneAccessEvaluation = "access_evaluation"

// authzenOutcomeObligationWithheld is the `outcome` label for an evaluation
// that policy allowed and this surface denied anyway, because the allow carried
// a mandatory obligation the caller had not negotiated the profile to receive.
//
// It is NOT `DENY`. A policy denial and an un-negotiated caller are different
// events with different fixes - one is the customer's policy working, the other
// is an integration sending no profile header - and an operator who cannot tell
// them apart will read the second as the first. It is not `refused` either:
// nothing was refused, an answer was returned, and it was the safe one.
const authzenOutcomeObligationWithheld = "obligation_withheld"

var (
	authzenRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_authzen_requests_total",
			Help: "Total POST /api/v1/access/evaluation requests by outcome, shape and caller origin",
		},
		// `outcome` is the operational state, `refused`, or
		// authzenOutcomeObligationWithheld; `shape` is singular or plural. Both
		// are closed enums - never caller text - so neither can blow up label
		// cardinality.
		[]string{"outcome", "shape", "origin"},
	)
	authzenRefusals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_authzen_refusals_total",
			Help: "Requests refused before evaluation, by structured refusal code",
		},
		// The refusal code is the closed contract enumeration. This series is
		// the adoption signal that matters: a spike in unevaluable_attribute is
		// callers asking for something the adapter cannot yet map, which is the
		// input to widening it.
		[]string{"code"},
	)
	authzenEntries = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "axonflow_authzen_envelope_entries",
			Help:    "Entries per envelope; the plural shape meets its entries into one decision",
			Buckets: []float64{1, 2, 3, 5, 8, 13, 21},
		},
	)
)

func init() {
	prometheus.MustRegister(authzenRequests, authzenRefusals, authzenEntries)
}

// RegisterAuthZENHandlers registers the AuthZEN surface.
func RegisterAuthZENHandlers(r *mux.Router) {
	r.Handle(authzenHandlerPath, apiAuthMiddleware(http.HandlerFunc(handleAuthZENEvaluation))).Methods("POST", "OPTIONS")
	log.Printf("✅ AuthZEN endpoint registered: POST %s", authzenHandlerPath)
}

// decisionPlaneCtxKey carries the audit plane a delegated evaluation should
// record itself under.
type decisionPlaneCtxKeyType struct{}

var decisionPlaneCtxKey = decisionPlaneCtxKeyType{}

// withDecisionPlane marks a request as arriving through a named surface.
func withDecisionPlane(ctx context.Context, plane string) context.Context {
	if plane == "" {
		return ctx
	}
	return context.WithValue(ctx, decisionPlaneCtxKey, plane)
}

// decisionPlaneFromContext returns the surface a decision arrived through,
// defaulting to the Decision API's own plane.
//
// The DEFAULT is what keeps /api/v1/decide byte-stable: a request that set no
// override is a direct call, and its audit row is exactly what it was before
// this route existed.
func decisionPlaneFromContext(ctx context.Context) string {
	plane := PlaneDecision
	if v, ok := ctx.Value(decisionPlaneCtxKey).(string); ok && v != "" {
		plane = v
	}
	if decisionPlaneObserver != nil {
		decisionPlaneObserver(plane)
	}
	return plane
}

// decisionPlaneObserver is a test seam.
//
// The plane's real effect is a column in an audit row, which an in-process test
// with a mocked database cannot read. Without a seam the only proof the plane is
// threaded would be a live stack, and a check that only runs against a live
// stack is a check that does not run on most commits.
var decisionPlaneObserver func(string)

// captureWriter is an http.ResponseWriter that records what a handler wrote.
//
// It exists so the delegated handleDecide call can be read rather than sent. It
// is a production type rather than httptest.ResponseRecorder because httptest
// is a testing package and importing it into a serving path drags test-only
// behaviour into the binary.
type captureWriter struct {
	status      int
	wroteHeader bool
	header      http.Header
	body        bytes.Buffer
}

func newCaptureWriter() *captureWriter {
	return &captureWriter{status: http.StatusOK, header: http.Header{}}
}

func (c *captureWriter) Header() http.Header { return c.header }

func (c *captureWriter) Write(p []byte) (int, error) { return c.body.Write(p) }

// WriteHeader records the FIRST status, matching net/http: a second call to a
// real ResponseWriter is ignored with a "superfluous WriteHeader" warning. A
// last-wins capture would report a status the delegated handler could not
// actually have sent, and the adapter branches on that status.
func (c *captureWriter) WriteHeader(status int) {
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true
	c.status = status
}

// handleAuthZENEvaluation is the route.
func handleAuthZENEvaluation(w http.ResponseWriter, r *http.Request) {
	// Defence in depth, for the same reason handleDecide carries it: the route
	// is registered with OPTIONS so a preflight does not 404, and a policy
	// evaluation must never be reachable by anything but an authenticated POST.
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	negotiated := contract.AuthZENProfile(r.Header.Get(authzenProfileHeader))
	origin := classifyDecisionOrigin(r.Header.Get("X-Axonflow-Client"), "")

	// A profile the caller NAMED and this build does not emit is refused before
	// anything is evaluated. 406 rather than 422: nothing about the envelope is
	// wrong, the caller asked for a representation this build cannot produce,
	// and the fix is a different header rather than a different body.
	if negotiated != "" && negotiated != contract.AuthZENProfileV1 {
		writeAuthZENError(w, http.StatusNotAcceptable, &contract.AuthZENError{
			Code: contract.ErrUnevaluableAttribute,
			Message: fmt.Sprintf(
				"the %s header names %q, which this build does not emit; answering with the bare boolean would "+
					"report that the negotiation succeeded, and a decision carrying a mandatory obligation would "+
					"reach an enforcement point that never saw it",
				authzenProfileHeader, negotiated),
			Supported: []string{string(contract.AuthZENProfileV1)},
		}, origin)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAuthZENBodyBytes))
	if err != nil {
		writeAuthZENError(w, http.StatusRequestEntityTooLarge, &contract.AuthZENError{
			Code:    contract.ErrMalformedEnvelope,
			Message: "the request body could not be read or exceeded the maximum size",
		}, origin)
		return
	}

	env, decErr := contract.DecodeAuthZENEnvelope(body)
	if decErr != nil {
		writeAuthZENError(w, http.StatusBadRequest, &contract.AuthZENError{
			Code:    contract.ErrMalformedEnvelope,
			Message: decErr.Error(),
		}, origin)
		return
	}

	shape := "singular"
	if env.Evaluations != nil {
		shape = "plural"
	}

	// THE ENTRY CAP, and why it exists when the body is already bounded: the
	// 1 MiB body cap's own rationale says an unbounded list is an unbounded
	// number of policy evaluations from one request - and then bounds BYTES,
	// not entries. mergeEntry fills subject, action, resource and context from
	// the shared base, so `{}` is a fully valid entry; ~350,000 of them fit in
	// 1 MiB, each running the complete decide path plus an audit-log INSERT,
	// serially, on one request that edge rate limiting cannot see inside. The
	// bulk envelope's own documented semantics bound legitimate use: the
	// entries are PRECONDITIONS OF A SINGLE OPERATION, which is a handful, not
	// a batch API. 64 is far beyond any real operation's precondition count
	// while capping the amplification at 64x instead of ~350,000x.
	//
	// Refused BEFORE mapping, so an over-cap envelope costs one length check.
	// 413 with a typed refusal, matching the body-size path above: the caller
	// sent too much, and the pointer names the member to shrink. The JSON
	// Schema deliberately does NOT gain maxItems in this change - the schema
	// and its generated artifact are vendored byte-identically in five SDKs,
	// so narrowing the published contract rides the next surface-sync train
	// rather than a tag-week hotfix; the server refusing above the cap is the
	// security property, and it does not need the schema's agreement.
	if env.Evaluations != nil && len(env.Evaluations.Evaluations) > maxAuthZENBulkEntries {
		writeAuthZENError(w, http.StatusRequestEntityTooLarge, &contract.AuthZENError{
			Code:    contract.ErrMalformedEnvelope,
			Pointer: "/evaluations",
			Message: fmt.Sprintf("the plural envelope carries %d entries; this surface evaluates at most %d per request - the entries of a bulk envelope are the preconditions of a single operation, not a batch", len(env.Evaluations.Evaluations), maxAuthZENBulkEntries),
		}, origin)
		return
	}

	// #3704: resolve the handshake ONCE for this HTTP request, before the entry
	// loop, and thread it through delegateToDecide's inner requests. A plural
	// envelope delegates to handleDecide once per entry - up to 64 - and
	// resolving there would make the adoption counter a function of the entry
	// count the CALLER chose. See resolveAndRecordPEPHandshakeOnce.
	//
	// The refusal itself still travels the ordinary delegated path: the first
	// entry answers 4xx, the loop below stops, and this surface renders it
	// through the one branch it renders every delegated 4xx through. Refusing
	// here instead would be a SECOND validation site for the same input.
	handshakeCtx, _ := resolveAndRecordPEPHandshakeOnce(
		r.Context(), r, ClientIDFromContext(r.Context()), PlaneAccessEvaluation)
	r = r.WithContext(handshakeCtx)

	mapped, mapErr := mapEnvelope(env)
	if mapErr != nil {
		// A construct the adapter cannot evaluate is refused BEFORE anything is
		// evaluated, so no audit row claims a decision was made about it. 422
		// rather than 400: the envelope was well-formed, it just described
		// something this surface cannot answer.
		writeAuthZENError(w, http.StatusUnprocessableEntity, mapErr, origin)
		return
	}
	authzenEntries.Observe(float64(len(mapped)))

	states := make([]contract.OperationalState, 0, len(mapped))
	// decisionIDs is kept per entry so the response can name the entry that
	// DETERMINED the outcome. Returning the last entry's id made a denial
	// caused by entry 0 point at an entry that allowed, which is the one id an
	// operator would look up to explain the denial.
	decisionIDs := make([]string, 0, len(mapped))
	var obligations []contract.Obligation
	for _, m := range mapped {
		// A cancelled request context means the caller is gone. Without this
		// check the loop finishes every remaining entry - full evaluations and
		// audit INSERTs - for a response nobody will read, and the server has
		// no Read/WriteTimeout to stop it either. Stop at the boundary between
		// entries; the write below is a best-effort courtesy to a caller that
		// is usually no longer there.
		if ctxErr := r.Context().Err(); ctxErr != nil {
			// The refusal below rides the same evaluation_unavailable code and
			// metric series as an evaluator outage - the closed error enum
			// forces the wire code, and nobody reads the body of a cancelled
			// request anyway. This log line is what tells the two apart: an
			// operator whose evaluation_unavailable alert is firing should
			// grep for it before concluding the evaluator is down. A spike
			// here with a healthy evaluator is mass client disconnects or
			// too-short client timeouts, not an outage.
			log.Printf("[authzen] caller gone before every entry evaluated (%d of %d done): %v",
				len(states), len(mapped), ctxErr)
			writeAuthZENError(w, http.StatusBadGateway, &contract.AuthZENError{
				Code:    contract.ErrEvaluationUnavailable,
				Message: "the request context was cancelled before every entry was evaluated: " + ctxErr.Error(),
			}, origin)
			return
		}
		resp, status, err := delegateToDecide(r, m.request)
		if err != nil {
			writeAuthZENError(w, http.StatusBadGateway, &contract.AuthZENError{
				Code:    contract.ErrEvaluationUnavailable,
				Pointer: m.pointer,
				Message: err.Error(),
			}, origin)
			return
		}
		// A non-OK status from the evaluator is a refusal or an outage, not a
		// verdict. Reporting it as decision=false would make "denied" and
		// "could not evaluate" the same event for every caller and every audit.
		if status != http.StatusOK {
			code := contract.ErrEvaluationUnavailable
			httpStatus := http.StatusBadGateway
			if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
				code = contract.ErrIncompleteEvaluation
				httpStatus = status
			}
			writeAuthZENError(w, httpStatus, &contract.AuthZENError{
				Code:      code,
				Pointer:   m.pointer,
				Message:   resp.errorMessage(),
				RequestID: resp.DecisionID,
			}, origin)
			return
		}
		states = append(states, authzenStateFor(resp.Verdict))
		decisionIDs = append(decisionIDs, resp.DecisionID)
		mappedObligations, obErr := mapObligations(resp.Obligations)
		if obErr != nil {
			writeAuthZENError(w, http.StatusBadGateway, &contract.AuthZENError{
				Code:      contract.ErrEvaluationUnavailable,
				Pointer:   m.pointer,
				Message:   obErr.Error(),
				RequestID: resp.DecisionID,
			}, origin)
			return
		}
		obligations = append(obligations, mappedObligations...)
	}

	state, err := meetStates(states)
	if err != nil {
		writeAuthZENError(w, http.StatusInternalServerError, &contract.AuthZENError{
			Code:    contract.ErrEvaluationUnavailable,
			Message: err.Error(),
		}, origin)
		return
	}

	rendered := renderAuthZENOutcome(state, negotiated, obligations)

	out := contract.AuthZENResponse{Decision: rendered.decision}
	if negotiated == contract.AuthZENProfileV1 {
		// ONE producer, shared with Decision.ToAuthZEN. This used to be a
		// second struct literal, and the two had already drifted on exactly one
		// member - `Approval`, which this site never set - while the capability
		// entry and the OpenAPI document both advertised it. Building the
		// context here again would reintroduce the drift surface on the next
		// member added to the profile, so the rendering is a call rather than a
		// literal, and contract.AuthZENContextInput is what a new member has to
		// pass through.
		//
		// The obligation gate moved INTO the producer with it. It was stated
		// here as `state == contract.StateAllow`, narrower than the contract's
		// own rule: a CHALLENGE is a permit with an approval outstanding and may
		// carry obligations, and a plural envelope reaches that combination
		// because obligations accumulate across entries while the meet takes the
		// worst state. See contract.OperationalState.CarriesObligations.
		//
		// APPROVAL IS PASSED AS nil, DELIBERATELY, AND THE ADVERTISEMENTS NOW
		// SAY SO (#3631). This route is an adapter over POST /api/v1/decide, and
		// DecideResponse carries no approval requirement: a needs_approval
		// verdict raises a HITL queue entry, but nothing in the response names
		// the eligible groups, the quorum or the challenge expiry that
		// contract.ApprovalRequirement.Validate requires. Populating it would
		// mean INVENTING an approval policy - a fabricated quorum over a
		// fabricated eligible set - which is worse than the omission, because a
		// PEP would enforce it. Surfacing the real requirement needs the
		// evaluator to carry it on /api/v1/decide, which is a wire change to the
		// route this surface exists not to change; it is out of this fix's class
		// and is recorded as such rather than half-done here. The nil is
		// explicit rather than an omitted struct member so it is a decision on
		// the page instead of an absence nobody can see.
		reason := authzenReasonFor(state)
		out.Context = contract.NewAuthZENResponseContext(contract.AuthZENContextInput{
			State:         state,
			Reason:        reason,
			Obligations:   obligations,
			Approval:      nil,
			DecisionID:    determiningDecisionID(states, decisionIDs, state),
			SchemaVersion: contract.SchemaVersion,
		})
	}

	if rendered.withheld {
		// Logged as well as counted: the counter says how many, and this says
		// which caller to go and fix. No caller content is logged - `origin` is
		// a closed classification and the decision id is an opaque handle.
		log.Printf("⚠️ [AuthZEN] denying an otherwise-allowed evaluation: it carries a mandatory obligation "+
			"and the caller did not negotiate %s, so the obligation cannot be delivered (origin=%s, shape=%s, decision_id=%s)",
			contract.AuthZENProfileV1, origin, shape, determiningDecisionID(states, decisionIDs, state))
		// And the DURABLE record, which is the half a counter cannot supply:
		// the audit row for this request was written by the delegated evaluator
		// before the withholding rule existed, and it says `allowed`.
		amendAuditForWithheldObligation(r.Context(), usageDB, decisionIDs)
	}
	authzenRequests.WithLabelValues(rendered.outcome, shape, origin).Inc()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

// authzenRendering is what the wire response and the metric are built from.
//
// The two travel together because they must agree: a response that says false
// and a counter that says ALLOW describe the same request differently, and only
// one of them is right.
type authzenRendering struct {
	// decision is the AuthZEN 1.0 boolean.
	decision bool
	// outcome is the `outcome` metric label.
	outcome string
	// withheld records that the deny came from an undeliverable mandatory
	// obligation rather than from policy, so the handler can log it.
	withheld bool
}

// renderAuthZENOutcome collapses the evaluated state, the negotiated profile
// and the obligation set into the boolean and the label.
//
// # AN ALLOW WHOSE MANDATORY OBLIGATIONS THE CALLER CANNOT RECEIVE IS A DENY
//
// The obligations ride in the response CONTEXT, which is emitted only to a
// caller that negotiated the profile. For anything ADVISORY that gate is right:
// a bare AuthZEN 1.0 PEP cannot act on it, and a partial interpretation it will
// ignore is worse than the boolean it understands. For a MANDATORY obligation
// it was a fail-open, and a reachable one - a request carrying PII that policy
// otherwise allows arrives here as StateAllow with a mandatory field_redact
// attached, and a caller that sent no profile header received
// `{"decision":true}` and proceeded with the content unredacted, believing it
// had been permitted to.
//
// ADR-065 invariant 8 prescribes DENY for a mandatory obligation the PEP cannot
// enforce, and a PEP that cannot RECEIVE it is the limiting case of one that
// cannot enforce it. Invariant 12 says implement the complete profile or
// refuse; this refuses.
//
// # WHY DENY RATHER THAN A TYPED REFUSAL WITH A NEW ERROR CODE
//
// A new AuthZENErrorCode was the other candidate and was rejected. The refusal
// codes are a closed enumeration published in surface/authzen-surface.json, so
// adding one forces a regeneration of that artifact and of the generated wire
// types in all five SDKs - for a case none of our own SDKs can ever hit, since
// every one of them sends the profile header on every request. Deny needs none
// of that: it is expressible in bare AuthZEN 1.0, it is an answer a caller that
// negotiated nothing is already able to read, and it is fail-closed.
//
// # WHY THE PREDICATE IS ON Mandatory RATHER THAN ON len(obligations) > 0
//
// Today those are observationally identical on this surface, because
// mapObligations stamps Mandatory on everything it emits (the legacy contract
// has no advisory obligations, and an instruction whose enforceability is
// unknown is not advisory). Enforceability is nevertheless the property that
// decides the answer, and the emission side is the half expected to change.
// Keying on presence would, on the day an advisory obligation is first emitted,
// deny an operation a bare PEP was entitled to perform.
//
// # WHERE THE STATE TERM LIVES
//
// It is NOT restated here. contract.MandatoryObligationWithheld takes the state
// and applies the whole rule, so this function and Decision.ToAuthZEN - the two
// sites that render a decision onto this wire - pass their inputs to one
// predicate and neither spells out a term of its own. An earlier revision
// guarded `state == contract.StateAllow` at this call site while ToAuthZEN
// applied the predicate with no state term, which is precisely the two-copies-
// that-drift shape the shared predicate exists to prevent; they agreed only
// because Executable() is `s == StateAllow` today.
//
// This is a FUNCTION rather than four lines in the handler because the states
// other than ALLOW cannot be produced with an obligation set through the HTTP
// path in-process: the legacy evaluator attaches its redact obligation only to
// a VerdictAllow. A rule that can only be exercised on one of its four inputs
// is a rule whose other three are asserted by nobody, so it is separated from
// its call site and swept over the whole product. The call site is pinned by
// the handler tests, which is the other half - the two are not
// interchangeable.
func renderAuthZENOutcome(
	state contract.OperationalState,
	negotiated contract.AuthZENProfile,
	obligations []contract.Obligation,
) authzenRendering {
	withheld := contract.MandatoryObligationWithheld(state, negotiated, obligations)

	out := authzenRendering{
		decision: state.Executable() && !withheld,
		outcome:  string(state),
		withheld: withheld,
	}
	if withheld {
		// The withheld-obligation deny gets its OWN outcome value rather than
		// reporting as DENY. It reuses the existing `outcome` label - a closed
		// enum that already carries a non-state value in `refused` - so no new
		// metric is registered for it.
		out.outcome = authzenOutcomeObligationWithheld
	}
	return out
}

// Reason labels for decideAuditWriteFailures raised by the amendment below.
//
// They are distinct values on the EXISTING series rather than a new metric, for
// the same reason authzenOutcomeObligationWithheld is: the failure being
// reported - "the durable record of this decision does not say what happened" -
// is exactly what that series already means, and an operator alerting on a
// degraded audit trail should not have to know this route exists.
const (
	// authzenAuditAmendFailed is the UPDATE itself erroring.
	authzenAuditAmendFailed = "authzen_withheld_amend"
	// authzenAuditAmendNoRow is the UPDATE succeeding and matching nothing,
	// which is the SILENT half: the row was never inserted (the insert is
	// best-effort and a CHECK violation drops it), or its plane or decision id
	// is not what this surface believes it wrote. Either way the durable record
	// still reads `allowed` for a request answered false, so it is counted
	// rather than assumed impossible.
	authzenAuditAmendNoRow = "authzen_withheld_amend_norow"
)

// amendAuditForWithheldObligation makes the audit row say what the caller was
// actually told.
//
// # Why an amendment and not a fresh row
//
// The audit row for this request is written INSIDE the delegated evaluation
// (recordDecideDecision -> writeDecisionAuditLog, synchronously, before
// handleDecide returns), and the withholding rule cannot run there: it needs the
// negotiated profile AND the meet across every entry of the envelope, neither of
// which exists until every delegation has returned. So the row is already on
// disk, keyed `decide_<decision_id>`, reading policy_decision=`allowed`, by the
// time this surface decides to answer `{"decision":false}`.
//
// Leaving it is the more serious half of the fail-open this file closes. The
// counter can distinguish a withheld-obligation deny from an allow; the durable
// record could not, so a compliance reader querying "what did this platform
// permit" would count a request that was refused, and a customer asked to
// explain a blocked integration would find a row saying it succeeded.
//
// Writing a SECOND row was the other candidate and was rejected: the id is
// derived from the decision id (`decide_<id>`, one row per decision, by
// construction), so a second row is either a primary-key collision or a
// deliberate duplicate that every existing reader - the decisions feed, the
// explain endpoint, every compliance export - would count twice.
//
// # What it preserves
//
// The evaluator's own verdict is not erased, it is MOVED:
// policy_details.authzen_evaluated_policy_decision keeps what the policy engine
// concluded, and authzen_obligation_withheld records why the answer differs. So
// the row states both facts an auditor needs - policy permitted this, and the
// platform refused it anyway because the caller could not receive the
// precondition - and the obligations column continues to name the precondition
// in question. The signed decision_chain entry is deliberately NOT amended: it
// is the non-repudiation record of the EVALUATION, which genuinely was a permit,
// and it stays byte-identical to what was signed.
//
// Best-effort, exactly like the write it amends: a database failure here never
// changes the answer the caller already holds, which was decided and is denied
// either way. It is not silent, though - every no-amend branch increments
// decideAuditWriteFailures.
func amendAuditForWithheldObligation(ctx context.Context, db *sql.DB, decisionIDs []string) {
	if db == nil {
		// No usage DB is wired, so no row was inserted to amend. The delegated
		// writer already counted `nodb` for this same request; counting it a
		// second time here would double-report one deployment posture.
		return
	}
	ids := make([]string, 0, len(decisionIDs))
	for _, id := range decisionIDs {
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		decideAuditWriteFailures.WithLabelValues(authzenAuditAmendNoRow).Inc()
		return
	}

	// EVERY entry's row is amended, not just the determining one. The
	// withholding rule fires only when the met state is executable, and the meet
	// takes the worst state, so every entry of this envelope allowed - which
	// means every one of their rows reads `allowed` for an operation that did
	// not happen.
	//
	// policy_decision on the right-hand side of SET reads the OLD row value, so
	// the evaluator's verdict is captured before it is overwritten. The plane
	// term keeps the statement from reaching a row this surface did not write,
	// even if a decision id were ever reused on another plane.
	res, err := db.ExecContext(ctx, `
		UPDATE audit_logs
		   SET policy_decision = $1,
		       policy_details = jsonb_set(
		           jsonb_set(
		               COALESCE(policy_details, '{}'::jsonb),
		               '{authzen_evaluated_policy_decision}', to_jsonb(policy_decision), true),
		           '{authzen_obligation_withheld}', 'true'::jsonb, true)
		 WHERE decision_id = ANY($2)
		   AND plane = $3
	`, AuditVerdictBlocked, pq.Array(ids), PlaneAccessEvaluation)
	if err != nil {
		decideAuditWriteFailures.WithLabelValues(authzenAuditAmendFailed).Inc()
		log.Printf("⚠️ [AuthZEN] audit amendment failed (non-fatal): the durable record still reads %q "+
			"for a request answered decision:false: %v", AuditVerdictAllowed, err)
		return
	}
	// A driver may not support RowsAffected; that is not a failure, and treating
	// it as one would make this counter fire on every request under such a
	// driver. Only a definite zero is reported.
	if n, rErr := res.RowsAffected(); rErr == nil && n == 0 {
		decideAuditWriteFailures.WithLabelValues(authzenAuditAmendNoRow).Inc()
		log.Printf("⚠️ [AuthZEN] audit amendment matched no row on plane=%s (non-fatal): the withheld-obligation "+
			"deny has no durable record; the delegated insert is best-effort, so grep for 'audit log insert failed'",
			PlaneAccessEvaluation)
	}
}

// determiningDecisionID returns the id of the entry that produced the combined
// outcome.
//
// A meet is decided by ONE entry, and that is the entry an operator needs when
// they ask why the operation was refused. Returning the last entry's id instead
// pointed a denial at an entry that allowed - an id that explains nothing, on
// the one path where an explanation is wanted. The FIRST matching entry is
// chosen so the answer is stable rather than dependent on evaluation order.
func determiningDecisionID(states []contract.OperationalState, ids []string, effective contract.OperationalState) string {
	for i, s := range states {
		if s == effective && i < len(ids) {
			return ids[i]
		}
	}
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// maxAuthZENBodyBytes bounds the envelope. A plural envelope is a list, and an
// unbounded list is an unbounded number of policy evaluations from one request.
const maxAuthZENBodyBytes = 1 << 20 // 1 MiB

// maxAuthZENBulkEntries bounds the ENTRY COUNT of a plural envelope - the axis
// the body cap above cannot see. See the refusal site for the full rationale.
const maxAuthZENBulkEntries = 64

// decideOutcome is the part of the legacy response this adapter reads.
type decideOutcome struct {
	DecideResponse
	Error string `json:"error"`
}

func (d decideOutcome) errorMessage() string {
	if d.Error != "" {
		return d.Error
	}
	return "the evaluator did not return a verdict"
}

// delegateToDecide runs one mapped request through the real Decision API
// handler and reads back what it wrote.
//
// The synthetic request carries the ORIGINAL request's context, which is where
// apiAuthMiddleware has already stamped the authenticated tenant, org and
// client. Rebuilding the identity here instead would be a second
// implementation of authentication, and the two would eventually disagree about
// who the caller is.
func delegateToDecide(r *http.Request, req DecideRequest) (decideOutcome, int, error) {
	var out decideOutcome
	encoded, err := json.Marshal(req)
	if err != nil {
		return out, 0, err
	}
	// The delegated evaluation records itself under THIS surface's plane, not
	// the Decision API's, so adoption of the AuthZEN route is measurable.
	inner, err := http.NewRequestWithContext(
		withDecisionPlane(r.Context(), PlaneAccessEvaluation),
		http.MethodPost, decisionHandlerPath, bytes.NewReader(encoded))
	if err != nil {
		return out, 0, err
	}
	inner.Header.Set("Content-Type", "application/json")
	// Headers the evaluator reads for attribution, correlation and telemetry are
	// forwarded verbatim. They are copied by NAME rather than wholesale: copying
	// every header would forward Authorization into a handler that has already
	// been authenticated through the context, and would let a header this
	// adapter has never considered change the evaluation.
	//
	// THE COPY LIST IS A SECOND PLACE THE CONTRACT LIVES, and a header omitted
	// from it is not "not forwarded" - it is SILENTLY STRIPPED, so the
	// evaluator sees the absent case and takes the unchanged path. #3704's
	// capability handshake is on the list for exactly that reason: without it a
	// caller presenting a perfectly valid declaration on this surface would
	// have every capability refusal, every identity binding and every
	// over-advertising check go inert, with no error and no counter. A leg of
	// the runtime-e2e asserts the REFUSAL on this plane rather than the allow,
	// because the allow is what a stripped header also produces.
	for _, h := range []string{
		"X-Axonflow-Client", "traceparent",
		contract.PEPHandshakeHeader,
		identityHeaderUserEmail, identityHeaderSessionID,
	} {
		// Values, not Get, for the handshake's sake: a repeated header must
		// reach the evaluator AS a repeat so it is refused there, rather than
		// being silently collapsed to its first value on the way through.
		//
		// AND THE EMPTINESS FILTER IS EXEMPTED FOR THE HANDSHAKE, which the
		// first version of this loop got wrong. `v != ""` is right for the other
		// four headers, where an empty value means "nothing to attribute" and
		// forwarding it is noise. For the handshake it is a DEFECT: a
		// present-but-empty declaration would be dropped here, the evaluator
		// would see the ABSENT case, and the request would take the unchanged
		// path with no refusal and no counter - the exact degrade-to-legacy this
		// change exists to close, reintroduced one frame above the resolver that
		// refuses it. Worse, `["", <valid>]` would collapse a REPEAT into a
		// single accepted declaration, defeating the Values/Add rewrite's own
		// purpose.
		//
		// So an empty handshake line is forwarded and refused downstream, where
		// the refusal names the header.
		for _, v := range r.Header.Values(h) {
			if v == "" && h != contract.PEPHandshakeHeader {
				continue
			}
			inner.Header.Add(h, v)
		}
	}

	cw := newCaptureWriter()
	handleDecide(cw, inner)

	if cw.body.Len() == 0 {
		return out, cw.status, nil
	}
	if err := json.Unmarshal(cw.body.Bytes(), &out); err != nil {
		return out, cw.status, err
	}
	return out, cw.status, nil
}

// authzenRedactionTarget is the field path a legacy redact_pii obligation acts
// on, expressed in the contract's attribute-path vocabulary.
//
// The legacy obligation redacts the content the caller asked about, which on
// this surface arrives as context.args.query -- so `args.query` is not a
// placeholder, it is the actual leaf. A disclosure transform REQUIRES a target
// (contract.Obligation.Validate), and an empty one would be rejected by the
// contract's own validator.
const authzenRedactionTarget = "args.query"

// legacyObligationType maps each obligation the Decision API can emit onto the
// contract's typed equivalent.
//
// It is a closed table, and an absent key is an ERROR rather than a default.
// Defaulting is the tempting shortcut here and it is wrong twice over: mapping
// an unrecognised instruction onto field_redact would tell a PEP to redact when
// the policy asked for something else, and DROPPING it would hand the caller an
// allow whose conditions it never saw. Both misrepresent the decision.
var legacyObligationType = map[string]contract.ObligationType{
	ObligationRedactPII: contract.ObFieldRedact,
}

// mapObligations translates the legacy obligations onto the contract's typed
// obligation.
//
// THE FULFILLMENT BLOCK IS CARRIED, NOT DROPPED. A legacy redact_pii obligation
// is not "redact this yourself": ADR-056 forbids client-side redaction, and the
// Fulfillment block names the endpoint, method and phase a PEP calls to obtain
// engine-redacted content. Emitting `field_redact, mandatory` without it would
// tell the caller it MUST redact while removing the only sanctioned way to do
// so -- and the contract's rule for a mandatory obligation that cannot be
// discharged is to deny. So the block rides in Params, and an obligation that
// arrives WITHOUT one is refused rather than rendered undischargeable.
//
// Every obligation is run through the contract's own Validate before it is
// returned. That check is what makes the two rules above enforced rather than
// merely intended: the first version of this function emitted a disclosure
// transform with no target, which Validate rejects, and nothing noticed because
// nothing called it.
func mapObligations(in []DecisionObligation) ([]contract.Obligation, error) {
	out := make([]contract.Obligation, 0, len(in))
	for _, o := range in {
		typ, ok := legacyObligationType[o.Type]
		if !ok {
			return nil, fmt.Errorf(
				"the evaluator attached the obligation %q, which this surface has no typed equivalent for; "+
					"rendering the decision would either misstate the instruction or omit it", o.Type)
		}
		if o.Fulfillment == nil {
			return nil, fmt.Errorf(
				"the evaluator attached %q with no fulfillment block; a mandatory obligation "+
					"the caller cannot discharge must not be rendered as one it can", o.Type)
		}
		params := map[string]string{
			// The names a PEP needs to discharge it. They mirror
			// ObligationFulfillment field-for-field so the legacy contract stays
			// the single source of the endpoint.
			"fulfillment_endpoint": o.Fulfillment.Endpoint,
			"fulfillment_method":   o.Fulfillment.Method,
			"fulfillment_phase":    o.Fulfillment.Phase,
		}
		if len(o.Fulfillment.ContentTypes) > 0 {
			// Advertised so a PEP holding content of a type the endpoint cannot
			// redact fails closed rather than forwarding it unredacted.
			params["fulfillment_content_types"] = strings.Join(o.Fulfillment.ContentTypes, ",")
		}
		if o.Detail != "" {
			params["detail"] = o.Detail
		}
		ob := contract.Obligation{
			Type:   typ,
			Target: authzenRedactionTarget,
			Params: params,
			// Mandatory: the legacy contract has no advisory obligations, and an
			// instruction whose enforceability is unknown is not advisory.
			Mandatory:     true,
			SourcePolicy:  "legacy:" + o.Type,
			SchemaVersion: 1,
		}
		if err := ob.Validate(); err != nil {
			return nil, fmt.Errorf("the obligation this surface would emit is not valid under the contract: %w", err)
		}
		out = append(out, ob)
	}
	return out, nil
}

// writeAuthZENError emits the structured refusal.
//
// It does NOT depend on profile negotiation. The refusal shape is the route's
// error contract, published for every caller in the OpenAPI document, not part
// of the versioned profile payload - so gating it would leave an un-negotiated
// caller with a status code and no reason. Only the DECISION context is gated.
func writeAuthZENError(w http.ResponseWriter, status int, e *contract.AuthZENError, origin string) {
	if err := e.Validate(); err != nil {
		// A refusal that is not itself well formed would leave the caller with
		// no code to branch on, so it is replaced rather than sent.
		e = &contract.AuthZENError{
			Code:    contract.ErrEvaluationUnavailable,
			Message: "the request could not be evaluated",
		}
	}
	authzenRefusals.WithLabelValues(string(e.Code)).Inc()
	authzenRequests.WithLabelValues("refused", "unknown", origin).Inc()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}
