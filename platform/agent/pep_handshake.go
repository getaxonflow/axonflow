package agent

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/deploymode"
	logutil "axonflow/platform/shared/logger"
)

// The ADR-065 PEP capability handshake, server side (#3704).
//
// An EXTERNAL enforcement point - an SDK client, a plugin, a gateway adapter -
// presents contract.PEPHandshakeHeader on a governed call to say what it is and
// which obligations it can discharge. Before this existed the only thing such a
// caller could say about itself was X-Axonflow-Client, which carries a library
// name and no capabilities, so every external enforcement point was
// CapabilityNoRecord for ever and the only reason nothing refused was that
// nothing asked.
//
// # NOTHING CHANGES BY DEFAULT, AND WHAT THAT DOES NOT MEAN
//
// A request with NO handshake header takes byte-for-byte the path it took
// before this file existed. That is the whole compatibility claim and it is
// pinned by a frozen fixture.
//
// It does NOT mean a handshake that fails to parse is treated as absent.
// Degrading a malformed declaration to "legacy caller" would be the silent
// allow-all this file exists to prevent: a client whose handshake broke in
// transit, or in a serializer, would go on being handed obligations it had just
// told the platform it cannot discharge, and nothing would say so. A present
// header either produces a validated enforcement point or refuses the request.
//
// # WHERE IT RUNS, AND WHY THAT IS BEFORE THE BODY
//
// resolvePEPHandshake runs UNCONDITIONALLY, immediately after the authenticated
// identity is captured and BEFORE the request body is decoded. Three reasons,
// and the first two are defects avoided rather than preferences:
//
//   - The community-mode branch. handleDecide's caller_identity impersonation
//     checks sit inside an `else`, skipped when isCommunityMode() and the
//     client identity is the shared community principal. Placing the handshake
//     check "beside" them would make it unreachable in community mode - which
//     is the one deployment class where the over-advertising rule can fire at
//     all.
//   - The counter's denominator. Every request refused earlier - malformed
//     body, invalid stage, missing query - would increment nothing, so the
//     adoption ratio the per-plane cutover (#3564) is read off would
//     systematically undercount the fleet that is presenting handshakes.
//   - It needs nothing from the body. The declaration is a header.

const (
	// pepHandshakeAbsent means no header was presented. Counted, because a
	// window with zero malformed handshakes is equally well explained by a
	// correct fleet and by a fleet presenting nothing at all - absence is the
	// denominator, not a non-event.
	pepHandshakeAbsent = "absent"
	// pepHandshakeAccepted means a validated enforcement point was admitted.
	pepHandshakeAccepted = "accepted"
	// pepHandshakeMalformed means the header could not be read as a handshake.
	pepHandshakeMalformed = "malformed"
	// pepHandshakeUnbindable means the authenticated channel carries no client
	// identity, so no enforcement point identifier can be built. Distinct from
	// malformed: the DOCUMENT was fine and the CHANNEL was not, and an operator
	// sent to look at the client's code would find nothing wrong with it.
	pepHandshakeUnbindable = "identity_unbindable"
	// pepHandshakeOverAdvertised means at least one declared capability was
	// dropped as unclaimable by this edition of enforcement point. The request
	// PROCEEDS with the narrowed set; see registry.SplitOverAdvertised.
	pepHandshakeOverAdvertised = "over_advertised"
	// pepHandshakeUnresolvable means this deployment's mode is unrecognised, so
	// the enforcement point's edition cannot be established. Unreachable on a
	// booted agent, which refuses to start on an unrecognised DEPLOYMENT_MODE
	// (platform/shared/deploymode), and present because a guard whose
	// unreachability depends on another package's behaviour must still refuse
	// rather than pick an answer.
	pepHandshakeUnresolvable = "edition_unresolvable"
)

// allPEPHandshakeOutcomes is every value the outcome label can take, in a
// stable order, so a test can assert the label domain rather than the outcomes
// one test happened to produce.
func allPEPHandshakeOutcomes() []string {
	return []string{
		pepHandshakeAbsent, pepHandshakeAccepted, pepHandshakeMalformed,
		pepHandshakeOverAdvertised, pepHandshakeUnbindable, pepHandshakeUnresolvable,
	}
}

// capabilityRefusalProjectionFailed is the status label for a refusal raised
// BEFORE any capability status exists: the obligation had no typed equivalent,
// so nothing could be asked about it. It is not a registry.CapabilityStatus and
// deliberately does not pretend to be one - inventing a status for "we never
// got as far as asking" would put a made-up answer in a series whose other
// values are real ones.
const capabilityRefusalProjectionFailed = "projection_failed"

// allCapabilityRefusalStatuses is the closed domain of the status label, in a
// stable order, so a test can assert the domain rather than the values one test
// happened to produce.
func allCapabilityRefusalStatuses() []string {
	out := []string{capabilityRefusalProjectionFailed, capabilityRefusalStatusUndeclared}
	for _, st := range registry.AllCapabilityStatuses() {
		if st == registry.CapabilitySupported {
			continue // the admitting member never reaches a refusal counter
		}
		out = append(out, st.String())
	}
	return out
}

// allOverAdvertisedFamilies is the closed domain of the over-advertised
// counter's family label: every declared obligation family, plus the literal
// written when a capability names a type whose family cannot be resolved.
//
// Declared for the same reason the other two label domains are - the round-1
// review found a status written outside its own documented domain, and this
// counter shipped in the same change with no domain at all, which is the class
// replanted rather than fixed.
func allOverAdvertisedFamilies() []string {
	out := make([]string, 0, len(contract.AllObligationFamilies())+1)
	for _, f := range contract.AllObligationFamilies() {
		out = append(out, string(f))
	}
	return append(out, overAdvertisedFamilyUnresolved)
}

// capabilityRefusalStatusUndeclared is the label for a capability status this
// build does not declare.
//
// IT BOUNDS THE LABEL, and that is a cardinality control rather than tidiness.
// CapabilityStatus.String() renders an unrecognised value as
// "CapabilityStatus(9999)" - a DISTINCT string per value - so writing it
// straight into a Prometheus label lets one undeclared status mint one series
// each. The zero value renders as "unspecified", which is equally undeclared as
// a refusal label: it means nobody ever answered, not that a check refused.
//
// Both collapse here, and they collapse LOUDLY rather than silently: the series
// exists, so an operator sees that something wrote a status this build has no
// name for.
const capabilityRefusalStatusUndeclared = "undeclared"

// capabilityRefusalStatusLabel bounds a status before it becomes a label.
func capabilityRefusalStatusLabel(st registry.CapabilityStatus) string {
	if !st.IsValid() {
		return capabilityRefusalStatusUndeclared
	}
	return st.String()
}

// overAdvertisedFamilyUnresolved is the family label for a capability whose
// family could not be resolved. Unreachable through SplitOverAdvertised, which
// only reports a capability whose family it resolved, and written rather than
// dropped because a series that stops being written is indistinguishable from a
// clean window.
const overAdvertisedFamilyUnresolved = "unresolved"

// Reason strings a PEP branches on. They are TEXT carried on an existing
// channel - the decide error message and the deny reason list - and each one
// pairs with a contract.ReasonCode that already exists. No new reason-code
// vocabulary is introduced: contract.ReasonInvalidInput, ReasonBindingMismatch
// and ReasonUnsupportedObligation already mean these three things.
const (
	pepHandshakeMalformedReason   = "pep_handshake_malformed"
	pepHandshakeUnbindableReason  = "pep_handshake_identity_unbindable"
	pepCapabilityUnsupportedCode  = "pep_capability_unsupported"
	pepHandshakeUnresolvableCause = "pep_handshake_edition_unresolvable"
)

// allPEPHandshakeReasons is the closed set of reason strings this code puts in
// front of a CALLER, in a stable order.
//
// Declared for the same reason all three metric label domains are, and because
// this set has the stronger claim of the four: a metric label is read by an
// operator, and these are read by a PEP branching on the refusal it got. An
// undeclared reason string is an unreviewed branch in somebody else's client.
//
// The check that matters is not that this list exists but that it is asserted
// against what the code WRITES - a list compared to another list is the
// tautology this lane has already had to remove twice.
func allPEPHandshakeReasons() []string {
	return []string{
		pepCapabilityUnsupportedCode,
		pepHandshakeMalformedReason,
		pepHandshakeUnbindableReason,
		pepHandshakeUnresolvableCause,
	}
}

var (
	// pepHandshakeOutcomes is the ADOPTION signal: is the fleet presenting
	// handshakes, and are they well formed? It is what #3564's per-plane
	// cutover is read off. Labels are closed server-side enumerations and
	// neither identifies a customer.
	pepHandshakeOutcomes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_pep_handshake_total",
			Help: "ADR-065 PEP capability handshakes by outcome (absent|accepted|malformed|over_advertised|identity_unbindable|edition_unresolvable) and decision plane",
		},
		[]string{"outcome", "plane"},
	)

	// pepCapabilityRefusals is the ENFORCEMENT signal: which capability gap is
	// denying requests, on which obligation?
	//
	// A SECOND series rather than a status label on the first, because the two
	// answer different operator questions and pooling them would lose the one
	// distinction the whole design turns on: declared_none (this enforcement
	// point told us it discharges nothing - it is not configured) and
	// type_unsupported (it discharges other things but not this one - it is out
	// of date) are different problems with different fixes.
	//
	// The status domain is allCapabilityRefusalStatuses(): every
	// registry.CapabilityStatus except the admitting member, PLUS
	// capabilityRefusalProjectionFailed, which is not a CapabilityStatus at all
	// - the projection fails before any status exists. An earlier version of
	// this comment claimed the domain was AllCapabilityStatuses and the code
	// then wrote a value outside it, which is the shape a label domain is
	// documented for in the first place.
	//
	// obligation_unversioned cannot arise on this path, because
	// projectDecisionObligations stamps a positive schema version on every
	// obligation it emits. It is declared anyway so that a future projection
	// which forgets to is COUNTED rather than silently minting an undeclared
	// series.
	pepCapabilityRefusals = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_pep_capability_refusals_total",
			Help: "EVALUATIONS denied because the advertising enforcement point cannot discharge a mandatory obligation, by capability status (a registry.CapabilityStatus, or projection_failed when the obligation had no typed equivalent), obligation type and decision plane. NOTE THE UNIT: evaluations, not requests - one plural AuthZEN envelope delegates up to 64, while axonflow_pep_handshake_total counts one per HTTP request. Do not ratio the two without accounting for that.",
		},
		[]string{"status", "obligation", "plane"},
	)

	// pepCapabilityOverAdvertised counts capabilities DROPPED from an external
	// declaration as unclaimable by that enforcement point's edition.
	//
	// A third series rather than a label on either of the others, because it
	// reports neither an outcome of the handshake (the request proceeded) nor a
	// refusal (nothing was denied). It is the signal an operator needs to see a
	// client shipping a capability set this deployment will never honour -
	// silently narrowing a declaration and never saying so is the only thing
	// that would make dropping worse than refusing.
	//
	// The label is the FAMILY, not the type: the rule that dropped it is
	// keyed on the family (registry.EnterpriseOnlyFamilies), so the family is
	// what an operator needs to look up, and it is the coarser of the two so
	// the series count is the smaller one.
	pepCapabilityOverAdvertised = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_pep_capability_over_advertised_total",
			Help: "Capabilities dropped from an external enforcement point's declaration because its edition may not claim that obligation family",
		},
		[]string{"family", "plane"},
	)
)

func init() {
	_ = prometheus.Register(pepHandshakeOutcomes)
	_ = prometheus.Register(pepCapabilityRefusals)
	_ = prometheus.Register(pepCapabilityOverAdvertised)
}

// externalPEPCatalog is the catalog external enforcement points are admitted
// against.
//
// It declares the external realm and NOTHING else, which is deliberate. Nothing
// is registered into it and nothing is read out of it: AdmitExternalPEP stores
// no record, so the catalog's only job here is to be the thing that has DECLARED
// the realm - the same fence RegisterPEP puts in front of the in-process
// planes, so a deployment that has not declared the realm cannot admit an
// external enforcement point at all. Seeding it with the legacy planes would
// build a surface with no reader.
//
// Catalog.Validate is never called on it and would fail (it registers no
// actions); AdmitExternalPEP validates the RECORD and the realm, not the whole
// catalog.
var externalPEPCatalog = sync.OnceValues(func() (*registry.Catalog, error) {
	c := registry.NewCatalog(time.Now())
	if err := registry.RegisterExternalPEPRealm(c); err != nil {
		return nil, err
	}
	return c, nil
})

// pepHandshakeResolution is what one request's handshake resolved to.
type pepHandshakeResolution struct {
	// outcome is the metric label, always set.
	outcome string
	// pep is the admitted enforcement point. Usable only when Admitted().
	pep registry.ExternalPEP
	// refused is true when the request must not be evaluated.
	refused bool
	// status is the HTTP status for a refusal.
	status int
	// reason is the machine-readable cause a PEP branches on.
	reason string
	// detail is the operator-facing explanation.
	detail string
	// reasonCode and memberPointer are the MACHINE facts a caller branches on,
	// carried out of contract.HandshakeRefusal rather than left in it. An
	// earlier version stamped a hand-written reason string and left the typed
	// code inside the refusal, where nothing read it - a documented "you can
	// branch on this" that the type did not keep. The pointer matters most on
	// the AuthZEN plane, where the surface's own error code cannot distinguish
	// a malformed HEADER from a malformed body ENVELOPE and prose is otherwise
	// the only signal.
	reasonCode    contract.ReasonCode
	memberPointer string
	// dropped names the capabilities removed as unclaimable by this edition.
	dropped []contract.Capability
	// audience is the declared audience, carried for the audit row. It is not
	// on the PEPRecord because an audience is what a decision proof is bound
	// to, not a property of the enforcement point's registration.
	audience string
}

// pepAuditFields is what an admitted declaration contributes to the audit row.
type pepAuditFields struct {
	// identity is the RESOLVED identifier the platform composed, never the
	// caller's raw pep_id: the row must not record a name the platform did not
	// build, or a reader could not tell an enforcement point from a claim.
	identity string
	audience string
	// capabilities is the ADMITTED set, after any over-advertised entry was
	// dropped - what the decision was actually taken against, not what arrived.
	// Non-nil for an admitted point that declared nothing, so "declared none"
	// stays distinguishable in the durable record.
	capabilities []string
}

// auditFields renders an admitted declaration for the audit row.
//
// Reports false when nothing was admitted, so a caller cannot write an empty
// identity onto a row and make "no handshake" look like "a handshake from
// nobody".
func (p pepHandshakeResolution) auditFields() (pepAuditFields, bool) {
	if !p.pep.Admitted() {
		return pepAuditFields{}, false
	}
	rec := p.pep.Record()
	caps := make([]string, 0, len(rec.Capabilities))
	for _, c := range rec.Capabilities {
		caps = append(caps, fmt.Sprintf("%s@%d", c.Type, c.Version))
	}
	return pepAuditFields{identity: rec.ID, audience: p.audience, capabilities: caps}, true
}

// presented reports whether the caller presented a handshake at all.
func (p pepHandshakeResolution) presented() bool { return p.outcome != pepHandshakeAbsent }

// resolvePEPHandshake reads, validates and binds one request's handshake.
//
// authenticatedClientID is the identity apiAuthMiddleware derived from the
// CREDENTIAL. It is the only source of the enforcement point's namespace; see
// registry.ExternalPEPID for why the caller supplies a name inside it rather
// than the identifier itself.
func resolvePEPHandshake(r *http.Request, authenticatedClientID string) pepHandshakeResolution {
	// Header.Values, never Header.Get. Get returns "" for a header that is
	// ABSENT and for one that is PRESENT AND EMPTY, and returns only the first
	// of a repeated header - so a handler written against it would read a
	// present-but-empty declaration as today's behaviour (the exact
	// degrade-to-legacy this file exists to close) and could not see a repeat
	// at all.
	values := r.Header.Values(contract.PEPHandshakeHeader)
	if len(values) == 0 {
		return pepHandshakeResolution{outcome: pepHandshakeAbsent}
	}
	if len(values) > 1 {
		return pepHandshakeResolution{
			outcome: pepHandshakeMalformed, refused: true, status: http.StatusBadRequest,
			reason: pepHandshakeMalformedReason, reasonCode: contract.ReasonInvalidInput,
			detail: fmt.Sprintf(
				"the %s header was presented %d times; a declaration must be unambiguous, and an intermediary that joined two of them would produce a value neither client sent",
				contract.PEPHandshakeHeader, len(values)),
		}
	}

	handshake, refusal := contract.DecodePEPHandshake(values[0])
	if refusal != nil {
		return pepHandshakeResolution{
			outcome: pepHandshakeMalformed, refused: true, status: http.StatusBadRequest,
			reason:     pepHandshakeMalformedReason,
			reasonCode: refusal.ReasonCode(), memberPointer: refusal.MemberPointer(),
			detail: refusal.Error(),
		}
	}

	// The channel identity is the enforcement point's NAMESPACE, and an empty
	// one is refused rather than compared. Building "client::name" from an
	// absent identity would give every such caller ONE accepted identifier - an
	// equals-shaped condition satisfied by the empty actor, which is fail-open
	// in the direction that matters: two different enforcement points would
	// share one record.
	if strings.TrimSpace(authenticatedClientID) == "" {
		return pepHandshakeResolution{
			outcome: pepHandshakeUnbindable, refused: true, status: http.StatusForbidden,
			reason: pepHandshakeUnbindableReason, reasonCode: contract.ReasonBindingMismatch,
			memberPointer: "/pep_id",
			detail: contract.PEPHandshakeHeader + ": the authenticated channel carries no client identity, so no enforcement point " +
				"identifier can be built for this declaration; an enforcement point that cannot be named cannot be held to what it advertised",
		}
	}

	edition, ok := externalPEPEdition()
	if !ok {
		return pepHandshakeResolution{
			outcome: pepHandshakeUnresolvable, refused: true, status: http.StatusInternalServerError,
			reason: pepHandshakeUnresolvableCause, reasonCode: contract.ReasonEvaluationError,
			detail: fmt.Sprintf(
				"this deployment's mode %q is not one this build recognises, so the edition of an enforcement point authenticating into it cannot be established",
				logutil.Sanitize(deploymode.Current())),
		}
	}

	kept, overAdvertised := registry.SplitOverAdvertised(edition, handshake.Capabilities)
	handshake.Capabilities = kept

	catalog, err := externalPEPCatalog()
	if err != nil {
		return pepHandshakeResolution{
			outcome: pepHandshakeUnresolvable, refused: true, status: http.StatusInternalServerError,
			reason: pepHandshakeUnresolvableCause, reasonCode: contract.ReasonEvaluationError,
			detail: "the external enforcement point realm could not be declared: " + err.Error(),
		}
	}
	admitted, findings := catalog.AdmitExternalPEP(
		registry.ExternalPEPRecordFrom(authenticatedClientID, edition, handshake))
	if err := findings.Err(); err != nil {
		return pepHandshakeResolution{
			outcome: pepHandshakeMalformed, refused: true, status: http.StatusBadRequest,
			reason: pepHandshakeMalformedReason, reasonCode: contract.ReasonInvalidInput,
			detail: err.Error(),
		}
	}

	out := pepHandshakeResolution{
		outcome: pepHandshakeAccepted, pep: admitted,
		dropped: overAdvertised, audience: handshake.Audience,
	}
	if len(overAdvertised) > 0 {
		// The request PROCEEDS with the narrowed set. Dropping can only make an
		// enforcement point look LESS capable, which produces a deny at the
		// moment the capability is needed rather than a blanket 400 on every
		// call from a correctly-built client whose single compile-time
		// capability set happens to name a family this deployment does not
		// issue. It is logged and counted so it is never SILENT, which is the
		// only property that separates this from ignoring the declaration.
		out.outcome = pepHandshakeOverAdvertised
		log.Printf("[pep-handshake] enforcement point %s advertised %d capability(ies) a %s enforcement point may not claim; they were dropped and the request proceeds with the narrowed set: %v",
			logutil.Sanitize(admitted.Record().ID), len(overAdvertised), edition, overAdvertised)
	}
	return out
}

// externalPEPEdition derives the edition of an enforcement point authenticating
// into THIS deployment.
//
// # WHY THE PEP DOES NOT DECLARE IT
//
// A community build claiming Enterprise would defeat exactly the rule that
// exists to catch it. There is deliberately no edition member on the wire.
//
// # WHY THIS SIGNAL AND NOT THE OTHER TWO
//
// NOT edition.Current: that constant answers "which set of source files was
// compiled into THIS binary", and its own package documentation says it must
// never gate an entitlement. Using this process's build tag to describe a
// DIFFERENT machine's enforcement point is the error
// platform/decision/registry/doc.go warns against by name.
//
// NOT isCommunityMode(): it is `DEPLOYMENT_MODE == "community"` and nothing
// else, so it answers FALSE - i.e. Enterprise, the permissive direction here -
// for an unset variable AND for the whole community-saas fleet, which its own
// comment says is intentionally not community mode. Either would silently
// disable the over-advertising rule on a deployment that is genuinely
// community.
//
// The signal is the deployment's MIGRATION CATEGORY, resolved through
// platform/shared/deploymode. It is a proxy and it is named as one: the
// question is "can this deployment issue an Enterprise-only obligation family",
// today just the approval family, and the approval machinery lives in the
// Enterprise schema. A deployment that never applied migrations/enterprise/ has
// no approval tables, so an enforcement point authenticating into it can never
// be handed an approval_challenge whatever it claims.
//
// An UNRECOGNISED mode returns false. deploymode.AppliesCategory answers "yes"
// for one, which is correct for schema selection (a read that fails is
// recoverable, a schema that is missing is not) and is the wrong direction
// here, so this function resolves first and refuses rather than reusing that
// predicate's fallback.
func externalPEPEdition() (registry.Edition, bool) {
	mode, recognised := deploymode.Resolve(deploymode.Current())
	if !recognised {
		return registry.EditionUnspecified, false
	}
	if deploymode.AppliesCategory(mode, deploymode.CategoryEnterprise) {
		return registry.EditionEnterprise, true
	}
	return registry.EditionCommunity, true
}

// pepHandshakeCountedCtxKey marks that THIS HTTP request's handshake outcome
// has already been counted.
//
// It carries no VALUE, only the fact. That is the correction: an earlier
// version cached the whole resolution here and returned it on a hit, which
// meant the delegated handler never read its own request's headers again - and
// silently made the AuthZEN forward list's handshake entry, and the emptiness
// exemption written to protect it, DEAD CODE. Three mutants recorded as kills
// in the same round then survived, because they had been measured against a
// tree this very function had not yet changed.
type pepHandshakeCountedCtxKeyType struct{}

var pepHandshakeCountedCtxKey = pepHandshakeCountedCtxKeyType{}

// resolveAndRecordPEPHandshakeOnce resolves the handshake for the request in
// front of it and counts the outcome AT MOST ONCE per inbound HTTP request.
//
// # RESOLVE ALWAYS, COUNT ONCE - and the split is the whole point
//
// The two halves have different scopes and conflating them cost a real defect:
//
//   - RESOLUTION is a property of the REQUEST BEING HANDLED. Deriving it from
//     the request every time is what keeps the header's journey load bearing:
//     the AuthZEN surface forwards the header onto its synthetic inner request,
//     and if this function short-circuited on a cached value that forwarding
//     would be unobservable - present in the code, asserted by tests, and
//     provably unnecessary.
//   - COUNTING is a property of the INBOUND HTTP REQUEST. The AuthZEN surface
//     delegates once per entry of a plural envelope, up to 64, all from ONE
//     header. Counting per entry made the adoption ratio a function of a number
//     the CALLER chooses, and the skew was directional: a malformed handshake
//     short-circuits the entry loop after one increment while absent and
//     accepted multiply, understating the malformed rate on exactly the plane
//     where the header is most fragile.
//
// So the context carries a MARK, not a value. The re-resolution costs one
// base64 decode and one bounded JSON parse per entry, on a path that is already
// running a full policy evaluation and an audit insert per entry; buying back
// that noise by making a forwarding path unobservable was a bad trade.
func resolveAndRecordPEPHandshakeOnce(
	ctx context.Context, r *http.Request, authenticatedClientID, plane string,
) (context.Context, pepHandshakeResolution) {
	// ALWAYS from this request's own headers.
	res := resolvePEPHandshake(r, authenticatedClientID)
	if _, counted := ctx.Value(pepHandshakeCountedCtxKey).(struct{}); counted {
		return ctx, res
	}
	recordPEPHandshakeOutcome(plane, res)
	return context.WithValue(ctx, pepHandshakeCountedCtxKey, struct{}{}), res
}

// recordPEPHandshakeOutcome counts one resolution, including every capability
// the edition rule dropped.
//
// The dropped entries are counted PER CAPABILITY rather than once per request,
// because "one request had something dropped" and "this client is shipping
// three capabilities we will never honour" are different facts and the second
// is the one that gets a client fixed.
func recordPEPHandshakeOutcome(plane string, res pepHandshakeResolution) {
	pepHandshakeOutcomes.WithLabelValues(res.outcome, plane).Inc()
	for _, c := range res.dropped {
		family, err := contract.FamilyOf(c.Type)
		if err != nil {
			// Unreachable: SplitOverAdvertised only reports a capability whose
			// family it resolved. Counted under a bounded literal rather than
			// dropped, because a series that stops being written is
			// indistinguishable from a clean window.
			family = overAdvertisedFamilyUnresolved
		}
		pepCapabilityOverAdvertised.WithLabelValues(string(family), plane).Inc()
	}
}

// applyObligationGates runs BOTH obligation gates, in the one order that is
// correct.
//
// # WHY THE TWO ARE COMPOSED HERE RATHER THAN CALLED IN SEQUENCE
//
// The order is load bearing. The seam gate SUPPRESSES an obligation the
// caller's plumbing cannot discharge and lets the org's fallback posture decide
// the outcome; the capability check DENIES when the enforcement point declared
// it cannot discharge one. Running the seam gate first would convert an ADR-065
// invariant-8 deny into an allow-minus-obligation - a widening produced by two
// correct rules in the wrong order, with nothing in either rule to notice.
//
// A property that lives in the sequence of two statements is a property one
// refactor removes, and no unit test of either function can see it: the only
// test that could would be one asserting a source ordering, which an overlay
// mutant walks straight past. Composing them makes the order STRUCTURAL - there
// is no call site left to reorder - and gives the ordering assertion a function
// to be about.
//
// Returns the possibly-rewritten triple, the seam's fallback record (nil unless
// the seam gate suppressed something), and whether the capability check denied.
func applyObligationGates(
	ctx context.Context,
	orgID, plane string,
	res pepHandshakeResolution,
	seamCapabilities *[]string,
	verdict string,
	reasons []string,
	obligations []DecisionObligation,
) (string, []string, []DecisionObligation, *obligationFallback, bool) {
	verdict, reasons, obligations, denied := applyPEPCapabilityRefusal(
		plane, res, verdict, reasons, obligations)
	verdict, reasons, obligations, fallback := applySeamCapabilityObligations(
		ctx, orgID, seamCapabilities, verdict, reasons, obligations)
	return verdict, reasons, obligations, fallback, denied
}
