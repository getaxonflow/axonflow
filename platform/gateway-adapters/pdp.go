// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/pep"
	"axonflow/platform/shared/version"
)

// Seam is one call path's COMPLETE self-declaration.
//
// It carries both vocabularies because they answer different questions about
// the same call path and they must not be able to disagree. Fulfillment is the
// #2958 SEAM-MECHANICS vocabulary — "what can this plumbing do to a request?" —
// and Capabilities is the ADR-065 OBLIGATION vocabulary — "which obligations
// can this enforcement point discharge?". They are not derivable from each
// other: request_header_mutation has no obligation type at all, and
// immutable_audit has no seam mechanic.
//
// Passing ONE value at each call site rather than two parameters is the whole
// reason this type exists. Two arguments that have to agree, written apart at
// four call sites, will eventually not: the fifth call site would declare a
// body-capable seam that discharges nothing, or the reverse, and the mismatch
// would be invisible because each half is individually plausible.
type Seam struct {
	// Name is this enforcement point's name inside the adapter's credential.
	// The platform prefixes it with the authenticated credential; see
	// registry.ExternalPEPID.
	Name string
	// Fulfillment is the #2958 seam-mechanics declaration.
	Fulfillment []string
	// Capabilities is the ADR-065 obligation declaration.
	//
	// EMPTY IS A REAL ANSWER HERE and is not an oversight: the headers-only
	// seam discharges no obligation whatever, and since #3704 it can say so.
	Capabilities []contract.Capability
	// handshake is the rendered header value, or "" when the adapter is not
	// configured to present one. Rendered ONCE per process in NewPDP.
	handshake string
}

// copy returns a Seam whose slices share nothing with the receiver's, and whose
// slices are never nil.
//
// make+copy, NOT `append([]string(nil), ...)` - which returns NIL for an empty
// input and is the exact idiom contract.SortCapabilities' own comment forbids by
// name as the #2958 collapse. The first version of this function used it for
// Fulfillment, latent only because both declared seams happen to be non-empty
// today. A seam that legitimately declares no seam mechanic would have had its
// declaration turn into an ABSENT member on the wire.
func (s Seam) copy() Seam {
	out := s
	out.Fulfillment = make([]string, len(s.Fulfillment))
	copy(out.Fulfillment, s.Fulfillment)
	out.Capabilities = contract.SortCapabilities(s.Capabilities)
	return out
}

var (
	// seamHeadersOnly — a seam that can set request headers but cannot rewrite
	// the content it forwards: the ext_authz seam, and ext_proc's bodyless
	// request-line path (both return header mutations on allow).
	//
	// Fulfillment is non-empty on purpose, and the old justification needs
	// splitting rather than retiring. It read: "an empty slice would serialize
	// away under omitempty AND read as a legacy caller". #3704 expired the
	// FIRST clause - an empty list is sendable now - and the SECOND clause is
	// exactly what #3704 then went on to RESTORE, because changing the reading
	// would widen a security control for a non-Go caller. So an empty
	// Fulfillment here would still read as legacy; it stays non-empty because
	// it is TRUE that this seam can mutate request headers, and a truthful
	// declaration beats a minimal one.
	//
	// Capabilities is EMPTY, and that is the honest ADR-065 declaration: this
	// seam cannot discharge field_redact, cannot write an immutable audit
	// record, and cannot raise an approval challenge. Under the handshake the
	// platform answers CapabilityDeclaredNone and denies a mandatory obligation
	// outright, which is the same block the never-fires ObligationBackstop
	// produces today - reached before the content is held rather than after,
	// and with a reason an operator can read.
	seamHeadersOnly = Seam{
		Name:         "gateway-headers-only",
		Fulfillment:  []string{pep.CapabilityRequestHeaderMutation},
		Capabilities: []contract.Capability{},
	}

	// seamBodyCapable — a seam that can replace the payload it forwards with
	// the engine-redacted content FulfillRequest returns: the ExtMcp params
	// path and ext_proc's request-BODY path.
	seamBodyCapable = Seam{
		Name:        "gateway-body-capable",
		Fulfillment: []string{pep.CapabilityRequestBodyRedaction},
		// field_redact at schema version 1 is what a request-phase redact_pii
		// obligation maps onto in the contract's typed vocabulary
		// (platform/agent/authzen_handler.go, legacyObligationType). This seam
		// discharges it by calling the engine's redaction endpoint, which is
		// exactly what FulfillRequest does.
		Capabilities: []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}},
	}
)

// PDP is the single engine-facing facade all three adapters share: the
// blessed pep client plus the defensive circuit posture (bounded timeout +
// trip-after-N breaker). It adds NO policy semantics of its own.
type PDP struct {
	pep      *pep.Client
	breaker  *breaker
	failOpen bool // request-plane posture; the response plane ignores it

	// The two seams with their handshakes rendered for THIS process. Held on
	// the PDP rather than read from the package vars so that a process which
	// did not opt into the handshake and one that did are two VALUES rather
	// than one value plus a global that a test can leave mutated.
	seamHeadersOnly Seam
	seamBodyCapable Seam
}

// NewPDP builds the facade from cfg.
func NewPDP(cfg Config) (*PDP, error) {
	client, err := pep.New(pep.Config{
		Endpoint:     cfg.AxonFlowEndpoint,
		OrgID:        cfg.OrgID,
		LicenseKey:   cfg.LicenseKey,
		TenantID:     cfg.TenantID,
		ConnectorTag: cfg.ConnectorTag,
		// Identify this integration on every engine round-trip (#3660). The
		// adapters were the one client of the decide plane that sent no
		// X-Axonflow-Client at all, so a self-hosted fleet running them could
		// not see them in axonflow_client_version_requests_total — the counter
		// built to answer exactly "which client versions is this fleet on".
		//
		// TELEMETRY-ONLY on both sides: the agent's recorder never consults it
		// for auth or a verdict, and nothing here treats it as a credential.
		ClientID:      ClientID,
		ClientVersion: version.Resolve(),
		HTTPClient:    &http.Client{Timeout: cfg.RequestTimeout},
	})
	if err != nil {
		return nil, err
	}
	headersOnly, bodyCapable, err := renderSeams(cfg.PEPAudience)
	if err != nil {
		return nil, err
	}
	return &PDP{
		pep:             client,
		breaker:         newBreaker(cfg.BreakerThreshold, cfg.BreakerCooldown),
		failOpen:        cfg.FailMode == FailModeOpen,
		seamHeadersOnly: headersOnly,
		seamBodyCapable: bodyCapable,
	}, nil
}

// SeamHeadersOnly and SeamBodyCapable are THIS process's rendered seams.
//
// The adapters read them from the PDP rather than from the package vars,
// because only the PDP's copies carry the rendered handshake. Reading the
// package var would send the #2958 declaration and silently omit the ADR-065
// one - a half-configured client that looks configured.
// They return COPIES. Returning the stored Seam by value still shares its
// slices' backing arrays, so `pdp.SeamHeadersOnly().Fulfillment[0] = "x"` would
// corrupt this PDP's declaration for every subsequent request - the hazard
// narrowed rather than removed, and two call sites already hand
// `SeamHeadersOnly().Fulfillment` out to a log line.
func (p *PDP) SeamHeadersOnly() Seam { return p.seamHeadersOnly.copy() }

// SeamBodyCapable is the body-capable call path's declaration.
func (p *PDP) SeamBodyCapable() Seam { return p.seamBodyCapable.copy() }

// renderSeams renders each seam's ADR-065 handshake once per process.
//
// OPT-IN, and that is what keeps this change dark. An empty PEPAudience leaves
// both handshakes empty, no header is sent, and the adapters behave byte for
// byte as they did before #3704.
//
// Which matters more than "dark by default" usually does, because the
// transition it gates is ALLOW -> DENY. Today the headers-only seam's
// request-body redaction is SUPPRESSED by #2958's gate and the organization's
// obligation-fallback posture decides, defaulting to `log` - i.e. allowed,
// minus the obligation. With a handshake presented, the seam's honest ADR-065
// declaration is an empty capability set, the platform answers
// CapabilityDeclaredNone, and the request is DENIED - on an ENTERPRISE
// deployment. On a community one the deny is physically absent from the build,
// so nothing changes at all. See Config.PEPAudience for
// the full statement; an earlier version of both comments said "both block",
// which was wrong: ObligationBackstop never fires precisely because the
// obligation was already withheld.
//
// Rendered ONCE rather than per request: a seam's declaration cannot change
// over the process's life, and Encode is a JSON marshal plus a base64 on the
// decide hot path.
func renderSeams(audience string) (headersOnly, bodyCapable Seam, err error) {
	// COPIED, not just struct-assigned. A struct copy shares the backing arrays
	// of Fulfillment and Capabilities with the package vars, and SeamHeadersOnly
	// hands them out - so `pdp.SeamHeadersOnly().Fulfillment[0] = "x"` would
	// corrupt the global for every PDP in the process, which is the hazard the
	// PDP field's own comment says holding them per-instance removed.
	headersOnly, bodyCapable = seamHeadersOnly.copy(), seamBodyCapable.copy()
	if audience == "" {
		return headersOnly, bodyCapable, nil
	}
	for _, s := range []*Seam{&headersOnly, &bodyCapable} {
		encoded, refusal := contract.PEPHandshake{
			ProfileVersion: contract.PEPHandshakeProfileV1,
			PEPID:          s.Name,
			Audience:       audience,
			Capabilities:   s.Capabilities,
		}.Encode()
		if refusal != nil {
			// Refused at CONSTRUCTION, not at the first request. A seam whose
			// declaration the platform is certain to reject must not be a
			// runtime surprise on the hot path.
			return Seam{}, Seam{}, fmt.Errorf("gateway-adapters: seam %q cannot present a capability handshake: %w", s.Name, refusal)
		}
		s.handshake = encoded
	}
	return headersOnly, bodyCapable, nil
}

// RequestOutcome is the uniform request-plane result the adapters branch on.
type RequestOutcome struct {
	// Kind is one of the Outcome* constants below.
	Kind int
	// Decision is the raw PDP verdict when one was obtained (nil on
	// transport-level failure).
	Decision *pep.DecideResponse
	// RedactedStatement holds the engine-redacted payload when Kind is
	// OutcomeAllowRedacted.
	RedactedStatement string
	// Reason is a human-readable block/failure reason.
	Reason string
}

// RequestOutcome kinds.
const (
	// OutcomeAllow — forward the original payload unchanged.
	OutcomeAllow = iota
	// OutcomeAllowRedacted — forward RedactedStatement instead of the original.
	OutcomeAllowRedacted
	// OutcomeDeny — the PDP denied (verdict deny or needs_approval); block
	// with Decision context.
	OutcomeDeny
	// OutcomeFailClosed — no trustworthy verdict (PDP rejected the call, an
	// obligation was unfulfillable, or the PDP is unreachable under
	// fail-closed posture); block.
	OutcomeFailClosed
	// OutcomeFailOpen — PDP unreachable and posture is fail-open; forward the
	// original payload (request plane only).
	OutcomeFailOpen
)

// GateRequest runs the full request-plane path shared by the ExtMcp and
// ext_proc seams: decide on req, then — when the verdict carries a
// request-phase redaction obligation — fulfill it through the engine against
// statement (the FULL payload that will actually be forwarded, which may be a
// superset of req.Query). The returned outcome is exhaustive; callers never
// see a raw error and therefore cannot accidentally fail open.
// seam is what the CALLING PATH can actually discharge — pass seamBodyCapable
// from a path that can rewrite what it forwards, and seamHeadersOnly from one
// that cannot (ext_proc's bodyless request-line path). It is a parameter rather
// than a constant because one adapter can span both, and over-declaring means
// the PDP hands this seam work it cannot do.
func (p *PDP) GateRequest(ctx context.Context, req pep.DecideRequest, statement, traceparent string, seam Seam) RequestOutcome {
	req.FulfillmentCapabilities = pep.AdvertiseCapabilities(seam.Fulfillment)
	req.Handshake = seam.handshake
	decision, err := p.decide(ctx, req, traceparent)
	if err != nil {
		return p.requestFailure(err)
	}
	if decision.Verdict != pep.VerdictAllow {
		return RequestOutcome{Kind: OutcomeDeny, Decision: decision, Reason: firstReason(decision)}
	}
	if !pep.HasRequestRedaction(decision.Obligations) {
		return RequestOutcome{Kind: OutcomeAllow, Decision: decision}
	}
	redacted, didRedact, err := p.pep.FulfillRequest(ctx, decision, statement)
	if err != nil {
		// An unfulfillable redaction obligation ALWAYS blocks — forwarding
		// the unredacted payload is the exact leak the obligation exists to
		// prevent, so posture does not apply.
		return RequestOutcome{
			Kind:     OutcomeFailClosed,
			Decision: decision,
			Reason:   fmt.Sprintf("redact_pii obligation not fulfillable: %v", err),
		}
	}
	if didRedact {
		return RequestOutcome{Kind: OutcomeAllowRedacted, Decision: decision, RedactedStatement: redacted}
	}
	return RequestOutcome{Kind: OutcomeAllow, Decision: decision}
}

// Decide is the headers-only decision path used by the ext_authz seam (which
// cannot mutate bodies and therefore never fulfills). Callers must apply
// requestFailure-equivalent posture themselves via ClassifyDecideErr.
//
// It declares the headers-only capability set (#2958), so a >=9.11.0 PDP knows
// not to emit a request-body redaction on this seam and applies the org's
// obligation-fallback posture instead of handing us work we cannot do. Callers
// must still run ObligationBackstop on the verdict — see its doc for why.
func (p *PDP) Decide(ctx context.Context, req pep.DecideRequest, traceparent string) (*pep.DecideResponse, error) {
	req.FulfillmentCapabilities = pep.AdvertiseCapabilities(p.seamHeadersOnly.Fulfillment)
	req.Handshake = p.seamHeadersOnly.handshake
	return p.decide(ctx, req, traceparent)
}

// ObligationBackstop reports whether decision carries a request-body redaction
// obligation that the HEADERS-ONLY seam cannot discharge — a state that must
// not happen, since Decide told the PDP this seam cannot do it.
//
// It is a NEVER-FIRES backstop, and it exists for exactly one real case:
// version skew. A >=9.11.0 adapter pointed at a <=9.10.0 PDP will have its
// fulfillment_capabilities silently ignored (the field did not exist yet) and
// will still be handed the obligation. Blocking is the only safe answer —
// forwarding is the unredacted leak the obligation exists to prevent, and
// masking locally is forbidden by the package charter (see doc.go). This is
// also why posture does NOT apply: fail-open here would forward raw PII.
//
// It returning true always means a DEPLOYMENT BUG (mismatched versions), never
// a policy outcome, so the caller logs it at ERROR naming the fix rather than
// treating it as a routine deny.
func (p *PDP) ObligationBackstop(decision *pep.DecideResponse) bool {
	return decision != nil && pep.HasRequestRedaction(decision.Obligations)
}

// ClassifyDecideErr maps a Decide error to a request-plane outcome kind
// (OutcomeFailClosed or OutcomeFailOpen) plus a reason.
func (p *PDP) ClassifyDecideErr(err error) RequestOutcome {
	return p.requestFailure(err)
}

// CheckOutput runs the response-governance engine round-trip. The response
// plane is UNCONDITIONALLY fail-closed: every error return means "withhold
// the response"; posture never applies.
func (p *PDP) CheckOutput(ctx context.Context, req pep.CheckOutputRequest, traceparent string) (*pep.CheckOutputResult, error) {
	if !p.breaker.allow() {
		return nil, fmt.Errorf("%w: circuit open (recent consecutive PDP failures)", pep.ErrPDPUnavailable)
	}
	res, err := p.pep.CheckOutput(ctx, req, traceparent)
	p.breaker.record(errors.Is(err, pep.ErrPDPUnavailable))
	return res, err
}

// decide applies the breaker around the pep decide call.
func (p *PDP) decide(ctx context.Context, req pep.DecideRequest, traceparent string) (*pep.DecideResponse, error) {
	if !p.breaker.allow() {
		return nil, fmt.Errorf("%w: circuit open (recent consecutive PDP failures)", pep.ErrPDPUnavailable)
	}
	decision, err := p.pep.Decide(ctx, req, traceparent)
	p.breaker.record(errors.Is(err, pep.ErrPDPUnavailable))
	return decision, err
}

// requestFailure maps a decide-path error to the fail posture. Only
// ErrPDPUnavailable (transport / 5xx / open circuit) is eligible for
// fail-open; a 4xx rejection signals a real problem with the request and
// always blocks (pep.ErrDecisionRejected contract).
func (p *PDP) requestFailure(err error) RequestOutcome {
	if errors.Is(err, pep.ErrPDPUnavailable) && p.failOpen {
		log.Printf("[gateway-adapters] PDP unavailable, forwarding per fail-open posture: %v", err)
		return RequestOutcome{Kind: OutcomeFailOpen, Reason: err.Error()}
	}
	return RequestOutcome{Kind: OutcomeFailClosed, Reason: err.Error()}
}

// firstReason extracts a displayable reason from a decision.
func firstReason(d *pep.DecideResponse) string {
	if d == nil {
		return ""
	}
	if len(d.Reasons) > 0 {
		return d.Reasons[0]
	}
	if d.Verdict == pep.VerdictNeedsApproval {
		return "human approval required"
	}
	return "blocked by policy"
}

// breaker is a minimal consecutive-failure circuit breaker: after threshold
// consecutive transport failures it fails fast (per plane posture) until
// cooldown elapses, then lets one probe through. It exists so a dead PDP
// degrades to bounded-latency failures instead of every gateway callout
// waiting out the full timeout.
type breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
	probing   bool             // half-open: exactly one probe in flight
	now       func() time.Time // test seam
}

func newBreaker(threshold int, cooldown time.Duration) *breaker {
	return &breaker{threshold: threshold, cooldown: cooldown, now: time.Now}
}

// allow reports whether a call may proceed.
func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.threshold {
		return true
	}
	if b.now().After(b.openUntil) && !b.probing {
		// Half-open: admit exactly ONE probe; concurrent callers keep
		// failing fast until it reports back (record clears probing). A
		// success resets, a failure re-opens for another cooldown.
		b.probing = true
		return true
	}
	return false
}

// record updates the breaker with the call result. Only transport-level
// failures (ErrPDPUnavailable) count — an engine that answers (even with a
// deny or a 4xx) is healthy.
func (b *breaker) record(transportFailure bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
	if !transportFailure {
		b.failures = 0
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = b.now().Add(b.cooldown)
	}
}
