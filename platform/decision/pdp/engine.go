// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
)

// Engine is a contract.Decider backed by verified, digest-pinned bundles and
// the ADR-065 combining semantics.
//
// It holds one runtime per authority root. Permission and constraint policies
// are read from separate signed roots, so an organization bundle cannot
// modify, remove or shadow a system constraint: the two artifacts are verified
// against different keys and their outcomes are unioned, never merged.
type Engine struct {
	runtimes map[Root]*Runtime
	meta     map[string]PolicyMeta
	// PayloadLeaves is the leaf field schema disclosure obligations expand
	// over for this action class.
	payloadLeaves []string
	approvalTTL   time.Duration
	pep           *contract.PEPProfile
	breakGlass    BreakGlassLookup
	registry      *Registry
	compat        *CompatibilityProfile
}

// BreakGlassLookup returns the active, time-bound, approved break-glass roles
// for a principal at a point in time. It is an interface rather than a field so
// the engine cannot read a break-glass state that outlives its window: the
// caller supplies the evaluation instant and gets back only what is active
// then.
type BreakGlassLookup func(principal contract.ID, at time.Time) []contract.ID

// EngineConfig configures an Engine.
type EngineConfig struct {
	// Bundles are the verified bundles, one per root.
	Bundles []*Bundle
	// Documents are the typed source documents the bundles were compiled
	// from, used for combiner metadata.
	Documents []*Document
	// TrustStore verifies every bundle before activation.
	TrustStore *TrustStore
	// PayloadLeaves is the canonical leaf field schema for the payload
	// disclosure obligations transform.
	PayloadLeaves []string
	// ApprovalTTL is the challenge lifetime stamped on a composed approval
	// requirement.
	ApprovalTTL time.Duration
	// PEP is the advertised enforcement profile. A nil profile means the
	// enforcement point advertised nothing, and a decision carrying mandatory
	// obligations then denies rather than being partially interpreted.
	PEP *contract.PEPProfile
	// BreakGlass is optional.
	BreakGlass BreakGlassLookup
	// Registry resolves the action and the declared trust realms. It is
	// required: an engine with no registry cannot tell a registered action
	// from an unregistered one, and admitting an unregistered surface is the
	// failure the registry exists to prevent.
	Registry *Registry
	// Compat is the temporary, action-scoped compatibility profile. Nil is the
	// production posture.
	Compat *CompatibilityProfile
	// Limits bound evaluation.
	Limits Limits
}

// NewEngine verifies every bundle, prepares a runtime per root, and returns a
// Decider.
//
// Verification happens before preparation and preparation happens before the
// first request. A bundle signature, provenance, compiler, schema and helper
// digest that do not verify block activation, so a defective or unsigned
// artifact never reaches a decision path.
func NewEngine(ctx context.Context, cfg EngineConfig) (*Engine, error) {
	if cfg.TrustStore == nil {
		return nil, fmt.Errorf("pdp: an engine requires a trust store; an unverified bundle cannot be activated")
	}
	if len(cfg.Bundles) == 0 {
		return nil, fmt.Errorf("pdp: an engine requires at least one bundle")
	}
	if cfg.Registry == nil {
		return nil, fmt.Errorf("pdp: an engine requires an action registry; without one an unregistered action cannot be refused")
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = 15 * time.Minute
	}
	// The combiner's metadata comes from the DOCUMENTS: which policies may be
	// pierced by break-glass, which obligations they attach, which are
	// mandatory. That metadata is security-critical and the documents are not
	// signed, so each one is bound to the bundle it claims to be the source of
	// before any of it is trusted. Without the comparison, a caller could hand
	// over byte-identical signed bundles and an edited document, and suspend an
	// unbreakable system constraint through a struct nothing verified.
	byRoot := map[Root]*Bundle{}
	for _, b := range cfg.Bundles {
		if b == nil {
			return nil, fmt.Errorf("pdp: a nil bundle was supplied")
		}
		byRoot[b.Root] = b
	}
	for _, d := range cfg.Documents {
		if d == nil {
			return nil, fmt.Errorf("pdp: a nil source document was supplied")
		}
		b, ok := byRoot[d.Root]
		if !ok {
			return nil, fmt.Errorf("pdp: a source document was supplied for root %q with no matching bundle", d.Root)
		}
		digest, err := contract.ExactDigest(d)
		if err != nil {
			return nil, fmt.Errorf("pdp: digesting the %s source document: %w", d.Root, err)
		}
		if digest != b.Provenance.SourceDigest {
			return nil, fmt.Errorf(
				"pdp: the %s source document digests to %s, the bundle it accompanies was compiled from %s; "+
					"the combiner reads policy metadata out of the document, so the two must be the same policy set",
				d.Root, digest, b.Provenance.SourceDigest)
		}
	}
	for root := range byRoot {
		found := false
		for _, d := range cfg.Documents {
			if d != nil && d.Root == root {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("pdp: a bundle was supplied for root %q with no matching source document", root)
		}
	}

	meta, err := MetaIndex(cfg.Documents...)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		runtimes:      map[Root]*Runtime{},
		meta:          meta,
		payloadLeaves: append([]string(nil), cfg.PayloadLeaves...),
		approvalTTL:   cfg.ApprovalTTL,
		pep:           cfg.PEP,
		breakGlass:    cfg.BreakGlass,
		registry:      cfg.Registry,
		compat:        cfg.Compat,
	}
	for _, b := range cfg.Bundles {
		if err := cfg.TrustStore.Verify(b); err != nil {
			return nil, err
		}
		if _, dup := e.runtimes[b.Root]; dup {
			return nil, fmt.Errorf("pdp: two bundles were supplied for root %q", b.Root)
		}
		rt, err := NewRuntime(ctx, b, cfg.Limits)
		if err != nil {
			return nil, err
		}
		e.runtimes[b.Root] = rt
		for _, decl := range b.Manifest {
			if _, ok := e.meta[decl.ID]; !ok {
				return nil, fmt.Errorf("pdp: bundle %s declares policy %q with no matching source document entry", b.Digest, decl.ID)
			}
		}
	}
	return e, nil
}

// Decide evaluates one normalized request.
//
// Every failure below becomes a Decision with authorization Indeterminate
// rather than a Go error, because a caller that receives an error has to
// remember to fail closed and a caller that receives an Indeterminate decision
// cannot do anything else. An error is returned only when a Decision cannot be
// constructed at all.
func (e *Engine) Decide(ctx context.Context, req *contract.Request) (*contract.Decision, error) {
	return e.DecideWith(ctx, req, DecideOptions{})
}

// DecideOptions carries the per-request facts an evaluation needs that are not
// part of the request itself.
type DecideOptions struct {
	// PEP is the enforcement profile THIS caller advertised, from the ADR-065
	// capability handshake (#3704). Nil means the caller advertised nothing
	// for this request and the engine-wide profile applies, so every existing
	// caller is unchanged.
	//
	// A profile is per REQUEST because an external enforcement point declares
	// its capabilities per request; an engine-wide profile can only describe
	// one of them. Before #3706 the engine held exactly one and the handshake's
	// refusal was therefore enforced by the agent's decide plane rather than by
	// the PDP - two checks over the same vocabulary, agreeing, written apart.
	//
	// NIL MEANS TWO DIFFERENT THINGS ON THE TWO SIDES OF THIS SEAM, AND #3564
	// MUST NOT PASS ONE THROUGH AS THE OTHER. Here nil means "this caller
	// advertised nothing for this request, so the engine-wide profile
	// applies". In the registry, ExternalPEP.Profile() returns nil for a PEP
	// that was never ADMITTED, and there nil means "refuse" - a caller with no
	// admitted profile must not be granted the engine's. Issue #3706 step 3
	// tells #3564 to pass exactly that value here, so the prescribed call
	// FAILS OPEN unless the caller distinguishes the two: an unadmitted PEP
	// must be REFUSED BEFORE Decide is reached.
	//
	// Passing an EMPTY profile (&contract.PEPProfile{}) is the safer of the
	// two wrong-looking values - it advertises nothing, so any mandatory
	// obligation is denied - but it is NOT equivalent to refusing, and R3
	// round 2 proved it: a request that carries no mandatory obligation is
	// PERMITTED under an empty profile, because the capability check only
	// runs over mandatory obligations. ADR-065 invariant 12 says a plane that
	// has not advertised the decision profile refuses the request, full stop.
	// So the empty profile is a floor, not the answer; the answer is that an
	// unadmitted enforcement point never reaches a decision.
	PEP *contract.PEPProfile
}

// DecideWith evaluates one normalized request against a per-request profile.
//
// The resolved profile is computed ONCE, here, and reaches all THREE places
// composition consults it: the per-hop Combine, the multi-hop MeetDecisions,
// and ComposeObligations inside applyCompatibility. That is the whole of
// #3706: e.pep used to be read at each of those separately, so a change made
// at one left the other two answering against the engine-wide profile -
// silently, because each remaining site kept passing its own tests.
func (e *Engine) DecideWith(ctx context.Context, req *contract.Request, opts DecideOptions) (*contract.Decision, error) {
	decisionID, bindErr := decisionIDFor(req)
	var approvalExpiry time.Time
	if req != nil {
		approvalExpiry = req.EvaluatedAt.Add(e.approvalTTL)
	}
	// Resolved once. Every site below reads in.PEP rather than e.pep, so
	// there is one answer to "which profile is this request judged against"
	// and no site can be forgotten.
	pep := e.pep
	if opts.PEP != nil {
		pep = opts.PEP
	}
	// SITE 1 of 3 (#3706): CombineInput.PEP, read by every per-hop Combine.
	in := CombineInput{
		Request:        req,
		Meta:           e.meta,
		PEP:            pep,
		PayloadLeaves:  e.payloadLeaves,
		ApprovalExpiry: approvalExpiry,
		DecisionID:     decisionID,
	}
	if bindErr != nil {
		// A request whose binding cannot be computed cannot be bound to a
		// decision, and a decision that cannot be bound cannot be rebound
		// before execution. Evaluating it anyway would produce a permit whose
		// binding guarantee is void, so it is refused as invalid input.
		in.InputError = bindErr
		in.InputInvalid = true
		in.Request = shellRequest(req)
		return Combine(in)
	}
	if err := req.Validate(); err != nil {
		in.InputError = err
		in.InputInvalid = true
		in.Request = shellRequest(req)
		return Combine(in)
	}
	// Admission refuses an unknown surface before any policy is loaded.
	adm := e.registry.Admit(req)
	if adm.Failed {
		return admissionDecision(req, decisionID, adm)
	}
	if len(adm.Entry.PayloadLeaves) > 0 {
		in.PayloadLeaves = append([]string(nil), adm.Entry.PayloadLeaves...)
	}

	// Freshness is applied once, here, so that every root and every chain hop
	// sees the identical shared attribute set and a value cannot be inside its
	// bound for one bundle and outside it for another.
	shared := req.Attributes.AtFreshness(req.EvaluatedAt)

	roots := make([]Root, 0, len(e.runtimes))
	for r := range e.runtimes {
		roots = append(roots, r)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })

	// One evaluation per chain hop, then a MEET. Every identity resolves in
	// its own realm before the meet; pooling the chain's identities instead
	// builds a privilege-escalation machine, because placing an agent in a
	// powerful group would then let any low-privilege user who invokes that
	// agent inherit its reach.
	perHop := make([]*contract.Decision, 0, len(req.Context.ActorChain))
	for _, actor := range req.Context.ActorChain {
		hopIn := in
		hopIn.Actor = actor.ID
		hopIn.Attributes = mergeAttributes(shared, actor.Attributes.AtFreshness(req.EvaluatedAt))
		hopIn.Outcomes = nil
		if e.breakGlass != nil {
			hopIn.BreakGlassRoles = e.breakGlass(actor.ID, req.EvaluatedAt)
		}
		for _, root := range roots {
			res, err := e.runtimes[root].Eval(ctx, hopIn.Attributes)
			if err != nil {
				in.InputError = fmt.Errorf("actor %q, root %q: %w", actor.ID, root, err)
				return Combine(in)
			}
			ids := make([]string, 0, len(res.Outcomes))
			for id := range res.Outcomes {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				hopIn.Outcomes = append(hopIn.Outcomes, res.Outcomes[id])
			}
		}
		hopDec, err := Combine(hopIn)
		if err != nil {
			return nil, err
		}
		perHop = append(perHop, hopDec)
	}
	// SITE 2 of 3 (#3706): the multi-hop meet recomposes the union of the
	// permitted hops' obligations, so it applies the capability check a second
	// time and must apply it against the SAME profile the hops were judged by.
	dec, err := contract.MeetDecisions(perHop, contract.MeetOptions{
		PayloadLeaves: in.PayloadLeaves,
		PEP:           in.PEP,
	})
	if err != nil {
		return nil, err
	}
	return e.applyCompatibility(dec, adm.Entry, req, in)
}

// mergeAttributes overlays one actor's identity attributes onto the shared
// surface. The shared surface never contains principal attributes (the request
// validator refuses one that does), so the overlay can never mask a shared
// value.
func mergeAttributes(shared, actor contract.AttributeSet) contract.AttributeSet {
	out := make(contract.AttributeSet, len(shared)+len(actor))
	for k, v := range shared {
		out[k] = v
	}
	for k, v := range actor {
		out[k] = v
	}
	return out
}

// applyCompatibility converts a NotApplicable result into a permit when, and
// only when, an explicit, unexpired, correctly attributed exception covers a
// non-privileged, reversible, non-egress action.
//
// A refusal to apply an exception that names the action is recorded as a
// warning rather than silently ignored, because an operator who configured an
// exception and did not get one needs to see why.
func (e *Engine) applyCompatibility(dec *contract.Decision, entry ActionEntry, req *contract.Request, in CombineInput) (*contract.Decision, error) {
	if dec.Authorization != contract.AuthzNotApplicable || e.compat == nil {
		return dec, nil
	}
	out := e.compat.Apply(entry, req.Action, req.EvaluatedAt)
	if dec.Trace == nil {
		return nil, fmt.Errorf("pdp: decision %q carries no trace, so a compatibility exception cannot be recorded", dec.DecisionID)
	}
	if out.Refusal != "" {
		dec.Trace.Warnings = append(dec.Trace.Warnings, out.Refusal)
	}
	if !out.Applies {
		return dec, nil
	}
	// SITE 3 of 3 (#3706): a DIRECT ComposeObligations call that bypasses
	// CombineInput entirely. The compatibility exception carries a mandatory
	// immutable-audit obligation, so an enforcement point that cannot write
	// that record must not be granted the exception - and "that enforcement
	// point" is the one which advertised on THIS request.
	composed := contract.ComposeObligations(contract.ComposeInput{
		Obligations:    CompatibilityObligations(req.Action),
		Leaves:         in.PayloadLeaves,
		PEP:            in.PEP,
		ApprovalExpiry: in.ApprovalExpiry,
	})
	if composed.Denied {
		// The exception cannot be applied without its audit record, and an
		// enforcement point that cannot write that record cannot be trusted to
		// run under a compatibility posture at all.
		dec.Trace.Warnings = append(dec.Trace.Warnings,
			"compatibility exception was refused because its mandatory audit obligation cannot be discharged: "+composed.Detail)
		return dec, nil
	}
	dec.Authorization = contract.AuthzPermit
	dec.State = contract.StateAllow
	dec.Reason = contract.ReasonPermitted
	dec.Obligations = composed.Obligations
	dec.Trace.State = dec.State
	dec.Trace.Reason = dec.Reason
	dec.Trace.Category = contract.CategoryFor(dec.Reason)
	dec.Trace.Obligations = composed.Obligations
	dec.Trace.Warnings = append(dec.Trace.Warnings,
		"permitted under a temporary compatibility exception rather than by a matching permission: "+out.Detail)
	if err := dec.Validate(); err != nil {
		return nil, err
	}
	return dec, nil
}

// admissionDecision builds the refusal for a request that never reaches policy.
func admissionDecision(req *contract.Request, decisionID string, adm AdmissionResult) (*contract.Decision, error) {
	dec := &contract.Decision{
		DecisionID:    decisionID,
		RequestID:     req.RequestID,
		Authorization: contract.AuthzDeny,
		State:         contract.StateDeny,
		Reason:        adm.Reason,
		Snapshot:      req.Snapshot,
	}
	snapshot := req.Snapshot
	dec.Trace = &contract.Trace{
		State:       dec.State,
		Category:    contract.CategoryFor(dec.Reason),
		Reason:      dec.Reason,
		Remediation: adm.Detail,
		Snapshot:    &snapshot,
	}
	if err := dec.Validate(); err != nil {
		return nil, err
	}
	return dec, nil
}

// shellRequest keeps just enough of an invalid request to build a decision
// that names it. A request that failed validation may carry anything, so
// nothing is copied out of it except the identifiers a decision needs and a
// snapshot that satisfies the decision contract.
func shellRequest(req *contract.Request) *contract.Request {
	out := &contract.Request{}
	if req != nil {
		out.RequestID = req.RequestID
		out.Snapshot = req.Snapshot
		out.EvaluatedAt = req.EvaluatedAt
	}
	if out.RequestID == "" {
		out.RequestID = "req_unvalidated"
	}
	if out.Snapshot.SchemaVersion == "" {
		out.Snapshot.SchemaVersion = contract.SchemaVersion
	}
	if out.Snapshot.PolicyBundle == "" {
		out.Snapshot.PolicyBundle = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	return out
}

// decisionIDFor derives a stable decision identifier from the request binding
// digest, and reports whether the binding could be computed at all.
//
// Deriving rather than generating means a replay of the same request against
// the same bundle produces the same decision identifier. The error is RETURNED
// rather than swallowed: an earlier version fell back to a digest of the
// caller-supplied request identifier, so two materially different requests
// shared a decision identifier and the request was evaluated to a permit whose
// binding guarantee was void.
//
// THE IDENTIFIER DOES NOT COVER THE ENFORCEMENT PROFILE, AND SINCE #3706 THAT
// IS OBSERVABLE. The binding digest is over the REQUEST; the profile is a
// property of the caller, supplied per request through DecideOptions. So one
// engine, one request and one bundle can now produce the same decision
// identifier with different outcomes - a permit for a caller that can
// discharge a mandatory obligation and a deny for one that cannot. That is
// correct as a decision (the whole point of the capability check is that the
// answer depends on who is asking) and it means the older, broader phrasing
// here - "identical input and bundle reproduce identical decision" - is no
// longer true as written, so it has been removed rather than left to be read
// as a guarantee.
//
// WHAT THIS COSTS AND WHO OWNS IT. replay/environment.go pins the profile as
// part of the ENVIRONMENT precisely because it "changes decisions without
// changing a bundle", and replay reproduces decisions through Decide. So a
// replay is sound today: the environment carries the profile the record was
// taken against. It stops being automatic once #3564 routes a per-request
// profile from the handshake, because then the profile travels with the
// request and a record replayed against an environment-level profile could
// reproduce a different answer while reporting a match. Recorded on #3706 for
// #3564 to carry; it is not fixed here, because the fix is either binding the
// profile into the identifier - which changes #3614's proof surface - or
// recording it alongside the request, which is the replay format's decision.
//
// The exposure begins with any caller that passes a non-nil DecideOptions.PEP,
// which is possible from this commit onward because DecideWith is exported.
// #3564 is simply the first planned one. But exposure is not the trigger: a
// per-request profile only matters to replay once a record exists that was
// taken under one.
//
// REVISIT WHEN anything outside a _test.go file constructs a replay.Record.
// Nothing does today - `git grep 'replay.Record{'` outside tests returns
// nothing - so no record in existence was taken under a per-request profile,
// and the gap is a TRIGGER rather than a defect. The observable is that grep,
// not a component: an earlier version of this sentence named "the sampler",
// and there is no sampler, so it named nothing anybody could watch and its
// trailing clause read as "nothing to do here".
func decisionIDFor(req *contract.Request) (string, error) {
	if req == nil {
		sum := sha256.Sum256([]byte("nil canonical request"))
		return "dec_" + hex.EncodeToString(sum[:8]), fmt.Errorf("pdp: request is nil")
	}
	binding, err := req.BindingDigest()
	if err != nil {
		sum := sha256.Sum256([]byte(req.RequestID))
		return "dec_" + hex.EncodeToString(sum[:8]), fmt.Errorf("pdp: the request cannot be bound: %w", err)
	}
	sum := sha256.Sum256([]byte(binding))
	return "dec_" + hex.EncodeToString(sum[:8]), nil
}

var _ contract.Decider = (*Engine)(nil)
