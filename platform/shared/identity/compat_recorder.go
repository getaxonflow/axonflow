// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Counterfactual recorders for the compatibility adapters (#3550).
//
// The shadow phase's only product is this record. If it is not emitted, or is
// emitted at a volume nobody reads, the phase produced nothing - which is why
// the adapter refuses to be constructed without a recorder, and why the
// default one below is deliberately quiet about agreement and loud about
// everything else.
package identity

import (
	"context"
	"log"
	"sync"

	logutil "axonflow/platform/shared/logger"
)

// LogCounterfactualRecorder writes counterfactuals to the process log.
//
// # WHY AGREEMENT IS SAMPLED AND DIVERGENCE IS NOT
//
// This runs on the authentication path of every request. Logging every
// agreement would emit one line per request forever, which floods the log for
// no operational benefit and, worse, buries the divergences underneath it. So
// agreement is counted and logged periodically; a divergence, an adapter
// defect, and every enforced refusal are logged individually and always.
//
// The counters are exported through Snapshot so a metrics adapter, a test, or
// an operator command can read the totals without parsing log lines.
type LogCounterfactualRecorder struct {
	// agreementLogEvery emits one agreement line per N agreements. Zero
	// disables agreement logging entirely (the counters still move).
	agreementLogEvery uint64

	mu     sync.Mutex
	counts map[CompatDivergence]uint64
	// perPath counts divergences (never agreements) by path, so "which of the
	// four adapters is diverging" is answerable without a log query.
	perPath map[LegacyPath]map[CompatDivergence]uint64
	// agreements counts total agreements, used for the sampling decision.
	agreements uint64
}

// NewLogCounterfactualRecorder builds the default recorder. agreementLogEvery
// is how many agreements pass between log lines; zero logs none.
func NewLogCounterfactualRecorder(agreementLogEvery uint64) *LogCounterfactualRecorder {
	return &LogCounterfactualRecorder{
		agreementLogEvery: agreementLogEvery,
		counts:            map[CompatDivergence]uint64{},
		perPath:           map[LegacyPath]map[CompatDivergence]uint64{},
	}
}

// RecordCounterfactual implements CounterfactualRecorder.
func (r *LogCounterfactualRecorder) RecordCounterfactual(_ context.Context, rec Counterfactual) {
	if r == nil {
		return
	}
	shouldLogAgreement := r.tally(rec)

	// AN OUTAGE IS NOT AN AGREEMENT WORTH SUPPRESSING.
	//
	// When the legacy path rejects a credential and the identity plane reports
	// Indeterminate, the two AGREE on the outcome, so the divergence is none.
	// Sampling that away hides the operationally sharpest record this plane
	// produces: "your IdP is unreachable" and "your revocation store is down"
	// both arrive here, and both are agreements. The runtime suite found this
	// by asserting on a KEY_MATERIAL_UNAVAILABLE record that was being
	// classified as agreement and therefore never logged.
	//
	// So the log trigger is a divergence OR an Indeterminate. See
	// logsIndividually.
	if !logsIndividually(rec) {
		if shouldLogAgreement {
			log.Printf("[IDENTITY-COMPAT] component=%s mode=%s path=%s org=%s agreement (sampled 1 in %d)",
				logutil.Sanitize(rec.Component), rec.Mode, logutil.Sanitize(string(rec.Path)),
				logutil.Sanitize(rec.OrgID), r.agreementLogEvery)
		}
		return
	}

	// Everything below is a line an operator is meant to read. The principal
	// is included because it is a realm-qualified identifier the operator
	// declared, never credential material; the legacy reason is a reason
	// string this package's callers construct, never a token.
	log.Printf(
		"[IDENTITY-COMPAT] component=%s mode=%s path=%s org=%s divergence=%s legacy=%s legacy_reason=%q identity=%s/%s detail=%q realm=%s principal=%s epoch=%d enforced=%t",
		logutil.Sanitize(rec.Component),
		rec.Mode,
		// SANITIZED like every other caller-influenced field. It is the one
		// that most needs it: on the adapter-defect branch the path has just
		// been PROVEN invalid and is still recorded, so an unsanitized value
		// there would let a newline inject lines into the process log.
		logutil.Sanitize(string(rec.Path)),
		logutil.Sanitize(rec.OrgID),
		rec.Divergence,
		rec.LegacyDecision,
		logutil.Sanitize(rec.LegacyReason),
		rec.IdentityState,
		rec.IdentityReason,
		// THE FIELD THAT MAKES THE RECORD ACTIONABLE. It names the issuer that
		// has no realm, the claim that was absent, the audience that did not
		// intersect. Sanitized, and never surfaced to a caller.
		logutil.Sanitize(rec.IdentityDetail),
		logutil.Sanitize(string(rec.RealmID)),
		logutil.Sanitize(rec.Principal),
		rec.IdentityEpoch,
		rec.Enforced,
	)

	if rec.Divergence == DivergenceIdentityAdmittedLegacyRejected {
		// The unreachable one. If this ever fires, the adapter is feeding the
		// identity plane a credential the legacy path did not verify, which is
		// worse than any divergence in the other direction: it means the
		// shadow's own accept/reject comparison cannot be trusted. It gets its
		// own line so it cannot be lost among ordinary divergences.
		log.Printf("[IDENTITY-COMPAT] ALARM: path=%s admitted a credential the legacy path REJECTED; the adapter is presenting unverified material", logutil.Sanitize(string(rec.Path)))
	}
}

// logsIndividually reports whether this record gets its own log line rather
// than being counted and sampled.
//
// The Indeterminate arm is tested by MEMBERSHIP on the one state that means
// "could not tell", not by `!= AdmissionAccept`, which would also drag in
// every ordinary Deny that the legacy path independently rejected. Those are
// the bulk of a shadow phase's records in any deployment with expired tokens
// in circulation, and logging each one individually would flood the log with
// the least interesting thing this plane sees.
func logsIndividually(rec Counterfactual) bool {
	return rec.Divergence != DivergenceNone || rec.IdentityState == AdmissionIndeterminate
}

// tally updates the counters and reports whether this agreement should be
// logged. It holds the lock for the counter update only.
func (r *LogCounterfactualRecorder) tally(rec Counterfactual) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[rec.Divergence]++
	if rec.Divergence == DivergenceNone {
		r.agreements++
		if r.agreementLogEvery == 0 {
			return false
		}
		return r.agreements%r.agreementLogEvery == 0
	}
	// Keyed on the path only AFTER it is known to be a declared one. The
	// adapter records defects carrying an arbitrary path, and an unbounded map
	// keyed on a value the adapter itself rejected is a memory lever.
	if !rec.Path.IsValid() {
		return false
	}
	byPath, ok := r.perPath[rec.Path]
	if !ok {
		byPath = map[CompatDivergence]uint64{}
		r.perPath[rec.Path] = byPath
	}
	byPath[rec.Divergence]++
	return false
}

// CounterfactualSnapshot is a point-in-time read of the recorder's counters.
type CounterfactualSnapshot struct {
	// ByDivergence totals every outcome, agreement included.
	ByDivergence map[CompatDivergence]uint64
	// ByPath totals DIVERGENCES per legacy path. Agreements are deliberately
	// absent: a per-path agreement count would be one counter per request and
	// says nothing an operator acts on.
	ByPath map[LegacyPath]map[CompatDivergence]uint64
}

// Snapshot returns a deep copy of the counters.
func (r *LogCounterfactualRecorder) Snapshot() CounterfactualSnapshot {
	if r == nil {
		return CounterfactualSnapshot{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := CounterfactualSnapshot{
		ByDivergence: make(map[CompatDivergence]uint64, len(r.counts)),
		ByPath:       make(map[LegacyPath]map[CompatDivergence]uint64, len(r.perPath)),
	}
	for k, v := range r.counts {
		out.ByDivergence[k] = v
	}
	for path, byDiv := range r.perPath {
		copied := make(map[CompatDivergence]uint64, len(byDiv))
		for k, v := range byDiv {
			copied[k] = v
		}
		out.ByPath[path] = copied
	}
	return out
}

// MultiCounterfactualRecorder fans one record out to several recorders, in
// order. A nil member is skipped rather than panicking: a deployment that
// wires a metrics recorder only in one edition must not crash in the other.
type MultiCounterfactualRecorder []CounterfactualRecorder

// RecordCounterfactual implements CounterfactualRecorder.
func (m MultiCounterfactualRecorder) RecordCounterfactual(ctx context.Context, rec Counterfactual) {
	for _, r := range m {
		if r == nil {
			continue
		}
		r.RecordCounterfactual(ctx, rec)
	}
}
