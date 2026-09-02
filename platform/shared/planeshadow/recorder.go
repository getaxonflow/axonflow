// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"log"
	"strings"
	"sync/atomic"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
	logutil "axonflow/platform/shared/logger"
)

// Comparison is one recorded dual-evaluation.
//
// Every field is a plane name, a classification, a reason code, a policy row
// key, an organization id or a count. NO CONTENT, for Observation's reason:
// this record is logged, and a record that can carry request content is a
// record that leaks it into a log aggregator.
type Comparison struct {
	// Component names the binary that recorded it. Two processes evaluate
	// planes and both log under the same prefix, so without this a difference
	// cannot be attributed to a plane except by which container's log it came
	// from - and gate 18 is stated per plane. Same argument as
	// identity.Counterfactual.Component.
	Component string
	// Mode is the mode this comparison ran under, resolved for THIS
	// organization, so a record from an organization shadowing on a
	// process-wide off deployment reads shadow and can be told apart from the
	// deployment's default.
	Mode Mode
	// Plane and Phase identify the enforcement surface.
	Plane legacycompile.Plane
	Phase legacycompile.Phase
	// OrgID is the authenticated organization; OrgScope is the policy load
	// scope. Both, because they differ on three call sites (#3490) and a
	// difference attributed to the wrong one sends an operator to the wrong
	// tenant.
	OrgID    string
	OrgScope string
	// Tool is the governed tool or connector identity the plane reported, for
	// ATTRIBUTION only.
	//
	// It deliberately does not address the ADR-065 request: a compiled world
	// registers one action, and naming anything else denies for
	// unknown_action (see caseFor). It is carried here so a difference can
	// still be traced to the tool it came from, which is what an operator
	// actually needs it for.
	Tool string
	// SampleRate is the rate in force. A record whose sampling rate is unknown
	// cannot have its denominator interpreted, and gate 18 is a statement
	// about a population rather than about a sample of unknown size.
	SampleRate float64
	// Record is the classified difference.
	Record shadow.DiffRecord
	// BundleDigest is the signed bundle the ADR-065 side was evaluated
	// against. A replay that cannot name the bundle it was measured against is
	// not a replay (CAPTURE.md), and rollback by immutable bundle digest is
	// one of epic #3552's exit criteria.
	BundleDigest string
	// PolicySnapshot is the digest of the policy set the PLANE evaluated, and
	// therefore the set the bundle was proven to match.
	PolicySnapshot string

	// THE RESET STAMPS. See versions.go for why BundleDigest alone cannot
	// carry them: it is derived from the policy ROWS, so it is byte-identical
	// across every change to the code that reads, translates, evaluates and
	// classifies them.
	//
	// EvaluatorVersion moves when the classifier's semantics or the OPA build
	// change. AdapterVersion moves when the translation from a plane's
	// evaluation to a PDP question changes. SiteVersion moves when the
	// emitting plane's own observation site changes, which is the one an
	// operator would otherwise never see: a site can start reporting a
	// different set of row facts with no change anywhere else in this package.
	//
	// Together they make a gate-18 reset boundary a property OF THE RECORDS.
	// A window is one window only across records that agree on all three; a
	// change to any of them ends the window at that instant, and the records
	// on either side say so without anyone reconstructing it from git.
	EvaluatorVersion string
	AdapterVersion   string
	// SiteVersion is EMPTY for a call site that does not stamp one, and that
	// is not an error here: an unstamped site is a site whose changes are
	// invisible to the reset rule, which is a coverage gap rather than a
	// corrupt record, and dropping the comparison would trade evidence for
	// tidiness. TestEveryObservationSiteStampsItsVersion is what keeps the gap
	// from opening.
	SiteVersion string
}

// Recorder receives every completed comparison.
//
// A shadow phase that records nothing is a shadow phase that has not run, so
// the observer refuses a nil recorder - identity.NewCompatAdapter's argument,
// and the same failure it prevents.
type Recorder interface {
	// RecordComparison is called exactly once per completed comparison, on a
	// worker goroutine and never on the request path.
	RecordComparison(ctx context.Context, c Comparison)
}

// MultiRecorder fans a comparison out. A nil member is SKIPPED rather than
// refused, because an edition that wires no metrics recorder is a legitimate
// fan-out; a fan-out whose every member is nil is not, and the constructor
// refuses that (recorderRecordsNothing).
type MultiRecorder []Recorder

func (m MultiRecorder) RecordComparison(ctx context.Context, c Comparison) {
	for _, r := range m {
		if r == nil {
			continue
		}
		r.RecordComparison(ctx, c)
	}
}

// recorderRecordsNothing returns a non-empty reason when this recorder is one
// of the shapes that constructs successfully and then records NOTHING.
//
// It tests the SHAPES that cannot record, named one at a time, rather than a
// reflective proxy for them: reflect.Value.IsZero on a slice is IsNil, so it
// catches only the accidental `var m MultiRecorder` spelling while
// `MultiRecorder{}` - what anyone writing a fan-out actually types - sails
// through, and it refuses a legitimate stateless `struct{}` recorder with a
// value receiver. That mistake was made once already, in
// identity.recorderRecordsNothing's own history.
func recorderRecordsNothing(r Recorder) string {
	if r == nil {
		return "no recorder was supplied"
	}
	switch v := r.(type) {
	case *LogRecorder:
		if v == nil {
			return "the log recorder is a typed nil, whose RecordComparison returns immediately"
		}
	case MultiRecorder:
		for _, member := range v {
			if member != nil && recorderRecordsNothing(member) == "" {
				return ""
			}
		}
		return "the fan-out has no member that records anything"
	}
	return ""
}

// MetricsRecorder exports every comparison as counters. It is stateless and is
// a value receiver deliberately: it records perfectly well as a zero value,
// which is why recorderRecordsNothing tests shapes rather than zero-ness.
type MetricsRecorder struct{}

func (MetricsRecorder) RecordComparison(_ context.Context, c Comparison) {
	plane := string(c.Plane)
	shadowComparisons.WithLabelValues(plane, string(c.Record.Class)).Inc()
	shadowFailOpen.WithLabelValues(plane, string(c.Record.FailOpen), string(c.Record.Class)).Inc()
}

// LogRecorder writes one line per comparison.
//
// # IT DOES NOT LOG EVERY MATCH
//
// A match is the expected outcome on a healthy migration, so logging every one
// of them turns the signal into a line an operator has to filter out of every
// request. Matches are counted (MetricsRecorder) and sampled into the log at a
// low rate so the log is not silent about what the shadow is doing; every
// expected_change and every UNEXPLAINED is logged in full, because those are
// the two an operator must be able to find without a metrics stack.
type LogRecorder struct {
	// MatchEvery logs one match in N. Zero or negative logs none.
	MatchEvery uint64

	// matches is ATOMIC because RecordComparison runs on every worker
	// goroutine at once - cfg.Workers of them, two by default and up to 64 -
	// and this recorder is wired into every production deployment by
	// Bootstrap. A plain uint64 here is a data race by the Go memory model:
	// undefined behaviour, not merely a miscounted sampling interval.
	//
	// It was a plain field, and nothing in this repository would have caught
	// it: no CI job runs the race detector over platform/agent, and the one
	// test that drives the observer with real workers wires MetricsRecorder
	// only. TestTheLogRecorderIsSafeUnderConcurrentWorkers now does, under
	// -race.
	matches atomic.Uint64
}

// NewLogRecorder builds the log recorder.
func NewLogRecorder(matchEvery uint64) *LogRecorder {
	return &LogRecorder{MatchEvery: matchEvery}
}

func (l *LogRecorder) RecordComparison(_ context.Context, c Comparison) {
	if l == nil {
		return
	}
	if c.Record.Class == shadow.ClassMatch {
		n := l.matches.Add(1)
		if l.MatchEvery == 0 || n%l.MatchEvery != 0 {
			return
		}
	}
	detail := c.Record.Detail
	if c.Record.RuleID != "" {
		detail = c.Record.RuleID + ": " + detail
	}
	// The three reset stamps ride the LOG LINE as well as the record, because
	// the log is the only surface a deployment without a metrics stack has,
	// and "which window does this record belong to" is unanswerable without
	// them. Truncated like the bundle digest: a log line needs enough to
	// correlate and to notice a change, not enough to verify.
	log.Printf("[DECISION-SHADOW] component=%s mode=%s plane=%s phase=%s org=%s scope=%s class=%s fail_open=%s rate=%.3f bundle=%s eval=%s adapter=%s site=%s legacy_exec=%t new_exec=%t determining=%s defects=%s detail=%s",
		logutil.Sanitize(c.Component),
		strings.ToLower(c.Mode.String()),
		logutil.Sanitize(string(c.Plane)),
		logutil.Sanitize(string(c.Phase)),
		logutil.Sanitize(c.OrgID),
		logutil.Sanitize(c.OrgScope),
		c.Record.Class,
		c.Record.FailOpen,
		c.SampleRate,
		short(c.BundleDigest),
		short(c.EvaluatorVersion),
		short(c.AdapterVersion),
		short(c.SiteVersion),
		c.Record.Legacy.Executable,
		c.Record.New.Executable,
		logutil.Sanitize(strings.Join(shadow.SourceDetermining(c.Record.Legacy), ",")),
		logutil.Sanitize(strings.Join(c.Record.PreservedDefects, ",")),
		logutil.Sanitize(detail),
	)
}

// short truncates a digest for a log line. The full digest is on the record;
// a log line needs enough to correlate, not enough to verify.
func short(digest string) string {
	if len(digest) <= 12 {
		return digest
	}
	return digest[:12]
}
