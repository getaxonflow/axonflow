// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Indonesia PII detection-event persistence seam (#3242, epic #2892).
//
// # The gap this closes
//
// The Indonesia PII detector already DETECTS, BLOCKS, redacts and metricises
// NIK / NPWP / +62 / bank-account values on three enforcement planes -- the
// gateway pre-check (gateway_handlers.go), the Decision API
// (decision_handler.go) and the MCP response path (mcp_handler.go) -- and it
// computes an OJK category for every hit. None of that reached any exportable
// surface, so the OJK exporter's `pii_redactions` section had no source and
// returned a silent, successful, empty section to a regulator.
//
// # Build-tag seam
//
// This file is UNTAGGED and declares a nil hook. The enterprise-only
// implementation (indonesia_pii_events_enterprise.go) wires it in init(). In a
// community build the hook stays nil, recordIndonesiaPIIEvents is a cheap
// nil-check return, and no statement is issued -- behaviour is byte-identical
// to before this change. This mirrors the proven stampCrossBorderTransfer seam
// (platform/orchestrator/cross_border_audit.go, #2718). The seam is needed
// because the destination table ships in migrations/enterprise/137, which a
// community deployment never applies: a community build that tried to write it
// would fail on every request carrying Indonesia PII.
//
// # What is recorded
//
// Detection EVENTS, never a new PII store. Only the detector's MaskedValue is
// persisted. The raw match and the detector's `Context` window (free text lifted
// from the caller's query, which would re-introduce exactly what masking
// removes) are deliberately dropped at this boundary -- see
// indonesiaPIIEventFrom, which constructs the event from named fields rather
// than copying the detection struct, so a future field added to
// IndonesiaPIIDetectionResult cannot silently start flowing to the database.

import (
	"context"

	"axonflow/platform/agent/indonesia"
)

// Actions recorded against a detection event: what the platform DID about it.
// These are the vocabulary the enterprise/137 CHECK constraint enforces.
const (
	// indonesiaPIIActionBlocked: the request/response was REFUSED because of
	// this detection (PII_ACTION=block on critical PII).
	indonesiaPIIActionBlocked = "blocked"
	// indonesiaPIIActionRedacted: this plane MASKED the value before the content
	// moved on. Only the MCP response path can claim this, because it is the
	// only plane that mutates content itself, and it claims it only when the
	// mask actually changed something.
	indonesiaPIIActionRedacted = "redacted"
	// indonesiaPIIActionRedactionRequired: the PDP determined the content
	// required redaction and said so to the PEP -- it did NOT mask anything
	// itself.
	//
	// This value exists because the gateway pre-check and /api/v1/decide are
	// POLICY DECISION POINTS: the gateway sets RequiresRedaction on its response
	// and /decide emits a redact_pii OBLIGATION; the calling SDK does the
	// masking. Recording those as "redacted" told a regulator the platform had
	// masked the value when it had only asked someone else to, and it did so
	// even on paths where the obligation was subsequently never emitted (a
	// later deny drops it). "We required redaction here" is true in every one of
	// those cases; "we redacted it" is not.
	indonesiaPIIActionRedactionRequired = "redaction_required"
	// indonesiaPIIActionDetected: observed under a warn/log posture (or with
	// detection disabled for this org's action) and the content was NOT
	// modified. Recording it is the point: an auditor must be able to find
	// "PII was present here and we did not mask it".
	indonesiaPIIActionDetected = "detected"
)

// maxIndonesiaPIIEventsPerRequest bounds how many detection rows a single
// request can write. A pathological payload (a pasted spreadsheet of NIKs) must
// not turn one request into thousands of INSERTs. When the cap trims the batch
// the event count is still truthful in the metric
// (axonflow_indonesia_pii_events_dropped_total{reason="capped"}), so a silent
// truncation is observable rather than presented as full coverage.
const maxIndonesiaPIIEventsPerRequest = 100

// indonesiaPIIEvent is one persisted detection. Field-for-field this is the
// enterprise/137 row shape; it carries NO raw value and no context window.
type indonesiaPIIEvent struct {
	// PIIType is the detector's IndonesiaPIIType (nik, npwp_legacy, ...).
	PIIType string
	// OJKCategory is the regulator-facing grouping the detector computes
	// (national_identity | tax_identifier | contact_information |
	// financial_account).
	OJKCategory string
	Severity    string
	// MaskedValue is the detector's MaskedValue. Never the raw match.
	MaskedValue string
	Confidence  float64
}

// indonesiaPIIEventBatch is one plane's detections for one request.
type indonesiaPIIEventBatch struct {
	// OrgID is the RLS isolation key. Empty means the batch is dropped: an
	// unscoped write is refused by the enterprise/137 WITH CHECK anyway, and
	// planting a row nothing can scope is the failure mode core/155+156 exist to
	// prevent.
	OrgID string
	// TenantID is descriptive (a real, DIFFERENT v9 identifier, #3071). It is
	// never an isolation predicate.
	TenantID string
	// DecisionID / CorrelationID let an auditor pivot from a redaction event to
	// the audit_logs row carrying the verdict. Either may be empty.
	DecisionID    string
	CorrelationID string
	// Plane is gateway | decision | mcp (the enterprise/137 CHECK vocabulary).
	Plane string
	// Action is one of the indonesiaPIIAction* constants.
	Action string
	Events []indonesiaPIIEvent
}

// persistIndonesiaPIIEvents is the enterprise hook. nil in a community build.
// Assigned exactly once, from init() in indonesia_pii_events_enterprise.go.
var persistIndonesiaPIIEvents func(ctx context.Context, batch indonesiaPIIEventBatch)

// recordIndonesiaPIIEvents converts a detector check result into persisted
// detection events for one plane.
//
// BEST EFFORT, and deliberately so: enforcement has ALREADY happened by the time
// this is called (the block is held, the value is masked). A database hiccup
// must never convert an enforced block into a 5xx, so the implementation logs
// and increments a counter rather than returning an error. It is not SILENT --
// every drop reason is counted.
//
// It is a no-op when: the hook is nil (community build), the result carries no
// detections, or orgID is blank.
func recordIndonesiaPIIEvents(
	ctx context.Context,
	orgID, tenantID, decisionID, correlationID, plane, action string,
	result *indonesia.IndonesiaPIICheckResult,
) {
	hook := persistIndonesiaPIIEvents
	if hook == nil {
		return
	}
	if result == nil || len(result.Detections) == 0 {
		return
	}
	batch := indonesiaPIIEventBatch{
		OrgID:         orgID,
		TenantID:      tenantID,
		DecisionID:    decisionID,
		CorrelationID: correlationID,
		Plane:         plane,
		Action:        action,
		Events:        indonesiaPIIEventsFrom(result.Detections),
	}
	if len(batch.Events) == 0 {
		return
	}
	hook(ctx, batch)
}

// indonesiaPIIEventsFrom projects detector results onto the persisted event
// shape. It copies NAMED fields only -- never the struct -- so a field added to
// IndonesiaPIIDetectionResult (a new raw-bearing field, say) cannot start
// flowing to the database without an explicit edit here. Detections whose
// MaskedValue is empty are dropped rather than written blank: the enterprise/137
// CHECK would refuse them and take the whole batch down with them.
func indonesiaPIIEventsFrom(detections []indonesia.IndonesiaPIIDetectionResult) []indonesiaPIIEvent {
	out := make([]indonesiaPIIEvent, 0, len(detections))
	for _, d := range detections {
		if d.MaskedValue == "" || d.OJKCategory == "" {
			continue
		}
		out = append(out, indonesiaPIIEvent{
			PIIType:     string(d.Type),
			OJKCategory: d.OJKCategory,
			Severity:    string(d.Severity),
			MaskedValue: d.MaskedValue,
			Confidence:  d.Confidence,
		})
	}
	return out
}

// indonesiaPIIActionForEnforcedPlane maps the outcome on a plane that MASKS
// content itself (today: the MCP response path). `masked` must reflect whether
// content actually changed, not merely whether the redact posture was active.
func indonesiaPIIActionForEnforcedPlane(blocked, masked bool) string {
	switch {
	case blocked:
		return indonesiaPIIActionBlocked
	case masked:
		return indonesiaPIIActionRedacted
	default:
		return indonesiaPIIActionDetected
	}
}

// indonesiaPIIActionForDecisionPlane maps the outcome on a POLICY DECISION
// POINT -- the gateway pre-check and /api/v1/decide -- which never masks
// anything itself. `redactionRequired` is the PDP's determination that the
// content requires redaction; the recorded action says exactly that and never
// claims the platform performed a mask it did not perform.
func indonesiaPIIActionForDecisionPlane(blocked, redactionRequired bool) string {
	switch {
	case blocked:
		return indonesiaPIIActionBlocked
	case redactionRequired:
		return indonesiaPIIActionRedactionRequired
	default:
		return indonesiaPIIActionDetected
	}
}
