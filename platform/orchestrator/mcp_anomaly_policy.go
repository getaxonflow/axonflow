// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"fmt"
	"time"
)

// Layer-4 anomaly policy evaluation for the MCP dynamic policy path (#2522).
//
// A design partner's Risk-Committee operating model (§6.2 "Layer 4: Anomaly Alerts")
// requires three controls that the original MCP dynamic engine could not express:
//
//   1. Off-hours access — requests outside business hours 07:00–22:00 in a named
//      timezone (Asia/Jakarta / WIB for the design partner). The pre-existing time-access
//      evaluator only compared the server's local-clock hour, so it could neither
//      anchor a window to a customer timezone nor model an allowed business-hours
//      band that wraps the comparison correctly.
//   2. Bulk retrieval — a single MCP session pulling more than N individual
//      merchant records (>500 per R&C §6.2). The caller (the PEP/MCP server, which
//      already counts the rows it returns per Layer-1 logging) supplies the running
//      session record count; AxonFlow evaluates the threshold rule.
//   3. Volume anomaly — a leader's query volume exceeding a multiple (3× per R&C)
//      of their rolling baseline. The 30-day rolling baseline is computed by the
//      Layer-3/Layer-4 audit pipeline (BigQuery → SIEM); the caller supplies both
//      the current session volume and the baseline, and AxonFlow evaluates the
//      multiplier rule. AxonFlow does NOT itself maintain the 30-day history — see
//      the evidence pack for this boundary; this evaluator is the policy decision
//      point, not the metrics store.
//
// Anomaly policies carry policy_type = "anomaly". Their action governs the
// outcome via actionDenies(): block / require_approval hold the request
// (allowed=false), while alert / warn / log surface the match for the SIEM
// without stopping the call (allowed=true). This mirrors the R&C's
// "alert / require_approval" Layer-4 disposition.

// businessHoursWindow describes an allowed access window anchored to a timezone.
type businessHoursWindow struct {
	timezone string // IANA location, e.g. "Asia/Jakarta"
	start    int    // inclusive start hour [0,24)
	end      int    // exclusive end hour (0,24]; access allowed for start <= hour < end
	hasStart bool
	hasEnd   bool
}

// actionDenies reports whether a matched policy action should stop the request
// from proceeding automatically. block stops it outright; require_approval pauses
// it pending human sign-off (so the auto-flow does not continue). alert / warn /
// log are observability dispositions that record the anomaly but allow the call.
func actionDenies(action string) bool {
	switch action {
	case "block", "require_approval":
		return true
	default:
		return false
	}
}

// firstActionType returns the action type of the policy's first action, or "" if
// the policy declares no actions.
func firstActionType(policy DynamicPolicy) string {
	if len(policy.Actions) > 0 {
		return policy.Actions[0].Type
	}
	return ""
}

// toFloat coerces a JSON-decoded numeric (float64), an int, or a numeric string
// into a float64. Returns ok=false for non-numeric values.
func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		var f float64
		if _, err := fmt.Sscanf(n, "%g", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

// numericCompare applies a comparison operator between two float64 values.
// Unknown operators return false (fail closed for the match, not the request).
func numericCompare(actual, threshold float64, operator string) bool {
	switch operator {
	case "greater_than", "gt":
		return actual > threshold
	case "greater_or_equal", "gte":
		return actual >= threshold
	case "less_than", "lt":
		return actual < threshold
	case "less_or_equal", "lte":
		return actual <= threshold
	case "equals", "eq":
		return actual == threshold
	default:
		return false
	}
}

// lookupNumeric resolves a numeric value for an anomaly condition field from the
// request. Bulk-retrieval and volume signals are supplied by the caller in
// Metadata (preferred) or Parameters, since the PEP/MCP server is the component
// that counts records and tracks per-session volume.
func lookupNumeric(req MCPPolicyEvaluationRequest, key string) (float64, bool) {
	if req.Metadata != nil {
		if v, ok := req.Metadata[key]; ok {
			if f, ok := toFloat(v); ok {
				return f, true
			}
		}
	}
	if req.Parameters != nil {
		if v, ok := req.Parameters[key]; ok {
			if f, ok := toFloat(v); ok {
				return f, true
			}
		}
	}
	return 0, false
}

// evaluateAnomaly evaluates a Layer-4 anomaly policy (bulk retrieval and/or
// volume multiplier). All declared conditions must hold for the policy to match
// (AND semantics, consistent with the rest of the dynamic engine). A policy that
// declares no recognized anomaly condition does not match (fail open — it cannot
// silently block every request).
//
// Recognized condition fields:
//
//   - session_record_count: numeric compare of the caller-supplied per-session
//     record count (Metadata/Parameters["session_record_count"]) against value.
//     Models R&C bulk retrieval (>500 records/session).
//   - volume_ratio: computed ratio of session_volume / baseline_volume (both from
//     Metadata/Parameters) compared against value. Models R&C 3× baseline. The
//     condition does not match when the baseline is absent or non-positive, so a
//     cold start (no baseline yet) never spuriously fires.
func (h *MCPDynamicPolicyHandler) evaluateAnomaly(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	if len(policy.Conditions) == 0 {
		return false, true, ""
	}

	var reasons []string

	for _, cond := range policy.Conditions {
		switch cond.Field {
		case "session_record_count", "record_count":
			actual, ok := lookupNumeric(req, cond.Field)
			if !ok {
				// Signal not provided by the caller — this condition cannot match.
				return false, true, ""
			}
			threshold, ok := toFloat(cond.Value)
			if !ok || !numericCompare(actual, threshold, cond.Operator) {
				return false, true, ""
			}
			reasons = append(reasons, fmt.Sprintf("bulk retrieval: %.0f records this session (%s %.0f)", actual, cond.Operator, threshold))

		case "volume_ratio":
			session, sOK := lookupNumeric(req, "session_volume")
			baseline, bOK := lookupNumeric(req, "baseline_volume")
			if !sOK || !bOK || baseline <= 0 {
				// Without a positive baseline the multiplier rule is undefined; do
				// not match (avoids cold-start false positives).
				return false, true, ""
			}
			ratio := session / baseline
			multiplier, ok := toFloat(cond.Value)
			if !ok || !numericCompare(ratio, multiplier, cond.Operator) {
				return false, true, ""
			}
			reasons = append(reasons, fmt.Sprintf("volume anomaly: %.0f vs baseline %.0f = %.1f× (%s %.1f)", session, baseline, ratio, cond.Operator, multiplier))

		default:
			// Unknown condition field for an anomaly policy: do not match.
			return false, true, ""
		}
	}

	reason := "Layer-4 anomaly detected"
	if len(reasons) > 0 {
		reason = "Layer-4 anomaly — " + joinReasons(reasons)
	}
	if r := actionReason(policy); r != "" {
		reason = r
	}

	return true, !actionDenies(firstActionType(policy)), reason
}

// joinReasons concatenates anomaly reason fragments without pulling in strings
// just for a single join (keeps the dependency surface small).
func joinReasons(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out
}

// actionReason extracts a custom reason string from the policy's first action
// config, if present.
func actionReason(policy DynamicPolicy) string {
	if len(policy.Actions) == 0 || policy.Actions[0].Config == nil {
		return ""
	}
	if r, ok := policy.Actions[0].Config["reason"].(string); ok {
		return r
	}
	return ""
}

// parseBusinessHoursWindow extracts a timezone-anchored business-hours window
// from a time-access policy's conditions. Supported condition fields:
//
//   - timezone:             IANA location string (e.g. "Asia/Jakarta")
//   - business_hours_start: inclusive window start hour [0,24)
//   - business_hours_end:   exclusive window end hour (0,24]
//
// Returns ok=false when no business-hours window is declared, so the caller can
// fall back to the legacy hour/day comparison for backward compatibility.
func parseBusinessHoursWindow(policy DynamicPolicy) (businessHoursWindow, bool) {
	var w businessHoursWindow
	declared := false

	for _, cond := range policy.Conditions {
		switch cond.Field {
		case "timezone":
			if tz, ok := cond.Value.(string); ok && tz != "" {
				w.timezone = tz
				declared = true
			}
		case "business_hours_start":
			if v, ok := toFloat(cond.Value); ok {
				w.start = int(v)
				w.hasStart = true
				declared = true
			}
		case "business_hours_end":
			if v, ok := toFloat(cond.Value); ok {
				w.end = int(v)
				w.hasEnd = true
				declared = true
			}
		}
	}

	return w, declared && (w.hasStart || w.hasEnd)
}

// businessHoursReason renders a human-readable off-hours reason that is correct
// even for a one-sided window (only a start, or only an end declared), so a
// partial window never prints a misleading "00:00" bound.
func businessHoursReason(w businessHoursWindow) string {
	tz := w.timezone
	if tz == "" {
		tz = "UTC"
	}
	switch {
	case w.hasStart && w.hasEnd:
		return fmt.Sprintf("Access outside business hours (%02d:00–%02d:00 %s)", w.start, w.end, tz)
	case w.hasStart:
		return fmt.Sprintf("Access before business hours (opens %02d:00 %s)", w.start, tz)
	case w.hasEnd:
		return fmt.Sprintf("Access after business hours (closes %02d:00 %s)", w.end, tz)
	default:
		return "Access outside business hours"
	}
}

// outsideBusinessHours reports whether the given instant, interpreted in the
// window's timezone, falls outside the allowed [start, end) business-hours band.
// An unparseable timezone falls back to the instant's own location rather than
// silently treating every request as in-hours.
func outsideBusinessHours(w businessHoursWindow, at time.Time) bool {
	loc := at.Location()
	if w.timezone != "" {
		if parsed, err := time.LoadLocation(w.timezone); err == nil {
			loc = parsed
		}
	}
	hour := at.In(loc).Hour()

	if w.hasStart && hour < w.start {
		return true
	}
	if w.hasEnd && hour >= w.end {
		return true
	}
	return false
}
