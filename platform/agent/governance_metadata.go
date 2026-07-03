// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Governance-plane metadata exemption (#2803, epic #2800).
//
// The plugins' pre-tool hooks govern EVERY tool call — including calls to
// AxonFlow's own governance tools. When the model calls `create_override`, the
// hook serializes the tool input (policy_id, policy_type, and the mandatory
// free-text `override_reason`) and submits it as the check_policy /
// check-input `statement`. The justification is metadata ABOUT a policy
// decision, not governed content — scanning it with the content detectors
// creates an unresolvable loop: a design partner could not create an override
// for a `.env`-documentation block because the justification explaining the
// block necessarily contained the string `.env` (the very policy being
// overridden then blocked the override request itself).
//
// The fix strips ONLY the designated free-text metadata fields from the
// serialized statement before content-policy evaluation. Everything else in
// the tool input — the override's TARGET scope (policy_id, policy_type,
// tool_signature, ttl_seconds) — is still evaluated, so content cannot be
// smuggled past governance by stuffing it into a scope field.
//
// The exemption is anchored to AxonFlow's create_override SHAPE, not merely a
// tool name (#2803 R3): it fires only when the statement is a JSON object whose
// tool-name segment is exactly `create_override` AND that carries the override's
// identifying scope fields (policy_id + policy_type). This shape guard is NOT an
// unforgeable authorization boundary — connector_type and the statement are both
// client-supplied over a cooperative gate, so a caller could always mimic the
// shape. What makes the exemption SAFE is not the guard but that the only field
// it ever drops (override_reason) is inert metadata: AxonFlow's override handler
// stores it as a length-capped justification string and never executes,
// interpolates, or otherwise makes it a sink (see overrides_handler.go). The
// guard's job is narrower — keep the exemption from silently firing on an
// unrelated third-party tool that merely shares the name — and even when it does
// fire, ONLY override_reason is removed; every other field stays and is
// evaluated. (PII typed into a justification is neither redacted nor blocked
// here, matching the pre-existing persistence path, which also stores it raw;
// redact-on-store would belong at the override repository, orthogonal to #2803.)
//
// Sibling metadata surfaces were audited for the same class and need no
// exemption (they never pass through content-policy evaluation, or carry no
// free text):
//   - HITL approval comment / override justification: HTTP-only path
//     (hitl/handler.go ReviewInput.Comment, OverrideInput.Justification) —
//     stored raw, never routed through evaluateInputPolicies.
//   - Policy descriptions: portal CRUD (static_policy_api_handlers.go) — not
//     content-scanned.
//   - Audit search (`search_audit_events` MCP tool / POST /api/v1/audit/search):
//     structured filters only (from/to/request_type/limit) — no free-text field.
//   - explain_decision / delete_override / list_overrides: identifier-only
//     arguments.
//
// Enforcement boundary: this exemption is applied ONLY at the two cooperative
// plugin-facing governance gates (check_policy tool + POST /mcp/check-input).
// The adversarial server-side proxy paths (mcp query/execute, gateway) do NOT
// apply it — they evaluate the raw statement.

import (
	"bytes"
	"encoding/json"
	"strings"
)

// governanceMetadataExemption describes one AxonFlow governance-plane tool whose
// designated free-text metadata fields are exempt from content-policy
// evaluation — but only when the statement carries the tool's identifying scope
// fields (so the exemption is bound to the AxonFlow request shape, not just a
// tool name a third party could reuse).
type governanceMetadataExemption struct {
	// exemptFields are the top-level free-text metadata fields to strip.
	exemptFields []string
	// requireFields must ALL be present for the exemption to apply. These are
	// the scope fields that identify an AxonFlow request of this shape.
	requireFields []string
}

var governanceMetadataExemptions = map[string]governanceMetadataExemption{
	"create_override": {
		exemptFields:  []string{"override_reason"},
		requireFields: []string{"policy_id", "policy_type"},
	},
}

// stripLogCRLF removes CR/LF from a value before it is written to a log line,
// preventing log-line forgery via a crafted (client-supplied) connector_type.
func stripLogCRLF(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}

// governedToolName extracts the bare tool name from a client-supplied
// connector_type. The plugins derive connector_type as
// "<client>.<ToolName>" (e.g. "claude_code.Bash"), and MCP tools carry the
// server-qualified form "<client>.mcp__<server>__<tool>" — the MCP server
// name is user-chosen, so only the final segment identifies the tool. The
// segment is returned verbatim (no case-folding): AxonFlow's own tools are
// registered lowercase, and case-folding would only widen the match surface.
func governedToolName(connectorType string) string {
	name := connectorType
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	} else if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// stripGovernanceMetadata removes the exempt free-text metadata fields for a
// governance-plane tool call from its serialized JSON statement, returning the
// sanitized statement plus the names of the stripped fields. The statement is
// returned UNCHANGED (nil fields) — i.e. evaluated in full, fail-closed —
// whenever we cannot be certain it is an AxonFlow governance request:
//   - the tool-name segment is not a known governance tool,
//   - the statement is not a JSON object,
//   - the statement lacks the tool's required scope fields (so a third-party
//     tool with the same name is not exempted),
//   - the statement has duplicate top-level keys (a re-serialize would collapse
//     them and could drop content from a KEPT scope field — #2803 R3), or
//   - re-serialization fails.
//
// Only TOP-LEVEL fields are stripped: the hooks serialize the tool input as a
// flat argument object, and a nested same-named key is somebody's payload, not
// our metadata.
func stripGovernanceMetadata(connectorType, statement string) (string, []string) {
	ex, ok := governanceMetadataExemptions[governedToolName(connectorType)]
	if !ok {
		return statement, nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(statement), &obj); err != nil || obj == nil {
		return statement, nil
	}

	// Bind the exemption to the AxonFlow request shape: every required scope
	// field must be present, else this is not our governance request.
	for _, f := range ex.requireFields {
		if _, present := obj[f]; !present {
			return statement, nil
		}
	}

	// Duplicate top-level keys would be silently collapsed to the last value on
	// re-serialization, which could drop dangerous content from a KEPT scope
	// field (the encoding/json "last wins" rule). Fail closed: evaluate raw.
	if hasDuplicateTopLevelKey(statement) {
		return statement, nil
	}

	var stripped []string
	for _, f := range ex.exemptFields {
		if _, present := obj[f]; present {
			delete(obj, f)
			stripped = append(stripped, f)
		}
	}
	if len(stripped) == 0 {
		return statement, nil
	}

	// Re-serialize WITHOUT HTML escaping: json.Marshal would rewrite `>` as
	// `>`, which hides shell-redirection shapes (`echo x > .env`) in the
	// REMAINING scope fields from the content detectors — the exact smuggle
	// this exemption must not enable. The plugins serialize tool input with
	// `jq -c` (no HTML escaping), so this also stays byte-faithful to what
	// an ungoverned field would have looked like.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		// Fail-closed: evaluate the original statement in full.
		return statement, nil
	}
	return strings.TrimRight(buf.String(), "\n"), stripped
}

// hasDuplicateTopLevelKey reports whether the top-level JSON object in statement
// contains the same key more than once. It scans the token stream (encoding/json
// preserves every key token, unlike Unmarshal which keeps only the last), so a
// smuggle attempt like {"tool_signature":"echo x > .env","tool_signature":"ok"}
// is detected and the caller falls back to evaluating the raw statement.
//
// After the opening `{`, tokens alternate key, value, key, value, …; a value
// that is itself an object/array is consumed whole (by nesting depth) so its
// inner keys are never mistaken for top-level keys.
func hasDuplicateTopLevelKey(statement string) bool {
	dec := json.NewDecoder(strings.NewReader(statement))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return false
	}
	seen := make(map[string]struct{})
	for dec.More() {
		// Next token is a top-level key (always a string in a JSON object).
		keyTok, err := dec.Token()
		if err != nil {
			return false
		}
		key, ok := keyTok.(string)
		if !ok {
			return false
		}
		if _, dup := seen[key]; dup {
			return true
		}
		seen[key] = struct{}{}

		// Consume the value. If it opens a nested object/array, skip to its
		// matching close so nested keys are not counted as top-level.
		valTok, err := dec.Token()
		if err != nil {
			return false
		}
		if d, ok := valTok.(json.Delim); ok && (d == '{' || d == '[') {
			depth := 1
			for depth > 0 {
				t, err := dec.Token()
				if err != nil {
					return false
				}
				if dd, ok := t.(json.Delim); ok {
					if dd == '{' || dd == '[' {
						depth++
					} else {
						depth--
					}
				}
			}
		}
	}
	return false
}
