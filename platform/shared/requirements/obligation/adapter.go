// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
	"strings"
)

// LegacyPolicyRow is the shape the shipped policy tables expose to the
// adapter: the three action columns plus the attribution a trace needs.
//
// THE THREE COLUMNS ARE NOT INTERCHANGEABLE and the adapter does not treat
// them as one value with two overrides:
//
//   - Action is the always-present column.
//   - ActionRequest was added NULLABLE WITH NO DEFAULT (core/039), so most
//     rows carry NULL beside a set Action. NULL means "this row says nothing
//     about the request phase", which falls back to Action. An EMPTY STRING
//     is a different fact - a row that was written with a blank value - and
//     the adapter refuses it rather than guessing which of the two it meant.
//   - ActionResponse is the response-phase column with the same NULL rules.
//
// Distinguishing NULL from empty is why these are *string and not string. A
// `string` field would have collapsed both into "" at scan time, and the
// adapter would have had to invent a rule for the collapsed value.
type LegacyPolicyRow struct {
	PolicyID       string
	PolicyName     string
	Action         string
	ActionRequest  *string
	ActionResponse *string
	// Applicability is the tri-state the condition evaluator produced for this
	// row. The adapter carries it through UNCHANGED; converting an unevaluable
	// condition into "not applicable" here is exactly the fail-open ADR-065
	// exists to close, so this field is required and has no default.
	Applicability       Applicability
	ApplicabilityReason string
	// RedactPaths are the field paths a redact action targets. Required for a
	// redact/filter mapping; a redaction with no target cannot be discharged.
	RedactPaths []string
	// ApprovalClauses are the clauses a require_approval action carries. The
	// legacy tables have no clause column, so the caller supplies them from
	// the tier/compliance configuration; an empty set is refused rather than
	// defaulted to "anyone may approve".
	ApprovalClauses       []ApprovalClause
	SeparationOfDuties    bool
	ApprovalExpirySeconds int
	// RouteDestinations are the destinations a route action permits.
	RouteDestinations []string
	// NotifyTargets are the sinks a warn/alert/log action writes to.
	NotifyTargets []AuditNotifyTarget
}

// AdaptResult is what the adapter produced, plus what it refused to produce.
type AdaptResult struct {
	Obligations []Obligation
	// Unmapped names every (policy, action) pair the adapter could not turn
	// into a typed obligation. The planner DENIES on a non-empty list. It is
	// returned rather than logged because a silently unmapped enforcement
	// instruction is the defect class this whole plane exists to remove.
	Unmapped []string
}

// legacyMapping is the closed table from a legacy action string to a typed
// obligation. Anything not in it is UNMAPPED - there is no default case, and
// a `default:` that produced "no obligation" would be the silent drop.
type legacyMapping struct {
	typ         Type
	version     int
	enforcement Enforcement
	// phase records which column this mapping is legal in. `block` and
	// `modify_risk` appear in no mapping at all; see AdaptRow.
	requestOK  bool
	responseOK bool
}

var legacyActionMappings = map[string]legacyMapping{
	// require_approval gates the request. Always mandatory: an advisory
	// approval is a contradiction - nothing would wait for it.
	"require_approval": {typ: TypeApprovalChallenge, version: 1, enforcement: Mandatory, requestOK: true},
	// redact is a disclosure transform in whichever phase the column names.
	"redact": {typ: TypeFieldRedaction, version: 1, enforcement: Mandatory, requestOK: true, responseOK: true},
	// route restricts egress.
	"route": {typ: TypeRouteRestriction, version: 1, enforcement: Mandatory, requestOK: true},
	// log is an audit record that does not gate anything: ADVISORY. The
	// legacy engine treats `log` as the weakest action on its severity scale,
	// and that intuition happens to land in the right place here - but for a
	// different reason. It is advisory because it neither transforms nor
	// holds, not because it is "less severe" than redact.
	"log": {typ: TypeImmutableAudit, version: 1, enforcement: Advisory, requestOK: true, responseOK: true},
	// warn notifies and continues: advisory.
	"warn": {typ: TypeNotification, version: 1, enforcement: Advisory, requestOK: true, responseOK: true},
	// alert notifies and is MANDATORY: an alert a policy author configured is
	// a control they expect to fire, and a lost alert is an unnoticed
	// governance event. This is a deliberate divergence from `warn`, which is
	// the same family and the same type at a different enforcement level -
	// and it is exactly the distinction a numeric severity scale cannot make.
	"alert": {typ: TypeNotification, version: 1, enforcement: Mandatory, requestOK: true, responseOK: true},
}

// AdaptRow converts one legacy policy row into typed obligations.
//
// It returns an error only for MALFORMED input (a row that cannot be
// interpreted at all). An action it does not recognise is not an error: it
// lands in Unmapped, and the planner denies on it, which puts the refusal in
// the governance path with a reason code rather than in a log line.
func AdaptRow(row LegacyPolicyRow) (AdaptResult, error) {
	var res AdaptResult

	if !row.Applicability.Valid() {
		return res, fmt.Errorf("legacy adapter: policy %s has no applicability tri-state; the adapter will not default one",
			policyLabel(row.PolicyID))
	}
	if row.Applicability == Unknown && row.ApplicabilityReason == "" {
		return res, fmt.Errorf("legacy adapter: policy %s has unknown applicability with no named reason",
			policyLabel(row.PolicyID))
	}

	// Resolve the effective action for each phase. NULL falls back to Action;
	// an explicit empty string does not.
	requestAction, err := effectiveAction(row.PolicyID, "action_request", row.Action, row.ActionRequest)
	if err != nil {
		return res, err
	}
	responseAction, err := effectiveAction(row.PolicyID, "action_response", row.Action, row.ActionResponse)
	if err != nil {
		return res, err
	}

	type phaseAction struct {
		phase  Phase
		action string
	}
	// Deduplicate: the overwhelmingly common row has ActionRequest and
	// ActionResponse both NULL, so both phases resolve to the same Action.
	// Emitting two obligations there would double every audit record and
	// double-charge every reservation.
	pending := []phaseAction{{PhaseRequest, requestAction}}
	if responseAction != requestAction || row.ActionResponse != nil {
		pending = append(pending, phaseAction{PhaseResponse, responseAction})
	}

	seen := map[string]struct{}{}
	for _, pa := range pending {
		if pa.action == "" {
			continue
		}
		// `block` is a DENY, not an obligation. It is listed here explicitly
		// so that "block is unmapped" can never be the reading: it is mapped,
		// to nothing, on purpose, because the authorization decision carries
		// it.
		if pa.action == "block" {
			continue
		}
		// `modify_risk` belongs to the inspection/risk plane
		// (platform/shared/requirements/assurance), not to obligations. It is
		// likewise deliberately not an obligation - but unlike `block` it is
		// an instruction that has to be executed SOMEWHERE, so it is reported
		// as unmapped-by-this-adapter rather than swallowed.
		if pa.action == "modify_risk" {
			res.Unmapped = append(res.Unmapped, fmt.Sprintf("%s:%s (belongs to the inspection/risk plane, not the obligation plane)",
				policyLabel(row.PolicyID), pa.action))
			continue
		}

		m, ok := legacyActionMappings[pa.action]
		if !ok {
			res.Unmapped = append(res.Unmapped, fmt.Sprintf("%s:%s", policyLabel(row.PolicyID), pa.action))
			continue
		}
		if (pa.phase == PhaseRequest && !m.requestOK) || (pa.phase == PhaseResponse && !m.responseOK) {
			res.Unmapped = append(res.Unmapped, fmt.Sprintf("%s:%s (not legal in the %s phase)",
				policyLabel(row.PolicyID), pa.action, pa.phase))
			continue
		}

		typ := m.typ
		// redact in the response phase is response_filtering, not
		// field_redaction: a different type with a different owner and a
		// different completion evidence, even though the legacy column says
		// the same word.
		if typ == TypeFieldRedaction && pa.phase == PhaseResponse {
			typ = TypeResponseFiltering
		}

		key := fmt.Sprintf("%s/%s", typ, pa.phase)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		params, err := legacyParams(row, typ)
		if err != nil {
			return res, err
		}
		// A NotApplicable or Unknown row carries no parameters: there was
		// nothing to parameterise. Obligation.Validate permits nil params in
		// exactly those two states.
		if row.Applicability != Applicable {
			params = nil
		}

		res.Obligations = append(res.Obligations, Obligation{
			Type:                typ,
			Version:             m.version,
			Enforcement:         m.enforcement,
			Applicability:       row.Applicability,
			ApplicabilityReason: row.ApplicabilityReason,
			SourcePolicyID:      legacyAttribution(row),
			Params:              params,
		})
	}

	sort.Strings(res.Unmapped)
	sort.Slice(res.Obligations, func(i, j int) bool {
		return res.Obligations[i].Type < res.Obligations[j].Type
	})
	return res, nil
}

// AdaptRows adapts many rows, accumulating obligations and unmapped actions.
func AdaptRows(rows []LegacyPolicyRow) (AdaptResult, error) {
	var out AdaptResult
	for _, r := range rows {
		res, err := AdaptRow(r)
		if err != nil {
			return AdaptResult{}, err
		}
		out.Obligations = append(out.Obligations, res.Obligations...)
		out.Unmapped = append(out.Unmapped, res.Unmapped...)
	}
	out.Unmapped = sortedUnique(out.Unmapped)
	return out, nil
}

// effectiveAction resolves a phase column against the base Action column.
func effectiveAction(policyID, column, base string, override *string) (string, error) {
	if override == nil {
		return base, nil
	}
	if strings.TrimSpace(*override) == "" {
		return "", fmt.Errorf("legacy adapter: policy %s has an empty (not NULL) %s; NULL means 'defer to action', an empty string means nothing and will not be guessed at",
			policyLabel(policyID), column)
	}
	return *override, nil
}

// legacyAttribution builds the SourcePolicyID string, preferring the id and
// falling back to the name. The WCP step gate can produce a row with a name
// and no id (see the enqueue chokepoint's validate()), and losing the
// attribution entirely would make the resulting deny unattributable.
func legacyAttribution(row LegacyPolicyRow) string {
	switch {
	case row.PolicyID != "" && row.PolicyName != "":
		return row.PolicyID + " (" + row.PolicyName + ")"
	case row.PolicyID != "":
		return row.PolicyID
	case row.PolicyName != "":
		return row.PolicyName
	}
	return ""
}

// legacyParams builds the family-typed params for a mapped type.
func legacyParams(row LegacyPolicyRow, typ Type) (Params, error) {
	switch typ {
	case TypeFieldRedaction, TypeResponseFiltering:
		if len(row.RedactPaths) == 0 {
			return nil, fmt.Errorf("legacy adapter: policy %s maps to %s but names no field paths; a redaction with no target cannot be discharged",
				policyLabel(row.PolicyID), typ)
		}
		return DisclosureParams{
			Paths: row.RedactPaths,
			// constant_redact, not remove: the shipped redactor replaces with
			// a marker rather than deleting the field, and mapping it to
			// `remove` would claim a STRONGER guarantee than the engine
			// actually provides. Claiming less than the engine does would be
			// safe; claiming more is not.
			Transform: Transform{Kind: TransformConstantRedact},
		}, nil
	case TypeApprovalChallenge:
		if len(row.ApprovalClauses) == 0 {
			return nil, fmt.Errorf("legacy adapter: policy %s maps to %s but names no approval clauses; the adapter will not default an eligible set",
				policyLabel(row.PolicyID), typ)
		}
		expiry := row.ApprovalExpirySeconds
		if expiry <= 0 {
			// 24h, matching the HITL enqueue chokepoint's DefaultExpiry, so a
			// row adapted here and a row enqueued through the legacy path do
			// not time out at different moments for the same policy.
			expiry = 24 * 60 * 60
		}
		return ApprovalParams{
			AllOf:              row.ApprovalClauses,
			SeparationOfDuties: row.SeparationOfDuties,
			ExpirySeconds:      expiry,
		}, nil
	case TypeRouteRestriction:
		if len(row.RouteDestinations) == 0 {
			return nil, fmt.Errorf("legacy adapter: policy %s maps to %s but names no destinations",
				policyLabel(row.PolicyID), typ)
		}
		return RoutingParams{AllowedDestinations: row.RouteDestinations}, nil
	case TypeImmutableAudit, TypeNotification:
		if len(row.NotifyTargets) == 0 {
			return nil, fmt.Errorf("legacy adapter: policy %s maps to %s but names no targets",
				policyLabel(row.PolicyID), typ)
		}
		return AuditNotifyParams{Targets: row.NotifyTargets}, nil
	}
	return nil, fmt.Errorf("legacy adapter: no parameter mapping for %s", typ)
}
