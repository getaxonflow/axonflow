// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"fmt"
	"sort"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// The once-only upgrade import of legacy per-policy overrides (PRD v11 §1.5,
// migrations/core/183).
//
// v11 controls the shipped set through the organization's typed document, and
// no enforcing engine reads policy_overrides. An organization upgrading from
// v10 may carry customer settings there, so this translates its rows ONCE into
// an unpublished draft - the shipped organization template plus a
// system_controls section - and records it in typed_policy_import_drafts, with
// every row it did not carry and why. Nothing is published or activated: the
// organization reviews the draft in the editor and publishes it.

// policyOverrideImportActor is the recorded actor of every import.
const policyOverrideImportActor = "system:upgrade-import"

// policyOverrideImportAuthor is the draft's author. The canonical principal
// vocabulary has no system type, so the import writes as the platform's
// internal service; a publication records the publishing session instead.
var policyOverrideImportAuthor = contract.ID{
	Kind: contract.KindPrincipal, Type: "Service", Qualifier: "axonflow-internal-service", Local: "upgrade-import",
}

// importCandidate is one policy_overrides row, as
// typed_policy_import_candidates() returns it.
type importCandidate struct {
	OverrideID  string
	TenantID    sql.NullString
	PolicyTable string // static_policies or dynamic_policies
	PolicyID    string // the legacy row's text id; empty when the row names none
	Enabled     sql.NullBool
	Action      sql.NullString
	Revoked     bool
	Expired     bool
	BreakGlass  bool // the row carries a tool signature (ADR-044)
}

// importSkip is one row the import did not carry into the draft. Code is the
// save-time code the entry would have been refused with, when that is why.
type importSkip struct {
	OverrideID string `json:"override_id"`
	Control    string `json:"control,omitempty"`
	Code       string `json:"code,omitempty"`
	Reason     string `json:"reason"`
}

// importRecord is what typed_policy_import_drafts records for one organization.
type importRecord struct {
	SourceRows  int
	Imported    int
	Skipped     []importSkip
	Draft       []byte // the draft's exact canonical bytes; nil when nothing was carried
	DraftDigest string
}

// buildImportRecord translates one organization's rows.
//
// A row is carried only when it is organization-wide, unrevoked, unexpired,
// not break-glass, and changes a shipped control: enabled false leaves the
// control out, and an action replaces its own. Rows that disagree about one
// control are all skipped. Every entry is proposed through the save-time checks
// alone, so a dynamic control's re-action (#4187), an action outside the four,
// or a row naming no shipped control is skipped with the code an author would
// be refused with, never written unvalidated.
func buildImportRecord(rows []importCandidate) (*importRecord, error) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, fmt.Errorf("the organization template: %w", err)
	}
	rec := &importRecord{SourceRows: len(rows), Skipped: []importSkip{}}
	skip := func(overrideID, control, code, reason string) {
		rec.Skipped = append(rec.Skipped, importSkip{OverrideID: overrideID, Control: control, Code: code, Reason: reason})
	}

	type proposal struct {
		entry     authoring.SystemControlEntry
		overrides []string
		conflict  bool
	}
	proposals := map[string]*proposal{}
	for _, r := range rows {
		switch {
		case r.TenantID.Valid:
			skip(r.OverrideID, "", "", "tenant-scoped: an organization's document has no tenant scope")
			continue
		case r.Revoked:
			skip(r.OverrideID, "", "", "revoked")
			continue
		case r.Expired:
			skip(r.OverrideID, "", "", "expired")
			continue
		case r.BreakGlass || r.Action.String == "allow":
			skip(r.OverrideID, "", "", "break-glass (ADR-044): it stays in policy_overrides")
			continue
		case r.PolicyID == "":
			skip(r.OverrideID, "", "", "names no legacy policy")
			continue
		}
		control, _, _ := legacycompile.CorpusControlOf(legacycompile.CorpusPolicyIDFor(r.PolicyTable, r.PolicyID))
		entry := authoring.SystemControlEntry{Control: control}
		switch {
		case r.Enabled.Valid && !r.Enabled.Bool:
			disabled := false
			entry.Enabled = &disabled
		case r.Action.Valid:
			entry.Action = legacycompile.LegacyAction(r.Action.String)
		default:
			skip(r.OverrideID, control, "", "changes nothing: the control as shipped")
			continue
		}
		if p, seen := proposals[control]; seen {
			p.conflict = p.conflict || p.entry.Disabled() != entry.Disabled() || p.entry.Action != entry.Action
			p.overrides = append(p.overrides, r.OverrideID)
			continue
		}
		proposals[control] = &proposal{entry: entry, overrides: []string{r.OverrideID}}
	}

	controls := make([]string, 0, len(proposals))
	for control := range proposals {
		controls = append(controls, control)
	}
	sort.Strings(controls)
	var entries []authoring.SystemControlEntry
	for _, control := range controls {
		p := proposals[control]
		if p.conflict {
			for _, id := range p.overrides {
				skip(id, control, "", "disagrees with another override of the same control")
			}
			continue
		}
		probe := &authoring.Document{Policy: *template, SystemControls: []authoring.SystemControlEntry{p.entry}}
		if refused, ok := firstRejection(authoring.CheckSystemControls(probe)); ok {
			for _, id := range p.overrides {
				skip(id, control, refused.Code, refused.Summary)
			}
			continue
		}
		entries = append(entries, p.entry)
		rec.Imported += len(p.overrides)
	}
	if len(entries) == 0 {
		return rec, nil
	}

	doc := &authoring.Document{
		APIVersion: authoring.APIVersion,
		Metadata: authoring.Metadata{
			DocumentID: "organization-policy",
			Title:      "Organization policy, imported from per-policy overrides",
			Author:     policyOverrideImportAuthor,
		},
		Policy:         *template,
		SystemControls: entries,
	}
	if refused, ok := firstRejection(authoring.CheckSystemControls(doc)); ok {
		return nil, fmt.Errorf("entries accepted one at a time are refused together: %s %s", refused.Code, refused.Detail)
	}
	if rec.Draft, err = authoring.Render(doc); err != nil {
		return nil, err
	}
	if rec.DraftDigest, err = authoring.Digest(doc); err != nil {
		return nil, err
	}
	return rec, nil
}

// firstRejection is the first finding that refuses the save, if any does.
func firstRejection(findings authoring.Findings) (authoring.Finding, bool) {
	for _, f := range findings {
		if f.Severity == authoring.SeverityReject {
			return f, true
		}
	}
	return authoring.Finding{}, false
}
