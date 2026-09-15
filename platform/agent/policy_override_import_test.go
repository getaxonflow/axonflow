// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

func importRow(id, table, policy string) importCandidate {
	return importCandidate{OverrideID: id, PolicyTable: table, PolicyID: policy}
}

func withAction(c importCandidate, action string) importCandidate {
	c.Action = sql.NullString{String: action, Valid: true}
	return c
}

func withEnabled(c importCandidate, enabled bool) importCandidate {
	c.Enabled = sql.NullBool{Bool: enabled, Valid: true}
	return c
}

const (
	unionSelectControl       = "corpus:static_policies:sys__sqli__union__select"
	injectionOverrideControl = "corpus:static_policies:sys__dangerous__injection__override"
)

// THE IMPORT CARRIES A CUSTOMER'S SETTINGS AND SAYS WHY IT SKIPPED EVERY OTHER
// ROW (PRD v11 §1.5). Two rows change a shipped control and are carried; each
// of the others is skipped for its own reason, and an entry the save-time checks
// refuse is skipped with the code an author would be refused with.
func TestTheOverrideImportCarriesEachSettingAndSaysWhyItSkippedTheRest(t *testing.T) {
	tenant := withAction(importRow("o-tenant", "static_policies", "sys_sqli_union_select"), "warn")
	tenant.TenantID = sql.NullString{String: "tenant-1", Valid: true}
	revoked := withAction(importRow("o-revoked", "static_policies", "sys_sqli_union_select"), "warn")
	revoked.Revoked = true
	expired := withAction(importRow("o-expired", "static_policies", "sys_sqli_union_select"), "warn")
	expired.Expired = true
	breakGlass := withAction(importRow("o-break-glass", "static_policies", "sys_sqli_union_select"), "block")
	breakGlass.BreakGlass = true
	rows := []importCandidate{
		withAction(importRow("o-union", "static_policies", "sys_sqli_union_select"), "block"),
		withEnabled(importRow("o-injection", "static_policies", "sys_dangerous_injection_override"), false),
		tenant, revoked, expired, breakGlass,
		withAction(importRow("o-allow", "static_policies", "sys_dangerous_injection_override"), "allow"),
		withAction(importRow("o-orphan", "static_policies", ""), "block"),
		withEnabled(importRow("o-noop", "static_policies", "sys_sqli_union_injection"), true),
		withAction(importRow("o-custom", "static_policies", "tenant_custom_rule"), "block"),
		withAction(importRow("o-dynamic", "dynamic_policies", "sys_dyn_expensive_query"), "block"),
		withAction(importRow("o-approval", "static_policies", "sys_sqli_union_injection"), "require_approval"),
	}
	rec, err := buildImportRecord(rows)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SourceRows != len(rows) || rec.Imported != 2 {
		t.Fatalf("the record counts %d rows and %d imported; want %d and 2", rec.SourceRows, rec.Imported, len(rows))
	}

	// Each skipped row by its reason, or by the save-time code refusing it.
	want := map[string]string{
		"o-tenant": "tenant-scoped", "o-revoked": "revoked", "o-expired": "expired",
		"o-break-glass": "break-glass", "o-allow": "break-glass", "o-orphan": "names no legacy policy",
		"o-noop": "changes nothing", "o-custom": "SYSTEM_CONTROL_UNKNOWN",
		"o-dynamic": "SYSTEM_CONTROL_NOT_REACTIONABLE", "o-approval": "SYSTEM_CONTROL_MALFORMED",
	}
	got := map[string]importSkip{}
	for _, s := range rec.Skipped {
		got[s.OverrideID] = s
	}
	if len(got) != len(want) || len(rec.Skipped) != len(want) {
		t.Fatalf("%d rows skipped (%+v); want exactly %d", len(rec.Skipped), rec.Skipped, len(want))
	}
	for id, why := range want {
		s, ok := got[id]
		switch {
		case !ok:
			t.Errorf("%s is not listed as skipped", id)
		case strings.HasPrefix(why, "SYSTEM_CONTROL_"):
			if s.Code != why || s.Reason == "" || s.Control == "" {
				t.Errorf("%s skipped as %+v; want code %s with its declared summary and the control it named", id, s, why)
			}
		case s.Code != "" || !strings.HasPrefix(s.Reason, why):
			t.Errorf("%s skipped as %+v; want the reason %q", id, s, why)
		}
	}

	// THE DRAFT: the shipped template, the two settings in control order, and
	// the digest an authored document gets (rule 8).
	var doc authoring.Document
	if err := json.Unmarshal(rec.Draft, &doc); err != nil {
		t.Fatalf("the draft does not parse: %v", err)
	}
	if digest, err := authoring.Digest(&doc); err != nil || digest != rec.DraftDigest {
		t.Fatalf("the draft digests to %s (err %v); the record names %s", digest, err, rec.DraftDigest)
	}
	disabled := false
	wantControls := []authoring.SystemControlEntry{
		{Control: injectionOverrideControl, Enabled: &disabled},
		{Control: unionSelectControl, Action: legacycompile.ActionBlock},
	}
	if !reflect.DeepEqual(doc.SystemControls, wantControls) {
		t.Fatalf("the draft's system_controls are %+v; want %+v", doc.SystemControls, wantControls)
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	if doc.APIVersion != authoring.APIVersion || doc.Policy.Root != template.Root || len(doc.Policy.Policies) != len(template.Policies) {
		t.Fatalf("the draft is %s on root %s with %d policies; want the shipped template's %s with %d",
			doc.APIVersion, doc.Policy.Root, len(doc.Policy.Policies), template.Root, len(template.Policies))
	}
	if doc.Metadata.Author != policyOverrideImportAuthor {
		t.Fatalf("the draft's author is %+v; want the internal service principal", doc.Metadata.Author)
	}
	if err := doc.Metadata.Author.Validate(); err != nil {
		t.Fatalf("the draft's author is not a canonical principal: %v", err)
	}
}

// Overrides that disagree about one control carry none of them: which one the
// customer meant is not the import's to guess. Overrides that agree carry once.
func TestOverridesThatDisagreeAboutAControlAreAllSkippedAndAgreeingOnesCarryOnce(t *testing.T) {
	rec, err := buildImportRecord([]importCandidate{
		withAction(importRow("o-block", "static_policies", "sys_sqli_union_select"), "block"),
		withAction(importRow("o-warn", "static_policies", "sys_sqli_union_select"), "warn"),
		withEnabled(importRow("o-off-1", "static_policies", "sys_dangerous_injection_override"), false),
		withEnabled(importRow("o-off-2", "static_policies", "sys_dangerous_injection_override"), false),
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc authoring.Document
	if err := json.Unmarshal(rec.Draft, &doc); err != nil {
		t.Fatal(err)
	}
	if rec.Imported != 2 || len(doc.SystemControls) != 1 || doc.SystemControls[0].Control != injectionOverrideControl {
		t.Fatalf("imported %d into %+v; want the two agreeing rows as one entry for %s", rec.Imported, doc.SystemControls, injectionOverrideControl)
	}
	if len(rec.Skipped) != 2 {
		t.Fatalf("skipped %+v; want both disagreeing rows", rec.Skipped)
	}
	for _, s := range rec.Skipped {
		if s.Control != unionSelectControl || !strings.HasPrefix(s.Reason, "disagrees") {
			t.Fatalf("skipped %+v; want a disagreement about %s", s, unionSelectControl)
		}
	}
}

// An organization none of whose rows can be carried is recorded with no draft,
// so the editor can say nothing could be imported, and why.
func TestAnOrganizationWhoseRowsAllSkipIsRecordedWithNoDraft(t *testing.T) {
	tenant := withAction(importRow("o-tenant", "static_policies", "sys_sqli_union_select"), "block")
	tenant.TenantID = sql.NullString{String: "tenant-9", Valid: true}
	rec, err := buildImportRecord([]importCandidate{tenant})
	if err != nil {
		t.Fatal(err)
	}
	if rec.SourceRows != 1 || rec.Imported != 0 || rec.Draft != nil || rec.DraftDigest != "" || len(rec.Skipped) != 1 {
		t.Fatalf("the record is %+v; want one row, nothing imported, no draft, one skip", rec)
	}
}
