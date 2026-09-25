// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// A SCOPE THAT FORCES AN ACTION KEEPS IT WHATEVER THE DOCUMENT SAYS (#4259).
//
// The cowork ingest plane masks PII before it stores content: PlaneSpec.Forces
// coerces redact for every pii-* category, and the shipped corpus compiles each
// of its seventeen PII controls there as a redact requirement. A document's
// system_controls (PRD v11 §1.5) applies on every plane, so before #4259 a
// disable of sys_pii_ssn, or a re-action of sys_pii_email to log, left the
// storage plane with nothing to mask: raw PII reached storage because of a
// document. The entry is legitimate on every other plane it names, so
// publication warns rather than refuses (SYSTEM_CONTROL_FORCED_ON_SCOPE), and
// the fold keeps the forced control on the scope that forces it.

var coworkScope = legacycompile.MustScopeFor(legacycompile.PlaneCoworkIngest, legacycompile.PhaseResponse)

// codeSystemControlForcedOnScope is written out rather than read from the
// authoring package so these cells compile, and are red, on the tree before it.
const codeSystemControlForcedOnScope = "SYSTEM_CONTROL_FORCED_ON_SCOPE"

// publishControls publishes the baseline document with a system_controls
// section and returns the artifact and every finding publication produced.
func (w *digestWorld) publishControls(t *testing.T, id string, controls []authoring.SystemControlEntry) (*authoring.Artifact, authoring.Findings) {
	t.Helper()
	doc := baselineDocument(t, w.snap)
	meta := authoring.Metadata{DocumentID: id, Title: id, Author: contract.MustParseID(contract.KindPrincipal, testAuthor)}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: doc}, w.snap.Catalog)
	if err != nil {
		t.Fatalf("%s: NewDocument: %v\n%v", id, err, findings)
	}
	d.SystemControls = controls
	art, pub, err := w.api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: testOrgKeyID, PrivateKey: w.orgPriv,
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, testApprover)},
		Fixtures:  fixturesFor(&doc), Now: digestNow,
	})
	if err != nil {
		t.Fatalf("%s: publish refused: %v\n%v", id, err, pub)
	}
	return art, append(findings, pub...)
}

// forcedCase is one weakening a document can write.
type forcedCase struct {
	name     string
	detector string
	entry    func(control string) authoring.SystemControlEntry
}

func forcedCases() []forcedCase {
	off := false
	return []forcedCase{
		{"a disable of sys_pii_ssn", "sys_pii_ssn", func(c string) authoring.SystemControlEntry {
			return authoring.SystemControlEntry{Control: c, Enabled: &off}
		}},
		{"a re-action of sys_pii_email to log", "sys_pii_email", func(c string) authoring.SystemControlEntry {
			return authoring.SystemControlEntry{Control: c, Action: legacycompile.ActionLog}
		}},
	}
}

// shippedPolicyOn is the one shipped policy of detector's control that scope
// keeps, and the control's identifier.
func shippedPolicyOn(t *testing.T, scope legacycompile.EnforcementScope, detector string) (pdp.Policy, string) {
	t.Helper()
	path := legacycompile.DetectorSignalPath(detector)
	var found []pdp.Policy
	for _, p := range restrictionOf(t, scope).Policies {
		for _, read := range p.ReferencedPaths() {
			if read == path {
				found = append(found, p)
				break
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("PREMISE: %s keeps %d shipped policies reading %s, want 1", scope, len(found), path)
	}
	return found[0], controlOf(t, found[0].ID)
}

// redactsFrom reports whether d obliges a field redaction sourced from policy.
func redactsFrom(d *contract.Decision, policy string) bool {
	for _, o := range obligationsFrom(d, policy) {
		if o.Type == contract.ObFieldRedact {
			return true
		}
	}
	return false
}

func TestADocumentCannotDisableOrWeakenAPIIControlOnTheStoragePlane(t *testing.T) {
	for _, tc := range forcedCases() {
		t.Run(tc.name, func(t *testing.T) {
			w := newDigestWorld(t, registry.EditionEnterprise)
			shipped, control := shippedPolicyOn(t, coworkScope, tc.detector)
			signal := map[string]bool{tc.detector: true}

			// CONTROL: with no entry the storage plane redacts the detector's
			// match through the shipped control.
			plain, _ := w.publishControls(t, "no-entry", nil)
			before := decideWithSignals(t, w.activateOn(t, plain, coworkScope.Plane, coworkScope.Phase), authoringcatalog.ActionLLMCompletion, signal)
			if !redactsFrom(before, shipped.ID) {
				t.Fatalf("CONTROL: with no system control, %s fired on %s decides %s with %+v; want a field redaction from %s",
					tc.detector, coworkScope, before.State, before.Obligations, shipped.ID)
			}

			art, findings := w.publishControls(t, "weakened", []authoring.SystemControlEntry{tc.entry(control)})

			// PUBLICATION WARNS, NAMING THE SCOPE AND WHY, AND DOES NOT REFUSE.
			var warned *authoring.Finding
			for i, f := range findings {
				if f.Code == codeSystemControlForcedOnScope {
					warned = &findings[i]
				}
			}
			if warned == nil {
				t.Fatalf("publication of %s produced no %s: %v", control, codeSystemControlForcedOnScope, findings)
			}
			if warned.Severity != authoring.SeverityWarn {
				t.Fatalf("%s has severity %s, want %s", codeSystemControlForcedOnScope, warned.Severity, authoring.SeverityWarn)
			}
			for _, want := range []string{control, coworkScope.String(), "redact"} {
				if !strings.Contains(warned.Detail, want) {
					t.Fatalf("the warning reads %q; want it to name %q", warned.Detail, want)
				}
			}

			// THE STORAGE PLANE STILL REDACTS, THROUGH THE SHIPPED CONTROL.
			act := w.activateOn(t, art, coworkScope.Plane, coworkScope.Phase)
			if _, kept := act.Policy(shipped.ID); !kept {
				t.Fatalf("%s left %s off %s, the scope that forces redact on its category", tc.name, shipped.ID, coworkScope)
			}
			if _, replaced := act.Policy(activation.OrganizationControlPolicyIDPrefix + shipped.ID); replaced {
				t.Fatalf("%s carries the document's replacement of %s beside the forced control", coworkScope, shipped.ID)
			}
			after := decideWithSignals(t, act, authoringcatalog.ActionLLMCompletion, signal)
			if !redactsFrom(after, shipped.ID) {
				t.Fatalf("with %s, %s fired on %s decides %s with %+v; want a field redaction from %s",
					tc.name, tc.detector, coworkScope, after.State, after.Obligations, shipped.ID)
			}

			// EVERY OTHER PLANE STILL APPLIES THE ENTRY (§1.5 unchanged).
			mcp := legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse)
			elsewhere, _ := shippedPolicyOn(t, mcp, tc.detector)
			onMCP := w.activateOn(t, art, mcp.Plane, mcp.Phase)
			if _, still := onMCP.Policy(elsewhere.ID); still {
				t.Fatalf("%s: the MCP response pass still carries %s, which the document controls", tc.name, elsewhere.ID)
			}
		})
	}
}

// THE IMPORT STILL PROPOSES THE ENTRY. The upgrade import
// (platform/agent/policy_override_import.go) turns a legacy disable into a
// system_controls entry and drops any entry CheckSystemControls rejects; the
// warning is publication's and must not reach the save-time check as a
// rejection, or an upgrading organization would lose its disable everywhere.
func TestTheSaveTimeCheckDoesNotRejectAForcedControlsEntry(t *testing.T) {
	for _, tc := range forcedCases() {
		_, control := shippedPolicyOn(t, coworkScope, tc.detector)
		template, err := pdp.SystemCorpusOrganizationTemplate()
		if err != nil {
			t.Fatal(err)
		}
		probe := &authoring.Document{Policy: *template, SystemControls: []authoring.SystemControlEntry{tc.entry(control)}}
		for _, f := range authoring.CheckSystemControls(probe) {
			if f.Severity == authoring.SeverityReject {
				t.Fatalf("%s: the save-time check rejects the entry: %s %s", tc.name, f.Code, f.Detail)
			}
		}
	}
}
