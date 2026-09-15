// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
)

// TestAMatchedPIIControlIsNeverABareAllowOnDecide is #2965's class guard on the
// engine that now authors every decide verdict (PRD v11 §1.1): a MATCHED
// detection control never returns verdict=allow with no obligation and no
// reason. A matched policy always produces a governance signal the caller can
// read - a deny, an obligation, or an advisory reason naming it.
//
// The four postures are an organization's recorded pii override, which the
// anchored engine folds onto the shipped control (#4045): block compiles to a
// constraint, redact to a mandatory field_redact, warn to an advisory
// notification and log to an immutable_audit. The last two are the ones the
// wire cannot carry - decide drops an advisory obligation and the audit row
// discharges immutable_audit - so they are the ones that could fall silent.
//
// One control suffices, where the retired guard looped every pii-* category:
// the category decided that guard's convert step, while the rendering this
// guard judges reads only the decision's determining sets, which carry no
// category.
func TestAMatchedPIIControlIsNeverABareAllowOnDecide(t *testing.T) {
	enfSetup(t)
	row, policy, probe := enfOverrideReachedControl(t, DetectionCategoryPII)
	enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta(probe)}, nil)
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	query := mrsRedactContent(probe)
	replacement := activation.OverridePolicyIDPrefix + policy

	for _, c := range []struct {
		action DetectionAction
		check  func(t *testing.T, r enfResponse, verdict string, reasons []string)
	}{
		{DetectionActionBlock, func(t *testing.T, r enfResponse, verdict string, reasons []string) {
			if verdict != VerdictDeny || len(reasons) != 1 || reasons[0] != string(contract.ReasonExplicitConstraint) {
				t.Fatalf("verdict %q reasons %v; want deny [%s]", verdict, reasons, contract.ReasonExplicitConstraint)
			}
		}},
		// The caller declares no redaction, so the mandatory obligation is
		// refused rather than handed to a caller that cannot discharge it.
		{DetectionActionRedact, func(t *testing.T, r enfResponse, verdict string, reasons []string) {
			if verdict != VerdictDeny || len(reasons) != 1 || !strings.HasPrefix(reasons[0], string(contract.ReasonUnsupportedObligation)) {
				t.Fatalf("verdict %q reasons %v; want deny %s", verdict, reasons, contract.ReasonUnsupportedObligation)
			}
		}},
		{DetectionActionWarn, advisoryAllow(replacement)},
		{DetectionActionLog, advisoryAllow(replacement)},
	} {
		t.Run(string(c.action), func(t *testing.T) {
			enfRecordOverride(reader, enfOrgPublished, DetectionCategoryPII, c.action)
			r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, query)
			if r.code != http.StatusOK || r.str(t, "engine") != decisionEngineAnchored {
				t.Fatalf("got HTTP %d engine %q; want 200 from the anchored engine. body=%s", r.code, r.str(t, "engine"), r.raw)
			}
			verdict, reasons := r.str(t, "verdict"), r.strings(t, "reasons")
			if verdict == VerdictAllow && len(reasons) == 0 && string(r.body["obligations"]) == "[]" {
				t.Fatalf("BARE ALLOW for the matched control %s under pii=%s: no obligation and no reason, so the match produced no signal. body=%s",
					replacement, c.action, r.raw)
			}
			c.check(t, r, verdict, reasons)
		})
	}

	// CONTROL: the same request with the probe absent matches nothing, and a
	// clean allow carries no advisory reason - so the reasons above are the
	// match's, not something every allow says.
	t.Run("CONTROL: an unmatched request is a clean allow with no reason", func(t *testing.T) {
		enfRecordOverride(reader, enfOrgPublished, DetectionCategoryPII, DetectionActionWarn)
		r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, "What is the weather today?")
		if r.str(t, "verdict") != VerdictAllow || len(r.strings(t, "reasons")) != 0 {
			t.Fatalf("verdict %q reasons %v; want a clean allow with no reason. body=%s", r.str(t, "verdict"), r.strings(t, "reasons"), r.raw)
		}
	})
}

// advisoryAllow is the posture of a control whose match the wire carries no
// obligation for: the request is allowed, and a reason names the control.
func advisoryAllow(policyID string) func(t *testing.T, r enfResponse, verdict string, reasons []string) {
	return func(t *testing.T, r enfResponse, verdict string, reasons []string) {
		t.Helper()
		if verdict != VerdictAllow {
			t.Fatalf("verdict %q; an advisory control does not refuse. body=%s", verdict, r.raw)
		}
		for _, reason := range reasons {
			if strings.Contains(reason, policyID) {
				return
			}
		}
		t.Fatalf("reasons %v name no reason for %s, the control that matched. body=%s", reasons, policyID, r.raw)
	}
}
