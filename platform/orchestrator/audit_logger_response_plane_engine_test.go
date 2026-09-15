// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"reflect"
	"testing"

	"axonflow/platform/agent"
	"axonflow/platform/shared/anchoredenforcer"
)

// THE RESPONSE PLANE'S AUDIT ROWS NAME THE ENGINE THAT DECIDED (PRD v11 §5.7).
//
// The plane=llm row is the per-organization record of a response decision, so
// it carries what the wire carries: the engine, the subject type and the policy
// bundle, with the reason and the blocking constraint. Each member is asserted
// on its own, in each presence state - set, absent (no record at all) and set
// but empty - on BOTH writers, because the allowed, redacted and blocked rows
// are written by different functions and a member stamped on one only is the
// defect this pins.

func responsePlaneLogger() *AuditLogger {
	return &AuditLogger{auditQueue: make(chan *AuditEntry, 16), shutdownChan: make(chan struct{})}
}

func responsePlaneRequest() OrchestratorRequest {
	return OrchestratorRequest{
		RequestID: "req-engine-row", Query: "q", RequestType: "llm_chat",
		User:   UserContext{ID: 1, Email: "u@example.com", Role: "user", TenantID: "t"},
		Client: ClientContext{ID: "client-a", OrgID: "org-a"},
	}
}

// decidedRecord is a response the anchored engine decided, with every member set.
func decidedRecord(verdict string) *RedactionInfo {
	return &RedactionInfo{
		Verdict:          verdict,
		Engine:           anchoredenforcer.EngineAnchored,
		SubjectType:      "Client",
		PolicyBundle:     "sha256:bundle",
		DecisionReason:   "explicit_constraint",
		BlockingPolicyID: "organization_override:corpus:static_policies:sys__pii__ssn:block",
		LegacyValidators: []agent.LegacyValidatorAction{{Validator: agent.LegacyValidatorIndonesia, Action: agent.LegacyActionMasked}},
	}
}

var responsePlaneMembers = []string{"engine", "subject_type", "policy_bundle", "decision_reason", "blocking_policy_id"}

// rowFor writes one row through the named writer with info as the pass's record.
func rowFor(t *testing.T, writer string, info *RedactionInfo) map[string]interface{} {
	t.Helper()
	l := responsePlaneLogger()
	policy := &PolicyEvaluationResult{Allowed: true}
	var entry *AuditEntry
	switch writer {
	case "success":
		ctx := context.Background()
		if info != nil {
			ctx = context.WithValue(ctx, ctxKeyRedactionInfo, info)
		}
		entry = l.LogSuccessfulRequest(ctx, responsePlaneRequest(), "released", policy, &ProviderInfo{Provider: "ollama"})
	case "blocked":
		entry = l.LogBlockedResponse(context.Background(), responsePlaneRequest(), policy, info, nil)
	default:
		t.Fatalf("unknown writer %q", writer)
	}
	if entry.Plane != "llm" {
		t.Fatalf("%s row plane = %q, want llm", writer, entry.Plane)
	}
	return entry.PolicyDetails
}

func TestEveryResponsePlaneRowCarriesTheAnchoredDecision(t *testing.T) {
	for _, writer := range []string{"success", "blocked"} {
		t.Run(writer, func(t *testing.T) {
			verdict := responseVerdictRedacted
			if writer == "blocked" {
				verdict = responseVerdictBlocked
			}
			full := decidedRecord(verdict)
			details := rowFor(t, writer, full)
			want := map[string]string{
				"engine": full.Engine, "subject_type": full.SubjectType, "policy_bundle": full.PolicyBundle,
				"decision_reason": full.DecisionReason, "blocking_policy_id": full.BlockingPolicyID,
			}
			for _, member := range responsePlaneMembers {
				if got, ok := details[member]; !ok || got != want[member] {
					t.Errorf("SET: the %s row's %s = %v (present %v), want %q", writer, member, got, ok, want[member])
				}
			}
			if got := details["legacy_validators"]; !reflect.DeepEqual(got, full.LegacyValidators) {
				t.Errorf("SET: the %s row's legacy_validators = %v, want %v", writer, got, full.LegacyValidators)
			}
			if details["plane"] != "llm" {
				t.Errorf("the %s row's policy_details plane = %v, want llm", writer, details["plane"])
			}

			// ABSENT: no record at all writes none of the members.
			absent := rowFor(t, writer, nil)
			for _, member := range append(append([]string{}, responsePlaneMembers...), "legacy_validators", "withheld_by_validation") {
				if _, ok := absent[member]; ok {
					t.Errorf("ABSENT: the %s row with no response-plane record carries %s = %v", writer, member, absent[member])
				}
			}

			// SET BUT EMPTY: each member left empty on an otherwise decided record
			// is omitted, never written as an empty string.
			for _, member := range responsePlaneMembers {
				empty := decidedRecord(verdict)
				switch member {
				case "engine":
					empty.Engine = ""
				case "subject_type":
					empty.SubjectType = ""
				case "policy_bundle":
					empty.PolicyBundle = ""
				case "decision_reason":
					empty.DecisionReason = ""
				case "blocking_policy_id":
					empty.BlockingPolicyID = ""
				}
				row := rowFor(t, writer, empty)
				if got, ok := row[member]; ok {
					t.Errorf("EMPTY: the %s row writes %s = %q for an empty member, want it omitted", writer, member, got)
				}
				for _, other := range responsePlaneMembers {
					if other != member {
						if _, ok := row[other]; !ok {
							t.Errorf("EMPTY %s: the %s row dropped %s, which was set", member, writer, other)
						}
					}
				}
			}
		})
	}
}

// TestOnlyTheBlockedRowSaysAValidationRuleWithheldIt: a response the engine
// released and a validation rule refused is recorded blocked, naming the rule
// as the withholder, and never as the engine's refusal. The success row has no
// such member, whatever the record says.
func TestOnlyTheBlockedRowSaysAValidationRuleWithheldIt(t *testing.T) {
	byValidation := decidedRecord(responseVerdictBlocked)
	byValidation.DecisionReason, byValidation.BlockingPolicyID = "permitted", ""
	byValidation.WithheldByValidation, byValidation.ValidationError = true, "no_error_messages: response contains error message"

	blocked := rowFor(t, "blocked", byValidation)
	if blocked["withheld_by_validation"] != true || blocked["validation_error"] != byValidation.ValidationError {
		t.Fatalf("the blocked row says withheld_by_validation=%v validation_error=%v; want true and the rule", blocked["withheld_by_validation"], blocked["validation_error"])
	}
	if blocked["decision_reason"] != "permitted" || blocked["engine"] != anchoredenforcer.EngineAnchored {
		t.Fatalf("the blocked row says reason %v engine %v; want the engine's permit kept, not a refusal", blocked["decision_reason"], blocked["engine"])
	}
	if _, ok := blocked["blocking_policy_id"]; ok {
		t.Fatal("a validation withholding names a blocking policy; no policy blocked it")
	}

	engineRefusal := rowFor(t, "blocked", decidedRecord(responseVerdictBlocked))
	if _, ok := engineRefusal["withheld_by_validation"]; ok {
		t.Fatal("an engine refusal's row says a validation rule withheld it")
	}
	if _, ok := rowFor(t, "success", byValidation)["withheld_by_validation"]; ok {
		t.Fatal("the success row carries withheld_by_validation")
	}
}

// TestAWriterSetEntryWinsOverTheStamp: the stamp never overwrites a member the
// writer already put on the row.
func TestAWriterSetEntryWinsOverTheStamp(t *testing.T) {
	details := map[string]interface{}{"engine": "set-by-the-writer"}
	stampResponsePlaneDecision(details, decidedRecord(responseVerdictAllowed))
	if details["engine"] != "set-by-the-writer" {
		t.Fatalf("the stamp overwrote the writer's engine with %v", details["engine"])
	}
	if details["subject_type"] != "Client" {
		t.Fatalf("CONTROL: the stamp wrote no subject_type (%v), so the first assertion proves nothing", details["subject_type"])
	}
}
