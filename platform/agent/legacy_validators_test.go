// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/contract"
)

// A CHECKSUM VALIDATOR THAT ACTS BEFORE THE ENGINE IS NAMED (#4122).
//
// Under an organization's recorded pii override, the Indonesia and India
// validators still block a request, or mask a response, before the anchored
// engine decides it. Until #4122 routes them through the engine, the wire and
// the audit row name the validator and its action, so a masked response does
// not go out under the anchored engine's name and a block is not left with no
// author. Each case has its control: with no override recorded nothing acts
// ahead of the engine, and the member is absent.

func legacyActed(validator, action string) []LegacyValidatorAction {
	return []LegacyValidatorAction{{Validator: validator, Action: action}}
}

// legacyValidatorsInRow reports the audit row's legacy_validators as recorded.
func legacyValidatorsInRow(t *testing.T, details []byte) []LegacyValidatorAction {
	t.Helper()
	var row struct {
		LegacyValidators []LegacyValidatorAction `json:"legacy_validators"`
	}
	if len(details) == 0 {
		t.Fatal("no audit row was captured")
	}
	if err := json.Unmarshal(details, &row); err != nil {
		t.Fatalf("policy_details is not a JSON object: %v (raw=%s)", err, details)
	}
	return row.LegacyValidators
}

// captureAuditDetails installs a usage database and returns where the next
// audit row's policy_details lands: column 14 of the decide writer's
// 21-column insert, writeMCPDecisionAudit's 20-column one and
// writeExplainableAuditLog's 19-column one alike.
func captureAuditDetails(t *testing.T, columns int) *[]byte {
	t.Helper()
	return expectAuditDetails(installUsageDBMock(t), columns)
}

// expectAuditDetails is captureAuditDetails on a usage database already
// installed (setupPreCheckAuditTest installs its own).
func expectAuditDetails(mock sqlmock.Sqlmock, columns int) *[]byte {
	mock.MatchExpectationsInOrder(false)
	details := new([]byte)
	args := make([]driver.Value, columns)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13] = captureArg{dst: details}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
	return details
}

// decideForLegacy sends query to /api/v1/decide as the community credential.
func decideForLegacy(t *testing.T, query string) DecideResponse {
	t.Helper()
	return decideForLegacyWith(t, query, "")
}

// decideForLegacyWith is decideForLegacy from an enforcement point presenting
// handshake as its PEP capability declaration ("" presents none).
func decideForLegacyWith(t *testing.T, query, handshake string) DecideResponse {
	t.Helper()
	body, _ := json.Marshal(DecideRequest{
		Stage:          DecisionStageLLM,
		CallerIdentity: DecisionCallerIdentity{GatewayID: "test-llm-gateway", TenantID: "test-tenant"},
		Target:         DecisionTarget{Type: "llm", Model: "gpt-4o", Provider: "openai"},
		Query:          query,
	})
	req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	if handshake != "" {
		req.Header.Set(contract.PEPHandshakeHeader, handshake)
	}
	rr := serveDecide(t, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp DecideResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v -- body=%s", err, rr.Body.String())
	}
	return resp
}

func TestAValidatorThatBlocksAheadOfTheEngineIsNamedOnDecide(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installCircuitBreakerWithMockDB(t)
	org := getDeploymentOrgID()

	for _, c := range []struct{ name, query, validator string }{
		{"Indonesia", "Customer NIK is " + fixtureNIK, legacyValidatorIndonesia},
		{"India", indiaPII, legacyValidatorIndia},
	} {
		t.Run(c.name+": a recorded pii=block blocks ahead of the engine, and the record says so", func(t *testing.T) {
			installNIKWorld(t, org, DetectionActionBlock)
			details := captureAuditDetails(t, 21)
			resp := decideForLegacy(t, c.query)
			want := legacyActed(c.validator, legacyActionBlocked)
			if resp.Verdict != VerdictDeny || !reflect.DeepEqual(resp.LegacyValidators, want) {
				t.Fatalf("verdict=%q legacy_validators=%+v; want deny naming %+v", resp.Verdict, resp.LegacyValidators, want)
			}
			if got := legacyValidatorsInRow(t, *details); !reflect.DeepEqual(got, want) {
				t.Fatalf("the audit row's legacy_validators = %+v; want %+v", got, want)
			}
		})
		t.Run(c.name+": CONTROL, no override recorded: nothing acts ahead of the engine", func(t *testing.T) {
			installNIKWorld(t, org, "")
			details := captureAuditDetails(t, 21)
			resp := decideForLegacy(t, c.query)
			if len(resp.LegacyValidators) != 0 || resp.Engine != decisionEngineAnchored {
				t.Fatalf("engine=%q legacy_validators=%+v; want the anchored engine's verdict and no validator acting", resp.Engine, resp.LegacyValidators)
			}
			if got := legacyValidatorsInRow(t, *details); len(got) != 0 {
				t.Fatalf("the audit row names %+v with no override recorded", got)
			}
		})
	}
}

func TestAValidatorThatBlocksAheadOfTheEngineIsNamedOnThePreCheck(t *testing.T) {
	const org = "seg-gw-org"
	for _, c := range []struct {
		name     string
		override DetectionAction
		want     []LegacyValidatorAction
	}{
		{"a recorded pii=block blocks ahead of the engine, and the response says so", DetectionActionBlock, legacyActed(legacyValidatorIndonesia, legacyActionBlocked)},
		{"CONTROL, no override recorded: nothing acts ahead of the engine", "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, cleanup := setupGatewaySegmentPreCheckTest(t)
			defer cleanup()
			reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
			if c.override != "" {
				reader.data[org] = map[string]DetectionAction{DetectionCategoryPII: c.override}
			}
			installTestOverrideCache(t, reader, time.Minute)
			rr := doGatewayPreCheckSegmentRequest(t, "seg-gw-tenant", org, "erin@corp.example", "Customer NIK is "+fixtureNIK)
			var resp PreCheckResponse
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !reflect.DeepEqual(resp.LegacyValidators, c.want) {
				t.Fatalf("legacy_validators = %+v; want %+v (response %+v)", resp.LegacyValidators, c.want, resp)
			}
		})
	}
}

func TestAValidatorThatActsAheadOfTheEngineIsNamedOnTheMCPResponse(t *testing.T) {
	t.Run("a recorded pii=redact: the validator masks, the engine decides the masked content, and both are said", func(t *testing.T) {
		withMCPPIIAction(t, DetectionActionRedact)
		details := captureAuditDetails(t, 20)
		m := checkOutputTool(t, map[string]interface{}{"connector_type": "postgres", "message": validNIKResponse})
		want := legacyActed(legacyValidatorIndonesia, legacyActionMasked)
		if m["allowed"] != true || m["engine"] != decisionEngineAnchored || !reflect.DeepEqual(m["legacy_validators"], want) {
			t.Fatalf("got %v; want a released response decided by the anchored engine naming %+v", m, want)
		}
		if got := legacyValidatorsInRow(t, *details); !reflect.DeepEqual(got, want) {
			t.Fatalf("the redaction's audit row names %+v; want %+v", got, want)
		}
	})
	t.Run("a recorded pii=block: the validator blocks, no engine decided, and the response says so", func(t *testing.T) {
		withMCPPIIAction(t, DetectionActionBlock)
		// The block's row is writeExplainableAuditLog's 19-column insert, and the
		// validator is its only author: the pass never ran.
		details := captureAuditDetails(t, 19)
		m := checkOutputTool(t, map[string]interface{}{"connector_type": "postgres", "message": validNIKResponse})
		want := legacyActed(legacyValidatorIndonesia, legacyActionBlocked)
		if m["allowed"] != false || m["engine"] != nil || !reflect.DeepEqual(m["legacy_validators"], want) {
			t.Fatalf("got %v; want a withheld response, no engine, naming %+v", m, want)
		}
		if got := legacyValidatorsInRow(t, *details); !reflect.DeepEqual(got, want) {
			t.Fatalf("the block's audit row names %+v; want %+v", got, want)
		}
	})
	t.Run("REST check-output: a recorded pii=block is named on the typed response", func(t *testing.T) {
		cleanup := setupCommunityModeForTest(t)
		defer cleanup()
		withMCPPIIAction(t, DetectionActionBlock)
		installUsageDBMock(t)
		body, _ := json.Marshal(MCPCheckOutputRequest{ConnectorType: "postgres", Message: validNIKResponse, TenantID: "default"})
		req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mcpCheckOutputHandler(w, req)
		var resp MCPCheckOutputResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
		}
		if want := legacyActed(legacyValidatorIndonesia, legacyActionBlocked); resp.Allowed || !reflect.DeepEqual(resp.LegacyValidators, want) {
			t.Fatalf("allowed=%v legacy_validators=%+v; want withheld naming %+v", resp.Allowed, resp.LegacyValidators, want)
		}
	})
	t.Run("CONTROL, no override recorded: nothing acts ahead of the engine", func(t *testing.T) {
		installUsageDBMock(t)
		m := checkOutputTool(t, map[string]interface{}{"connector_type": "postgres", "message": validNIKResponse})
		if _, named := m["legacy_validators"]; named {
			t.Fatalf("got %v; no validator acts without an override", m)
		}
	})
}

// A CHECKSUM VALIDATOR'S REDACTION IS CARRIED ONTO THE VERDICT (#3564; a stopgap
// #4122 replaces). Under a recorded pii=redact override the validators find
// identifiers no shipped control detects. The seam carries the requirement as a
// mandatory redact_pii judged by the engine's own discharge rule, so a caller
// that cannot redact is refused rather than handed an allow with the identifier
// in it. The world is validator-only: the corpus control's detector matches
// nothing, so nothing but the validator can have asked for the redaction.

// installValidatorOnlyWorld installs the shared engine with the NIK row's
// detector matching nothing, and records piiAction for org ("" records none).
func installValidatorOnlyWorld(t *testing.T, org string, piiAction DetectionAction) {
	t.Helper()
	enfInstallDetectors(t, map[string]string{fixtureNIKRow: `\Aw3g-no-request-carries-this\z`}, nil)
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	if piiAction != "" {
		reader.data[org] = map[string]DetectionAction{DetectionCategoryPII: piiAction}
	}
	installTestOverrideCache(t, reader, time.Minute)
}

// requestRedactions counts the redact_pii obligations resp hands its caller for
// the request content.
func requestRedactions(resp DecideResponse) int {
	n := 0
	for _, o := range resp.Obligations {
		if o.Type == ObligationRedactPII && o.Fulfillment != nil && o.Fulfillment.Phase == ObligationPhaseRequest {
			n++
		}
	}
	return n
}

func TestAValidatorsRedactionIsCarriedOntoTheVerdictOnDecide(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installCircuitBreakerWithMockDB(t)
	org := getDeploymentOrgID()

	for _, c := range []struct{ name, query, validator string }{
		{"Indonesia", "Customer NIK is " + fixtureNIK, legacyValidatorIndonesia},
		{"India", indiaPII, legacyValidatorIndia},
	} {
		want := legacyActed(c.validator, legacyActionRedactionRequired)
		policy := legacyValidatorPolicyIDs[c.validator]
		t.Run(c.name+": a caller that declares redaction is allowed, and handed it", func(t *testing.T) {
			installValidatorOnlyWorld(t, org, DetectionActionRedact)
			details := captureAuditDetails(t, 21)
			resp := decideForLegacyWith(t, c.query, redactionHandshake(t))
			if resp.Verdict != VerdictAllow || requestRedactions(resp) != 1 {
				t.Fatalf("verdict=%q obligations=%+v; want allow carrying one request-content redact_pii", resp.Verdict, resp.Obligations)
			}
			if !reflect.DeepEqual(resp.LegacyValidators, want) || slices.Contains(resp.EvaluatedPolicies, policy) {
				t.Fatalf("legacy_validators=%+v evaluated_policies=%v; want %+v, and %s NOT captioned as a control the engine applied", resp.LegacyValidators, resp.EvaluatedPolicies, want, policy)
			}
			if got := legacyValidatorsInRow(t, *details); !reflect.DeepEqual(got, want) {
				t.Fatalf("the audit row's legacy_validators = %+v; want %+v", got, want)
			}
		})
		t.Run(c.name+": a caller that declares nothing is never handed a bare allow", func(t *testing.T) {
			installValidatorOnlyWorld(t, org, DetectionActionRedact)
			details := captureAuditDetails(t, 21)
			resp := decideForLegacyWith(t, c.query, "")
			// The fail-open this closes: an allow with the identifier in it and no
			// instruction to redact. Whether a caller that declares nothing is refused
			// or allowed with the redaction is the engine-wide profile's to say, and
			// the parity leg below holds it to the engine's own answer.
			refused := resp.Verdict == VerdictDeny && len(resp.Reasons) == 1 && strings.HasPrefix(resp.Reasons[0], string(contract.ReasonUnsupportedObligation))
			carried := resp.Verdict == VerdictAllow && requestRedactions(resp) == 1
			if !refused && !carried {
				t.Fatalf("verdict=%q reasons=%v obligations=%+v; want a refusal unsupported_obligation or an allow carrying the redaction", resp.Verdict, resp.Reasons, resp.Obligations)
			}
			if !reflect.DeepEqual(resp.LegacyValidators, want) {
				t.Fatalf("legacy_validators=%+v; want %+v", resp.LegacyValidators, want)
			}
			if got := legacyValidatorsInRow(t, *details); !reflect.DeepEqual(got, want) {
				t.Fatalf("the audit row's legacy_validators = %+v; want %+v", got, want)
			}
		})
		t.Run(c.name+": CONTROL, no override recorded: no redaction, and no validator named", func(t *testing.T) {
			installValidatorOnlyWorld(t, org, "")
			details := captureAuditDetails(t, 21)
			resp := decideForLegacyWith(t, c.query, redactionHandshake(t))
			if resp.Verdict != VerdictAllow || requestRedactions(resp) != 0 || len(resp.LegacyValidators) != 0 {
				t.Fatalf("verdict=%q obligations=%+v legacy_validators=%+v; want a plain allow", resp.Verdict, resp.Obligations, resp.LegacyValidators)
			}
			if got := legacyValidatorsInRow(t, *details); len(got) != 0 {
				t.Fatalf("the audit row names %+v with no override recorded", got)
			}
		})
	}
	t.Run("a caller that declares nothing is judged exactly as for the engine's own redaction", func(t *testing.T) {
		outcome := func(install func(*testing.T)) (string, int) {
			install(t)
			captureAuditDetails(t, 21)
			resp := decideForLegacyWith(t, "Customer NIK is "+fixtureNIK, "")
			return resp.Verdict, requestRedactions(resp)
		}
		engineVerdict, engineRedact := outcome(func(t *testing.T) { installNIKWorld(t, org, DetectionActionRedact) })
		validatorVerdict, validatorRedact := outcome(func(t *testing.T) { installValidatorOnlyWorld(t, org, DetectionActionRedact) })
		if engineVerdict != validatorVerdict || engineRedact != validatorRedact {
			t.Fatalf("with no handshake the engine's own redaction answers %s with %d redaction(s) and the validator's answers %s with %d; one rule must give one answer",
				engineVerdict, engineRedact, validatorVerdict, validatorRedact)
		}
		t.Logf("no handshake, both: %s with %d redaction(s)", engineVerdict, engineRedact)
	})
	t.Run("already met: when the engine redacts the content itself, the validator adds no second instruction", func(t *testing.T) {
		installNIKWorld(t, org, DetectionActionRedact)
		captureAuditDetails(t, 21)
		resp := decideForLegacyWith(t, "Customer NIK is "+fixtureNIK, redactionHandshake(t))
		want := legacyActed(legacyValidatorIndonesia, legacyActionRedactionRequired)
		if resp.Verdict != VerdictAllow || requestRedactions(resp) != 1 || !reflect.DeepEqual(resp.LegacyValidators, want) {
			t.Fatalf("verdict=%q obligations=%+v legacy_validators=%+v; want allow, one redact_pii, %+v", resp.Verdict, resp.Obligations, resp.LegacyValidators, want)
		}
	})
}

// preCheckFor decodes a pre-check response.
func preCheckFor(t *testing.T, rr *httptest.ResponseRecorder) PreCheckResponse {
	t.Helper()
	var resp PreCheckResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode the pre-check response: %v", err)
	}
	return resp
}

func TestAValidatorsRedactionIsCarriedOntoTheVerdictOnThePreCheck(t *testing.T) {
	// A community pre-check resolves no organization, so the detection action
	// the validators read is the pinned gateway configuration.
	redact := func(c *ModeDetectionConfig) { c.PIIAction = DetectionActionRedact }
	for _, c := range []struct{ name, query, validator string }{
		{"Indonesia", "Customer NIK is " + fixtureNIK, legacyValidatorIndonesia},
		{"India", indiaPII, legacyValidatorIndia},
	} {
		want := legacyActed(c.validator, legacyActionRedactionRequired)
		t.Run(c.name+": a caller that declares redaction is approved and told to redact", func(t *testing.T) {
			mock, cleanup := setupPreCheckAuditTest(t)
			defer cleanup()
			installValidatorOnlyWorld(t, getDeploymentOrgID(), "")
			pinGatewayOverride(t, redact)
			details := expectAuditDetails(mock, 21)
			resp := preCheckFor(t, newPreCheckRecorderWithHandshake(t, c.query, redactionHandshake(t)))
			if !resp.Approved || !resp.RequiresRedaction || !reflect.DeepEqual(resp.LegacyValidators, want) || slices.Contains(resp.Policies, legacyValidatorPolicyIDs[c.validator]) {
				t.Fatalf("approved=%v requires_redaction=%v legacy_validators=%+v policies=%v; want approved, told to redact, naming %+v, and the validator not in policies", resp.Approved, resp.RequiresRedaction, resp.LegacyValidators, resp.Policies, want)
			}
			if got := legacyValidatorsInRow(t, *details); !reflect.DeepEqual(got, want) {
				t.Fatalf("the audit row's legacy_validators = %+v; want %+v", got, want)
			}
		})
	}
	t.Run("a caller that declares nothing is judged exactly as for the engine's own redaction", func(t *testing.T) {
		outcome := func(install func(*testing.T)) (bool, bool) {
			_, cleanup := setupPreCheckAuditTest(t)
			defer cleanup()
			install(t)
			pinGatewayOverride(t, redact)
			resp := preCheckFor(t, newPreCheckRecorderWithHandshake(t, "Customer NIK is "+fixtureNIK, ""))
			return resp.Approved, resp.RequiresRedaction
		}
		engineApproved, engineRedact := outcome(func(t *testing.T) { installNIKWorld(t, getDeploymentOrgID(), DetectionActionRedact) })
		validatorApproved, validatorRedact := outcome(func(t *testing.T) { installValidatorOnlyWorld(t, getDeploymentOrgID(), "") })
		if engineApproved != validatorApproved || engineRedact != validatorRedact {
			t.Fatalf("with no handshake the engine's own redaction answers approved=%v requires_redaction=%v and the validator's answers approved=%v requires_redaction=%v; one discharge rule must give one answer",
				engineApproved, engineRedact, validatorApproved, validatorRedact)
		}
		t.Logf("no handshake, both: approved=%v requires_redaction=%v", engineApproved, engineRedact)
	})
	t.Run("CONTROL, no override: not told to redact, and no validator named", func(t *testing.T) {
		_, cleanup := setupPreCheckAuditTest(t)
		defer cleanup()
		installValidatorOnlyWorld(t, getDeploymentOrgID(), "")
		resp := preCheckFor(t, newPreCheckRecorderWithHandshake(t, "Customer NIK is "+fixtureNIK, redactionHandshake(t)))
		if resp.RequiresRedaction || len(resp.LegacyValidators) != 0 {
			t.Fatalf("requires_redaction=%v legacy_validators=%+v; want neither with no override", resp.RequiresRedaction, resp.LegacyValidators)
		}
	})
}
