// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// What a request pass is judged against, per handshake state
// (pepHandshakeResolution.requestProfile), on every plane that builds a pass
// from a handshake: decide, the gateway pre-check and both MCP passes.
//
// A caller that presents NO handshake is judged against the plane's registered
// profile (legacy_plane_peps.tsv). Under an organization's pii=redact that is a
// refusal on decide and the pre-check, whose rows discharge no field_redact,
// and a mask on the MCP passes, whose rows do. The organization's
// obligation-fallback posture never turns that refusal into an allow. A
// handshake that was presented and not admitted is never granted the plane's
// profile. This is the v11.0.0 Known Issue on #4249 row 5675016368: the fix is
// the gateway adapters presenting a handshake, and these tests pin the platform
// contract that fix relies on.
//
// Untagged, so both builds run it. The legacy_plane_peps.tsv row a caller is
// judged against is chosen by DEPLOYMENT_MODE (deploymode.PlaneEdition, as the
// snapshot the engine activates against chooses it), not by the build tag: the
// enf-harness decide and pre-check tests run enterprise mode, and
// TestAValidatorsRedactionRefusesACallerThatPresentsNoHandshake runs community
// mode. planeRowOfThisDeployment selects that row, and requireRowRedacts logs
// it and fails when it stops being the one an assertion describes. Only the capability-gap
// detail differs by build: an Enterprise build names it, a community build does
// not.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/agent/indonesia"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/deploymode"
	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/pep"
)

// planeRowOfThisDeployment is the legacy_plane_peps.tsv row a caller that
// presents no handshake is judged against on plane: the row for the edition
// DEPLOYMENT_MODE selects (deploymode.PlaneEdition), which is how the snapshot
// the engine activates against chooses it - not the build tag. Call it after the
// test has set its deployment mode.
func planeRowOfThisDeployment(t *testing.T, plane string) registry.LegacyPlaneRow {
	t.Helper()
	ed, ok := deploymode.PlaneEdition()
	if !ok {
		t.Fatalf("PREMISE: DEPLOYMENT_MODE %q is not a recognised mode", deploymode.Current())
	}
	rows, err := registry.ParseLegacyPlanes(registry.LegacyPlaneFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Plane == plane && r.Edition == ed {
			return r
		}
	}
	t.Fatalf("legacy_plane_peps.tsv has no %s row for the %s edition", plane, ed)
	return registry.LegacyPlaneRow{}
}

// requireRowRedacts fails unless plane's row for this deployment does (want) or
// does not discharge field_redact@1, the premise every assertion below rests on.
func requireRowRedacts(t *testing.T, plane string, want bool) {
	t.Helper()
	row := planeRowOfThisDeployment(t, plane)
	got := slices.Contains(row.Capabilities, contract.Capability{Type: contract.ObFieldRedact, Version: 1})
	if got != want {
		t.Fatalf("PREMISE: the %s row for the %s edition DEPLOYMENT_MODE=%q selects (line %d) discharges field_redact@1 = %v; this test describes %v", plane, row.Edition, deploymode.Current(), row.Line, got, want)
	}
	t.Logf("judged against legacy_plane_peps.tsv line %d: %s/%s %v (DEPLOYMENT_MODE=%q, build %s)", row.Line, row.Plane, row.Edition, row.Capabilities, deploymode.Current(), edition.Current)
}

// enterpriseNamesTheGap reports whether this build names an admitted
// enforcement point's capability gap after the refusal's own reason.
func enterpriseNamesTheGap() bool { return edition.Current == edition.Enterprise }

func TestRequestProfileReadsEachResolutionState(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	fieldRedact := contract.Capability{Type: contract.ObFieldRedact, Version: 1}
	mandatoryRedact := contract.Obligation{Type: contract.ObFieldRedact, SchemaVersion: 1, Mandatory: true}

	t.Run("no handshake: nil, which the pass judges against the plane's registered profile", func(t *testing.T) {
		res := resolvePEPHandshake(requestWithHandshake(), "acme")
		if res.outcome != pepHandshakeAbsent || res.refused {
			t.Fatalf("PREMISE: outcome=%q refused=%v; want absent and not refused", res.outcome, res.refused)
		}
		if got := res.requestProfile(); got != nil {
			t.Fatalf("an absent handshake produced profile %+v; want nil", got)
		}
	})

	// The MCP connector routes never read a header, so their passes carry the
	// zero value, whose outcome is "" and not absent (and so does a test that
	// calls a pass directly). It is a caller declaring nothing, exactly as absent
	// is; handing it the empty profile would refuse a redaction those planes
	// discharge (the regression the first version of requestProfile had, which
	// TestARequestRedactionIsDischargedOnlyWhereTheWireHandsTheStatementBack caught).
	t.Run("never resolved (the zero value): nil, as for no handshake", func(t *testing.T) {
		var res pepHandshakeResolution
		if res.outcome == pepHandshakeAbsent || res.refused || res.pep.Admitted() {
			t.Fatalf("PREMISE: the zero value is outcome=%q refused=%v admitted=%v; want an unresolved, unrefused, unadmitted value", res.outcome, res.refused, res.pep.Admitted())
		}
		if got := res.requestProfile(); got != nil {
			t.Fatalf("the zero value produced profile %+v; want nil, the plane's registered profile", got)
		}
	})

	// The default is the refusing answer: an outcome that is presented and
	// neither admitted nor marked refused - none exists today - gets the EMPTY
	// profile, so a future outcome that forgets refused cannot be granted the
	// plane's profile.
	t.Run("an outcome this build does not declare, neither admitted nor refused: the EMPTY profile", func(t *testing.T) {
		res := pepHandshakeResolution{outcome: "an-outcome-not-yet-declared"}
		if res.refused || res.pep.Admitted() {
			t.Fatalf("PREMISE: refused=%v admitted=%v; want neither", res.refused, res.pep.Admitted())
		}
		got := res.requestProfile()
		if got == nil || got.ID != unadmittedPEPProfileID || got.Capabilities == nil || len(got.Capabilities) != 0 {
			t.Fatalf("an undeclared outcome produced profile %+v; want the empty %q profile, never nil", got, unadmittedPEPProfileID)
		}
	})

	for _, c := range []struct {
		name string
		mode string
		caps []contract.Capability
	}{
		{"admitted, declaring field_redact@1", "enterprise", []contract.Capability{fieldRedact}},
		{"admitted, declaring nothing", "enterprise", nil},
		{"admitted on a community deployment (DEPLOYMENT_MODE unset), declaring field_redact@1", "", []contract.Capability{fieldRedact}},
	} {
		t.Run(c.name+": the declared profile, never nil", func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", c.mode)
			res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "request-profile", c.caps...)), "acme")
			if !res.pep.Admitted() {
				t.Fatalf("PREMISE: not admitted: outcome=%q detail=%q", res.outcome, res.detail)
			}
			got := res.requestProfile()
			if got == nil {
				t.Fatal("an admitted handshake produced a nil profile, which the engine would read as the plane's registered one")
			}
			if got.ID != res.pep.Record().ID || got.Capabilities == nil {
				t.Fatalf("profile %+v; want the admitted record %q with a non-nil capability list", got, res.pep.Record().ID)
			}
			if want := contract.SortCapabilities(c.caps); !slices.Equal(got.Capabilities, want) {
				t.Fatalf("capabilities %v; want the declared %v", got.Capabilities, want)
			}
			if got.Supports(mandatoryRedact) != (len(c.caps) > 0) {
				t.Fatalf("Supports(field_redact@1) = %v for a declaration of %v", got.Supports(mandatoryRedact), c.caps)
			}
		})
	}

	valid := encodedHandshake(t, "request-profile", fieldRedact)
	for _, c := range []struct {
		name string
		res  pepHandshakeResolution
	}{
		{"present and empty", resolvePEPHandshake(requestWithHandshake(""), "acme")},
		{"presented twice", resolvePEPHandshake(requestWithHandshake(valid, valid), "acme")},
		{"not a handshake", resolvePEPHandshake(requestWithHandshake("not-a-handshake!"), "acme")},
		{"a valid declaration on a channel with no client identity", resolvePEPHandshake(requestWithHandshake(valid), "")},
	} {
		t.Run(c.name+": an EMPTY profile, never the plane's", func(t *testing.T) {
			if !c.res.presented() || c.res.pep.Admitted() || !c.res.refused {
				t.Fatalf("PREMISE: presented=%v admitted=%v refused=%v outcome=%q; want presented, not admitted, refused",
					c.res.presented(), c.res.pep.Admitted(), c.res.refused, c.res.outcome)
			}
			if c.res.pep.Profile() != nil {
				t.Fatalf("PREMISE: the registry's profile is %+v; this case exists because the registry answers nil", c.res.pep.Profile())
			}
			got := c.res.requestProfile()
			if got == nil {
				t.Fatal("a handshake the platform did not admit produced a nil profile, which the engine grants the plane's registered profile")
			}
			if got.ID != unadmittedPEPProfileID || got.Capabilities == nil || len(got.Capabilities) != 0 || got.Supports(mandatoryRedact) {
				t.Fatalf("profile %+v; want %q with an empty, non-nil capability list that supports nothing", got, unadmittedPEPProfileID)
			}
		})
	}
}

// noHandshakeWorld installs the shipped PII control an organization's recorded
// pii override reaches on decide, records pii=redact for org and, unless
// fallback is empty, the organization's obligation-fallback posture beside it,
// and returns content that control's detector matches.
func noHandshakeWorld(t *testing.T, org string, fallback DetectionAction) string {
	t.Helper()
	row, _, probe := enfOverrideReachedControl(t, DetectionCategoryPII)
	enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta(probe)}, nil)
	postures := map[string]DetectionAction{DetectionCategoryPII: DetectionActionRedact}
	if fallback != "" {
		postures[DetectionCategoryObligationFallback] = fallback
	}
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{org: postures}}, time.Minute)
	return mrsRedactContent(probe)
}

// decideAsEnforcementPoint posts content to decide as enfUser of
// enfOrgPublished, from an enforcement point presenting handshake ("" presents
// none) and advertising fulfillment on #2958's axis (nil advertises nothing).
func decideAsEnforcementPoint(t *testing.T, content, handshake string, fulfillment *[]string) (int, DecideResponse, string) {
	t.Helper()
	body := DecideRequest{
		Stage: DecisionStageLLM, Target: DecisionTarget{Type: DecisionStageLLM}, Query: content,
		UserToken: enfMintUserToken(t, enfOrgPublished, enfUser), FulfillmentCapabilities: fulfillment,
	}
	req := decideEnterpriseReq(t, body, enfOrgPublished, enfOrgPublished)
	if handshake != "" {
		req.Header.Set(contract.PEPHandshakeHeader, handshake)
	}
	rr := httptest.NewRecorder()
	handleDecide(rr, req)
	var resp DecideResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("the decide body is not a DecideResponse: %v\n%s", err, rr.Body.String())
		}
	}
	return rr.Code, resp, rr.Body.String()
}

// expectDecisionRow expects the one decision audit row, written with verdict,
// and captures its policy_details; readDecisionRow checks it was written.
func expectDecisionRow(t *testing.T, verdict string) (sqlmock.Sqlmock, *[]byte) {
	t.Helper()
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	details := new([]byte)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(decideAuditInsertArgs(verdict, captureArg{dst: details})...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	return mock, details
}

func readDecisionRow(t *testing.T, mock sqlmock.Sqlmock, raw *[]byte, verdict string) map[string]any {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no decision audit row was written with policy_decision=%s: %v", verdict, err)
	}
	var d map[string]any
	if err := json.Unmarshal(*raw, &d); err != nil {
		t.Fatalf("policy_details is not a JSON object: %v\n%s", err, *raw)
	}
	return d
}

// wantNoFallbackOnRow asserts a row carries no trace of #2958's seam gate.
func wantNoFallbackOnRow(t *testing.T, d map[string]any) {
	t.Helper()
	for _, k := range []string{"suppressed_obligations", "obligation_fallback"} {
		if v, ok := d[k]; ok {
			t.Fatalf("the audit row carries %s=%v; the organization's obligation-fallback posture must not have been applied", k, v)
		}
	}
}

// wantRefusedUnsupported asserts a refusal whose own reason is
// unsupported_obligation, followed by the named capability gap on an
// Enterprise build when named is set, and by nothing otherwise.
func wantRefusedUnsupported(t *testing.T, reasons []string, named bool) {
	t.Helper()
	want := 1
	if named && enterpriseNamesTheGap() {
		want = 2
	}
	if len(reasons) != want || !strings.HasPrefix(reasons[0], string(contract.ReasonUnsupportedObligation)) {
		t.Fatalf("reasons %q; want %d reason(s), the first %s", reasons, want, contract.ReasonUnsupportedObligation)
	}
	if want == 2 && !strings.HasPrefix(reasons[1], pepCapabilityUnsupportedCode+": ") {
		t.Fatalf("reasons %q; want the %s detail after the refusal's own reason", reasons, pepCapabilityUnsupportedCode)
	}
}

func TestACallerThatPresentsNoHandshakeIsJudgedAgainstThePlaneProfileOnDecide(t *testing.T) {
	headersOnlySeam := &[]string{pep.CapabilityRequestHeaderMutation}
	bodySeam := &[]string{pep.CapabilityRequestBodyRedaction}

	for _, posture := range []DetectionAction{"", DetectionActionLog, DetectionActionBlock} {
		name := "obligation_fallback=" + string(posture)
		if posture == "" {
			name = "obligation_fallback not recorded"
		}
		t.Run(name, func(t *testing.T) {
			enfSetup(t)
			requireRowRedacts(t, "decide", false)
			content := noHandshakeWorld(t, enfOrgPublished, posture)

			for _, c := range []struct {
				name        string
				fulfillment *[]string
			}{
				{"no handshake, no seam declaration", nil},
				{"no handshake, the headers-only seam's #2958 declaration", headersOnlySeam},
				{"no handshake, the body-capable seam's #2958 declaration", bodySeam},
			} {
				t.Run(c.name+": refused unsupported_obligation, and the posture is not applied", func(t *testing.T) {
					mock, raw := expectDecisionRow(t, AuditVerdictBlocked)
					code, resp, body := decideAsEnforcementPoint(t, content, "", c.fulfillment)
					if code != http.StatusOK || resp.Verdict != VerdictDeny || len(resp.Obligations) != 0 {
						t.Fatalf("HTTP %d verdict %q obligations %+v; want 200 deny carrying nothing. body=%s", code, resp.Verdict, resp.Obligations, body)
					}
					if !slices.Equal(resp.Reasons, []string{string(contract.ReasonUnsupportedObligation)}) {
						t.Fatalf("reasons %q; want exactly [%s]: no fallback reason and no capability gap for a caller that declared nothing", resp.Reasons, contract.ReasonUnsupportedObligation)
					}
					d := readDecisionRow(t, mock, raw, AuditVerdictBlocked)
					wantNoFallbackOnRow(t, d)
					if _, ok := d["pep_id"]; ok {
						t.Fatalf("the row names an enforcement point %v for a caller that presented no handshake", d["pep_id"])
					}
				})
			}

			t.Run("CONTROL, a handshake declaring field_redact@1: allowed and handed the redaction", func(t *testing.T) {
				mock, raw := expectDecisionRow(t, AuditVerdictAllowed)
				code, resp, body := decideAsEnforcementPoint(t, content, redactionHandshake(t), nil)
				if code != http.StatusOK || resp.Verdict != VerdictAllow || requestRedactions(resp) != 1 {
					t.Fatalf("HTTP %d verdict %q obligations %+v; want allow carrying one request redact_pii. body=%s", code, resp.Verdict, resp.Obligations, body)
				}
				d := readDecisionRow(t, mock, raw, AuditVerdictAllowed)
				wantNoFallbackOnRow(t, d)
				if caps, _ := d["pep_capabilities"].([]any); len(caps) != 1 || caps[0] != "field_redact@1" {
					t.Fatalf("the row's pep_capabilities = %v; want [field_redact@1]", d["pep_capabilities"])
				}
			})

			for _, c := range []struct{ name, handshake string }{
				{"a handshake declaring nothing", encodedHandshake(t, "decide-declared-none")},
				{"a handshake declaring only immutable_audit@1", encodedHandshake(t, "decide-audit-only", contract.Capability{Type: contract.ObImmutableAudit, Version: 1})},
			} {
				t.Run(c.name+": still refused, whatever the posture", func(t *testing.T) {
					mock, raw := expectDecisionRow(t, AuditVerdictBlocked)
					code, resp, body := decideAsEnforcementPoint(t, content, c.handshake, headersOnlySeam)
					if code != http.StatusOK || resp.Verdict != VerdictDeny || len(resp.Obligations) != 0 {
						t.Fatalf("HTTP %d verdict %q obligations %+v; want deny. body=%s", code, resp.Verdict, resp.Obligations, body)
					}
					wantRefusedUnsupported(t, resp.Reasons, true)
					wantNoFallbackOnRow(t, readDecisionRow(t, mock, raw, AuditVerdictBlocked))
				})
			}

			// The posture is reachable only where the caller's two declarations
			// disagree: a handshake that can discharge field_redact on a seam that
			// says it cannot rewrite a body. The engine hands the obligation over,
			// and #2958's gate then withholds it under the posture.
			t.Run("a field_redact@1 handshake from a seam that declares it cannot rewrite a body: the posture decides", func(t *testing.T) {
				verdict, rowVerdict, reason := VerdictAllow, AuditVerdictAllowed, obligationFallbackLogReason
				if posture == DetectionActionBlock {
					verdict, rowVerdict, reason = VerdictDeny, AuditVerdictBlocked, obligationFallbackDenyReason
				}
				mock, raw := expectDecisionRow(t, rowVerdict)
				code, resp, body := decideAsEnforcementPoint(t, content, redactionHandshake(t), headersOnlySeam)
				if code != http.StatusOK || resp.Verdict != verdict || requestRedactions(resp) != 0 || !slices.Contains(resp.Reasons, reason) {
					t.Fatalf("HTTP %d verdict %q reasons %q obligations %+v; want %s with %q and no redaction handed over. body=%s", code, resp.Verdict, resp.Reasons, resp.Obligations, verdict, reason, body)
				}
				d := readDecisionRow(t, mock, raw, rowVerdict)
				wantAction := string(DetectionActionLog)
				if posture == DetectionActionBlock {
					wantAction = string(DetectionActionBlock)
				}
				if d["obligation_fallback"] != wantAction {
					t.Fatalf("the row's obligation_fallback = %v; want %s", d["obligation_fallback"], wantAction)
				}
			})
		})
	}

	t.Run("a present but empty header is refused before evaluation", func(t *testing.T) {
		enfSetup(t)
		content := noHandshakeWorld(t, enfOrgPublished, "")
		body := DecideRequest{Stage: DecisionStageLLM, Target: DecisionTarget{Type: DecisionStageLLM}, Query: content, UserToken: enfMintUserToken(t, enfOrgPublished, enfUser)}
		req := decideEnterpriseReq(t, body, enfOrgPublished, enfOrgPublished)
		req.Header[http.CanonicalHeaderKey(contract.PEPHandshakeHeader)] = []string{""}
		rr := httptest.NewRecorder()
		handleDecide(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), pepHandshakeMalformedReason) {
			t.Fatalf("HTTP %d body %s; want 400 %s", rr.Code, rr.Body.String(), pepHandshakeMalformedReason)
		}
	})
}

func TestACallerThatPresentsNoHandshakeKeepsItsRefusalWhenTheAuditStoreFails(t *testing.T) {
	enfSetup(t)
	requireRowRedacts(t, "decide", false)
	content := noHandshakeWorld(t, enfOrgPublished, DetectionActionLog)

	t.Run("no database: refused, and the failed write is counted", func(t *testing.T) {
		orig := usageDB
		usageDB = nil
		t.Cleanup(func() { usageDB = orig })
		before := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("nodb"))
		code, resp, body := decideAsEnforcementPoint(t, content, "", nil)
		if code != http.StatusOK || resp.Verdict != VerdictDeny || !slices.Equal(resp.Reasons, []string{string(contract.ReasonUnsupportedObligation)}) {
			t.Fatalf("HTTP %d verdict %q reasons %q; want the refusal to stand. body=%s", code, resp.Verdict, resp.Reasons, body)
		}
		if after := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("nodb")); after != before+1 {
			t.Fatalf("decide_audit_write_failures{reason=nodb} moved %v -> %v; want +1", before, after)
		}
	})

	t.Run("the insert fails: refused, and the failed write is counted", func(t *testing.T) {
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		mock.ExpectExec("INSERT INTO audit_logs").WillReturnError(errAuditStoreDown)
		before := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("insert"))
		code, resp, body := decideAsEnforcementPoint(t, content, "", nil)
		if code != http.StatusOK || resp.Verdict != VerdictDeny || !slices.Equal(resp.Reasons, []string{string(contract.ReasonUnsupportedObligation)}) {
			t.Fatalf("HTTP %d verdict %q reasons %q; want the refusal to stand. body=%s", code, resp.Verdict, resp.Reasons, body)
		}
		if after := testutil.ToFloat64(decideAuditWriteFailures.WithLabelValues("insert")); after != before+1 {
			t.Fatalf("decide_audit_write_failures{reason=insert} moved %v -> %v; want +1", before, after)
		}
	})

	t.Run("replayed: the same refusal and one row per request, with nothing suppressed", func(t *testing.T) {
		var ids []string
		var rows []map[string]any
		for i := 0; i < 2; i++ {
			mock, raw := expectDecisionRow(t, AuditVerdictBlocked)
			code, resp, body := decideAsEnforcementPoint(t, content, "", nil)
			if code != http.StatusOK || resp.Verdict != VerdictDeny || !slices.Equal(resp.Reasons, []string{string(contract.ReasonUnsupportedObligation)}) {
				t.Fatalf("request %d: HTTP %d verdict %q reasons %q. body=%s", i+1, code, resp.Verdict, resp.Reasons, body)
			}
			d := readDecisionRow(t, mock, raw, AuditVerdictBlocked)
			wantNoFallbackOnRow(t, d)
			ids, rows = append(ids, resp.DecisionID), append(rows, d)
		}
		if ids[0] == "" || ids[0] == ids[1] {
			t.Fatalf("decision ids %q; want two distinct decisions, one per request", ids)
		}
		for _, k := range []string{"reasons", "policy_ids", "engine"} {
			a, _ := json.Marshal(rows[0][k])
			b, _ := json.Marshal(rows[1][k])
			if string(a) != string(b) {
				t.Fatalf("the replayed row's %s = %s; the first row's = %s", k, b, a)
			}
		}
	})
}

// errAuditStoreDown is the failure the audit insert answers with when the
// audit store is unavailable.
var errAuditStoreDown = errors.New("the audit store is unavailable")

// preCheckWithRawHandshake is enfPreCheckWithHandshake with the header set to
// exactly values, so a present but empty header can be sent (Header.Set would
// send it, but enfPreCheckWithHandshake reads "" as "present none").
func preCheckWithRawHandshake(t *testing.T, org, userToken, query string, values ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(PreCheckRequest{ClientID: "auth-client", UserToken: userToken, Query: query})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header[http.CanonicalHeaderKey(contract.PEPHandshakeHeader)] = values
	ctx := req.Context()
	ctx = context.WithValue(ctx, ContextKeyTenantID, org)
	ctx = context.WithValue(ctx, ContextKeyOrgID, org)
	ctx = context.WithValue(ctx, ContextKeyClientID, "auth-client")
	ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req.WithContext(ctx))
	return rr
}

func TestACallerThatPresentsNoHandshakeIsJudgedAgainstThePlaneProfileOnThePreCheck(t *testing.T) {
	for _, posture := range []DetectionAction{"", DetectionActionLog, DetectionActionBlock} {
		name := "obligation_fallback=" + string(posture)
		if posture == "" {
			name = "obligation_fallback not recorded"
		}
		t.Run(name, func(t *testing.T) {
			enfSetup(t)
			requireRowRedacts(t, "gateway_request", false)
			content := noHandshakeWorld(t, enfOrgPublished, posture)
			token := enfMintUserToken(t, enfOrgPublished, enfUser)

			r := enfPreCheckWithHandshake(t, enfOrgPublished, token, content, "")
			if r.code != http.StatusOK || r.approved(t) || r.str(t, "block_reason") != string(contract.ReasonUnsupportedObligation) {
				t.Fatalf("no handshake: HTTP %d approved=%v block_reason %q; want a refusal whose reason is %s alone. body=%s", r.code, r.approved(t), r.str(t, "block_reason"), contract.ReasonUnsupportedObligation, r.raw)
			}

			r = enfPreCheckWithHandshake(t, enfOrgPublished, token, content, redactionHandshake(t))
			var approved PreCheckResponse
			if err := json.Unmarshal(r.raw, &approved); err != nil {
				t.Fatal(err)
			}
			if !approved.Approved || !approved.RequiresRedaction {
				t.Fatalf("CONTROL, a handshake declaring field_redact@1: approved=%v requires_redaction=%v; want approved and told to redact. body=%s", approved.Approved, approved.RequiresRedaction, r.raw)
			}

			r = enfPreCheckWithHandshake(t, enfOrgPublished, token, content, encodedHandshake(t, "precheck-declared-none"))
			if r.approved(t) {
				t.Fatalf("a handshake declaring nothing was approved. body=%s", r.raw)
			}
			wantRefusedUnsupported(t, strings.SplitN(r.str(t, "block_reason"), "; ", 2), true)
		})
	}

	t.Run("a present but empty header is refused before evaluation", func(t *testing.T) {
		enfSetup(t)
		content := noHandshakeWorld(t, enfOrgPublished, "")
		rr := preCheckWithRawHandshake(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), content, "")
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), pepHandshakeMalformedReason) {
			t.Fatalf("HTTP %d body %s; want 400 %s", rr.Code, rr.Body.String(), pepHandshakeMalformedReason)
		}
	})
}

// The pre-seam checksum validators' redaction (attachValidatorRedactions) reads
// the same profile: a caller that presents no handshake is judged against the
// plane's registered profile there too, and refused, where the parity tests in
// legacy_validators_test.go accept either answer.
func TestAValidatorsRedactionRefusesACallerThatPresentsNoHandshake(t *testing.T) {
	query := "Customer NIK is " + fixtureNIK

	t.Run("decide, community deployment mode", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		t.Setenv("ENVIRONMENT", "development")
		requireRowRedacts(t, "decide", false)
		// Pin the Indonesia detector the validators read, so this subtest does not
		// depend on which earlier test first created it. It is created lazily
		// behind indonesiaPIIDetectorOnce; getIndonesiaPIIDetector() fires the Once
		// BEFORE the value is saved, so this cleanup cannot leave a fired Once over
		// nil for the tests after it (the hazard setupPreCheckAuditTest had).
		origIndo := getIndonesiaPIIDetector()
		indonesiaPIIDetector = indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
		t.Cleanup(func() { indonesiaPIIDetector = origIndo })
		installCircuitBreakerWithMockDB(t)
		org := getDeploymentOrgID()

		installValidatorOnlyWorld(t, org, DetectionActionRedact)
		captureAuditDetails(t, 21)
		resp := decideForLegacyWith(t, query, "")
		if resp.Verdict != VerdictDeny || len(resp.Reasons) != 1 || !strings.HasPrefix(resp.Reasons[0], string(contract.ReasonUnsupportedObligation)) || !strings.Contains(resp.Reasons[0], legacyValidatorIndonesia) {
			t.Fatalf("no handshake: verdict %q reasons %q; want one unsupported_obligation reason naming %s", resp.Verdict, resp.Reasons, legacyValidatorIndonesia)
		}

		installValidatorOnlyWorld(t, org, DetectionActionRedact)
		captureAuditDetails(t, 21)
		resp = decideForLegacyWith(t, query, redactionHandshake(t))
		if resp.Verdict != VerdictAllow || requestRedactions(resp) != 1 {
			t.Fatalf("CONTROL, a handshake declaring field_redact@1: verdict %q obligations %+v; want allow carrying one request redact_pii", resp.Verdict, resp.Obligations)
		}

		// The engine's own redaction, on the same deployment mode: the same answer.
		installNIKWorld(t, org, DetectionActionRedact)
		captureAuditDetails(t, 21)
		resp = decideForLegacyWith(t, query, "")
		if resp.Verdict != VerdictDeny || !slices.Equal(resp.Reasons, []string{string(contract.ReasonUnsupportedObligation)}) {
			t.Fatalf("no handshake, the engine's own redaction: verdict %q reasons %q; want deny [%s]", resp.Verdict, resp.Reasons, contract.ReasonUnsupportedObligation)
		}
	})

	t.Run("the gateway pre-check", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		requireRowRedacts(t, "gateway_request", false)
		redact := func(c *ModeDetectionConfig) { c.PIIAction = DetectionActionRedact }
		preCheck := func(handshake string) PreCheckResponse {
			_, cleanup := setupPreCheckAuditTest(t)
			t.Cleanup(cleanup)
			installValidatorOnlyWorld(t, getDeploymentOrgID(), "")
			pinGatewayOverride(t, redact)
			return preCheckFor(t, newPreCheckRecorderWithHandshake(t, query, handshake))
		}

		resp := preCheck("")
		if resp.Approved || !strings.HasPrefix(resp.BlockReason, string(contract.ReasonUnsupportedObligation)) || !strings.Contains(resp.BlockReason, legacyValidatorIndonesia) {
			t.Fatalf("no handshake: approved=%v block_reason %q; want a refusal unsupported_obligation naming %s", resp.Approved, resp.BlockReason, legacyValidatorIndonesia)
		}
		resp = preCheck(redactionHandshake(t))
		if !resp.Approved || !resp.RequiresRedaction {
			t.Fatalf("CONTROL, a handshake declaring field_redact@1: approved=%v requires_redaction=%v; want approved and told to redact", resp.Approved, resp.RequiresRedaction)
		}

		// The engine's own redaction on the same community pre-check: the same
		// answer, so the community gateway_request row is exercised by the
		// engine's refusal and not only by the validators'.
		_, cleanup := setupPreCheckAuditTest(t)
		t.Cleanup(cleanup)
		installNIKWorld(t, getDeploymentOrgID(), DetectionActionRedact)
		pinGatewayOverride(t, redact)
		resp = preCheckFor(t, newPreCheckRecorderWithHandshake(t, query, ""))
		// EXACTLY the engine's reason: the validator is live in this world too,
		// and its refusal carries the same prefix followed by the validator's
		// name, so a prefix match would pass with the engine's control removed.
		if resp.Approved || resp.BlockReason != string(contract.ReasonUnsupportedObligation) {
			t.Fatalf("no handshake, the engine's own redaction: approved=%v block_reason %q; want exactly %s, the engine's refusal and not the validator's", resp.Approved, resp.BlockReason, contract.ReasonUnsupportedObligation)
		}
	})
}

// The MCP passes build their pass from the same helper, and their rows DO
// discharge field_redact: a caller that presents no handshake is masked exactly
// as a caller declaring field_redact@1 is. The declared-empty leg is what makes
// the helper's nil distinguishable from an empty profile on these planes.
func TestTheMCPRequestPassMasksForACallerThatPresentsNoHandshake(t *testing.T) {
	w := mrsSetup(t)
	requireRowRedacts(t, "mcp", true)
	row, probe := mrqRedactWorld(t, w.org)
	enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta(probe)}, nil)
	w.mrsWire(t, w.docs)
	token := mrsToken(t)
	statement := mrsRedactContent(probe)

	for _, c := range []struct{ name, handshake string }{
		{"no handshake", ""},
		{"a handshake declaring field_redact@1", redactionHandshake(t)},
	} {
		code, raw, r := mrqCheckInput(t, token, statement, c.handshake)
		if code != http.StatusOK || !r.Redacted || strings.Contains(r.RedactedStatement, probe) {
			t.Fatalf("%s: HTTP %d redacted=%v statement %q; want the statement handed back masked. body=%s", c.name, code, r.Redacted, r.RedactedStatement, raw)
		}
	}
	code, raw, r := mrqCheckInput(t, token, statement, encodedHandshake(t, "mcp-request-declared-none"))
	if code != http.StatusForbidden || r.Allowed || !strings.HasPrefix(r.BlockReason, string(contract.ReasonUnsupportedObligation)) {
		t.Fatalf("a handshake declaring nothing: HTTP %d allowed=%v block_reason %q; want 403 unsupported_obligation, not the plane's profile. body=%s", code, r.Allowed, r.BlockReason, raw)
	}
}

func TestTheMCPResponsePassMasksForACallerThatPresentsNoHandshake(t *testing.T) {
	w := mrsSetup(t)
	requireRowRedacts(t, "mcp", true)
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}, time.Minute)
	w.mrsWire(t, w.docs)
	token := mrsToken(t)
	content := mrsRedactContent(w.redactProbe)

	for _, c := range []struct{ name, handshake string }{
		{"no handshake", ""},
		{"a handshake declaring field_redact@1", redactionHandshake(t)},
	} {
		r := mrsCheckOutputWith(t, token, content, c.handshake)
		masked, ok := r.body.RedactedData.(string)
		if r.code != http.StatusOK || !ok || strings.Contains(masked, w.redactProbe) {
			t.Fatalf("%s: HTTP %d redacted=%v; want the response released masked. body=%s", c.name, r.code, r.body.RedactedData, r.raw)
		}
	}
	r := mrsCheckOutputWith(t, token, content, encodedHandshake(t, "mcp-response-declared-none"))
	if r.body.Allowed || r.body.Engine != decisionEngineAnchored ||
		!strings.HasPrefix(strings.TrimPrefix(r.body.BlockReason, "Response blocked: "), string(contract.ReasonUnsupportedObligation)) {
		t.Fatalf("a handshake declaring nothing: HTTP %d allowed=%v engine=%q block_reason %q; want the anchored engine's unsupported_obligation refusal, not the plane's profile. body=%s", r.code, r.body.Allowed, r.body.Engine, r.body.BlockReason, r.raw)
	}
}
