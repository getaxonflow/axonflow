// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"axonflow/platform/shared/pep"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Seam-capability-aware obligations (#2958).
//
// The property under test: /decide must never hand a PEP an obligation its seam
// cannot discharge, because the PEP's only safe response to one is to block —
// which is how an `allow` became a client-facing 403 and took a design
// partner's LLM chat offline. What happens INSTEAD to content a policy wanted
// redacted is the PDP's decision (the org's obligation-fallback posture), not
// the PEP's.

// capableSeam / headersOnlySeam are the two advertisements under test, named so
// the assertions read as behavior rather than as string literals.
var (
	capableSeam     = []string{pep.CapabilityRequestBodyRedaction}
	headersOnlySeam = []string{pep.CapabilityRequestHeaderMutation}
)

// redactObligations returns the obligation slice a PII-matching policy produces.
func redactObligations() []DecisionObligation {
	return []DecisionObligation{newRedactPIIObligation("PII detected: [nric]")}
}

func hasRedactObligation(obs []DecisionObligation) bool {
	for _, o := range obs {
		if requiresRequestBodyRedaction(o) {
			return true
		}
	}
	return false
}

func TestApplySeamCapabilityObligations_CapableSeamKeepsObligation(t *testing.T) {
	// A body-capable seam gets the obligation and fulfills it — the redaction
	// path this whole mechanism exists to preserve.
	installTestOverrideCache(t, &fakeOverrideReader{}, time.Minute)

	verdict, reasons, obs, fb := applySeamCapabilityObligations(
		context.Background(), "org-1", capableSeam, VerdictAllow, []string{}, redactObligations())

	if verdict != VerdictAllow {
		t.Errorf("verdict = %q, want allow", verdict)
	}
	if !hasRedactObligation(obs) {
		t.Error("a seam that CAN redact must still receive the redact_pii obligation")
	}
	if fb != nil {
		t.Errorf("no obligation was suppressed, so there must be no fallback: %+v", fb)
	}
	if len(reasons) != 0 {
		t.Errorf("reasons must be untouched when nothing is suppressed: %v", reasons)
	}
}

func TestApplySeamCapabilityObligations_NonCapableSeamLogFallbackAllows(t *testing.T) {
	// The default posture, and the fix for the reported outage: allow the
	// request, withhold the obligation, and hand the caller a reason it can log.
	installTestOverrideCache(t, &fakeOverrideReader{}, time.Minute)

	verdict, reasons, obs, fb := applySeamCapabilityObligations(
		context.Background(), "org-1", headersOnlySeam, VerdictAllow, []string{}, redactObligations())

	if verdict != VerdictAllow {
		t.Errorf("verdict = %q, want allow — the log posture must not become a deny", verdict)
	}
	if hasRedactObligation(obs) {
		t.Error("the obligation MUST be withheld from a seam that cannot fulfill it — emitting it is what forces the PEP to 403")
	}
	if fb == nil {
		t.Fatal("a suppressed obligation must be reported so it can be audited + counted")
	}
	if fb.action != DetectionActionLog {
		t.Errorf("fallback action = %q, want log (the default)", fb.action)
	}
	if len(fb.suppressed) != 1 || fb.suppressed[0].Type != ObligationRedactPII {
		t.Errorf("fallback must name what was suppressed, got %+v", fb.suppressed)
	}
	if fb.suppressed[0].Detail != "PII detected: [nric]" {
		t.Errorf("the suppressed obligation must keep its detail for the audit row, got %q", fb.suppressed[0].Detail)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "suppressed") {
		t.Errorf("the response must say a redaction was suppressed, got %v", reasons)
	}
}

func TestApplySeamCapabilityObligations_NonCapableSeamBlockFallbackDenies(t *testing.T) {
	// An org that refuses detect-and-log for content it wanted masked.
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
		"org-strict": {DetectionCategoryObligationFallback: DetectionActionBlock},
	}}, time.Minute)

	verdict, reasons, obs, fb := applySeamCapabilityObligations(
		context.Background(), "org-strict", headersOnlySeam, VerdictAllow, []string{}, redactObligations())

	if verdict != VerdictDeny {
		t.Errorf("verdict = %q, want deny under the block posture", verdict)
	}
	if len(obs) != 0 {
		t.Errorf("a deny carries no obligations, got %+v", obs)
	}
	if fb == nil || fb.action != DetectionActionBlock {
		t.Fatalf("fallback = %+v, want action=block", fb)
	}
	if len(fb.suppressed) != 1 {
		t.Errorf("the block path must still record WHAT was suppressed for the audit row, got %+v", fb.suppressed)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "obligation-fallback") {
		t.Errorf("the deny must explain itself, got %v", reasons)
	}
}

func TestApplySeamCapabilityObligations_PostureReadFromOrgNotRequest(t *testing.T) {
	// The security property: a caller steers WHICH obligations it is offered,
	// never what happens when one is suppressed. Two identical requests, two
	// orgs, two outcomes — driven only by server-side config.
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
		"org-strict": {DetectionCategoryObligationFallback: DetectionActionBlock},
	}}, time.Minute)

	strict, _, _, _ := applySeamCapabilityObligations(
		context.Background(), "org-strict", headersOnlySeam, VerdictAllow, []string{}, redactObligations())
	lenient, _, _, _ := applySeamCapabilityObligations(
		context.Background(), "org-lenient", headersOnlySeam, VerdictAllow, []string{}, redactObligations())

	if strict != VerdictDeny {
		t.Errorf("org-strict verdict = %q, want deny", strict)
	}
	if lenient != VerdictAllow {
		t.Errorf("org-lenient verdict = %q, want allow", lenient)
	}
}

func TestApplySeamCapabilityObligations_LegacyCallerUnchanged(t *testing.T) {
	// Every SDK, the desktop proxy and the plugins are in this bucket. If this
	// regresses, they start losing redactions silently.
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
		// Even an org that configured `block` must not affect a legacy caller:
		// the posture only applies to a suppression, and nothing is suppressed.
		"org-strict": {DetectionCategoryObligationFallback: DetectionActionBlock},
	}}, time.Minute)

	for _, tc := range []struct {
		name string
		caps []string
	}{
		{"absent (nil)", nil},
		{"explicit empty", []string{}},
		{"blank entries only", []string{"", "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := redactObligations()
			verdict, reasons, obs, fb := applySeamCapabilityObligations(
				context.Background(), "org-strict", tc.caps, VerdictAllow, []string{}, in)

			if verdict != VerdictAllow {
				t.Errorf("verdict = %q, want allow (unchanged)", verdict)
			}
			if !hasRedactObligation(obs) {
				t.Error("a legacy caller MUST still receive the obligation — silently dropping it would forward unredacted PII")
			}
			if fb != nil {
				t.Errorf("a legacy caller must never trigger a fallback: %+v", fb)
			}
			if len(reasons) != 0 {
				t.Errorf("reasons must be untouched for a legacy caller: %v", reasons)
			}
		})
	}
}

func TestApplySeamCapabilityObligations_LegacyResponseIsByteIdentical(t *testing.T) {
	// Stronger than the field-by-field check above: the SERIALIZED verdict a
	// legacy caller receives must be byte-for-byte what it received before this
	// change — that is the actual backward-compatibility contract.
	installTestOverrideCache(t, &fakeOverrideReader{}, time.Minute)

	build := func(verdict string, reasons []string, obs []DecisionObligation) []byte {
		b, err := json.Marshal(DecideResponse{
			Verdict: verdict, DecisionID: "dec-1", TraceID: "trace-1", Stage: "llm",
			Reasons: reasons, Obligations: obs, EvaluatedPolicies: []string{"sys_pii_singapore_nric"},
			ExpiresAt: time.Unix(0, 0).UTC(),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}

	// What the pre-#2958 handler produced: no gate, obligation emitted.
	want := build(VerdictAllow, []string{}, redactObligations())

	// What the gated handler produces for the same legacy request.
	verdict, reasons, obs, _ := applySeamCapabilityObligations(
		context.Background(), "org-1", nil, VerdictAllow, []string{}, redactObligations())
	got := build(verdict, reasons, obs)

	if string(got) != string(want) {
		t.Errorf("legacy decide response changed shape:\n got: %s\nwant: %s", got, want)
	}
}

func TestApplySeamCapabilityObligations_GarbageCapabilitiesAreNotCapable(t *testing.T) {
	// Unknown/forged tokens must never be mistaken for a capability, and must
	// never raise an error — an older PDP meeting a newer PEP's vocabulary has
	// to degrade, not fail. A garbage set reads as "not capable", which routes
	// to the org posture (safe), never to "emit the obligation anyway".
	installTestOverrideCache(t, &fakeOverrideReader{}, time.Minute)

	for _, caps := range [][]string{
		{"bogus"},
		{"REQUEST_BODY_REDACTION_X"},
		{"request_body_redaction_but_not_really"},
		{"'; DROP TABLE audit_logs; --"},
		{strings.Repeat("x", 5000)},  // over-long: unusable, but still an advertisement
		{"request_body_redactio"},    // near-miss (truncated constant)
		{" request_body_redaction "}, // padded — canonicalization trims, so VALID
	} {
		verdict, _, obs, fb := applySeamCapabilityObligations(
			context.Background(), "org-1", caps, VerdictAllow, []string{}, redactObligations())

		if verdict != VerdictAllow {
			t.Errorf("caps=%q: verdict = %q, want allow (garbage must never block)", caps, verdict)
		}
		padded := strings.TrimSpace(caps[0]) == pep.CapabilityRequestBodyRedaction
		if padded {
			// Canonicalization trims, so this IS a valid advertisement.
			if !hasRedactObligation(obs) || fb != nil {
				t.Errorf("caps=%q: a padded but valid capability must be honored", caps)
			}
			continue
		}
		if hasRedactObligation(obs) {
			t.Errorf("caps=%q: an unknown token must not be treated as request_body_redaction", caps)
		}
		if fb == nil {
			t.Errorf("caps=%q: expected the org fallback to apply", caps)
		}
	}
}

func TestApplySeamCapabilityObligations_CapabilitySetIsBounded(t *testing.T) {
	// A hostile caller must not be able to make the PDP do unbounded work — in
	// memory OR in iteration — on the decide hot path.
	//
	// The DUPLICATE payload is the interesting one: it collapses to a one-entry
	// map, so a cap on the map SIZE would never trip and the loop would walk all
	// 10k entries. The bound therefore has to be on the input index.
	huge := make([]string, 10_000)
	for i := range huge {
		huge[i] = "junk"
	}
	got, advertised := canonicalizeFulfillmentCapabilities(huge)
	if len(got) > maxFulfillmentCapabilities {
		t.Errorf("canonicalized set size = %d, want <= %d", len(got), maxFulfillmentCapabilities)
	}
	if !advertised {
		t.Error("a non-blank entry is an advertisement even when the value is unknown")
	}

	// Over-long entries are not stored (an unbounded key would let a caller size
	// the map) but DO still count as an advertisement — otherwise a long garbage
	// token would masquerade as a legacy caller.
	long, advertisedLong := canonicalizeFulfillmentCapabilities([]string{strings.Repeat("a", maxFulfillmentCapabilityLen+1)})
	if len(long) != 0 {
		t.Errorf("an over-long capability must not be stored, got %v", long)
	}
	if !advertisedLong {
		t.Error("an over-long token is still an advertisement — treating it as legacy would emit the obligation to a caller that told us it is capability-aware")
	}

	// Blank padding alone is NOT an advertisement.
	if _, adv := canonicalizeFulfillmentCapabilities([]string{"", "  "}); adv {
		t.Error("blank entries must not count as an advertisement")
	}

	// Truncation must fail SAFE: a real capability pushed out past the index cap
	// reads as NOT capable (→ org fallback), never as capable.
	installTestOverrideCache(t, &fakeOverrideReader{}, time.Minute)
	overflow := append(append([]string{}, huge[:maxFulfillmentCapabilities]...), pep.CapabilityRequestBodyRedaction)
	_, _, obs, fb := applySeamCapabilityObligations(
		context.Background(), "org-1", overflow, VerdictAllow, []string{}, redactObligations())
	if hasRedactObligation(obs) {
		t.Error("a capability truncated away by the bound must read as NOT capable (fail-safe), not as capable")
	}
	if fb == nil {
		t.Error("the truncated-away capability must route to the org fallback posture")
	}
}

func TestApplySeamCapabilityObligations_NonAllowVerdictsUntouched(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
		"org-strict": {DetectionCategoryObligationFallback: DetectionActionBlock},
	}}, time.Minute)

	for _, v := range []string{VerdictDeny, VerdictNeedsApproval} {
		verdict, _, _, fb := applySeamCapabilityObligations(
			context.Background(), "org-strict", headersOnlySeam, v, []string{"policy"}, nil)
		if verdict != v {
			t.Errorf("verdict %q was rewritten to %q — the gate must only ever act on an allow", v, verdict)
		}
		if fb != nil {
			t.Errorf("verdict %q produced a fallback: %+v", v, fb)
		}
	}
}

func TestApplySeamCapabilityObligations_NonRedactObligationsPassThrough(t *testing.T) {
	// Only request-BODY redaction needs the body capability. A hypothetical
	// future obligation that a headers-only seam CAN discharge must not be
	// collateral damage, and must not trigger a fallback.
	installTestOverrideCache(t, &fakeOverrideReader{}, time.Minute)

	other := DecisionObligation{Type: "annotate_header", Detail: "x"}
	// A redact_pii with NO fulfillment block: pep.HasRequestRedaction does not
	// report it, so no PEP would try to discharge it → it needs no capability.
	unfulfillable := DecisionObligation{Type: ObligationRedactPII, Detail: "no fulfillment"}

	verdict, _, obs, fb := applySeamCapabilityObligations(
		context.Background(), "org-1", headersOnlySeam, VerdictAllow, []string{},
		[]DecisionObligation{other, unfulfillable})

	if verdict != VerdictAllow {
		t.Errorf("verdict = %q, want allow", verdict)
	}
	if len(obs) != 2 {
		t.Errorf("non-body-redaction obligations must pass through untouched, got %+v", obs)
	}
	if fb != nil {
		t.Errorf("nothing needed the body capability, so there must be no fallback: %+v", fb)
	}
}

// TestObligationAttachmentSiteCensus is the structural guard that makes the
// "single choke point" claim TRUE rather than aspirational.
//
// The gate works by filtering the FINAL obligation slice, so it covers every
// attachment site that exists today AND any added later — but only as long as
// obligations reach the response through handleDecide's terminal path. This
// census pins the two known emitters and fails if a third appears, forcing
// whoever adds it to confirm it flows through the gate rather than around it.
// (#2625's audit-hole class came from exactly this: a rule copied per-site
// instead of enforced at one choke point.)
func TestObligationAttachmentSiteCensus(t *testing.T) {
	// Scan the WHOLE package, not just decision_handler.go: an attachment site
	// (or a writer of DecideResponse.Obligations) added in a sibling file would
	// bypass both the gate and a single-file census, which would make this test
	// claim a property it does not enforce.
	pkg, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package: %v", err)
	}
	callRe := regexp.MustCompile(`newRedactPIIObligation\(`)
	obligationWriteRe := regexp.MustCompile(`Obligations:\s`)

	calls := map[string]int{}
	writers := map[string]int{}
	for _, f := range pkg {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, rErr := os.ReadFile(f)
		if rErr != nil {
			t.Fatalf("read %s: %v", f, rErr)
		}
		if n := len(callRe.FindAllString(string(b), -1)); n > 0 {
			calls[f] = n
		}
		if n := len(obligationWriteRe.FindAllString(string(b), -1)); n > 0 {
			writers[f] = n
		}
	}

	// 1 definition + 2 attachment sites, all in decision_handler.go.
	const wantDefinitionPlusSites = 3
	if len(calls) != 1 || calls["decision_handler.go"] != wantDefinitionPlusSites {
		t.Errorf("newRedactPIIObligation call census = %v, expected exactly {decision_handler.go: %d} "+
			"(1 definition + 2 attachment sites: mapPolicyResultToVerdict and the India/Indonesia validator merge).\n"+
			"If you ADDED an attachment site: confirm its obligations flow through applySeamCapabilityObligations "+
			"(they do if you appended to the `obligations` slice before the gate runs) and update this census. "+
			"If you added one that BYPASSES the gate — writing straight to the response or the audit row — that is the "+
			"#2958 bug re-opening: a PEP would receive an obligation its seam cannot discharge and would have to block.",
			calls, wantDefinitionPlusSites)
	}

	// Every producer of a DecideResponse.Obligations value must be a file whose
	// obligations went through the gate. decision_handler.go is the only one
	// today (the response write + the two mapPolicyResultToVerdict returns).
	for f := range writers {
		if f != "decision_handler.go" {
			t.Errorf("%s writes an Obligations field outside decision_handler.go — if that value reaches a PEP "+
				"without passing applySeamCapabilityObligations, a non-capable seam can be handed an obligation "+
				"it cannot discharge (#2958). Route it through the gate or census it consciously.", f)
		}
	}

	// The gate must run on the terminal path, between the attachment sites and
	// the response write. If someone deletes the call, every test above still
	// passes (they call the function directly) while production regresses.
	src, err := os.ReadFile("decision_handler.go")
	if err != nil {
		t.Fatalf("read decision_handler.go: %v", err)
	}
	if !strings.Contains(string(src), "applySeamCapabilityObligations(") {
		t.Error("handleDecide no longer calls applySeamCapabilityObligations — the gate is bypassed in production")
	}
}

// TestFulfillmentCapabilityReadCensus pins EVERY place the client-supplied
// fulfillment_capabilities field is read (#2958).
//
// Rationale (the #2896 lesson, [[feedback_forgeable_input_census_writers_and_body_and_global_gate]]):
// this field is untrusted input that STEERS a policy outcome. It is safe only
// because it is read at exactly ONE server-side gate that cannot widen
// authority — the fallback posture comes from the org, never the request. A
// second read site is how that property quietly dies, so a new one fails CI and
// forces a conscious review instead of tribal knowledge.
func TestFulfillmentCapabilityReadCensus(t *testing.T) {
	allowed := map[string]string{
		"platform/agent/decision_handler.go":        "THE gate: DecideRequest schema + applySeamCapabilityObligations, the single site that reads the advertised set",
		"platform/shared/pep/pep.go":                "client-side mirror of the published contract + the capability vocabulary constants (no read — this is the PEP's own request it is building)",
		"ee/platform/agent/gateway_adapters/pdp.go": "PEP side: stamps the per-seam capability set onto its OWN outbound request (a write, not an ingest read)",
	}
	found := userTokenCensusScan(t, func(c string) bool {
		return strings.Contains(c, "FulfillmentCapabilities") ||
			strings.Contains(c, `json:"fulfillment_capabilities`)
	})
	assertCensusExact(t, "fulfillment_capabilities reference", found, allowed)

	// The gate is the only site that may consult the capability VOCABULARY to
	// make a decision. A platform file comparing against the constant is a
	// second decision point by definition.
	deciders := userTokenCensusScan(t, func(c string) bool {
		return strings.Contains(c, "CapabilityRequestBodyRedaction")
	})
	for f := range deciders {
		switch f {
		case "platform/agent/decision_handler.go", "platform/shared/pep/pep.go",
			"ee/platform/agent/gateway_adapters/pdp.go":
		default:
			t.Errorf("%s consults the capability vocabulary outside the single gate — "+
				"the outcome of a suppressed obligation must be resolved from the ORG posture at one place, not per-caller (#2958)", f)
		}
	}
	_ = filepath.Separator // keep filepath imported for the scan helper's contract
}

// --- ResolveObligationFallbackAction (#2958) ---

func TestResolveObligationFallbackAction_Postures(t *testing.T) {
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
		"org-block":  {DetectionCategoryObligationFallback: DetectionActionBlock},
		"org-log":    {DetectionCategoryObligationFallback: DetectionActionLog},
		"org-other":  {DetectionCategoryPII: DetectionActionRedact}, // a DIFFERENT category
		"org-legacy": {},
	}}, time.Minute)
	t.Cleanup(ResetObligationFallbackWarnForTest)

	for _, tc := range []struct {
		name string
		org  string
		want DetectionAction
	}{
		{"explicit block", "org-block", DetectionActionBlock},
		{"explicit log", "org-log", DetectionActionLog},
		{"no obligation_fallback row → default", "org-other", DetectionActionLog},
		{"org with no overrides at all → default", "org-legacy", DetectionActionLog},
		{"unknown org → default", "org-never-seen", DetectionActionLog},
		{"empty org → default", "", DetectionActionLog},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveObligationFallbackAction(context.Background(), tc.org); got != tc.want {
				t.Errorf("ResolveObligationFallbackAction(%q) = %q, want %q", tc.org, got, tc.want)
			}
		})
	}
}

func TestResolveObligationFallbackAction_PIIPostureDoesNotLeakIn(t *testing.T) {
	// The reason this category exists: the pii lever must NOT drive this axis.
	// An org with pii=block is a plausible mis-read of the design ("surely
	// pii=block means block here too"), so pin that it does not.
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
		"org-pii-block": {DetectionCategoryPII: DetectionActionBlock},
	}}, time.Minute)

	if got := ResolveObligationFallbackAction(context.Background(), "org-pii-block"); got != DetectionActionLog {
		t.Errorf("pii posture leaked into the obligation-fallback axis: got %q, want log — these are independent levers (that is why mig 144 exists)", got)
	}
}

func TestResolveObligationFallbackAction_UnusableValueFallsBackToLogWithWarn(t *testing.T) {
	// redact/warn are unreachable through the portal (it rejects them for this
	// category) but a hand-edited DB can hold them. Fail toward the documented
	// default, never toward denying live traffic on a config typo.
	for _, stored := range []DetectionAction{DetectionActionRedact, DetectionActionWarn, DetectionAction("nonsense")} {
		t.Run(string(stored), func(t *testing.T) {
			installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
				"org-typo": {DetectionCategoryObligationFallback: stored},
			}}, time.Minute)
			ResetObligationFallbackWarnForTest()
			t.Cleanup(ResetObligationFallbackWarnForTest)

			var buf bytes.Buffer
			log.SetOutput(&buf)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			if got := ResolveObligationFallbackAction(context.Background(), "org-typo"); got != DetectionActionLog {
				t.Errorf("stored %q → %q, want log", stored, got)
			}
			if !strings.Contains(buf.String(), "not enforceable") {
				t.Errorf("an unusable posture must WARN so it is diagnosable, log was: %q", buf.String())
			}
			if !strings.Contains(buf.String(), string(stored)) {
				t.Errorf("the WARN must name the offending value, log was: %q", buf.String())
			}
		})
	}
}

func TestResolveObligationFallbackAction_WarnIsRateLimited(t *testing.T) {
	// This runs on the decide hot path: a single misconfigured org must not be
	// able to flood the log with one line per request.
	installTestOverrideCache(t, &fakeOverrideReader{data: map[string]map[string]DetectionAction{
		"org-typo": {DetectionCategoryObligationFallback: DetectionActionRedact},
	}}, time.Minute)
	ResetObligationFallbackWarnForTest()
	t.Cleanup(ResetObligationFallbackWarnForTest)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	for i := 0; i < 50; i++ {
		if got := ResolveObligationFallbackAction(context.Background(), "org-typo"); got != DetectionActionLog {
			t.Fatalf("call %d: got %q, want log", i, got)
		}
	}
	if n := strings.Count(buf.String(), "not enforceable"); n != 1 {
		t.Errorf("50 resolutions produced %d WARN lines, want exactly 1 (rate-limited per org)", n)
	}
}

func TestResolveObligationFallbackAction_CacheErrorFailsSafeToDefault(t *testing.T) {
	// A DB problem must not deny live traffic, and must not error out of the
	// hot path — the cache already fails safe to "no overrides".
	installTestOverrideCache(t, &fakeOverrideReader{err: errors.New("db down")}, time.Minute)

	if got := ResolveObligationFallbackAction(context.Background(), "org-1"); got != DetectionActionLog {
		t.Errorf("on a lookup failure: got %q, want log (fail-safe to the documented default)", got)
	}
}

func TestResolveObligationFallbackAction_NoCacheWiredFallsBackToDefault(t *testing.T) {
	// Community / no-DB deployments never wire the cache.
	ResetDetectionOverrideCacheForTest()
	if got := ResolveObligationFallbackAction(context.Background(), "org-1"); got != DetectionActionLog {
		t.Errorf("with no cache wired: got %q, want log", got)
	}
}

// --- Audit observability of a suppressed obligation (#2958) ---

// TestSuppressedObligationIsAudited is the compliance-critical assertion.
//
// Under the log posture the PEP is told to do NOTHING: the verdict is a plain
// allow and the obligations column is empty. This audit row is therefore the
// ONLY record that PII was detected and that a redaction was withheld.
// Suppressing the obligation AND the audit trail would be a worse regression
// than the 403 this change removes — partner ask #4 is detect+audit, not silent
// allow.
func TestSuppressedObligationIsAudited(t *testing.T) {
	suppressed := redactObligations()
	details := buildDecisionAuditDetails(
		"dec-1", "llm",
		[]string{"sys_pii_singapore_nric"},
		[]string{obligationFallbackLogReason},
		nil, false,
		decisionAuditInput{
			clientID: "gw", requestID: "req-1", plane: PlaneDecision,
			obligations:           nil, // withheld — the PEP was told to do nothing
			suppressedObligations: suppressed,
			obligationFallback:    string(DetectionActionLog),
		})

	// Round-trip through JSON: this lands in a JSONB column, so the contract is
	// what survives serialization, not the Go map.
	raw, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("policy_details must be marshalable: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("policy_details is not valid JSON: %v", err)
	}

	if got["obligation_fallback"] != string(DetectionActionLog) {
		t.Errorf("policy_details.obligation_fallback = %v, want %q — without it a reader cannot tell an ordinary allow from an allow that WITHHELD a redaction",
			got["obligation_fallback"], DetectionActionLog)
	}
	sup, ok := got["suppressed_obligations"].([]interface{})
	if !ok || len(sup) != 1 {
		t.Fatalf("policy_details.suppressed_obligations = %v, want 1 entry", got["suppressed_obligations"])
	}
	entry, _ := sup[0].(map[string]interface{})
	if entry["type"] != ObligationRedactPII {
		t.Errorf("suppressed obligation type = %v, want %q", entry["type"], ObligationRedactPII)
	}
	if entry["detail"] != "PII detected: [nric]" {
		t.Errorf("suppressed obligation detail = %v, want the detected categories — this IS the detect-and-audit record", entry["detail"])
	}
	// The triggering policies must still be recorded: they are the detected
	// categories a compliance reader queries on.
	ids, _ := got["policy_ids"].([]interface{})
	if len(ids) != 1 || ids[0] != "sys_pii_singapore_nric" {
		t.Errorf("policy_ids = %v, want the triggering PII policy", got["policy_ids"])
	}
	if reason, _ := got["reason"].(string); !strings.Contains(reason, "suppressed") {
		t.Errorf("policy_details.reason = %q, want it to explain the suppression (explain_handler reads this scalar)", reason)
	}
}

// TestSuppressedObligationIsAuditedUnderBlockPosture: the deny path must record
// the same evidence — an auditor asks "what did we detect and what did we do",
// and "denied" is only half the answer.
func TestSuppressedObligationIsAuditedUnderBlockPosture(t *testing.T) {
	details := buildDecisionAuditDetails(
		"dec-2", "llm",
		[]string{"sys_pii_singapore_nric"},
		[]string{obligationFallbackDenyReason},
		nil, false,
		decisionAuditInput{
			clientID: "gw", requestID: "req-2", plane: PlaneDecision,
			suppressedObligations: redactObligations(),
			obligationFallback:    string(DetectionActionBlock),
		})

	if details["obligation_fallback"] != string(DetectionActionBlock) {
		t.Errorf("obligation_fallback = %v, want block", details["obligation_fallback"])
	}
	if sup, ok := details["suppressed_obligations"].([]map[string]string); !ok || len(sup) != 1 {
		t.Errorf("the block path must also record WHAT was suppressed, got %v", details["suppressed_obligations"])
	}
}

// TestOrdinaryAllowCarriesNoSuppressionFields pins the negative: a normal
// decision must not gain these keys, or every audit consumer sees noise and the
// "this row withheld a redaction" signal stops meaning anything.
func TestOrdinaryAllowCarriesNoSuppressionFields(t *testing.T) {
	details := buildDecisionAuditDetails(
		"dec-3", "llm", []string{}, []string{}, nil, false,
		decisionAuditInput{clientID: "gw", requestID: "r", plane: PlaneDecision})

	if _, present := details["suppressed_obligations"]; present {
		t.Error("an ordinary allow must not carry suppressed_obligations")
	}
	if _, present := details["obligation_fallback"]; present {
		t.Error("an ordinary allow must not carry obligation_fallback")
	}
}

// --- Fallback metric (#2958) ---

// TestObligationFallbackMetric: a seam silently degrading to detect-and-log is
// exactly the condition an operator must be able to alert on — it means content
// a policy wanted masked is reaching a backend unmasked. It has to be counted
// on BOTH postures, because a fallback can end in allow or deny.
func TestObligationFallbackMetric(t *testing.T) {
	const origin = "gateway"

	for _, tc := range []struct {
		name    string
		action  DetectionAction
		verdict string
	}{
		{"log posture (allow)", DetectionActionLog, VerdictAllow},
		{"block posture (deny)", DetectionActionBlock, VerdictDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := testutil.ToFloat64(decideObligationFallbacks.WithLabelValues(
				ObligationRedactPII, string(tc.action), "llm", origin))

			recordDecideOutcomeMetrics(tc.verdict, "llm", origin, nil, "", "", nil,
				&obligationFallback{action: tc.action, suppressed: redactObligations()})

			after := testutil.ToFloat64(decideObligationFallbacks.WithLabelValues(
				ObligationRedactPII, string(tc.action), "llm", origin))
			if after != before+1 {
				t.Errorf("decideObligationFallbacks{%s} = %v, want %v", tc.action, after, before+1)
			}
		})
	}
}

func TestObligationFallbackMetricNotEmittedWithoutFallback(t *testing.T) {
	const origin = "sdk"
	before := testutil.CollectAndCount(decideObligationFallbacks)
	// An ordinary allow WITH an obligation (the capable-seam path) is not a
	// fallback and must not be counted as one.
	recordDecideOutcomeMetrics(VerdictAllow, "llm", origin, redactObligations(), "", "", nil, nil)
	if got := testutil.CollectAndCount(decideObligationFallbacks); got != before {
		t.Errorf("a non-fallback decision emitted a fallback series (%d -> %d)", before, got)
	}
}

func TestObligationFallbackMetricSkipsTypelessObligation(t *testing.T) {
	// A malformed obligation must not create an empty-label series.
	before := testutil.CollectAndCount(decideObligationFallbacks)
	recordDecideOutcomeMetrics(VerdictAllow, "llm", "gateway", nil, "", "", nil,
		&obligationFallback{action: DetectionActionLog, suppressed: []DecisionObligation{{}}})
	if got := testutil.CollectAndCount(decideObligationFallbacks); got != before {
		t.Errorf("a type-less obligation created a metric series (%d -> %d)", before, got)
	}
}
