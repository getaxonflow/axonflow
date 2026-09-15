// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"axonflow/platform/agent"
)

// A WITHHELD RESPONSE'S CONTENT REACHES NO READER (PRD v11 §1.1).
//
// The response plane withholding a response is worth nothing if the refusal
// ships what it withheld. ProcessResponse substitutes an error map for the
// content before anything downstream runs, and the two readers a withheld
// response has - the caller, through the 403 body's `data`, and the auditor,
// through the blocked plane=llm row - are both built from that substitute.
//
// PR-1 REWROTE ProcessResponse, so this pins the property against the rewrite
// instead of trusting a reading of it: a marker planted in the LLM response
// appears in no value either reader can see. Every assertion is paired with a
// CONTROL that makes the same reader find the marker where it genuinely is,
// because "the marker is absent" is also what a reader looking at the wrong
// bytes reports.
//
// What this does NOT do: drive processHandler end to end. No handler-level
// harness for /api/v1/process exists, and standing one up would assert against
// my own copy of run.go's response literal rather than against run.go. The last
// test closes that gap from the other side, over run.go's source.

const withheldMarker = "w3ag-withheld-content-8c1f4d"

// withheldResponse runs one response the recorded pii=block withholds, and
// returns what ProcessResponse handed back for it.
func withheldResponse(t *testing.T) (interface{}, *RedactionInfo) {
	t.Helper()
	installResponseDetectors(t, map[string]string{"sys_pii_ssn": respSSN}, nil)
	installResponseEnforcer(t, respDocuments{}, func(context.Context, string) (map[string]agent.DetectionAction, error) {
		return map[string]agent.DetectionAction{agent.DetectionCategoryPII: agent.DetectionAction("block")}, nil
	})
	content := "Customer SSN is " + respSSN + ". Case note: " + withheldMarker + "."
	out, info := NewResponseProcessor().ProcessResponse(respContext(respHeaders()), respUser, &LLMResponse{Content: content})
	if info == nil || info.Verdict != responseVerdictBlocked {
		t.Fatalf("PREMISE: the response was not withheld (verdict %v); the assertions below would hold for an allowed response too", info)
	}
	// The control for every "absent" assertion below: the same reader, over the
	// content itself, finds both markers.
	if !strings.Contains(content, withheldMarker) || !strings.Contains(content, respSSN) {
		t.Fatal("CONTROL: the planted content does not carry the markers being searched for")
	}
	return out, info
}

func TestNoWithheldContentIsInTheRefusalThatWithholdsIt(t *testing.T) {
	out, info := withheldResponse(t)

	// 1. THE CALLER'S READER: the value run.go puts in the 403 body's `data`.
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("the withheld response's replacement does not encode: %v", err)
	}
	for _, secret := range []string{withheldMarker, respSSN} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the refusal's data carries the withheld content (%q): %s", secret, data)
		}
	}

	// 2. THE RECORD ITSELF: every member of the decision the row is stamped from,
	// including the reason text a refusal names.
	record, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("the decision record does not encode: %v", err)
	}
	for _, secret := range []string{withheldMarker, respSSN} {
		if strings.Contains(string(record), secret) {
			t.Errorf("the decision record carries the withheld content (%q): %s", secret, record)
		}
	}

	// 3. THE AUDITOR'S READER: the canonical blocked plane=llm row.
	entry := responsePlaneLogger().LogBlockedResponse(context.Background(), responsePlaneRequest(), &PolicyEvaluationResult{Allowed: false}, info, nil)
	row, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("the blocked row does not encode: %v", err)
	}
	for _, secret := range []string{withheldMarker, respSSN} {
		if strings.Contains(string(row), secret) {
			t.Errorf("the blocked audit row carries the withheld content (%q): %s", secret, row)
		}
	}

	// CONTROL for 3: the same reader over a row whose record DOES carry the
	// marker finds it, so the assertion above is capable of failing.
	leaky := decidedRecord(responseVerdictBlocked)
	leaky.ValidationError = "explicit_constraint: " + withheldMarker
	leakyRow, err := json.Marshal(responsePlaneLogger().LogBlockedResponse(context.Background(), responsePlaneRequest(), &PolicyEvaluationResult{Allowed: false}, leaky, nil))
	if err != nil {
		t.Fatalf("the control row does not encode: %v", err)
	}
	if !strings.Contains(string(leakyRow), withheldMarker) {
		t.Fatalf("CONTROL: a row whose record carries the marker reads as clean, so assertion 3 inspects bytes that could never carry it: %s", leakyRow)
	}
}

// TestTheRefusalIsBuiltFromTheSubstituteNotTheLLMResponse closes the gap the
// tests above leave: they hold what ProcessResponse RETURNS, and the 403 body is
// built in run.go. Rather than re-implementing that literal in a test - where it
// would agree with itself whatever run.go does - this reads run.go's blocked
// branch and requires that the only content it carries is the value
// ProcessResponse returned, and that the raw LLM response is not named in it.
func TestTheRefusalIsBuiltFromTheSubstituteNotTheLLMResponse(t *testing.T) {
	source, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("run.go is unreadable: %v", err)
	}
	const opens = "if redactionInfo != nil && redactionInfo.Verdict == responseVerdictBlocked {"
	start := strings.Index(string(source), opens)
	if start < 0 {
		t.Fatalf("the blocked branch is not in run.go under %q; this guard is anchored on a line that no longer exists", opens)
	}
	end := strings.Index(string(source)[start:], "\n\t}\n")
	if end < 0 {
		t.Fatal("the blocked branch does not close where this guard expects")
	}
	branch := string(source)[start : start+end]

	if !regexp.MustCompile(`Data:\s+processedResponse,`).MatchString(branch) {
		t.Errorf("the refusal's data is not the value ProcessResponse returned:\n%s", branch)
	}
	if strings.Contains(branch, "llmResponse") {
		t.Errorf("the refusal names the raw LLM response, which is the content it withheld:\n%s", branch)
	}
}
