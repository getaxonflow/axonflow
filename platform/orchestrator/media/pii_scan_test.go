// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// recordingEngine is a PIIEngine that records the options it was asked with and
// answers a fixed result.
type recordingEngine struct {
	result *sharedpolicy.RequestResult
	opts   []sharedpolicy.EvalOptions
	inputs []string
	// noCategories answers no enabled text PII category.
	noCategories bool
	// categoryAsks records the tenant, org and phase each category read named.
	categoryAsks []string
}

func (e *recordingEngine) EvaluateRequest(_ context.Context, input string, opts sharedpolicy.EvalOptions) *sharedpolicy.RequestResult {
	e.inputs = append(e.inputs, input)
	e.opts = append(e.opts, opts)
	return e.result
}

func (e *recordingEngine) EnabledPIICategories(_ context.Context, tenantID string, orgID *string, phase sharedpolicy.Phase) []sharedpolicy.PolicyCategory {
	org := "<nil>"
	if orgID != nil {
		org = *orgID
	}
	e.categoryAsks = append(e.categoryAsks, tenantID+"/"+org+"/"+string(phase))
	if e.noCategories {
		return nil
	}
	return sharedpolicy.AllTextPIICategories()
}

// ranResult is a RequestResult whose detector facts report that a PII detector
// ran, with the given matches.
func ranResult(matches ...sharedpolicy.PolicyMatch) *sharedpolicy.RequestResult {
	return &sharedpolicy.RequestResult{
		MatchedPolicies: matches,
		Observation:     &sharedpolicy.Observation{Rows: []sharedpolicy.DetectorFact{{PolicyID: "sys_pii_ssn", Ran: true}}},
	}
}

func scoped() context.Context {
	return WithScanScope(context.Background(), ScanScope{OrgID: "org-1", TenantID: "tenant-1", UserID: "user-1"})
}

// TestEnginePIIDetectorMapsMatchesAndIgnoresTheEngineVerdict: each PII match
// becomes a finding typed by its policy id; a non-PII match is not a PII finding;
// the engine's Blocked verdict changes nothing (the decision is the anchored
// engine's over signal.media.has_pii).
func TestEnginePIIDetectorMapsMatchesAndIgnoresTheEngineVerdict(t *testing.T) {
	eng := &recordingEngine{result: &sharedpolicy.RequestResult{
		Observation: &sharedpolicy.Observation{Rows: []sharedpolicy.DetectorFact{{PolicyID: "sys_pii_ssn", Ran: true}}},
		Blocked:     true,
		BlockedBy:   &sharedpolicy.CompiledPolicy{PolicyID: "sys_pii_indonesia_ktp"},
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{PolicyID: "sys_pii_ssn", Category: sharedpolicy.CategoryPIIUS, MatchText: "123-45-6789", StartIndex: 4, EndIndex: 15, Confidence: 0.9},
			{PolicyID: "sys_sqli_union", Category: sharedpolicy.CategorySecuritySQLi, MatchText: "UNION SELECT", StartIndex: 20, EndIndex: 32, Confidence: 1},
		},
	}}
	detect := NewEnginePIIDetector(func() PIIEngine { return eng }, "local-ocr")

	findings, err := detect(scoped(), "SSN 123-45-6789 and UNION SELECT")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	want := []PIIFinding{{Type: "sys_pii_ssn", Value: "123-45-6789", Redacted: "[redacted]", Confidence: 0.9, StartIndex: 4, EndIndex: 15}}
	if !reflect.DeepEqual(findings, want) {
		t.Errorf("findings = %+v, want %+v", findings, want)
	}
}

// TestEnginePIIDetectorAsksForTheTextPIICategoriesUnderTheRequestsOrg pins the
// evaluation options: the organization and tenant from the scan scope (the load
// scope included), the text PII categories exactly, and ConnectorName
// "media:<analyzer>" - the field a recorded violation carries, which names the
// image as the source. (The orchestrator's engine is built with no audit queue,
// run.go, so it records no violation rows; the marker is on the evaluation.)
func TestEnginePIIDetectorAsksForTheTextPIICategoriesUnderTheRequestsOrg(t *testing.T) {
	eng := &recordingEngine{result: ranResult()}
	detect := NewEnginePIIDetector(func() PIIEngine { return eng }, "local-ocr")

	findings, err := detect(scoped(), "nothing here")
	if err != nil || len(findings) != 0 {
		t.Fatalf("clean scan: findings=%v err=%v", findings, err)
	}
	if len(eng.opts) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(eng.opts))
	}
	o := eng.opts[0]
	if o.OrgID != "org-1" || o.TenantID != "tenant-1" || o.UserID != "user-1" || o.OrgScope == nil || *o.OrgScope != "org-1" {
		t.Errorf("scope = org %q tenant %q user %q load scope %v, want org-1/tenant-1/user-1 with load scope org-1", o.OrgID, o.TenantID, o.UserID, o.OrgScope)
	}
	if o.ConnectorName != "media:local-ocr" {
		t.Errorf("ConnectorName = %q, want media:local-ocr", o.ConnectorName)
	}
	if !reflect.DeepEqual(o.Categories, sharedpolicy.AllTextPIICategories()) {
		t.Errorf("Categories = %v, want the text PII categories %v", o.Categories, sharedpolicy.AllTextPIICategories())
	}
	if want := []string{"tenant-1/org-1/" + string(sharedpolicy.PhaseRequest)}; !reflect.DeepEqual(eng.categoryAsks, want) {
		t.Errorf("enabled-category reads = %v, want %v", eng.categoryAsks, want)
	}
}

// TestEnginePIIDetectorDoesNotScanWithoutAnOrgAnEngineOrItsPolicies: each is
// ErrPIIScanNotRun, never an empty scan - including an organization with no
// enabled text PII category and a pass in which no detector reports it ran
// (R3 round 1: an empty detector set must not state has_pii false).
func TestEnginePIIDetectorDoesNotScanWithoutAnOrgAnEngineOrItsPolicies(t *testing.T) {
	// Every engine below except the case's own defect reports a detector that
	// ran, so each case is refused by its own guard and names its own reason.
	ran := func() PIIEngine { return &recordingEngine{result: ranResult()} }
	loadFailed := ranResult()
	loadFailed.EvaluationError, loadFailed.Blocked = true, true
	cases := map[string]struct {
		ctx    context.Context
		engine func() PIIEngine
		reason string
	}{
		"no scan scope":                {context.Background(), ran, "no organization scope"},
		"scope with no org":            {WithScanScope(context.Background(), ScanScope{TenantID: "tenant-1"}), ran, "no organization scope"},
		"no engine installed":          {scoped(), func() PIIEngine { return nil }, "no policy engine"},
		"nil engine provider":          {scoped(), nil, "no policy engine"},
		"engine returned nil":          {scoped(), func() PIIEngine { return &recordingEngine{} }, "returned no result"},
		"no enabled text PII category": {scoped(), func() PIIEngine { return &recordingEngine{result: ranResult(), noCategories: true} }, "no enabled text PII detector"},
		"no detector reported as run":  {scoped(), func() PIIEngine { return &recordingEngine{result: &sharedpolicy.RequestResult{}} }, "no PII detector ran"},
		"policies failed to load":      {scoped(), func() PIIEngine { return &recordingEngine{result: loadFailed} }, "could not load"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := NewEnginePIIDetector(c.engine, "local-ocr")(c.ctx, "SSN 123-45-6789")
			if !errors.Is(err, ErrPIIScanNotRun) || findings != nil {
				t.Fatalf("findings=%v err=%v, want nil and ErrPIIScanNotRun", findings, err)
			}
			if !strings.Contains(err.Error(), c.reason) {
				t.Errorf("err=%v, want the reason %q", err, c.reason)
			}
		})
	}
}

// TestGlobalPIIEngineIsNilWithoutAnInstalledEngine: a nil *UnifiedPolicyEngine
// must not reach the adapter as a non-nil interface.
func TestGlobalPIIEngineIsNilWithoutAnInstalledEngine(t *testing.T) {
	if sharedpolicy.GetGlobalEngine() != nil {
		t.Skip("a global engine is installed in this process")
	}
	if e := globalPIIEngine(); e != nil {
		t.Errorf("globalPIIEngine() = %#v, want nil", e)
	}
}

// fakeTesseract writes an executable standing in for tesseract that prints
// out (or fails when fail is set), and returns its path.
func fakeTesseract(t *testing.T, out string, fail bool) string {
	t.Helper()
	body := "#!/bin/sh\ncat >/dev/null\nprintf '%s' '" + strings.ReplaceAll(out, "'", "'\\''") + "'\n"
	if fail {
		body = "#!/bin/sh\ncat >/dev/null\necho 'tesseract: cannot read image' >&2\nexit 1\n"
	}
	path := filepath.Join(t.TempDir(), "tesseract")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake tesseract: %v", err)
	}
	return path
}

// TestLocalOCRRecordsWhatRan covers every state of a local OCR analysis: text
// extraction and the PII scan are recorded as RUN only when they ran, so an
// empty finding list is "no PII" only beside PIIScanned (#4249 row 5705208432).
func TestLocalOCRRecordsWhatRan(t *testing.T) {
	ssnEngine := &recordingEngine{result: ranResult(
		sharedpolicy.PolicyMatch{PolicyID: "sys_pii_ssn", Category: sharedpolicy.CategoryPIIUS, MatchText: "123-45-6789", StartIndex: 4, EndIndex: 15, Confidence: 1},
	)}
	scanner := NewEnginePIIDetector(func() PIIEngine { return ssnEngine }, "local-ocr")
	failing := func(context.Context, string) ([]PIIFinding, error) { return nil, ErrPIIScanNotRun }

	cases := []struct {
		name          string
		out           string
		fail          bool
		detector      PIIDetectorFunc
		ctx           context.Context
		wantText      bool
		wantScanned   bool
		wantFindings  int
		wantErrSubstr string
	}{
		{"text with an SSN is scanned", "SSN 123-45-6789", false, scanner, scoped(), true, true, 1, ""},
		{"empty text from a successful OCR is a scan with nothing to find", "   ", false, scanner, scoped(), true, true, 0, ""},
		{"OCR failure: nothing ran", "", true, scanner, scoped(), false, false, 0, "OCR failed"},
		{"detector did not run: text extracted, not scanned", "SSN 123-45-6789", false, failing, scoped(), true, false, 0, "PII scan did not run"},
		{"no scan scope: text extracted, not scanned", "SSN 123-45-6789", false, scanner, context.Background(), true, false, 0, "PII scan did not run"},
		{"no detector injected: text extracted, not scanned", "SSN 123-45-6789", false, nil, scoped(), true, false, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := NewLocalOCRAnalyzer("local-ocr", fakeTesseract(t, c.out, c.fail), "eng", c.detector)
			r, err := a.Analyze(c.ctx, validTestMedia()[0])
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if r.TextExtracted != c.wantText || r.PIIScanned != c.wantScanned || len(r.PIIFindings) != c.wantFindings {
				t.Errorf("text_extracted=%v pii_scanned=%v findings=%d, want %v/%v/%d (error %q)",
					r.TextExtracted, r.PIIScanned, len(r.PIIFindings), c.wantText, c.wantScanned, c.wantFindings, r.Error)
			}
			if c.wantErrSubstr != "" && !strings.Contains(r.Error, c.wantErrSubstr) {
				t.Errorf("error = %q, want it to contain %q", r.Error, c.wantErrSubstr)
			}
			// The pipeline passes Error into the media_pii_scan_not_run warning,
			// the response and the audit record: it must never carry the text.
			if strings.Contains(r.Error, "123-45-6789") {
				t.Errorf("error %q carries the extracted text", r.Error)
			}
		})
	}
}

// TestLocalOCRScansALongTextWhole: no text cap is added (the image cap bounds
// the input); a few MiB of extracted text reach the detector whole.
func TestLocalOCRScansALongTextWhole(t *testing.T) {
	long := strings.Repeat("lorem ipsum dolor sit amet ", 150000) + "SSN 123-45-6789"
	eng := &recordingEngine{result: ranResult()}
	a := NewLocalOCRAnalyzer("local-ocr", fakeTesseract(t, long, false), "eng", NewEnginePIIDetector(func() PIIEngine { return eng }, "local-ocr"))
	if _, err := a.Analyze(scoped(), validTestMedia()[0]); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(eng.inputs) != 1 || len(eng.inputs[0]) != len(strings.TrimSpace(long)) {
		t.Fatalf("scanned %d input(s) of length %v, want one of %d", len(eng.inputs), lens(eng.inputs), len(strings.TrimSpace(long)))
	}
}

func lens(ss []string) []int {
	out := make([]int, len(ss))
	for i, s := range ss {
		out[i] = len(s)
	}
	return out
}

// TestTheFactoryInjectsTheEngineBackedDetector: the production factory injects
// the engine-backed scan, so the capability is advertised and a scan runs on
// the installed engine (#4300: it injected nil).
func TestTheFactoryInjectsTheEngineBackedDetector(t *testing.T) {
	eng := &recordingEngine{result: ranResult(
		sharedpolicy.PolicyMatch{PolicyID: "sys_pii_email", Category: sharedpolicy.CategoryPIIGlobal, MatchText: "a@b.example", StartIndex: 0, EndIndex: 11, Confidence: 1},
	)}
	prev := globalPIIEngine
	globalPIIEngine = func() PIIEngine { return eng }
	t.Cleanup(func() { globalPIIEngine = prev })

	analyzer, err := CreateAnalyzer(AnalyzerConfig{
		Name: "local-ocr", Type: AnalyzerTypeLocalOCR, Enabled: true,
		Settings: map[string]any{"tesseract_path": fakeTesseract(t, "a@b.example", false)},
	})
	if err != nil {
		t.Fatalf("CreateAnalyzer: %v", err)
	}
	hasPII := false
	for _, c := range analyzer.Capabilities() {
		if c == CapabilityPIIDetection {
			hasPII = true
		}
	}
	if !hasPII {
		t.Error("the factory-built analyzer does not advertise PII detection")
	}
	r, err := analyzer.Analyze(scoped(), validTestMedia()[0])
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !r.PIIScanned || len(r.PIIFindings) != 1 || r.PIIFindings[0].Type != "sys_pii_email" {
		t.Errorf("factory analyzer: pii_scanned=%v findings=%+v, want scanned with sys_pii_email", r.PIIScanned, r.PIIFindings)
	}
	if len(eng.opts) != 1 || eng.opts[0].ConnectorName != "media:local-ocr" {
		t.Errorf("engine evaluations = %+v, want one marked media:local-ocr", eng.opts)
	}
}

// TestTheLocalOCRFactoryInjectsTheScan is the local half of the analyzer
// census: local OCR's factory injects the engine-backed PII scan. The cloud
// analyzers' half is in pii_scan_enterprise_test.go, because their source files
// are enterprise-only and the community mirror does not carry them.
func TestTheLocalOCRFactoryInjectsTheScan(t *testing.T) {
	b, err := os.ReadFile("local_ocr.go")
	if err != nil {
		t.Fatalf("read local_ocr.go: %v", err)
	}
	if !strings.Contains(string(b), "NewEnginePIIDetector(globalPIIEngine, config.Name)") {
		t.Error("local_ocr.go's factory does not inject the engine-backed PII scan")
	}
}

// TestScannedListsWhatRanFromTheResultsNotTheAdvertisedCapabilities: an
// analyzer that returns no section for a capability did not run it, whatever
// it advertises (the cloud analyzers are stubs returning empty results). The
// aggregated Scanned list is what a governance signal is stated from.
func TestScannedListsWhatRanFromTheResultsNotTheAdvertisedCapabilities(t *testing.T) {
	cases := []struct {
		name      string
		analyzers []MediaAnalyzer
		want      []string
	}{
		{"an empty result states nothing", []MediaAnalyzer{&mockPipelineAnalyzer{name: "stub", result: &MediaAnalysisResult{AnalyzerName: "stub"}}}, nil},
		{"no analyzers states nothing", nil, nil},
		{"content safety section", []MediaAnalyzer{&mockPipelineAnalyzer{name: "safety", result: &MediaAnalysisResult{AnalyzerName: "safety", ContentSafety: &ContentSafetyResult{IsSafe: true}}}}, []string{ScanContentSafety}},
		{"faces scanned with none found", []MediaAnalyzer{&mockPipelineAnalyzer{name: "faces", result: &MediaAnalysisResult{AnalyzerName: "faces", FacesScanned: true}}}, []string{ScanFaces}},
		{"faces found are a scan", []MediaAnalyzer{&mockPipelineAnalyzer{name: "faces", result: &MediaAnalysisResult{AnalyzerName: "faces", Faces: []FaceDetection{{Confidence: 1}}}}}, []string{ScanFaces}},
		{"document section", []MediaAnalyzer{&mockPipelineAnalyzer{name: "doc", result: &MediaAnalysisResult{AnalyzerName: "doc", DocumentClassification: &DocumentClassification{DocumentType: "passport"}}}}, []string{ScanDocument}},
		{"OCR text and PII scan", []MediaAnalyzer{&mockPipelineAnalyzer{name: "ocr", result: &MediaAnalysisResult{AnalyzerName: "ocr", TextExtracted: true, PIIScanned: true}}}, []string{ScanPII, ScanText}},
		{"OCR text, PII not scanned", []MediaAnalyzer{&mockPipelineAnalyzer{name: "ocr", result: &MediaAnalysisResult{AnalyzerName: "ocr", TextExtracted: true, ExtractedText: "SSN 123-45-6789"}}}, []string{ScanText}},
		{"PII findings are a scan", []MediaAnalyzer{&mockPipelineAnalyzer{name: "ocr", result: &MediaAnalysisResult{AnalyzerName: "ocr", PIIFindings: []PIIFinding{{Type: "sys_pii_ssn"}}}}}, []string{ScanPII}},
		{"two analyzers extract text, one scans it: pii is not listed", []MediaAnalyzer{
			&mockPipelineAnalyzer{name: "ocr-a", result: &MediaAnalysisResult{AnalyzerName: "ocr-a", TextExtracted: true, PIIScanned: true, ExtractedText: "agenda"}},
			&mockPipelineAnalyzer{name: "ocr-b", result: &MediaAnalysisResult{AnalyzerName: "ocr-b", TextExtracted: true, ExtractedText: "SSN 123-45-6789"}},
		}, []string{ScanText}},
		{"two analyzers extract text and both scan it: pii is listed", []MediaAnalyzer{
			&mockPipelineAnalyzer{name: "ocr-a", result: &MediaAnalysisResult{AnalyzerName: "ocr-a", TextExtracted: true, PIIScanned: true}},
			&mockPipelineAnalyzer{name: "ocr-b", result: &MediaAnalysisResult{AnalyzerName: "ocr-b", TextExtracted: true, PIIScanned: true}},
		}, []string{ScanPII, ScanText}},
		{"a result with an error and no sections states nothing", []MediaAnalyzer{&mockPipelineAnalyzer{name: "ocr", result: &MediaAnalysisResult{AnalyzerName: "ocr", Error: "OCR failed"}}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := buildTestPipeline(t, EnforcementFailOpen, c.analyzers...)
			results, err := p.AnalyzeMedia(context.Background(), "req-scanned", validTestMedia())
			if err != nil {
				t.Fatalf("AnalyzeMedia: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("results = %d, want 1", len(results))
			}
			if !reflect.DeepEqual(results[0].Scanned, c.want) {
				t.Errorf("Scanned = %v, want %v", results[0].Scanned, c.want)
			}
		})
	}
}

// TestAnUnscannedExtractionIsReportedAsAWarning: text extracted with no PII
// scan leaves has_pii unknown and the image refused; the result says why, with
// the analyzer's reason and never the text (R3 round 2). A scanned extraction,
// and an analyzer that extracted nothing, add no such warning.
func TestAnUnscannedExtractionIsReportedAsAWarning(t *testing.T) {
	const text = "Employee SSN 123-45-6789"
	cases := []struct {
		name       string
		result     MediaAnalysisResult
		wantReason string
	}{
		{"scan did not run", MediaAnalysisResult{TextExtracted: true, ExtractedText: text, Error: "PII scan did not run: media: extracted text was not scanned for PII: the organization has no enabled text PII detector"}, "no enabled text PII detector"},
		{"no detector injected", MediaAnalysisResult{TextExtracted: true, ExtractedText: text}, "no PII detector is configured"},
		{"scanned", MediaAnalysisResult{TextExtracted: true, PIIScanned: true, ExtractedText: text}, ""},
		{"nothing extracted", MediaAnalysisResult{Error: "OCR failed: exit status 1"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := c.result
			res.AnalyzerName, res.AnalyzerType = "local-ocr", AnalyzerTypeLocalOCR
			p := buildTestPipeline(t, EnforcementFailOpen, &mockPipelineAnalyzer{name: "local-ocr", result: &res})
			results, err := p.AnalyzeMedia(context.Background(), "req-unscanned", validTestMedia())
			if err != nil || len(results) != 1 {
				t.Fatalf("results=%v err=%v", results, err)
			}
			var got []MediaWarning
			for _, w := range results[0].StructuredWarnings {
				if w.Code == WarnMediaPIIScanNotRun {
					got = append(got, w)
				}
			}
			if c.wantReason == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected %s warnings: %v", WarnMediaPIIScanNotRun, got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0].Message, "local-ocr") || !strings.Contains(got[0].Message, c.wantReason) {
				t.Fatalf("%s warnings = %v, want one naming local-ocr and %q", WarnMediaPIIScanNotRun, got, c.wantReason)
			}
			for _, w := range results[0].Warnings {
				if strings.Contains(w, "123-45-6789") {
					t.Errorf("a warning carries the extracted text: %q", w)
				}
			}
		})
	}
}
