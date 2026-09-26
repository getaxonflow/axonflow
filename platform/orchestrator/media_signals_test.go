// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/media"
)

func scannedResult(scanned ...string) *media.AggregatedMediaResult {
	return &media.AggregatedMediaResult{Scanned: scanned, ContentSafe: true}
}

// TestAMediaSignalIsStatedOnlyWhenItsCapabilityRanOnEveryItem is #4249 row
// 5705208432: every key, per state. No capability ran -> the key is absent
// (UNKNOWN); it ran on some items only -> absent; it ran on every item -> the
// worst case across them.
func TestAMediaSignalIsStatedOnlyWhenItsCapabilityRanOnEveryItem(t *testing.T) {
	allKeys := []string{}
	for _, keys := range mediaSignalKeys {
		allKeys = append(allKeys, keys...)
	}

	t.Run("no results state nothing", func(t *testing.T) {
		if got := mediaSignalsFromResults(nil); len(got) != 0 {
			t.Errorf("signals = %v, want none", got)
		}
	})
	t.Run("results with no capability run state nothing (the zero-analyzer shipped image)", func(t *testing.T) {
		got := mediaSignalsFromResults([]*media.AggregatedMediaResult{scannedResult(), scannedResult()})
		for _, k := range allKeys {
			if _, stated := got[k]; stated {
				t.Errorf("%s stated as %v with no analyzer run", k, got[k])
			}
		}
	})

	for capability, keys := range mediaSignalKeys {
		t.Run(capability+" ran on one of two items: its signals are not stated", func(t *testing.T) {
			got := mediaSignalsFromResults([]*media.AggregatedMediaResult{scannedResult(capability), scannedResult()})
			for _, k := range keys {
				if _, stated := got[k]; stated {
					t.Errorf("%s stated as %v though %s did not run on every item", k, got[k], capability)
				}
			}
		})
		t.Run(capability+" ran on every item: its signals, and only its, are stated", func(t *testing.T) {
			got := mediaSignalsFromResults([]*media.AggregatedMediaResult{scannedResult(capability), scannedResult(capability)})
			for _, k := range allKeys {
				_, stated := got[k]
				if want := slices.Contains(keys, k); stated != want {
					t.Errorf("%s stated=%v, want %v when only %s ran", k, stated, want, capability)
				}
			}
		})
	}

	t.Run("the worst case across items", func(t *testing.T) {
		all := []string{media.ScanContentSafety, media.ScanDocument, media.ScanFaces, media.ScanPII, media.ScanText}
		a := &media.AggregatedMediaResult{Scanned: all, ContentSafe: true, NSFWScore: 0.2, ViolenceScore: 0.9, FaceCount: 1, HasFaces: true,
			PIITypes: []string{"sys_pii_ssn"}, HasPII: true, ExtractedText: "SSN 123-45-6789"}
		b := &media.AggregatedMediaResult{Scanned: all, ContentSafe: false, NSFWScore: 0.85, ViolenceScore: 0.1, FaceCount: 2, HasFaces: true,
			HasBiometricData: true, DocumentType: "passport", IsSensitiveDocument: true, PIITypes: []string{"sys_pii_email", "sys_pii_ssn"}, HasPII: true}
		got := mediaSignalsFromResults([]*media.AggregatedMediaResult{a, b})
		want := map[string]interface{}{
			"nsfw_score": 0.85, "violence_score": 0.9, "content_safe": false,
			"has_faces": true, "face_count": 3, "has_biometric_data": true,
			"document_type": "passport", "is_sensitive_document": true,
			"has_pii": true, "pii_types": []string{"sys_pii_email", "sys_pii_ssn"},
			"has_extracted_text": true, "extracted_text_length": len("SSN 123-45-6789"),
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("signals = %#v\nwant      %#v", got, want)
		}
	})
	t.Run("the worst case holds in either order (one flagged image, one clean)", func(t *testing.T) {
		all := []string{media.ScanContentSafety, media.ScanDocument, media.ScanFaces, media.ScanPII, media.ScanText}
		flagged := &media.AggregatedMediaResult{Scanned: all, ContentSafe: false, NSFWScore: 0.9, ViolenceScore: 0.7, HasFaces: true, FaceCount: 1,
			HasBiometricData: true, DocumentType: "passport", IsSensitiveDocument: true, HasPII: true, PIITypes: []string{"sys_pii_ssn"}, ExtractedText: "SSN 123-45-6789"}
		clean := &media.AggregatedMediaResult{Scanned: all, ContentSafe: true}
		want := map[string]interface{}{
			"nsfw_score": 0.9, "violence_score": 0.7, "content_safe": false,
			"has_faces": true, "face_count": 1, "has_biometric_data": true,
			"document_type": "passport", "is_sensitive_document": true,
			"has_pii": true, "pii_types": []string{"sys_pii_ssn"},
			"has_extracted_text": true, "extracted_text_length": len("SSN 123-45-6789"),
		}
		for name, items := range map[string][]*media.AggregatedMediaResult{
			"flagged first": {flagged, clean},
			"flagged last":  {clean, flagged},
		} {
			if got := mediaSignalsFromResults(items); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: signals = %#v\nwant      %#v", name, got, want)
			}
		}
	})
	t.Run("a scan that found nothing states a known false", func(t *testing.T) {
		got := mediaSignalsFromResults([]*media.AggregatedMediaResult{scannedResult(media.ScanPII, media.ScanText)})
		if got["has_pii"] != false || !reflect.DeepEqual(got["pii_types"], []string{}) || got["has_extracted_text"] != false || got["extracted_text_length"] != 0 {
			t.Errorf("signals = %v, want has_pii false, pii_types [], no text", got)
		}
	})
}

// TestTheResponseListsWhatRanOnEachItem: the API response's scanned field is
// the item's ran record, so has_pii false is read beside it.
func TestTheResponseListsWhatRanOnEachItem(t *testing.T) {
	resp := buildMediaAnalysisResponse([]*media.AggregatedMediaResult{
		{MediaIndex: 0, Scanned: []string{media.ScanPII, media.ScanText}},
		{MediaIndex: 1},
	})
	if resp == nil || len(resp.Results) != 2 {
		t.Fatalf("response = %+v", resp)
	}
	if !reflect.DeepEqual(resp.Results[0].Scanned, []string{"pii", "text"}) {
		t.Errorf("item 0 scanned = %v, want [pii text]", resp.Results[0].Scanned)
	}
	if resp.Results[1].Scanned == nil || len(resp.Results[1].Scanned) != 0 {
		t.Errorf("item 1 scanned = %#v, want an empty (non-nil) list, so the wire says [] rather than null", resp.Results[1].Scanned)
	}
}

// mediaDecision is the anchored decision on the workflow control plane for a
// request with one image attached whose analysis is signals.
func mediaDecision(t *testing.T, signals map[string]interface{}) *contract.Decision {
	t.Helper()
	act := wcpActivation(t)
	req := stepFactRequest("summarise the attached image", nil)
	req.Media = []MediaContentRequest{{Source: "url", URL: "https://example.com/a.png", MIMEType: "image/png"}}
	req.mediaAnalysis = signals
	return decideStep(t, act, req.Query, produceFacts(t, testFactProducer(t, seedDynamicRows(t)), req))
}

const (
	mediaPIIBlock      = "corpus:dynamic_policies:sys__media__pii__block"
	mediaNSFWBlock     = "corpus:dynamic_policies:sys__media__nsfw__block"
	mediaBiometricLog  = "corpus:dynamic_policies:sys__media__biometric__log"
	mediaSensitiveWarn = "corpus:dynamic_policies:sys__media__sensitive__doc__warn#1"
	mediaViolenceWarn  = "corpus:dynamic_policies:sys__media__violence__warn#1"
)

// TestSysMediaPIIBlockRefusesAnSSNFoundInImageText is the path end to end short
// of the HTTP handler: a local OCR analysis that found an SSN, aggregated by the
// pipeline, stated as media signals and decided by the anchored engine on the
// wcp scope over the shipped corpus - refused by sys_media_pii_block.
func TestSysMediaPIIBlockRefusesAnSSNFoundInImageText(t *testing.T) {
	ocr := &media.MediaAnalysisResult{AnalyzerName: "local-ocr", AnalyzerType: media.AnalyzerTypeLocalOCR, TextExtracted: true, PIIScanned: true,
		ExtractedText: "SSN 123-45-6789", PIIFindings: []media.PIIFinding{{Type: "sys_pii_ssn", Confidence: 1, StartIndex: 4, EndIndex: 15}}}
	results := analyzeWith(t, ocr)
	signals := mediaSignalsFromResults(results)
	if signals["has_pii"] != true || !reflect.DeepEqual(signals["pii_types"], []string{"sys_pii_ssn"}) {
		t.Fatalf("PREMISE: signals %v, want has_pii true with pii_types [sys_pii_ssn]", signals)
	}
	dec := mediaDecision(t, signals)
	if dec.State != contract.StateDeny || !slices.Contains(dec.Determining.MatchedConstraints, mediaPIIBlock) {
		t.Fatalf("decision %s %s matched %v unknown %v; want DENY by %s", dec.State, dec.Reason, dec.Determining.MatchedConstraints, dec.Determining.Unknown, mediaPIIBlock)
	}
	resp := buildMediaAnalysisResponse(results)
	if !resp.Results[0].HasPII || !reflect.DeepEqual(resp.Results[0].PIITypes, []string{"sys_pii_ssn"}) || !reflect.DeepEqual(resp.Results[0].Scanned, []string{"pii", "text"}) {
		t.Errorf("response item = %+v, want has_pii true, pii_types [sys_pii_ssn], scanned [pii text]", resp.Results[0])
	}
}

// TestTheMediaControlsOnUnknownSignals pins, per shipped media control, what the
// anchored engine does when the image's signals are UNKNOWN (no analyzer ran on
// them) on the wcp scope: the two block rows withhold the request as
// unknown_constraint - a block over a signal nobody measured is not admitted -
// and the three warn/log rows do not withhold. The same request with every
// capability scanned and clean is allowed.
//
// This is what makes a deployment whose only analyzer is local OCR refuse every
// image while sys_media_nsfw_block is active: OCR never measures content safety.
func TestTheMediaControlsOnUnknownSignals(t *testing.T) {
	clean := map[string]interface{}{
		"nsfw_score": 0.0, "violence_score": 0.0, "content_safe": true,
		"has_faces": false, "face_count": 0, "has_biometric_data": false,
		"document_type": "", "is_sensitive_document": false,
		"has_pii": false, "pii_types": []string{},
		"has_extracted_text": false, "extracted_text_length": 0,
	}
	if scanned := mediaDecision(t, clean); scanned.State != contract.StateAllow {
		t.Fatalf("a clean, fully scanned image is %s %s (unknown %v); want ALLOW", scanned.State, scanned.Reason, scanned.Determining.Unknown)
	}

	unknown := mediaDecision(t, map[string]interface{}{})
	if unknown.State != contract.StateError || unknown.Reason != contract.ReasonUnknownConstraint {
		t.Fatalf("no analyzer ran: %s %s; want ERROR unknown_constraint", unknown.State, unknown.Reason)
	}
	for id, withholds := range map[string]bool{
		mediaPIIBlock:      true,
		mediaNSFWBlock:     true,
		mediaBiometricLog:  false,
		mediaSensitiveWarn: false,
		mediaViolenceWarn:  false,
	} {
		if got := namesUnknown(unknown, id); got != withholds {
			t.Errorf("%s named unknown = %v, want %v", id, got, withholds)
		}
	}

	// Local OCR only: pii and text stated clean, content safety never measured.
	ocrOnly := mediaSignalsFromResults([]*media.AggregatedMediaResult{{Scanned: []string{media.ScanPII, media.ScanText}}})
	dec := mediaDecision(t, ocrOnly)
	if dec.State != contract.StateError || dec.Reason != contract.ReasonUnknownConstraint || !namesUnknown(dec, mediaNSFWBlock) || namesUnknown(dec, mediaPIIBlock) {
		t.Errorf("OCR-only clean image: %s %s unknown %v; want ERROR unknown_constraint naming %s and not %s",
			dec.State, dec.Reason, dec.Determining.Unknown, mediaNSFWBlock, mediaPIIBlock)
	}
}

// analyzeWith runs one fake analyzer through a real pipeline and returns the
// aggregated results for one image.
func analyzeWith(t *testing.T, result *media.MediaAnalysisResult) []*media.AggregatedMediaResult {
	t.Helper()
	reg := media.NewRegistry()
	if err := reg.RegisterAnalyzer(result.AnalyzerName, &fixedAnalyzer{result: result}); err != nil {
		t.Fatal(err)
	}
	p := media.NewPipeline(media.WithPipelineRegistry(reg))
	results, err := p.AnalyzeMedia(context.Background(), "req-media", []media.MediaContent{{
		Source: media.MediaSourceBase64, MIMEType: "image/png", Base64Data: onePixelPNG,
	}})
	if err != nil {
		t.Fatalf("AnalyzeMedia: %v", err)
	}
	return results
}

type fixedAnalyzer struct{ result *media.MediaAnalysisResult }

func (a *fixedAnalyzer) Name() string                                  { return a.result.AnalyzerName }
func (a *fixedAnalyzer) Type() media.MediaAnalyzerType                 { return a.result.AnalyzerType }
func (a *fixedAnalyzer) Capabilities() []media.MediaAnalyzerCapability { return nil }
func (a *fixedAnalyzer) HealthCheck(context.Context) error             { return nil }
func (a *fixedAnalyzer) Analyze(context.Context, media.MediaContent) (*media.MediaAnalysisResult, error) {
	r := *a.result
	return &r, nil
}

// onePixelPNG is a 1x1 transparent PNG.
const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

// scopeRecordingAnalyzer records the scan scope its analysis ran under and
// answers a local OCR result that scanned text and found no PII.
type scopeRecordingAnalyzer struct {
	scopes []media.ScanScope
	found  []bool
	// result, when set, is answered instead of the clean OCR scan.
	result *media.MediaAnalysisResult
}

func (a *scopeRecordingAnalyzer) Name() string                                  { return "local-ocr" }
func (a *scopeRecordingAnalyzer) Type() media.MediaAnalyzerType                 { return media.AnalyzerTypeLocalOCR }
func (a *scopeRecordingAnalyzer) Capabilities() []media.MediaAnalyzerCapability { return nil }
func (a *scopeRecordingAnalyzer) HealthCheck(context.Context) error             { return nil }
func (a *scopeRecordingAnalyzer) Analyze(ctx context.Context, _ media.MediaContent) (*media.MediaAnalysisResult, error) {
	scope, ok := media.ScanScopeFrom(ctx)
	a.scopes, a.found = append(a.scopes, scope), append(a.found, ok)
	if a.result != nil {
		r := *a.result
		return &r, nil
	}
	return &media.MediaAnalysisResult{AnalyzerName: "local-ocr", AnalyzerType: media.AnalyzerTypeLocalOCR,
		TextExtracted: true, PIIScanned: true, ExtractedText: "Quarterly meeting agenda"}, nil
}

// TestProcessAnalysesMediaUnderTheLicensedScopeAndStatesOnlyWhatRan drives
// /api/v1/process: the media analysis runs with the licensed organization as
// its scan scope (the scope the governed-scope binder resolved, never a body
// claim), and the analysis the decision reads states the pii and text signals
// the OCR result measured and nothing else - no fabricated nsfw_score or
// content_safe.
func TestProcessAnalysesMediaUnderTheLicensedScopeAndStatesOnlyWhatRan(t *testing.T) {
	t.Setenv("MEDIA_GOVERNANCE_ENABLED", "true")
	previousAudit := auditLogger
	auditLogger = NewAuditLogger("")
	t.Cleanup(func() { auditLogger = previousAudit })
	analyzer := &scopeRecordingAnalyzer{}
	reg := media.NewRegistry()
	if err := reg.RegisterAnalyzer("local-ocr", analyzer); err != nil {
		t.Fatal(err)
	}
	previousPipeline := mediaPipeline
	mediaPipeline = media.NewPipeline(media.WithPipelineRegistry(reg))
	t.Cleanup(func() { mediaPipeline = previousPipeline })
	_, src := withRouteRequestEngine(t, routeDenyVerdict("pol-a"))

	handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)
	rr := gs3066Post(t, handler, "/api/v1/process",
		map[string]string{"X-Org-ID": gs3066AttackerOrg, "X-Tenant-ID": gs3066AttackerTenat},
		map[string]any{"query": "summarise the image", "request_type": "llm",
			"client": map[string]any{"org_id": gs3066AttackerOrg, "tenant_id": gs3066AttackerTenat},
			"media":  []map[string]any{{"source": "base64", "base64_data": onePixelPNG, "mime_type": "image/png"}}})

	if len(analyzer.scopes) != 1 || !analyzer.found[0] || analyzer.scopes[0].OrgID != gs3066AttackerOrg || analyzer.scopes[0].TenantID != gs3066AttackerTenat {
		t.Fatalf("analysis scan scopes = %+v (present %v), want one with org %s tenant %s", analyzer.scopes, analyzer.found, gs3066AttackerOrg, gs3066AttackerTenat)
	}
	if len(src.captured) != 1 {
		t.Fatalf("PREMISE: the plane decided %d request(s), want 1", len(src.captured))
	}
	got := src.captured[0].mediaAnalysis
	want := map[string]interface{}{"has_pii": false, "pii_types": []string{}, "has_extracted_text": true, "extracted_text_length": len("Quarterly meeting agenda")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the decided request's media analysis = %#v, want exactly %#v", got, want)
	}

	// The refusal carries the media analysis the decision read (it carried
	// none before #4300's change), and never the extracted text.
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
	}
	var refused struct {
		MediaAnalysis *struct {
			Results []map[string]json.RawMessage `json:"results"`
		} `json:"media_analysis"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &refused); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if refused.MediaAnalysis == nil || len(refused.MediaAnalysis.Results) != 1 {
		t.Fatalf("the refusal's media_analysis = %+v, want one result (body=%s)", refused.MediaAnalysis, rr.Body.String())
	}
	item := refused.MediaAnalysis.Results[0]
	if string(item["has_pii"]) != "false" || string(item["scanned"]) != `["pii","text"]` {
		t.Errorf("refusal item has_pii=%s scanned=%s, want false and [\"pii\",\"text\"]", item["has_pii"], item["scanned"])
	}
	if _, leaked := item["extracted_text"]; leaked || strings.Contains(rr.Body.String(), "Quarterly meeting agenda") {
		t.Errorf("the refusal carries the extracted text: %s", rr.Body.String())
	}
}

// TestTheProcessRouteRefusesMediaOnTheRealEngine decides /api/v1/process's own
// action (llm.completion, processRouteAction) through decideRouteRequest with a
// real enforcer over the shipped corpus and the real fact producer - not the
// step gate's tool.call, and not a verdict double (R3 round 1 finding 5):
//   - an SSN found in image text: refused explicit_constraint, naming
//     sys_media_pii_block first and nothing unknown;
//   - a clean image measured by local OCR only: refused unknown_constraint,
//     naming sys_media_nsfw_block first and not sys_media_pii_block.
func TestTheProcessRouteRefusesMediaOnTheRealEngine(t *testing.T) {
	// The runtime suite runs Community; the constraint combination is not
	// mode-dependent, and both modes are decided here so that is measured
	// rather than read (R3 round 2).
	for _, mode := range []string{"enterprise", "community"} {
		t.Run(mode, func(t *testing.T) { processRouteRefusesMediaOnTheRealEngine(t, mode) })
	}
}

func processRouteRefusesMediaOnTheRealEngine(t *testing.T, mode string) {
	t.Setenv("DEPLOYMENT_MODE", mode)
	enforcer := stepDecisionEnforcer(t)
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: enforcer})
	rows := seedDynamicRows(t)
	previousFactory := newRouteRequestFactProducer
	newRouteRequestFactProducer = func() (routeFactSource, error) { return testFactProducer(t, rows), nil }
	resetRouteRequestFacts()
	t.Cleanup(func() {
		newRouteRequestFactProducer = previousFactory
		resetRouteRequestFacts()
	})

	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	decide := func(signals map[string]interface{}) PolicyEvaluationResult {
		req := stepFactRequest("summarise the attached image", nil)
		req.RequestType = "llm"
		req.Media = []MediaContentRequest{{Source: "base64", Base64Data: onePixelPNG, MIMEType: "image/png"}}
		req.mediaAnalysis = signals
		return *decideRouteRequest(context.Background(), h, req, processRouteAction).result
	}

	ssn := decide(mediaSignalsFromResults([]*media.AggregatedMediaResult{{
		Scanned: []string{media.ScanPII, media.ScanText}, HasPII: true, PIITypes: []string{"sys_pii_ssn"}, ExtractedText: "SSN 123-45-6789",
	}}))
	if ssn.Allowed || len(ssn.AppliedPolicies) == 0 || ssn.AppliedPolicies[0] != mediaPIIBlock ||
		!reflect.DeepEqual(ssn.RequiredActions, []string{"blocked: explicit_constraint"}) {
		t.Errorf("SSN image: allowed=%v applied=%v required=%v; want refused explicit_constraint naming %s first",
			ssn.Allowed, ssn.AppliedPolicies, ssn.RequiredActions, mediaPIIBlock)
	}

	benign := decide(mediaSignalsFromResults([]*media.AggregatedMediaResult{{
		Scanned: []string{media.ScanPII, media.ScanText}, ExtractedText: "Quarterly meeting agenda",
	}}))
	if benign.Allowed || len(benign.AppliedPolicies) == 0 || benign.AppliedPolicies[0] != mediaNSFWBlock ||
		slices.Contains(benign.AppliedPolicies, mediaPIIBlock) ||
		len(benign.RequiredActions) == 0 || benign.RequiredActions[0] != "blocked: unknown_constraint" {
		t.Errorf("benign OCR-only image: allowed=%v applied=%v required=%v; want refused unknown_constraint naming %s first and not %s",
			benign.Allowed, benign.AppliedPolicies, benign.RequiredActions, mediaNSFWBlock, mediaPIIBlock)
	}
}

// TestAMediaRefusalNeverCarriesTheFoundPII: when OCR found an SSN, the served
// refusal names the finding by detector (pii_types) and carries neither the
// extracted text nor the finding's value.
func TestAMediaRefusalNeverCarriesTheFoundPII(t *testing.T) {
	t.Setenv("MEDIA_GOVERNANCE_ENABLED", "true")
	previousAudit := auditLogger
	auditLogger = NewAuditLogger("")
	t.Cleanup(func() { auditLogger = previousAudit })
	analyzer := &scopeRecordingAnalyzer{result: &media.MediaAnalysisResult{
		AnalyzerName: "local-ocr", AnalyzerType: media.AnalyzerTypeLocalOCR, TextExtracted: true, PIIScanned: true,
		ExtractedText: "Employee SSN 123-45-6789",
		PIIFindings:   []media.PIIFinding{{Type: "sys_pii_ssn", Value: "123-45-6789", Redacted: "[redacted]", Confidence: 1, StartIndex: 13, EndIndex: 24}},
	}}
	reg := media.NewRegistry()
	if err := reg.RegisterAnalyzer("local-ocr", analyzer); err != nil {
		t.Fatal(err)
	}
	previousPipeline := mediaPipeline
	mediaPipeline = media.NewPipeline(media.WithPipelineRegistry(reg))
	t.Cleanup(func() { mediaPipeline = previousPipeline })
	withRouteRequestEngine(t, routeDenyVerdict(mediaPIIBlock))

	handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)
	rr := gs3066Post(t, handler, "/api/v1/process",
		map[string]string{"X-Org-ID": gs3066AttackerOrg, "X-Tenant-ID": gs3066AttackerTenat},
		map[string]any{"query": "summarise the image", "request_type": "llm",
			"client": map[string]any{"org_id": gs3066AttackerOrg, "tenant_id": gs3066AttackerTenat},
			"media":  []map[string]any{{"source": "base64", "base64_data": onePixelPNG, "mime_type": "image/png"}}})

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"pii_types":["sys_pii_ssn"]`) || !strings.Contains(body, `"has_pii":true`) {
		t.Errorf("the refusal does not name the finding by detector: %s", body)
	}
	for _, leak := range []string{"123-45-6789", "Employee SSN"} {
		if strings.Contains(body, leak) {
			t.Errorf("the refusal carries %q: %s", leak, body)
		}
	}
}
