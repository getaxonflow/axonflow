// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"axonflow/platform/orchestrator/media"
)

func TestConvertMediaRequestsToMediaContent(t *testing.T) {
	requests := []MediaContentRequest{
		{Source: "base64", Base64Data: "dGVzdA==", MIMEType: "image/jpeg"},
		{Source: "url", URL: "https://example.com/img.png", MIMEType: "image/png"},
	}

	items := convertMediaRequestsToMediaContent(requests)

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Source != media.MediaSourceBase64 {
		t.Errorf("items[0].Source = %s, want base64", items[0].Source)
	}
	if items[0].Base64Data != "dGVzdA==" {
		t.Errorf("items[0].Base64Data = %s, want dGVzdA==", items[0].Base64Data)
	}
	if items[0].MIMEType != "image/jpeg" {
		t.Errorf("items[0].MIMEType = %s, want image/jpeg", items[0].MIMEType)
	}
	if items[1].Source != media.MediaSourceURL {
		t.Errorf("items[1].Source = %s, want url", items[1].Source)
	}
	if items[1].URL != "https://example.com/img.png" {
		t.Errorf("items[1].URL = %s, want https://example.com/img.png", items[1].URL)
	}
}

func TestConvertMediaRequestsToMediaContent_Empty(t *testing.T) {
	items := convertMediaRequestsToMediaContent(nil)
	if len(items) != 0 {
		t.Fatalf("expected 0 items, got %d", len(items))
	}
}

func TestBuildMediaAnalysisResponse_Nil(t *testing.T) {
	resp := buildMediaAnalysisResponse(nil)
	if resp != nil {
		t.Fatal("expected nil response for nil input")
	}
}

func TestBuildMediaAnalysisResponse_Empty(t *testing.T) {
	resp := buildMediaAnalysisResponse([]*media.AggregatedMediaResult{})
	if resp != nil {
		t.Fatal("expected nil response for empty input")
	}
}

func TestBuildMediaAnalysisResponse_SingleResult(t *testing.T) {
	results := []*media.AggregatedMediaResult{
		{
			MediaIndex:       0,
			SHA256Hash:       "abc123",
			HasFaces:         true,
			FaceCount:        2,
			HasBiometricData: true,
			NSFWScore:        0.1,
			ViolenceScore:    0.2,
			ContentSafe:      true,
			DocumentType:     "invoice",
			HasPII:           true,
			PIITypes:         []string{"email", "phone"},
			ExtractedText:    "Hello World",
			EstimatedCostUSD: 0.005,
			Warnings:         []string{"test warning"},
		},
	}

	resp := buildMediaAnalysisResponse(results)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}

	item := resp.Results[0]
	if item.SHA256Hash != "abc123" {
		t.Errorf("SHA256Hash = %s, want abc123", item.SHA256Hash)
	}
	if !item.HasFaces {
		t.Error("expected HasFaces=true")
	}
	if item.FaceCount != 2 {
		t.Errorf("FaceCount = %d, want 2", item.FaceCount)
	}
	if !item.HasExtractedText {
		t.Error("expected HasExtractedText=true for non-empty ExtractedText")
	}
	if item.ExtractedTextLength != 11 {
		t.Errorf("ExtractedTextLength = %d, want 11", item.ExtractedTextLength)
	}
	if !item.HasPII {
		t.Error("expected HasPII=true")
	}
	if resp.TotalCostUSD != 0.005 {
		t.Errorf("TotalCostUSD = %f, want 0.005", resp.TotalCostUSD)
	}
}

func TestBuildMediaAnalysisResponse_NoExtractedText(t *testing.T) {
	results := []*media.AggregatedMediaResult{
		{
			MediaIndex:  0,
			ContentSafe: true,
		},
	}

	resp := buildMediaAnalysisResponse(results)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	item := resp.Results[0]
	if item.HasExtractedText {
		t.Error("expected HasExtractedText=false for empty ExtractedText")
	}
	if item.ExtractedTextLength != 0 {
		t.Errorf("ExtractedTextLength = %d, want 0", item.ExtractedTextLength)
	}
}

func TestSendErrorResponse_Forbidden(t *testing.T) {
	w := httptest.NewRecorder()
	sendErrorResponse(w, "media policy violation", http.StatusForbidden)

	if w.Code != http.StatusForbidden {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusForbidden)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", ct)
	}
	var resp OrchestratorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false")
	}
	if resp.Error != "media policy violation" {
		t.Errorf("Error = %s, want media policy violation", resp.Error)
	}
}

func TestBuildMediaAnalysisResponse_MultipleCostAggregation(t *testing.T) {
	results := []*media.AggregatedMediaResult{
		{MediaIndex: 0, EstimatedCostUSD: 0.01, ContentSafe: true},
		{MediaIndex: 1, EstimatedCostUSD: 0.02, ContentSafe: true},
		{MediaIndex: 2, EstimatedCostUSD: 0.03, ContentSafe: false},
	}

	resp := buildMediaAnalysisResponse(results)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(resp.Results))
	}
	expectedCost := 0.06
	if resp.TotalCostUSD < expectedCost-0.001 || resp.TotalCostUSD > expectedCost+0.001 {
		t.Errorf("TotalCostUSD = %f, want ~%f", resp.TotalCostUSD, expectedCost)
	}
}
