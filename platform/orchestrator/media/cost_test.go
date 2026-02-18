// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"math"
	"testing"
)

func TestEstimateMediaCost_SingleKnownAnalyzer(t *testing.T) {
	est := EstimateMediaCost(5, []MediaAnalyzerType{AnalyzerTypeLocalOCR})

	if est.Currency != "USD" {
		t.Errorf("expected currency USD, got %s", est.Currency)
	}
	// LocalOCR is free: 5 * 0.0 = 0.0
	if est.TotalEstimateUSD != 0.0 {
		t.Errorf("expected total 0.0 for local-ocr, got %f", est.TotalEstimateUSD)
	}
	if len(est.PerAnalyzerBreakdown) != 1 {
		t.Fatalf("expected 1 breakdown entry, got %d", len(est.PerAnalyzerBreakdown))
	}
	if est.PerAnalyzerBreakdown[0].EstimateUSD != 0.0 {
		t.Errorf("expected local-ocr cost 0.0, got %f", est.PerAnalyzerBreakdown[0].EstimateUSD)
	}
}

func TestEstimateMediaCost_AWSRekognition(t *testing.T) {
	est := EstimateMediaCost(10, []MediaAnalyzerType{AnalyzerTypeAWSRekognition})

	// 10 * 0.001 = 0.01
	expected := 0.01
	if math.Abs(est.TotalEstimateUSD-expected) > 1e-9 {
		t.Errorf("expected total %f for aws-rekognition, got %f", expected, est.TotalEstimateUSD)
	}
	if len(est.PerAnalyzerBreakdown) != 1 {
		t.Fatalf("expected 1 breakdown entry, got %d", len(est.PerAnalyzerBreakdown))
	}
	if est.PerAnalyzerBreakdown[0].AnalyzerType != string(AnalyzerTypeAWSRekognition) {
		t.Errorf("expected analyzer type %s, got %s", AnalyzerTypeAWSRekognition, est.PerAnalyzerBreakdown[0].AnalyzerType)
	}
}

func TestEstimateMediaCost_MultipleAnalyzers(t *testing.T) {
	analyzers := []MediaAnalyzerType{AnalyzerTypeLocalOCR, AnalyzerTypeAWSRekognition}
	est := EstimateMediaCost(3, analyzers)

	// 3*0.0 + 3*0.001 = 0.003
	expected := 0.003
	if math.Abs(est.TotalEstimateUSD-expected) > 1e-9 {
		t.Errorf("expected total %f, got %f", expected, est.TotalEstimateUSD)
	}
	if len(est.PerAnalyzerBreakdown) != 2 {
		t.Fatalf("expected 2 breakdown entries, got %d", len(est.PerAnalyzerBreakdown))
	}
}

func TestEstimateMediaCost_UnknownAnalyzerUsesDefault(t *testing.T) {
	unknown := MediaAnalyzerType("experimental-analyzer")
	est := EstimateMediaCost(4, []MediaAnalyzerType{unknown})

	// Unknown defaults to 0.001 per image: 4 * 0.001 = 0.004
	expected := 0.004
	if math.Abs(est.TotalEstimateUSD-expected) > 1e-9 {
		t.Errorf("expected total %f for unknown analyzer, got %f", expected, est.TotalEstimateUSD)
	}
}

func TestEstimateMediaCost_ZeroMedia(t *testing.T) {
	est := EstimateMediaCost(0, []MediaAnalyzerType{AnalyzerTypeAWSRekognition})

	if est.TotalEstimateUSD != 0.0 {
		t.Errorf("expected total 0.0 for zero media, got %f", est.TotalEstimateUSD)
	}
}

func TestEstimateMediaCost_EmptyAnalyzers(t *testing.T) {
	est := EstimateMediaCost(5, []MediaAnalyzerType{})

	if est.TotalEstimateUSD != 0.0 {
		t.Errorf("expected total 0.0 for no analyzers, got %f", est.TotalEstimateUSD)
	}
	if len(est.PerAnalyzerBreakdown) != 0 {
		t.Errorf("expected empty breakdown, got %d entries", len(est.PerAnalyzerBreakdown))
	}
}

func TestEstimateAnalyzerCost_LocalOCR(t *testing.T) {
	cost := EstimateAnalyzerCost(AnalyzerTypeLocalOCR)
	if cost != 0.0 {
		t.Errorf("expected local-ocr cost 0.0, got %f", cost)
	}
}

func TestEstimateAnalyzerCost_AWSRekognition(t *testing.T) {
	cost := EstimateAnalyzerCost(AnalyzerTypeAWSRekognition)
	if cost != 0.001 {
		t.Errorf("expected aws-rekognition cost 0.001, got %f", cost)
	}
}

func TestEstimateAnalyzerCost_GoogleVision(t *testing.T) {
	cost := EstimateAnalyzerCost(AnalyzerTypeGoogleVision)
	if cost != 0.0015 {
		t.Errorf("expected google-vision cost 0.0015, got %f", cost)
	}
}

func TestEstimateAnalyzerCost_AzureVision(t *testing.T) {
	cost := EstimateAnalyzerCost(AnalyzerTypeAzureVision)
	if cost != 0.001 {
		t.Errorf("expected azure-vision cost 0.001, got %f", cost)
	}
}

func TestEstimateAnalyzerCost_UnknownReturnsDefault(t *testing.T) {
	cost := EstimateAnalyzerCost(MediaAnalyzerType("unknown-analyzer"))
	if cost != 0.001 {
		t.Errorf("expected default cost 0.001 for unknown, got %f", cost)
	}
}

func TestAggregateMediaCostFromResults_NilSlice(t *testing.T) {
	total := AggregateMediaCostFromResults(nil)
	if total != 0.0 {
		t.Errorf("expected 0.0 for nil results, got %f", total)
	}
}

func TestAggregateMediaCostFromResults_EmptySlice(t *testing.T) {
	total := AggregateMediaCostFromResults([]*AggregatedMediaResult{})
	if total != 0.0 {
		t.Errorf("expected 0.0 for empty results, got %f", total)
	}
}

func TestAggregateMediaCostFromResults_WithCosts(t *testing.T) {
	results := []*AggregatedMediaResult{
		{EstimatedCostUSD: 0.005},
		{EstimatedCostUSD: 0.010},
		{EstimatedCostUSD: 0.003},
	}

	total := AggregateMediaCostFromResults(results)
	expected := 0.018
	if math.Abs(total-expected) > 1e-9 {
		t.Errorf("expected %f, got %f", expected, total)
	}
}

func TestAggregateMediaCostFromResults_NilEntriesSkipped(t *testing.T) {
	results := []*AggregatedMediaResult{
		{EstimatedCostUSD: 0.005},
		nil,
		{EstimatedCostUSD: 0.003},
	}

	total := AggregateMediaCostFromResults(results)
	expected := 0.008
	if math.Abs(total-expected) > 1e-9 {
		t.Errorf("expected %f, got %f", expected, total)
	}
}

func TestAggregateMediaCostFromResults_AllNilEntries(t *testing.T) {
	results := []*AggregatedMediaResult{nil, nil, nil}
	total := AggregateMediaCostFromResults(results)
	if total != 0.0 {
		t.Errorf("expected 0.0 for all-nil entries, got %f", total)
	}
}
