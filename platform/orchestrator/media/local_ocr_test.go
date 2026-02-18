// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"testing"
)

func TestNewLocalOCRAnalyzer_Defaults(t *testing.T) {
	a := NewLocalOCRAnalyzer("test-ocr", "", "", nil)

	if a.tesseractPath != "tesseract" {
		t.Errorf("expected default tesseractPath 'tesseract', got %q", a.tesseractPath)
	}
	if a.language != "eng" {
		t.Errorf("expected default language 'eng', got %q", a.language)
	}
	if a.name != "test-ocr" {
		t.Errorf("expected name 'test-ocr', got %q", a.name)
	}
	if a.piiDetector != nil {
		t.Error("expected nil piiDetector when none provided")
	}
}

func TestNewLocalOCRAnalyzer_CustomValues(t *testing.T) {
	detector := func(text string) []PIIFinding {
		return nil
	}
	a := NewLocalOCRAnalyzer("my-ocr", "/usr/local/bin/tesseract", "deu", detector)

	if a.tesseractPath != "/usr/local/bin/tesseract" {
		t.Errorf("expected custom tesseractPath, got %q", a.tesseractPath)
	}
	if a.language != "deu" {
		t.Errorf("expected language 'deu', got %q", a.language)
	}
	if a.piiDetector == nil {
		t.Error("expected non-nil piiDetector")
	}
}

func TestLocalOCRAnalyzer_Name(t *testing.T) {
	a := NewLocalOCRAnalyzer("my-analyzer", "", "", nil)
	if a.Name() != "my-analyzer" {
		t.Errorf("expected Name() = 'my-analyzer', got %q", a.Name())
	}
}

func TestLocalOCRAnalyzer_Type(t *testing.T) {
	a := NewLocalOCRAnalyzer("test", "", "", nil)
	if a.Type() != AnalyzerTypeLocalOCR {
		t.Errorf("expected Type() = %q, got %q", AnalyzerTypeLocalOCR, a.Type())
	}
}

func TestLocalOCRAnalyzer_Capabilities_WithoutPIIDetector(t *testing.T) {
	a := NewLocalOCRAnalyzer("test", "", "", nil)
	caps := a.Capabilities()

	if len(caps) != 1 {
		t.Fatalf("expected 1 capability without PII detector, got %d", len(caps))
	}
	if caps[0] != CapabilityOCR {
		t.Errorf("expected capability %q, got %q", CapabilityOCR, caps[0])
	}
}

func TestLocalOCRAnalyzer_Capabilities_WithPIIDetector(t *testing.T) {
	detector := func(text string) []PIIFinding {
		return nil
	}
	a := NewLocalOCRAnalyzer("test", "", "", detector)
	caps := a.Capabilities()

	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities with PII detector, got %d", len(caps))
	}

	hasOCR := false
	hasPII := false
	for _, c := range caps {
		switch c {
		case CapabilityOCR:
			hasOCR = true
		case CapabilityPIIDetection:
			hasPII = true
		}
	}
	if !hasOCR {
		t.Error("expected OCR capability")
	}
	if !hasPII {
		t.Error("expected PII detection capability")
	}
}

func TestLocalOCRAnalyzer_FactoryRegistration(t *testing.T) {
	// The local_ocr.go init() registers the factory. Verify it exists.
	if !HasAnalyzerFactory(AnalyzerTypeLocalOCR) {
		t.Fatal("expected local-ocr factory to be registered")
	}

	factory := GetAnalyzerFactory(AnalyzerTypeLocalOCR)
	if factory == nil {
		t.Fatal("expected non-nil factory for local-ocr")
	}
}

func TestLocalOCRAnalyzer_CreateAnalyzer_DefaultConfig(t *testing.T) {
	config := AnalyzerConfig{
		Name:    "factory-ocr",
		Type:    AnalyzerTypeLocalOCR,
		Enabled: true,
	}

	analyzer, err := CreateAnalyzer(config)
	if err != nil {
		t.Fatalf("CreateAnalyzer failed: %v", err)
	}
	if analyzer == nil {
		t.Fatal("expected non-nil analyzer")
	}
	if analyzer.Name() != "factory-ocr" {
		t.Errorf("expected Name() = 'factory-ocr', got %q", analyzer.Name())
	}
	if analyzer.Type() != AnalyzerTypeLocalOCR {
		t.Errorf("expected Type() = %q, got %q", AnalyzerTypeLocalOCR, analyzer.Type())
	}
}

func TestLocalOCRAnalyzer_CreateAnalyzer_CustomSettings(t *testing.T) {
	config := AnalyzerConfig{
		Name:    "custom-ocr",
		Type:    AnalyzerTypeLocalOCR,
		Enabled: true,
		Settings: map[string]any{
			"tesseract_path": "/opt/tesseract/bin/tesseract",
			"language":       "fra",
		},
	}

	analyzer, err := CreateAnalyzer(config)
	if err != nil {
		t.Fatalf("CreateAnalyzer failed: %v", err)
	}

	// Verify it's a LocalOCRAnalyzer with custom settings.
	localOCR, ok := analyzer.(*LocalOCRAnalyzer)
	if !ok {
		t.Fatal("expected analyzer to be *LocalOCRAnalyzer")
	}
	if localOCR.tesseractPath != "/opt/tesseract/bin/tesseract" {
		t.Errorf("expected tesseractPath '/opt/tesseract/bin/tesseract', got %q", localOCR.tesseractPath)
	}
	if localOCR.language != "fra" {
		t.Errorf("expected language 'fra', got %q", localOCR.language)
	}
}

func TestLocalOCRAnalyzer_ImplementsMediaAnalyzer(t *testing.T) {
	a := NewLocalOCRAnalyzer("test", "", "", nil)

	// Compile-time check that *LocalOCRAnalyzer satisfies MediaAnalyzer.
	var _ MediaAnalyzer = a
}
