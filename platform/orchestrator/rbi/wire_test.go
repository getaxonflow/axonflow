// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Test default export path
	if config.ExportBasePath != "/tmp/rbi-audit-exports" {
		t.Errorf("Expected default ExportBasePath '/tmp/rbi-audit-exports', got '%s'", config.ExportBasePath)
	}

	// Test default PII settings
	if config.PIIContextWindow != 50 {
		t.Errorf("Expected PIIContextWindow 50, got %d", config.PIIContextWindow)
	}

	if config.PIIMinConfidence != 0.5 {
		t.Errorf("Expected PIIMinConfidence 0.5, got %f", config.PIIMinConfidence)
	}

	if !config.PIIEnableValidation {
		t.Error("Expected PIIEnableValidation to be true")
	}

	// Test that all expected PII types are enabled
	expectedTypes := []IndiaPIIType{
		IndiaPIITypeUPI,
		IndiaPIITypeAadhaar,
		IndiaPIITypePAN,
		IndiaPIITypeIFSC,
		IndiaPIITypeBankAccount,
		IndiaPIITypeGSTIN,
		IndiaPIITypeVoterID,
		IndiaPIITypeDrivingLicense,
		IndiaPIITypePassport,
		IndiaPIITypeIndianPhone,
		IndiaPIITypePincode,
	}

	if len(config.PIIEnabledTypes) != len(expectedTypes) {
		t.Errorf("Expected %d PII types, got %d", len(expectedTypes), len(config.PIIEnabledTypes))
	}

	// Verify each expected type is present
	typeMap := make(map[IndiaPIIType]bool)
	for _, pt := range config.PIIEnabledTypes {
		typeMap[pt] = true
	}

	for _, expected := range expectedTypes {
		if !typeMap[expected] {
			t.Errorf("Expected PII type %s to be enabled", expected)
		}
	}
}

func TestNewRBIModule_NilDB(t *testing.T) {
	config := RBIModuleConfig{
		ExportBasePath:      "/tmp/test-exports",
		PIIContextWindow:    30,
		PIIMinConfidence:    0.6,
		PIIEnableValidation: true,
		PIIEnabledTypes: []IndiaPIIType{
			IndiaPIITypeUPI,
			IndiaPIITypePAN,
		},
	}

	module, err := NewRBIModule(config)
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	// With nil DB, repositories should be nil
	if module.AISystemRepo != nil {
		t.Error("Expected AISystemRepo to be nil with nil DB")
	}
	if module.ValidationRepo != nil {
		t.Error("Expected ValidationRepo to be nil with nil DB")
	}
	if module.IncidentRepo != nil {
		t.Error("Expected IncidentRepo to be nil with nil DB")
	}
	if module.KillSwitchRepo != nil {
		t.Error("Expected KillSwitchRepo to be nil with nil DB")
	}
	if module.BoardReportRepo != nil {
		t.Error("Expected BoardReportRepo to be nil with nil DB")
	}
	if module.AuditExportRepo != nil {
		t.Error("Expected AuditExportRepo to be nil with nil DB")
	}

	// Services should still be created
	if module.RegistryService == nil {
		t.Error("Expected RegistryService to be created")
	}
	if module.ValidationService == nil {
		t.Error("Expected ValidationService to be created")
	}
	if module.IncidentService == nil {
		t.Error("Expected IncidentService to be created")
	}
	if module.KillSwitchService == nil {
		t.Error("Expected KillSwitchService to be created")
	}
	if module.BoardService == nil {
		t.Error("Expected BoardService to be created")
	}
	if module.AuditService == nil {
		t.Error("Expected AuditService to be created")
	}

	// Handlers should be created
	if module.RegistryHandler == nil {
		t.Error("Expected RegistryHandler to be created")
	}
	if module.ValidationHandler == nil {
		t.Error("Expected ValidationHandler to be created")
	}
	if module.IncidentHandler == nil {
		t.Error("Expected IncidentHandler to be created")
	}
	if module.KillSwitchHandler == nil {
		t.Error("Expected KillSwitchHandler to be created")
	}
	if module.BoardHandler == nil {
		t.Error("Expected BoardHandler to be created")
	}
	if module.AuditHandler == nil {
		t.Error("Expected AuditHandler to be created")
	}

	// PII detector should be created
	if module.PIIDetector == nil {
		t.Error("Expected PIIDetector to be created")
	}
}

func TestNewRBIModule_DefaultPIITypes(t *testing.T) {
	// Test with empty PII types - should use defaults
	config := RBIModuleConfig{
		PIIEnabledTypes: nil,
	}

	module, err := NewRBIModule(config)
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	if module.PIIDetector == nil {
		t.Fatal("Expected PIIDetector to be created")
	}

	// Should be able to detect all types
	testText := "UPI: user@ybl, PAN: ABCPP1234F, Aadhaar: 234567890123"
	results := module.DetectPII(testText)

	// Should detect at least UPI and PAN
	if len(results) < 2 {
		t.Errorf("Expected at least 2 PII detections, got %d", len(results))
	}
}

func TestNewRBIModule_DefaultExportPath(t *testing.T) {
	// Test with empty export path - should use default
	config := RBIModuleConfig{
		ExportBasePath: "",
	}

	module, err := NewRBIModule(config)
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	// AuditService should be created (though we can't directly check the path)
	if module.AuditService == nil {
		t.Error("Expected AuditService to be created")
	}
}

func TestNewRBIModule_DefaultPIIConfig(t *testing.T) {
	// Test with zero values for PII config - should use defaults
	config := RBIModuleConfig{
		PIIContextWindow: 0,
		PIIMinConfidence: 0,
	}

	module, err := NewRBIModule(config)
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	if module.PIIDetector == nil {
		t.Fatal("Expected PIIDetector to be created")
	}
}

func TestRBIModule_DetectPII(t *testing.T) {
	module, err := NewRBIModule(DefaultConfig())
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	tests := []struct {
		name        string
		text        string
		expectCount int
		expectTypes []IndiaPIIType
	}{
		{
			name:        "detect UPI",
			text:        "Please send payment to merchant@ybl",
			expectCount: 1,
			expectTypes: []IndiaPIIType{IndiaPIITypeUPI},
		},
		{
			name:        "detect PAN",
			text:        "My PAN is ABCPP1234F",
			expectCount: 1,
			expectTypes: []IndiaPIIType{IndiaPIITypePAN},
		},
		{
			name:        "detect multiple",
			text:        "UPI: user@paytm and PAN: DEFGH5678I",
			expectCount: 2,
			expectTypes: []IndiaPIIType{IndiaPIITypeUPI, IndiaPIITypePAN},
		},
		{
			name:        "no PII",
			text:        "This is a normal message without any PII",
			expectCount: 0,
			expectTypes: nil,
		},
		{
			name:        "detect IFSC",
			text:        "Bank IFSC code is HDFC0001234",
			expectCount: 1,
			expectTypes: []IndiaPIIType{IndiaPIITypeIFSC},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := module.DetectPII(tt.text)

			if len(results) != tt.expectCount {
				t.Errorf("Expected %d detections, got %d", tt.expectCount, len(results))
				for i, r := range results {
					t.Logf("  Detection %d: type=%s, value=%s", i, r.Type, r.Value)
				}
			}

			// Verify expected types are found
			foundTypes := make(map[IndiaPIIType]bool)
			for _, r := range results {
				foundTypes[r.Type] = true
			}

			for _, expectedType := range tt.expectTypes {
				if !foundTypes[expectedType] {
					t.Errorf("Expected to find PII type %s", expectedType)
				}
			}
		})
	}
}

func TestRBIModule_HasSensitiveData(t *testing.T) {
	module, err := NewRBIModule(DefaultConfig())
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	tests := []struct {
		name     string
		text     string
		expected bool
	}{
		{
			name:     "has UPI",
			text:     "Payment to user@ybl",
			expected: true,
		},
		{
			name:     "has PAN",
			text:     "PAN number ABCPP1234F",
			expected: true,
		},
		{
			name:     "no PII",
			text:     "Hello world, no sensitive data here",
			expected: false,
		},
		{
			name:     "has IFSC",
			text:     "IFSC: SBIN0001234",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := module.HasSensitiveData(tt.text)
			if result != tt.expected {
				t.Errorf("Expected HasSensitiveData to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRBIModule_MaskPII(t *testing.T) {
	module, err := NewRBIModule(DefaultConfig())
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	tests := []struct {
		name         string
		text         string
		shouldChange bool
	}{
		{
			name:         "mask UPI",
			text:         "Send to merchant@ybl please",
			shouldChange: true,
		},
		{
			name:         "mask PAN",
			text:         "PAN is ABCPP1234F",
			shouldChange: true,
		},
		{
			name:         "no masking needed",
			text:         "Hello world",
			shouldChange: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := module.MaskPII(tt.text)

			if tt.shouldChange {
				if masked == tt.text {
					t.Error("Expected text to be masked but it wasn't changed")
				}
			} else {
				if masked != tt.text {
					t.Errorf("Expected text to remain unchanged, but got: %s", masked)
				}
			}
		})
	}
}

func TestRBIModule_MaskPII_MultipleItems(t *testing.T) {
	module, err := NewRBIModule(DefaultConfig())
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	text := "UPI: user@ybl and PAN: ABCPP1234F"
	masked := module.MaskPII(text)

	// Should not contain the original values
	if masked == text {
		t.Error("Expected text to be masked")
	}

	// Should contain masked patterns
	if len(masked) == 0 {
		t.Error("Masked result should not be empty")
	}
}

func TestRBIModule_HealthCheck(t *testing.T) {
	module, err := NewRBIModule(DefaultConfig())
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	health := module.HealthCheck()

	expectedServices := []string{
		"registry",
		"validation",
		"incident",
		"killswitch",
		"board_reporting",
		"audit_export",
		"pii_detector",
	}

	for _, svc := range expectedServices {
		status, ok := health[svc]
		if !ok {
			t.Errorf("Expected health check to include %s", svc)
		}
		if status != "ok" {
			t.Errorf("Expected %s status to be 'ok', got '%s'", svc, status)
		}
	}

	// Check we got all expected services
	if len(health) != len(expectedServices) {
		t.Errorf("Expected %d services in health check, got %d", len(expectedServices), len(health))
	}
}

func TestRBIModule_RegisterRoutes(t *testing.T) {
	module, err := NewRBIModule(DefaultConfig())
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	mux := http.NewServeMux()

	// This should not panic
	module.RegisterRoutes(mux)

	// Verify module handlers are not nil (routes are registered through handlers)
	if module.RegistryHandler == nil {
		t.Error("RegistryHandler should not be nil after RegisterRoutes")
	}
	if module.ValidationHandler == nil {
		t.Error("ValidationHandler should not be nil after RegisterRoutes")
	}
	if module.IncidentHandler == nil {
		t.Error("IncidentHandler should not be nil after RegisterRoutes")
	}
	if module.KillSwitchHandler == nil {
		t.Error("KillSwitchHandler should not be nil after RegisterRoutes")
	}
	if module.BoardHandler == nil {
		t.Error("BoardHandler should not be nil after RegisterRoutes")
	}
	if module.AuditHandler == nil {
		t.Error("AuditHandler should not be nil after RegisterRoutes")
	}
}

func TestHandleGetPolicyTemplates(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/policies/templates", nil)
	rec := httptest.NewRecorder()

	handleGetPolicyTemplates(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

func TestHandleGetPolicyTemplates_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/policies/templates", nil)
	rec := httptest.NewRecorder()

	handleGetPolicyTemplates(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestHandleGetPolicyTemplate_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/policies/templates/nonexistent", nil)
	rec := httptest.NewRecorder()

	handleGetPolicyTemplate(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestHandleGetPolicyTemplate_Found(t *testing.T) {
	// Use a known template ID
	templates := GetRBIPolicyTemplates()
	if len(templates) == 0 {
		t.Skip("No policy templates available")
	}

	templateID := templates[0].ID

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/policies/templates/"+templateID, nil)
	rec := httptest.NewRecorder()

	handleGetPolicyTemplate(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestHandleGetPolicyTemplate_MissingID(t *testing.T) {
	// Path with trailing slash but no ID
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/policies/templates/", nil)
	rec := httptest.NewRecorder()

	handleGetPolicyTemplate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestHandleGetPolicyTemplate_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/policies/templates/123", nil)
	rec := httptest.NewRecorder()

	handleGetPolicyTemplate(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestHandleGetPolicyCategories(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/policies/categories", nil)
	rec := httptest.NewRecorder()

	handleGetPolicyCategories(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

func TestHandleGetPolicyCategories_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/policies/categories", nil)
	rec := httptest.NewRecorder()

	handleGetPolicyCategories(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestRBIModuleConfig_Fields(t *testing.T) {
	config := RBIModuleConfig{
		DB:                  nil,
		ExportBasePath:      "/custom/path",
		PIIContextWindow:    100,
		PIIMinConfidence:    0.8,
		PIIEnableValidation: false,
		PIIEnabledTypes:     []IndiaPIIType{IndiaPIITypeUPI},
	}

	if config.ExportBasePath != "/custom/path" {
		t.Errorf("Expected ExportBasePath '/custom/path', got '%s'", config.ExportBasePath)
	}

	if config.PIIContextWindow != 100 {
		t.Errorf("Expected PIIContextWindow 100, got %d", config.PIIContextWindow)
	}

	if config.PIIMinConfidence != 0.8 {
		t.Errorf("Expected PIIMinConfidence 0.8, got %f", config.PIIMinConfidence)
	}

	if config.PIIEnableValidation != false {
		t.Error("Expected PIIEnableValidation to be false")
	}

	if len(config.PIIEnabledTypes) != 1 || config.PIIEnabledTypes[0] != IndiaPIITypeUPI {
		t.Error("Expected PIIEnabledTypes to contain only UPI")
	}
}

func TestRBIModule_CustomPIITypes(t *testing.T) {
	config := RBIModuleConfig{
		PIIEnabledTypes: []IndiaPIIType{IndiaPIITypeUPI}, // Only UPI
	}

	module, err := NewRBIModule(config)
	if err != nil {
		t.Fatalf("NewRBIModule failed: %v", err)
	}

	// Should detect UPI
	upiText := "Payment to user@ybl"
	upiResults := module.DetectPII(upiText)
	if len(upiResults) == 0 {
		t.Error("Expected to detect UPI")
	}

	// Should NOT detect PAN (not in enabled types)
	panText := "PAN is ABCPP1234F"
	panResults := module.DetectPII(panText)
	if len(panResults) > 0 {
		t.Error("Should not detect PAN when only UPI is enabled")
	}
}

// Test writeJSON helper function
func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()

	testData := map[string]string{"key": "value"}
	writeJSON(rec, http.StatusOK, testData)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	body := rec.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

func TestWriteJSON_DifferentStatusCodes(t *testing.T) {
	tests := []struct {
		status int
	}{
		{http.StatusOK},
		{http.StatusCreated},
		{http.StatusBadRequest},
		{http.StatusNotFound},
		{http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeJSON(rec, tt.status, map[string]string{"status": "test"})

			if rec.Code != tt.status {
				t.Errorf("Expected status %d, got %d", tt.status, rec.Code)
			}
		})
	}
}
