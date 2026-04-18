// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExportType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		et       ExportType
		expected bool
	}{
		{"full_audit is valid", ExportTypeFullAudit, true},
		{"conformity_evidence is valid", ExportTypeConformityEvidence, true},
		{"hitl_summary is valid", ExportTypeHITLSummary, true},
		{"decision_chain is valid", ExportTypeDecisionChain, true},
		{"policy_violations is valid", ExportTypePolicyViolations, true},
		{"accuracy_metrics is valid", ExportTypeAccuracyMetrics, true},
		{"empty is invalid", ExportType(""), false},
		{"unknown is invalid", ExportType("unknown"), false},
		{"FULL_AUDIT uppercase is invalid", ExportType("FULL_AUDIT"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.et.Valid(); got != tt.expected {
				t.Errorf("ExportType(%q).Valid() = %v, want %v", tt.et, got, tt.expected)
			}
		})
	}
}

func TestExportFormat_Valid(t *testing.T) {
	tests := []struct {
		name     string
		ef       ExportFormat
		expected bool
	}{
		{"json is valid", ExportFormatJSON, true},
		{"csv is valid", ExportFormatCSV, true},
		{"xml is valid", ExportFormatXML, true},
		{"pdf is valid", ExportFormatPDF, true},
		{"empty is invalid", ExportFormat(""), false},
		{"xlsx is invalid", ExportFormat("xlsx"), false},
		{"JSON uppercase is invalid", ExportFormat("JSON"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ef.Valid(); got != tt.expected {
				t.Errorf("ExportFormat(%q).Valid() = %v, want %v", tt.ef, got, tt.expected)
			}
		})
	}
}

func TestAssessmentStatus_Valid(t *testing.T) {
	tests := []struct {
		name     string
		as       AssessmentStatus
		expected bool
	}{
		{"draft is valid", AssessmentStatusDraft, true},
		{"in_progress is valid", AssessmentStatusInProgress, true},
		{"submitted is valid", AssessmentStatusSubmitted, true},
		{"approved is valid", AssessmentStatusApproved, true},
		{"rejected is valid", AssessmentStatusRejected, true},
		{"empty is invalid", AssessmentStatus(""), false},
		{"pending is invalid", AssessmentStatus("pending"), false},
		{"DRAFT uppercase is invalid", AssessmentStatus("DRAFT"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.as.Valid(); got != tt.expected {
				t.Errorf("AssessmentStatus(%q).Valid() = %v, want %v", tt.as, got, tt.expected)
			}
		})
	}
}

func TestRiskCategory_Valid(t *testing.T) {
	tests := []struct {
		name     string
		rc       RiskCategory
		expected bool
	}{
		{"minimal is valid", RiskCategoryMinimal, true},
		{"limited is valid", RiskCategoryLimited, true},
		{"high-risk is valid", RiskCategoryHighRisk, true},
		{"unacceptable is valid", RiskCategoryUnacceptable, true},
		{"empty is invalid", RiskCategory(""), false},
		{"high is invalid", RiskCategory("high"), false},
		{"low is invalid", RiskCategory("low"), false},
		{"MINIMAL uppercase is invalid", RiskCategory("MINIMAL"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rc.Valid(); got != tt.expected {
				t.Errorf("RiskCategory(%q).Valid() = %v, want %v", tt.rc, got, tt.expected)
			}
		})
	}
}

func TestMetricType_Valid(t *testing.T) {
	tests := []struct {
		name     string
		mt       MetricType
		expected bool
	}{
		{"accuracy is valid", MetricTypeAccuracy, true},
		{"precision is valid", MetricTypePrecision, true},
		{"recall is valid", MetricTypeRecall, true},
		{"f1_score is valid", MetricTypeF1Score, true},
		{"auc_roc is valid", MetricTypeAUCROC, true},
		{"auc_pr is valid", MetricTypeAUCPR, true},
		{"mse is valid", MetricTypeMSE, true},
		{"mae is valid", MetricTypeMAE, true},
		{"custom is valid", MetricTypeCustom, true},
		{"empty is invalid", MetricType(""), false},
		{"rmse is invalid", MetricType("rmse"), false},
		{"ACCURACY uppercase is invalid", MetricType("ACCURACY"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mt.Valid(); got != tt.expected {
				t.Errorf("MetricType(%q).Valid() = %v, want %v", tt.mt, got, tt.expected)
			}
		})
	}
}

func TestBiasCategory_Valid(t *testing.T) {
	tests := []struct {
		name     string
		bc       BiasCategory
		expected bool
	}{
		{"gender is valid", BiasCategoryGender, true},
		{"age is valid", BiasCategoryAge, true},
		{"ethnicity is valid", BiasCategoryEthnicity, true},
		{"disability is valid", BiasCategoryDisability, true},
		{"religion is valid", BiasCategoryReligion, true},
		{"nationality is valid", BiasCategoryNationality, true},
		{"socioeconomic is valid", BiasCategorySocioeconomic, true},
		{"custom is valid", BiasCategoryCustom, true},
		{"empty is invalid", BiasCategory(""), false},
		{"race is invalid", BiasCategory("race"), false},
		{"GENDER uppercase is invalid", BiasCategory("GENDER"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.bc.Valid(); got != tt.expected {
				t.Errorf("BiasCategory(%q).Valid() = %v, want %v", tt.bc, got, tt.expected)
			}
		})
	}
}

func TestGetOrgIDFromRequest(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		expected  string
	}{
		{
			name:     "X-Org-ID header",
			headers:  map[string]string{"X-Org-ID": "org-123"},
			expected: "org-123",
		},
		{
			name:     "X-Tenant-ID header",
			headers:  map[string]string{"X-Tenant-ID": "tenant-456"},
			expected: "tenant-456",
		},
		{
			name:     "X-Org-ID takes precedence over X-Tenant-ID",
			headers:  map[string]string{"X-Org-ID": "org-123", "X-Tenant-ID": "tenant-456"},
			expected: "org-123",
		},
		{
			name:     "empty when no headers",
			headers:  map[string]string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			if got := getOrgIDFromRequest(req); got != tt.expected {
				t.Errorf("getOrgIDFromRequest() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		data           interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "success response",
			status:         http.StatusOK,
			data:           map[string]string{"message": "success"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"success"}`,
		},
		{
			name:           "created response",
			status:         http.StatusCreated,
			data:           map[string]interface{}{"id": "123", "created": true},
			expectedStatus: http.StatusCreated,
			expectedBody:   `{"created":true,"id":"123"}`,
		},
		{
			name:           "empty object",
			status:         http.StatusOK,
			data:           map[string]interface{}{},
			expectedStatus: http.StatusOK,
			expectedBody:   `{}`,
		},
		{
			name:           "array response",
			status:         http.StatusOK,
			data:           []string{"item1", "item2"},
			expectedStatus: http.StatusOK,
			expectedBody:   `["item1","item2"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeJSON(w, tt.status, tt.data)

			if w.Code != tt.expectedStatus {
				t.Errorf("writeJSON() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if w.Header().Get("Content-Type") != "application/json" {
				t.Errorf("writeJSON() Content-Type = %v, want application/json", w.Header().Get("Content-Type"))
			}

			if w.Body.String() != tt.expectedBody {
				t.Errorf("writeJSON() body = %v, want %v", w.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestWriteJSON_MarshalError(t *testing.T) {
	w := httptest.NewRecorder()

	// Create an unmarshallable value (channel cannot be marshalled to JSON)
	unmarshallable := make(chan int)

	writeJSON(w, http.StatusOK, unmarshallable)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("writeJSON() with unmarshalable data status = %v, want %v", w.Code, http.StatusInternalServerError)
	}

	expectedBody := `{"error":"Failed to marshal response"}`
	if w.Body.String() != expectedBody {
		t.Errorf("writeJSON() with unmarshalable data body = %v, want %v", w.Body.String(), expectedBody)
	}
}

func TestWriteError(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		message        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "bad request",
			status:         http.StatusBadRequest,
			message:        "Invalid request body",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"Invalid request body"}`,
		},
		{
			name:           "not found",
			status:         http.StatusNotFound,
			message:        "Resource not found",
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"Resource not found"}`,
		},
		{
			name:           "unauthorized",
			status:         http.StatusUnauthorized,
			message:        "Missing authentication",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"Missing authentication"}`,
		},
		{
			name:           "internal server error",
			status:         http.StatusInternalServerError,
			message:        "Database connection failed",
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"Database connection failed"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeError(w, tt.status, tt.message)

			if w.Code != tt.expectedStatus {
				t.Errorf("writeError() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if w.Header().Get("Content-Type") != "application/json" {
				t.Errorf("writeError() Content-Type = %v, want application/json", w.Header().Get("Content-Type"))
			}

			if w.Body.String() != tt.expectedBody {
				t.Errorf("writeError() body = %v, want %v", w.Body.String(), tt.expectedBody)
			}
		})
	}
}

// Test struct types are properly initialized
func TestExport_ZeroValue(t *testing.T) {
	export := Export{}

	if export.ID != "" {
		t.Error("Expected empty ID for zero value Export")
	}
	if export.OrgID != "" {
		t.Error("Expected empty OrgID for zero value Export")
	}
	if export.Progress != 0 {
		t.Error("Expected 0 Progress for zero value Export")
	}
	if export.ModelIDs != nil {
		t.Error("Expected nil ModelIDs for zero value Export")
	}
	if export.Filters != nil {
		t.Error("Expected nil Filters for zero value Export")
	}
}

func TestConformityAssessment_ZeroValue(t *testing.T) {
	assessment := ConformityAssessment{}

	if assessment.ID != "" {
		t.Error("Expected empty ID for zero value ConformityAssessment")
	}
	if assessment.Version != 0 {
		t.Error("Expected 0 Version for zero value ConformityAssessment")
	}
	if assessment.Assessors != nil {
		t.Error("Expected nil Assessors for zero value ConformityAssessment")
	}
	if assessment.Requirements != nil {
		t.Error("Expected nil Requirements for zero value ConformityAssessment")
	}
	if assessment.Evidence != nil {
		t.Error("Expected nil Evidence for zero value ConformityAssessment")
	}
	if assessment.Findings != nil {
		t.Error("Expected nil Findings for zero value ConformityAssessment")
	}
}

func TestAccuracyMetric_ZeroValue(t *testing.T) {
	metric := AccuracyMetric{}

	if metric.ID != "" {
		t.Error("Expected empty ID for zero value AccuracyMetric")
	}
	if metric.Value != 0 {
		t.Error("Expected 0 Value for zero value AccuracyMetric")
	}
	if metric.SampleSize != 0 {
		t.Error("Expected 0 SampleSize for zero value AccuracyMetric")
	}
	if metric.Metadata != nil {
		t.Error("Expected nil Metadata for zero value AccuracyMetric")
	}
}

func TestBiasRecord_ZeroValue(t *testing.T) {
	record := BiasRecord{}

	if record.ID != "" {
		t.Error("Expected empty ID for zero value BiasRecord")
	}
	if record.Score != 0 {
		t.Error("Expected 0 Score for zero value BiasRecord")
	}
	if record.IsViolation != false {
		t.Error("Expected false IsViolation for zero value BiasRecord")
	}
}

func TestAccuracyAlert_ZeroValue(t *testing.T) {
	alert := AccuracyAlert{}

	if alert.ID != "" {
		t.Error("Expected empty ID for zero value AccuracyAlert")
	}
	if alert.AckedAt != nil {
		t.Error("Expected nil AckedAt for zero value AccuracyAlert")
	}
	if alert.ResolvedAt != nil {
		t.Error("Expected nil ResolvedAt for zero value AccuracyAlert")
	}
}

// Test request types
func TestCreateExportRequest_ZeroValue(t *testing.T) {
	req := CreateExportRequest{}

	if req.ExportType != "" {
		t.Error("Expected empty ExportType for zero value CreateExportRequest")
	}
	if req.Format != "" {
		t.Error("Expected empty Format for zero value CreateExportRequest")
	}
	if req.ModelIDs != nil {
		t.Error("Expected nil ModelIDs for zero value CreateExportRequest")
	}
}

func TestCreateAssessmentRequest_ZeroValue(t *testing.T) {
	req := CreateAssessmentRequest{}

	if req.SystemID != "" {
		t.Error("Expected empty SystemID for zero value CreateAssessmentRequest")
	}
	if req.SystemName != "" {
		t.Error("Expected empty SystemName for zero value CreateAssessmentRequest")
	}
}

func TestRecordAccuracyRequest_ZeroValue(t *testing.T) {
	req := RecordAccuracyRequest{}

	if req.ModelID != "" {
		t.Error("Expected empty ModelID for zero value RecordAccuracyRequest")
	}
	if req.Value != 0 {
		t.Error("Expected 0 Value for zero value RecordAccuracyRequest")
	}
}

func TestRecordBiasRequest_ZeroValue(t *testing.T) {
	req := RecordBiasRequest{}

	if req.ModelID != "" {
		t.Error("Expected empty ModelID for zero value RecordBiasRequest")
	}
	if req.GroupA != "" {
		t.Error("Expected empty GroupA for zero value RecordBiasRequest")
	}
}

// Test nested types
func TestRequirementStatus_Fields(t *testing.T) {
	rs := RequirementStatus{
		RequirementID: "req-001",
		Article:       "Article 9",
		Description:   "Risk Management System",
		Status:        "compliant",
		Notes:         "Fully implemented",
		EvidenceIDs:   []string{"ev-1", "ev-2"},
	}

	if rs.RequirementID != "req-001" {
		t.Errorf("Expected RequirementID 'req-001', got %s", rs.RequirementID)
	}
	if len(rs.EvidenceIDs) != 2 {
		t.Errorf("Expected 2 EvidenceIDs, got %d", len(rs.EvidenceIDs))
	}
}

func TestEvidenceItem_Fields(t *testing.T) {
	ev := EvidenceItem{
		ID:          "ev-001",
		Type:        "document",
		Title:       "Risk Assessment Report",
		Description: "Comprehensive risk assessment",
		FilePath:    "/evidence/report.pdf",
	}

	if ev.ID != "ev-001" {
		t.Errorf("Expected ID 'ev-001', got %s", ev.ID)
	}
	if ev.Type != "document" {
		t.Errorf("Expected Type 'document', got %s", ev.Type)
	}
}

func TestFinding_Fields(t *testing.T) {
	f := Finding{
		ID:          "find-001",
		Severity:    "major",
		Category:    "documentation",
		Description: "Missing privacy policy",
		Article:     "Article 13",
		Remediation: "Create and publish privacy policy",
		Status:      "open",
	}

	if f.ID != "find-001" {
		t.Errorf("Expected ID 'find-001', got %s", f.ID)
	}
	if f.Severity != "major" {
		t.Errorf("Expected Severity 'major', got %s", f.Severity)
	}
}

func TestAggregatedMetric_Fields(t *testing.T) {
	agg := AggregatedMetric{
		MetricType: MetricTypeAccuracy,
		Count:      100,
		Min:        0.85,
		Max:        0.95,
		Avg:        0.90,
		StdDev:     0.03,
		P50:        0.90,
		P95:        0.94,
		P99:        0.95,
	}

	if agg.Count != 100 {
		t.Errorf("Expected Count 100, got %d", agg.Count)
	}
	if agg.Avg != 0.90 {
		t.Errorf("Expected Avg 0.90, got %f", agg.Avg)
	}
}

func TestAccuracySummary_Fields(t *testing.T) {
	summary := AccuracySummary{
		OrgID:             "org-123",
		TotalModels:       10,
		ModelsAboveTarget: 8,
		ModelsBelowTarget: 2,
		AverageAccuracy:   0.92,
		ActiveAlerts:      3,
	}

	if summary.TotalModels != 10 {
		t.Errorf("Expected TotalModels 10, got %d", summary.TotalModels)
	}
	if summary.ModelsAboveTarget != 8 {
		t.Errorf("Expected ModelsAboveTarget 8, got %d", summary.ModelsAboveTarget)
	}
}
