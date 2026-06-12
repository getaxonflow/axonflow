// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"testing"
	"time"
)

// MockBoardReportRepository is a mock implementation for testing.
type MockBoardReportRepository struct {
	reports map[string]map[string]*BoardReport
	counter int
}

func NewMockBoardReportRepository() *MockBoardReportRepository {
	return &MockBoardReportRepository{
		reports: make(map[string]map[string]*BoardReport),
	}
}

func (m *MockBoardReportRepository) Create(ctx context.Context, report *BoardReport) error {
	if report.ID == "" {
		m.counter++
		report.ID = "mock-report-" + string(rune(m.counter+'0'))
	}
	report.CreatedAt = time.Now().UTC()
	report.UpdatedAt = report.CreatedAt

	if m.reports[report.OrgID] == nil {
		m.reports[report.OrgID] = make(map[string]*BoardReport)
	}
	m.reports[report.OrgID][report.ID] = report
	return nil
}

func (m *MockBoardReportRepository) Get(ctx context.Context, orgID, id string) (*BoardReport, error) {
	if orgReports, ok := m.reports[orgID]; ok {
		if report, ok := orgReports[id]; ok {
			return report, nil
		}
	}
	return nil, ErrBoardReportNotFound
}

func (m *MockBoardReportRepository) List(ctx context.Context, orgID string, params *ListBoardReportsParams) ([]*BoardReport, int, error) {
	if params == nil {
		params = &ListBoardReportsParams{}
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	var result []*BoardReport
	orgReports := m.reports[orgID]
	if orgReports == nil {
		return result, 0, nil
	}

	for _, report := range orgReports {
		if params.ReportType != "" && string(report.ReportType) != params.ReportType {
			continue
		}
		if params.Quarter != "" && report.ReportQuarter != params.Quarter {
			continue
		}
		if params.ApprovalStatus != "" && string(report.ApprovalStatus) != params.ApprovalStatus {
			continue
		}
		result = append(result, report)
	}

	total := len(result)
	if params.Offset >= len(result) {
		return []*BoardReport{}, total, nil
	}
	end := params.Offset + params.Limit
	if end > len(result) {
		end = len(result)
	}
	return result[params.Offset:end], total, nil
}

func (m *MockBoardReportRepository) ListByQuarter(ctx context.Context, orgID, quarter string) ([]*BoardReport, error) {
	var result []*BoardReport
	orgReports := m.reports[orgID]
	if orgReports == nil {
		return result, nil
	}

	for _, report := range orgReports {
		if report.ReportQuarter == quarter {
			result = append(result, report)
		}
	}
	return result, nil
}

func (m *MockBoardReportRepository) Update(ctx context.Context, report *BoardReport) error {
	if orgReports, ok := m.reports[report.OrgID]; ok {
		if _, ok := orgReports[report.ID]; ok {
			report.UpdatedAt = time.Now().UTC()
			m.reports[report.OrgID][report.ID] = report
			return nil
		}
	}
	return ErrBoardReportNotFound
}

func (m *MockBoardReportRepository) Delete(ctx context.Context, orgID, id string) error {
	if orgReports, ok := m.reports[orgID]; ok {
		if _, ok := orgReports[id]; ok {
			delete(m.reports[orgID], id)
			return nil
		}
	}
	return ErrBoardReportNotFound
}

func (m *MockBoardReportRepository) GetLatest(ctx context.Context, orgID string, reportType ReportType) (*BoardReport, error) {
	orgReports := m.reports[orgID]
	if orgReports == nil {
		return nil, ErrBoardReportNotFound
	}

	var latest *BoardReport
	for _, report := range orgReports {
		if report.ReportType == reportType {
			if latest == nil || report.GeneratedAt.After(latest.GeneratedAt) {
				latest = report
			}
		}
	}

	if latest == nil {
		return nil, ErrBoardReportNotFound
	}
	return latest, nil
}

func (m *MockBoardReportRepository) GetPendingApproval(ctx context.Context, orgID string) ([]*BoardReport, error) {
	var result []*BoardReport
	orgReports := m.reports[orgID]
	if orgReports == nil {
		return result, nil
	}

	for _, report := range orgReports {
		if report.ApprovalStatus == ReportApprovalPendingReview {
			result = append(result, report)
		}
	}
	return result, nil
}

func TestBoardReportService_GenerateReport(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	t.Run("generate quarterly report", func(t *testing.T) {
		now := time.Now().UTC()
		start := now.AddDate(0, -3, 0)
		req := &GenerateReportRequest{
			ReportType:        "quarterly",
			ReportPeriodStart: &start,
			ReportPeriodEnd:   &now,
			ReportQuarter:     "Q4-2024",
			GeneratedBy:       "compliance-officer",
			GeneratedByEmail:  "compliance@example.com",
		}

		report, err := service.GenerateReport(context.Background(), "org-1", req)
		if err != nil {
			t.Fatalf("GenerateReport failed: %v", err)
		}

		if report.ID == "" {
			t.Error("Expected ID to be set")
		}
		if report.ReportType != ReportTypeQuarterly {
			t.Errorf("ReportType = %v, want %v", report.ReportType, ReportTypeQuarterly)
		}
		if report.ReportQuarter != "Q4-2024" {
			t.Errorf("ReportQuarter = %v, want Q4-2024", report.ReportQuarter)
		}
		if report.ApprovalStatus != ReportApprovalDraft {
			t.Errorf("ApprovalStatus = %v, want %v", report.ApprovalStatus, ReportApprovalDraft)
		}
		// Pinned to 'automatic' — the DB check constraint (migration 301)
		// only accepts 'automatic' or 'manual'. The literal 'automated'
		// in the old value was the very bug this test was supposed to
		// prevent; it would have 500'd on write every time.
		if report.GenerationMethod != "automatic" {
			t.Errorf("GenerationMethod = %v, want automatic", report.GenerationMethod)
		}
	})

	t.Run("generate annual report", func(t *testing.T) {
		req := &GenerateReportRequest{
			ReportType: "annual",
		}

		report, err := service.GenerateReport(context.Background(), "org-2", req)
		if err != nil {
			t.Fatalf("GenerateReport failed: %v", err)
		}

		if report.ReportType != ReportTypeAnnual {
			t.Errorf("ReportType = %v, want %v", report.ReportType, ReportTypeAnnual)
		}
	})

	t.Run("invalid report type", func(t *testing.T) {
		req := &GenerateReportRequest{
			ReportType: "invalid",
		}

		_, err := service.GenerateReport(context.Background(), "org-1", req)
		if err == nil {
			t.Error("Expected error for invalid report type")
		}
	})

	t.Run("nil request", func(t *testing.T) {
		_, err := service.GenerateReport(context.Background(), "org-1", nil)
		if err == nil {
			t.Error("Expected error for nil request")
		}
	})
}

func TestBoardReportService_ApprovalWorkflow(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	// Create a draft report
	req := &GenerateReportRequest{
		ReportType:    "quarterly",
		ReportQuarter: "Q4-2024",
	}
	report, _ := service.GenerateReport(context.Background(), "org-1", req)

	t.Run("submit for approval", func(t *testing.T) {
		submitReq := &SubmitForApprovalRequest{
			SubmittedBy:      "compliance-officer",
			SubmittedByEmail: "compliance@example.com",
		}

		submitted, err := service.SubmitForApproval(context.Background(), "org-1", report.ID, submitReq)
		if err != nil {
			t.Fatalf("SubmitForApproval failed: %v", err)
		}

		if submitted.ApprovalStatus != ReportApprovalPendingReview {
			t.Errorf("ApprovalStatus = %v, want %v", submitted.ApprovalStatus, ReportApprovalPendingReview)
		}
	})

	t.Run("approve report", func(t *testing.T) {
		approveReq := &ApproveReportRequest{
			ApprovedBy:      "board-member",
			ApprovedByEmail: "board@example.com",
			ApprovalNotes:   "Approved after board review",
		}

		approved, err := service.ApproveReport(context.Background(), "org-1", report.ID, approveReq)
		if err != nil {
			t.Fatalf("ApproveReport failed: %v", err)
		}

		if approved.ApprovalStatus != ReportApprovalApproved {
			t.Errorf("ApprovalStatus = %v, want %v", approved.ApprovalStatus, ReportApprovalApproved)
		}
		if approved.ApprovedBy != "board-member" {
			t.Errorf("ApprovedBy = %v, want board-member", approved.ApprovedBy)
		}
		if approved.ApprovedAt == nil {
			t.Error("Expected ApprovedAt to be set")
		}
	})

	t.Run("cannot submit already approved report", func(t *testing.T) {
		submitReq := &SubmitForApprovalRequest{
			SubmittedBy: "another-user",
		}

		_, err := service.SubmitForApproval(context.Background(), "org-1", report.ID, submitReq)
		if err == nil {
			t.Error("Expected error when submitting approved report")
		}
	})
}

func TestBoardReportService_RejectReport(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	// Create and submit a report
	req := &GenerateReportRequest{
		ReportType: "quarterly",
	}
	report, _ := service.GenerateReport(context.Background(), "org-1", req)
	service.SubmitForApproval(context.Background(), "org-1", report.ID, &SubmitForApprovalRequest{
		SubmittedBy: "compliance-officer",
	})

	t.Run("reject report", func(t *testing.T) {
		rejectReq := &RejectReportRequest{
			RejectedBy:      "board-member",
			RejectionReason: "Missing incident details",
		}

		rejected, err := service.RejectReport(context.Background(), "org-1", report.ID, rejectReq)
		if err != nil {
			t.Fatalf("RejectReport failed: %v", err)
		}

		if rejected.ApprovalStatus != ReportApprovalRejected {
			t.Errorf("ApprovalStatus = %v, want %v", rejected.ApprovalStatus, ReportApprovalRejected)
		}
		if rejected.ApprovalNotes != "Missing incident details" {
			t.Errorf("ApprovalNotes = %v, want 'Missing incident details'", rejected.ApprovalNotes)
		}
	})

	t.Run("reject missing reason", func(t *testing.T) {
		rejectReq := &RejectReportRequest{
			RejectedBy: "board-member",
		}

		_, err := service.RejectReport(context.Background(), "org-1", report.ID, rejectReq)
		if err == nil {
			t.Error("Expected error for missing rejection reason")
		}
	})
}

func TestBoardReportService_DeleteReport(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	t.Run("delete draft report", func(t *testing.T) {
		req := &GenerateReportRequest{
			ReportType: "adhoc",
		}
		report, _ := service.GenerateReport(context.Background(), "org-1", req)

		err := service.DeleteReport(context.Background(), "org-1", report.ID)
		if err != nil {
			t.Fatalf("DeleteReport failed: %v", err)
		}

		// Verify deletion
		_, err = service.GetReport(context.Background(), "org-1", report.ID)
		if err != ErrBoardReportNotFound {
			t.Error("Expected report to be deleted")
		}
	})

	t.Run("cannot delete approved report", func(t *testing.T) {
		req := &GenerateReportRequest{
			ReportType: "quarterly",
		}
		report, _ := service.GenerateReport(context.Background(), "org-2", req)

		// Submit and approve
		service.SubmitForApproval(context.Background(), "org-2", report.ID, &SubmitForApprovalRequest{
			SubmittedBy: "user",
		})
		service.ApproveReport(context.Background(), "org-2", report.ID, &ApproveReportRequest{
			ApprovedBy: "board",
		})

		err := service.DeleteReport(context.Background(), "org-2", report.ID)
		if err == nil {
			t.Error("Expected error when deleting approved report")
		}
	})
}

func TestBoardReportService_CorrectiveActions(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	// Create a report
	req := &GenerateReportRequest{
		ReportType: "quarterly",
	}
	report, _ := service.GenerateReport(context.Background(), "org-1", req)

	t.Run("add corrective action", func(t *testing.T) {
		dueDate := time.Now().AddDate(0, 0, 30)
		action := &CorrectiveAction{
			Action:     "Review high-risk AI systems",
			Priority:   "high",
			AssignedTo: "risk-team",
			DueDate:    &dueDate,
		}

		updated, err := service.AddCorrectiveAction(context.Background(), "org-1", report.ID, action)
		if err != nil {
			t.Fatalf("AddCorrectiveAction failed: %v", err)
		}

		if len(updated.CorrectiveActions) != 1 {
			t.Errorf("CorrectiveActions count = %d, want 1", len(updated.CorrectiveActions))
		}
		if updated.CorrectiveActions[0].Status != "pending" {
			t.Errorf("Status = %v, want pending", updated.CorrectiveActions[0].Status)
		}
	})

	t.Run("update corrective action", func(t *testing.T) {
		// Get the action ID
		report, _ := service.GetReport(context.Background(), "org-1", report.ID)
		actionID := report.CorrectiveActions[0].ID

		completedAt := time.Now().UTC()
		update := &UpdateCorrectiveActionRequest{
			Status:      "completed",
			CompletedAt: &completedAt,
		}

		updated, err := service.UpdateCorrectiveAction(context.Background(), "org-1", report.ID, actionID, update)
		if err != nil {
			t.Fatalf("UpdateCorrectiveAction failed: %v", err)
		}

		if updated.CorrectiveActions[0].Status != "completed" {
			t.Errorf("Status = %v, want completed", updated.CorrectiveActions[0].Status)
		}
	})

	t.Run("update non-existent action", func(t *testing.T) {
		update := &UpdateCorrectiveActionRequest{
			Status: "completed",
		}

		_, err := service.UpdateCorrectiveAction(context.Background(), "org-1", report.ID, "non-existent", update)
		if err == nil {
			t.Error("Expected error for non-existent action")
		}
	})
}

func TestBoardReportService_ListAndFilter(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	// Create multiple reports
	for _, rt := range []string{"quarterly", "annual", "quarterly"} {
		req := &GenerateReportRequest{
			ReportType: rt,
		}
		service.GenerateReport(context.Background(), "org-list", req)
	}

	t.Run("list all reports", func(t *testing.T) {
		reports, total, err := service.ListReports(context.Background(), "org-list", nil)
		if err != nil {
			t.Fatalf("ListReports failed: %v", err)
		}

		if total != 3 {
			t.Errorf("Total = %d, want 3", total)
		}
		if len(reports) != 3 {
			t.Errorf("Len = %d, want 3", len(reports))
		}
	})

	t.Run("filter by report type", func(t *testing.T) {
		params := &ListBoardReportsParams{
			ReportType: "quarterly",
		}
		reports, total, err := service.ListReports(context.Background(), "org-list", params)
		if err != nil {
			t.Fatalf("ListReports failed: %v", err)
		}

		if total != 2 {
			t.Errorf("Total = %d, want 2 quarterly reports", total)
		}
		for _, r := range reports {
			if r.ReportType != ReportTypeQuarterly {
				t.Errorf("ReportType = %v, want quarterly", r.ReportType)
			}
		}
	})
}

func TestBoardReportService_GetLatest(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	// Create reports with different times
	service.GenerateReport(context.Background(), "org-latest", &GenerateReportRequest{
		ReportType:    "quarterly",
		ReportQuarter: "Q1",
	})
	time.Sleep(10 * time.Millisecond)
	service.GenerateReport(context.Background(), "org-latest", &GenerateReportRequest{
		ReportType:    "quarterly",
		ReportQuarter: "Q2",
	})

	t.Run("get latest quarterly report", func(t *testing.T) {
		latest, err := service.GetLatestReport(context.Background(), "org-latest", ReportTypeQuarterly)
		if err != nil {
			t.Fatalf("GetLatestReport failed: %v", err)
		}

		if latest.ReportQuarter != "Q2" {
			t.Errorf("ReportQuarter = %v, want Q2", latest.ReportQuarter)
		}
	})

	t.Run("get latest for non-existent type", func(t *testing.T) {
		_, err := service.GetLatestReport(context.Background(), "org-latest", ReportTypeAnnual)
		if err != ErrBoardReportNotFound {
			t.Error("Expected ErrBoardReportNotFound for non-existent report type")
		}
	})
}

func TestBoardReportService_GetPendingApproval(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	// Create reports with different statuses
	r1, _ := service.GenerateReport(context.Background(), "org-pending", &GenerateReportRequest{
		ReportType: "quarterly",
	})
	service.SubmitForApproval(context.Background(), "org-pending", r1.ID, &SubmitForApprovalRequest{
		SubmittedBy: "user1",
	})

	service.GenerateReport(context.Background(), "org-pending", &GenerateReportRequest{
		ReportType: "annual",
	}) // Draft, not submitted

	t.Run("get pending approval", func(t *testing.T) {
		pending, err := service.GetPendingApproval(context.Background(), "org-pending")
		if err != nil {
			t.Fatalf("GetPendingApproval failed: %v", err)
		}

		if len(pending) != 1 {
			t.Errorf("Pending count = %d, want 1", len(pending))
		}
	})
}

// MockAISystemRepoForBoardReport implements AISystemRepository for board report testing.
type MockAISystemRepoForBoardReport struct {
	systems []*AISystem
}

func (m *MockAISystemRepoForBoardReport) Create(ctx context.Context, system *AISystem) error {
	return nil
}
func (m *MockAISystemRepoForBoardReport) Get(ctx context.Context, orgID, id string) (*AISystem, error) {
	return nil, ErrSystemNotFound
}
func (m *MockAISystemRepoForBoardReport) GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystem, error) {
	return nil, ErrSystemNotFound
}
func (m *MockAISystemRepoForBoardReport) List(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error) {
	return m.systems, len(m.systems), nil
}
func (m *MockAISystemRepoForBoardReport) Update(ctx context.Context, system *AISystem) error {
	return nil
}
func (m *MockAISystemRepoForBoardReport) Delete(ctx context.Context, orgID, id string) error {
	return nil
}
func (m *MockAISystemRepoForBoardReport) GetSummary(ctx context.Context, orgID string) (*AISystemSummary, error) {
	return nil, nil
}

// MockValidationRepoForBoardReport implements ModelValidationRepository for board report testing.
type MockValidationRepoForBoardReport struct {
	validations []*ModelValidation
}

func (m *MockValidationRepoForBoardReport) Create(ctx context.Context, v *ModelValidation) error {
	return nil
}
func (m *MockValidationRepoForBoardReport) Get(ctx context.Context, orgID, id string) (*ModelValidation, error) {
	return nil, ErrValidationNotFound
}
func (m *MockValidationRepoForBoardReport) List(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error) {
	return m.validations, len(m.validations), nil
}
func (m *MockValidationRepoForBoardReport) ListBySystem(ctx context.Context, orgID, systemID string) ([]*ModelValidation, error) {
	return m.validations, nil
}
func (m *MockValidationRepoForBoardReport) Update(ctx context.Context, v *ModelValidation) error {
	return nil
}
func (m *MockValidationRepoForBoardReport) Delete(ctx context.Context, orgID, id string) error {
	return nil
}
func (m *MockValidationRepoForBoardReport) GetLatestBySystem(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error) {
	return nil, nil
}

// MockIncidentRepoForBoardReport implements AIIncidentRepository for board report testing.
type MockIncidentRepoForBoardReport struct {
	incidents []*AIIncident
	// pending maps notificationType ("board"/"rbi") to the incidents that
	// legally require but have not yet sent that notification. nil → none.
	pending map[string][]*AIIncident
}

func (m *MockIncidentRepoForBoardReport) Create(ctx context.Context, i *AIIncident) error {
	return nil
}
func (m *MockIncidentRepoForBoardReport) Get(ctx context.Context, orgID, id string) (*AIIncident, error) {
	return nil, ErrIncidentNotFound
}
func (m *MockIncidentRepoForBoardReport) GetByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error) {
	return nil, ErrIncidentNotFound
}
func (m *MockIncidentRepoForBoardReport) List(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error) {
	return m.incidents, len(m.incidents), nil
}
func (m *MockIncidentRepoForBoardReport) ListBySystem(ctx context.Context, orgID, systemID string) ([]*AIIncident, error) {
	return m.incidents, nil
}
func (m *MockIncidentRepoForBoardReport) Update(ctx context.Context, i *AIIncident) error {
	return nil
}
func (m *MockIncidentRepoForBoardReport) Delete(ctx context.Context, orgID, id string) error {
	return nil
}
func (m *MockIncidentRepoForBoardReport) GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error) {
	return nil, nil
}
func (m *MockIncidentRepoForBoardReport) GetPendingNotifications(ctx context.Context, orgID, notificationType string) ([]*AIIncident, error) {
	if m.pending == nil {
		return nil, nil
	}
	return m.pending[notificationType], nil
}

// MockKillSwitchRepoForBoardReport implements KillSwitchRepository for board report testing.
type MockKillSwitchRepoForBoardReport struct {
	switches []*KillSwitch
}

func (m *MockKillSwitchRepoForBoardReport) Create(ctx context.Context, ks *KillSwitch) error {
	return nil
}
func (m *MockKillSwitchRepoForBoardReport) Get(ctx context.Context, orgID, id string) (*KillSwitch, error) {
	return nil, ErrKillSwitchNotFound
}
func (m *MockKillSwitchRepoForBoardReport) GetByScope(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (*KillSwitch, error) {
	return nil, ErrKillSwitchNotFound
}
func (m *MockKillSwitchRepoForBoardReport) List(ctx context.Context, orgID string, params *ListKillSwitchParams) ([]*KillSwitch, int, error) {
	return m.switches, len(m.switches), nil
}
func (m *MockKillSwitchRepoForBoardReport) ListActive(ctx context.Context, orgID string) ([]*KillSwitch, error) {
	var result []*KillSwitch
	for _, ks := range m.switches {
		if ks.IsActive {
			result = append(result, ks)
		}
	}
	return result, nil
}
func (m *MockKillSwitchRepoForBoardReport) ListBySystem(ctx context.Context, orgID, systemID string) ([]*KillSwitch, error) {
	return m.switches, nil
}
func (m *MockKillSwitchRepoForBoardReport) ListByScope(ctx context.Context, orgID string, scope KillSwitchScope) ([]*KillSwitch, error) {
	return m.switches, nil
}
func (m *MockKillSwitchRepoForBoardReport) Update(ctx context.Context, ks *KillSwitch) error {
	return nil
}
func (m *MockKillSwitchRepoForBoardReport) Delete(ctx context.Context, orgID, id string) error {
	return nil
}
func (m *MockKillSwitchRepoForBoardReport) AddHistoryEntry(ctx context.Context, entry *KillSwitchHistoryEntry) error {
	return nil
}
func (m *MockKillSwitchRepoForBoardReport) GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*KillSwitchHistoryEntry, error) {
	return nil, nil
}
func (m *MockKillSwitchRepoForBoardReport) CheckActive(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (bool, *KillSwitch, error) {
	return false, nil, nil
}

func TestBoardReportService_GenerateReportWithData(t *testing.T) {
	// Setup mock repositories with test data
	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)

	systemRepo := &MockAISystemRepoForBoardReport{
		systems: []*AISystem{
			{
				ID:               "sys-1",
				OrgID:            "org-data",
				SystemID:         "credit-scoring",
				SystemName:       "Credit Scoring Model",
				RiskCategory:     RiskCategoryHigh,
				DeploymentStatus: DeploymentStatusProduction,
				CreatedAt:        now.AddDate(0, -1, 0),
			},
			{
				ID:               "sys-2",
				OrgID:            "org-data",
				SystemID:         "chatbot",
				SystemName:       "Customer Chatbot",
				RiskCategory:     RiskCategoryMedium,
				DeploymentStatus: DeploymentStatusProduction,
				CreatedAt:        now.AddDate(0, -6, 0),
			},
			{
				ID:               "sys-3",
				OrgID:            "org-data",
				SystemID:         "fraud-detection",
				SystemName:       "Fraud Detection",
				RiskCategory:     RiskCategoryHigh,
				DeploymentStatus: DeploymentStatusDeprecated,
				CreatedAt:        now.AddDate(-1, 0, 0),
			},
			{
				ID:                "sys-4",
				OrgID:             "org-data",
				SystemID:          "loan-approval",
				SystemName:        "Loan Approval",
				RiskCategory:      RiskCategoryLow,
				DeploymentStatus:  DeploymentStatusDevelopment,
				CreatedAt:         weekAgo,
				NextValidationDue: &weekAgo, // Overdue
			},
		},
	}

	validationRepo := &MockValidationRepoForBoardReport{
		validations: []*ModelValidation{
			{
				ID:             "val-1",
				OrgID:          "org-data",
				SystemID:       "sys-1",
				ValidationType: ValidationTypeIndependent,
				Recommendation: ValidationRecommendationApprove,
			},
			{
				ID:             "val-2",
				OrgID:          "org-data",
				SystemID:       "sys-2",
				ValidationType: ValidationTypeDevelopment,
				Recommendation: ValidationRecommendationConditional,
			},
			{
				ID:             "val-3",
				OrgID:          "org-data",
				SystemID:       "sys-1",
				ValidationType: ValidationTypeIndependent,
				Recommendation: ValidationRecommendationReject,
			},
		},
	}

	resolvedAt := now.Add(-2 * time.Hour)
	incidentRepo := &MockIncidentRepoForBoardReport{
		incidents: []*AIIncident{
			{
				ID:           "inc-1",
				OrgID:        "org-data",
				SystemID:     "sys-1",
				Severity:     IncidentSeverityCritical,
				IncidentType: IncidentTypeModelFailure,
				Status:       IncidentStatusResolved,
				DetectedAt:   now.Add(-4 * time.Hour),
				ResolvedAt:   &resolvedAt,
			},
			{
				ID:           "inc-2",
				OrgID:        "org-data",
				SystemID:     "sys-2",
				Severity:     IncidentSeverityHigh,
				IncidentType: IncidentTypeBiasDetected,
				Status:       IncidentStatusOpen,
				DetectedAt:   now.Add(-1 * time.Hour),
			},
			{
				ID:           "inc-3",
				OrgID:        "org-data",
				SystemID:     "sys-1",
				Severity:     IncidentSeverityMedium,
				IncidentType: IncidentTypeModelFailure,
				Status:       IncidentStatusClosed,
				DetectedAt:   now.Add(-24 * time.Hour),
				ResolvedAt:   &resolvedAt,
			},
		},
	}

	killSwitchRepo := &MockKillSwitchRepoForBoardReport{
		switches: []*KillSwitch{
			{
				ID:               "ks-1",
				OrgID:            "org-data",
				SystemID:         "sys-3",
				Scope:            KillSwitchScopeSystem,
				IsActive:         true,
				ActivatedBy:      "admin@example.com",
				ActivationReason: "Critical vulnerability",
			},
		},
	}

	boardRepo := NewMockBoardReportRepository()
	service := NewBoardReportService(boardRepo, systemRepo, validationRepo, incidentRepo, killSwitchRepo)

	t.Run("generate report with aggregated data", func(t *testing.T) {
		start := now.AddDate(0, -3, 0)
		req := &GenerateReportRequest{
			ReportType:        "quarterly",
			ReportPeriodStart: &start,
			ReportPeriodEnd:   &now,
			ReportQuarter:     "Q4-2024",
			GeneratedBy:       "compliance-officer",
		}

		report, err := service.GenerateReport(context.Background(), "org-data", req)
		if err != nil {
			t.Fatalf("GenerateReport failed: %v", err)
		}

		// Verify AI Systems aggregation
		if report.TotalAISystems != 4 {
			t.Errorf("TotalAISystems = %d, want 4", report.TotalAISystems)
		}
		if report.SystemsByRisk == nil {
			t.Error("SystemsByRisk should not be nil")
		} else {
			if count, ok := report.SystemsByRisk["high"]; !ok || count != 2 {
				t.Errorf("SystemsByRisk[high] = %v, want 2", report.SystemsByRisk["high"])
			}
			if count, ok := report.SystemsByRisk["medium"]; !ok || count != 1 {
				t.Errorf("SystemsByRisk[medium] = %v, want 1", report.SystemsByRisk["medium"])
			}
		}
		if report.SystemsByStatus == nil {
			t.Error("SystemsByStatus should not be nil")
		} else {
			if count, ok := report.SystemsByStatus["production"]; !ok || count != 2 {
				t.Errorf("SystemsByStatus[production] = %v, want 2", report.SystemsByStatus["production"])
			}
		}
		if report.SystemsDeprecated != 1 {
			t.Errorf("SystemsDeprecated = %d, want 1", report.SystemsDeprecated)
		}

		// Verify new systems (created after period start)
		if report.NewSystemsDeployed < 1 {
			t.Errorf("NewSystemsDeployed = %d, want at least 1", report.NewSystemsDeployed)
		}

		// Verify Validations aggregation
		if report.TotalValidations != 3 {
			t.Errorf("TotalValidations = %d, want 3", report.TotalValidations)
		}
		if report.ValidationsByType == nil {
			t.Error("ValidationsByType should not be nil")
		} else {
			if count, ok := report.ValidationsByType["independent"]; !ok || count != 2 {
				t.Errorf("ValidationsByType[independent] = %v, want 2", report.ValidationsByType["independent"])
			}
		}
		if report.ValidationsByRecommendation == nil {
			t.Error("ValidationsByRecommendation should not be nil")
		}

		// Verify overdue validations
		if report.OverdueValidations != 1 {
			t.Errorf("OverdueValidations = %d, want 1", report.OverdueValidations)
		}

		// Verify Incidents aggregation
		if report.TotalIncidents != 3 {
			t.Errorf("TotalIncidents = %d, want 3", report.TotalIncidents)
		}
		if report.IncidentsResolved != 2 {
			t.Errorf("IncidentsResolved = %d, want 2", report.IncidentsResolved)
		}
		if report.IncidentsOpen != 1 {
			t.Errorf("IncidentsOpen = %d, want 1", report.IncidentsOpen)
		}
		if report.IncidentsBySeverity == nil {
			t.Error("IncidentsBySeverity should not be nil")
		} else {
			if count, ok := report.IncidentsBySeverity["critical"]; !ok || count != 1 {
				t.Errorf("IncidentsBySeverity[critical] = %v, want 1", report.IncidentsBySeverity["critical"])
			}
		}
		if report.IncidentsByType == nil {
			t.Error("IncidentsByType should not be nil")
		} else {
			if count, ok := report.IncidentsByType["model_failure"]; !ok || count != 2 {
				t.Errorf("IncidentsByType[model_failure] = %v, want 2", report.IncidentsByType["model_failure"])
			}
		}
		if report.AverageResolutionTimeHours <= 0 {
			t.Error("AverageResolutionTimeHours should be > 0")
		}

		// Verify Kill Switch aggregation
		if report.KillSwitchActivations != 1 {
			t.Errorf("KillSwitchActivations = %d, want 1", report.KillSwitchActivations)
		}
		if report.KillSwitchDetails == nil {
			t.Error("KillSwitchDetails should not be nil")
		}

		// Verify compliance score (should be < 100 due to incidents and active kill switch)
		if report.ComplianceScore >= 100 {
			t.Errorf("ComplianceScore = %f, want < 100 due to issues", report.ComplianceScore)
		}

		// Verify compliance issues identified
		if len(report.ComplianceIssues) == 0 {
			t.Error("ComplianceIssues should not be empty")
		}
	})
}

func TestBoardReportService_ComplianceScoreCalculation(t *testing.T) {
	boardRepo := NewMockBoardReportRepository()

	// Create service with no other repos (null data)
	service := NewBoardReportService(boardRepo, nil, nil, nil, nil)

	t.Run("perfect compliance score with no issues", func(t *testing.T) {
		req := &GenerateReportRequest{
			ReportType: "quarterly",
		}

		report, err := service.GenerateReport(context.Background(), "org-clean", req)
		if err != nil {
			t.Fatalf("GenerateReport failed: %v", err)
		}

		// With no systems, no incidents, no issues - score should be 100
		if report.ComplianceScore != 100 {
			t.Errorf("ComplianceScore = %f, want 100 for clean slate", report.ComplianceScore)
		}
	})
}

// findIssue returns the first compliance issue with the given category, or nil.
func findIssue(issues []ComplianceIssue, category string) *ComplianceIssue {
	for i := range issues {
		if issues[i].Category == category {
			return &issues[i]
		}
	}
	return nil
}

// TestBoardReportService_PendingNotificationVisibility proves #2640 P2: the
// board report consults GetPendingNotifications and surfaces an unsent-but-
// legally-required RBI / board notification as a distinct compliance issue
// (not a generic open-critical incident), penalizing the compliance score.
//
// Red-on-revert: if GenerateReport stops calling GetPendingNotifications, the
// pending counts stay zero, the regulatory_notification / board_notification
// issues disappear, and the score is not penalized — every assertion below
// fails.
func TestBoardReportService_PendingNotificationVisibility(t *testing.T) {
	now := time.Now().UTC()
	resolvedAt := now.Add(-1 * time.Hour)

	t.Run("unsent required RBI+board notifications surface as distinct issues", func(t *testing.T) {
		// A critical incident that was already RESOLVED but whose RBI/board
		// notification was never sent. GetOpenIncidents would miss it; only
		// the pending-notification query catches it.
		critical := &AIIncident{
			ID:                        "inc-unreported",
			OrgID:                     "org-pending",
			Severity:                  IncidentSeverityCritical,
			IncidentType:              IncidentTypeModelFailure,
			Status:                    IncidentStatusResolved,
			DetectedAt:                now.Add(-3 * time.Hour),
			ResolvedAt:                &resolvedAt,
			BoardNotificationRequired: true,
			RBINotificationRequired:   true,
		}
		incidentRepo := &MockIncidentRepoForBoardReport{
			incidents: []*AIIncident{critical},
			pending: map[string][]*AIIncident{
				"board": {critical},
				"rbi":   {critical},
			},
		}
		boardRepo := NewMockBoardReportRepository()
		service := NewBoardReportService(boardRepo, nil, nil, incidentRepo, nil)

		report, err := service.GenerateReport(context.Background(), "org-pending", &GenerateReportRequest{
			ReportType: "quarterly",
		})
		if err != nil {
			t.Fatalf("GenerateReport failed: %v", err)
		}

		if report.PendingRBINotifications != 1 {
			t.Errorf("PendingRBINotifications = %d, want 1", report.PendingRBINotifications)
		}
		if report.PendingBoardNotifications != 1 {
			t.Errorf("PendingBoardNotifications = %d, want 1", report.PendingBoardNotifications)
		}

		rbiIssue := findIssue(report.ComplianceIssues, "regulatory_notification")
		if rbiIssue == nil {
			t.Fatal("expected a 'regulatory_notification' compliance issue for the unsent RBI notification")
		}
		if rbiIssue.Severity != "critical" {
			t.Errorf("regulatory_notification severity = %q, want critical", rbiIssue.Severity)
		}
		if findIssue(report.ComplianceIssues, "board_notification") == nil {
			t.Error("expected a 'board_notification' compliance issue for the unsent board notification")
		}

		// Score must be penalized below a clean 100. The unsent RBI (15) +
		// board (5) deductions stack on top of the critical-incident (10)
		// deduction, so the score is strictly < 100.
		if report.ComplianceScore >= 100 {
			t.Errorf("ComplianceScore = %f, want < 100 (unsent required notifications must penalize)", report.ComplianceScore)
		}
	})

	t.Run("notification deductions are bounded (caps RBI=30, board=15)", func(t *testing.T) {
		// Five pending of each — the deductions must cap, not run away:
		// RBI 5*15=75 → capped at 30, board 5*5=25 → capped at 15. With no
		// other issues, score = 100 - 30 - 15 = 55.
		mk := func(id string) *AIIncident {
			return &AIIncident{OrgID: "org-many", ID: id, Severity: IncidentSeverityCritical}
		}
		incidentRepo := &MockIncidentRepoForBoardReport{
			// incidents is empty so severity aggregation adds no extra
			// deduction — this isolates the notification caps.
			incidents: nil,
			pending: map[string][]*AIIncident{
				"rbi":   {mk("r1"), mk("r2"), mk("r3"), mk("r4"), mk("r5")},
				"board": {mk("b1"), mk("b2"), mk("b3"), mk("b4"), mk("b5")},
			},
		}
		boardRepo := NewMockBoardReportRepository()
		service := NewBoardReportService(boardRepo, nil, nil, incidentRepo, nil)

		report, err := service.GenerateReport(context.Background(), "org-many", &GenerateReportRequest{
			ReportType: "quarterly",
		})
		if err != nil {
			t.Fatalf("GenerateReport failed: %v", err)
		}
		if report.PendingRBINotifications != 5 || report.PendingBoardNotifications != 5 {
			t.Fatalf("pending counts = (rbi=%d, board=%d), want (5, 5)",
				report.PendingRBINotifications, report.PendingBoardNotifications)
		}
		if report.ComplianceScore != 55 {
			t.Errorf("ComplianceScore = %f, want 55 (100 - capped RBI 30 - capped board 15)", report.ComplianceScore)
		}
	})

	t.Run("no pending notifications => no notification issues, no penalty", func(t *testing.T) {
		// Precondition-absent control: a clean slate with an incident repo
		// that returns NO pending notifications must not invent the issues.
		incidentRepo := &MockIncidentRepoForBoardReport{
			incidents: nil,
			pending:   nil, // GetPendingNotifications returns empty
		}
		boardRepo := NewMockBoardReportRepository()
		service := NewBoardReportService(boardRepo, nil, nil, incidentRepo, nil)

		report, err := service.GenerateReport(context.Background(), "org-clean", &GenerateReportRequest{
			ReportType: "quarterly",
		})
		if err != nil {
			t.Fatalf("GenerateReport failed: %v", err)
		}

		if report.PendingRBINotifications != 0 || report.PendingBoardNotifications != 0 {
			t.Errorf("pending counts = (rbi=%d, board=%d), want (0, 0)",
				report.PendingRBINotifications, report.PendingBoardNotifications)
		}
		if findIssue(report.ComplianceIssues, "regulatory_notification") != nil {
			t.Error("did not expect a 'regulatory_notification' issue with no pending notifications")
		}
		if findIssue(report.ComplianceIssues, "board_notification") != nil {
			t.Error("did not expect a 'board_notification' issue with no pending notifications")
		}
		if report.ComplianceScore != 100 {
			t.Errorf("ComplianceScore = %f, want 100 (clean slate, no penalty)", report.ComplianceScore)
		}
	})
}

func TestBoardReportService_ErrorHandling(t *testing.T) {
	repo := NewMockBoardReportRepository()
	service := NewBoardReportService(repo, nil, nil, nil, nil)

	t.Run("approve non-existent report", func(t *testing.T) {
		_, err := service.ApproveReport(context.Background(), "org-1", "non-existent", &ApproveReportRequest{
			ApprovedBy: "admin",
		})
		if err == nil || err != ErrBoardReportNotFound {
			t.Error("Expected ErrBoardReportNotFound")
		}
	})

	t.Run("reject non-existent report", func(t *testing.T) {
		_, err := service.RejectReport(context.Background(), "org-1", "non-existent", &RejectReportRequest{
			RejectedBy:      "admin",
			RejectionReason: "test",
		})
		if err == nil || err != ErrBoardReportNotFound {
			t.Error("Expected ErrBoardReportNotFound")
		}
	})

	t.Run("approve with nil request", func(t *testing.T) {
		report, _ := service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
			ReportType: "quarterly",
		})
		service.SubmitForApproval(context.Background(), "org-1", report.ID, &SubmitForApprovalRequest{
			SubmittedBy: "user",
		})

		_, err := service.ApproveReport(context.Background(), "org-1", report.ID, nil)
		if err == nil {
			t.Error("Expected error for nil request")
		}
	})

	t.Run("reject with nil request", func(t *testing.T) {
		report, _ := service.GenerateReport(context.Background(), "org-2", &GenerateReportRequest{
			ReportType: "quarterly",
		})
		service.SubmitForApproval(context.Background(), "org-2", report.ID, &SubmitForApprovalRequest{
			SubmittedBy: "user",
		})

		_, err := service.RejectReport(context.Background(), "org-2", report.ID, nil)
		if err == nil {
			t.Error("Expected error for nil request")
		}
	})

	t.Run("add corrective action with nil action", func(t *testing.T) {
		report, _ := service.GenerateReport(context.Background(), "org-3", &GenerateReportRequest{
			ReportType: "quarterly",
		})

		_, err := service.AddCorrectiveAction(context.Background(), "org-3", report.ID, nil)
		if err == nil {
			t.Error("Expected error for nil action")
		}
	})

	t.Run("add corrective action with empty fields succeeds", func(t *testing.T) {
		report, _ := service.GenerateReport(context.Background(), "org-4", &GenerateReportRequest{
			ReportType: "quarterly",
		})

		// Empty action is allowed (fields get defaults)
		updated, err := service.AddCorrectiveAction(context.Background(), "org-4", report.ID, &CorrectiveAction{})
		if err != nil {
			t.Errorf("Expected empty action to succeed, got error: %v", err)
		}
		if len(updated.CorrectiveActions) != 1 {
			t.Errorf("Expected 1 corrective action, got %d", len(updated.CorrectiveActions))
		}
	})
}
