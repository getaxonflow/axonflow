// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"errors"
	"time"

	"axonflow/platform/orchestrator/euaiact"
	"axonflow/platform/orchestrator/masfeat"
	"axonflow/platform/orchestrator/ojk"
	"axonflow/platform/orchestrator/rbi"
	"axonflow/platform/orchestrator/sebi"
)

// Module-service fakes for the per-regulator provider tests.
//
// Each fake stands in for the real module's own interface, so the provider
// under test runs its real conversion code against a controlled data set. The
// alternative - a real database per provider - would test the modules rather
// than the adapters, and the modules already have their own suites.
//
// Every fake ASSERTS the scoping key it was handed. A provider that passed the
// wrong tenancy dimension (org where the module keys on tenant, or the reverse)
// would read the wrong customer's rows in production, and under a single
// enterprise license those are different values (#3071). Recording the key here
// is what makes that testable at all.

var errFakeModule = errors.New("fake module service failure")

// -----------------------------------------------------------------------------
// EU AI Act
// -----------------------------------------------------------------------------

type fakeEUAIActRepo struct {
	gotOrgID    string
	assessments []*euaiact.ConformityAssessment
	metrics     []*euaiact.AccuracyMetric
	violations  []euaiact.PolicyViolationRecord
	hitl        []euaiact.HITLApprovalRecord
	decisions   []euaiact.DecisionChainRecord
	failOn      string
}

func (f *fakeEUAIActRepo) record(orgID, call string) error {
	f.gotOrgID = orgID
	if f.failOn == call {
		return errFakeModule
	}
	return nil
}

func (f *fakeEUAIActRepo) Create(ctx context.Context, e *euaiact.Export) error { return nil }
func (f *fakeEUAIActRepo) GetByID(ctx context.Context, orgID, id string) (*euaiact.Export, error) {
	return nil, euaiact.ErrExportNotFound
}
func (f *fakeEUAIActRepo) List(ctx context.Context, orgID string, limit, offset int) ([]*euaiact.Export, int64, error) {
	return nil, 0, nil
}
func (f *fakeEUAIActRepo) Update(ctx context.Context, e *euaiact.Export) error { return nil }
func (f *fakeEUAIActRepo) Delete(ctx context.Context, orgID, id string) error  { return nil }

func (f *fakeEUAIActRepo) GetDecisionChain(ctx context.Context, orgID string, from, to time.Time) ([]euaiact.DecisionChainRecord, error) {
	if err := f.record(orgID, "decisions"); err != nil {
		return nil, err
	}
	return f.decisions, nil
}
func (f *fakeEUAIActRepo) GetFullAudit(ctx context.Context, orgID string, from, to time.Time) ([]euaiact.AuditLogRecord, error) {
	return nil, f.record(orgID, "fullaudit")
}
func (f *fakeEUAIActRepo) GetPolicyViolations(ctx context.Context, orgID string, from, to time.Time) ([]euaiact.PolicyViolationRecord, error) {
	if err := f.record(orgID, "violations"); err != nil {
		return nil, err
	}
	return f.violations, nil
}
func (f *fakeEUAIActRepo) GetHITLApprovalHistory(ctx context.Context, orgID string, from, to time.Time) ([]euaiact.HITLApprovalRecord, error) {
	if err := f.record(orgID, "hitl"); err != nil {
		return nil, err
	}
	return f.hitl, nil
}
func (f *fakeEUAIActRepo) GetAccuracyMetrics(ctx context.Context, orgID string, from, to time.Time) ([]*euaiact.AccuracyMetric, error) {
	if err := f.record(orgID, "metrics"); err != nil {
		return nil, err
	}
	return f.metrics, nil
}
func (f *fakeEUAIActRepo) GetConformityAssessments(ctx context.Context, orgID string, from, to time.Time) ([]*euaiact.ConformityAssessment, error) {
	if err := f.record(orgID, "assessments"); err != nil {
		return nil, err
	}
	return f.assessments, nil
}

// -----------------------------------------------------------------------------
// SEBI
// -----------------------------------------------------------------------------

type fakeSEBIService struct {
	gotTenantID string
	export      *sebi.SEBIAuditExportResponse
	readiness   *sebi.SEBIComplianceReadinessResponse
	retention   *sebi.SEBIRetentionStatusResponse
	failOn      string
}

func (f *fakeSEBIService) record(tenantID, call string) error {
	f.gotTenantID = tenantID
	if f.failOn == call {
		return errFakeModule
	}
	return nil
}

func (f *fakeSEBIService) ExportAuditData(ctx context.Context, tenantID string, req *sebi.SEBIAuditExportRequest) (*sebi.SEBIAuditExportResponse, error) {
	if err := f.record(tenantID, "export"); err != nil {
		return nil, err
	}
	return f.export, nil
}
func (f *fakeSEBIService) GetRetentionStatus(ctx context.Context, tenantID string, req *sebi.SEBIRetentionStatusRequest) (*sebi.SEBIRetentionStatusResponse, error) {
	if err := f.record(tenantID, "retention"); err != nil {
		return nil, err
	}
	return f.retention, nil
}
func (f *fakeSEBIService) GetExportStatus(ctx context.Context, tenantID, exportID string) (*sebi.SEBIAuditExportResponse, error) {
	return f.export, nil
}
func (f *fakeSEBIService) ValidateComplianceReadiness(ctx context.Context, tenantID string) (*sebi.SEBIComplianceReadinessResponse, error) {
	if err := f.record(tenantID, "readiness"); err != nil {
		return nil, err
	}
	return f.readiness, nil
}

// -----------------------------------------------------------------------------
// OJK
// -----------------------------------------------------------------------------

type fakeOJKService struct {
	gotTenantID  string
	gotFramework ojk.OJKComplianceFramework
	export       *ojk.OJKAuditExportResponse
	readiness    *ojk.OJKComplianceReadinessResponse
	dashboard    *ojk.OJKDashboardResponse
	retention    *ojk.OJKRetentionStatusResponse
	failOn       string
}

func (f *fakeOJKService) record(tenantID, call string) error {
	f.gotTenantID = tenantID
	if f.failOn == call {
		return errFakeModule
	}
	return nil
}

func (f *fakeOJKService) ExportAuditData(ctx context.Context, tenantID string, req *ojk.OJKAuditExportRequest) (*ojk.OJKAuditExportResponse, error) {
	f.gotFramework = req.Framework
	if err := f.record(tenantID, "export"); err != nil {
		return nil, err
	}
	return f.export, nil
}
func (f *fakeOJKService) GetRetentionStatus(ctx context.Context, tenantID string, req *ojk.OJKRetentionStatusRequest) (*ojk.OJKRetentionStatusResponse, error) {
	if err := f.record(tenantID, "retention"); err != nil {
		return nil, err
	}
	return f.retention, nil
}
func (f *fakeOJKService) GetExportStatus(ctx context.Context, tenantID, exportID string) (*ojk.OJKAuditExportResponse, error) {
	return f.export, nil
}
func (f *fakeOJKService) ValidateComplianceReadiness(ctx context.Context, tenantID string) (*ojk.OJKComplianceReadinessResponse, error) {
	if err := f.record(tenantID, "readiness"); err != nil {
		return nil, err
	}
	return f.readiness, nil
}
func (f *fakeOJKService) SubmitBreachNotification(ctx context.Context, tenantID string, req *ojk.OJKBreachNotification) (*ojk.OJKBreachNotification, error) {
	return nil, nil
}
func (f *fakeOJKService) AcknowledgeBreachNotification(ctx context.Context, tenantID, id string) (*ojk.OJKBreachNotification, error) {
	return nil, nil
}
func (f *fakeOJKService) EvaluateBreachDeadlines(ctx context.Context, tenantID string) (int, error) {
	return 0, nil
}
func (f *fakeOJKService) GetDashboard(ctx context.Context, tenantID string) (*ojk.OJKDashboardResponse, error) {
	if err := f.record(tenantID, "dashboard"); err != nil {
		return nil, err
	}
	return f.dashboard, nil
}

// -----------------------------------------------------------------------------
// RBI
// -----------------------------------------------------------------------------

type fakeRBIRegistry struct {
	gotOrgID string
	systems  []*rbi.AISystem
	failOn   string
}

func (f *fakeRBIRegistry) CreateSystem(ctx context.Context, orgID string, req *rbi.CreateAISystemRequest) (*rbi.AISystem, error) {
	return nil, nil
}
func (f *fakeRBIRegistry) GetSystem(ctx context.Context, orgID, id string) (*rbi.AISystem, error) {
	return nil, nil
}
func (f *fakeRBIRegistry) ListSystems(ctx context.Context, orgID string, params *rbi.ListAISystemsParams) ([]*rbi.AISystem, int, error) {
	f.gotOrgID = orgID
	if f.failOn == "list" {
		return nil, 0, errFakeModule
	}
	return f.systems, len(f.systems), nil
}
func (f *fakeRBIRegistry) UpdateSystem(ctx context.Context, orgID, id string, req *rbi.UpdateAISystemRequest) (*rbi.AISystem, error) {
	return nil, nil
}
func (f *fakeRBIRegistry) DeleteSystem(ctx context.Context, orgID, id string) error { return nil }
func (f *fakeRBIRegistry) ProcessBoardApproval(ctx context.Context, orgID, id string, req *rbi.BoardApprovalRequest) (*rbi.AISystem, error) {
	return nil, nil
}
func (f *fakeRBIRegistry) GetSystemSummary(ctx context.Context, orgID string) (*rbi.AISystemSummary, error) {
	return nil, nil
}
func (f *fakeRBIRegistry) ScheduleValidation(ctx context.Context, orgID, id string, validationDate time.Time) (*rbi.AISystem, error) {
	return nil, nil
}

type fakeRBIValidation struct {
	validations []*rbi.ModelValidation
}

func (f *fakeRBIValidation) CreateValidation(ctx context.Context, orgID string, req *rbi.CreateValidationRequest) (*rbi.ModelValidation, error) {
	return nil, nil
}
func (f *fakeRBIValidation) GetValidation(ctx context.Context, orgID, id string) (*rbi.ModelValidation, error) {
	return nil, nil
}
func (f *fakeRBIValidation) ListValidations(ctx context.Context, orgID string, params *rbi.ListValidationsParams) ([]*rbi.ModelValidation, int, error) {
	return f.validations, len(f.validations), nil
}
func (f *fakeRBIValidation) UpdateValidation(ctx context.Context, orgID, id string, req *rbi.UpdateValidationRequest) (*rbi.ModelValidation, error) {
	return nil, nil
}
func (f *fakeRBIValidation) DeleteValidation(ctx context.Context, orgID, id string) error { return nil }
func (f *fakeRBIValidation) GetLatestValidation(ctx context.Context, orgID, systemID string, vt rbi.ValidationType) (*rbi.ModelValidation, error) {
	return nil, nil
}
func (f *fakeRBIValidation) AddFinding(ctx context.Context, orgID, validationID string, finding *rbi.ValidationFinding) (*rbi.ModelValidation, error) {
	return nil, nil
}

type fakeRBIIncident struct {
	incidents []*rbi.AIIncident
}

func (f *fakeRBIIncident) CreateIncident(ctx context.Context, orgID string, req *rbi.CreateIncidentRequest) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) GetIncident(ctx context.Context, orgID, id string) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) GetIncidentByIncidentID(ctx context.Context, orgID, incidentID string) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) ListIncidents(ctx context.Context, orgID string, params *rbi.ListIncidentsParams) ([]*rbi.AIIncident, int, error) {
	return f.incidents, len(f.incidents), nil
}
func (f *fakeRBIIncident) UpdateIncident(ctx context.Context, orgID, id string, req *rbi.UpdateIncidentRequest) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) DeleteIncident(ctx context.Context, orgID, id string) error { return nil }
func (f *fakeRBIIncident) UpdateStatus(ctx context.Context, orgID, id string, status rbi.IncidentStatus, resolution string) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) AddRemediationAction(ctx context.Context, orgID, id string, action *rbi.RemediationAction) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) UpdateRemediationAction(ctx context.Context, orgID, id, actionID string, req *rbi.UpdateRemediationActionRequest) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) RecordBoardNotification(ctx context.Context, orgID, id string, req *rbi.RecordNotificationRequest) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) RecordRBINotification(ctx context.Context, orgID, id string, req *rbi.RecordNotificationRequest) (*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) GetOpenIncidents(ctx context.Context, orgID string) ([]*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) GetPendingBoardNotifications(ctx context.Context, orgID string) ([]*rbi.AIIncident, error) {
	return nil, nil
}
func (f *fakeRBIIncident) GetPendingRBINotifications(ctx context.Context, orgID string) ([]*rbi.AIIncident, error) {
	return nil, nil
}

type fakeRBIKillSwitch struct {
	switches []*rbi.KillSwitch
	history  map[string][]*rbi.KillSwitchHistoryEntry
	// gotHistoryOrgIDs records every orgID the provider fanned out with, so a
	// test can prove the fan-out never leaves the caller's organization.
	gotHistoryOrgIDs []string
}

func (f *fakeRBIKillSwitch) CreateKillSwitch(ctx context.Context, orgID string, req *rbi.CreateKillSwitchRequest) (*rbi.KillSwitch, error) {
	return nil, nil
}
func (f *fakeRBIKillSwitch) GetKillSwitch(ctx context.Context, orgID, id string) (*rbi.KillSwitch, error) {
	return nil, nil
}
func (f *fakeRBIKillSwitch) ListKillSwitches(ctx context.Context, orgID string, params *rbi.ListKillSwitchParams) ([]*rbi.KillSwitch, int, error) {
	return f.switches, len(f.switches), nil
}
func (f *fakeRBIKillSwitch) ListActiveKillSwitches(ctx context.Context, orgID string) ([]*rbi.KillSwitch, error) {
	return nil, nil
}
func (f *fakeRBIKillSwitch) Activate(ctx context.Context, orgID, id string, req *rbi.ActivateKillSwitchRequest) (*rbi.KillSwitch, error) {
	return nil, nil
}
func (f *fakeRBIKillSwitch) Deactivate(ctx context.Context, orgID, id string, req *rbi.DeactivateKillSwitchRequest) (*rbi.KillSwitch, error) {
	return nil, nil
}
func (f *fakeRBIKillSwitch) DeleteKillSwitch(ctx context.Context, orgID, id string) error { return nil }
func (f *fakeRBIKillSwitch) CheckKillSwitch(ctx context.Context, orgID string, scope rbi.KillSwitchScope, systemID, targetID string) (*rbi.KillSwitchCheckResult, error) {
	return nil, nil
}
func (f *fakeRBIKillSwitch) GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*rbi.KillSwitchHistoryEntry, error) {
	f.gotHistoryOrgIDs = append(f.gotHistoryOrgIDs, orgID)
	return f.history[killSwitchID], nil
}
func (f *fakeRBIKillSwitch) AutoTrigger(ctx context.Context, orgID, systemID, reason string) (*rbi.KillSwitch, error) {
	return nil, nil
}

type fakeRBIBoard struct {
	reports []*rbi.BoardReport
}

func (f *fakeRBIBoard) GenerateReport(ctx context.Context, orgID string, req *rbi.GenerateReportRequest) (*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) GetReport(ctx context.Context, orgID, id string) (*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) ListReports(ctx context.Context, orgID string, params *rbi.ListBoardReportsParams) ([]*rbi.BoardReport, int, error) {
	return f.reports, len(f.reports), nil
}
func (f *fakeRBIBoard) SubmitForApproval(ctx context.Context, orgID, id string, req *rbi.SubmitForApprovalRequest) (*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) ApproveReport(ctx context.Context, orgID, id string, req *rbi.ApproveReportRequest) (*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) RejectReport(ctx context.Context, orgID, id string, req *rbi.RejectReportRequest) (*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) DeleteReport(ctx context.Context, orgID, id string) error { return nil }
func (f *fakeRBIBoard) GetLatestReport(ctx context.Context, orgID string, rt rbi.ReportType) (*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) GetPendingApproval(ctx context.Context, orgID string) ([]*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) AddCorrectiveAction(ctx context.Context, orgID, reportID string, action *rbi.CorrectiveAction) (*rbi.BoardReport, error) {
	return nil, nil
}
func (f *fakeRBIBoard) UpdateCorrectiveAction(ctx context.Context, orgID, reportID, actionID string, update *rbi.UpdateCorrectiveActionRequest) (*rbi.BoardReport, error) {
	return nil, nil
}

// -----------------------------------------------------------------------------
// MAS FEAT
// -----------------------------------------------------------------------------

// MAS FEAT's Module holds CONCRETE service pointers, so its fakes sit one layer
// lower - at the repository interfaces the real services are constructed from.
// The provider therefore runs against the real service logic.

type fakeMASRegistryRepo struct {
	gotOrgID string
	systems  []*masfeat.AISystemRegistry
	failOn   string
}

func (f *fakeMASRegistryRepo) Create(ctx context.Context, s *masfeat.AISystemRegistry) error {
	return nil
}
func (f *fakeMASRegistryRepo) GetByID(ctx context.Context, orgID, id string) (*masfeat.AISystemRegistry, error) {
	return nil, nil
}
func (f *fakeMASRegistryRepo) GetBySystemID(ctx context.Context, orgID, systemID string) (*masfeat.AISystemRegistry, error) {
	return nil, nil
}
func (f *fakeMASRegistryRepo) List(ctx context.Context, orgID string, params masfeat.ListParams) ([]*masfeat.AISystemRegistry, error) {
	f.gotOrgID = orgID
	if f.failOn == "list" {
		return nil, errFakeModule
	}
	return f.systems, nil
}
func (f *fakeMASRegistryRepo) Update(ctx context.Context, s *masfeat.AISystemRegistry) error {
	return nil
}
func (f *fakeMASRegistryRepo) Delete(ctx context.Context, orgID, id string) error { return nil }
func (f *fakeMASRegistryRepo) GetSummary(ctx context.Context, orgID string) (*masfeat.RegistrySummary, error) {
	return &masfeat.RegistrySummary{OrgID: orgID, TotalSystems: len(f.systems)}, nil
}
func (f *fakeMASRegistryRepo) CountByStatus(ctx context.Context, orgID string) (map[masfeat.SystemStatus]int, error) {
	return map[masfeat.SystemStatus]int{}, nil
}

type fakeMASAssessmentRepo struct {
	assessments []*masfeat.FEATAssessment
}

func (f *fakeMASAssessmentRepo) Create(ctx context.Context, a *masfeat.FEATAssessment) error {
	return nil
}
func (f *fakeMASAssessmentRepo) GetByID(ctx context.Context, orgID, id string) (*masfeat.FEATAssessment, error) {
	return nil, nil
}
func (f *fakeMASAssessmentRepo) List(ctx context.Context, orgID string, params masfeat.ListParams) ([]*masfeat.FEATAssessment, error) {
	return f.assessments, nil
}
func (f *fakeMASAssessmentRepo) Update(ctx context.Context, a *masfeat.FEATAssessment) error {
	return nil
}
func (f *fakeMASAssessmentRepo) GetLatestForSystem(ctx context.Context, orgID, systemID string) (*masfeat.FEATAssessment, error) {
	return nil, nil
}

type fakeMASKillSwitchRepo struct {
	history          map[string][]*masfeat.KillSwitchHistory
	gotHistoryOrgIDs []string
}

func (f *fakeMASKillSwitchRepo) Create(ctx context.Context, ks *masfeat.KillSwitch) error { return nil }
func (f *fakeMASKillSwitchRepo) GetBySystemID(ctx context.Context, orgID, systemID string) (*masfeat.KillSwitch, error) {
	return nil, nil
}
func (f *fakeMASKillSwitchRepo) Update(ctx context.Context, ks *masfeat.KillSwitch) error { return nil }
func (f *fakeMASKillSwitchRepo) RecordHistory(ctx context.Context, orgID string, h *masfeat.KillSwitchHistory) error {
	return nil
}
func (f *fakeMASKillSwitchRepo) GetHistory(ctx context.Context, orgID, systemID string, limit int) ([]*masfeat.KillSwitchHistory, error) {
	f.gotHistoryOrgIDs = append(f.gotHistoryOrgIDs, orgID)
	return f.history[systemID], nil
}
