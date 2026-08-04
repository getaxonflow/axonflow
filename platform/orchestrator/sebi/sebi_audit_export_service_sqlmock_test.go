// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package sebi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ExportAuditData Tests
// =============================================================================

func TestExportAuditData_AllDataTypes_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "travel-us"

	now := time.Now().UTC()
	startDate := now.Add(-30 * 24 * time.Hour)
	endDate := now

	// Mock getOrgName
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test Org"))
	mock.ExpectCommit()

	// Mock exportPolicyViolations
	detailsJSON, _ := json.Marshal(map[string]interface{}{"pii_type": "pan"})
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, created_at, violation_type, severity, description, policy_id, client_id, user_id, action, details FROM policy_violations")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "created_at", "violation_type", "severity", "description",
			"policy_id", "client_id", "user_id", "action", "details",
		}).
			AddRow("pv-1", now, "pii_detected", "critical", "PAN detected",
				"pol-1", "agent-1", int64(10), "blocked", detailsJSON).
			AddRow("pv-2", now, "unauthorized", "high", "Unauthorized access",
				nil, nil, nil, "blocked", nil))

	// Mock exportLLMCalls
	redactedJSON, _ := json.Marshal([]string{"pan"})
	flagsJSON, _ := json.Marshal([]string{"sebi_aiml"})
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, timestamp, provider, model, input_tokens, output_tokens, response_time_ms, cost, policy_decision, user_id, client_id, redacted_fields, compliance_flags FROM llm_call_audits")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "provider", "model",
			"input_tokens", "output_tokens", "response_time_ms", "cost",
			"policy_decision", "user_id", "client_id", "redacted_fields", "compliance_flags",
		}).
			AddRow("llm-1", "req-1", now, "openai", "gpt-4o",
				100, 200, int64(450), 0.005,
				"allowed", int64(10), "agent-1", redactedJSON, flagsJSON))

	// Mock exportDecisionChain (now reads canonical audit_logs decision rows, #2588)
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->'policy_ids'->>0")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "decision_type", "policy_decision",
			"model_id", "policies_evaluated", "policy_triggered", "response_time_ms",
			"correlation_id",
		}).
			AddRow("dc-1", "req-1", now, "policy_eval", "needs_approval",
				"model-v2", "[\"policy-1\",\"policy-2\"]", "policy-1", int64(150), ""))

	// Mock exportHITLOversight
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, trigger_reason, reviewer_id, decision, notes, review_time_ms FROM hitl_queue")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "trigger_reason",
			"reviewer_id", "decision", "notes", "review_time_ms",
		}).
			AddRow("hitl-1", "req-2", now, "high_risk",
				42, "approved", "Looks good", int64(5000)))

	// Mock exportPIIRedactions
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, pii_type, redaction_method, location, detection_confidence, user_id, compliance_framework FROM pii_redaction_log")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "pii_type", "redaction_method",
			"location", "detection_confidence", "user_id", "compliance_framework",
		}).
			AddRow("pii-1", "req-3", now, "pan", "mask",
				"input.query", 0.99, int64(10), "SEBI_AI_ML"))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		Framework: SEBIFrameworkAIML,
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, SEBIFrameworkAIML, resp.Framework)
	assert.NotEmpty(t, resp.ExportID)
	assert.NotNil(t, resp.Metadata)
	assert.Equal(t, "Test Org", resp.Metadata.OrgName)
	assert.Equal(t, tenantID, resp.Metadata.TenantID)
	assert.NotEmpty(t, resp.Metadata.Checksum)

	require.NotNil(t, resp.Summary)
	assert.Equal(t, 6, resp.Summary.TotalRecords) // 2+1+1+1+1
	assert.Equal(t, 2, resp.Summary.RecordsByType[SEBIDataTypePolicyViolations])
	assert.Equal(t, 1, resp.Summary.RecordsByType[SEBIDataTypeLLMCalls])
	assert.Equal(t, 1, resp.Summary.RecordsByType[SEBIDataTypeDecisionChain])
	assert.Equal(t, 1, resp.Summary.RecordsByType[SEBIDataTypeHITLOversight])
	assert.Equal(t, 1, resp.Summary.RecordsByType[SEBIDataTypePIIRedactions])

	require.NotNil(t, resp.Data)
	assert.Len(t, resp.Data.PolicyViolations, 2)
	assert.Equal(t, "pv-1", resp.Data.PolicyViolations[0].ID)
	assert.Equal(t, "pol-1", resp.Data.PolicyViolations[0].PolicyID)
	assert.Equal(t, "agent-1", resp.Data.PolicyViolations[0].AgentID)
	assert.Equal(t, 10, resp.Data.PolicyViolations[0].UserID)
	assert.NotNil(t, resp.Data.PolicyViolations[0].Details)

	// Second violation has nil nullable fields
	assert.Empty(t, resp.Data.PolicyViolations[1].PolicyID)
	assert.Empty(t, resp.Data.PolicyViolations[1].AgentID)
	assert.Equal(t, 0, resp.Data.PolicyViolations[1].UserID)

	assert.Len(t, resp.Data.LLMCalls, 1)
	assert.Equal(t, "openai", resp.Data.LLMCalls[0].Provider)
	assert.Equal(t, 100, resp.Data.LLMCalls[0].InputTokens)
	assert.Equal(t, "agent-1", resp.Data.LLMCalls[0].AgentID)

	assert.Len(t, resp.Data.DecisionChain, 1)
	assert.True(t, resp.Data.DecisionChain[0].RequiresReview)
	assert.Equal(t, "pending_review", resp.Data.DecisionChain[0].DecisionOutcome)
	assert.Empty(t, resp.Data.DecisionChain[0].RiskLevel)

	assert.Len(t, resp.Data.HITLOversight, 1)
	assert.Equal(t, "Looks good", resp.Data.HITLOversight[0].Notes)
	assert.Equal(t, int64(5000), resp.Data.HITLOversight[0].ReviewTimeMs)

	assert.Len(t, resp.Data.PIIRedactions, 1)
	assert.Equal(t, "pan", resp.Data.PIIRedactions[0].PIIType)

	// Violations summary should be computed
	require.NotNil(t, resp.Summary.ViolationsSummary)
	assert.Equal(t, 2, resp.Summary.ViolationsSummary.Total)
	assert.Equal(t, 1, resp.Summary.ViolationsSummary.BySeverity["critical"])
	assert.Equal(t, 1, resp.Summary.ViolationsSummary.BySeverity["high"])

	// Compliance score should reflect violations
	assert.Less(t, resp.Summary.ComplianceScore, 100.0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_SpecificDataTypes(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-7 * 24 * time.Hour)
	endDate := now

	// Mock getOrgName
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Acme Corp"))
	mock.ExpectCommit()

	// Only requesting LLM calls - so only that query fires
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, timestamp, provider, model")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "provider", "model",
			"input_tokens", "output_tokens", "response_time_ms", "cost",
			"policy_decision", "user_id", "client_id", "redacted_fields", "compliance_flags",
		}).
			AddRow("llm-1", "req-1", now, "anthropic", "claude-sonnet-4-20250514",
				50, 100, int64(300), 0.002, "allowed", nil, nil, nil, nil))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeLLMCalls},
		Framework: SEBIFrameworkDPDP,
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, SEBIFrameworkDPDP, resp.Framework)
	assert.Equal(t, 1, resp.Summary.TotalRecords)
	assert.Len(t, resp.Data.LLMCalls, 1)
	assert.Nil(t, resp.Data.PolicyViolations)
	assert.Nil(t, resp.Data.DecisionChain)
	assert.Nil(t, resp.Data.HITLOversight)
	assert.Nil(t, resp.Data.PIIRedactions)
	assert.Nil(t, resp.Summary.ViolationsSummary) // No violations data

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_OrgNameNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "unknown-tenant"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	// Mock getOrgName returning no rows (org_id lookup fails, then id fallback also fails)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE id = $1")).
		WithArgs(tenantID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	// Request only PIIRedactions (simplest path)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, pii_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "pii_type", "redaction_method",
			"location", "detection_confidence", "user_id", "compliance_framework",
		}))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypePIIRedactions},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Fallback org name should be used
	assert.Equal(t, fmt.Sprintf("Tenant-%s", tenantID), resp.Metadata.OrgName)
	assert.Equal(t, "completed", resp.Status)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_TableNotExists_LLMCalls(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	// LLM calls table does not exist
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, timestamp, provider, model")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnError(fmt.Errorf("relation \"llm_call_audits\" does not exist"))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeLLMCalls},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should return empty LLM calls, not error
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, 0, resp.Summary.TotalRecords)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_TableNotExists_DecisionChain(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	mock.ExpectQuery(regexp.QuoteMeta("policy_details->'policy_ids'->>0")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnError(fmt.Errorf("no such table: audit_logs"))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeDecisionChain},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, 0, resp.Summary.TotalRecords)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_TableNotExists_HITL(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, trigger_reason")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnError(fmt.Errorf("relation \"hitl_queue\" does not exist"))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeHITLOversight},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, 0, resp.Summary.TotalRecords)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_TableNotExists_PIIRedactions(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, pii_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnError(fmt.Errorf("no such table: pii_redaction_log"))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypePIIRedactions},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, 0, resp.Summary.TotalRecords)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_PolicyViolationsQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	// Non-table-not-exists error -- connection error
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, created_at, violation_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnError(fmt.Errorf("connection refused"))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypePolicyViolations},
	}

	// ExportAuditData continues on error (logs and skips the data type)
	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, 0, resp.Summary.TotalRecords)
	assert.Nil(t, resp.Data.PolicyViolations)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_EmptyResults(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Empty Org"))
	mock.ExpectCommit()

	// All queries return empty result sets
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, created_at, violation_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "created_at", "violation_type", "severity", "description",
			"policy_id", "client_id", "user_id", "action", "details",
		}))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, timestamp, provider, model")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "provider", "model",
			"input_tokens", "output_tokens", "response_time_ms", "cost",
			"policy_decision", "user_id", "client_id", "redacted_fields", "compliance_flags",
		}))

	mock.ExpectQuery(regexp.QuoteMeta("policy_details->'policy_ids'->>0")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "decision_type", "policy_decision",
			"model_id", "policies_evaluated", "policy_triggered", "response_time_ms",
			"correlation_id",
		}))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, trigger_reason")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "trigger_reason",
			"reviewer_id", "decision", "notes", "review_time_ms",
		}))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, pii_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "pii_type", "redaction_method",
			"location", "detection_confidence", "user_id", "compliance_framework",
		}))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, 0, resp.Summary.TotalRecords)
	assert.Equal(t, 100.0, resp.Summary.ComplianceScore)
	assert.Nil(t, resp.Summary.ViolationsSummary)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_DecisionChain_NullableFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	// Decision chain with COALESCE'd empty strings; only response_time_ms is nil.
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->'policy_ids'->>0")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "decision_type", "policy_decision",
			"model_id", "policies_evaluated", "policy_triggered", "response_time_ms",
			"correlation_id",
		}).
			AddRow("dc-1", "req-1", now, "policy_eval", "allow",
				"", "", "", nil, ""))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeDecisionChain},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp.Data)
	require.Len(t, resp.Data.DecisionChain, 1)

	dc := resp.Data.DecisionChain[0]
	assert.Equal(t, "dc-1", dc.ID)
	assert.Empty(t, dc.ModelID)
	assert.False(t, dc.RequiresReview)
	assert.Empty(t, dc.RiskLevel)
	assert.Empty(t, dc.PolicyTriggered)
	assert.Nil(t, dc.ProcessingTimeMs)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_HITL_NullableFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	// HITL with nullable notes and review_time_ms as nil
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, trigger_reason")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "trigger_reason",
			"reviewer_id", "decision", "notes", "review_time_ms",
		}).
			AddRow("hitl-1", "req-1", now, "policy_trigger",
				5, "rejected", nil, nil))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeHITLOversight},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.Len(t, resp.Data.HITLOversight, 1)

	hitl := resp.Data.HITLOversight[0]
	assert.Equal(t, "hitl-1", hitl.ID)
	assert.Empty(t, hitl.Notes)
	assert.Equal(t, int64(0), hitl.ReviewTimeMs)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_PIIRedactions_NullableFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, pii_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "pii_type", "redaction_method",
			"location", "detection_confidence", "user_id", "compliance_framework",
		}).
			AddRow("pii-1", "req-1", now, "aadhaar", "hash",
				"response.body", 0.97, nil, nil))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypePIIRedactions},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.Len(t, resp.Data.PIIRedactions, 1)

	pii := resp.Data.PIIRedactions[0]
	assert.Equal(t, "aadhaar", pii.PIIType)
	assert.Equal(t, 0, pii.UserID)
	assert.Empty(t, pii.ComplianceFramework)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestExportAuditData_DataTypeAll(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test"))
	mock.ExpectCommit()

	// Passing "all" should expand to all 5 data types
	emptyViolationRows := sqlmock.NewRows([]string{
		"id", "created_at", "violation_type", "severity", "description",
		"policy_id", "client_id", "user_id", "action", "details",
	})
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, created_at, violation_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(emptyViolationRows)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, timestamp, provider")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "provider", "model",
			"input_tokens", "output_tokens", "response_time_ms", "cost",
			"policy_decision", "user_id", "client_id", "redacted_fields", "compliance_flags",
		}))

	mock.ExpectQuery(regexp.QuoteMeta("policy_details->'policy_ids'->>0")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "decision_type", "policy_decision",
			"model_id", "policies_evaluated", "policy_triggered", "response_time_ms",
			"correlation_id",
		}))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, trigger_reason")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "trigger_reason",
			"reviewer_id", "decision", "notes", "review_time_ms",
		}))

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, request_id, created_at, pii_type")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "pii_type", "redaction_method",
			"location", "detection_confidence", "user_id", "compliance_framework",
		}))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeAll},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	assert.Equal(t, "completed", resp.Status)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// =============================================================================





// =============================================================================
// GetRetentionStatus Tests
// =============================================================================

func TestGetRetentionStatus_AllCompliant(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "travel-us"

	// For each of the 5 data types, getRetentionConfig and getDataTypeStats are called
	dataTypes := []string{
		"policy_violations", "llm_calls", "decision_chain", "hitl_oversight", "pii_redactions",
	}
	tableNames := []string{
		"policy_violations", "llm_call_audits", "decision_chain", "hitl_queue", "pii_redaction_log",
	}

	for i, dt := range dataTypes {
		// getRetentionConfig — v9 Phase 8 B2: wraps in withOrgScope.
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
			WithArgs(tenantID).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days, COALESCE(last_cleanup_at, '1970-01-01'::timestamp) FROM audit_retention_config")).
			WithArgs(tenantID, dt).
			WillReturnRows(sqlmock.NewRows([]string{"retention_days", "last_cleanup"}).
				AddRow(1825, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))
		mock.ExpectCommit()

		// getDataTypeStats
		now := time.Now().UTC()
		oldest := now.Add(-365 * 24 * time.Hour)
		if dt == "decision_chain" {
			// Decision-record stats now derive from audit_logs decision rows (#2588).
			mock.ExpectQuery(regexp.QuoteMeta("MIN(timestamp), MAX(timestamp), COUNT(*)")).
				WithArgs(tenantID).
				WillReturnRows(sqlmock.NewRows([]string{"oldest", "newest", "total"}).
					AddRow(oldest, now, int64(1000)))
		} else {
			mock.ExpectQuery(regexp.QuoteMeta(fmt.Sprintf("SELECT\n\t\t\tMIN(created_at) as oldest,\n\t\t\tMAX(created_at) as newest,\n\t\t\tCOUNT(*) as total\n\t\tFROM %s", tableNames[i]))).
				WithArgs(tenantID).
				WillReturnRows(sqlmock.NewRows([]string{"oldest", "newest", "total"}).
					AddRow(oldest, now, int64(1000)))
		}
	}

	req := &SEBIRetentionStatusRequest{}

	resp, err := service.GetRetentionStatus(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, tenantID, resp.TenantID)
	assert.Equal(t, SEBIFrameworkAIML, resp.Framework)
	assert.Equal(t, "COMPLIANT", resp.ComplianceStatus)
	assert.Len(t, resp.Status, 5)

	for _, s := range resp.Status {
		assert.Equal(t, "COMPLIANT", s.ComplianceStatus)
		assert.Equal(t, 1825, s.RetentionDays)
		assert.Equal(t, int64(1000), s.TotalRecords)
	}

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRetentionStatus_NonCompliant(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	// Only check one data type
	// getRetentionConfig returns less than 1825 days — v9 Phase 8 B2: wraps in withOrgScope.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days, COALESCE(last_cleanup_at")).
		WithArgs(tenantID, "policy_violations").
		WillReturnRows(sqlmock.NewRows([]string{"retention_days", "last_cleanup"}).
			AddRow(365, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))
	mock.ExpectCommit()

	// getDataTypeStats
	mock.ExpectQuery("SELECT").
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"oldest", "newest", "total"}).
			AddRow(nil, nil, int64(0)))

	req := &SEBIRetentionStatusRequest{
		DataTypes: []SEBIAuditDataType{SEBIDataTypePolicyViolations},
	}

	resp, err := service.GetRetentionStatus(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "NON_COMPLIANT", resp.ComplianceStatus)
	require.Len(t, resp.Status, 1)
	assert.Equal(t, "NON_COMPLIANT", resp.Status[0].ComplianceStatus)
	assert.Equal(t, 365, resp.Status[0].RetentionDays)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRetentionStatus_RetentionConfigNotFound_DefaultsTo5Years(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	// getRetentionConfig returns no rows -> defaults to 1825.
	// v9 Phase 8 B2: wraps in withOrgScope; ErrNoRows → tx.Rollback.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days, COALESCE(last_cleanup_at")).
		WithArgs(tenantID, "llm_calls").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	// getDataTypeStats returns error
	mock.ExpectQuery("SELECT").
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("connection error"))

	req := &SEBIRetentionStatusRequest{
		DataTypes: []SEBIAuditDataType{SEBIDataTypeLLMCalls},
	}

	resp, err := service.GetRetentionStatus(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "COMPLIANT", resp.ComplianceStatus)
	require.Len(t, resp.Status, 1)
	assert.Equal(t, 1825, resp.Status[0].RetentionDays) // Default
	assert.Equal(t, "COMPLIANT", resp.Status[0].ComplianceStatus)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRetentionStatus_StatsError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	// getRetentionConfig - success. v9 Phase 8 B2: wraps in withOrgScope.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days")).
		WithArgs(tenantID, "decision_chain").
		WillReturnRows(sqlmock.NewRows([]string{"retention_days", "last_cleanup"}).
			AddRow(2000, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)))
	mock.ExpectCommit()

	// getDataTypeStats - error
	mock.ExpectQuery("SELECT").
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("table does not exist"))

	req := &SEBIRetentionStatusRequest{
		DataTypes: []SEBIAuditDataType{SEBIDataTypeDecisionChain},
	}

	resp, err := service.GetRetentionStatus(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Still compliant (2000 >= 1825), just no stats populated
	assert.Equal(t, "COMPLIANT", resp.ComplianceStatus)
	require.Len(t, resp.Status, 1)
	assert.Equal(t, 2000, resp.Status[0].RetentionDays)
	assert.Equal(t, int64(0), resp.Status[0].TotalRecords)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRetentionStatus_NullTimestamps(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	// v9 Phase 8 B2: getRetentionConfig wraps in withOrgScope; ErrNoRows → Rollback.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days")).
		WithArgs(tenantID, "pii_redactions").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	// Stats with null timestamps (empty table)
	mock.ExpectQuery("SELECT").
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"oldest", "newest", "total"}).
			AddRow(nil, nil, int64(0)))

	req := &SEBIRetentionStatusRequest{
		DataTypes: []SEBIAuditDataType{SEBIDataTypePIIRedactions},
	}

	resp, err := service.GetRetentionStatus(ctx, tenantID, req)
	require.NoError(t, err)
	require.Len(t, resp.Status, 1)
	assert.True(t, resp.Status[0].OldestRecord.IsZero())
	assert.True(t, resp.Status[0].NewestRecord.IsZero())

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// ValidateComplianceReadiness Tests
// =============================================================================

func TestValidateComplianceReadiness_AllPass(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "travel-us"

	// checkRetentionCompliance: all data types >= 1825.
	// v9 Phase 8 B2: checkRetentionCompliance wraps in withOrgScope.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type, retention_days FROM audit_retention_config")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"data_type", "retention_days"}).
			AddRow("policy_violations", 1825).
			AddRow("llm_calls", 2000).
			AddRow("decision_chain", 1825))
	mock.ExpectCommit()

	// checkPIIPolicies: count > 0
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM policies")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	// checkHITLConfiguration: count > 0
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM hitl_config")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// checkAuditLogging: count > 0
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM audit_logs")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(150))

	// checkDecisionChainTracing: count > 0
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->>'decision_id' IS NOT NULL")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(50))

	resp, err := service.ValidateComplianceReadiness(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Ready)
	assert.Equal(t, 100, resp.Score)
	assert.Len(t, resp.Checks, 5)
	assert.Nil(t, resp.Recommendations)

	for _, check := range resp.Checks {
		assert.Equal(t, "pass", check.Status, "Check %s should pass", check.Name)
	}

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestValidateComplianceReadiness_AllFail(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	// checkRetentionCompliance: non-compliant retention.
	// v9 Phase 8 B2: checkRetentionCompliance wraps in withOrgScope.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type, retention_days FROM audit_retention_config")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"data_type", "retention_days"}).
			AddRow("policy_violations", 365))
	mock.ExpectCommit()

	// checkPIIPolicies: no policies found
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM policies")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// checkHITLConfiguration: not configured
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM hitl_config")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// checkAuditLogging: no recent logs
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM audit_logs")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// checkDecisionChainTracing: no recent records
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->>'decision_id' IS NOT NULL")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	resp, err := service.ValidateComplianceReadiness(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Ready)
	// Retention(-25) + PII(-25) + HITL(-10 warning) + Audit(-25) + Chain(-10 warning) = 100 - 95 = 5
	assert.Equal(t, 5, resp.Score)
	assert.Len(t, resp.Checks, 5)

	assert.Equal(t, "fail", resp.Checks[0].Status)   // Retention
	assert.Equal(t, "fail", resp.Checks[1].Status)   // PII
	assert.Equal(t, "warning", resp.Checks[2].Status) // HITL
	assert.Equal(t, "fail", resp.Checks[3].Status)   // Audit
	assert.Equal(t, "warning", resp.Checks[4].Status) // Decision Chain

	assert.Len(t, resp.Recommendations, 5)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestValidateComplianceReadiness_TableNotExists_Retention(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	// checkRetentionCompliance: table does not exist -> defaults to compliant.
	// v9 Phase 8 B2: checkRetentionCompliance wraps in withOrgScope; on Query
	// error the helper triggers tx.Rollback().
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type, retention_days FROM audit_retention_config")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("relation \"audit_retention_config\" does not exist"))
	mock.ExpectRollback()

	// checkPIIPolicies: table does not exist -> defaults to true
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM policies")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("relation \"policies\" does not exist"))

	// checkHITLConfiguration: table does not exist -> false
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM hitl_config")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("no such table: hitl_config"))

	// checkAuditLogging: table does not exist -> false
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM audit_logs")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("relation \"audit_logs\" does not exist"))

	// checkDecisionChainTracing: table does not exist -> false
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->>'decision_id' IS NOT NULL")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("relation \"decision_chain\" does not exist"))

	resp, err := service.ValidateComplianceReadiness(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Retention: pass (table not exist = default 5yr)
	// PII: pass (table not exist = static policies enabled by default)
	// HITL: warning (table not exist = not configured)
	// Audit: fail (table not exist = not found)
	// Decision Chain: warning (table not exist = not configured)
	assert.Equal(t, "pass", resp.Checks[0].Status)    // Retention
	assert.Equal(t, "pass", resp.Checks[1].Status)    // PII
	assert.Equal(t, "warning", resp.Checks[2].Status)  // HITL
	assert.Equal(t, "fail", resp.Checks[3].Status)    // Audit
	assert.Equal(t, "warning", resp.Checks[4].Status)  // Decision Chain

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestValidateComplianceReadiness_DBErrors(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	// checkRetentionCompliance: non-table error -> fail.
	// v9 Phase 8 B2: checkRetentionCompliance wraps in withOrgScope; on Query
	// error the helper triggers tx.Rollback().
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type, retention_days FROM audit_retention_config")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("permission denied"))
	mock.ExpectRollback()

	// checkPIIPolicies: non-table error -> fail
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM policies")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("timeout"))

	// checkHITLConfiguration: non-table error -> fail
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM hitl_config")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("connection reset"))

	// checkAuditLogging: non-table error -> fail
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM audit_logs")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("disk full"))

	// checkDecisionChainTracing: non-table error -> fail
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->>'decision_id' IS NOT NULL")).
		WithArgs(tenantID).
		WillReturnError(fmt.Errorf("server crashed"))

	resp, err := service.ValidateComplianceReadiness(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Ready)
	assert.Equal(t, "fail", resp.Checks[0].Status) // Retention
	assert.Contains(t, resp.Checks[0].Details, "permission denied")
	assert.Equal(t, "fail", resp.Checks[1].Status) // PII
	assert.Contains(t, resp.Checks[1].Details, "timeout")
	assert.Equal(t, "warning", resp.Checks[2].Status) // HITL (uses false, not fail)
	assert.Equal(t, "fail", resp.Checks[3].Status)    // Audit
	assert.Equal(t, "warning", resp.Checks[4].Status)  // Decision Chain (uses false, not fail)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestValidateComplianceReadiness_MixedResults(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "healthcare-us"

	// checkRetentionCompliance: pass.
	// v9 Phase 8 B2: checkRetentionCompliance wraps in withOrgScope.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type, retention_days FROM audit_retention_config")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"data_type", "retention_days"}).
			AddRow("policy_violations", 2000))
	mock.ExpectCommit()

	// checkPIIPolicies: pass
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM policies")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// checkHITLConfiguration: fail (warning)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM hitl_config")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// checkAuditLogging: pass
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM audit_logs")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(10))

	// checkDecisionChainTracing: pass
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->>'decision_id' IS NOT NULL")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	resp, err := service.ValidateComplianceReadiness(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// HITL is warning, not fail, so Ready stays true
	assert.True(t, resp.Ready)
	assert.Equal(t, 90, resp.Score) // 100 - 10 (HITL warning)
	assert.Len(t, resp.Recommendations, 1)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// Utility Method Tests
// =============================================================================

func TestGetOrgName_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	// v9 Phase 8 B9 (migration 103): getOrgName wraps in withOrgScope
	// (BeginTx + set_config + Query + Commit). Same pattern as
	// getRetentionConfig's v9 Phase 8 B2 wrap below.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("travel-us").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs("travel-us").
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("AxonFlow India"))
	mock.ExpectCommit()

	name, err := service.getOrgName(ctx, "travel-us")
	require.NoError(t, err)
	assert.Equal(t, "AxonFlow India", name)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetOrgName_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	// v9 Phase 8 B9: both queries run inside the same withOrgScope tx —
	// first SELECT errors (no rows), fallback SELECT errors too. fn returns
	// the error → withOrgScope rolls back.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("unknown-tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs("unknown-tenant").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE id = $1")).
		WithArgs("unknown-tenant").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	name, err := service.getOrgName(ctx, "unknown-tenant")
	assert.Error(t, err)
	assert.Empty(t, name)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRetentionConfig_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	lastCleanup := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	// v9 Phase 8 B2: getRetentionConfig wraps in withOrgScope (BeginTx +
	// set_config + Query + Commit).
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("banking-india").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days, COALESCE(last_cleanup_at")).
		WithArgs("banking-india", "policy_violations").
		WillReturnRows(sqlmock.NewRows([]string{"retention_days", "last_cleanup"}).
			AddRow(1825, lastCleanup))
	mock.ExpectCommit()

	days, cleanup, err := service.getRetentionConfig(ctx, "banking-india", "policy_violations")
	require.NoError(t, err)
	assert.Equal(t, 1825, days)
	assert.Equal(t, lastCleanup, cleanup)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRetentionConfig_NoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	// v9 Phase 8 B2: getRetentionConfig wraps in withOrgScope. Query returns
	// ErrNoRows → withOrgScope returns the error → caller converts to default.
	// withOrgScope's `defer { if err != nil { tx.Rollback() } }` is what
	// actually rolls back the tx; sqlmock matches the explicit ExpectRollback
	// below to assert that rollback happened.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("banking-india").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days, COALESCE(last_cleanup_at")).
		WithArgs("banking-india", "llm_calls").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	days, cleanup, err := service.getRetentionConfig(ctx, "banking-india", "llm_calls")
	require.NoError(t, err)
	assert.Equal(t, 1825, days) // Default 5-year retention
	assert.True(t, cleanup.IsZero())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRetentionConfig_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	// v9 Phase 8 B2: withOrgScope opens tx + sets local + queries; on Query
	// error the helper triggers tx.Rollback().
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("banking-india").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT retention_days")).
		WithArgs("banking-india", "llm_calls").
		WillReturnError(fmt.Errorf("connection refused"))
	mock.ExpectRollback()

	_, _, err = service.getRetentionConfig(ctx, "banking-india", "llm_calls")
	assert.Error(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetDataTypeStats_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	now := time.Now().UTC()
	oldest := now.Add(-180 * 24 * time.Hour)

	mock.ExpectQuery("SELECT").
		WithArgs("travel-us").
		WillReturnRows(sqlmock.NewRows([]string{"oldest", "newest", "total"}).
			AddRow(oldest, now, int64(5000)))

	stats, err := service.getDataTypeStats(ctx, "travel-us", SEBIDataTypePolicyViolations)
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Equal(t, oldest.Unix(), stats.OldestRecord.Unix())
	assert.Equal(t, now.Unix(), stats.NewestRecord.Unix())
	assert.Equal(t, int64(5000), stats.TotalRecords)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetDataTypeStats_UnknownDataType(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	stats, err := service.getDataTypeStats(ctx, "banking-india", SEBIAuditDataType("unknown_type"))
	require.NoError(t, err)
	require.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.TotalRecords)
}

func TestGetDataTypeStats_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WithArgs("banking-india").
		WillReturnError(fmt.Errorf("timeout"))

	stats, err := service.getDataTypeStats(ctx, "banking-india", SEBIDataTypeLLMCalls)
	assert.Error(t, err)
	require.NotNil(t, stats)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetDataTypeStats_AllTableMappings(t *testing.T) {
	dataTypes := []SEBIAuditDataType{
		SEBIDataTypePolicyViolations,
		SEBIDataTypeLLMCalls,
		SEBIDataTypeDecisionChain,
		SEBIDataTypeHITLOversight,
		SEBIDataTypePIIRedactions,
	}

	for _, dt := range dataTypes {
		t.Run(string(dt), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			service := NewSEBIAuditExportService(db, nil)
			ctx := context.Background()

			mock.ExpectQuery("SELECT").
				WithArgs("banking-india").
				WillReturnRows(sqlmock.NewRows([]string{"oldest", "newest", "total"}).
					AddRow(nil, nil, int64(0)))

			stats, err := service.getDataTypeStats(ctx, "banking-india", dt)
			require.NoError(t, err)
			require.NotNil(t, stats)

			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// =============================================================================
// Compliance Check Helper Tests (via ValidateComplianceReadiness)
// =============================================================================

func TestCheckRetentionCompliance_MultipleNonCompliant(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	// v9 Phase 8 B2: checkRetentionCompliance wraps in withOrgScope.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("banking-india").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT data_type, retention_days FROM audit_retention_config")).
		WithArgs("banking-india").
		WillReturnRows(sqlmock.NewRows([]string{"data_type", "retention_days"}).
			AddRow("policy_violations", 365).
			AddRow("llm_calls", 730).
			AddRow("decision_chain", 1825)) // This one is compliant
	mock.ExpectCommit()

	ok, details := service.checkRetentionCompliance(ctx, "banking-india")
	assert.False(t, ok)
	assert.Contains(t, details, "policy_violations")
	assert.Contains(t, details, "llm_calls")
	assert.NotContains(t, details, "decision_chain")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckPIIPolicies_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM policies")).
		WithArgs("banking-india").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	ok, _ := service.checkPIIPolicies(ctx, "banking-india")
	assert.True(t, ok)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckPIIPolicies_NoPolicies(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM policies")).
		WithArgs("banking-india").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	ok, details := service.checkPIIPolicies(ctx, "banking-india")
	assert.False(t, ok)
	assert.Contains(t, details, "No PAN/Aadhaar")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckHITLConfiguration_NotConfigured(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM hitl_config")).
		WithArgs("banking-india").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	ok, details := service.checkHITLConfiguration(ctx, "banking-india")
	assert.False(t, ok)
	assert.Contains(t, details, "HITL not configured")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckAuditLogging_NoRecentLogs(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM audit_logs")).
		WithArgs("banking-india").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	ok, details := service.checkAuditLogging(ctx, "banking-india")
	assert.False(t, ok)
	assert.Contains(t, details, "No audit logs")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCheckDecisionChainTracing_NoRecentRecords(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("policy_details->>'decision_id' IS NOT NULL")).
		WithArgs("banking-india").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	ok, details := service.checkDecisionChainTracing(ctx, "banking-india")
	assert.False(t, ok)
	assert.Contains(t, details, "No decision chain records")

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestExportDecisionChain_DecisionRows_FromAuditLogs is a red-on-revert guard
// for #2588 + #2598: the per-decision audit rows must be read from the canonical
// audit_logs decision rows, not the dead decision_chain table. It programs ONLY
// the audit_logs exportDecisionChain query, so if the production code reverts to
// FROM decision_chain the mock has no matching expectation and the test fails.
// It asserts the policy_decision → SEBI outcome mapping across three decision
// rows (allow / needs_approval / deny) AND that the three rows — which share one
// correlation_id (a 3-stage llm → tool → agent request) — reconstruct into
// exactly ONE grouped chain with three ordered steps (#2598).
func TestExportDecisionChain_DecisionRows_FromAuditLogs(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	service := NewSEBIAuditExportService(db, nil)
	ctx := context.Background()
	tenantID := "banking-india"

	now := time.Now().UTC()
	startDate := now.Add(-24 * time.Hour)
	endDate := now

	// getOrgName (FORCE-RLS org scope)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT name FROM organizations WHERE org_id = $1")).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("Test Org"))
	mock.ExpectCommit()

	// exportDecisionChain: three audit_logs decision rows that share ONE
	// correlation_id (a 3-stage llm → tool → agent request), in chronological
	// order, with allow / needs_approval / deny. correlation_id is the last column.
	const sharedCorr = "trace-req-3stage"
	mock.ExpectQuery(regexp.QuoteMeta("policy_details->'policy_ids'->>0")).
		WithArgs(tenantID, startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "timestamp", "decision_type", "policy_decision",
			"model_id", "policies_evaluated", "policy_triggered", "response_time_ms",
			"correlation_id",
		}).
			AddRow("dc-1", "req-a", now, "llm", "allow",
				"gpt-4o", "[\"sys_pii_indonesia_ktp\"]", "sys_pii_indonesia_ktp", int64(12), sharedCorr).
			AddRow("dc-2", "req-b", now.Add(time.Second), "tool", "needs_approval",
				"", "[\"sebi_high_risk\"]", "sebi_high_risk", int64(8), sharedCorr).
			AddRow("dc-3", "req-c", now.Add(2*time.Second), "agent", "deny",
				"", "[\"sebi_block\"]", "sebi_block", int64(5), sharedCorr))

	req := &SEBIAuditExportRequest{
		StartDate: startDate,
		EndDate:   endDate,
		DataTypes: []SEBIAuditDataType{SEBIDataTypeDecisionChain},
	}

	resp, err := service.ExportAuditData(ctx, tenantID, req)
	require.NoError(t, err)
	require.NotNil(t, resp.Data)

	// Flat list + record count are unchanged (chronological, one row per decision).
	assert.Equal(t, 3, resp.Summary.RecordsByType[SEBIDataTypeDecisionChain])
	require.Len(t, resp.Data.DecisionChain, 3)
	assert.Equal(t, "approved", resp.Data.DecisionChain[0].DecisionOutcome)
	assert.Equal(t, "pending_review", resp.Data.DecisionChain[1].DecisionOutcome)
	assert.Equal(t, "blocked", resp.Data.DecisionChain[2].DecisionOutcome)

	// #2598: the three shared-correlation rows reconstruct into ONE grouped chain
	// with three steps in step order (llm → tool → agent).
	require.Len(t, resp.Data.DecisionChains, 1)
	chain := resp.Data.DecisionChains[0]
	assert.Equal(t, sharedCorr, chain.CorrelationID)
	assert.Equal(t, 3, chain.StepCount)
	require.Len(t, chain.Steps, 3)
	assert.Equal(t, "dc-1", chain.Steps[0].ID)
	assert.Equal(t, "dc-2", chain.Steps[1].ID)
	assert.Equal(t, "dc-3", chain.Steps[2].ID)

	require.NoError(t, mock.ExpectationsWereMet())
}
