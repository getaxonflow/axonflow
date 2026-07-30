// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/rls"
)

// #3103. Migration 301 switches RLS on for all seven rbi_* tables with a
// `FOR ALL USING (org_id = get_current_org_id())` policy, but this package
// never set app.current_org_id — so on an axonflow_app_role pool every read
// here returned SILENT ZERO ROWS and every write was refused. Every statement
// below therefore runs inside rls.WithOrgScope, which opens a transaction and
// SET LOCALs the GUC the policy reads. The hand-written `WHERE org_id = $n`
// predicates are KEPT: the wrap is a backstop, not a replacement.

// Validation-specific errors.
var (
	ErrValidationNotFound = errors.New("validation record not found")
)

// ModelValidationRepository provides data access for model validations.
type ModelValidationRepository interface {
	Create(ctx context.Context, validation *ModelValidation) error
	Get(ctx context.Context, orgID, id string) (*ModelValidation, error)
	List(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error)
	ListBySystem(ctx context.Context, orgID, systemID string) ([]*ModelValidation, error)
	Update(ctx context.Context, validation *ModelValidation) error
	Delete(ctx context.Context, orgID, id string) error
	GetLatestBySystem(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error)
}

// ListValidationsParams are the parameters for listing validations.
type ListValidationsParams struct {
	SystemID       string `form:"system_id"`
	ValidationType string `form:"validation_type"`
	ValidatorType  string `form:"validator_type"`
	Recommendation string `form:"recommendation"`
	StartDate      *time.Time
	EndDate        *time.Time
	Limit          int `form:"limit"`
	Offset         int `form:"offset"`
}

// PostgresModelValidationRepository implements ModelValidationRepository.
type PostgresModelValidationRepository struct {
	db *sql.DB
}

// NewPostgresModelValidationRepository creates a new repository.
func NewPostgresModelValidationRepository(db *sql.DB) *PostgresModelValidationRepository {
	return &PostgresModelValidationRepository{db: db}
}

// Create creates a new validation record.
func (r *PostgresModelValidationRepository) Create(ctx context.Context, validation *ModelValidation) error {
	if validation.ID == "" {
		validation.ID = uuid.New().String()
	}
	if validation.CreatedAt.IsZero() {
		validation.CreatedAt = time.Now().UTC()
	}
	validation.UpdatedAt = validation.CreatedAt

	// Serialize JSON fields
	findingsJSON, err := json.Marshal(validation.Findings)
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	datasetCharsJSON, err := json.Marshal(validation.DatasetCharacteristics)
	if err != nil {
		return fmt.Errorf("marshal dataset_characteristics: %w", err)
	}
	testScenariosJSON, err := json.Marshal(validation.TestScenarios)
	if err != nil {
		return fmt.Errorf("marshal test_scenarios: %w", err)
	}
	accuracyJSON, err := json.Marshal(validation.AccuracyMetrics)
	if err != nil {
		return fmt.Errorf("marshal accuracy_metrics: %w", err)
	}
	biasJSON, err := json.Marshal(validation.BiasAssessment)
	if err != nil {
		return fmt.Errorf("marshal bias_assessment: %w", err)
	}
	biasCatsJSON, err := json.Marshal(validation.BiasCategoriesTested)
	if err != nil {
		return fmt.Errorf("marshal bias_categories_tested: %w", err)
	}
	stressJSON, err := json.Marshal(validation.StressTestResults)
	if err != nil {
		return fmt.Errorf("marshal stress_test_results: %w", err)
	}

	query := `
		INSERT INTO rbi_model_validations (
			id, org_id, system_id, validation_type, validator_type,
			validator_name, validator_organization, validator_credentials,
			validation_date, validation_period_start, validation_period_end,
			dataset_description, dataset_size, dataset_characteristics,
			methodology, test_scenarios, findings, accuracy_metrics,
			bias_assessment, bias_categories_tested, stress_test_results,
			stress_test_passed, recommendation, conditions,
			next_review_date, remediation_required, remediation_deadline,
			report_file_path, report_file_checksum, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31
		)
	`

	err = rls.WithOrgScope(ctx, r.db, validation.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			validation.ID, validation.OrgID, validation.SystemID, validation.ValidationType, validation.ValidatorType,
			validation.ValidatorName, validation.ValidatorOrganization, validation.ValidatorCredentials,
			validation.ValidationDate, validation.ValidationPeriodStart, validation.ValidationPeriodEnd,
			validation.DatasetDescription, validation.DatasetSize, datasetCharsJSON,
			validation.Methodology, testScenariosJSON, findingsJSON, accuracyJSON,
			biasJSON, biasCatsJSON, stressJSON,
			validation.StressTestPassed, validation.Recommendation, validation.Conditions,
			validation.NextReviewDate, validation.RemediationRequired, validation.RemediationDeadline,
			validation.ReportFilePath, validation.ReportFileChecksum, validation.CreatedAt, validation.UpdatedAt,
		)
		return execErr
	})

	if err != nil {
		return fmt.Errorf("insert validation: %w", err)
	}

	return nil
}

// Get retrieves a validation by ID.
func (r *PostgresModelValidationRepository) Get(ctx context.Context, orgID, id string) (*ModelValidation, error) {
	query := `
		SELECT
			id, org_id, system_id, validation_type, validator_type,
			validator_name, validator_organization, validator_credentials,
			validation_date, validation_period_start, validation_period_end,
			dataset_description, dataset_size, dataset_characteristics,
			methodology, test_scenarios, findings, accuracy_metrics,
			bias_assessment, bias_categories_tested, stress_test_results,
			stress_test_passed, recommendation, conditions,
			next_review_date, remediation_required, remediation_deadline,
			report_file_path, report_file_checksum, created_at, updated_at
		FROM rbi_model_validations
		WHERE org_id = $1 AND id = $2
	`

	var v *ModelValidation
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var scanErr error
		v, scanErr = r.scanValidation(tx.QueryRowContext(ctx, query, orgID, id))
		return scanErr
	}); err != nil {
		return nil, err
	}
	return v, nil
}

// scanValidation scans a row into a ModelValidation.
func (r *PostgresModelValidationRepository) scanValidation(row *sql.Row) (*ModelValidation, error) {
	var v ModelValidation
	var findingsJSON, datasetCharsJSON, testScenariosJSON []byte
	var accuracyJSON, biasJSON, biasCatsJSON, stressJSON []byte
	var validatorOrg, validatorCreds, datasetDesc, methodology, conditions sql.NullString
	var reportPath, reportChecksum sql.NullString
	var periodStart, periodEnd, nextReview, remDeadline sql.NullTime
	var datasetSize sql.NullInt32
	var stressTestPassed sql.NullBool

	err := row.Scan(
		&v.ID, &v.OrgID, &v.SystemID, &v.ValidationType, &v.ValidatorType,
		&v.ValidatorName, &validatorOrg, &validatorCreds,
		&v.ValidationDate, &periodStart, &periodEnd,
		&datasetDesc, &datasetSize, &datasetCharsJSON,
		&methodology, &testScenariosJSON, &findingsJSON, &accuracyJSON,
		&biasJSON, &biasCatsJSON, &stressJSON,
		&stressTestPassed, &v.Recommendation, &conditions,
		&nextReview, &v.RemediationRequired, &remDeadline,
		&reportPath, &reportChecksum, &v.CreatedAt, &v.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrValidationNotFound
		}
		return nil, fmt.Errorf("scan validation: %w", err)
	}

	// Handle nullable fields
	if validatorOrg.Valid {
		v.ValidatorOrganization = validatorOrg.String
	}
	if validatorCreds.Valid {
		v.ValidatorCredentials = validatorCreds.String
	}
	if datasetDesc.Valid {
		v.DatasetDescription = datasetDesc.String
	}
	if datasetSize.Valid {
		v.DatasetSize = int(datasetSize.Int32)
	}
	if methodology.Valid {
		v.Methodology = methodology.String
	}
	if conditions.Valid {
		v.Conditions = conditions.String
	}
	if reportPath.Valid {
		v.ReportFilePath = reportPath.String
	}
	if reportChecksum.Valid {
		v.ReportFileChecksum = reportChecksum.String
	}
	if periodStart.Valid {
		v.ValidationPeriodStart = &periodStart.Time
	}
	if periodEnd.Valid {
		v.ValidationPeriodEnd = &periodEnd.Time
	}
	if nextReview.Valid {
		v.NextReviewDate = &nextReview.Time
	}
	if remDeadline.Valid {
		v.RemediationDeadline = &remDeadline.Time
	}
	if stressTestPassed.Valid {
		v.StressTestPassed = &stressTestPassed.Bool
	}

	// Parse JSON fields
	if len(findingsJSON) > 0 {
		if err := json.Unmarshal(findingsJSON, &v.Findings); err != nil {
			return nil, fmt.Errorf("unmarshal findings: %w", err)
		}
	}
	if len(datasetCharsJSON) > 0 {
		if err := json.Unmarshal(datasetCharsJSON, &v.DatasetCharacteristics); err != nil {
			return nil, fmt.Errorf("unmarshal dataset_characteristics: %w", err)
		}
	}
	if len(testScenariosJSON) > 0 {
		if err := json.Unmarshal(testScenariosJSON, &v.TestScenarios); err != nil {
			return nil, fmt.Errorf("unmarshal test_scenarios: %w", err)
		}
	}
	if len(accuracyJSON) > 0 {
		if err := json.Unmarshal(accuracyJSON, &v.AccuracyMetrics); err != nil {
			return nil, fmt.Errorf("unmarshal accuracy_metrics: %w", err)
		}
	}
	if len(biasJSON) > 0 {
		if err := json.Unmarshal(biasJSON, &v.BiasAssessment); err != nil {
			return nil, fmt.Errorf("unmarshal bias_assessment: %w", err)
		}
	}
	if len(biasCatsJSON) > 0 {
		if err := json.Unmarshal(biasCatsJSON, &v.BiasCategoriesTested); err != nil {
			return nil, fmt.Errorf("unmarshal bias_categories_tested: %w", err)
		}
	}
	if len(stressJSON) > 0 {
		if err := json.Unmarshal(stressJSON, &v.StressTestResults); err != nil {
			return nil, fmt.Errorf("unmarshal stress_test_results: %w", err)
		}
	}

	return &v, nil
}

// List retrieves validations with optional filtering.
func (r *PostgresModelValidationRepository) List(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error) {
	if params == nil {
		params = &ListValidationsParams{}
	}
	if params.Limit <= 0 {
		params.Limit = 20
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	baseQuery := " FROM rbi_model_validations WHERE org_id = $1"
	args := []interface{}{orgID}
	argIdx := 2

	if params.SystemID != "" {
		baseQuery += fmt.Sprintf(" AND system_id = $%d", argIdx)
		args = append(args, params.SystemID)
		argIdx++
	}
	if params.ValidationType != "" {
		baseQuery += fmt.Sprintf(" AND validation_type = $%d", argIdx)
		args = append(args, params.ValidationType)
		argIdx++
	}
	if params.ValidatorType != "" {
		baseQuery += fmt.Sprintf(" AND validator_type = $%d", argIdx)
		args = append(args, params.ValidatorType)
		argIdx++
	}
	if params.Recommendation != "" {
		baseQuery += fmt.Sprintf(" AND recommendation = $%d", argIdx)
		args = append(args, params.Recommendation)
		argIdx++
	}
	if params.StartDate != nil {
		baseQuery += fmt.Sprintf(" AND validation_date >= $%d", argIdx)
		args = append(args, *params.StartDate)
		argIdx++
	}
	if params.EndDate != nil {
		baseQuery += fmt.Sprintf(" AND validation_date <= $%d", argIdx)
		args = append(args, *params.EndDate)
		argIdx++
	}

	// Count total
	countQuery := "SELECT COUNT(*)" + baseQuery

	// Get paginated results
	selectQuery := `
		SELECT
			id, org_id, system_id, validation_type, validator_type,
			validator_name, validator_organization, validator_credentials,
			validation_date, validation_period_start, validation_period_end,
			dataset_description, dataset_size, dataset_characteristics,
			methodology, test_scenarios, findings, accuracy_metrics,
			bias_assessment, bias_categories_tested, stress_test_results,
			stress_test_passed, recommendation, conditions,
			next_review_date, remediation_required, remediation_deadline,
			report_file_path, report_file_checksum, created_at, updated_at
	` + baseQuery + fmt.Sprintf(" ORDER BY validation_date DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	countArgs := args
	args = append(append([]interface{}{}, args...), params.Limit, params.Offset)

	// One wrap for BOTH statements: the count and the page are separate call
	// sites and each had to be scoped, and sharing the transaction also makes
	// total and rows a consistent snapshot.
	var validations []*ModelValidation
	var total int
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return fmt.Errorf("count validations: %w", err)
		}

		rows, err := tx.QueryContext(ctx, selectQuery, args...)
		if err != nil {
			return fmt.Errorf("query validations: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			v, scanErr := r.scanValidationRow(rows)
			if scanErr != nil {
				return scanErr
			}
			validations = append(validations, v)
		}

		return rows.Err()
	}); err != nil {
		return nil, 0, err
	}

	return validations, total, nil
}

// scanValidationRow scans a row from rows iterator.
func (r *PostgresModelValidationRepository) scanValidationRow(rows *sql.Rows) (*ModelValidation, error) {
	var v ModelValidation
	var findingsJSON, datasetCharsJSON, testScenariosJSON []byte
	var accuracyJSON, biasJSON, biasCatsJSON, stressJSON []byte
	var validatorOrg, validatorCreds, datasetDesc, methodology, conditions sql.NullString
	var reportPath, reportChecksum sql.NullString
	var periodStart, periodEnd, nextReview, remDeadline sql.NullTime
	var datasetSize sql.NullInt32
	var stressTestPassed sql.NullBool

	err := rows.Scan(
		&v.ID, &v.OrgID, &v.SystemID, &v.ValidationType, &v.ValidatorType,
		&v.ValidatorName, &validatorOrg, &validatorCreds,
		&v.ValidationDate, &periodStart, &periodEnd,
		&datasetDesc, &datasetSize, &datasetCharsJSON,
		&methodology, &testScenariosJSON, &findingsJSON, &accuracyJSON,
		&biasJSON, &biasCatsJSON, &stressJSON,
		&stressTestPassed, &v.Recommendation, &conditions,
		&nextReview, &v.RemediationRequired, &remDeadline,
		&reportPath, &reportChecksum, &v.CreatedAt, &v.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("scan validation row: %w", err)
	}

	// Handle nullable fields (same as scanValidation)
	if validatorOrg.Valid {
		v.ValidatorOrganization = validatorOrg.String
	}
	if validatorCreds.Valid {
		v.ValidatorCredentials = validatorCreds.String
	}
	if datasetDesc.Valid {
		v.DatasetDescription = datasetDesc.String
	}
	if datasetSize.Valid {
		v.DatasetSize = int(datasetSize.Int32)
	}
	if methodology.Valid {
		v.Methodology = methodology.String
	}
	if conditions.Valid {
		v.Conditions = conditions.String
	}
	if reportPath.Valid {
		v.ReportFilePath = reportPath.String
	}
	if reportChecksum.Valid {
		v.ReportFileChecksum = reportChecksum.String
	}
	if periodStart.Valid {
		v.ValidationPeriodStart = &periodStart.Time
	}
	if periodEnd.Valid {
		v.ValidationPeriodEnd = &periodEnd.Time
	}
	if nextReview.Valid {
		v.NextReviewDate = &nextReview.Time
	}
	if remDeadline.Valid {
		v.RemediationDeadline = &remDeadline.Time
	}
	if stressTestPassed.Valid {
		v.StressTestPassed = &stressTestPassed.Bool
	}

	// Parse JSON fields
	if len(findingsJSON) > 0 {
		json.Unmarshal(findingsJSON, &v.Findings)
	}
	if len(datasetCharsJSON) > 0 {
		json.Unmarshal(datasetCharsJSON, &v.DatasetCharacteristics)
	}
	if len(testScenariosJSON) > 0 {
		json.Unmarshal(testScenariosJSON, &v.TestScenarios)
	}
	if len(accuracyJSON) > 0 {
		json.Unmarshal(accuracyJSON, &v.AccuracyMetrics)
	}
	if len(biasJSON) > 0 {
		json.Unmarshal(biasJSON, &v.BiasAssessment)
	}
	if len(biasCatsJSON) > 0 {
		json.Unmarshal(biasCatsJSON, &v.BiasCategoriesTested)
	}
	if len(stressJSON) > 0 {
		json.Unmarshal(stressJSON, &v.StressTestResults)
	}

	return &v, nil
}

// ListBySystem retrieves all validations for a system.
func (r *PostgresModelValidationRepository) ListBySystem(ctx context.Context, orgID, systemID string) ([]*ModelValidation, error) {
	validations, _, err := r.List(ctx, orgID, &ListValidationsParams{
		SystemID: systemID,
		Limit:    100,
	})
	return validations, err
}

// Update updates a validation record.
func (r *PostgresModelValidationRepository) Update(ctx context.Context, validation *ModelValidation) error {
	validation.UpdatedAt = time.Now().UTC()

	findingsJSON, _ := json.Marshal(validation.Findings)
	datasetCharsJSON, _ := json.Marshal(validation.DatasetCharacteristics)
	testScenariosJSON, _ := json.Marshal(validation.TestScenarios)
	accuracyJSON, _ := json.Marshal(validation.AccuracyMetrics)
	biasJSON, _ := json.Marshal(validation.BiasAssessment)
	biasCatsJSON, _ := json.Marshal(validation.BiasCategoriesTested)
	stressJSON, _ := json.Marshal(validation.StressTestResults)

	query := `
		UPDATE rbi_model_validations SET
			validation_type = $1, validator_type = $2,
			validator_name = $3, validator_organization = $4, validator_credentials = $5,
			validation_date = $6, validation_period_start = $7, validation_period_end = $8,
			dataset_description = $9, dataset_size = $10, dataset_characteristics = $11,
			methodology = $12, test_scenarios = $13, findings = $14, accuracy_metrics = $15,
			bias_assessment = $16, bias_categories_tested = $17, stress_test_results = $18,
			stress_test_passed = $19, recommendation = $20, conditions = $21,
			next_review_date = $22, remediation_required = $23, remediation_deadline = $24,
			report_file_path = $25, report_file_checksum = $26, updated_at = $27
		WHERE org_id = $28 AND id = $29
	`

	var result sql.Result
	err := rls.WithOrgScope(ctx, r.db, validation.OrgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query,
			validation.ValidationType, validation.ValidatorType,
			validation.ValidatorName, validation.ValidatorOrganization, validation.ValidatorCredentials,
			validation.ValidationDate, validation.ValidationPeriodStart, validation.ValidationPeriodEnd,
			validation.DatasetDescription, validation.DatasetSize, datasetCharsJSON,
			validation.Methodology, testScenariosJSON, findingsJSON, accuracyJSON,
			biasJSON, biasCatsJSON, stressJSON,
			validation.StressTestPassed, validation.Recommendation, validation.Conditions,
			validation.NextReviewDate, validation.RemediationRequired, validation.RemediationDeadline,
			validation.ReportFilePath, validation.ReportFileChecksum, validation.UpdatedAt,
			validation.OrgID, validation.ID,
		)
		return execErr
	})

	if err != nil {
		return fmt.Errorf("update validation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrValidationNotFound
	}

	return nil
}

// Delete deletes a validation record.
func (r *PostgresModelValidationRepository) Delete(ctx context.Context, orgID, id string) error {
	var result sql.Result
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx,
			"DELETE FROM rbi_model_validations WHERE org_id = $1 AND id = $2",
			orgID, id,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("delete validation: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrValidationNotFound
	}

	return nil
}

// GetLatestBySystem gets the latest validation of a specific type for a system.
func (r *PostgresModelValidationRepository) GetLatestBySystem(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error) {
	query := `
		SELECT
			id, org_id, system_id, validation_type, validator_type,
			validator_name, validator_organization, validator_credentials,
			validation_date, validation_period_start, validation_period_end,
			dataset_description, dataset_size, dataset_characteristics,
			methodology, test_scenarios, findings, accuracy_metrics,
			bias_assessment, bias_categories_tested, stress_test_results,
			stress_test_passed, recommendation, conditions,
			next_review_date, remediation_required, remediation_deadline,
			report_file_path, report_file_checksum, created_at, updated_at
		FROM rbi_model_validations
		WHERE org_id = $1 AND system_id = $2
	`
	args := []interface{}{orgID, systemID}

	if validationType != "" {
		query += " AND validation_type = $3"
		args = append(args, validationType)
	}

	query += " ORDER BY validation_date DESC LIMIT 1"

	var v ModelValidation
	var findingsJSON, datasetCharsJSON, testScenariosJSON []byte
	var accuracyJSON, biasJSON, biasCatsJSON, stressJSON []byte
	var validatorOrg, validatorCreds, datasetDesc, methodology, conditions sql.NullString
	var reportPath, reportChecksum sql.NullString
	var periodStart, periodEnd, nextReview, remDeadline sql.NullTime
	var datasetSize sql.NullInt32
	var stressTestPassed sql.NullBool

	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, args...).Scan(
			&v.ID, &v.OrgID, &v.SystemID, &v.ValidationType, &v.ValidatorType,
			&v.ValidatorName, &validatorOrg, &validatorCreds,
			&v.ValidationDate, &periodStart, &periodEnd,
			&datasetDesc, &datasetSize, &datasetCharsJSON,
			&methodology, &testScenariosJSON, &findingsJSON, &accuracyJSON,
			&biasJSON, &biasCatsJSON, &stressJSON,
			&stressTestPassed, &v.Recommendation, &conditions,
			&nextReview, &v.RemediationRequired, &remDeadline,
			&reportPath, &reportChecksum, &v.CreatedAt, &v.UpdatedAt,
		)
	})

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrValidationNotFound
		}
		return nil, fmt.Errorf("get latest validation: %w", err)
	}

	// Handle nullable fields
	if validatorOrg.Valid {
		v.ValidatorOrganization = validatorOrg.String
	}
	if validatorCreds.Valid {
		v.ValidatorCredentials = validatorCreds.String
	}
	if datasetDesc.Valid {
		v.DatasetDescription = datasetDesc.String
	}
	if datasetSize.Valid {
		v.DatasetSize = int(datasetSize.Int32)
	}
	if methodology.Valid {
		v.Methodology = methodology.String
	}
	if conditions.Valid {
		v.Conditions = conditions.String
	}
	if reportPath.Valid {
		v.ReportFilePath = reportPath.String
	}
	if reportChecksum.Valid {
		v.ReportFileChecksum = reportChecksum.String
	}
	if periodStart.Valid {
		v.ValidationPeriodStart = &periodStart.Time
	}
	if periodEnd.Valid {
		v.ValidationPeriodEnd = &periodEnd.Time
	}
	if nextReview.Valid {
		v.NextReviewDate = &nextReview.Time
	}
	if remDeadline.Valid {
		v.RemediationDeadline = &remDeadline.Time
	}
	if stressTestPassed.Valid {
		v.StressTestPassed = &stressTestPassed.Bool
	}

	// Parse JSON
	if len(findingsJSON) > 0 {
		json.Unmarshal(findingsJSON, &v.Findings)
	}
	if len(datasetCharsJSON) > 0 {
		json.Unmarshal(datasetCharsJSON, &v.DatasetCharacteristics)
	}
	if len(testScenariosJSON) > 0 {
		json.Unmarshal(testScenariosJSON, &v.TestScenarios)
	}
	if len(accuracyJSON) > 0 {
		json.Unmarshal(accuracyJSON, &v.AccuracyMetrics)
	}
	if len(biasJSON) > 0 {
		json.Unmarshal(biasJSON, &v.BiasAssessment)
	}
	if len(biasCatsJSON) > 0 {
		json.Unmarshal(biasCatsJSON, &v.BiasCategoriesTested)
	}
	if len(stressJSON) > 0 {
		json.Unmarshal(stressJSON, &v.StressTestResults)
	}

	return &v, nil
}

// Ensure PostgresModelValidationRepository implements the interface.
var _ ModelValidationRepository = (*PostgresModelValidationRepository)(nil)

// Ensure strings import is used.
var _ = strings.TrimSpace
