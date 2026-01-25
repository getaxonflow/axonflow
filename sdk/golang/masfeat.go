package axonflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// ===========================================================================
// MAS FEAT Types
// ===========================================================================

// MaterialityClassification represents the materiality level of an AI system
type MaterialityClassification string

const (
	MaterialityHigh   MaterialityClassification = "high"
	MaterialityMedium MaterialityClassification = "medium"
	MaterialityLow    MaterialityClassification = "low"
)

// SystemStatus represents the status of an AI system
type SystemStatus string

const (
	SystemStatusDraft     SystemStatus = "draft"
	SystemStatusActive    SystemStatus = "active"
	SystemStatusSuspended SystemStatus = "suspended"
	SystemStatusRetired   SystemStatus = "retired"
)

// FEATAssessmentStatus represents the status of a FEAT assessment
type FEATAssessmentStatus string

const (
	FEATStatusPending    FEATAssessmentStatus = "pending"
	FEATStatusInProgress FEATAssessmentStatus = "in_progress"
	FEATStatusCompleted  FEATAssessmentStatus = "completed"
	FEATStatusApproved   FEATAssessmentStatus = "approved"
	FEATStatusRejected   FEATAssessmentStatus = "rejected"
)

// KillSwitchStatus represents the status of a kill switch
type KillSwitchStatus string

const (
	KillSwitchEnabled   KillSwitchStatus = "enabled"
	KillSwitchDisabled  KillSwitchStatus = "disabled"
	KillSwitchTriggered KillSwitchStatus = "triggered"
)

// AISystemUseCase represents the use case category
type AISystemUseCase string

const (
	UseCaseCreditScoring         AISystemUseCase = "credit_scoring"
	UseCaseRoboAdvisory          AISystemUseCase = "robo_advisory"
	UseCaseInsuranceUnderwriting AISystemUseCase = "insurance_underwriting"
	UseCaseTradingAlgorithm      AISystemUseCase = "trading_algorithm"
	UseCaseAMLCFT                AISystemUseCase = "aml_cft"
	UseCaseCustomerService       AISystemUseCase = "customer_service"
	UseCaseFraudDetection        AISystemUseCase = "fraud_detection"
	UseCaseOther                 AISystemUseCase = "other"
)

// ===========================================================================
// AI System Registry Types
// ===========================================================================

// RegisterSystemRequest represents a request to register an AI system
type RegisterSystemRequest struct {
	SystemID        string                 `json:"system_id"`
	SystemName      string                 `json:"system_name"`
	Description     string                 `json:"description,omitempty"`
	UseCase         AISystemUseCase        `json:"use_case"`
	OwnerTeam       string                 `json:"owner_team"`
	TechnicalOwner  string                 `json:"technical_owner,omitempty"`
	BusinessOwner   string                 `json:"business_owner,omitempty"`
	CustomerImpact  int                    `json:"customer_impact"`
	ModelComplexity int                    `json:"model_complexity"`
	HumanReliance   int                    `json:"human_reliance"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateSystemRequest represents a request to update an AI system
type UpdateSystemRequest struct {
	SystemName      *string                `json:"system_name,omitempty"`
	Description     *string                `json:"description,omitempty"`
	OwnerTeam       *string                `json:"owner_team,omitempty"`
	TechnicalOwner  *string                `json:"technical_owner,omitempty"`
	BusinessOwner   *string                `json:"business_owner,omitempty"`
	CustomerImpact  *int                   `json:"customer_impact,omitempty"`
	ModelComplexity *int                   `json:"model_complexity,omitempty"`
	HumanReliance   *int                   `json:"human_reliance,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// AISystemRegistry represents an AI system in the registry
type AISystemRegistry struct {
	ID              string                    `json:"id"`
	OrgID           string                    `json:"org_id"`
	SystemID        string                    `json:"system_id"`
	SystemName      string                    `json:"system_name"`
	Description     string                    `json:"description,omitempty"`
	UseCase         AISystemUseCase           `json:"use_case"`
	OwnerTeam       string                    `json:"owner_team"`
	TechnicalOwner  string                    `json:"technical_owner,omitempty"`
	BusinessOwner   string                    `json:"business_owner,omitempty"`
	CustomerImpact  int                       `json:"customer_impact"`
	ModelComplexity int                       `json:"model_complexity"`
	HumanReliance   int                       `json:"human_reliance"`
	Materiality     MaterialityClassification `json:"materiality"`
	Status          SystemStatus              `json:"status"`
	Metadata        map[string]interface{}    `json:"metadata,omitempty"`
	CreatedAt       time.Time                 `json:"created_at"`
	UpdatedAt       time.Time                 `json:"updated_at"`
	CreatedBy       string                    `json:"created_by,omitempty"`
}

// RegistrySummary represents summary statistics for the registry
type RegistrySummary struct {
	TotalSystems          int            `json:"total_systems"`
	ActiveSystems         int            `json:"active_systems"`
	HighMaterialityCount  int            `json:"high_materiality_count"`
	MediumMaterialityCount int           `json:"medium_materiality_count"`
	LowMaterialityCount   int            `json:"low_materiality_count"`
	ByUseCase             map[string]int `json:"by_use_case"`
	ByStatus              map[string]int `json:"by_status"`
}

// ListSystemsOptions represents options for listing AI systems
type ListSystemsOptions struct {
	Status      *SystemStatus
	UseCase     *AISystemUseCase
	Materiality *MaterialityClassification
	Limit       int
	Offset      int
}

// ===========================================================================
// FEAT Assessment Types
// ===========================================================================

// CreateAssessmentRequest represents a request to create a FEAT assessment
type CreateAssessmentRequest struct {
	SystemID       string   `json:"system_id"`
	AssessmentType string   `json:"assessment_type,omitempty"`
	Assessors      []string `json:"assessors,omitempty"`
}

// UpdateAssessmentRequest represents a request to update a FEAT assessment
type UpdateAssessmentRequest struct {
	FairnessScore         *int                   `json:"fairness_score,omitempty"`
	EthicsScore           *int                   `json:"ethics_score,omitempty"`
	AccountabilityScore   *int                   `json:"accountability_score,omitempty"`
	TransparencyScore     *int                   `json:"transparency_score,omitempty"`
	FairnessDetails       map[string]interface{} `json:"fairness_details,omitempty"`
	EthicsDetails         map[string]interface{} `json:"ethics_details,omitempty"`
	AccountabilityDetails map[string]interface{} `json:"accountability_details,omitempty"`
	TransparencyDetails   map[string]interface{} `json:"transparency_details,omitempty"`
	Findings              []string               `json:"findings,omitempty"`
	Recommendations       []string               `json:"recommendations,omitempty"`
	Assessors             []string               `json:"assessors,omitempty"`
}

// FEATAssessment represents a FEAT assessment
type FEATAssessment struct {
	ID                    string                 `json:"id"`
	OrgID                 string                 `json:"org_id"`
	SystemID              string                 `json:"system_id"`
	AssessmentType        string                 `json:"assessment_type"`
	Status                FEATAssessmentStatus   `json:"status"`
	AssessmentDate        time.Time              `json:"assessment_date"`
	ValidUntil            *time.Time             `json:"valid_until,omitempty"`
	FairnessScore         *int                   `json:"fairness_score,omitempty"`
	EthicsScore           *int                   `json:"ethics_score,omitempty"`
	AccountabilityScore   *int                   `json:"accountability_score,omitempty"`
	TransparencyScore     *int                   `json:"transparency_score,omitempty"`
	OverallScore          *int                   `json:"overall_score,omitempty"`
	FairnessDetails       map[string]interface{} `json:"fairness_details,omitempty"`
	EthicsDetails         map[string]interface{} `json:"ethics_details,omitempty"`
	AccountabilityDetails map[string]interface{} `json:"accountability_details,omitempty"`
	TransparencyDetails   map[string]interface{} `json:"transparency_details,omitempty"`
	Findings              []string               `json:"findings,omitempty"`
	Recommendations       []string               `json:"recommendations,omitempty"`
	Assessors             []string               `json:"assessors,omitempty"`
	ApprovedBy            string                 `json:"approved_by,omitempty"`
	ApprovedAt            *time.Time             `json:"approved_at,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	CreatedBy             string                 `json:"created_by,omitempty"`
}

// ApproveAssessmentRequest represents a request to approve an assessment
type ApproveAssessmentRequest struct {
	ApprovedBy string `json:"approved_by"`
	Comments   string `json:"comments,omitempty"`
}

// RejectAssessmentRequest represents a request to reject an assessment
type RejectAssessmentRequest struct {
	RejectedBy string `json:"rejected_by"`
	Reason     string `json:"reason"`
}

// ListAssessmentsOptions represents options for listing assessments
type ListAssessmentsOptions struct {
	SystemID *string
	Status   *FEATAssessmentStatus
	Limit    int
	Offset   int
}

// ===========================================================================
// Kill Switch Types
// ===========================================================================

// KillSwitch represents a kill switch configuration
type KillSwitch struct {
	ID                 string           `json:"id"`
	OrgID              string           `json:"org_id"`
	SystemID           string           `json:"system_id"`
	Status             KillSwitchStatus `json:"status"`
	AccuracyThreshold  *float64         `json:"accuracy_threshold,omitempty"`
	BiasThreshold      *float64         `json:"bias_threshold,omitempty"`
	ErrorRateThreshold *float64         `json:"error_rate_threshold,omitempty"`
	AutoTriggerEnabled bool             `json:"auto_trigger_enabled"`
	TriggeredAt        *time.Time       `json:"triggered_at,omitempty"`
	TriggeredBy        string           `json:"triggered_by,omitempty"`
	TriggeredReason    string           `json:"triggered_reason,omitempty"`
	RestoredAt         *time.Time       `json:"restored_at,omitempty"`
	RestoredBy         string           `json:"restored_by,omitempty"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
}

// ConfigureKillSwitchRequest represents a request to configure a kill switch
type ConfigureKillSwitchRequest struct {
	AccuracyThreshold  *float64 `json:"accuracy_threshold,omitempty"`
	BiasThreshold      *float64 `json:"bias_threshold,omitempty"`
	ErrorRateThreshold *float64 `json:"error_rate_threshold,omitempty"`
	AutoTriggerEnabled *bool    `json:"auto_trigger_enabled,omitempty"`
}

// CheckKillSwitchRequest represents a request to check kill switch metrics
type CheckKillSwitchRequest struct {
	Accuracy  float64  `json:"accuracy"`
	BiasScore *float64 `json:"bias_score,omitempty"`
	ErrorRate *float64 `json:"error_rate,omitempty"`
}

// TriggerKillSwitchRequest represents a request to trigger a kill switch
type TriggerKillSwitchRequest struct {
	Reason      string `json:"reason"`
	TriggeredBy string `json:"triggered_by,omitempty"`
}

// RestoreKillSwitchRequest represents a request to restore a kill switch
type RestoreKillSwitchRequest struct {
	Reason     string `json:"reason"`
	RestoredBy string `json:"restored_by,omitempty"`
}

// KillSwitchEvent represents a kill switch event
type KillSwitchEvent struct {
	ID           string                 `json:"id"`
	KillSwitchID string                 `json:"kill_switch_id"`
	EventType    string                 `json:"event_type"`
	EventData    map[string]interface{} `json:"event_data,omitempty"`
	CreatedBy    string                 `json:"created_by,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// ===========================================================================
// MAS FEAT Registry Methods
// ===========================================================================

// MASFEATRegisterSystem registers a new AI system in the MAS FEAT registry
func (c *AxonFlowClient) MASFEATRegisterSystem(req *RegisterSystemRequest) (*AISystemRegistry, error) {
	url := c.config.AgentURL + "/api/v1/masfeat/registry"

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register system request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create register system request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("register system request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read register system response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result AISystemRegistry
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal register system response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] System registered: %s materiality=%s", result.SystemID, result.Materiality)
	}

	return &result, nil
}

// MASFEATGetSystem retrieves an AI system from the registry
func (c *AxonFlowClient) MASFEATGetSystem(systemID string) (*AISystemRegistry, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/registry/%s", c.config.AgentURL, systemID)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get system request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get system request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read get system response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result AISystemRegistry
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal get system response: %w", err)
	}

	return &result, nil
}

// MASFEATUpdateSystem updates an AI system in the registry
func (c *AxonFlowClient) MASFEATUpdateSystem(systemID string, req *UpdateSystemRequest) (*AISystemRegistry, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/registry/%s", c.config.AgentURL, systemID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update system request: %w", err)
	}

	httpReq, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create update system request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("update system request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read update system response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result AISystemRegistry
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal update system response: %w", err)
	}

	return &result, nil
}

// MASFEATListSystems lists AI systems in the registry
func (c *AxonFlowClient) MASFEATListSystems(opts *ListSystemsOptions) ([]AISystemRegistry, error) {
	url := c.config.AgentURL + "/api/v1/masfeat/registry"
	if opts != nil {
		params := "?"
		if opts.Status != nil {
			params += fmt.Sprintf("status=%s&", *opts.Status)
		}
		if opts.UseCase != nil {
			params += fmt.Sprintf("use_case=%s&", *opts.UseCase)
		}
		if opts.Materiality != nil {
			params += fmt.Sprintf("materiality=%s&", *opts.Materiality)
		}
		if opts.Limit > 0 {
			params += fmt.Sprintf("limit=%d&", opts.Limit)
		}
		if opts.Offset > 0 {
			params += fmt.Sprintf("offset=%d&", opts.Offset)
		}
		if len(params) > 1 {
			url += params[:len(params)-1]
		}
	}

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list systems request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("list systems request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read list systems response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result []AISystemRegistry
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal list systems response: %w", err)
	}

	return result, nil
}

// MASFEATActivateSystem activates an AI system
func (c *AxonFlowClient) MASFEATActivateSystem(systemID string) (*AISystemRegistry, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/registry/%s/activate", c.config.AgentURL, systemID)

	httpReq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create activate system request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("activate system request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read activate system response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result AISystemRegistry
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal activate system response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] System activated: %s", systemID)
	}

	return &result, nil
}

// MASFEATRetireSystem retires an AI system
func (c *AxonFlowClient) MASFEATRetireSystem(systemID string) (*AISystemRegistry, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/registry/%s", c.config.AgentURL, systemID)

	httpReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create retire system request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("retire system request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read retire system response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result AISystemRegistry
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal retire system response: %w", err)
	}

	return &result, nil
}

// MASFEATGetRegistrySummary gets registry summary statistics
func (c *AxonFlowClient) MASFEATGetRegistrySummary() (*RegistrySummary, error) {
	url := c.config.AgentURL + "/api/v1/masfeat/registry/summary"

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get registry summary request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get registry summary request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read registry summary response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result RegistrySummary
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal registry summary response: %w", err)
	}

	return &result, nil
}

// ===========================================================================
// MAS FEAT Assessment Methods
// ===========================================================================

// MASFEATCreateAssessment creates a new FEAT assessment
func (c *AxonFlowClient) MASFEATCreateAssessment(req *CreateAssessmentRequest) (*FEATAssessment, error) {
	url := c.config.AgentURL + "/api/v1/masfeat/assessments"

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal create assessment request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create assessment request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("create assessment request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read create assessment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result FEATAssessment
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal create assessment response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] Assessment created: %s for system %s", result.ID, result.SystemID)
	}

	return &result, nil
}

// MASFEATGetAssessment retrieves a FEAT assessment
func (c *AxonFlowClient) MASFEATGetAssessment(assessmentID string) (*FEATAssessment, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/assessments/%s", c.config.AgentURL, assessmentID)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get assessment request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get assessment request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read get assessment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result FEATAssessment
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal get assessment response: %w", err)
	}

	return &result, nil
}

// MASFEATUpdateAssessment updates a FEAT assessment
func (c *AxonFlowClient) MASFEATUpdateAssessment(assessmentID string, req *UpdateAssessmentRequest) (*FEATAssessment, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/assessments/%s", c.config.AgentURL, assessmentID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update assessment request: %w", err)
	}

	httpReq, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create update assessment request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("update assessment request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read update assessment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result FEATAssessment
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal update assessment response: %w", err)
	}

	return &result, nil
}

// MASFEATListAssessments lists FEAT assessments
func (c *AxonFlowClient) MASFEATListAssessments(opts *ListAssessmentsOptions) ([]FEATAssessment, error) {
	url := c.config.AgentURL + "/api/v1/masfeat/assessments"
	if opts != nil {
		params := "?"
		if opts.SystemID != nil {
			params += fmt.Sprintf("system_id=%s&", *opts.SystemID)
		}
		if opts.Status != nil {
			params += fmt.Sprintf("status=%s&", *opts.Status)
		}
		if opts.Limit > 0 {
			params += fmt.Sprintf("limit=%d&", opts.Limit)
		}
		if opts.Offset > 0 {
			params += fmt.Sprintf("offset=%d&", opts.Offset)
		}
		if len(params) > 1 {
			url += params[:len(params)-1]
		}
	}

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list assessments request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("list assessments request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read list assessments response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result []FEATAssessment
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal list assessments response: %w", err)
	}

	return result, nil
}

// MASFEATSubmitAssessment submits an assessment for review
func (c *AxonFlowClient) MASFEATSubmitAssessment(assessmentID string) (*FEATAssessment, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/assessments/%s/submit", c.config.AgentURL, assessmentID)

	httpReq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create submit assessment request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("submit assessment request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read submit assessment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result FEATAssessment
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal submit assessment response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] Assessment submitted: %s", assessmentID)
	}

	return &result, nil
}

// MASFEATApproveAssessment approves a completed assessment
func (c *AxonFlowClient) MASFEATApproveAssessment(assessmentID string, req *ApproveAssessmentRequest) (*FEATAssessment, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/assessments/%s/approve", c.config.AgentURL, assessmentID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal approve assessment request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create approve assessment request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("approve assessment request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read approve assessment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result FEATAssessment
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal approve assessment response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] Assessment approved: %s by %s", assessmentID, req.ApprovedBy)
	}

	return &result, nil
}

// MASFEATRejectAssessment rejects a completed assessment
func (c *AxonFlowClient) MASFEATRejectAssessment(assessmentID string, req *RejectAssessmentRequest) (*FEATAssessment, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/assessments/%s/reject", c.config.AgentURL, assessmentID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal reject assessment request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create reject assessment request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("reject assessment request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read reject assessment response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result FEATAssessment
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal reject assessment response: %w", err)
	}

	return &result, nil
}

// ===========================================================================
// MAS FEAT Kill Switch Methods
// ===========================================================================

// MASFEATGetKillSwitch gets or creates a kill switch for a system
func (c *AxonFlowClient) MASFEATGetKillSwitch(systemID string) (*KillSwitch, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s", c.config.AgentURL, systemID)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get kill switch request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get kill switch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read get kill switch response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result KillSwitch
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal get kill switch response: %w", err)
	}

	return &result, nil
}

// MASFEATConfigureKillSwitch configures kill switch thresholds
func (c *AxonFlowClient) MASFEATConfigureKillSwitch(systemID string, req *ConfigureKillSwitchRequest) (*KillSwitch, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s/configure", c.config.AgentURL, systemID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configure kill switch request: %w", err)
	}

	httpReq, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create configure kill switch request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("configure kill switch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read configure kill switch response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result KillSwitch
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configure kill switch response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] Kill switch configured: %s auto_trigger=%v", systemID, result.AutoTriggerEnabled)
	}

	return &result, nil
}

// MASFEATCheckKillSwitch checks metrics and potentially triggers the kill switch
func (c *AxonFlowClient) MASFEATCheckKillSwitch(systemID string, req *CheckKillSwitchRequest) (*KillSwitch, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s/check", c.config.AgentURL, systemID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal check kill switch request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create check kill switch request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("check kill switch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read check kill switch response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result KillSwitch
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal check kill switch response: %w", err)
	}

	if c.config.Debug && result.Status == KillSwitchTriggered {
		log.Printf("[AxonFlow MASFEAT] Kill switch TRIGGERED: %s reason=%s", systemID, result.TriggeredReason)
	}

	return &result, nil
}

// MASFEATTriggerKillSwitch manually triggers the kill switch
func (c *AxonFlowClient) MASFEATTriggerKillSwitch(systemID string, req *TriggerKillSwitchRequest) (*KillSwitch, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s/trigger", c.config.AgentURL, systemID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal trigger kill switch request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create trigger kill switch request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("trigger kill switch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read trigger kill switch response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result KillSwitch
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trigger kill switch response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] Kill switch manually triggered: %s", systemID)
	}

	return &result, nil
}

// MASFEATRestoreKillSwitch restores a triggered kill switch
func (c *AxonFlowClient) MASFEATRestoreKillSwitch(systemID string, req *RestoreKillSwitchRequest) (*KillSwitch, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s/restore", c.config.AgentURL, systemID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal restore kill switch request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create restore kill switch request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("restore kill switch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read restore kill switch response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result KillSwitch
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal restore kill switch response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MASFEAT] Kill switch restored: %s", systemID)
	}

	return &result, nil
}

// MASFEATEnableKillSwitch enables a kill switch
func (c *AxonFlowClient) MASFEATEnableKillSwitch(systemID string) (*KillSwitch, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s/enable", c.config.AgentURL, systemID)

	httpReq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create enable kill switch request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enable kill switch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read enable kill switch response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result KillSwitch
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal enable kill switch response: %w", err)
	}

	return &result, nil
}

// MASFEATDisableKillSwitch disables a kill switch
func (c *AxonFlowClient) MASFEATDisableKillSwitch(systemID string, reason string) (*KillSwitch, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s/disable", c.config.AgentURL, systemID)

	reqBody := map[string]string{"reason": reason}
	body, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create disable kill switch request: %w", err)
	}

	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("disable kill switch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read disable kill switch response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(respBody)}
	}

	var result KillSwitch
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal disable kill switch response: %w", err)
	}

	return &result, nil
}

// MASFEATGetKillSwitchHistory gets kill switch event history
func (c *AxonFlowClient) MASFEATGetKillSwitchHistory(systemID string, limit int) ([]KillSwitchEvent, error) {
	url := fmt.Sprintf("%s/api/v1/masfeat/killswitch/%s/history", c.config.AgentURL, systemID)
	if limit > 0 {
		url += fmt.Sprintf("?limit=%d", limit)
	}

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get kill switch history request: %w", err)
	}

	c.setAuthHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get kill switch history request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read get kill switch history response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{statusCode: resp.StatusCode, message: string(body)}
	}

	var result []KillSwitchEvent
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal get kill switch history response: %w", err)
	}

	return result, nil
}
