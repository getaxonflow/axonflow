// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package agent provides the AxonFlow Agent service for authentication,
// authorization, and static policy enforcement.
package agent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// =============================================================================
// Decision Chain Types
// =============================================================================

// DecisionType represents the type of AI decision being recorded.
// Each type corresponds to a different stage in the AI processing pipeline.
type DecisionType string

const (
	// DecisionTypePolicyEnforcement is a static policy evaluation decision.
	DecisionTypePolicyEnforcement DecisionType = "policy_enforcement"

	// DecisionTypeLLMGeneration is an LLM model invocation decision.
	DecisionTypeLLMGeneration DecisionType = "llm_generation"

	// DecisionTypeDataRetrieval is a data source/connector query decision.
	DecisionTypeDataRetrieval DecisionType = "data_retrieval"

	// DecisionTypeHumanReview is a human-in-the-loop decision.
	DecisionTypeHumanReview DecisionType = "human_review"

	// DecisionTypeSystemAction is an automated system action decision.
	DecisionTypeSystemAction DecisionType = "system_action"
)

// DecisionOutcome represents the result of an AI decision.
type DecisionOutcome string

const (
	// DecisionOutcomeApproved indicates the request was allowed to proceed.
	DecisionOutcomeApproved DecisionOutcome = "approved"

	// DecisionOutcomeBlocked indicates the request was denied by policy.
	DecisionOutcomeBlocked DecisionOutcome = "blocked"

	// DecisionOutcomeModified indicates content was filtered or modified.
	DecisionOutcomeModified DecisionOutcome = "modified"

	// DecisionOutcomePendingReview indicates the decision awaits human review.
	DecisionOutcomePendingReview DecisionOutcome = "pending_review"

	// DecisionOutcomeError indicates a processing error occurred.
	DecisionOutcomeError DecisionOutcome = "error"
)

// RiskLevel represents the EU AI Act risk classification.
type RiskLevel string

const (
	// RiskLevelMinimal indicates no significant AI risk.
	RiskLevelMinimal RiskLevel = "minimal"

	// RiskLevelLimited indicates transparency obligations apply.
	RiskLevelLimited RiskLevel = "limited"

	// RiskLevelHigh indicates conformity assessment required.
	RiskLevelHigh RiskLevel = "high"

	// RiskLevelUnacceptable indicates prohibited AI use.
	RiskLevelUnacceptable RiskLevel = "unacceptable"
)

// DecisionEntry represents a single decision step in a chain.
// This is the core data structure for EU AI Act Article 12 record-keeping.
type DecisionEntry struct {
	// Identification
	ID              string `json:"id"`
	ChainID         string `json:"chain_id"`
	RequestID       string `json:"request_id"`
	ParentRequestID string `json:"parent_request_id,omitempty"`
	StepNumber      int    `json:"step_number"`

	// Tenant context
	OrgID    string `json:"org_id"`
	TenantID string `json:"tenant_id"`
	ClientID string `json:"client_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`

	// Decision details
	DecisionType    DecisionType    `json:"decision_type"`
	DecisionOutcome DecisionOutcome `json:"decision_outcome"`

	// AI system information
	SystemID      string `json:"system_id"`
	ModelProvider string `json:"model_provider,omitempty"`
	ModelID       string `json:"model_id,omitempty"`

	// Policy information
	PoliciesEvaluated []string `json:"policies_evaluated,omitempty"`
	PolicyTriggered   string   `json:"policy_triggered,omitempty"`

	// Risk assessment
	RiskLevel           RiskLevel `json:"risk_level"`
	RequiresHumanReview bool      `json:"requires_human_review"`

	// Performance
	ProcessingTimeMs int64 `json:"processing_time_ms"`

	// Verification
	InputHash  string                 `json:"input_hash,omitempty"`
	OutputHash string                 `json:"output_hash,omitempty"`
	AuditHash  string                 `json:"audit_hash,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`

	// Data lineage
	DataSources []string `json:"data_sources,omitempty"`

	// Timestamp
	CreatedAt time.Time `json:"created_at"`
}

// ChainSummary provides aggregate statistics for a decision chain.
type ChainSummary struct {
	ChainID             string    `json:"chain_id"`
	TotalSteps          int       `json:"total_steps"`
	TotalProcessingMs   int64     `json:"total_processing_time_ms"`
	HasBlocked          bool      `json:"has_blocked"`
	RequiresReview      bool      `json:"requires_review"`
	HighestRiskLevel    RiskLevel `json:"highest_risk_level"`
	FirstDecisionAt     time.Time `json:"first_decision_at"`
	LastDecisionAt      time.Time `json:"last_decision_at"`
	DecisionTypes       []string  `json:"decision_types"`
	TotalPoliciesApplied int      `json:"total_policies_applied"`
}

// =============================================================================
// Decision Chain Tracker
// =============================================================================

// DecisionChainTracker records AI decision chains for audit and compliance.
// It provides a thread-safe interface for recording decision steps and
// retrieving complete chains for EU AI Act Article 12 compliance.
//
// The tracker can operate in two modes:
//   - Database mode: Persists decisions to PostgreSQL (production)
//   - Memory mode: Keeps decisions in memory (testing)
//
// All methods are thread-safe and can be called from multiple goroutines.
type DecisionChainTracker struct {
	db           *sql.DB
	memoryStore  map[string][]DecisionEntry
	mu           sync.RWMutex
	useMemory    bool
	systemID     string

	// Metrics
	decisionsRecorded uint64
	chainsCreated     uint64
	recordErrors      uint64

	// Async processing
	asyncQueue chan DecisionEntry
	wg         sync.WaitGroup
	closed     atomic.Bool
}

// DecisionChainTrackerConfig holds configuration for the tracker.
type DecisionChainTrackerConfig struct {
	// DB is the PostgreSQL database connection.
	// If nil, the tracker operates in memory mode.
	DB *sql.DB

	// SystemID identifies this system (e.g., "axonflow-agent/1.0.0").
	SystemID string

	// AsyncQueueSize is the buffer size for async processing.
	// Set to 0 for synchronous operation. Default: 1000.
	AsyncQueueSize int

	// Workers is the number of async worker goroutines.
	// Only used if AsyncQueueSize > 0. Default: 2.
	Workers int
}

// NewDecisionChainTracker creates a new decision chain tracker.
//
// Example:
//
//	tracker, err := NewDecisionChainTracker(DecisionChainTrackerConfig{
//	    DB:       db,
//	    SystemID: "axonflow-agent/1.0.0",
//	})
func NewDecisionChainTracker(config DecisionChainTrackerConfig) (*DecisionChainTracker, error) {
	if config.SystemID == "" {
		config.SystemID = "axonflow-agent/unknown"
	}
	// AsyncQueueSize < 0 means synchronous mode (no workers)
	// AsyncQueueSize == 0 means default (1000)
	// AsyncQueueSize > 0 means use that value
	if config.AsyncQueueSize == 0 {
		config.AsyncQueueSize = 1000
	}
	if config.Workers == 0 && config.AsyncQueueSize > 0 {
		config.Workers = 2
	}

	tracker := &DecisionChainTracker{
		db:          config.DB,
		memoryStore: make(map[string][]DecisionEntry),
		useMemory:   config.DB == nil,
		systemID:    config.SystemID,
	}

	// Start async workers if queue size > 0 and DB is provided
	if config.AsyncQueueSize > 0 && config.DB != nil {
		tracker.asyncQueue = make(chan DecisionEntry, config.AsyncQueueSize)
		for i := 0; i < config.Workers; i++ {
			tracker.wg.Add(1)
			go tracker.asyncWorker(i)
		}
		log.Printf("[DecisionChain] Started with %d async workers, queue size: %d",
			config.Workers, config.AsyncQueueSize)
	}

	if tracker.useMemory {
		log.Println("[DecisionChain] Running in memory mode (no database)")
	}

	return tracker, nil
}

// =============================================================================
// Recording Decisions
// =============================================================================

// RecordDecision records a decision entry in the chain.
// This is the primary method for logging AI decisions.
//
// If the tracker is configured for async processing, the decision is
// queued for background persistence. Otherwise, it's written synchronously.
//
// The entry's AuditHash is computed automatically if not already set.
func (t *DecisionChainTracker) RecordDecision(ctx context.Context, entry DecisionEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	if entry.SystemID == "" {
		entry.SystemID = t.systemID
	}
	if entry.RiskLevel == "" {
		entry.RiskLevel = RiskLevelLimited
	}
	if entry.AuditHash == "" {
		entry.AuditHash = t.computeAuditHash(entry)
	}

	atomic.AddUint64(&t.decisionsRecorded, 1)

	// Memory mode
	if t.useMemory {
		return t.recordToMemory(entry)
	}

	// Async mode
	if t.asyncQueue != nil && !t.closed.Load() {
		select {
		case t.asyncQueue <- entry:
			return nil
		default:
			// Queue full, fall through to sync
			log.Println("[DecisionChain] Async queue full, writing synchronously")
		}
	}

	// Sync mode
	return t.recordToDB(ctx, entry)
}

// TransparencyInfo holds transparency data for creating decision entries.
// This is a lightweight struct for passing transparency data without
// depending on the full TransparencyContext type.
type TransparencyInfo struct {
	ChainID           string
	RequestID         string
	OrgID             string
	TenantID          string
	ClientID          string
	UserID            string
	SystemID          string
	ModelProvider     string
	ModelID           string
	PoliciesApplied   []string
	RiskLevel         string
	HumanOversight    bool
	ProcessingTimeMs  int64
	DataSources       []string
}

// RecordFromTransparencyInfo creates and records a decision entry from transparency info.
// This provides seamless integration between transparency headers and decision chain tracking.
func (t *DecisionChainTracker) RecordFromTransparencyInfo(ctx context.Context, ti *TransparencyInfo, decisionType DecisionType, outcome DecisionOutcome) error {
	if ti == nil {
		return fmt.Errorf("transparency info is nil")
	}

	entry := DecisionEntry{
		ChainID:             ti.ChainID,
		RequestID:           ti.RequestID,
		OrgID:               ti.OrgID,
		TenantID:            ti.TenantID,
		ClientID:            ti.ClientID,
		UserID:              ti.UserID,
		DecisionType:        decisionType,
		DecisionOutcome:     outcome,
		SystemID:            ti.SystemID,
		ModelProvider:       ti.ModelProvider,
		ModelID:             ti.ModelID,
		PoliciesEvaluated:   append([]string(nil), ti.PoliciesApplied...),
		RiskLevel:           RiskLevel(ti.RiskLevel),
		RequiresHumanReview: ti.HumanOversight,
		ProcessingTimeMs:    ti.ProcessingTimeMs,
		DataSources:         append([]string(nil), ti.DataSources...),
	}

	// Set policy triggered if blocked
	if outcome == DecisionOutcomeBlocked && len(entry.PoliciesEvaluated) > 0 {
		entry.PolicyTriggered = entry.PoliciesEvaluated[len(entry.PoliciesEvaluated)-1]
	}

	return t.RecordDecision(ctx, entry)
}

// recordToMemory stores an entry in the in-memory store (for testing).
func (t *DecisionChainTracker) recordToMemory(entry DecisionEntry) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.memoryStore[entry.ChainID]; !exists {
		atomic.AddUint64(&t.chainsCreated, 1)
	}

	t.memoryStore[entry.ChainID] = append(t.memoryStore[entry.ChainID], entry)
	return nil
}

// recordToDB persists an entry to the database.
func (t *DecisionChainTracker) recordToDB(ctx context.Context, entry DecisionEntry) error {
	query := `
		INSERT INTO decision_chain (
			id, chain_id, request_id, parent_request_id, step_number,
			org_id, tenant_id, client_id, user_id,
			decision_type, decision_outcome,
			system_id, model_provider, model_id,
			policies_evaluated, policy_triggered,
			risk_level, requires_human_review,
			processing_time_ms,
			input_hash, output_hash, audit_hash,
			data_sources, metadata,
			created_at
		) VALUES (
			$1, $2, $3, NULLIF($4, ''), $5,
			$6, $7, $8, $9,
			$10, $11,
			$12, NULLIF($13, ''), NULLIF($14, ''),
			$15, NULLIF($16, ''),
			$17, $18,
			$19,
			NULLIF($20, ''), NULLIF($21, ''), $22,
			$23, $24,
			$25
		)
	`

	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		metadata = []byte("{}")
	}

	_, err = t.db.ExecContext(ctx, query,
		entry.ID, entry.ChainID, entry.RequestID, entry.ParentRequestID, entry.StepNumber,
		entry.OrgID, entry.TenantID, entry.ClientID, entry.UserID,
		string(entry.DecisionType), string(entry.DecisionOutcome),
		entry.SystemID, entry.ModelProvider, entry.ModelID,
		pq.Array(entry.PoliciesEvaluated), entry.PolicyTriggered,
		string(entry.RiskLevel), entry.RequiresHumanReview,
		entry.ProcessingTimeMs,
		entry.InputHash, entry.OutputHash, entry.AuditHash,
		pq.Array(entry.DataSources), metadata,
		entry.CreatedAt,
	)

	if err != nil {
		atomic.AddUint64(&t.recordErrors, 1)
		return fmt.Errorf("failed to record decision: %w", err)
	}

	return nil
}

// asyncWorker processes decisions from the async queue.
func (t *DecisionChainTracker) asyncWorker(id int) {
	defer t.wg.Done()

	for entry := range t.asyncQueue {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := t.recordToDB(ctx, entry); err != nil {
			log.Printf("[DecisionChain] Worker %d: failed to record: %v", id, err)
		}
		cancel()
	}
}

// =============================================================================
// Retrieving Chains
// =============================================================================

// GetChain retrieves all decision entries for a chain, ordered by step number.
func (t *DecisionChainTracker) GetChain(ctx context.Context, chainID string) ([]DecisionEntry, error) {
	if t.useMemory {
		t.mu.RLock()
		defer t.mu.RUnlock()
		if entries, ok := t.memoryStore[chainID]; ok {
			// Return a copy to prevent modification
			result := make([]DecisionEntry, len(entries))
			copy(result, entries)
			return result, nil
		}
		return nil, nil
	}

	query := `
		SELECT id, chain_id, request_id, COALESCE(parent_request_id::text, ''), step_number,
		       org_id, tenant_id, COALESCE(client_id, ''), COALESCE(user_id, ''),
		       decision_type, decision_outcome,
		       system_id, COALESCE(model_provider, ''), COALESCE(model_id, ''),
		       policies_evaluated, COALESCE(policy_triggered, ''),
		       risk_level, requires_human_review,
		       processing_time_ms,
		       COALESCE(input_hash, ''), COALESCE(output_hash, ''), COALESCE(audit_hash, ''),
		       data_sources, metadata,
		       created_at
		FROM decision_chain
		WHERE chain_id = $1
		ORDER BY step_number ASC
	`

	rows, err := t.db.QueryContext(ctx, query, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to query chain: %w", err)
	}
	defer rows.Close()

	var entries []DecisionEntry
	for rows.Next() {
		var entry DecisionEntry
		var decisionType, decisionOutcome, riskLevel string
		var policiesEvaluated, dataSources pq.StringArray
		var metadata []byte

		err := rows.Scan(
			&entry.ID, &entry.ChainID, &entry.RequestID, &entry.ParentRequestID, &entry.StepNumber,
			&entry.OrgID, &entry.TenantID, &entry.ClientID, &entry.UserID,
			&decisionType, &decisionOutcome,
			&entry.SystemID, &entry.ModelProvider, &entry.ModelID,
			&policiesEvaluated, &entry.PolicyTriggered,
			&riskLevel, &entry.RequiresHumanReview,
			&entry.ProcessingTimeMs,
			&entry.InputHash, &entry.OutputHash, &entry.AuditHash,
			&dataSources, &metadata,
			&entry.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		entry.DecisionType = DecisionType(decisionType)
		entry.DecisionOutcome = DecisionOutcome(decisionOutcome)
		entry.RiskLevel = RiskLevel(riskLevel)
		entry.PoliciesEvaluated = []string(policiesEvaluated)
		entry.DataSources = []string(dataSources)

		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &entry.Metadata)
		}

		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// GetChainSummary returns aggregate statistics for a chain.
func (t *DecisionChainTracker) GetChainSummary(ctx context.Context, chainID string) (*ChainSummary, error) {
	entries, err := t.GetChain(ctx, chainID)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	summary := &ChainSummary{
		ChainID:          chainID,
		TotalSteps:       len(entries),
		HighestRiskLevel: RiskLevelMinimal,
	}

	decisionTypesMap := make(map[string]bool)
	policiesSet := make(map[string]bool)

	for i, entry := range entries {
		summary.TotalProcessingMs += entry.ProcessingTimeMs

		if entry.DecisionOutcome == DecisionOutcomeBlocked {
			summary.HasBlocked = true
		}
		if entry.RequiresHumanReview {
			summary.RequiresReview = true
		}

		// Track highest risk level
		if compareRiskLevels(entry.RiskLevel, summary.HighestRiskLevel) > 0 {
			summary.HighestRiskLevel = entry.RiskLevel
		}

		// Track timestamps
		if i == 0 || entry.CreatedAt.Before(summary.FirstDecisionAt) {
			summary.FirstDecisionAt = entry.CreatedAt
		}
		if entry.CreatedAt.After(summary.LastDecisionAt) {
			summary.LastDecisionAt = entry.CreatedAt
		}

		// Collect decision types
		decisionTypesMap[string(entry.DecisionType)] = true

		// Count unique policies
		for _, p := range entry.PoliciesEvaluated {
			policiesSet[p] = true
		}
	}

	// Convert maps to slices
	for dt := range decisionTypesMap {
		summary.DecisionTypes = append(summary.DecisionTypes, dt)
	}
	summary.TotalPoliciesApplied = len(policiesSet)

	return summary, nil
}

// GetRecentChains returns recent chains for a tenant within a time window.
func (t *DecisionChainTracker) GetRecentChains(ctx context.Context, orgID, tenantID string, since time.Duration, limit int) ([]ChainSummary, error) {
	if t.useMemory {
		// Memory mode: return summaries of all chains matching org/tenant
		t.mu.RLock()
		defer t.mu.RUnlock()

		var summaries []ChainSummary
		cutoff := time.Now().Add(-since)

		for chainID, entries := range t.memoryStore {
			if len(entries) == 0 {
				continue
			}
			// Check if any entry matches org/tenant and is recent enough
			var matches bool
			for _, e := range entries {
				if e.OrgID == orgID && e.TenantID == tenantID && e.CreatedAt.After(cutoff) {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}

			summary, _ := t.GetChainSummary(ctx, chainID)
			if summary != nil {
				summaries = append(summaries, *summary)
			}

			if len(summaries) >= limit {
				break
			}
		}
		return summaries, nil
	}

	query := `
		SELECT chain_id, COUNT(*) as step_count,
		       COALESCE(SUM(processing_time_ms), 0) as total_processing_ms,
		       bool_or(decision_outcome = 'blocked') as has_blocked,
		       bool_or(requires_human_review) as requires_review,
		       MIN(created_at) as first_decision_at,
		       MAX(created_at) as last_decision_at
		FROM decision_chain
		WHERE org_id = $1 AND tenant_id = $2
		  AND created_at > NOW() - $3::INTERVAL
		GROUP BY chain_id
		ORDER BY MAX(created_at) DESC
		LIMIT $4
	`

	rows, err := t.db.QueryContext(ctx, query, orgID, tenantID, since.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent chains: %w", err)
	}
	defer rows.Close()

	var summaries []ChainSummary
	for rows.Next() {
		var summary ChainSummary
		err := rows.Scan(
			&summary.ChainID, &summary.TotalSteps,
			&summary.TotalProcessingMs, &summary.HasBlocked, &summary.RequiresReview,
			&summary.FirstDecisionAt, &summary.LastDecisionAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		summaries = append(summaries, summary)
	}

	return summaries, rows.Err()
}

// =============================================================================
// Helper Functions
// =============================================================================

// computeAuditHash generates a SHA-256 hash for tamper detection.
// Uses length-prefixed encoding to prevent collision attacks.
func (t *DecisionChainTracker) computeAuditHash(entry DecisionEntry) string {
	// Length-prefixed format to prevent hash collisions
	hashInput := fmt.Sprintf(
		"%d:%s|%d:%s|%d:%s|%d:%s|%d:%s|%s|%s|%t|%d",
		len(entry.ChainID), entry.ChainID,
		len(entry.RequestID), entry.RequestID,
		len(entry.OrgID), entry.OrgID,
		len(entry.TenantID), entry.TenantID,
		len(string(entry.DecisionType)), string(entry.DecisionType),
		string(entry.DecisionOutcome),
		string(entry.RiskLevel),
		entry.RequiresHumanReview,
		entry.ProcessingTimeMs,
	)

	hash := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(hash[:])
}

// compareRiskLevels returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareRiskLevels(a, b RiskLevel) int {
	order := map[RiskLevel]int{
		RiskLevelMinimal:      0,
		RiskLevelLimited:      1,
		RiskLevelHigh:         2,
		RiskLevelUnacceptable: 3,
	}

	if order[a] < order[b] {
		return -1
	}
	if order[a] > order[b] {
		return 1
	}
	return 0
}

// =============================================================================
// Metrics and Lifecycle
// =============================================================================

// GetStats returns tracker statistics.
func (t *DecisionChainTracker) GetStats() map[string]interface{} {
	pending := 0
	if t.asyncQueue != nil {
		pending = len(t.asyncQueue)
	}

	t.mu.RLock()
	memoryChains := len(t.memoryStore)
	t.mu.RUnlock()

	return map[string]interface{}{
		"decisions_recorded": atomic.LoadUint64(&t.decisionsRecorded),
		"chains_created":     atomic.LoadUint64(&t.chainsCreated),
		"record_errors":      atomic.LoadUint64(&t.recordErrors),
		"async_pending":      pending,
		"memory_mode":        t.useMemory,
		"memory_chains":      memoryChains,
	}
}

// Shutdown gracefully shuts down the tracker.
// Waits for pending async operations to complete.
func (t *DecisionChainTracker) Shutdown(ctx context.Context) error {
	if t.asyncQueue == nil {
		return nil
	}

	log.Println("[DecisionChain] Shutting down...")
	t.closed.Store(true)
	close(t.asyncQueue)

	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[DecisionChain] Shutdown complete. Recorded: %d, Errors: %d",
			atomic.LoadUint64(&t.decisionsRecorded),
			atomic.LoadUint64(&t.recordErrors))
		return nil
	case <-ctx.Done():
		log.Printf("[DecisionChain] Shutdown timeout. Recorded: %d, Errors: %d",
			atomic.LoadUint64(&t.decisionsRecorded),
			atomic.LoadUint64(&t.recordErrors))
		return ctx.Err()
	}
}

// =============================================================================
// Context Integration
// =============================================================================

// decisionChainContextKey is the context key for storing DecisionChainTracker.
type decisionChainContextKey struct{}

// SetDecisionChainTracker stores the tracker in the context.
func SetDecisionChainTracker(ctx context.Context, tracker *DecisionChainTracker) context.Context {
	return context.WithValue(ctx, decisionChainContextKey{}, tracker)
}

// GetDecisionChainTracker retrieves the tracker from the context.
// Returns nil if no tracker is set.
func GetDecisionChainTracker(ctx context.Context) *DecisionChainTracker {
	if tracker, ok := ctx.Value(decisionChainContextKey{}).(*DecisionChainTracker); ok {
		return tracker
	}
	return nil
}
