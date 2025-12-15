// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// execWithRetry executes a database query with exponential backoff retry
func execWithRetry(db *sql.DB, query string, args ...interface{}) error {
	maxRetries := 3
	baseDelay := 100 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, err := db.Exec(query, args...)
		if err == nil {
			return nil // Success
		}

		lastErr = err
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt)) // Exponential: 100ms, 200ms, 400ms
			log.Printf("Database write failed (attempt %d/%d), retrying in %v: %v",
				attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
		}
	}

	// All retries exhausted
	log.Printf("Database write failed after %d attempts: %v", maxRetries, lastErr)
	return lastErr
}

// DatabasePolicyEngine handles loading and caching policies from database
type DatabasePolicyEngine struct {
	db                    *sql.DB
	sqlInjectionPatterns  []*PolicyPattern
	dangerousQueryPatterns []*PolicyPattern
	adminAccessPatterns   []*PolicyPattern
	piiDetectionPatterns  []*PolicyPattern
	cacheMutex           sync.RWMutex
	lastRefresh          time.Time
	refreshInterval      time.Duration
	performanceMode      bool  // When true, uses async writes for better performance
	auditQueue           *AuditQueue  // Handles async audit logging with persistent fallback
	piiBlockCritical     bool  // Block critical PII (SSN, credit cards) - default: true
}

// PolicyRecord represents a policy from database
type PolicyRecord struct {
	PolicyID    string
	Name        string
	Category    string
	Pattern     string
	Severity    string
	Description string
	Action      string
	TenantID    string
	Metadata    json.RawMessage
}

// NewDatabasePolicyEngine creates a policy engine with database support
func NewDatabasePolicyEngine() (*DatabasePolicyEngine, error) {
	// Try DATABASE_URL first, then fall back to building from individual env vars
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Build connection string from individual env vars (12-Factor App pattern)
		host := os.Getenv("DATABASE_HOST")
		port := os.Getenv("DATABASE_PORT")
		user := os.Getenv("DATABASE_USER")
		password := os.Getenv("DATABASE_PASSWORD")
		dbname := os.Getenv("DATABASE_NAME")
		sslmode := os.Getenv("DATABASE_SSLMODE")

		if sslmode == "" {
			sslmode = "require" // Default to secure connection
		}

		if host == "" || user == "" || password == "" || dbname == "" {
			log.Println("DATABASE env vars not set, falling back to in-memory policies")
			return nil, fmt.Errorf("database not configured (need DATABASE_HOST, DATABASE_USER, DATABASE_PASSWORD, DATABASE_NAME)")
		}

		if port == "" {
			port = "5432" // Default PostgreSQL port
		}

		// Build PostgreSQL connection string
		dbURL = fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s",
			user, password, host, port, dbname, sslmode)

		log.Printf("✅ Built DATABASE_URL from individual env vars (host=%s, db=%s)", host, dbname)
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	// Check for performance mode
	performanceMode := os.Getenv("AGENT_PERFORMANCE_MODE") == "true"

	// Determine audit mode
	var auditMode AuditMode
	if performanceMode {
		auditMode = AuditModePerformance
		log.Println("Agent running in PERFORMANCE MODE - async audit writes enabled")
	} else {
		auditMode = AuditModeCompliance
		log.Println("Agent running in COMPLIANCE MODE - sync audit writes for violations")
	}

	// Initialize audit queue with persistent fallback
	fallbackPath := os.Getenv("AUDIT_FALLBACK_PATH")
	if fallbackPath == "" {
		fallbackPath = "/var/lib/axonflow/audit/audit_fallback.jsonl"
	}

	auditQueue, err := NewAuditQueue(auditMode, 10000, 3, db, fallbackPath)
	if err != nil {
		log.Printf("Warning: Failed to initialize audit queue: %v", err)
		log.Println("Falling back to direct database writes (no queue)")
	}

	// PII blocking is ON by default; set PII_BLOCK_CRITICAL=false to disable
	piiBlock := true
	if val := os.Getenv("PII_BLOCK_CRITICAL"); val == "false" || val == "0" {
		piiBlock = false
		log.Println("[DatabasePolicyEngine] PII blocking DISABLED - critical PII will be logged but not blocked")
	}

	engine := &DatabasePolicyEngine{
		db:               db,
		refreshInterval:  60 * time.Second, // Refresh cache every 60 seconds
		performanceMode:  performanceMode,
		auditQueue:       auditQueue,
		piiBlockCritical: piiBlock,
	}

	// Load initial policies
	if err := engine.LoadPoliciesFromDB(); err != nil {
		log.Printf("Warning: Failed to load policies from DB: %v", err)
		// Fall back to default policies
		engine.loadDefaultPolicies()
	}

	// Start background refresh routine
	go engine.refreshPoliciesRoutine()

	return engine, nil
}

// validateRE2Pattern checks if a regex pattern is compatible with Go's RE2 engine
func validateRE2Pattern(pattern string) error {
	// Check for common unsupported Perl regex syntax
	unsupportedPatterns := map[string]string{
		`\(\?!`:    "negative lookahead (?!...)",
		`\(\?=`:    "positive lookahead (?=...)",
		`\(\?<!`:   "negative lookbehind (?<!...)",
		`\(\?<=`:   "positive lookbehind (?<=...)",
		`\\[0-9]`:  "backreferences (\\1, \\2, etc.)",
		`\(\?P=`:   "named backreferences (?P=name)",
	}

	for regexPattern, description := range unsupportedPatterns {
		matched, _ := regexp.MatchString(regexPattern, pattern)
		if matched {
			return fmt.Errorf("unsupported RE2 syntax: %s not supported in Go regexp", description)
		}
	}

	return nil
}

// LoadPoliciesFromDB loads policies from database into memory
func (dpe *DatabasePolicyEngine) LoadPoliciesFromDB() error {
	query := `
		SELECT policy_id, name, category, pattern, severity, description, action, tenant_id, metadata
		FROM static_policies
		WHERE enabled = true
		ORDER BY category, severity DESC
	`

	rows, err := dpe.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query policies: %v", err)
	}
	defer func() { _ = rows.Close() }()

	// Temporary storage for new policies
	var sqlInjection []*PolicyPattern
	var dangerousQueries []*PolicyPattern
	var adminAccess []*PolicyPattern
	var piiDetection []*PolicyPattern

	policiesLoaded := 0
	for rows.Next() {
		var record PolicyRecord
		if err := rows.Scan(
			&record.PolicyID,
			&record.Name,
			&record.Category,
			&record.Pattern,
			&record.Severity,
			&record.Description,
			&record.Action,
			&record.TenantID,
			&record.Metadata,
		); err != nil {
			log.Printf("Error scanning policy row: %v", err)
			continue
		}

		// Validate and compile regex pattern
		if err := validateRE2Pattern(record.Pattern); err != nil {
			log.Printf("⚠️  Policy %s (%s) has invalid regex pattern: %v", record.PolicyID, record.Name, err)
			log.Printf("    Pattern: %s", record.Pattern)
			log.Printf("    Hint: Go's regexp uses RE2 syntax - no lookaheads (?=/?!), lookbehinds (?<=/?<!), or backreferences")
			continue
		}

		compiledPattern, err := regexp.Compile(record.Pattern)
		if err != nil {
			log.Printf("Error compiling pattern for policy %s: %v", record.PolicyID, err)
			continue
		}

		policy := &PolicyPattern{
			ID:          record.PolicyID,
			Name:        record.Name,
			Pattern:     compiledPattern,
			PatternStr:  record.Pattern,
			Severity:    record.Severity,
			Description: record.Description,
			Enabled:     true,
		}

		// Categorize policies
		switch record.Category {
		case "sql_injection":
			sqlInjection = append(sqlInjection, policy)
		case "dangerous_queries":
			dangerousQueries = append(dangerousQueries, policy)
		case "admin_access":
			adminAccess = append(adminAccess, policy)
		case "pii_detection":
			piiDetection = append(piiDetection, policy)
		}

		policiesLoaded++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating policies: %v", err)
	}

	// Update cache atomically
	dpe.cacheMutex.Lock()
	dpe.sqlInjectionPatterns = sqlInjection
	dpe.dangerousQueryPatterns = dangerousQueries
	dpe.adminAccessPatterns = adminAccess
	dpe.piiDetectionPatterns = piiDetection
	dpe.lastRefresh = time.Now()
	dpe.cacheMutex.Unlock()

	log.Printf("Loaded %d policies from database", policiesLoaded)

	// Log audit event
	dpe.logAuditEvent("policy_refresh", fmt.Sprintf("Loaded %d policies", policiesLoaded))

	return nil
}

// EvaluateStaticPolicies evaluates using cached database policies
func (dpe *DatabasePolicyEngine) EvaluateStaticPolicies(user *User, query string, requestType string) *StaticPolicyResult {
	startTime := time.Now()

	// Check if cache needs refresh (non-blocking)
	if time.Since(dpe.lastRefresh) > dpe.refreshInterval {
		go func() {
			if err := dpe.LoadPoliciesFromDB(); err != nil {
				log.Printf("Background policy refresh failed: %v", err)
			}
		}()
	}

	result := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{},
		ChecksPerformed:   []string{},
	}

	queryLower := strings.ToLower(strings.TrimSpace(query))

	// Use read lock for accessing cached policies
	dpe.cacheMutex.RLock()
	defer dpe.cacheMutex.RUnlock()

	// 1. SQL Injection Detection
	if blockedPattern := dpe.checkPatterns(queryLower, dpe.sqlInjectionPatterns); blockedPattern != nil {
		result.Blocked = true
		result.Reason = fmt.Sprintf("SQL injection attempt detected: %s", blockedPattern.Description)
		result.TriggeredPolicies = append(result.TriggeredPolicies, blockedPattern.ID)
		result.Severity = "critical"
		result.ChecksPerformed = append(result.ChecksPerformed, "sql_injection")
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000

		// Log to audit queue (handles async/sync based on mode)
		dpe.logPolicyViolationToQueue(user, blockedPattern, query)
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "sql_injection")

	// 2. Dangerous Query Detection
	if blockedPattern := dpe.checkPatterns(queryLower, dpe.dangerousQueryPatterns); blockedPattern != nil {
		result.Blocked = true
		result.Reason = fmt.Sprintf("Dangerous query detected: %s", blockedPattern.Description)
		result.TriggeredPolicies = append(result.TriggeredPolicies, blockedPattern.ID)
		result.Severity = "critical"
		result.ChecksPerformed = append(result.ChecksPerformed, "dangerous_queries")
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000

		// Log to audit queue
		dpe.logPolicyViolationToQueue(user, blockedPattern, query)
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "dangerous_queries")

	// 3. Admin Access Control
	if !dpe.hasPermission(user, "admin") {
		if blockedPattern := dpe.checkPatterns(queryLower, dpe.adminAccessPatterns); blockedPattern != nil {
			result.Blocked = true
			result.Reason = fmt.Sprintf("Administrative access required: %s", blockedPattern.Description)
			result.TriggeredPolicies = append(result.TriggeredPolicies, blockedPattern.ID)
			result.Severity = "high"
			result.ChecksPerformed = append(result.ChecksPerformed, "admin_access")
			result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000

			// Log to audit queue
			dpe.logPolicyViolationToQueue(user, blockedPattern, query)
			return result
		}
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "admin_access")

	// 4. PII Detection
	// Critical PII (SSN, credit cards, Aadhaar, PAN) - block if piiBlockCritical is enabled
	// Non-critical PII (email, phone) - log and flag for redaction
	if piiPattern := dpe.checkPatterns(queryLower, dpe.piiDetectionPatterns); piiPattern != nil {
		result.TriggeredPolicies = append(result.TriggeredPolicies, piiPattern.ID)
		log.Printf("PII detected in query: %s", piiPattern.Description)
		if piiPattern.Severity == "critical" && dpe.piiBlockCritical {
			result.Blocked = true
			result.Reason = piiPattern.Description
			result.Severity = piiPattern.Severity
			result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
			dpe.logPolicyViolationToQueue(user, piiPattern, query)
			return result
		}
		// Non-critical PII: allow with redaction in Orchestrator
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "pii_detection")

	result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000

	// Update policy metrics via queue (always async)
	dpe.updatePolicyMetricsToQueue(result)

	return result
}

// checkPatterns checks if query matches any patterns
func (dpe *DatabasePolicyEngine) checkPatterns(query string, patterns []*PolicyPattern) *PolicyPattern {
	for _, pattern := range patterns {
		if pattern.Enabled && pattern.Pattern.MatchString(query) {
			return pattern
		}
	}
	return nil
}

// hasPermission checks user permissions
func (dpe *DatabasePolicyEngine) hasPermission(user *User, permission string) bool {
	if user == nil {
		return false
	}
	return user.Role == permission || user.Role == "admin"
}

// refreshPoliciesRoutine periodically refreshes policies from database
func (dpe *DatabasePolicyEngine) refreshPoliciesRoutine() {
	ticker := time.NewTicker(dpe.refreshInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := dpe.LoadPoliciesFromDB(); err != nil {
			log.Printf("Policy refresh failed: %v", err)
		}
	}
}

// logPolicyViolationToQueue logs policy violations via audit queue
func (dpe *DatabasePolicyEngine) logPolicyViolationToQueue(user *User, policy *PolicyPattern, query string) {
	userID := ""
	if user != nil {
		userID = strconv.Itoa(user.ID)
	}

	entry := AuditEntry{
		Type:      "violation",
		Timestamp: time.Now(),
		Severity:  policy.Severity,
		UserID:    userID,
		ClientID:  "agent",
		Details: map[string]interface{}{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"description": policy.Description,
			"query":       query,
		},
	}

	// Use queue if available, otherwise fall back to direct write
	if dpe.auditQueue != nil {
		if err := dpe.auditQueue.LogViolation(entry); err != nil {
			log.Printf("Failed to queue policy violation: %v", err)
			// Fallback to direct write
			dpe.logPolicyViolationDirect(user, policy, query)
		}
	} else {
		// No queue available, use direct write
		dpe.logPolicyViolationDirect(user, policy, query)
	}
}

// logPolicyViolationDirect logs policy violations directly to database (fallback)
func (dpe *DatabasePolicyEngine) logPolicyViolationDirect(user *User, policy *PolicyPattern, query string) {
	insertQuery := `
		INSERT INTO policy_violations (violation_type, severity, client_id, user_id, description, details)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	details := map[string]interface{}{
		"policy_id": policy.ID,
		"query":     query,
		"timestamp": time.Now(),
	}

	detailsJSON, _ := json.Marshal(details)

	userID := ""
	if user != nil {
		userID = strconv.Itoa(user.ID)
	}

	err := execWithRetry(dpe.db, insertQuery, policy.Name, policy.Severity, "agent", userID, policy.Description, detailsJSON)
	if err != nil {
		log.Printf("Failed to log policy violation after retries: %v", err)
	}
}

// logAuditEvent logs general audit events via queue
func (dpe *DatabasePolicyEngine) logAuditEvent(action, details string) {
	entry := AuditEntry{
		Type:      "audit",
		Timestamp: time.Now(),
		ClientID:  "agent",
		Details: map[string]interface{}{
			"action":   action,
			"resource": details,
		},
	}

	// Use queue if available, otherwise fall back to direct write
	if dpe.auditQueue != nil {
		if err := dpe.auditQueue.LogViolation(entry); err != nil {
			log.Printf("Failed to queue audit event: %v", err)
			// Fallback to direct write
			dpe.logAuditEventDirect(action, details)
		}
	} else {
		dpe.logAuditEventDirect(action, details)
	}
}

// logAuditEventDirect logs audit events directly to database (fallback)
func (dpe *DatabasePolicyEngine) logAuditEventDirect(action, details string) {
	insertQuery := `
		INSERT INTO agent_audit_logs (client_id, action, resource, timestamp)
		VALUES ($1, $2, $3, $4)
	`

	err := execWithRetry(dpe.db, insertQuery, "agent", action, details, time.Now())
	if err != nil {
		log.Printf("Failed to log audit event after retries: %v", err)
	}
}

// updatePolicyMetricsToQueue updates policy hit metrics via queue
func (dpe *DatabasePolicyEngine) updatePolicyMetricsToQueue(result *StaticPolicyResult) {
	for _, policyID := range result.TriggeredPolicies {
		entry := AuditEntry{
			Type:      "metric",
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"policy_id": policyID,
				"blocked":   result.Blocked,
			},
		}

		// Metrics always go through queue (async even in compliance mode)
		if dpe.auditQueue != nil {
			if err := dpe.auditQueue.LogMetric(entry); err != nil {
				log.Printf("Failed to queue metric for policy %s: %v", policyID, err)
			}
		} else {
			// Fallback to direct write if no queue
			dpe.updatePolicyMetricDirect(policyID, result.Blocked)
		}
	}
}

// updatePolicyMetricDirect updates a single policy metric directly (fallback)
func (dpe *DatabasePolicyEngine) updatePolicyMetricDirect(policyID string, blocked bool) {
	updateQuery := `
		INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date)
		VALUES ($1, 'static', 1, $2, CURRENT_DATE)
		ON CONFLICT (policy_id, date) DO UPDATE SET
			hit_count = policy_metrics.hit_count + 1,
			block_count = policy_metrics.block_count + $2
	`

	blockCount := 0
	if blocked {
		blockCount = 1
	}

	err := execWithRetry(dpe.db, updateQuery, policyID, blockCount)
	if err != nil {
		log.Printf("Failed to update policy metrics after retries: %v", err)
	}
}

// loadDefaultPolicies loads hardcoded defaults as fallback
func (dpe *DatabasePolicyEngine) loadDefaultPolicies() {
	log.Println("Loading default hardcoded policies as fallback")

	dpe.cacheMutex.Lock()
	defer dpe.cacheMutex.Unlock()

	// SQL Injection Patterns
	dpe.sqlInjectionPatterns = []*PolicyPattern{
		{
			ID:          "sql_injection_union",
			Name:        "SQL Injection - UNION Attack",
			Pattern:     regexp.MustCompile(`union\s+select`),
			PatternStr:  `union\s+select`,
			Severity:    "critical",
			Description: "UNION-based SQL injection attempt",
			Enabled:     true,
		},
		{
			ID:          "sql_injection_comment",
			Name:        "SQL Injection - Comment Bypass",
			Pattern:     regexp.MustCompile(`--|\*\/|\/\*`),
			PatternStr:  `--|\*\/|\/\*`,
			Severity:    "critical",
			Description: "SQL comment injection attempt",
			Enabled:     true,
		},
	}

	// Dangerous Query Patterns
	dpe.dangerousQueryPatterns = []*PolicyPattern{
		{
			ID:          "drop_table_prevention",
			Name:        "DROP TABLE Prevention",
			Pattern:     regexp.MustCompile(`drop\s+table`),
			PatternStr:  `drop\s+table`,
			Severity:    "critical",
			Description: "DROP TABLE operations are not allowed",
			Enabled:     true,
		},
	}

	// Admin Access Patterns
	dpe.adminAccessPatterns = []*PolicyPattern{
		{
			ID:          "config_table_access",
			Name:        "Configuration Table Access",
			Pattern:     regexp.MustCompile(`system_config|admin_settings`),
			PatternStr:  `system_config|admin_settings`,
			Severity:    "high",
			Description: "Access to system configuration requires admin privileges",
			Enabled:     true,
		},
	}

	// PII Detection Patterns
	dpe.piiDetectionPatterns = []*PolicyPattern{
		{
			ID:          "ssn_detection",
			Name:        "SSN Detection",
			Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			PatternStr:  `\b\d{3}-\d{2}-\d{4}\b`,
			Severity:    "critical", // Critical PII - blocks by default
			Description: "Social Security Number detected",
			Enabled:     true,
		},
	}

	dpe.lastRefresh = time.Now()
}

// Close closes database connection and shuts down audit queue
func (dpe *DatabasePolicyEngine) Close() error {
	// Gracefully shutdown audit queue first (drains pending entries)
	if dpe.auditQueue != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := dpe.auditQueue.Shutdown(ctx); err != nil {
			log.Printf("Warning: Audit queue shutdown error: %v", err)
		}
	}

	// Then close database connection
	if dpe.db != nil {
		return dpe.db.Close()
	}
	return nil
}

// GetAuditQueue returns the audit queue for use by other components (e.g., Gateway Mode handlers)
// Returns nil if the audit queue is not initialized
func (dpe *DatabasePolicyEngine) GetAuditQueue() *AuditQueue {
	return dpe.auditQueue
}

// RecoverAuditEntries recovers any failed audit entries from the fallback file
// This should be called during startup after the audit queue is initialized
func (dpe *DatabasePolicyEngine) RecoverAuditEntries() (int, error) {
	if dpe.auditQueue == nil {
		return 0, nil
	}

	fallbackPath := dpe.auditQueue.GetFallbackPath()
	if fallbackPath == "" {
		return 0, nil
	}

	return dpe.auditQueue.RecoverFromFallback(fallbackPath)
}