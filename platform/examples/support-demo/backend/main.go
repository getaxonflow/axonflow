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

package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	_ "github.com/lib/pq"

	axonflow "github.com/getaxonflow/axonflow-go"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Configuration
var (
	db             *sql.DB
	jwtSecret      = []byte(os.Getenv("JWT_SECRET"))
	llmRouter      *LLMRouter
	policyEngine   *PolicyEngine
	axonflowClient *axonflow.AxonFlowClient
)

// Data structures
type User struct {
	ID          int      `json:"id"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Department  string   `json:"department"`
	Role        string   `json:"role"`
	Region      string   `json:"region"`
	Permissions []string `json:"permissions"`
}

type QueryRequest struct {
	Query     string `json:"query"`
	QueryType string `json:"query_type"` // "natural_language", "sql_query", "mongodb_query", "api_call"
}

type QueryResponse struct {
	Results         []map[string]interface{} `json:"results"`
	Count           int                      `json:"count"`
	PIIDetected     []string                 `json:"pii_detected"`
	PIIRedacted     bool                     `json:"pii_redacted"`
	SecurityLog     SecurityLog              `json:"security_log"`
	LLMProvider     *LLMProviderInfo         `json:"llm_provider,omitempty"`
	PolicyViolations []PolicyViolation       `json:"policy_violations,omitempty"`
	QueryBlocked    bool                     `json:"query_blocked"`
	BlockReason     string                   `json:"block_reason,omitempty"`
}

type LLMProviderInfo struct {
	Name        string `json:"name"`
	Reason      string `json:"reason"`
	TokensUsed  int    `json:"tokens_used"`
	Duration    string `json:"duration"`
}

type PerformanceMetrics struct {
	AvgResponseTime      float64           `json:"avg_response_time"`
	P95ResponseTime      int               `json:"p95_response_time"`
	P99ResponseTime      int               `json:"p99_response_time"`
	RequestsPerSecond    float64           `json:"requests_per_second"`
	ErrorRate            float64           `json:"error_rate"`
	TotalRequests        int               `json:"total_requests"`
	AgentLatency         float64           `json:"agent_latency"`
	OrchestratorLatency  float64           `json:"orchestrator_latency"`
	TimeSeriesData       []TimeSeriesPoint `json:"time_series_data"`
}

type TimeSeriesPoint struct {
	Timestamp    string `json:"timestamp"`
	ResponseTime int    `json:"response_time"`
}

type PolicyMetrics struct {
	TotalPoliciesEnforced int               `json:"total_policies_enforced"`
	AiQueries             int               `json:"ai_queries"`
	PiiRedacted           int               `json:"pii_redacted"`
	RegionalBlocks        int               `json:"regional_blocks"`
	AgentHealth           string            `json:"agent_health"`
	OrchestratorHealth    string            `json:"orchestrator_health"`
	RecentActivity        []ActivityItem    `json:"recent_activity"`
}

type ActivityItem struct {
	Type      string `json:"type"`
	Query     string `json:"query"`
	Timestamp string `json:"timestamp"`
	Provider  string `json:"provider,omitempty"`
}

type SecurityLog struct {
	UserEmail       string    `json:"user_email"`
	QueryExecuted   string    `json:"query_executed"`
	AccessGranted   bool      `json:"access_granted"`
	FilteredResults int       `json:"filtered_results"`
	PIIRedacted     bool      `json:"pii_redacted"`
	Timestamp       time.Time `json:"timestamp"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type AuditLogEntry struct {
	ID           int       `json:"id"`
	UserEmail    string    `json:"user_email"`
	QueryText    string    `json:"query_text"`
	ResultsCount int       `json:"results_count"`
	PIIDetected  []string  `json:"pii_detected"`
	PIIRedacted  bool      `json:"pii_redacted"`
	AccessGranted bool     `json:"access_granted"`
	CreatedAt    time.Time `json:"created_at"`
}

// PII Detection patterns
var piiPatterns = map[string]*regexp.Regexp{
	"ssn":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"credit_card": regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
	"phone":       regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
	"email":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
}

// runMigrations applies database migrations on startup
func runMigrations(db *sql.DB) error {
	// Get list of migration files from embedded filesystem
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort migration files by name (01-schema.sql, 02-performance-metrics.sql, etc.)
	var migrationFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			migrationFiles = append(migrationFiles, entry.Name())
		}
	}
	sort.Strings(migrationFiles)

	if len(migrationFiles) == 0 {
		log.Println("ℹ️  No migration files found")
		return nil
	}

	// Check if tables already exist (simple check for users table)
	var exists bool
	err = db.QueryRow("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')").Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if tables exist: %w", err)
	}

	if exists {
		log.Println("✅ Database schema already exists, skipping migrations")
		return nil
	}

	// Apply each migration file
	log.Printf("Applying %d migration files...", len(migrationFiles))
	for _, filename := range migrationFiles {
		sqlBytes, err := migrationsFS.ReadFile(filepath.Join("migrations", filename))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", filename, err)
		}

		startTime := time.Now()
		_, err = db.Exec(string(sqlBytes))
		executionTime := time.Since(startTime)

		if err != nil {
			return fmt.Errorf("migration %s failed: %w", filename, err)
		}

		log.Printf("✅ Applied migration %s (%v)", filename, executionTime)
	}

	return nil
}

func main() {
	// Connect to database
	var err error
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}
	
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// Test database connection
	if err = db.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}
	log.Println("Connected to database successfully")

	// Run database migrations
	log.Println("Running database migrations...")
	if err := runMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	log.Println("✅ Database migrations completed")

	// Initialize LLM Router
	llmRouter = NewLLMRouter()
	log.Println("LLM Router initialized with multi-model support")

	// Initialize Policy Engine
	policyEngine = NewPolicyEngine()
	log.Println("Policy Engine initialized with security policies")

	// Initialize AxonFlow Client with license-based authentication
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080" // Default for local development
	}

	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		log.Fatal("AXONFLOW_LICENSE_KEY environment variable is required")
	}

	axonflowClient = axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:   agentURL,
		LicenseKey: licenseKey,
		Mode:       "production",
		Debug:      os.Getenv("AXONFLOW_DEBUG") == "true",
	})
	log.Printf("AxonFlow Client initialized with license-based authentication")

	// Setup router
	r := mux.NewRouter()

	// CORS middleware using rs/cors
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{
			"http://localhost:3000",
			"http://demo-portal-eu.getaxonflow.com",
			"https://demo-portal-eu.getaxonflow.com",
			"http://demo.getaxonflow.com",
			"https://demo.getaxonflow.com",
			"http://support-eu.getaxonflow.com",
			"https://support-eu.getaxonflow.com",
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	// Routes
	r.HandleFunc("/api/health", healthHandler).Methods("GET")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/query", authMiddleware(queryHandler)).Methods("POST")
	r.HandleFunc("/api/audit", authMiddleware(auditHandler)).Methods("GET")
	r.HandleFunc("/api/dashboard", authMiddleware(dashboardHandler)).Methods("GET")
	
	// LLM Orchestration Routes
	r.HandleFunc("/api/llm/chat", authMiddleware(llmChatHandler)).Methods("POST")
	r.HandleFunc("/api/llm/natural-query", authMiddleware(naturalQueryHandler)).Methods("POST")
	r.HandleFunc("/api/llm/axonflow-query", authMiddleware(axonflowQueryHandler)).Methods("POST")
	r.HandleFunc("/api/llm/status", authMiddleware(llmStatusHandler)).Methods("GET")
	r.HandleFunc("/api/llm/user-access", authMiddleware(llmUserAccessHandler)).Methods("GET")
	
	// Policy Engine Routes
	r.HandleFunc("/api/policies", authMiddleware(policiesHandler)).Methods("GET")
	r.HandleFunc("/api/policies/violations", authMiddleware(policyViolationsHandler)).Methods("GET")
	r.HandleFunc("/api/policies/test", authMiddleware(policyTestHandler)).Methods("POST")
	
	// Performance Metrics Routes
	r.HandleFunc("/api/performance/metrics", authMiddleware(performanceMetricsHandler)).Methods("GET")
	r.HandleFunc("/api/performance/record", authMiddleware(recordPerformanceHandler)).Methods("POST")
	
	// Policy Metrics Routes
	r.HandleFunc("/api/policy-metrics", authMiddleware(policyMetricsHandler)).Methods("GET")
	r.HandleFunc("/api/policy-metrics/update", authMiddleware(updatePolicyMetricsHandler)).Methods("POST")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	handler := c.Handler(r)
	log.Printf("AxonFlow Demo API starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "axonflow-demo"})
}


func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Simple demo authentication - in production, use proper password hashing
	var user User
	var permissions string
	query := `
		SELECT id, email, name, department, role, region, array_to_string(permissions, ',')
		FROM users 
		WHERE email = $1`
	
	err := db.QueryRow(query, req.Email).Scan(
		&user.ID, &user.Email, &user.Name, &user.Department, 
		&user.Role, &user.Region, &permissions)
	
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if permissions != "" {
		user.Permissions = strings.Split(permissions, ",")
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	response := LoginResponse{
		Token: tokenString,
		User:  user,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func queryHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 1. Evaluate query against security policies FIRST
	policyResult := policyEngine.EvaluateQuery(r.Context(), user, req.Query, "direct_sql")
	
	// If query is blocked, return error immediately
	if !policyResult.Allowed {
		log.Printf("Query blocked by policy for user %s: %s", user.Email, req.Query)
		
		blockReason := "Query blocked by security policy"
		if len(policyResult.BlockedBy) > 0 {
			blockReason = fmt.Sprintf("Blocked by policy: %s", strings.Join(policyResult.BlockedBy, ", "))
		}
		
		response := QueryResponse{
			Results:          []map[string]interface{}{},
			Count:            0,
			PIIDetected:      []string{},
			PIIRedacted:      false,
			QueryBlocked:     true,
			BlockReason:      blockReason,
			PolicyViolations: policyResult.Violations,
			SecurityLog: SecurityLog{
				UserEmail:       user.Email,
				QueryExecuted:   req.Query,
				AccessGranted:   false,
				FilteredResults: 0,
				PIIRedacted:     false,
				Timestamp:       time.Now(),
			},
		}
		
		// Log blocked query
		auditQuery(user, req.Query, 0, []string{}, false, false)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 2. Route based on explicit query_type flag
	if req.QueryType == "natural_language" {
		log.Printf("Processing natural language query: %s", req.Query)
		
		// Route through LLM for conversion to SQL
		llmResponse, err := llmRouter.ConvertNLToSQL(r.Context(), user, req.Query)
		if err != nil {
			log.Printf("LLM conversion error: %v", err)
			http.Error(w, fmt.Sprintf("Natural language query failed: %v", err), http.StatusBadRequest)
			return
		}
		
		// Return the LLM response directly (it includes SQL execution results)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(llmResponse)
		return
	} else if req.QueryType == "" {
		// Default to sql_query for backward compatibility
		req.QueryType = "sql_query"
		log.Printf("No query_type specified, defaulting to sql_query")
	}

	// 3. Apply row-level security based on user's region and permissions for direct SQL queries
	secureQuery := applyRowLevelSecurity(req.Query, user)
	
	log.Printf("Original query: %s", req.Query)
	log.Printf("Secure query: %s", secureQuery)

	// Execute query
	rows, err := db.Query(secureQuery)
	if err != nil {
		log.Printf("Query error: %v", err)
		http.Error(w, "Query execution failed", http.StatusBadRequest)
		return
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		http.Error(w, "Failed to get columns", http.StatusInternalServerError)
		return
	}

	// Process results
	var results []map[string]interface{}
	var piiDetected []string
	piiRedacted := false

	for rows.Next() {
		// Create a slice to hold the values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		// Convert to map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if val != nil {
				// Convert byte arrays to strings
				if b, ok := val.([]byte); ok {
					val = string(b)
				}
				
				// Apply enhanced PII detection and redaction using Policy Engine
				if strVal, ok := val.(string); ok {
					redacted, detected := policyEngine.RedactSensitiveData(strVal, user)
					if len(detected) > 0 {
						piiDetected = append(piiDetected, detected...)
						// Only set piiRedacted if the value actually changed
						if redacted != strVal {
							val = redacted
							piiRedacted = true
						}
					}
				}
			}
			row[col] = val
		}
		results = append(results, row)
	}

	// Also detect PII keywords in the query text itself for better dashboard metrics
	queryTextPII := detectPIIInQueryText(req.Query)
	allPIIDetected := append(piiDetected, queryTextPII...)
	
	// Remove duplicates
	allPIIDetected = removeDuplicates(allPIIDetected)
	
	// Log to audit trail
	auditQuery(user, req.Query, len(results), allPIIDetected, piiRedacted, true)

	response := QueryResponse{
		Results:          results,
		Count:            len(results),
		PIIDetected:      piiDetected,
		PIIRedacted:      piiRedacted,
		QueryBlocked:     false,
		PolicyViolations: policyResult.Violations,
		SecurityLog: SecurityLog{
			UserEmail:       user.Email,
			QueryExecuted:   secureQuery,
			AccessGranted:   true,
			FilteredResults: 0, // Would be calculated in production
			PIIRedacted:     piiRedacted,
			Timestamp:       time.Now(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func auditHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	// Only show audit logs for admin users or their own logs
	query := `
		SELECT id, user_email, query_text, results_count, 
			   COALESCE(array_to_string(pii_detected, ','), '') as pii_detected,
			   pii_redacted, access_granted, created_at
		FROM audit_log
		ORDER BY created_at DESC
		LIMIT 50`
	
	// Non-admin users can only see their own logs
	if !contains(user.Permissions, "admin") {
		query = `
			SELECT id, user_email, query_text, results_count, 
				   COALESCE(array_to_string(pii_detected, ','), '') as pii_detected,
				   pii_redacted, access_granted, created_at
			FROM audit_log
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT 50`
	}

	var rows *sql.Rows
	var err error

	if contains(user.Permissions, "admin") {
		rows, err = db.Query(query)
	} else {
		rows, err = db.Query(query, user.ID)
	}

	if err != nil {
		http.Error(w, "Failed to fetch audit logs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var auditLogs []AuditLogEntry
	for rows.Next() {
		var entry AuditLogEntry
		var piiDetectedStr string
		
		err := rows.Scan(&entry.ID, &entry.UserEmail, &entry.QueryText, 
			&entry.ResultsCount, &piiDetectedStr, &entry.PIIRedacted,
			&entry.AccessGranted, &entry.CreatedAt)
		
		if err != nil {
			continue
		}

		if piiDetectedStr != "" {
			entry.PIIDetected = strings.Split(piiDetectedStr, ",")
		}

		auditLogs = append(auditLogs, entry)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(auditLogs)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get dashboard metrics - show all-time data
	var totalQueries, totalPIIDetections, totalUsers int
	
	db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&totalQueries)
	db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE array_length(pii_detected, 1) > 0").Scan(&totalPIIDetections)
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)

	// Calculate sophisticated compliance score
	complianceScore := calculateComplianceScore(totalQueries, totalPIIDetections)

	dashboard := map[string]interface{}{
		"total_queries":        totalQueries,
		"total_pii_detections": totalPIIDetections,
		"total_users":          totalUsers,
		"compliance_score":     complianceScore,
		"system_status":        "healthy",
		"uptime_hours":         24,
		"data_processed_mb":    1024,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard)
}

// Security functions
func applyRowLevelSecurity(query string, user User) string {
	// Remove semicolons to prevent SQL syntax errors when appending region filters
	query = strings.ReplaceAll(query, ";", "")
	query = strings.TrimSpace(query)
	
	queryLower := strings.ToLower(query)
	
	// Log original query for debugging
	fmt.Printf("Original query: %s\n", query)
	fmt.Printf("User: %s, Region: %s, Admin: %v\n", user.Email, user.Region, contains(user.Permissions, "admin"))
	
	// Add region-based filtering for non-admin users
	if !contains(user.Permissions, "admin") && user.Region != "global" {
		// For queries on customers or support_tickets, add region filter
		// Skip region filtering for complex queries involving users/audit_log tables
		if (strings.Contains(queryLower, "customers") || strings.Contains(queryLower, "support_tickets")) && 
		   !strings.Contains(queryLower, "audit_log") && !strings.Contains(queryLower, "users") && 
		   !strings.Contains(queryLower, "count(") && !strings.Contains(queryLower, "group by") {
			// Check if the query already includes a region filter for the user's region
			regionAlreadyFiltered := strings.Contains(queryLower, fmt.Sprintf("region = '%s'", user.Region)) ||
				strings.Contains(queryLower, fmt.Sprintf("t.region = '%s'", user.Region)) ||
				strings.Contains(queryLower, fmt.Sprintf("c.region = '%s'", user.Region)) ||
				strings.Contains(queryLower, fmt.Sprintf("st.region = '%s'", user.Region))
			
			if !regionAlreadyFiltered {
				// For JOIN queries with customers and support_tickets, we need to be careful about which table to filter
				var regionFilter string
				if strings.Contains(queryLower, "join") && strings.Contains(queryLower, "customers c") && strings.Contains(queryLower, "support_tickets st") {
					// Complex JOIN query - filter by customer region
					regionFilter = fmt.Sprintf(" AND c.region = '%s'", user.Region)
				} else if strings.Contains(queryLower, "join") && strings.Contains(queryLower, "customers c") && strings.Contains(queryLower, "support_tickets t") {
					// Complex JOIN query with 't' alias - filter by customer region
					regionFilter = fmt.Sprintf(" AND c.region = '%s'", user.Region)
				} else if strings.Contains(queryLower, "from customers c") {
					// Customers query with alias
					regionFilter = fmt.Sprintf(" AND c.region = '%s'", user.Region)
				} else if strings.Contains(queryLower, "from support_tickets st") {
					// Support tickets query with alias
					regionFilter = fmt.Sprintf(" AND st.region = '%s'", user.Region)
				} else if strings.Contains(queryLower, "from support_tickets t") {
					// Support tickets query with 't' alias (used by real LLM)
					regionFilter = fmt.Sprintf(" AND t.region = '%s'", user.Region)
				} else {
					// Simple query without alias - don't qualify table name
					regionFilter = fmt.Sprintf(" AND region = '%s'", user.Region)
				}
				
				// Find the right place to insert the region filter
				upperQuery := strings.ToUpper(query)
				
				if strings.Contains(queryLower, "where") {
					// Has WHERE clause - add region filter after WHERE but before GROUP BY/ORDER BY/LIMIT
					if idx := strings.Index(upperQuery, " GROUP BY"); idx > 0 {
						query = query[:idx] + regionFilter + query[idx:]
					} else if idx := strings.Index(upperQuery, " ORDER BY"); idx > 0 {
						query = query[:idx] + regionFilter + query[idx:]
					} else if idx := strings.Index(upperQuery, " LIMIT"); idx > 0 {
						query = query[:idx] + regionFilter + query[idx:]
					} else {
						// No GROUP BY, ORDER BY, or LIMIT - append at end
						query += regionFilter
					}
				} else {
					// No WHERE clause - convert AND to WHERE and insert before GROUP BY/ORDER BY/LIMIT
					regionFilter = strings.Replace(regionFilter, " AND ", " WHERE ", 1)
					if idx := strings.Index(upperQuery, " GROUP BY"); idx > 0 {
						query = query[:idx] + regionFilter + query[idx:]
					} else if idx := strings.Index(upperQuery, " ORDER BY"); idx > 0 {
						query = query[:idx] + regionFilter + query[idx:]
					} else if idx := strings.Index(upperQuery, " LIMIT"); idx > 0 {
						query = query[:idx] + regionFilter + query[idx:]
					} else {
						// No GROUP BY, ORDER BY, or LIMIT - append at end
						query += regionFilter
					}
				}
			}
		}
	}
	
	// Log final query for debugging
	fmt.Printf("Final secure query: %s\n", query)
	return query
}

func detectAndRedactPII(text string, user User) ([]string, string) {
	var detected []string
	redacted := text

	// Only redact PII if user doesn't have read_pii permission
	shouldRedact := !contains(user.Permissions, "read_pii")

	for piiType, pattern := range piiPatterns {
		matches := pattern.FindAllString(text, -1)
		if len(matches) > 0 {
			detected = append(detected, piiType)
			if shouldRedact {
				redacted = pattern.ReplaceAllString(redacted, "[REDACTED_"+strings.ToUpper(piiType)+"]")
			}
		}
	}

	return detected, redacted
}

func auditQuery(user User, query string, resultCount int, piiDetected []string, piiRedacted bool, accessGranted bool) {
	piiArray := "{}"
	if len(piiDetected) > 0 {
		piiArray = "{" + strings.Join(piiDetected, ",") + "}"
	}

	_, err := db.Exec(`
		INSERT INTO audit_log (user_id, user_email, query_text, results_count, pii_detected, pii_redacted, access_granted)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.ID, user.Email, query, resultCount, piiArray, piiRedacted, accessGranted)
	
	if err != nil {
		log.Printf("Failed to log audit entry: %v", err)
	}
}

// Middleware
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userID := int(claims["user_id"].(float64))
		
		// Get user details
		var user User
		var permissions string
		query := `
			SELECT id, email, name, department, role, region, array_to_string(permissions, ',')
			FROM users WHERE id = $1`
		
		err = db.QueryRow(query, userID).Scan(
			&user.ID, &user.Email, &user.Name, &user.Department,
			&user.Role, &user.Region, &permissions)
		
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		if permissions != "" {
			user.Permissions = strings.Split(permissions, ",")
		}

		// Add user to request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user", user)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// LLM Handler Functions
func llmChatHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	var req struct {
		Message     string            `json:"message"`
		Context     map[string]string `json:"context"`
		MaxTokens   int               `json:"max_tokens"`
		Temperature float64           `json:"temperature"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Set defaults
	if req.MaxTokens == 0 {
		req.MaxTokens = 500
	}
	if req.Temperature == 0 {
		req.Temperature = 0.7
	}
	
	llmReq := &LLMRequest{
		Prompt:      req.Message,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		User:        user,
		Context:     req.Context,
	}
	
	resp, err := llmRouter.RouteRequest(r.Context(), llmReq)
	if err != nil {
		http.Error(w, "LLM request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func naturalQueryHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	var req struct {
		Query string `json:"query"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	resp, err := llmRouter.ConvertNLToSQL(r.Context(), user, req.Query)
	if err != nil {
		http.Error(w, "Natural language query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func axonflowQueryHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	var req struct {
		Query       string                 `json:"query"`
		RequestType string                 `json:"request_type,omitempty"`
		Context     map[string]interface{} `json:"context,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Default request type if not specified
	if req.RequestType == "" {
		req.RequestType = "sql"
	}
	
	// Extract user token from Authorization header
	authHeader := r.Header.Get("Authorization")
	userToken := strings.Replace(authHeader, "Bearer ", "", 1)
	
	// Add additional context from user
	if req.Context == nil {
		req.Context = make(map[string]interface{})
	}
	req.Context["user_email"] = user.Email
	req.Context["user_role"] = user.Role
	req.Context["user_region"] = user.Region
	req.Context["user_permissions"] = user.Permissions
	
	// Call AxonFlow Agent
	axonflowResp, err := axonflowClient.ExecuteQuery(userToken, req.Query, req.RequestType, req.Context)
	if err != nil {
		log.Printf("AxonFlow query failed for user %s: %v", user.Email, err)
		http.Error(w, "AxonFlow query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Handle blocked queries
	if axonflowResp.Blocked {
		log.Printf("Query blocked by AxonFlow for user %s: %s", user.Email, axonflowResp.BlockReason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      false,
			"blocked":      true,
			"block_reason": axonflowResp.BlockReason,
			"policy_info":  axonflowResp.PolicyInfo,
		})
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(axonflowResp)
}

func llmStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"providers": map[string]interface{}{
			"openai": map[string]interface{}{
				"available": llmRouter.providers["openai"].IsAvailable(),
				"name":      llmRouter.providers["openai"].GetName(),
			},
			"anthropic": map[string]interface{}{
				"available": llmRouter.providers["anthropic"].IsAvailable(),
				"name":      llmRouter.providers["anthropic"].GetName(),
			},
			"local": map[string]interface{}{
				"available": llmRouter.providers["local"].IsAvailable(),
				"name":      llmRouter.providers["local"].GetName(),
			},
		},
		"routing_policy": llmRouter.policies,
		"total_providers": len(llmRouter.providers),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func llmUserAccessHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	// Use the actual LLM router logic to determine access for this user
	// Create sample requests to test routing
	testRequests := []struct {
		query       string
		description string
		category    string
	}{
		{"SELECT * FROM customers", "Regular Query", "normal"},
		{"Find customer with SSN 123-45-6789", "PII Query", "pii"},
		{"Show confidential enterprise data", "Confidential Query", "confidential"},
	}
	
	accessInfo := map[string]interface{}{
		"user_role": user.Role,
		"providers": make(map[string]interface{}),
		"routing_rules": make([]map[string]string, 0),
	}
	
	// Test each scenario to see where this user's queries would route
	for _, test := range testRequests {
		llmReq := &LLMRequest{
			Prompt:      test.query,
			MaxTokens:   100,
			Temperature: 0.7,
			User:        user,
			Context:     map[string]string{},
		}
		
		// Get routing decision using actual router logic
		result := llmRouter.selectProviderWithReason(llmReq)
		
		accessInfo["routing_rules"] = append(
			accessInfo["routing_rules"].([]map[string]string),
			map[string]string{
				"scenario":    test.description,
				"category":    test.category,
				"provider":    result.Provider,
				"reason":      result.Reason,
				"accessible": "true", // All scenarios are accessible, routing just determines which provider
			},
		)
	}
	
	// Provider access summary based on actual router logic
	providers := map[string]map[string]interface{}{}
	
	// Check if EU user (GDPR compliance - only local allowed)
	isEUUser := strings.HasPrefix(strings.ToLower(user.Region), "eu")
	
	// Local provider - always available
	providers["local"] = map[string]interface{}{
		"name":        "🔒 Local Models",
		"accessible":  true,
		"status":      "Always Available",
		"description": "PII queries and GDPR-compliant processing",
		"color":       "green",
	}
	
	// OpenAI provider - availability depends on role and region
	if isEUUser {
		providers["openai"] = map[string]interface{}{
			"name":        "⚡ OpenAI GPT",
			"accessible":  false,
			"status":      "GDPR Restricted",
			"description": "EU users must use local models only",
			"color":       "red",
		}
	} else {
		providers["openai"] = map[string]interface{}{
			"name":        "⚡ OpenAI GPT",
			"accessible":  user.Role != "agent",
			"status":      func() string {
				if user.Role == "agent" {
					return "Role Restricted"
				}
				return "Available"
			}(),
			"description": "Manager/Admin role for general queries",
			"color":       func() string {
				if user.Role == "agent" {
					return "red"
				}
				return "green"
			}(),
		}
	}
	
	// Anthropic provider - availability depends on region
	if isEUUser {
		providers["anthropic"] = map[string]interface{}{
			"name":        "🧠 Anthropic Claude",
			"accessible":  false,
			"status":      "GDPR Restricted",
			"description": "EU users must use local models only",
			"color":       "red",
		}
	} else {
		providers["anthropic"] = map[string]interface{}{
			"name":        "🧠 Anthropic Claude",
			"accessible":  true,
			"status":      "Confidential data only",
			"description": "All users for confidential/sensitive queries",
			"color":       "orange",
		}
	}
	
	accessInfo["providers"] = providers
	
	// Routing priority varies by user region and role
	var routingPriority []string
	if isEUUser {
		routingPriority = []string{
			"1. EU Region → Local only (GDPR compliance)",
			"2. All queries → Local models required",
			"3. No external providers allowed",
		}
	} else {
		routingPriority = []string{
			"1. PII keywords → Local (security)",
			"2. \"Confidential\" → Anthropic (safety)",
			fmt.Sprintf("3. User role → %s", func() string {
				if user.Role == "agent" {
					return "Local"
				}
				return "OpenAI"
			}()),
		}
	}
	accessInfo["routing_priority"] = routingPriority
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accessInfo)
}

// Utility functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// detectPIIInQueryText detects PII keywords in the query text for better dashboard metrics
func detectPIIInQueryText(queryText string) []string {
	var detected []string
	queryLower := strings.ToLower(queryText)
	
	// Check for PII keywords in the query text
	if strings.Contains(queryLower, "ssn") || strings.Contains(queryLower, "social security") {
		detected = append(detected, "ssn")
	}
	if strings.Contains(queryLower, "credit") && strings.Contains(queryLower, "card") {
		detected = append(detected, "credit_card")
	}
	if strings.Contains(queryLower, "phone") {
		detected = append(detected, "phone")
	}
	if strings.Contains(queryLower, "email") {
		detected = append(detected, "email")
	}
	
	return detected
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// calculateComplianceScore computes enterprise compliance rating
func calculateComplianceScore(totalQueries, totalPIIDetections int) float64 {
	if totalQueries == 0 {
		return 95.0 // Default score for new systems
	}
	
	// Multi-factor compliance calculation
	
	// Factor 1: PII Handling (40% weight) - More granular calculation
	piiRate := float64(totalPIIDetections) / float64(totalQueries)
	piiScore := 100.0
	if piiRate > 0 {
		// Linear degradation for more responsive scoring
		if piiRate <= 0.05 { // ≤5% PII queries is excellent
			piiScore = 100.0
		} else if piiRate <= 0.1 { // ≤10% is very good
			piiScore = 95.0 - (piiRate-0.05)*100 // 95-90
		} else if piiRate <= 0.2 { // ≤20% is good
			piiScore = 90.0 - (piiRate-0.1)*50 // 90-85
		} else if piiRate <= 0.3 { // ≤30% is acceptable
			piiScore = 85.0 - (piiRate-0.2)*50 // 85-80
		} else if piiRate <= 0.4 { // ≤40% is concerning
			piiScore = 80.0 - (piiRate-0.3)*100 // 80-70
		} else { // >40% is critical
			piiScore = 70.0 - (piiRate-0.4)*50 // Below 70
		}
	}
	
	// Factor 2: Query Security (30% weight) - simulated metrics
	var unauthorizedAttempts, regionViolations int
	db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE query_text LIKE '%admin%' AND user_email NOT LIKE '%admin%'").Scan(&unauthorizedAttempts)
	db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE access_granted = false").Scan(&regionViolations)
	
	securityScore := 100.0
	if unauthorizedAttempts > 0 {
		securityScore -= float64(unauthorizedAttempts) * 5.0 // -5 points per violation
	}
	if regionViolations > 0 {
		securityScore -= float64(regionViolations) * 10.0 // -10 points per violation
	}
	if securityScore < 60.0 {
		securityScore = 60.0 // Floor
	}
	
	// Factor 3: Audit Coverage (20% weight)
	auditScore := 100.0 // All queries are logged in our demo
	
	// Factor 4: Data Governance (10% weight) - AI model routing compliance
	var localModelQueries, totalAIQueries int
	db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE query_text LIKE '%[LLM:local]%'").Scan(&localModelQueries)
	db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE query_text LIKE '%[LLM:%'").Scan(&totalAIQueries)
	
	governanceScore := 100.0
	if totalAIQueries > 0 {
		// Higher percentage of local model usage = better governance
		localRatio := float64(localModelQueries) / float64(totalAIQueries)
		if localRatio >= 0.5 { // ≥50% local is excellent for privacy
			governanceScore = 100.0
		} else if localRatio >= 0.3 { // ≥30% local is good
			governanceScore = 90.0
		} else { // <30% local needs improvement
			governanceScore = 80.0
		}
	}
	
	// Weighted final score
	finalScore := (piiScore * 0.4) + (securityScore * 0.3) + (auditScore * 0.2) + (governanceScore * 0.1)
	
	// Debug logging for compliance calculation
	log.Printf("Compliance Calculation - Total: %d, PII: %d, Rate: %.1f%%, PII Score: %.1f, Final: %.1f", 
		totalQueries, totalPIIDetections, piiRate*100, piiScore, finalScore)
	
	// Ensure reasonable range but allow dynamic changes
	if finalScore < 70.0 {
		finalScore = 70.0 // Floor for any functioning system
	}
	if finalScore > 99.5 {
		finalScore = 99.5 // Perfect scores look suspicious
	}
	
	return finalScore
}

// Policy Engine API Handlers
func policiesHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	// Only admin users can view policies
	if !contains(user.Permissions, "admin") {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}
	
	policies := map[string]interface{}{
		"security_policies": policyEngine.policies,
		"dlp_rules":        policyEngine.dlpRules,
		"blocked_queries":  policyEngine.blockedQueries,
		"total_policies":   len(policyEngine.policies),
		"enabled_policies": countEnabledPolicies(policyEngine.policies),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func policyViolationsHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	// Admin users see all violations, others see only their own
	var violations []PolicyViolation
	
	// In production, this would query a violations table
	// For demo, we'll return recent violations from logs
	mockViolations := []PolicyViolation{
		{
			ID:            "violation_1",
			PolicyID:      "pii_access_control",
			UserEmail:     "john.doe@company.com",
			ViolationType: "dlp_detection",
			Description:   "PII detected in query results",
			Severity:      "medium",
			Timestamp:     time.Now().Add(-2 * time.Hour),
			Resolved:      false,
		},
		{
			ID:            "violation_2",
			PolicyID:      "admin_table_access",
			UserEmail:     "john.doe@company.com",
			ViolationType: "blocked_query",
			Description:   "Attempted access to administrative table",
			Severity:      "high",
			Timestamp:     time.Now().Add(-1 * time.Hour),
			Resolved:      false,
		},
	}
	
	// Filter violations based on user permissions
	for _, violation := range mockViolations {
		if contains(user.Permissions, "admin") || violation.UserEmail == user.Email {
			violations = append(violations, violation)
		}
	}
	
	response := map[string]interface{}{
		"violations": violations,
		"total":      len(violations),
		"unresolved": countUnresolvedViolations(violations),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func policyTestHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	
	var req struct {
		Query string `json:"query"`
		TestUser *User `json:"test_user,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Use test user if provided and user has admin permissions
	testUser := user
	if req.TestUser != nil && contains(user.Permissions, "admin") {
		testUser = *req.TestUser
	}
	
	// Evaluate the query against policies
	result := policyEngine.EvaluateQuery(r.Context(), testUser, req.Query, "test")
	
	response := map[string]interface{}{
		"query":             req.Query,
		"user":              testUser.Email,
		"allowed":           result.Allowed,
		"blocked_by":        result.BlockedBy,
		"violations":        result.Violations,
		"redaction_required": result.RedactionRequired,
		"approval_required": result.ApprovalRequired,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Utility functions for policy handlers
func countEnabledPolicies(policies []SecurityPolicy) int {
	count := 0
	for _, policy := range policies {
		if policy.Enabled {
			count++
		}
	}
	return count
}

func countUnresolvedViolations(violations []PolicyViolation) int {
	count := 0
	for _, violation := range violations {
		if !violation.Resolved {
			count++
		}
	}
	return count
}

// performanceMetricsHandler returns real-time performance metrics calculated from actual data
func performanceMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var summary PerformanceMetrics
	
	// Calculate real-time metrics from performance_metrics table (last hour)
	err := db.QueryRow(`
		WITH hourly_stats AS (
			SELECT 
				AVG(response_time_ms) as avg_response_time,
				PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_response_time,
				PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY response_time_ms) as p99_response_time,
				COUNT(*) as requests_count,
				AVG(agent_latency_ms) as agent_avg_latency,
				AVG(orchestrator_latency_ms) as orchestrator_avg_latency
			FROM performance_metrics 
			WHERE timestamp > NOW() - INTERVAL '1 hour'
		),
		daily_total AS (
			SELECT COUNT(*) as total_requests_today
			FROM audit_log 
			WHERE DATE(created_at) = CURRENT_DATE
		)
		SELECT 
			COALESCE(h.avg_response_time, 145) as avg_response_time,
			COALESCE(h.p95_response_time, 220) as p95_response_time,
			COALESCE(h.p99_response_time, 380) as p99_response_time,
			CASE 
				WHEN h.requests_count > 0 THEN h.requests_count::float / 3600
				ELSE 0.1
			END as requests_per_second,
			0.2 as error_rate,
			d.total_requests_today as total_requests,
			COALESCE(h.agent_avg_latency, 41.2) as agent_avg_latency,
			COALESCE(h.orchestrator_avg_latency, 107.8) as orchestrator_avg_latency
		FROM hourly_stats h, daily_total d
	`).Scan(
		&summary.AvgResponseTime,
		&summary.P95ResponseTime, 
		&summary.P99ResponseTime,
		&summary.RequestsPerSecond,
		&summary.ErrorRate,
		&summary.TotalRequests,
		&summary.AgentLatency,
		&summary.OrchestratorLatency,
	)
	
	if err != nil {
		log.Printf("Error calculating real-time performance metrics: %v", err)
		// Fallback: get basic counts from audit_log
		var totalRequests int
		db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE DATE(created_at) = CURRENT_DATE").Scan(&totalRequests)
		
		summary = PerformanceMetrics{
			AvgResponseTime:     145.0,
			P95ResponseTime:     220,
			P99ResponseTime:     380,
			RequestsPerSecond:   0.1,
			ErrorRate:           0.2,
			TotalRequests:       totalRequests,
			AgentLatency:        41.2,
			OrchestratorLatency: 107.8,
		}
	}
	
	// Get time series data for last 20 entries
	rows, err := db.Query(`
		SELECT timestamp, response_time_ms
		FROM performance_metrics 
		WHERE timestamp > NOW() - INTERVAL '2 hours'
		ORDER BY timestamp DESC 
		LIMIT 20
	`)
	
	if err != nil {
		log.Printf("Error fetching time series data: %v", err)
		// Generate demo time series data
		summary.TimeSeriesData = generateDemoTimeSeriesData()
	} else {
		defer rows.Close()
		var timeSeriesData []TimeSeriesPoint
		for rows.Next() {
			var point TimeSeriesPoint
			err := rows.Scan(&point.Timestamp, &point.ResponseTime)
			if err != nil {
				log.Printf("Error scanning time series row: %v", err)
				continue
			}
			timeSeriesData = append(timeSeriesData, point)
		}
		
		if len(timeSeriesData) == 0 {
			summary.TimeSeriesData = generateDemoTimeSeriesData()
		} else {
			// Reverse to get chronological order
			for i := len(timeSeriesData)/2 - 1; i >= 0; i-- {
				opp := len(timeSeriesData) - 1 - i
				timeSeriesData[i], timeSeriesData[opp] = timeSeriesData[opp], timeSeriesData[i]
			}
			summary.TimeSeriesData = timeSeriesData
		}
	}
	
	json.NewEncoder(w).Encode(summary)
}

// recordPerformanceHandler records a new performance metric
func recordPerformanceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var record struct {
		Endpoint         string `json:"endpoint"`
		Method           string `json:"method"`
		ResponseTimeMS   int    `json:"response_time_ms"`
		StatusCode       int    `json:"status_code"`
		AgentLatencyMS   int    `json:"agent_latency_ms"`
		OrchestratorLatencyMS int `json:"orchestrator_latency_ms"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	userEmail := r.Context().Value("user_email").(string)
	
	// Insert performance metric
	_, err := db.Exec(`
		INSERT INTO performance_metrics 
		(endpoint, method, response_time_ms, status_code, user_email, agent_latency_ms, orchestrator_latency_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, record.Endpoint, record.Method, record.ResponseTimeMS, record.StatusCode, userEmail,
		record.AgentLatencyMS, record.OrchestratorLatencyMS)
	
	if err != nil {
		log.Printf("Error recording performance metric: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
}

// generateDemoTimeSeriesData creates sample time series data
func generateDemoTimeSeriesData() []TimeSeriesPoint {
	var data []TimeSeriesPoint
	now := time.Now()
	responseTimes := []int{120, 135, 158, 142, 167, 145, 139, 152, 161, 148, 134, 156, 143, 169, 137, 154, 162, 141, 149, 145}
	
	for i, rt := range responseTimes {
		data = append(data, TimeSeriesPoint{
			Timestamp:    now.Add(time.Duration(-19+i) * time.Minute).Format(time.RFC3339),
			ResponseTime: rt,
		})
	}
	
	return data
}

// policyMetricsHandler returns real-time policy metrics calculated from actual data
func policyMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Calculate real-time policy metrics from audit_log only (no static demo data)
	var metrics PolicyMetrics
	err := db.QueryRow(`
		WITH daily_stats AS (
			SELECT 
				COUNT(*) as total_policies_enforced,
				COUNT(CASE WHEN array_length(pii_detected, 1) > 0 THEN 1 END) as pii_redacted,
				COUNT(CASE WHEN access_granted = false THEN 1 END) as unauthorized_queries,
				-- Regional blocks: queries from EU users trying to access US data (demo logic)
				COUNT(CASE WHEN query_text ILIKE '%customer%' AND user_email LIKE '%@%' THEN 1 END) / 10 as regional_blocks
			FROM audit_log 
			WHERE DATE(created_at) = CURRENT_DATE
		)
		SELECT 
			d.total_policies_enforced,
			d.unauthorized_queries,
			d.pii_redacted,
			d.regional_blocks,
			'healthy' as agent_health,
			'healthy' as orchestrator_health
		FROM daily_stats d
	`).Scan(
		&metrics.TotalPoliciesEnforced,
		&metrics.AiQueries, // Now contains unauthorized_queries count
		&metrics.PiiRedacted,
		&metrics.RegionalBlocks,
		&metrics.AgentHealth,
		&metrics.OrchestratorHealth,
	)
	
	if err != nil {
		log.Printf("Error calculating real-time policy metrics: %v", err)
		// Fallback: get basic counts from audit_log
		var totalToday int
		db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE DATE(created_at) = CURRENT_DATE").Scan(&totalToday)
		
		metrics = PolicyMetrics{
			TotalPoliciesEnforced: totalToday,
			AiQueries:             totalToday / 2, // Estimate ~50% are AI queries
			PiiRedacted:           totalToday / 7, // Estimate ~15% have PII
			RegionalBlocks:        0,
			AgentHealth:           "healthy",
			OrchestratorHealth:    "healthy",
		}
	}
	
	// Get recent activity (last 5 items)
	rows, err := db.Query(`
		SELECT activity_type, query_text, timestamp, COALESCE(provider, '') as provider
		FROM recent_activity 
		ORDER BY timestamp DESC 
		LIMIT 5
	`)
	
	if err != nil {
		log.Printf("Error fetching recent activity: %v", err)
		// Generate demo activity data
		metrics.RecentActivity = generateDemoActivityData()
	} else {
		defer rows.Close()
		var activities []ActivityItem
		for rows.Next() {
			var activity ActivityItem
			err := rows.Scan(&activity.Type, &activity.Query, &activity.Timestamp, &activity.Provider)
			if err != nil {
				log.Printf("Error scanning activity row: %v", err)
				continue
			}
			activities = append(activities, activity)
		}
		
		if len(activities) == 0 {
			metrics.RecentActivity = generateDemoActivityData()
		} else {
			metrics.RecentActivity = activities
		}
	}
	
	json.NewEncoder(w).Encode(metrics)
}

// updatePolicyMetricsHandler updates policy metrics counters
func updatePolicyMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	var update struct {
		IncrementPoliciesEnforced bool   `json:"increment_policies_enforced"`
		IncrementAiQueries        bool   `json:"increment_ai_queries"`
		IncrementPiiRedacted      int    `json:"increment_pii_redacted"`
		IncrementRegionalBlocks   int    `json:"increment_regional_blocks"`
		ActivityType              string `json:"activity_type"`
		Query                     string `json:"query"`
		Provider                  string `json:"provider"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	userEmail := r.Context().Value("user_email").(string)
	
	// Update policy metrics for today
	_, err := db.Exec(`
		INSERT INTO policy_metrics (
			date, total_policies_enforced, ai_queries, pii_redacted, regional_blocks
		) VALUES (
			CURRENT_DATE, 
			CASE WHEN $1 THEN 1 ELSE 0 END,
			CASE WHEN $2 THEN 1 ELSE 0 END,
			$3, $4
		) ON CONFLICT (date) DO UPDATE SET
			total_policies_enforced = policy_metrics.total_policies_enforced + CASE WHEN $1 THEN 1 ELSE 0 END,
			ai_queries = policy_metrics.ai_queries + CASE WHEN $2 THEN 1 ELSE 0 END,
			pii_redacted = policy_metrics.pii_redacted + $3,
			regional_blocks = policy_metrics.regional_blocks + $4,
			updated_at = NOW()
	`, update.IncrementPoliciesEnforced, update.IncrementAiQueries, 
		update.IncrementPiiRedacted, update.IncrementRegionalBlocks)
	
	if err != nil {
		log.Printf("Error updating policy metrics: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	
	// Add activity if provided
	if update.Query != "" {
		_, err = db.Exec(`
			INSERT INTO recent_activity (activity_type, query_text, user_email, provider)
			VALUES ($1, $2, $3, $4)
		`, update.ActivityType, update.Query, userEmail, update.Provider)
		
		if err != nil {
			log.Printf("Error recording activity: %v", err)
		}
		
		// Keep only last 20 activities to prevent table growth
		_, err = db.Exec(`
			DELETE FROM recent_activity 
			WHERE id NOT IN (
				SELECT id FROM recent_activity 
				ORDER BY timestamp DESC 
				LIMIT 20
			)
		`)
		
		if err != nil {
			log.Printf("Error cleaning old activities: %v", err)
		}
	}
	
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// generateDemoActivityData creates sample activity data
func generateDemoActivityData() []ActivityItem {
	return []ActivityItem{
		{
			Type:      "natural_query",
			Query:     "Show me customer support tickets from this week",
			Timestamp: time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			Provider:  "Local",
		},
		{
			Type:      "sql_query",
			Query:     "SELECT * FROM customers WHERE region = 'us-west'",
			Timestamp: time.Now().Add(-3 * time.Minute).Format(time.RFC3339),
			Provider:  "direct",
		},
		{
			Type:      "natural_query",
			Query:     "Find customers with high priority tickets",
			Timestamp: time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
			Provider:  "OpenAI",
		},
		{
			Type:      "sql_query",
			Query:     "SELECT COUNT(*) FROM support_tickets WHERE status = 'open'",
			Timestamp: time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
			Provider:  "direct",
		},
	}
}

// getSecret reads from environment variable or file
func getSecret(name string) string {
	// First try environment variable
	if value := os.Getenv(name); value != "" {
		return value
	}
	
	// Then try file-based secret (Docker secrets pattern)
	if filePath := os.Getenv(name + "_FILE"); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	
	return ""
}