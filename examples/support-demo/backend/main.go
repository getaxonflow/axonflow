// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Support Demo Backend - Refactored to use AxonFlow Proxy Mode
//
// This demo showcases AxonFlow's AI governance capabilities:
// - Policy enforcement via AxonFlow Agent
// - LLM request governance (OpenAI/Anthropic routed through AxonFlow)
// - Audit logging handled by AxonFlow
// - PII detection and redaction
//
// The demo maintains its own PostgreSQL database for demo data (customers, tickets)
// but delegates all LLM governance to AxonFlow.

package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	_ "github.com/lib/pq"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Configuration
var (
	db             *sql.DB
	jwtSecret      = []byte(os.Getenv("JWT_SECRET"))
	axonflowClient *axonflow.AxonFlowClient
)

// User represents a demo user with role-based permissions
type User struct {
	ID          int      `json:"id"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Department  string   `json:"department"`
	Role        string   `json:"role"`
	Region      string   `json:"region"`
	Permissions []string `json:"permissions"`
}

// QueryRequest represents an incoming query request
type QueryRequest struct {
	Query     string `json:"query"`
	QueryType string `json:"query_type"` // "natural_language" or "sql_query"
}

// QueryResponse represents the response to a query
type QueryResponse struct {
	Results      []map[string]interface{} `json:"results"`
	Count        int                      `json:"count"`
	QueryBlocked bool                     `json:"query_blocked"`
	BlockReason  string                   `json:"block_reason,omitempty"`
	LLMProvider  string                   `json:"llm_provider,omitempty"`
	SecurityLog  SecurityLog              `json:"security_log"`
}

// SecurityLog captures query execution metadata
type SecurityLog struct {
	UserEmail     string    `json:"user_email"`
	QueryExecuted string    `json:"query_executed"`
	AccessGranted bool      `json:"access_granted"`
	Timestamp     time.Time `json:"timestamp"`
}

// LoginRequest for authentication
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse with JWT token
type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// DashboardStats for the demo dashboard
type DashboardStats struct {
	TotalCustomers     int     `json:"total_customers"`
	OpenTickets        int     `json:"open_tickets"`
	ResolvedToday      int     `json:"resolved_today"`
	AvgResponseTime    int     `json:"avg_response_time"`
	TotalQueries       int     `json:"total_queries"`
	TotalPIIDetections int     `json:"total_pii_detections"`
	TotalUsers         int     `json:"total_users"`
	ComplianceScore    float64 `json:"compliance_score"`
}

// Demo users - in production these would come from a database
var demoUsers = map[string]User{
	"john.doe@company.com": {
		ID: 1, Email: "john.doe@company.com", Name: "John Doe",
		Department: "support", Role: "agent", Region: "us-west",
		Permissions: []string{"read_customers", "read_tickets"},
	},
	"sarah.manager@company.com": {
		ID: 2, Email: "sarah.manager@company.com", Name: "Sarah Manager",
		Department: "support", Role: "manager", Region: "us-east",
		Permissions: []string{"read_customers", "read_tickets", "read_pii", "escalate"},
	},
	"admin@company.com": {
		ID: 3, Email: "admin@company.com", Name: "Admin User",
		Department: "admin", Role: "admin", Region: "global",
		Permissions: []string{"read_customers", "read_tickets", "read_pii", "admin", "write"},
	},
}

func runMigrations(db *sql.DB) error {
	log.Println("Running database migrations...")

	// Check if tables exist
	var tableExists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_name = 'users'
		)
	`).Scan(&tableExists)
	if err != nil {
		return fmt.Errorf("failed to check if tables exist: %w", err)
	}

	if tableExists {
		log.Println("Database schema already exists, skipping migrations")
		return nil
	}

	// Read migration files
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var migrationFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			migrationFiles = append(migrationFiles, entry.Name())
		}
	}
	sort.Strings(migrationFiles)

	log.Printf("Applying %d migration files...", len(migrationFiles))

	for _, filename := range migrationFiles {
		content, err := migrationsFS.ReadFile("migrations/" + filename)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", filename, err)
		}

		start := time.Now()
		_, err = db.Exec(string(content))
		if err != nil {
			if strings.Contains(err.Error(), "already exists") {
				log.Printf("Skipping migration %s (objects already exist)", filename)
				continue
			}
			return fmt.Errorf("failed to execute migration %s: %w", filename, err)
		}
		log.Printf("Applied migration %s (%v)", filename, time.Since(start))
	}

	log.Println("Database migrations completed")
	return nil
}

func main() {
	// Database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://axonflow:axonflow_demo@localhost:5432/support_demo?sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Wait for database to be ready
	for i := 0; i < 30; i++ {
		err = db.Ping()
		if err == nil {
			break
		}
		log.Printf("Waiting for database... (%d/30)", i+1)
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatalf("Database not available: %v", err)
	}
	log.Println("Connected to database successfully")

	// Run migrations
	if err := runMigrations(db); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	// Initialize AxonFlow Client for Proxy Mode
	agentURL := os.Getenv("AXONFLOW_ENDPOINT")
	if agentURL == "" {
		agentURL = "http://host.docker.internal:8080"
	}

	axonflowClient = axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL: agentURL,
		Mode:     "production", // Fail-open if AxonFlow is unavailable
		Debug:    os.Getenv("AXONFLOW_DEBUG") == "true",
		Retry: axonflow.RetryConfig{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: time.Second,
		},
	})
	log.Printf("AxonFlow Client initialized (endpoint: %s, mode: proxy)", agentURL)

	// Setup router
	r := mux.NewRouter()

	// CORS configuration
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:3001"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// API Routes
	r.HandleFunc("/api/health", healthHandler).Methods("GET")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/dashboard", authMiddleware(dashboardHandler)).Methods("GET")
	r.HandleFunc("/api/query", authMiddleware(queryHandler)).Methods("POST")
	r.HandleFunc("/api/llm/chat", authMiddleware(llmChatHandler)).Methods("POST")
	r.HandleFunc("/api/llm/natural-query", authMiddleware(naturalQueryHandler)).Methods("POST")
	r.HandleFunc("/api/llm/status", authMiddleware(llmStatusHandler)).Methods("GET")
	r.HandleFunc("/api/llm/user-access", authMiddleware(userAccessHandler)).Methods("GET")
	r.HandleFunc("/api/audit", authMiddleware(auditStubHandler)).Methods("GET")
	r.HandleFunc("/api/policy-metrics", authMiddleware(policyMetricsStubHandler)).Methods("GET")
	r.HandleFunc("/api/policy-metrics/update", authMiddleware(stubHandler)).Methods("POST")
	r.HandleFunc("/api/performance/metrics", authMiddleware(performanceStubHandler)).Methods("GET")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	handler := c.Handler(r)
	log.Printf("Support Demo API starting on port %s (AxonFlow Proxy Mode)", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

// healthHandler returns service health status
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "axonflow-demo",
	})
}

// loginHandler authenticates demo users
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, exists := demoUsers[req.Email]
	// Accept both demo passwords for flexibility
	validPassword := req.Password == "demo123" || req.Password == "AxonFlow2024Demo!"
	if !exists || !validPassword {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{Token: tokenString, User: user})
}

// isLikelySQL checks if the query looks like SQL
func isLikelySQL(query string) bool {
	upper := strings.ToUpper(strings.TrimSpace(query))
	sqlKeywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "TRUNCATE", "SHOW", "DESCRIBE", "EXPLAIN"}
	for _, kw := range sqlKeywords {
		if strings.HasPrefix(upper, kw) {
			return true
		}
	}
	return false
}

// isDangerousQuery provides basic local safety check for demo
func isDangerousQuery(query string) (bool, string) {
	upper := strings.ToUpper(strings.TrimSpace(query))
	dangerousOps := map[string]string{
		"DROP":     "DROP operations are not allowed - data protection policy",
		"DELETE":   "DELETE operations require manager approval",
		"TRUNCATE": "TRUNCATE operations are not allowed - data protection policy",
		"ALTER":    "Schema modifications are not allowed",
	}
	for kw, reason := range dangerousOps {
		if strings.HasPrefix(upper, kw) {
			return true, reason
		}
	}
	return false, ""
}

// queryHandler processes SQL and natural language queries
func queryHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userToken := extractBearerToken(r)

	// Auto-detect query type if not specified
	queryType := req.QueryType
	if queryType == "" {
		if isLikelySQL(req.Query) {
			queryType = "sql"
		} else {
			queryType = "natural_language"
		}
	}

	// Handle natural language queries via AxonFlow LLM
	if queryType == "natural_language" {
		handleNaturalLanguageQuery(w, r, user, req.Query)
		return
	}

	// Basic local safety check (demo fallback when AxonFlow unavailable)
	if dangerous, reason := isDangerousQuery(req.Query); dangerous {
		log.Printf("Query blocked by local policy for %s: %s", user.Email, reason)
		respondWithBlocked(w, user, req.Query, reason)
		return
	}

	// Route SQL through AxonFlow for policy enforcement
	axonResp, err := axonflowClient.ExecuteQuery(
		userToken,
		req.Query,
		"sql",
		map[string]interface{}{
			"user_email":       user.Email,
			"user_role":        user.Role,
			"user_region":      user.Region,
			"user_permissions": user.Permissions,
		},
	)

	if err != nil {
		log.Printf("AxonFlow check failed (fail-open): %v", err)
		// Continue with fail-open strategy
	} else if axonResp.Blocked {
		log.Printf("Query blocked by AxonFlow for %s: %s", user.Email, axonResp.BlockReason)
		respondWithBlocked(w, user, req.Query, axonResp.BlockReason)
		return
	}

	// Execute SQL query
	results, err := executeSQL(req.Query)
	if err != nil {
		log.Printf("SQL execution error: %v", err)
		http.Error(w, "Query execution failed", http.StatusBadRequest)
		return
	}

	respondWithResults(w, user, req.Query, results, "")
}

// handleNaturalLanguageQuery converts NL to SQL via AxonFlow
func handleNaturalLanguageQuery(w http.ResponseWriter, r *http.Request, user User, query string) {
	userToken := extractBearerToken(r)

	prompt := fmt.Sprintf(`Convert this natural language query to SQL for a customer support database.

Database schema:
- customers (id, name, email, phone, region, support_tier, created_at)
- support_tickets (id, customer_id, title, description, status, priority, region, assigned_to, created_at, resolved_at)

User query: %s

Return only the SQL query, no explanation.`, query)

	resp, err := axonflowClient.ExecuteQuery(
		userToken,
		prompt,
		"chat",
		map[string]interface{}{
			"user_email":       user.Email,
			"user_role":        user.Role,
			"user_region":      user.Region,
			"user_permissions": user.Permissions,
			"task":             "nl_to_sql",
		},
	)

	if err != nil {
		log.Printf("AxonFlow NL query failed: %v", err)
		http.Error(w, "Natural language processing unavailable", http.StatusServiceUnavailable)
		return
	}

	log.Printf("[DEBUG] Response - Success: %v, Blocked: %v, BlockReason: %s", resp.Success, resp.Blocked, resp.BlockReason)

	// Check for blocked response - SDK v1.5.0 may not properly unmarshal blocked field
	// So we also check the Error field which may contain block reason
	blocked := resp.Blocked
	blockReason := resp.BlockReason

	// Also check if response indicates block through Error field or failed Success
	if !blocked && resp.Error != "" && (strings.Contains(resp.Error, "blocked") ||
		strings.Contains(resp.Error, "detected") || strings.Contains(resp.Error, "injection")) {
		blocked = true
		blockReason = resp.Error
	}

	if blocked || (!resp.Success && blockReason != "") {
		respondWithBlocked(w, user, query, blockReason)
		return
	}

	// Extract result from response - check both Result field and nested Data field
	result := resp.Result
	if result == "" && resp.Data != nil {
		// Try to extract from nested data.data field
		if dataMap, ok := resp.Data.(map[string]interface{}); ok {
			if nestedData, exists := dataMap["data"].(string); exists {
				result = nestedData
				log.Printf("[DEBUG] Extracted result from data.data field (length: %d)", len(result))
			}
		}
	}

	// Extract and execute generated SQL
	sqlQuery := extractSQL(result)
	if sqlQuery == "" {
		log.Printf("[DEBUG] Could not extract SQL. Result: %s", result)
		http.Error(w, "Could not generate SQL from query", http.StatusBadRequest)
		return
	}

	results, err := executeSQL(sqlQuery)
	if err != nil {
		log.Printf("Generated SQL error: %v", err)
		http.Error(w, "Generated query execution failed", http.StatusBadRequest)
		return
	}

	respondWithResults(w, user, sqlQuery, results, "axonflow")
}

// llmChatHandler processes chat messages via AxonFlow
func llmChatHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userToken := extractBearerToken(r)

	resp, err := axonflowClient.ExecuteQuery(
		userToken,
		req.Message,
		"chat",
		map[string]interface{}{
			"user_email":  user.Email,
			"user_role":   user.Role,
			"user_region": user.Region,
		},
	)

	if err != nil {
		log.Printf("AxonFlow chat failed: %v", err)
		http.Error(w, "Chat service unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.Blocked {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"blocked":      true,
			"block_reason": resp.BlockReason,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"response": resp.Result,
		"provider": "axonflow",
	})
}

// naturalQueryHandler is an alias for NL query processing
func naturalQueryHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)

	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	handleNaturalLanguageQuery(w, r, user, req.Query)
}

// llmStatusHandler returns LLM provider status
func llmStatusHandler(w http.ResponseWriter, r *http.Request) {
	err := axonflowClient.HealthCheck()
	axonflowHealthy := err == nil

	status := map[string]interface{}{
		"axonflow": map[string]interface{}{
			"healthy":  axonflowHealthy,
			"endpoint": os.Getenv("AXONFLOW_ENDPOINT"),
		},
		"providers": map[string]interface{}{
			"openai": map[string]interface{}{
				"configured": os.Getenv("OPENAI_API_KEY") != "",
				"name":       "OpenAI GPT-4",
			},
			"anthropic": map[string]interface{}{
				"configured": os.Getenv("ANTHROPIC_API_KEY") != "",
				"name":       "Anthropic Claude",
			},
		},
		"mode": "proxy",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// dashboardHandler returns demo dashboard statistics
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	var stats DashboardStats

	db.QueryRow("SELECT COUNT(*) FROM customers").Scan(&stats.TotalCustomers)
	db.QueryRow("SELECT COUNT(*) FROM support_tickets WHERE status != 'resolved'").Scan(&stats.OpenTickets)
	db.QueryRow("SELECT COUNT(*) FROM support_tickets WHERE resolved_at::date = CURRENT_DATE").Scan(&stats.ResolvedToday)
	stats.AvgResponseTime = 45 // Demo value in minutes

	// Query policy metrics from database
	db.QueryRow("SELECT COALESCE(total_policies_enforced, 0), COALESCE(pii_redacted, 0) FROM policy_metrics WHERE date = CURRENT_DATE").Scan(&stats.TotalQueries, &stats.TotalPIIDetections)

	// Count unique demo users
	stats.TotalUsers = len(demoUsers)

	// Calculate compliance score (100% - (blocked queries / total queries) * 100)
	if stats.TotalQueries > 0 {
		stats.ComplianceScore = 98.5 // Demo value - in production calculate from actual blocks
	} else {
		stats.ComplianceScore = 100.0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// authMiddleware validates JWT tokens and injects user context
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractBearerToken(r)
		if tokenString == "" {
			http.Error(w, "No authorization header", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			http.Error(w, "Invalid email claim", http.StatusUnauthorized)
			return
		}

		user, exists := demoUsers[email]
		if !exists {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Helper functions

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return auth
}

func executeSQL(query string) ([]map[string]interface{}, error) {
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				val = string(b)
			}
			row[col] = val
		}
		results = append(results, row)
	}

	return results, nil
}

func extractSQL(response string) string {
	// Extract from markdown code blocks
	if idx := strings.Index(response, "```sql"); idx >= 0 {
		start := idx + 6
		if end := strings.Index(response[start:], "```"); end > 0 {
			return strings.TrimSpace(response[start : start+end])
		}
	}
	if idx := strings.Index(response, "```"); idx >= 0 {
		start := idx + 3
		if end := strings.Index(response[start:], "```"); end > 0 {
			return strings.TrimSpace(response[start : start+end])
		}
	}
	return strings.TrimSpace(response)
}

func respondWithBlocked(w http.ResponseWriter, user User, query, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(QueryResponse{
		Results:      []map[string]interface{}{},
		Count:        0,
		QueryBlocked: true,
		BlockReason:  reason,
		SecurityLog: SecurityLog{
			UserEmail:     user.Email,
			QueryExecuted: query,
			AccessGranted: false,
			Timestamp:     time.Now(),
		},
	})
}

func respondWithResults(w http.ResponseWriter, user User, query string, results []map[string]interface{}, provider string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(QueryResponse{
		Results:      results,
		Count:        len(results),
		QueryBlocked: false,
		LLMProvider:  provider,
		SecurityLog: SecurityLog{
			UserEmail:     user.Email,
			QueryExecuted: query,
			AccessGranted: true,
			Timestamp:     time.Now(),
		},
	})
}

// Stub handlers for frontend compatibility
func stubHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
}

func userAccessHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(User)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_role": user.Role,
		"providers": map[string]interface{}{
			"openai": map[string]interface{}{
				"name":   "OpenAI GPT-4",
				"access": "Full access",
				"color":  "green",
			},
			"anthropic": map[string]interface{}{
				"name":   "Anthropic Claude",
				"access": "Full access",
				"color":  "green",
			},
		},
	})
}

func auditStubHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{})
}

func policyMetricsStubHandler(w http.ResponseWriter, r *http.Request) {
	var totalPolicies, aiQueries, piiRedacted, regionalBlocks int
	db.QueryRow(`SELECT COALESCE(total_policies_enforced, 0), COALESCE(ai_queries, 0),
		COALESCE(pii_redacted, 0), COALESCE(regional_blocks, 0)
		FROM policy_metrics WHERE date = CURRENT_DATE`).Scan(&totalPolicies, &aiQueries, &piiRedacted, &regionalBlocks)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_policies_enforced": totalPolicies,
		"ai_queries":              aiQueries,
		"pii_redacted":            piiRedacted,
		"regional_blocks":         regionalBlocks,
	})
}

func performanceStubHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"avg_latency_ms": 45,
		"requests_total": 0,
		"cache_hit_rate": 0,
	})
}
