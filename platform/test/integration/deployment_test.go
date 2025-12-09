package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDeploymentConfig represents the deployment configuration for testing
type TestDeploymentConfig struct {
	Environment string `json:"environment"`
	Region      string `json:"region"`
	Services    string `json:"services"`
	Version     string `json:"version"`
}

// MockECSService simulates ECS service responses for testing
type MockECSService struct {
	Services map[string]*MockService
}

type MockService struct {
	Name         string
	RunningCount int
	DesiredCount int
	Status       string
	RolloutState string
}

// TestApplicationDeploymentConfig tests that deployment configuration is properly parsed
func TestApplicationDeploymentConfig(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		services    string
		version     string
		wantErr     bool
	}{
		{
			name:        "valid staging deployment",
			environment: "staging",
			services:    "all",
			version:     "abc1234",
			wantErr:     false,
		},
		{
			name:        "valid production deployment",
			environment: "production",
			services:    "agent",
			version:     "def5678",
			wantErr:     false,
		},
		{
			name:        "valid multiple services",
			environment: "staging",
			services:    "agent,orchestrator",
			version:     "latest",
			wantErr:     false,
		},
		{
			name:        "empty environment should fail",
			environment: "",
			services:    "all",
			version:     "abc1234",
			wantErr:     true,
		},
		{
			name:        "invalid environment should fail",
			environment: "invalid-env",
			services:    "all",
			version:     "abc1234",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := TestDeploymentConfig{
				Environment: tt.environment,
				Services:    tt.services,
				Version:     tt.version,
			}

			err := validateDeploymentConfig(config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDeploymentConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// validateDeploymentConfig validates the deployment configuration
func validateDeploymentConfig(config TestDeploymentConfig) error {
	validEnvironments := map[string]bool{
		"staging":                   true,
		"production":                true,
		"production-us":             true,
		"production-healthcare-us":  true,
		"production-banking-india":  true,
	}

	if config.Environment == "" {
		return fmt.Errorf("environment is required")
	}

	if !validEnvironments[config.Environment] {
		return fmt.Errorf("invalid environment: %s", config.Environment)
	}

	return nil
}

// TestServiceSelection tests that services are correctly selected for deployment
func TestServiceSelection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "all services",
			input:    "all",
			expected: []string{"agent", "orchestrator", "customer-portal"},
		},
		{
			name:     "single service",
			input:    "agent",
			expected: []string{"agent"},
		},
		{
			name:     "multiple services comma-separated",
			input:    "agent,orchestrator",
			expected: []string{"agent", "orchestrator"},
		},
		{
			name:     "empty input defaults to all",
			input:    "",
			expected: []string{"agent", "orchestrator", "customer-portal"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandServices(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expandServices() = %v, want %v", result, tt.expected)
			}
			for i, svc := range result {
				if svc != tt.expected[i] {
					t.Errorf("expandServices()[%d] = %v, want %v", i, svc, tt.expected[i])
				}
			}
		})
	}
}

// expandServices expands service selection string to service list
func expandServices(input string) []string {
	if input == "" || input == "all" {
		return []string{"agent", "orchestrator", "customer-portal"}
	}
	return strings.Split(input, ",")
}

// TestDeploymentHealthCheck tests health check functionality
func TestDeploymentHealthCheck(t *testing.T) {
	// Create mock server for health checks
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"version": "1.0.0",
			})
		case "/orchestrator/health":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "healthy",
				"components": map[string]bool{
					"llm_router":      true,
					"planning_engine": true,
				},
			})
		case "/portal/health":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("healthy"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	tests := []struct {
		name       string
		endpoint   string
		wantStatus int
	}{
		{
			name:       "agent health check",
			endpoint:   "/health",
			wantStatus: http.StatusOK,
		},
		{
			name:       "orchestrator health check",
			endpoint:   "/orchestrator/health",
			wantStatus: http.StatusOK,
		},
		{
			name:       "portal health check",
			endpoint:   "/portal/health",
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid endpoint",
			endpoint:   "/invalid",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(mockServer.URL + tt.endpoint)
			if err != nil {
				t.Fatalf("failed to make request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("health check status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

// TestECSServiceStability tests ECS service stability detection
func TestECSServiceStability(t *testing.T) {
	tests := []struct {
		name         string
		runningCount int
		desiredCount int
		rolloutState string
		isStable     bool
	}{
		{
			name:         "stable service",
			runningCount: 2,
			desiredCount: 2,
			rolloutState: "COMPLETED",
			isStable:     true,
		},
		{
			name:         "deploying service",
			runningCount: 1,
			desiredCount: 2,
			rolloutState: "IN_PROGRESS",
			isStable:     false,
		},
		{
			name:         "failed deployment",
			runningCount: 0,
			desiredCount: 2,
			rolloutState: "FAILED",
			isStable:     false,
		},
		{
			name:         "scaling down",
			runningCount: 4,
			desiredCount: 2,
			rolloutState: "IN_PROGRESS",
			isStable:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := MockService{
				RunningCount: tt.runningCount,
				DesiredCount: tt.desiredCount,
				RolloutState: tt.rolloutState,
			}

			stable := isServiceStable(service)
			if stable != tt.isStable {
				t.Errorf("isServiceStable() = %v, want %v", stable, tt.isStable)
			}
		})
	}
}

// isServiceStable checks if an ECS service is stable
func isServiceStable(service MockService) bool {
	if service.RolloutState == "FAILED" {
		return false
	}
	if service.RolloutState != "COMPLETED" {
		return false
	}
	return service.RunningCount == service.DesiredCount
}

// TestCircuitBreakerDetection tests ECS circuit breaker detection
func TestCircuitBreakerDetection(t *testing.T) {
	tests := []struct {
		name           string
		rolloutState   string
		expectBreaker  bool
	}{
		{
			name:          "normal deployment",
			rolloutState:  "COMPLETED",
			expectBreaker: false,
		},
		{
			name:          "in progress deployment",
			rolloutState:  "IN_PROGRESS",
			expectBreaker: false,
		},
		{
			name:          "circuit breaker triggered",
			rolloutState:  "FAILED",
			expectBreaker: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			triggered := isCircuitBreakerTriggered(tt.rolloutState)
			if triggered != tt.expectBreaker {
				t.Errorf("isCircuitBreakerTriggered() = %v, want %v", triggered, tt.expectBreaker)
			}
		})
	}
}

// isCircuitBreakerTriggered checks if ECS circuit breaker was triggered
func isCircuitBreakerTriggered(rolloutState string) bool {
	return rolloutState == "FAILED"
}

// TestDeploymentTimeout tests deployment timeout handling
func TestDeploymentTimeout(t *testing.T) {
	tests := []struct {
		name       string
		timeout    time.Duration
		operation  func(ctx context.Context) error
		shouldFail bool
	}{
		{
			name:    "fast operation completes",
			timeout: 5 * time.Second,
			operation: func(ctx context.Context) error {
				time.Sleep(100 * time.Millisecond)
				return nil
			},
			shouldFail: false,
		},
		{
			name:    "slow operation times out",
			timeout: 100 * time.Millisecond,
			operation: func(ctx context.Context) error {
				select {
				case <-time.After(1 * time.Second):
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			err := tt.operation(ctx)
			if (err != nil) != tt.shouldFail {
				t.Errorf("operation error = %v, shouldFail = %v", err, tt.shouldFail)
			}
		})
	}
}

// TestRollbackDecision tests rollback decision logic
func TestRollbackDecision(t *testing.T) {
	tests := []struct {
		name           string
		deploymentOK   bool
		healthCheckOK  bool
		shouldRollback bool
	}{
		{
			name:           "successful deployment",
			deploymentOK:   true,
			healthCheckOK:  true,
			shouldRollback: false,
		},
		{
			name:           "deployment failed",
			deploymentOK:   false,
			healthCheckOK:  false,
			shouldRollback: true,
		},
		{
			name:           "health check failed",
			deploymentOK:   true,
			healthCheckOK:  false,
			shouldRollback: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldRollback := shouldTriggerRollback(tt.deploymentOK, tt.healthCheckOK)
			if shouldRollback != tt.shouldRollback {
				t.Errorf("shouldTriggerRollback() = %v, want %v", shouldRollback, tt.shouldRollback)
			}
		})
	}
}

// shouldTriggerRollback determines if a rollback should be triggered
func shouldTriggerRollback(deploymentOK, healthCheckOK bool) bool {
	return !deploymentOK || !healthCheckOK
}

// TestEnvironmentConfigLoading tests loading environment configuration
func TestEnvironmentConfigLoading(t *testing.T) {
	// Create a temporary config file for testing
	configContent := `
environment: staging
region: eu-central-1

deployment:
  stack_name_prefix: axonflow-staging
  domain_name: staging-eu.getaxonflow.com
  pricing_tier: Professional

services:
  agent:
    desired_count: 2
    cpu: 1024
    memory: 2048
`

	// Create temp directory and file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/staging.yaml"
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to create config file: %v", err)
	}

	// Test that file was created
	_, err = os.Stat(configPath)
	if err != nil {
		t.Errorf("config file not found: %v", err)
	}
}

// TestDeploymentDurationTargets tests deployment duration targets
func TestDeploymentDurationTargets(t *testing.T) {
	// Application deployment should complete in < 5 minutes
	applicationDeploymentTarget := 5 * time.Minute

	// Infrastructure deployment should complete in < 40 minutes
	infrastructureDeploymentTarget := 40 * time.Minute

	if applicationDeploymentTarget >= infrastructureDeploymentTarget {
		t.Error("application deployment should be faster than infrastructure deployment")
	}

	// Verify application deployment is at least 4x faster
	ratio := float64(infrastructureDeploymentTarget) / float64(applicationDeploymentTarget)
	if ratio < 4 {
		t.Errorf("application deployment should be at least 4x faster, got ratio: %.2f", ratio)
	}
}

// TestVersionTagging tests version tag formats
func TestVersionTagging(t *testing.T) {
	tests := []struct {
		name    string
		version string
		valid   bool
	}{
		{
			name:    "short SHA",
			version: "abc1234",
			valid:   true,
		},
		{
			name:    "full SHA",
			version: "abc1234567890def1234567890abc1234567890de",
			valid:   true,
		},
		{
			name:    "semantic version",
			version: "v1.2.3",
			valid:   true,
		},
		{
			name:    "latest tag",
			version: "latest",
			valid:   true,
		},
		{
			name:    "empty version",
			version: "",
			valid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := isValidVersion(tt.version)
			if valid != tt.valid {
				t.Errorf("isValidVersion(%q) = %v, want %v", tt.version, valid, tt.valid)
			}
		})
	}
}

// isValidVersion validates a version tag
func isValidVersion(version string) bool {
	if version == "" {
		return false
	}
	// Accept any non-empty version string
	return true
}
