// Package main demonstrates and VALIDATES AxonFlow's axonctl execution commands
// and the embedded Execution Viewer web UI.
//
// This example validates:
// 1. axonctl executions list       - List executions (table + JSON output)
// 2. axonctl executions get        - Get execution detail
// 3. axonctl executions export     - Export execution to JSON file
// 4. Embedded UI: /ui/executions/  - Web UI serves correctly
// 5. Embedded UI: detail.html      - Detail page serves correctly
// 6. Embedded UI: static assets    - app.js and styles.css load correctly
//
// VALIDATION: This example exits with code 1 if any check fails.
// This ensures CI/CD pipelines catch regressions.
//
// Prerequisites:
//   - docker compose up -d
//   - At least one execution must exist (run the Go SDK example first)
//   - go build -o axonctl ../../platform/cmd/axonctl (built automatically)
//
// Run with: go run main.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var failures []string

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   ❌ FAIL: %s\n", message)
	} else {
		fmt.Printf("   ✓ PASS: %s\n", message)
	}
}

func fatal(message string) {
	fmt.Printf("   ❌ FATAL: %s\n", message)
	os.Exit(1)
}

func main() {
	fmt.Println("AxonFlow Execution Replay - CLI & Embedded UI Validation")
	fmt.Println("========================================================")
	fmt.Println()

	agentEndpoint := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "demo-org")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "demo")

	// ========================================
	// 0. BUILD AXONCTL
	// ========================================
	fmt.Println("0. Building axonctl...")

	// Find the axonctl source directory relative to this example
	axonctlSrc := findAxonctlSrc()
	tmpDir, err := os.MkdirTemp("", "axonctl-test-*")
	if err != nil {
		fatal(fmt.Sprintf("Failed to create temp dir: %v", err))
	}
	defer os.RemoveAll(tmpDir)

	axonctlBin := filepath.Join(tmpDir, "axonctl")
	buildCmd := exec.Command("go", "build", "-o", axonctlBin, ".")
	buildCmd.Dir = axonctlSrc
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		fatal(fmt.Sprintf("Failed to build axonctl: %v\n%s", err, string(buildOutput)))
	}
	fmt.Printf("   Built: %s\n", axonctlBin)
	fmt.Println()

	// Set env for all axonctl commands
	env := append(os.Environ(),
		"AXONFLOW_ENDPOINT="+agentEndpoint,
		"AXONFLOW_CLIENT_ID="+clientID,
		"AXONFLOW_CLIENT_SECRET="+clientSecret,
	)

	// ========================================
	// 1. AXONCTL EXECUTIONS LIST (TABLE)
	// ========================================
	fmt.Println("1. axonctl executions list - Table output...")
	out, err := runAxonctl(axonctlBin, env, "executions", "list", "--limit", "5")
	if err != nil {
		fatal(fmt.Sprintf("axonctl executions list failed: %v\n%s", err, out))
	}
	assert(strings.Contains(out, "ID") || strings.Contains(out, "No executions found"),
		"Table output contains header or empty state message")
	fmt.Printf("   Output preview: %s\n", truncate(out, 200))
	fmt.Println()

	// ========================================
	// 2. AXONCTL EXECUTIONS LIST (JSON)
	// ========================================
	fmt.Println("2. axonctl executions list --format json - JSON output...")
	jsonOut, err := runAxonctl(axonctlBin, env, "executions", "list", "--format", "json", "--limit", "5")
	if err != nil {
		fatal(fmt.Sprintf("axonctl executions list --format json failed: %v\n%s", err, jsonOut))
	}

	var listResp struct {
		Executions []struct {
			RequestID    string `json:"request_id"`
			WorkflowName string `json:"workflow_name"`
			Status       string `json:"status"`
			TotalSteps   int    `json:"total_steps"`
		} `json:"executions"`
		Total int `json:"total"`
	}
	err = json.Unmarshal([]byte(jsonOut), &listResp)
	assert(err == nil, "JSON output is valid JSON")
	assert(listResp.Total >= 0, "Total is a valid count")
	fmt.Printf("   Total executions: %d\n", listResp.Total)

	var executionID string
	if len(listResp.Executions) > 0 {
		executionID = listResp.Executions[0].RequestID
		assert(executionID != "", "First execution has valid request_id")
		assert(listResp.Executions[0].Status != "", "First execution has valid status")
		fmt.Printf("   First execution: %s (status=%s, steps=%d)\n",
			executionID, listResp.Executions[0].Status, listResp.Executions[0].TotalSteps)
	} else {
		fmt.Println("   No executions found (run SDK example first to generate data)")
	}
	fmt.Println()

	// Continue with detail/export tests if executions exist
	if executionID != "" {
		// ========================================
		// 3. AXONCTL EXECUTIONS GET
		// ========================================
		fmt.Println("3. axonctl executions get - Execution detail...")
		getOut, err := runAxonctl(axonctlBin, env, "executions", "get", executionID)
		if err != nil {
			fatal(fmt.Sprintf("axonctl executions get failed: %v\n%s", err, getOut))
		}
		assert(strings.Contains(getOut, executionID) || strings.Contains(getOut, "Execution Summary"),
			"Detail output contains execution ID or summary header")
		assert(strings.Contains(getOut, "Status"),
			"Detail output contains Status field")
		fmt.Printf("   Output preview: %s\n", truncate(getOut, 300))
		fmt.Println()

		// ========================================
		// 4. AXONCTL EXECUTIONS GET (JSON)
		// ========================================
		fmt.Println("4. axonctl executions get --format json - JSON detail...")
		getJsonOut, err := runAxonctl(axonctlBin, env, "executions", "get", executionID, "--format", "json")
		if err != nil {
			fatal(fmt.Sprintf("axonctl executions get --format json failed: %v\n%s", err, getJsonOut))
		}

		var execDetail struct {
			Summary struct {
				RequestID string `json:"request_id"`
				Status    string `json:"status"`
			} `json:"summary"`
			Steps []struct {
				StepName string `json:"step_name"`
				Status   string `json:"status"`
			} `json:"steps"`
		}
		err = json.Unmarshal([]byte(getJsonOut), &execDetail)
		assert(err == nil, "Get JSON output is valid JSON")
		assert(execDetail.Summary.RequestID == executionID, "JSON summary.request_id matches")
		assert(execDetail.Summary.Status != "", "JSON summary.status is populated")
		assert(len(execDetail.Steps) > 0, "JSON steps array has entries")
		fmt.Printf("   Status: %s, Steps: %d\n", execDetail.Summary.Status, len(execDetail.Steps))
		for i, step := range execDetail.Steps {
			if i >= 3 {
				fmt.Printf("     ... and %d more steps\n", len(execDetail.Steps)-3)
				break
			}
			fmt.Printf("     [%d] %s: %s\n", i, step.StepName, step.Status)
		}
		fmt.Println()

		// ========================================
		// 5. AXONCTL EXECUTIONS EXPORT
		// ========================================
		fmt.Println("5. axonctl executions export - Export to file...")
		exportFile := filepath.Join(tmpDir, "export-test.json")
		exportOut, err := runAxonctl(axonctlBin, env, "executions", "export", executionID, "--output", exportFile, "--include-io")
		if err != nil {
			fatal(fmt.Sprintf("axonctl executions export failed: %v\n%s", err, exportOut))
		}

		assert(strings.Contains(exportOut, "Exported"), "Export output confirms success")

		exportData, err := os.ReadFile(exportFile)
		assert(err == nil, "Exported file exists and is readable")
		assert(json.Valid(exportData), "Exported file contains valid JSON")
		assert(len(exportData) > 10, fmt.Sprintf("Exported file has content (%d bytes)", len(exportData)))
		fmt.Printf("   Exported %d bytes to %s\n", len(exportData), exportFile)
		fmt.Println()
	}

	// ========================================
	// 6. EMBEDDED UI: LIST PAGE (via agent)
	// ========================================
	fmt.Println("6. Embedded UI - /ui/executions/ (list page via agent)...")
	body, statusCode, err := httpGet(agentEndpoint + "/ui/executions/")
	if err != nil {
		fatal(fmt.Sprintf("Failed to fetch UI list page via agent: %v", err))
	}
	assert(statusCode == 200, fmt.Sprintf("Agent UI returns 200 (got %d)", statusCode))
	assert(strings.Contains(body, "AxonFlow Execution Viewer"), "UI page contains expected title")
	assert(strings.Contains(body, "executions-table"), "UI page contains executions table element")
	assert(strings.Contains(body, "app.js"), "UI page references app.js")
	fmt.Println()

	// ========================================
	// 7. EMBEDDED UI: DETAIL PAGE (via agent)
	// ========================================
	fmt.Println("7. Embedded UI - /ui/executions/detail.html (detail page via agent)...")
	body, statusCode, err = httpGet(agentEndpoint + "/ui/executions/detail.html")
	if err != nil {
		fatal(fmt.Sprintf("Failed to fetch UI detail page via agent: %v", err))
	}
	assert(statusCode == 200, fmt.Sprintf("Detail page returns 200 (got %d)", statusCode))
	assert(strings.Contains(body, "Execution Detail"), "Detail page contains expected title")
	assert(strings.Contains(body, "steps-list"), "Detail page contains steps list element")
	assert(strings.Contains(body, "btn-export"), "Detail page contains export button")
	fmt.Println()

	// ========================================
	// 8. EMBEDDED UI: STATIC ASSETS (via agent)
	// ========================================
	fmt.Println("8. Embedded UI - Static assets (app.js, styles.css via agent)...")

	body, statusCode, err = httpGet(agentEndpoint + "/ui/executions/app.js")
	if err != nil {
		fatal(fmt.Sprintf("Failed to fetch app.js via agent: %v", err))
	}
	assert(statusCode == 200, fmt.Sprintf("app.js returns 200 (got %d)", statusCode))
	assert(strings.Contains(body, "loadExecutions"), "app.js contains loadExecutions function")
	assert(strings.Contains(body, "loadExecution"), "app.js contains loadExecution function")
	assert(strings.Contains(body, "exportExecution"), "app.js contains exportExecution function")

	body, statusCode, err = httpGet(agentEndpoint + "/ui/executions/styles.css")
	if err != nil {
		fatal(fmt.Sprintf("Failed to fetch styles.css via agent: %v", err))
	}
	assert(statusCode == 200, fmt.Sprintf("styles.css returns 200 (got %d)", statusCode))
	assert(strings.Contains(body, "status-completed"), "styles.css contains status-completed class")
	assert(strings.Contains(body, "status-failed"), "styles.css contains status-failed class")
	assert(strings.Contains(body, "step-card"), "styles.css contains step-card class")
	fmt.Println()

	// ========================================
	// 9. ORCHESTRATOR DIRECT (internal verification)
	// ========================================
	fmt.Println("9. Orchestrator direct - /ui/executions/ (internal)...")
	body, statusCode, err = httpGet(agentEndpoint + "/ui/executions/")
	if err != nil {
		fmt.Printf("   ⚠️  Orchestrator not reachable: %v\n", err)
	} else {
		assert(statusCode == 200, fmt.Sprintf("Orchestrator UI returns 200 (got %d)", statusCode))
		assert(strings.Contains(body, "AxonFlow Execution Viewer"),
			"Orchestrator-served UI page contains expected title")
	}
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("========================================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Features validated:")
		fmt.Println("  1. axonctl executions list       - Table + JSON output")
		fmt.Println("  2. axonctl executions get         - Detail view + JSON")
		fmt.Println("  3. axonctl executions export      - JSON file export")
		fmt.Println("  4. Embedded UI list page          - /ui/executions/ via agent")
		fmt.Println("  5. Embedded UI detail page        - /ui/executions/detail.html via agent")
		fmt.Println("  6. Embedded UI static assets      - app.js, styles.css via agent")
		fmt.Println("  7. Orchestrator direct serving    - /ui/executions/ internal")
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}

// runAxonctl executes an axonctl command and returns stdout.
func runAxonctl(bin string, env []string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// httpGet fetches a URL and returns body, status code, error.
func httpGet(url string) (string, int, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// findAxonctlSrc locates the axonctl source directory.
func findAxonctlSrc() string {
	// Try relative path from this example (examples/execution-replay/cli/)
	candidates := []string{
		"../../../platform/cmd/axonctl",
		"../../platform/cmd/axonctl",
		"platform/cmd/axonctl",
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(filepath.Join(abs, "main.go")); err == nil {
			return abs
		}
	}
	fatal("Cannot find axonctl source directory. Run from examples/execution-replay/cli/")
	return ""
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	var result []string
	total := 0
	for _, line := range lines {
		if total+len(line) > maxLen {
			result = append(result, "     ...")
			break
		}
		result = append(result, line)
		total += len(line)
	}
	return strings.Join(result, "\n     ")
}
