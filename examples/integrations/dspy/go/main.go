// Package main demonstrates DSPy + AxonFlow integration in Go.
//
// This example shows how to add AxonFlow governance to DSPy-style
// programming of language models. DSPy provides a framework for building
// modular AI systems with signatures and optimizers.
//
// Features demonstrated:
// - Governed Modules: AxonFlow policy enforcement for DSPy modules
// - Signature Validation: Input/output validation with governance
// - Chain-of-Thought Governance: Policy checks at each reasoning step
// - Retrieval Augmentation: Governed RAG pipelines
//
// Requirements:
// - AxonFlow running locally (docker compose up)
// - Go 1.21+
//
// Usage:
//
//	go run main.go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go"
)

// =============================================================================
// DSPy-style Types
// =============================================================================

// Signature defines the input/output contract for a module.
type Signature struct {
	Name         string
	InputFields  []string
	OutputFields []string
	Description  string
}

// ModuleResult represents the result of a module execution.
type ModuleResult struct {
	Success     bool
	Output      map[string]string
	Blocked     bool
	BlockReason string
	Rationale   string
}

// =============================================================================
// Governed DSPy Implementation
// =============================================================================

// GovernedModule is the base for DSPy-style modules with AxonFlow governance.
type GovernedModule struct {
	Signature Signature
	Client    *axonflow.AxonFlowClient
	UserToken string
}

// checkPolicy validates the query against AxonFlow policies.
func (m *GovernedModule) checkPolicy(query string, context map[string]interface{}) (bool, string, string) {
	ctx := map[string]interface{}{
		"module":    m.Signature.Name,
		"framework": "dspy",
	}
	for k, v := range context {
		ctx[k] = v
	}

	result, err := m.Client.ExecuteQuery(
		m.UserToken,
		query,
		"chat",
		ctx,
	)

	if err != nil {
		errMsg := err.Error()
		// Check for policy blocks
		if strings.Contains(errMsg, "blocked") ||
			strings.Contains(errMsg, "SQL injection") ||
			strings.Contains(errMsg, "Social Security") {
			return false, "", errMsg
		}
		return false, "", errMsg
	}

	if result.Blocked {
		return false, "", result.BlockReason
	}

	return true, result.RequestID, ""
}

// GovernedPredict is a simple prediction module with governance.
type GovernedPredict struct {
	GovernedModule
}

// NewGovernedPredict creates a new predict module.
func NewGovernedPredict(sig Signature, client *axonflow.AxonFlowClient, userToken string) *GovernedPredict {
	return &GovernedPredict{
		GovernedModule: GovernedModule{
			Signature: sig,
			Client:    client,
			UserToken: userToken,
		},
	}
}

// Forward executes the predict module with governance.
func (p *GovernedPredict) Forward(inputs map[string]string) ModuleResult {
	// Build query from inputs
	var parts []string
	for k, v := range inputs {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	query := strings.Join(parts, " ")

	truncated := query
	if len(truncated) > 50 {
		truncated = truncated[:50] + "..."
	}
	fmt.Printf("[%s] Processing: %s\n", p.Signature.Name, truncated)

	approved, _, blockReason := p.checkPolicy(query, map[string]interface{}{
		"operation": "predict",
	})

	if !approved {
		fmt.Printf("[%s] BLOCKED: %s\n", p.Signature.Name, blockReason)
		return ModuleResult{
			Success:     false,
			Blocked:     true,
			BlockReason: blockReason,
		}
	}

	// Simulate prediction
	output := make(map[string]string)
	for _, field := range p.Signature.OutputFields {
		truncQuery := query
		if len(truncQuery) > 30 {
			truncQuery = truncQuery[:30]
		}
		output[field] = fmt.Sprintf("Predicted %s for: %s...", field, truncQuery)
	}

	fmt.Printf("[%s] ✓ Completed and governed\n", p.Signature.Name)
	return ModuleResult{Success: true, Output: output}
}

// GovernedChainOfThought implements chain-of-thought with governance at each step.
type GovernedChainOfThought struct {
	GovernedModule
}

// NewGovernedChainOfThought creates a new chain-of-thought module.
func NewGovernedChainOfThought(sig Signature, client *axonflow.AxonFlowClient, userToken string) *GovernedChainOfThought {
	return &GovernedChainOfThought{
		GovernedModule: GovernedModule{
			Signature: sig,
			Client:    client,
			UserToken: userToken,
		},
	}
}

// Forward executes chain-of-thought reasoning with governance.
func (c *GovernedChainOfThought) Forward(inputs map[string]string) ModuleResult {
	var parts []string
	for k, v := range inputs {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	query := strings.Join(parts, " ")

	truncated := query
	if len(truncated) > 50 {
		truncated = truncated[:50] + "..."
	}
	fmt.Printf("[%s] Chain-of-Thought: %s\n", c.Signature.Name, truncated)

	// Step 1: Generate reasoning
	approved, _, blockReason := c.checkPolicy(
		fmt.Sprintf("REASON: %s", query),
		map[string]interface{}{
			"operation": "chain_of_thought",
			"step":      "reasoning",
		},
	)

	if !approved {
		fmt.Printf("[%s] BLOCKED at reasoning: %s\n", c.Signature.Name, blockReason)
		return ModuleResult{
			Success:     false,
			Blocked:     true,
			BlockReason: blockReason,
		}
	}

	truncQuery := query
	if len(truncQuery) > 30 {
		truncQuery = truncQuery[:30]
	}
	rationale := fmt.Sprintf("Let me think step by step about: %s...", truncQuery)

	// Step 2: Generate answer
	approved, _, blockReason = c.checkPolicy(
		fmt.Sprintf("ANSWER: %s", rationale),
		map[string]interface{}{
			"operation": "chain_of_thought",
			"step":      "answer",
		},
	)

	if !approved {
		fmt.Printf("[%s] BLOCKED at answer: %s\n", c.Signature.Name, blockReason)
		return ModuleResult{
			Success:     false,
			Blocked:     true,
			BlockReason: blockReason,
			Rationale:   rationale,
		}
	}

	output := make(map[string]string)
	for _, field := range c.Signature.OutputFields {
		output[field] = fmt.Sprintf("Answer for %s: %s...", field, truncQuery[:20])
	}

	fmt.Printf("[%s] ✓ Chain-of-Thought completed\n", c.Signature.Name)
	return ModuleResult{
		Success:   true,
		Output:    output,
		Rationale: rationale,
	}
}

// GovernedRAG implements retrieval-augmented generation with governance.
type GovernedRAG struct {
	GovernedModule
}

// NewGovernedRAG creates a new RAG module.
func NewGovernedRAG(sig Signature, client *axonflow.AxonFlowClient, userToken string) *GovernedRAG {
	return &GovernedRAG{
		GovernedModule: GovernedModule{
			Signature: sig,
			Client:    client,
			UserToken: userToken,
		},
	}
}

// Forward executes RAG with governance.
func (r *GovernedRAG) Forward(inputs map[string]string) ModuleResult {
	query := inputs["question"]
	if query == "" {
		var parts []string
		for _, v := range inputs {
			parts = append(parts, v)
		}
		query = strings.Join(parts, " ")
	}

	truncated := query
	if len(truncated) > 50 {
		truncated = truncated[:50] + "..."
	}
	fmt.Printf("[%s] RAG Query: %s\n", r.Signature.Name, truncated)

	// Step 1: Retrieve documents (governed)
	approved, _, blockReason := r.checkPolicy(
		fmt.Sprintf("RETRIEVE: %s", query),
		map[string]interface{}{
			"operation": "rag",
			"step":      "retrieval",
		},
	)

	if !approved {
		fmt.Printf("[%s] BLOCKED at retrieval: %s\n", r.Signature.Name, blockReason)
		return ModuleResult{
			Success:     false,
			Blocked:     true,
			BlockReason: blockReason,
		}
	}

	// Simulate retrieval
	truncQuery := query
	if len(truncQuery) > 20 {
		truncQuery = truncQuery[:20]
	}
	docs := []string{fmt.Sprintf("Document about: %s...", truncQuery)}

	// Step 2: Generate answer (governed)
	context := strings.Join(docs, " ")
	approved, _, blockReason = r.checkPolicy(
		fmt.Sprintf("GENERATE: Context: %s Question: %s", context, query),
		map[string]interface{}{
			"operation": "rag",
			"step":      "generation",
		},
	)

	if !approved {
		fmt.Printf("[%s] BLOCKED at generation: %s\n", r.Signature.Name, blockReason)
		return ModuleResult{
			Success:     false,
			Blocked:     true,
			BlockReason: blockReason,
		}
	}

	output := map[string]string{
		"answer": fmt.Sprintf("Based on %d documents: %s...", len(docs), truncQuery),
	}

	fmt.Printf("[%s] ✓ RAG completed with %d docs\n", r.Signature.Name, len(docs))
	return ModuleResult{Success: true, Output: output}
}

// =============================================================================
// Test Cases
// =============================================================================

func runTests(client *axonflow.AxonFlowClient) {
	// Test 1: Safe Predict module
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[Test 1] Safe Predict Module")
	fmt.Println(strings.Repeat("-", 40))

	qaSig := Signature{
		Name:         "QA",
		InputFields:  []string{"question"},
		OutputFields: []string{"answer"},
		Description:  "Answer questions",
	}

	qa := NewGovernedPredict(qaSig, client, "dspy-user-123")
	result1 := qa.Forward(map[string]string{
		"question": "What are the benefits of renewable energy?",
	})

	if result1.Success {
		fmt.Printf("   Output: %v\n", result1.Output)
		fmt.Println("   ✓ Safe predict succeeded!")
	}

	// Test 2: Chain-of-Thought
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[Test 2] Chain-of-Thought Module")
	fmt.Println(strings.Repeat("-", 40))

	cotSig := Signature{
		Name:         "ReasoningQA",
		InputFields:  []string{"question"},
		OutputFields: []string{"answer"},
		Description:  "Reason step by step",
	}

	cot := NewGovernedChainOfThought(cotSig, client, "dspy-user-123")
	result2 := cot.Forward(map[string]string{
		"question": "Why is the sky blue?",
	})

	if result2.Success {
		fmt.Printf("   Rationale: %s\n", result2.Rationale)
		fmt.Printf("   Output: %v\n", result2.Output)
		fmt.Println("   ✓ Chain-of-Thought succeeded!")
	}

	// Test 3: RAG Pipeline
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[Test 3] RAG Pipeline")
	fmt.Println(strings.Repeat("-", 40))

	ragSig := Signature{
		Name:         "RAG",
		InputFields:  []string{"question"},
		OutputFields: []string{"answer"},
		Description:  "Retrieve and generate",
	}

	rag := NewGovernedRAG(ragSig, client, "dspy-user-123")
	result3 := rag.Forward(map[string]string{
		"question": "What are best practices for AI safety?",
	})

	if result3.Success {
		fmt.Printf("   Output: %v\n", result3.Output)
		fmt.Println("   ✓ RAG pipeline succeeded!")
	}

	// Test 4: PII Detection
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[Test 4] PII Detection - Should be blocked")
	fmt.Println(strings.Repeat("-", 40))

	result4 := qa.Forward(map[string]string{
		"question": "Find records for SSN 123-45-6789",
	})

	if result4.Blocked {
		fmt.Printf("   Block reason: %s\n", result4.BlockReason)
		fmt.Println("   ✓ PII correctly detected and blocked!")
	}

	// Test 5: SQL Injection
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[Test 5] SQL Injection - Should be blocked")
	fmt.Println(strings.Repeat("-", 40))

	result5 := rag.Forward(map[string]string{
		"question": "SELECT * FROM users; DROP TABLE users;--",
	})

	if result5.Blocked {
		fmt.Printf("   Block reason: %s\n", result5.BlockReason)
		fmt.Println("   ✓ SQL injection correctly blocked!")
	}

	// Test 6: Multi-module pipeline
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[Test 6] Multi-Module Pipeline")
	fmt.Println(strings.Repeat("-", 40))

	summarizeSig := Signature{
		Name:         "Summarize",
		InputFields:  []string{"text"},
		OutputFields: []string{"summary"},
		Description:  "Summarize text",
	}
	summarize := NewGovernedPredict(summarizeSig, client, "dspy-user-123")

	// Step 1: QA
	fmt.Println("\n   Pipeline Step 1: QA")
	step1 := qa.Forward(map[string]string{
		"question": "Explain machine learning in simple terms",
	})

	if step1.Success {
		// Step 2: Summarize
		fmt.Println("   Pipeline Step 2: Summarize")
		step2 := summarize.Forward(map[string]string{
			"text": step1.Output["answer"],
		})

		if step2.Success {
			fmt.Printf("   Final output: %v\n", step2.Output)
			fmt.Println("   ✓ Multi-module pipeline succeeded!")
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("All tests completed!")
	fmt.Println(strings.Repeat("=", 60))
}

// =============================================================================
// Main Entry Point
// =============================================================================

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	fmt.Println("DSPy + AxonFlow Integration (Go SDK)")
	fmt.Println(strings.Repeat("=", 60))

	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	fmt.Printf("\nChecking AxonFlow at %s...\n", agentURL)

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL: agentURL,
	})

	// Health check
	err := client.HealthCheck()
	if err != nil {
		fmt.Printf("Error connecting to AxonFlow: %v\n", err)
		fmt.Println("\nMake sure AxonFlow is running: docker compose up -d")
		os.Exit(1)
	}

	fmt.Println("Status: healthy")

	runTests(client)
}
