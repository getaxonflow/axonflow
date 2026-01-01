// Package main demonstrates LangGraph + AxonFlow integration in Go.
//
// This example shows how to add AxonFlow governance to LangGraph-style
// stateful agent workflows using Proxy Mode. LangGraph uses graph-based
// orchestration with nodes and edges for building complex agent systems.
//
// Features demonstrated:
// - Graph-based workflow with governed nodes
// - Policy enforcement at each node transition
// - State management across the workflow
// - PII detection and SQL injection blocking
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
// Types - LangGraph-style state and graph structures
// =============================================================================

// GraphState represents the state passed through the workflow
type GraphState struct {
	Messages    []Message
	CurrentNode string
	Metadata    map[string]interface{}
}

// Message represents a conversation message
type Message struct {
	Role    string
	Content string
}

// NodeResult represents the result of a node execution
type NodeResult struct {
	NextNode    string
	State       GraphState
	Blocked     bool
	BlockReason string
}

// NodeFunc is the signature for node functions
type NodeFunc func(state GraphState, client *axonflow.AxonFlowClient) NodeResult

// =============================================================================
// Configuration
// =============================================================================

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// Graph Nodes - Each node is governed by AxonFlow using Proxy Mode
// =============================================================================

// inputNode validates and processes user input using Proxy Mode
func inputNode(state GraphState, client *axonflow.AxonFlowClient) NodeResult {
	var query string
	if len(state.Messages) > 0 {
		query = state.Messages[len(state.Messages)-1].Content
	}

	truncated := query
	if len(truncated) > 50 {
		truncated = truncated[:50] + "..."
	}
	fmt.Printf("[Input Node] Processing: %q\n", truncated)

	// Use Proxy Mode (ExecuteQuery) - works without credentials
	result, err := client.ExecuteQuery(
		"langgraph-user",
		query,
		"chat",
		map[string]interface{}{
			"node":     "input",
			"workflow": "research-assistant",
		},
	)

	if err != nil {
		errMsg := err.Error()
		// Check for blocked responses
		if strings.Contains(errMsg, "blocked") ||
			strings.Contains(errMsg, "SQL injection") ||
			strings.Contains(errMsg, "Social Security") ||
			strings.Contains(errMsg, "PII") {
			fmt.Printf("[Input Node] BLOCKED: %s\n", errMsg)
			state.CurrentNode = "blocked"
			return NodeResult{
				NextNode:    "",
				State:       state,
				Blocked:     true,
				BlockReason: errMsg,
			}
		}
		fmt.Printf("[Input Node] Error: %v\n", err)
		state.CurrentNode = "error"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: err.Error(),
		}
	}

	if result.Blocked {
		fmt.Printf("[Input Node] BLOCKED: %s\n", result.BlockReason)
		state.CurrentNode = "blocked"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: result.BlockReason,
		}
	}

	// Store request ID for audit trail
	state.Metadata["requestId"] = result.RequestID
	state.Metadata["inputApproved"] = true

	requestPrefix := result.RequestID
	if len(requestPrefix) > 8 {
		requestPrefix = requestPrefix[:8]
	}
	fmt.Printf("[Input Node] ✓ Approved (Request: %s...)\n", requestPrefix)

	state.CurrentNode = "router"
	return NodeResult{
		NextNode: "router",
		State:    state,
	}
}

// routerNode determines which processing path to take
func routerNode(state GraphState, client *axonflow.AxonFlowClient) NodeResult {
	var query string
	if len(state.Messages) > 0 {
		query = strings.ToLower(state.Messages[len(state.Messages)-1].Content)
	}

	fmt.Println("[Router Node] Analyzing query intent...")

	// Simple intent detection
	var nextNode string
	if strings.Contains(query, "search") || strings.Contains(query, "find") || strings.Contains(query, "look up") {
		nextNode = "search"
	} else if strings.Contains(query, "analyze") || strings.Contains(query, "compare") {
		nextNode = "analyze"
	} else {
		nextNode = "respond"
	}

	fmt.Printf("[Router Node] ✓ Routing to: %s\n", nextNode)

	state.CurrentNode = nextNode
	state.Metadata["route"] = nextNode
	return NodeResult{
		NextNode: nextNode,
		State:    state,
	}
}

// searchNode handles search-type queries with governance
func searchNode(state GraphState, client *axonflow.AxonFlowClient) NodeResult {
	var query string
	if len(state.Messages) > 0 {
		query = state.Messages[len(state.Messages)-1].Content
	}

	fmt.Println("[Search Node] Executing governed search...")

	// Policy check for search operation
	result, err := client.ExecuteQuery(
		"langgraph-user",
		fmt.Sprintf("SEARCH: %s", query),
		"chat",
		map[string]interface{}{
			"node":      "search",
			"operation": "database_query",
			"workflow":  "research-assistant",
		},
	)

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "blocked") ||
			strings.Contains(errMsg, "SQL injection") ||
			strings.Contains(errMsg, "Social Security") {
			fmt.Printf("[Search Node] BLOCKED: %s\n", errMsg)
			state.CurrentNode = "blocked"
			return NodeResult{
				NextNode:    "",
				State:       state,
				Blocked:     true,
				BlockReason: errMsg,
			}
		}
		fmt.Printf("[Search Node] Error: %v\n", err)
		state.CurrentNode = "error"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: err.Error(),
		}
	}

	if result.Blocked {
		fmt.Printf("[Search Node] BLOCKED: %s\n", result.BlockReason)
		state.CurrentNode = "blocked"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: result.BlockReason,
		}
	}

	// Use the LLM response from proxy mode
	truncated := query
	if len(truncated) > 30 {
		truncated = truncated[:30]
	}
	searchResult := fmt.Sprintf("[Search results for: %s...]", truncated)

	state.Messages = append(state.Messages, Message{Role: "assistant", Content: searchResult})
	fmt.Println("[Search Node] ✓ Search completed (governed by AxonFlow)")

	state.CurrentNode = "respond"
	return NodeResult{
		NextNode: "respond",
		State:    state,
	}
}

// analyzeNode handles analysis queries with governance
func analyzeNode(state GraphState, client *axonflow.AxonFlowClient) NodeResult {
	var query string
	if len(state.Messages) > 0 {
		query = state.Messages[len(state.Messages)-1].Content
	}

	fmt.Println("[Analyze Node] Running governed analysis...")

	result, err := client.ExecuteQuery(
		"langgraph-user",
		fmt.Sprintf("ANALYZE: %s", query),
		"chat",
		map[string]interface{}{
			"node":      "analyze",
			"operation": "data_analysis",
			"workflow":  "research-assistant",
		},
	)

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "blocked") ||
			strings.Contains(errMsg, "SQL injection") ||
			strings.Contains(errMsg, "Social Security") {
			fmt.Printf("[Analyze Node] BLOCKED: %s\n", errMsg)
			state.CurrentNode = "blocked"
			return NodeResult{
				NextNode:    "",
				State:       state,
				Blocked:     true,
				BlockReason: errMsg,
			}
		}
		fmt.Printf("[Analyze Node] Error: %v\n", err)
		state.CurrentNode = "error"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: err.Error(),
		}
	}

	if result.Blocked {
		fmt.Printf("[Analyze Node] BLOCKED: %s\n", result.BlockReason)
		state.CurrentNode = "blocked"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: result.BlockReason,
		}
	}

	// Use the LLM response
	truncated := query
	if len(truncated) > 30 {
		truncated = truncated[:30]
	}
	analysisResult := fmt.Sprintf("[Analysis complete for: %s...]", truncated)

	state.Messages = append(state.Messages, Message{Role: "assistant", Content: analysisResult})
	fmt.Println("[Analyze Node] ✓ Analysis completed (governed by AxonFlow)")

	state.CurrentNode = "respond"
	return NodeResult{
		NextNode: "respond",
		State:    state,
	}
}

// respondNode generates final response with governance
func respondNode(state GraphState, client *axonflow.AxonFlowClient) NodeResult {
	fmt.Println("[Respond Node] Generating governed response...")

	var contextSummary strings.Builder
	for i, m := range state.Messages {
		if i > 0 {
			contextSummary.WriteString(" | ")
		}
		contextSummary.WriteString(m.Content)
	}

	summary := contextSummary.String()
	if len(summary) > 200 {
		summary = summary[:200]
	}

	result, err := client.ExecuteQuery(
		"langgraph-user",
		fmt.Sprintf("RESPOND: %s", summary),
		"chat",
		map[string]interface{}{
			"node":      "respond",
			"operation": "response_generation",
			"workflow":  "research-assistant",
		},
	)

	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "blocked") ||
			strings.Contains(errMsg, "SQL injection") ||
			strings.Contains(errMsg, "Social Security") {
			fmt.Printf("[Respond Node] BLOCKED: %s\n", errMsg)
			state.CurrentNode = "blocked"
			return NodeResult{
				NextNode:    "",
				State:       state,
				Blocked:     true,
				BlockReason: errMsg,
			}
		}
		fmt.Printf("[Respond Node] Error: %v\n", err)
		state.CurrentNode = "error"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: err.Error(),
		}
	}

	if result.Blocked {
		fmt.Printf("[Respond Node] BLOCKED: %s\n", result.BlockReason)
		state.CurrentNode = "blocked"
		return NodeResult{
			NextNode:    "",
			State:       state,
			Blocked:     true,
			BlockReason: result.BlockReason,
		}
	}

	// Use the actual LLM response from AxonFlow
	response := "Based on my analysis, here are the key findings..."
	if result.Data != nil {
		if dataStr, ok := result.Data.(string); ok && len(dataStr) > 0 {
			if len(dataStr) > 100 {
				response = dataStr[:100] + "..."
			} else {
				response = dataStr
			}
		}
	}

	state.Messages = append(state.Messages, Message{Role: "assistant", Content: response})
	fmt.Println("[Respond Node] ✓ Response generated (governed by AxonFlow)")

	state.CurrentNode = "complete"
	return NodeResult{
		NextNode: "",
		State:    state,
	}
}

// =============================================================================
// Graph Execution Engine
// =============================================================================

// GovernedGraph represents a graph workflow with AxonFlow governance
type GovernedGraph struct {
	nodes  map[string]NodeFunc
	client *axonflow.AxonFlowClient
}

// NewGovernedGraph creates a new governed graph
func NewGovernedGraph(client *axonflow.AxonFlowClient) *GovernedGraph {
	g := &GovernedGraph{
		nodes:  make(map[string]NodeFunc),
		client: client,
	}

	// Register nodes
	g.nodes["input"] = inputNode
	g.nodes["router"] = routerNode
	g.nodes["search"] = searchNode
	g.nodes["analyze"] = analyzeNode
	g.nodes["respond"] = respondNode

	return g
}

// Execute runs the graph workflow
func (g *GovernedGraph) Execute(initialState GraphState) GraphState {
	currentNode := "input"
	state := initialState
	state.CurrentNode = currentNode

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Starting Graph Execution")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	for currentNode != "" {
		nodeFunc, ok := g.nodes[currentNode]
		if !ok {
			fmt.Printf("Unknown node: %s\n", currentNode)
			break
		}

		result := nodeFunc(state, g.client)
		state = result.State

		if result.Blocked {
			fmt.Printf("\n⚠️  Workflow blocked at node %q\n", currentNode)
			fmt.Printf("   Reason: %s\n", result.BlockReason)
			break
		}

		currentNode = result.NextNode
	}

	return state
}

// =============================================================================
// Test Cases
// =============================================================================

func runTests(client *axonflow.AxonFlowClient) {
	graph := NewGovernedGraph(client)

	// Test 1: Safe search query
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 1] Safe Search Query")
	fmt.Println(strings.Repeat("=", 60))

	graph.Execute(GraphState{
		Messages: []Message{{Role: "user", Content: "Search for best practices in AI safety"}},
		Metadata: map[string]interface{}{"testCase": "safe-search"},
	})

	// Test 2: Safe analysis query
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 2] Safe Analysis Query")
	fmt.Println(strings.Repeat("=", 60))

	graph.Execute(GraphState{
		Messages: []Message{{Role: "user", Content: "Analyze the trends in renewable energy adoption"}},
		Metadata: map[string]interface{}{"testCase": "safe-analysis"},
	})

	// Test 3: Query with PII (should be blocked)
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 3] Query with PII - Should be blocked")
	fmt.Println(strings.Repeat("=", 60))

	piiResult := graph.Execute(GraphState{
		Messages: []Message{{Role: "user", Content: "Search for customer with SSN 123-45-6789"}},
		Metadata: map[string]interface{}{"testCase": "pii-detection"},
	})

	if piiResult.CurrentNode == "blocked" {
		fmt.Println("\n✓ PII correctly detected and blocked!")
	}

	// Test 4: SQL injection attempt (should be blocked)
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 4] SQL Injection - Should be blocked")
	fmt.Println(strings.Repeat("=", 60))

	sqliResult := graph.Execute(GraphState{
		Messages: []Message{{Role: "user", Content: "Find users WHERE 1=1; DROP TABLE users;--"}},
		Metadata: map[string]interface{}{"testCase": "sql-injection"},
	})

	if sqliResult.CurrentNode == "blocked" {
		fmt.Println("\n✓ SQL injection correctly blocked!")
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("All tests completed!")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
}

// =============================================================================
// Main Entry Point
// =============================================================================

func main() {
	fmt.Println("LangGraph + AxonFlow Integration Example (Go SDK)")
	fmt.Println(strings.Repeat("=", 60))

	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	fmt.Printf("\nChecking AxonFlow at %s...\n", agentURL)

	// Initialize AxonFlow client (community mode - no credentials needed for Proxy Mode)
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
