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
	"axonflow/platform/shared/logger"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// PlanningEngine generates workflows from natural language queries
type PlanningEngine struct {
	llmRouter *LLMRouter
	templates map[string]*DomainTemplate
	logger    *logger.Logger
}

// DomainTemplate provides hints for specific domains
type DomainTemplate struct {
	Domain      string
	CommonTasks []string
	Hints       string
}

// QueryAnalysis represents the analysis of a user query
type QueryAnalysis struct {
	Domain           string   `json:"domain"`
	Complexity       int      `json:"complexity"`
	RequiresParallel bool     `json:"requires_parallel"`
	SuggestedTasks   []string `json:"suggested_tasks"`
	Reasoning        string   `json:"reasoning"`
}

// PlanGenerationRequest encapsulates planning request
type PlanGenerationRequest struct {
	Query         string
	Domain        string // Optional hint: travel, healthcare, finance, generic
	ExecutionMode string // auto, parallel, sequential
	ClientID      string // Client identifier for multi-tenant logging
	RequestID     string // Request ID for tracing
	Context       map[string]interface{}
}

// NewPlanningEngine creates a new planning engine instance
func NewPlanningEngine(router *LLMRouter) *PlanningEngine {
	engine := &PlanningEngine{
		llmRouter: router,
		templates: make(map[string]*DomainTemplate),
		logger:    logger.New("orchestrator"),
	}

	// Initialize domain templates
	engine.initializeTemplates()

	return engine
}

// Initialize domain-specific templates
func (e *PlanningEngine) initializeTemplates() {
	// Travel domain
	e.templates["travel"] = &DomainTemplate{
		Domain: "travel",
		CommonTasks: []string{
			"flight-search",
			"hotel-search",
			"activities-search",
			"restaurant-recommendations",
			"transportation-planning",
		},
		Hints: "Travel planning typically involves independent research tasks that can be parallelized (flights, hotels, activities) followed by synthesis into an itinerary.",
	}

	// Healthcare domain
	e.templates["healthcare"] = &DomainTemplate{
		Domain: "healthcare",
		CommonTasks: []string{
			"symptom-analysis",
			"lab-result-review",
			"imaging-review",
			"specialist-consultation",
			"treatment-plan-generation",
		},
		Hints: "Medical diagnosis often requires sequential analysis where each step informs the next (symptoms → labs → imaging → diagnosis).",
	}

	// Finance domain
	e.templates["finance"] = &DomainTemplate{
		Domain: "finance",
		CommonTasks: []string{
			"market-data-analysis",
			"company-financials-review",
			"news-sentiment-analysis",
			"competitor-analysis",
			"risk-assessment",
		},
		Hints: "Financial analysis typically involves parallel data gathering (market data, news, financials) followed by synthesis into investment recommendations.",
	}

	// Generic domain (no specific hints)
	e.templates["generic"] = &DomainTemplate{
		Domain:      "generic",
		CommonTasks: []string{},
		Hints:       "Analyze the query to determine logical task breakdown and dependencies.",
	}
}

// GeneratePlan creates a workflow from a natural language query
func (e *PlanningEngine) GeneratePlan(ctx context.Context, req PlanGenerationRequest) (*Workflow, error) {
	startTime := time.Now()

	log.Printf("[PlanningEngine] Generating plan for query: %s", req.Query)

	// 1. Analyze query
	analysis, err := e.analyzeQuery(ctx, req.Query, req.Domain)
	if err != nil {
		return nil, fmt.Errorf("query analysis failed: %w", err)
	}

	log.Printf("[PlanningEngine] Query analysis: domain=%s, complexity=%d, parallel=%v",
		analysis.Domain, analysis.Complexity, analysis.RequiresParallel)

	// 2. Generate workflow definition
	workflow, err := e.generateWorkflowDefinition(ctx, req, analysis)
	if err != nil {
		return nil, fmt.Errorf("workflow generation failed: %w", err)
	}

	// 3. Determine execution mode
	if req.ExecutionMode == "auto" {
		workflow = e.optimizeExecutionMode(workflow, analysis)
	} else {
		// User override
		e.applyExecutionMode(workflow, req.ExecutionMode)
	}

	elapsed := time.Since(startTime)
	log.Printf("[PlanningEngine] Plan generated in %s: %d steps", elapsed, len(workflow.Spec.Steps))

	return workflow, nil
}

// Analyze query to determine decomposition strategy
func (e *PlanningEngine) analyzeQuery(ctx context.Context, query string, domainHint string) (*QueryAnalysis, error) {
	// Get domain template
	template, exists := e.templates[domainHint]
	if !exists {
		template = e.templates["generic"]
	}

	// Build analysis prompt
	prompt := e.buildAnalysisPrompt(query, template)

	// Call LLM for analysis
	req := OrchestratorRequest{
		RequestID:   fmt.Sprintf("plan-analysis-%d", time.Now().Unix()),
		Query:       prompt,
		RequestType: "planning-analysis",
		User: UserContext{
			TenantID: "system",
		},
	}

	response, _, err := e.llmRouter.RouteRequest(ctx, req)
	if err != nil {
		// Fallback: Use heuristics when LLM is unavailable
		log.Printf("[PlanningEngine] LLM request failed, using heuristics: %v", err)
		return e.heuristicAnalysis(query, domainHint), nil
	}

	// Parse LLM response as JSON
	analysis, err := e.parseAnalysisResponse(response)
	if err != nil {
		// Fallback: Use heuristics
		log.Printf("[PlanningEngine] LLM analysis parsing failed, using heuristics: %v", err)
		return e.heuristicAnalysis(query, domainHint), nil
	}

	return analysis, nil
}

// Build prompt for query analysis
func (e *PlanningEngine) buildAnalysisPrompt(query string, template *DomainTemplate) string {
	return fmt.Sprintf(`You are a task planning AI. Analyze this query and return a JSON object with task decomposition analysis.

Query: "%s"

Domain: %s
%s

Common tasks for this domain: %v

Return a JSON object with this structure:
{
  "domain": "travel|healthcare|finance|generic",
  "complexity": <number 1-5 of subtasks>,
  "requires_parallel": <true if tasks are independent, false if sequential>,
  "suggested_tasks": ["task1", "task2", ...],
  "reasoning": "Brief explanation of decomposition strategy"
}

Respond ONLY with valid JSON, no additional text.`,
		query,
		template.Domain,
		template.Hints,
		template.CommonTasks)
}

// Parse LLM analysis response
func (e *PlanningEngine) parseAnalysisResponse(response interface{}) (*QueryAnalysis, error) {
	var responseStr string

	// Extract string from LLMResponse
	if llmResp, ok := response.(*LLMResponse); ok {
		responseStr = llmResp.Content
	} else if str, ok := response.(string); ok {
		responseStr = str
	} else {
		return nil, fmt.Errorf("unexpected response type")
	}

	// Try to extract JSON from response (LLM might add extra text)
	jsonStart := strings.Index(responseStr, "{")
	jsonEnd := strings.LastIndex(responseStr, "}")

	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := responseStr[jsonStart : jsonEnd+1]

	var analysis QueryAnalysis
	if err := json.Unmarshal([]byte(jsonStr), &analysis); err != nil {
		return nil, fmt.Errorf("JSON parsing failed: %w", err)
	}

	return &analysis, nil
}

// Heuristic analysis fallback (when LLM fails)
func (e *PlanningEngine) heuristicAnalysis(query string, domainHint string) *QueryAnalysis {
	query = strings.ToLower(query)

	analysis := &QueryAnalysis{
		Domain:           domainHint,
		Complexity:       3, // Default moderate complexity
		RequiresParallel: true, // Default to parallel
		SuggestedTasks:   []string{"task-1", "task-2", "task-3"},
		Reasoning:        "Heuristic analysis (LLM unavailable)",
	}

	// Detect domain from keywords
	if strings.Contains(query, "trip") || strings.Contains(query, "flight") || strings.Contains(query, "hotel") {
		analysis.Domain = "travel"
		analysis.SuggestedTasks = []string{"flight-search", "hotel-search", "activities"}
	} else if strings.Contains(query, "diagnose") || strings.Contains(query, "symptom") || strings.Contains(query, "patient") {
		analysis.Domain = "healthcare"
		analysis.RequiresParallel = false // Healthcare often sequential
		analysis.SuggestedTasks = []string{"symptom-analysis", "diagnosis", "treatment-plan"}
	} else if strings.Contains(query, "invest") || strings.Contains(query, "stock") || strings.Contains(query, "market") {
		analysis.Domain = "finance"
		analysis.SuggestedTasks = []string{"market-data", "financials", "analysis"}
	}

	// Detect parallelism keywords
	if strings.Contains(query, "step by step") || strings.Contains(query, "then") || strings.Contains(query, "after") {
		analysis.RequiresParallel = false
	}

	return analysis
}

// Generate workflow definition from analysis
func (e *PlanningEngine) generateWorkflowDefinition(ctx context.Context, req PlanGenerationRequest, analysis *QueryAnalysis) (*Workflow, error) {
	// Build workflow generation prompt
	prompt := e.buildWorkflowPrompt(req.Query, analysis)

	// Call LLM for workflow generation
	llmReq := OrchestratorRequest{
		RequestID:   fmt.Sprintf("plan-workflow-%d", time.Now().Unix()),
		Query:       prompt,
		RequestType: "workflow-generation",
		User: UserContext{
			TenantID: "system",
		},
	}

	response, _, err := e.llmRouter.RouteRequest(ctx, llmReq)
	if err != nil {
		// Fallback: Generate basic workflow from analysis
		log.Printf("[PlanningEngine] LLM workflow generation failed, using template: %v", err)
		return e.generateTemplateWorkflow(req.Query, analysis), nil
	}

	// Parse workflow from LLM response
	workflow, err := e.parseWorkflowResponse(response, req, analysis)
	if err != nil {
		log.Printf("[PlanningEngine] Workflow parsing failed, using template: %v", err)
		return e.generateTemplateWorkflow(req.Query, analysis), nil
	}

	// Convert flight/hotel steps to Amadeus connector-calls for travel domain
	if analysis.Domain == "travel" {
		e.convertToAmadeusConnectorCalls(workflow, req.Query, req.ClientID, req.RequestID)
	}

	// Enhance synthesis steps with domain-specific detailed prompts
	e.enhanceSynthesisSteps(workflow, req.Query, analysis.Domain)

	return workflow, nil
}

// Build workflow generation prompt
func (e *PlanningEngine) buildWorkflowPrompt(query string, analysis *QueryAnalysis) string {
	return fmt.Sprintf(`You are a workflow designer AI. Generate a structured workflow for this query.

Query: "%s"

Analysis:
- Domain: %s
- Complexity: %d tasks
- Execution: %s
- Suggested Tasks: %v

Generate a workflow with these steps (respond ONLY with valid JSON):
{
  "apiVersion": "v1",
  "kind": "Workflow",
  "metadata": {
    "name": "auto-generated-plan",
    "description": "Auto-generated from query",
    "version": "1.0"
  },
  "spec": {
    "steps": [
      {
        "name": "task-name",
        "type": "llm-call",
        "prompt": "Detailed prompt for this task",
        "execution_mode": "parallel|sequential"
      }
    ],
    "output": {
      "final_result": "{{steps.synthesize-results.output.response}}"
    }
  }
}

Create %d steps. Add a final step named "synthesize-results" (type: llm-call) to combine all previous results into a comprehensive, detailed response.`,
		query,
		analysis.Domain,
		analysis.Complexity,
		map[bool]string{true: "parallel", false: "sequential"}[analysis.RequiresParallel],
		analysis.SuggestedTasks,
		analysis.Complexity)
}

// Parse workflow from LLM response
func (e *PlanningEngine) parseWorkflowResponse(response interface{}, req PlanGenerationRequest, analysis *QueryAnalysis) (*Workflow, error) {
	var responseStr string

	// Extract string from LLMResponse
	if llmResp, ok := response.(*LLMResponse); ok {
		responseStr = llmResp.Content
	} else if str, ok := response.(string); ok {
		responseStr = str
	} else {
		return nil, fmt.Errorf("unexpected response type")
	}

	// Extract JSON
	jsonStart := strings.Index(responseStr, "{")
	jsonEnd := strings.LastIndex(responseStr, "}")

	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no JSON in response")
	}

	jsonStr := responseStr[jsonStart : jsonEnd+1]

	var workflow Workflow
	if err := json.Unmarshal([]byte(jsonStr), &workflow); err != nil {
		return nil, fmt.Errorf("workflow JSON parsing failed: %w", err)
	}

	// Validate workflow
	if len(workflow.Spec.Steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	return &workflow, nil
}

// Generate template workflow (fallback when LLM fails)
func (e *PlanningEngine) generateTemplateWorkflow(query string, analysis *QueryAnalysis) *Workflow {
	workflow := &Workflow{
		APIVersion: "v1",
		Kind:       "Workflow",
		Metadata: WorkflowMetadata{
			Name:        "auto-generated-plan",
			Description: fmt.Sprintf("Auto-generated plan for: %s", query),
			Version:     "1.0",
			Tags:        []string{analysis.Domain, "auto-generated"},
		},
		Spec: WorkflowSpec{
			Timeout: "5m",
			Retries: 1,
			Steps:   make([]WorkflowStep, 0),
			Output:  map[string]string{},
		},
	}

	// Check if Amadeus API is configured
	amadeusConfigured := e.isAmadeusConfigured()

	// Create steps based on suggested tasks
	for i, taskName := range analysis.SuggestedTasks {
		step := e.createTaskStep(taskName, query, analysis.Domain, amadeusConfigured)
		workflow.Spec.Steps = append(workflow.Spec.Steps, step)

		// Limit to complexity count
		if i+1 >= analysis.Complexity {
			break
		}
	}

	// Add synthesis step with domain-aware prompt
	synthesisPrompt := e.buildSynthesisPrompt(query, analysis.Domain)
	synthesisStep := WorkflowStep{
		Name:      "synthesize-results",
		Type:      "llm-call", // Use LLM to actually synthesize results
		Prompt:    synthesisPrompt,
		Timeout:   "30s",
		MaxTokens: 4000, // Allow longer responses for detailed itineraries
	}
	workflow.Spec.Steps = append(workflow.Spec.Steps, synthesisStep)

	// Set output template
	workflow.Spec.Output["final_result"] = "{{steps.synthesize-results.output.response}}"

	return workflow
}

// Build domain-specific synthesis prompt
func (e *PlanningEngine) buildSynthesisPrompt(query string, domain string) string {
	switch domain {
	case "travel":
		return fmt.Sprintf(`You are a travel planning assistant. Based on the research from previous steps, create a COMPLETE trip plan for: %s

IMPORTANT: Create a detailed sample itinerary with realistic estimates. Do NOT ask clarifying questions or mention limitations about real-time data. Generate the plan directly using typical prices and popular options for this destination.

Your response MUST include ALL of these sections:

1. **Flights**
   - Outbound flight: Airline, flight number, departure time, arrival time, estimated price
   - Return flight: Airline, flight number, departure time, arrival time, estimated price
   - Example: "Lufthansa LH1234, Depart 10:30 AM, Arrive 1:45 PM, ~$450"

2. **Hotels** (provide 2-3 options)
   - Hotel name, location/neighborhood, star rating
   - Nightly rate and total cost for the stay
   - Key amenities (WiFi, breakfast, pool, etc.)
   - Example: "Hotel Arts Barcelona - Beachfront, 5-star, $280/night x 3 nights = $840"

3. **Day-by-Day Itinerary** (for EACH day)
   - Morning (9 AM - 12 PM): Specific attraction with address
   - Lunch (12 PM - 2 PM): Restaurant recommendation with cuisine type
   - Afternoon (2 PM - 6 PM): Activities with entry fees
   - Evening (6 PM - 10 PM): Dinner spot and evening activity
   - Example: "Day 1 Morning: Sagrada Familia, Carrer de Mallorca 401, €26 entry"

4. **Activities & Attractions**
   - Must-see landmarks with entry fees
   - Local experiences (cooking class, bike tour, etc.) with prices
   - Transportation options (metro pass: $X, taxi estimates)

5. **Budget Summary**
   - Flights: $X
   - Hotels: $X (breakdown per night)
   - Activities/Entry Fees: $X
   - Food (estimated per day): $X
   - Transportation: $X
   - **TOTAL ESTIMATED COST: $X**

Format as a complete, actionable itinerary. Use specific names, addresses, prices, and times. Make it look professional and ready to use.`, query)

	case "healthcare":
		return fmt.Sprintf(`Based on the clinical data and research from all previous steps, provide a comprehensive medical analysis for: %s

Include:
- Patient assessment summary
- Recommended treatments with dosages and timing
- Expected outcomes and timelines
- Follow-up care plan
- Risk factors and monitoring needs

Be specific and clinically detailed.`, query)

	case "finance":
		return fmt.Sprintf(`Based on the market data and analysis from all previous steps, provide investment recommendations for: %s

Include:
- Investment thesis with supporting data
- Specific asset recommendations with allocations
- Risk analysis and mitigation strategies
- Expected returns and timeframes
- Action items with priorities

Be specific with numbers, tickers, and percentages.`, query)

	default:
		// Generic synthesis
		return fmt.Sprintf(`Synthesize the results from all previous steps into a comprehensive answer for: %s

Provide:
- Clear summary of findings
- Specific recommendations with details
- Action items with priorities
- Any relevant data, metrics, or numbers
- Next steps

Be specific and actionable.`, query)
	}
}

// Enhance synthesis steps with domain-specific detailed prompts
func (e *PlanningEngine) enhanceSynthesisSteps(workflow *Workflow, query string, domain string) {
	if workflow == nil {
		return
	}

	detailedPrompt := e.buildSynthesisPrompt(query, domain)
	enhancedCount := 0

	// Loop through all workflow steps
	for i := range workflow.Spec.Steps {
		step := &workflow.Spec.Steps[i]
		stepNameLower := strings.ToLower(step.Name)

		// Detect synthesis-related steps by name patterns
		if strings.Contains(stepNameLower, "synthesize") ||
			strings.Contains(stepNameLower, "combine") ||
			strings.Contains(stepNameLower, "final") ||
			strings.Contains(stepNameLower, "aggregate") ||
			strings.Contains(stepNameLower, "merge") ||
			strings.Contains(stepNameLower, "summary") {

			// Replace generic prompt with detailed domain-specific prompt
			log.Printf("[PlanningEngine] Enhancing synthesis step '%s' with detailed %s domain prompt", step.Name, domain)
			step.Prompt = detailedPrompt
			enhancedCount++
		}
	}

	if enhancedCount > 0 {
		log.Printf("[PlanningEngine] Enhanced %d synthesis step(s) with detailed prompts", enhancedCount)
	}
}

// Create a task step with appropriate type based on available APIs
func (e *PlanningEngine) createTaskStep(taskName string, query string, domain string, amadeusConfigured bool) WorkflowStep {
	// MCP v0.2: Use connectors for travel queries when available
	if domain == "travel" {
		// Check if this is a flight or hotel search task
		if strings.Contains(strings.ToLower(taskName), "flight") {
			// Use Amadeus connector for flight search
			return WorkflowStep{
				Name:      taskName,
				Type:      "connector-call",
				Connector: "amadeus-travel",
				Operation: "query",
				Statement: "search_flights",
				Parameters: e.extractFlightParameters(query),
				Timeout:   "30s",
			}
		} else if strings.Contains(strings.ToLower(taskName), "hotel") {
			// Use Amadeus connector for hotel search
			return WorkflowStep{
				Name:      taskName,
				Type:      "connector-call",
				Connector: "amadeus-travel",
				Operation: "query",
				Statement: "search_hotels",
				Parameters: e.extractHotelParameters(query),
				Timeout:   "30s",
			}
		}
	}

	// Fall back to LLM calls for other queries
	taskPrompt := e.buildTaskPrompt(taskName, query, domain)
	return WorkflowStep{
		Name:     taskName,
		Type:     "llm-call",
		Prompt:   taskPrompt,
		Timeout:  "30s",
	}
}

// Convert LLM-generated flight/hotel steps to Amadeus connector-calls
func (e *PlanningEngine) convertToAmadeusConnectorCalls(workflow *Workflow, query, clientID, requestID string) {
	if workflow == nil {
		return
	}

	convertedCount := 0

	// Loop through all workflow steps
	for i := range workflow.Spec.Steps {
		step := &workflow.Spec.Steps[i]
		stepNameLower := strings.ToLower(step.Name)

		// Only convert llm-call steps (API steps already have correct type)
		if step.Type != "llm-call" {
			continue
		}

		// Check if this is a flight search step
		if strings.Contains(stepNameLower, "flight") {
			e.logger.Info(clientID, requestID, "Converting step to Amadeus connector-call (flights)", map[string]interface{}{
				"step_name":        step.Name,
				"original_type":    "llm-call",
				"new_type":         "connector-call",
				"connector":        "amadeus-travel",
				"operation":        "search_flights",
			})
			step.Type = "connector-call"
			step.Connector = "amadeus-travel"
			step.Operation = "query"
			step.Statement = "search_flights"
			step.Parameters = e.extractFlightParameters(query)
			step.Timeout = "30s"
			// Clear LLM-specific fields
			step.Prompt = ""
			step.MaxTokens = 0
			convertedCount++
		} else if strings.Contains(stepNameLower, "hotel") {
			e.logger.Info(clientID, requestID, "Converting step to Amadeus connector-call (hotels)", map[string]interface{}{
				"step_name":        step.Name,
				"original_type":    "llm-call",
				"new_type":         "connector-call",
				"connector":        "amadeus-travel",
				"operation":        "search_hotels",
			})
			step.Type = "connector-call"
			step.Connector = "amadeus-travel"
			step.Operation = "query"
			step.Statement = "search_hotels"
			step.Parameters = e.extractHotelParameters(query)
			step.Timeout = "30s"
			// Clear LLM-specific fields
			step.Prompt = ""
			step.MaxTokens = 0
			convertedCount++
		}
	}

	if convertedCount > 0 {
		e.logger.Info(clientID, requestID, "Amadeus connector conversion complete", map[string]interface{}{
			"converted_steps": convertedCount,
			"query":          query,
		})
	}
}

// Build task-specific prompts
func (e *PlanningEngine) buildTaskPrompt(taskName string, query string, domain string) string {
	switch domain {
	case "travel":
		switch taskName {
		case "flight-search", "search-flights":
			return fmt.Sprintf(`Search for flights for: %s

Provide specific flight options including:
- Departure and arrival times
- Airlines and flight numbers
- Prices in USD
- Duration and layovers
- At least 2-3 options at different price points

Format as a clear list with all details.`, query)

		case "hotel-search", "search-hotels":
			return fmt.Sprintf(`Search for hotels for: %s

Provide specific hotel recommendations including:
- Hotel names and locations
- Star ratings
- Nightly rates in USD
- Key amenities (WiFi, breakfast, gym, etc.)
- Distance from city center
- At least 2-3 options at different price points

Format as a clear list with all details.`, query)

		case "activities", "activity-search":
			return fmt.Sprintf(`Find activities and attractions for: %s

Provide specific recommendations including:
- Activity/attraction names
- Locations and how to get there
- Entry fees/costs in USD
- Best times to visit
- Duration needed
- Insider tips

Format as a clear list with all details.`, query)

		default:
			return fmt.Sprintf(`Perform %s for: %s

Provide specific, actionable information with details like names, locations, prices, and times where applicable.`, taskName, query)
		}

	case "healthcare":
		return fmt.Sprintf(`Perform %s for: %s

Provide specific clinical information including:
- Relevant medical data
- Treatment options with dosages
- Expected outcomes
- Monitoring requirements
- Risk factors

Be clinically specific.`, taskName, query)

	case "finance":
		return fmt.Sprintf(`Perform %s for: %s

Provide specific financial analysis including:
- Relevant market data
- Specific recommendations with allocations
- Risk analysis
- Expected returns
- Action items

Be specific with numbers and tickers.`, taskName, query)

	default:
		return fmt.Sprintf(`Perform %s for: %s

Provide specific, detailed information with actionable recommendations.`, taskName, query)
	}
}

// Check if Amadeus API credentials are configured
func (e *PlanningEngine) isAmadeusConfigured() bool {
	apiKey := os.Getenv("AMADEUS_API_KEY")
	apiSecret := os.Getenv("AMADEUS_API_SECRET")
	return apiKey != "" && apiSecret != ""
}

// Optimize execution mode based on analysis
func (e *PlanningEngine) optimizeExecutionMode(workflow *Workflow, analysis *QueryAnalysis) *Workflow {
	// If analysis suggests parallel and tasks are independent
	if analysis.RequiresParallel {
		// Mark all steps except last (synthesis) as parallel
		for i := range workflow.Spec.Steps {
			if i < len(workflow.Spec.Steps)-1 {
				// Add execution_mode hint (not part of WorkflowStep yet, but can be in context)
				workflow.Spec.Steps[i].Timeout = "30s" // Ensure timeout for parallel
			}
		}
	}

	return workflow
}

// Apply user-specified execution mode
func (e *PlanningEngine) applyExecutionMode(workflow *Workflow, mode string) {
	// User override - would need to extend WorkflowStep to support this
	// For now, just log the preference
	log.Printf("[PlanningEngine] User execution mode override: %s", mode)
}

// IsHealthy checks if planning engine is operational
func (e *PlanningEngine) IsHealthy() bool {
	return e.llmRouter != nil && e.llmRouter.IsHealthy()
}

// extractFlightParameters extracts parameters from query for Amadeus flight search
// Enhanced with better pattern matching and validation
func (e *PlanningEngine) extractFlightParameters(query string) map[string]interface{} {
	params := make(map[string]interface{})
	queryLower := strings.ToLower(query)
	words := strings.Fields(query)

	// Pattern 1: "from ORIGIN to DESTINATION"
	if strings.Contains(queryLower, " from ") && strings.Contains(queryLower, " to ") {
		fromIdx := strings.Index(queryLower, " from ")
		toIdx := strings.Index(queryLower, " to ")

		if fromIdx < toIdx {
			// Extract origin (between "from" and "to")
			originText := query[fromIdx+6 : toIdx]
			if origin := e.extractLocation(originText); origin != "" {
				params["origin"] = origin
			}
		}

		// Extract destination (after "to")
		destText := query[toIdx+4:]
		if dest := e.extractLocation(destText); dest != "" {
			params["destination"] = dest
		}
	} else if strings.Contains(queryLower, " to ") {
		// Pattern 2: "DESTINATION trip" or "trip to DESTINATION"
		toIdx := strings.Index(queryLower, " to ")
		destText := query[toIdx+4:]
		if dest := e.extractLocation(destText); dest != "" {
			params["destination"] = dest
		}
	} else {
		// Pattern 3: Just a city name (e.g., "Paris 3 days trip")
		for _, word := range words {
			if len(word) > 2 {
				// Check if it's a known city
				if e.isKnownCity(strings.ToLower(word)) {
					params["destination"] = word
					break
				}
			}
		}
	}

	// Extract number of days
	for i, word := range words {
		wordLower := strings.ToLower(word)
		if wordLower == "day" || wordLower == "days" {
			if i > 0 {
				// Try to parse number before "days"
				if days := e.parseNumber(words[i-1]); days > 0 {
					params["days"] = days
					// Calculate departure date (tomorrow) and return date
					params["departure_date"] = time.Now().AddDate(0, 0, 1).Format("2006-01-02")
					// Don't set return date for Amadeus - one-way search is faster
				}
			}
		}
	}

	// Extract number of adults/people
	for i, word := range words {
		wordLower := strings.ToLower(word)
		if wordLower == "adult" || wordLower == "adults" || wordLower == "people" || wordLower == "person" {
			if i > 0 {
				if adults := e.parseNumber(words[i-1]); adults > 0 {
					params["adults"] = adults
				}
			}
		}
	}

	// Set smart defaults
	if _, ok := params["origin"]; !ok {
		// Try to infer from common patterns
		params["origin"] = "NYC" // Default origin
	}
	if _, ok := params["destination"]; !ok {
		params["destination"] = "PAR" // Fallback to Paris
	}
	if _, ok := params["departure_date"]; !ok {
		params["departure_date"] = time.Now().AddDate(0, 0, 7).Format("2006-01-02") // 1 week from now
	}
	if _, ok := params["adults"]; !ok {
		params["adults"] = 1
	}

	params["max"] = 5 // Always limit results

	log.Printf("[PlanningEngine] Extracted flight params: %+v from query: %s", params, query)
	return params
}

// extractLocation extracts a city/airport name from text
func (e *PlanningEngine) extractLocation(text string) string {
	text = strings.TrimSpace(text)
	words := strings.Fields(text)

	if len(words) == 0 {
		return ""
	}

	// Take first word (usually the city name)
	location := words[0]

	// Remove common words
	commonWords := []string{"for", "with", "in", "on", "at", "trip", "and", "budget", "moderate", "cheap", "luxury"}
	locationLower := strings.ToLower(location)
	for _, common := range commonWords {
		if locationLower == common {
			return ""
		}
	}

	// Clean punctuation
	location = strings.Trim(location, ".,!?;:")

	return location
}

// isKnownCity checks if a word is a known city
func (e *PlanningEngine) isKnownCity(city string) bool {
	knownCities := map[string]bool{
		"paris": true, "london": true, "amsterdam": true, "barcelona": true,
		"rome": true, "berlin": true, "madrid": true, "lisbon": true,
		"tokyo": true, "singapore": true, "bangkok": true, "seoul": true,
		"dubai": true, "sydney": true, "melbourne": true, "auckland": true,
		"nyc": true, "chicago": true, "miami": true, "toronto": true,
		"york": true, "angeles": true, "francisco": true,
	}
	return knownCities[city]
}

// parseNumber extracts a number from a string
func (e *PlanningEngine) parseNumber(s string) int {
	// Try direct conversion
	if num, err := strconv.Atoi(s); err == nil && num > 0 {
		return num
	}

	// Try word to number conversion
	wordToNum := map[string]int{
		"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
		"six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
	}
	if num, ok := wordToNum[strings.ToLower(s)]; ok {
		return num
	}

	return 0
}

// extractHotelParameters extracts parameters from query for Amadeus hotel search
func (e *PlanningEngine) extractHotelParameters(query string) map[string]interface{} {
	params := make(map[string]interface{})

	// Extract city from query
	query = strings.ToLower(query)

	// Extract destination
	words := strings.Fields(query)
	for _, word := range words {
		if len(word) > 2 && word[0] >= 'A' && word[0] <= 'Z' {
			params["city_code"] = word
			break
		}
	}

	if _, ok := params["city_code"]; !ok {
		params["city_code"] = "PAR" // Default to Paris
	}

	// Set check-in/check-out dates
	params["check_in"] = time.Now().AddDate(0, 0, 7).Format("2006-01-02")  // 1 week from now
	params["check_out"] = time.Now().AddDate(0, 0, 10).Format("2006-01-02") // 10 days from now

	return params
}
