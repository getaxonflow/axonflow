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

package orchestrator

import (
	"axonflow/platform/shared/logger"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestNewPlanningEngine tests planning engine initialization
func TestNewPlanningEngine(t *testing.T) {
	router := NewMockLLMRouter()

	engine := NewPlanningEngine(router)

	if engine == nil {
		t.Fatal("Expected planning engine to be created")
	}

	if engine.llmRouter != router {
		t.Error("Expected LLM router to be set")
	}

	// Either hardcoded templates OR registry-based configs should be initialized
	hasTemplates := len(engine.templates) > 0
	hasRegistry := engine.registry != nil && len(engine.registry.ListDomains()) > 0
	if !hasTemplates && !hasRegistry {
		t.Error("Expected domain templates or registry configs to be initialized")
	}

	// Verify all expected domains are present via getDomainTemplate
	expectedDomains := []string{"travel", "healthcare", "finance", "generic"}
	for _, domain := range expectedDomains {
		template := engine.getDomainTemplate(domain)
		if template == nil {
			t.Errorf("Expected domain %s to be initialized", domain)
		}
	}
}

// TestDomainTemplates tests domain template initialization
func TestDomainTemplates(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		domain          string
		minExpectedAgents int // Min agents (may vary between hardcoded and YAML configs)
		shouldHaveHints bool
	}{
		{"travel", 4, true},       // At least 4 agents
		{"healthcare", 4, true},   // At least 4 agents
		{"finance", 4, true},      // At least 4 agents
		{"generic", 0, true},      // Generic may have 0 or more
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			// Use getDomainTemplate which works with both registry and hardcoded templates
			template := engine.getDomainTemplate(tt.domain)

			if template == nil {
				t.Fatalf("Template for domain %s not found", tt.domain)
			}

			if template.Domain != tt.domain {
				t.Errorf("Expected domain %s, got %s", tt.domain, template.Domain)
			}

			if len(template.CommonTasks) < tt.minExpectedAgents {
				t.Errorf("Expected at least %d common tasks, got %d", tt.minExpectedAgents, len(template.CommonTasks))
			}

			if tt.shouldHaveHints && template.Hints == "" {
				t.Error("Expected hints to be present")
			}
		})
	}
}

// TestHeuristicAnalysis tests the heuristic fallback analysis
func TestHeuristicAnalysis(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name             string
		query            string
		domainHint       string
		expectedDomain   string
		expectedParallel bool
	}{
		{
			name:             "Travel query with flight keyword",
			query:            "Plan a trip to Paris with flights",
			domainHint:       "generic",
			expectedDomain:   "travel",
			expectedParallel: true,
		},
		{
			name:             "Healthcare query with diagnose keyword",
			query:            "Diagnose patient with chest pain",
			domainHint:       "generic",
			expectedDomain:   "healthcare",
			expectedParallel: false, // Healthcare is sequential
		},
		{
			name:             "Finance query with invest keyword",
			query:            "What should I invest in the stock market",
			domainHint:       "generic",
			expectedDomain:   "finance",
			expectedParallel: true,
		},
		{
			name:             "Sequential indicators in query",
			query:            "First analyze symptoms then recommend treatment",
			domainHint:       "healthcare",
			expectedDomain:   "healthcare",
			expectedParallel: false,
		},
		{
			name:             "Generic query with domain hint",
			query:            "Help me with something",
			domainHint:       "finance",
			expectedDomain:   "finance",
			expectedParallel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := engine.heuristicAnalysis(tt.query, tt.domainHint)

			if analysis.Domain != tt.expectedDomain {
				t.Errorf("Expected domain %s, got %s", tt.expectedDomain, analysis.Domain)
			}

			if analysis.RequiresParallel != tt.expectedParallel {
				t.Errorf("Expected parallel=%v, got %v", tt.expectedParallel, analysis.RequiresParallel)
			}

			if analysis.Complexity == 0 {
				t.Error("Expected complexity to be set")
			}

			if len(analysis.SuggestedTasks) == 0 {
				t.Error("Expected suggested tasks to be populated")
			}

			if !stringContains(analysis.Reasoning, "Heuristic") {
				t.Error("Expected reasoning to mention heuristic analysis")
			}
		})
	}
}

// TestParseAnalysisResponse tests JSON parsing of LLM analysis
func TestParseAnalysisResponse(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name        string
		response    interface{}
		shouldError bool
	}{
		{
			name: "Valid JSON in LLMResponse",
			response: &LLMResponse{
				Content: `{"domain":"travel","complexity":3,"requires_parallel":true,"suggested_tasks":["task1","task2"],"reasoning":"test"}`,
			},
			shouldError: false,
		},
		{
			name: "Valid JSON with extra text",
			response: &LLMResponse{
				Content: `Here is the analysis: {"domain":"healthcare","complexity":4,"requires_parallel":false,"suggested_tasks":["task1"],"reasoning":"sequential"} - hope this helps`,
			},
			shouldError: false,
		},
		{
			name:        "Invalid JSON",
			response:    &LLMResponse{Content: "This is not JSON at all"},
			shouldError: true,
		},
		{
			name:        "Empty response",
			response:    &LLMResponse{Content: ""},
			shouldError: true,
		},
		{
			name: "Valid JSON as string",
			response: `{"domain":"finance","complexity":2,"requires_parallel":true,"suggested_tasks":["market-data"],"reasoning":"parallel"}`,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis, err := engine.parseAnalysisResponse(tt.response)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if analysis == nil {
					t.Error("Expected analysis to be returned")
				}
				if analysis != nil && analysis.Domain == "" {
					t.Error("Expected domain to be set in analysis")
				}
			}
		})
	}
}

// TestBuildAnalysisPrompt tests analysis prompt generation
func TestBuildAnalysisPrompt(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	query := "Plan a trip to Tokyo"
	// Use getDomainTemplate which handles both registry and hardcoded templates
	template := engine.getDomainTemplate("travel")

	prompt := engine.buildAnalysisPrompt(query, template)

	// Verify prompt contains essential elements
	if !stringContains(prompt, query) {
		t.Error("Expected prompt to contain original query")
	}

	if !stringContains(prompt, "travel") {
		t.Error("Expected prompt to contain domain")
	}

	if !stringContains(prompt, "JSON") {
		t.Error("Expected prompt to request JSON output")
	}

	if !stringContains(prompt, "complexity") {
		t.Error("Expected prompt to mention complexity")
	}
}

// TestGenerateTemplateWorkflow tests template-based workflow generation
func TestGenerateTemplateWorkflow(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name     string
		query    string
		analysis *QueryAnalysis
	}{
		{
			name:  "Travel workflow",
			query: "Plan a trip to Paris",
			analysis: &QueryAnalysis{
				Domain:           "travel",
				Complexity:       3,
				RequiresParallel: true,
				SuggestedTasks:   []string{"flight-search", "hotel-search", "activities"},
			},
		},
		{
			name:  "Healthcare workflow",
			query: "Diagnose patient",
			analysis: &QueryAnalysis{
				Domain:           "healthcare",
				Complexity:       4,
				RequiresParallel: false,
				SuggestedTasks:   []string{"symptom-analysis", "lab-review", "imaging-review", "diagnosis"},
			},
		},
		{
			name:  "Finance workflow",
			query: "Investment analysis",
			analysis: &QueryAnalysis{
				Domain:           "finance",
				Complexity:       2,
				RequiresParallel: true,
				SuggestedTasks:   []string{"market-data", "company-financials"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow := engine.generateTemplateWorkflow(tt.query, tt.analysis)

			if workflow == nil {
				t.Fatal("Expected workflow to be created")
			}

			if workflow.APIVersion != "v1" {
				t.Errorf("Expected APIVersion v1, got %s", workflow.APIVersion)
			}

			if workflow.Kind != "Workflow" {
				t.Errorf("Expected Kind Workflow, got %s", workflow.Kind)
			}

			if len(workflow.Spec.Steps) == 0 {
				t.Error("Expected workflow to have steps")
			}

			// Should have synthesis step at the end
			lastStep := workflow.Spec.Steps[len(workflow.Spec.Steps)-1]
			if !stringContains(lastStep.Name, "synthesize") {
				t.Error("Expected last step to be synthesis step")
			}

			// Check output template
			if len(workflow.Spec.Output) == 0 {
				t.Error("Expected workflow to have output template")
			}
		})
	}
}

// TestBuildSynthesisPrompt tests domain-specific synthesis prompts
func TestBuildSynthesisPrompt(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		domain         string
		expectedKeywords []string
	}{
		{
			domain: "travel",
			expectedKeywords: []string{"Flights", "Hotels", "Itinerary", "Budget", "TOTAL ESTIMATED COST"},
		},
		{
			domain: "healthcare",
			expectedKeywords: []string{"clinical", "treatment", "dosages", "outcomes"},
		},
		{
			domain: "finance",
			expectedKeywords: []string{"investment", "Risk", "returns", "allocations"},
		},
		{
			domain: "generic",
			expectedKeywords: []string{"summary", "recommendations", "Action items"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			prompt := engine.buildSynthesisPrompt("Test query", tt.domain)

			for _, keyword := range tt.expectedKeywords {
				if !stringContains(prompt, keyword) {
					t.Errorf("Expected prompt to contain keyword: %s", keyword)
				}
			}
		})
	}
}

// TestEnhanceSynthesisSteps tests synthesis step enhancement
func TestEnhanceSynthesisSteps(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "task-1", Type: "llm-call", Prompt: "Do task 1"},
				{Name: "synthesize-results", Type: "llm-call", Prompt: "Combine results"},
				{Name: "final-summary", Type: "llm-call", Prompt: "Summarize"},
			},
		},
	}

	engine.enhanceSynthesisSteps(workflow, "Plan a trip", "travel")

	// Check that synthesis steps were enhanced
	synthesizeStep := workflow.Spec.Steps[1]
	if !stringContains(synthesizeStep.Prompt, "Flights") {
		t.Error("Expected synthesis prompt to be enhanced with travel-specific content")
	}

	finalStep := workflow.Spec.Steps[2]
	if !stringContains(finalStep.Prompt, "TOTAL ESTIMATED COST") {
		t.Error("Expected final step to be enhanced with detailed travel prompt")
	}
}

// TestCreateTaskStep tests task step creation
func TestCreateTaskStep(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name         string
		taskName     string
		domain       string
		expectedType string
	}{
		{
			name:         "Flight search in travel domain",
			taskName:     "flight-search",
			domain:       "travel",
			expectedType: "connector-call",
		},
		{
			name:         "Hotel search in travel domain",
			taskName:     "hotel-search",
			domain:       "travel",
			expectedType: "connector-call",
		},
		{
			name:         "Activities in travel domain",
			taskName:     "activities",
			domain:       "travel",
			expectedType: "llm-call",
		},
		{
			name:         "Healthcare task",
			taskName:     "symptom-analysis",
			domain:       "healthcare",
			expectedType: "llm-call",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := engine.createTaskStep(tt.taskName, "test query", tt.domain, true)

			if step.Name != tt.taskName {
				t.Errorf("Expected step name %s, got %s", tt.taskName, step.Name)
			}

			if step.Type != tt.expectedType {
				t.Errorf("Expected step type %s, got %s", tt.expectedType, step.Type)
			}

			if tt.expectedType == "connector-call" {
				if step.Connector != "amadeus-travel" {
					t.Errorf("Expected connector amadeus-travel, got %s", step.Connector)
				}
			}

			if tt.expectedType == "llm-call" {
				if step.Prompt == "" {
					t.Error("Expected LLM step to have prompt")
				}
			}
		})
	}
}

// TestConvertToAmadeusConnectorCalls tests Amadeus connector conversion
func TestConvertToAmadeusConnectorCalls(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "search-flights", Type: "llm-call", Prompt: "Find flights"},
				{Name: "search-hotels", Type: "llm-call", Prompt: "Find hotels"},
				{Name: "research-activities", Type: "llm-call", Prompt: "Find activities"},
				{Name: "synthesize", Type: "llm-call", Prompt: "Combine"},
			},
		},
	}

	engine.convertToAmadeusConnectorCalls(workflow, "Trip to Paris", "client-1", "req-1")

	// Verify flight step was converted
	flightStep := workflow.Spec.Steps[0]
	if flightStep.Type != "connector-call" {
		t.Errorf("Expected flight step type connector-call, got %s", flightStep.Type)
	}
	if flightStep.Connector != "amadeus-travel" {
		t.Error("Expected amadeus-travel connector for flights")
	}

	// Verify hotel step was converted
	hotelStep := workflow.Spec.Steps[1]
	if hotelStep.Type != "connector-call" {
		t.Errorf("Expected hotel step type connector-call, got %s", hotelStep.Type)
	}

	// Verify activities step was NOT converted
	activitiesStep := workflow.Spec.Steps[2]
	if activitiesStep.Type != "llm-call" {
		t.Error("Expected activities step to remain llm-call")
	}

	// Verify synthesis step was NOT converted
	synthesisStep := workflow.Spec.Steps[3]
	if synthesisStep.Type != "llm-call" {
		t.Error("Expected synthesis step to remain llm-call")
	}
}

// TestExtractFlightParameters tests flight parameter extraction
func TestExtractFlightParameters(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name        string
		query       string
		checkFields []string
	}{
		{
			name:        "From-to pattern",
			query:       "Plan a trip from NYC to Paris for 5 days",
			checkFields: []string{"origin", "destination", "days", "departure_date"},
		},
		{
			name:        "Simple destination",
			query:       "Trip to Barcelona for 3 days",
			checkFields: []string{"destination", "days"},
		},
		{
			name:        "With adults count",
			query:       "Flight to London for 2 adults",
			checkFields: []string{"destination", "adults"},
		},
		{
			name:        "City name only",
			query:       "Tokyo 7 days trip",
			checkFields: []string{"destination", "days"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := engine.extractFlightParameters(tt.query)

			if params == nil {
				t.Fatal("Expected parameters to be returned")
			}

			for _, field := range tt.checkFields {
				if _, exists := params[field]; !exists {
					t.Errorf("Expected field %s to be extracted", field)
				}
			}

			// Always should have max limit
			if params["max"] != 5 {
				t.Error("Expected max parameter to be set to 5")
			}
		})
	}
}

// TestExtractLocation tests location extraction
func TestExtractLocation(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		text     string
		expected string
	}{
		{"Paris for a week", "Paris"},
		{"London and surroundings", "London"},
		{"for Tokyo trip", ""}, // 'for' is filtered out
		{"Barcelona with family", "Barcelona"},
		{"trip to Rome", ""}, // 'trip' is filtered out as common word
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			result := engine.extractLocation(tt.text)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestIsKnownCity tests city validation
func TestIsKnownCity(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		city     string
		expected bool
	}{
		{"paris", true},
		{"london", true},
		{"tokyo", true},
		{"unknowncity", false},
		{"randomplace", false},
		{"nyc", true},
		{"york", true}, // New York
	}

	for _, tt := range tests {
		t.Run(tt.city, func(t *testing.T) {
			result := engine.isKnownCity(tt.city)
			if result != tt.expected {
				t.Errorf("For city %s, expected %v, got %v", tt.city, tt.expected, result)
			}
		})
	}
}

// TestParseNumber tests number parsing from strings
func TestParseNumber(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		input    string
		expected int
	}{
		{"5", 5},
		{"10", 10},
		{"three", 3},
		{"seven", 7},
		{"invalid", 0},
		{"", 0},
		{"0", 0},
		{"-5", 0}, // Negative numbers return 0
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := engine.parseNumber(tt.input)
			if result != tt.expected {
				t.Errorf("For input %s, expected %d, got %d", tt.input, tt.expected, result)
			}
		})
	}
}

// TestExtractHotelParameters tests hotel parameter extraction
func TestExtractHotelParameters(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name             string
		query            string
		expectedCityCode string
	}{
		{
			name:             "Query with known IATA code - matches NYC",
			query:            "Find hotels in NYC",
			expectedCityCode: "NYC", // NYC is a known IATA code
		},
		{
			name:             "Query with lowercase city name - matches paris",
			query:            "find hotels in paris",
			expectedCityCode: "PAR",
		},
		{
			name:             "Query with capitalized city name - matches London",
			query:            "Hotels in London please",
			expectedCityCode: "LON", // "London" is in knownCityCodes
		},
		{
			name:             "Empty query - uses default",
			query:            "",
			expectedCityCode: "PAR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := engine.extractHotelParameters(tt.query)

			if params == nil {
				t.Fatal("Expected parameters to be returned")
			}

			// Should always have city_code
			cityCode, exists := params["city_code"]
			if !exists {
				t.Error("Expected city_code to be set")
			}
			if cityCode != tt.expectedCityCode {
				t.Errorf("Expected city_code %s, got %s", tt.expectedCityCode, cityCode)
			}

			// Should have check-in and check-out dates
			if _, exists := params["check_in"]; !exists {
				t.Error("Expected check_in date to be set")
			}

			if _, exists := params["check_out"]; !exists {
				t.Error("Expected check_out date to be set")
			}
		})
	}
}

// TestIsAmadeusConfigured tests Amadeus configuration check
func TestIsAmadeusConfigured(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	// Save original env vars
	origKey := os.Getenv("AMADEUS_API_KEY")
	origSecret := os.Getenv("AMADEUS_API_SECRET")
	defer func() {
		_ = os.Setenv("AMADEUS_API_KEY", origKey)
		_ = os.Setenv("AMADEUS_API_SECRET", origSecret)
	}()

	// Test with no credentials
	_ = os.Unsetenv("AMADEUS_API_KEY")
	_ = os.Unsetenv("AMADEUS_API_SECRET")
	if engine.isAmadeusConfigured() {
		t.Error("Expected Amadeus to be unconfigured when credentials missing")
	}

	// Test with only API key
	_ = os.Setenv("AMADEUS_API_KEY", "test-key")
	_ = os.Unsetenv("AMADEUS_API_SECRET")
	if engine.isAmadeusConfigured() {
		t.Error("Expected Amadeus to be unconfigured when only API key is set")
	}

	// Test with both credentials
	_ = os.Setenv("AMADEUS_API_KEY", "test-key")
	_ = os.Setenv("AMADEUS_API_SECRET", "test-secret")
	if !engine.isAmadeusConfigured() {
		t.Error("Expected Amadeus to be configured when both credentials are set")
	}
}

// TestOptimizeExecutionMode tests execution mode optimization
func TestOptimizeExecutionMode(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "task-1", Type: "llm-call"},
				{Name: "task-2", Type: "llm-call"},
				{Name: "synthesize", Type: "llm-call"},
			},
		},
	}

	analysis := &QueryAnalysis{
		RequiresParallel: true,
	}

	optimized := engine.optimizeExecutionMode(workflow, analysis)

	if optimized == nil {
		t.Fatal("Expected optimized workflow to be returned")
	}

	// Verify timeouts are set for parallel execution
	for i, step := range optimized.Spec.Steps {
		if i < len(optimized.Spec.Steps)-1 {
			if step.Timeout == "" {
				t.Errorf("Expected timeout to be set for step %s", step.Name)
			}
		}
	}
}

// TestPlanningEngineIsHealthy tests planning engine health check
func TestPlanningEngineIsHealthy(t *testing.T) {
	healthyRouter := NewMockLLMRouter()
	unhealthyRouter := NewMockLLMRouter()
	unhealthyRouter.Healthy = false

	tests := []struct {
		name     string
		router   LLMRouterInterface
		expected bool
	}{
		{
			name:     "Healthy router",
			router:   healthyRouter,
			expected: true,
		},
		{
			name:     "Unhealthy router",
			router:   unhealthyRouter,
			expected: false,
		},
		{
			name:     "Nil router",
			router:   nil, // Explicitly nil LLMRouterInterface
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := &PlanningEngine{
				llmRouter: tt.router,
				templates: make(map[string]*DomainTemplate),
				logger:    logger.New("test"),
			}

			result := engine.IsHealthy()
			if result != tt.expected {
				t.Errorf("Expected health=%v, got %v", tt.expected, result)
			}
		})
	}
}

// TestGeneratePlanWithMockLLM tests end-to-end plan generation with mock LLM
func TestGeneratePlanWithMockLLM(t *testing.T) {
	// Create mock LLM router with fallback to heuristic analysis
	// Since LLM will fail, the planning engine will use heuristics
	router := NewMockLLMRouter()
	router.RouteError = fmt.Errorf("mock LLM failure")

	engine := NewPlanningEngine(router)

	req := PlanGenerationRequest{
		Query:         "Plan a 3 day trip to Paris",
		Domain:        "travel",
		ExecutionMode: "auto",
		ClientID:      "test-client",
		RequestID:     "test-req",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	workflow, err := engine.GeneratePlan(ctx, req)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if workflow == nil {
		t.Fatal("Expected workflow to be generated")
	}

	if len(workflow.Spec.Steps) == 0 {
		t.Error("Expected workflow to have steps")
	}

	// Should have synthesis step
	hasSynthesis := false
	for _, step := range workflow.Spec.Steps {
		if stringContains(strings.ToLower(step.Name), "synthesize") {
			hasSynthesis = true
			break
		}
	}
	if !hasSynthesis {
		t.Error("Expected workflow to have synthesis step")
	}
}

// TestBuildTaskPrompt tests task-specific prompt generation
func TestBuildTaskPrompt(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		domain   string
		taskName string
		keywords []string
	}{
		{
			domain:   "travel",
			taskName: "flight-search",
			keywords: []string{"flights", "Airlines", "Prices", "USD"},
		},
		{
			domain:   "travel",
			taskName: "hotel-search",
			keywords: []string{"hotels", "Star ratings", "Nightly rates"},
		},
		{
			domain:   "healthcare",
			taskName: "diagnosis",
			keywords: []string{"clinical", "Treatment", "dosages"},
		},
		{
			domain:   "finance",
			taskName: "analysis",
			keywords: []string{"financial", "market data", "tickers"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.domain+"_"+tt.taskName, func(t *testing.T) {
			prompt := engine.buildTaskPrompt(tt.taskName, "test query", tt.domain)

			if prompt == "" {
				t.Error("Expected prompt to be generated")
			}

			for _, keyword := range tt.keywords {
				if !stringContains(prompt, keyword) {
					t.Errorf("Expected prompt to contain keyword: %s", keyword)
				}
			}
		})
	}
}

// TestParseWorkflowResponse tests workflow JSON parsing
func TestParseWorkflowResponse(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	validWorkflow := Workflow{
		APIVersion: "v1",
		Kind:       "Workflow",
		Metadata: WorkflowMetadata{
			Name: "test-workflow",
		},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "task-1", Type: "llm-call", Prompt: "Do task"},
			},
		},
	}

	workflowJSON, _ := json.Marshal(validWorkflow)

	tests := []struct {
		name        string
		response    interface{}
		shouldError bool
	}{
		{
			name:        "Valid workflow JSON from LLMResponse",
			response:    &LLMResponse{Content: string(workflowJSON)},
			shouldError: false,
		},
		{
			name:        "Valid workflow JSON from string",
			response:    string(workflowJSON),
			shouldError: false,
		},
		{
			name:        "Workflow with extra text",
			response:    &LLMResponse{Content: "Here is the workflow: " + string(workflowJSON) + " - done"},
			shouldError: false,
		},
		{
			name:        "Invalid JSON",
			response:    &LLMResponse{Content: "Not JSON"},
			shouldError: true,
		},
		{
			name:        "Empty steps",
			response:    &LLMResponse{Content: `{"apiVersion":"v1","kind":"Workflow","spec":{"steps":[]}}`},
			shouldError: true,
		},
		{
			name:        "Unexpected response type",
			response:    123, // int instead of string or LLMResponse
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := PlanGenerationRequest{Query: "test"}
			analysis := &QueryAnalysis{Domain: "generic"}

			workflow, err := engine.parseWorkflowResponse(tt.response, req, analysis)

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if workflow == nil {
					t.Error("Expected workflow to be returned")
				}
			}
		})
	}
}

// TestApplyExecutionMode tests execution mode application
func TestApplyExecutionMode(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "task-1", Type: "llm-call"},
			},
		},
	}

	// Test that apply doesn't panic
	engine.applyExecutionMode(workflow, "parallel")
	engine.applyExecutionMode(workflow, "sequential")
}

// TestNewPlanningEngineWithConfigDir tests creating engine from a config directory
func TestNewPlanningEngineWithConfigDir(t *testing.T) {
	router := NewMockLLMRouter()

	t.Run("empty config dir uses default templates", func(t *testing.T) {
		engine, err := NewPlanningEngineWithConfigDir(router, "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if engine == nil {
			t.Error("expected non-nil engine")
		}
		// Should have default templates initialized
		if len(engine.templates) == 0 {
			t.Error("expected default templates to be initialized")
		}
	})

	t.Run("non-existent dir returns error", func(t *testing.T) {
		_, err := NewPlanningEngineWithConfigDir(router, "/non/existent/path")
		if err == nil {
			t.Error("expected error for non-existent config directory")
		}
	})

	t.Run("valid temp dir with no configs", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "agent-configs-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		engine, err := NewPlanningEngineWithConfigDir(router, tempDir)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if engine == nil {
			t.Error("expected non-nil engine")
		}
	})
}

// TestGetAgentRegistry tests the GetAgentRegistry method
func TestGetAgentRegistry(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	registry := engine.GetAgentRegistry()
	if registry == nil {
		t.Error("expected non-nil registry")
	}
	if registry != engine.registry {
		t.Error("expected GetAgentRegistry to return the same registry instance")
	}
}

// TestReloadAgentConfigs tests config reloading
func TestReloadAgentConfigs(t *testing.T) {
	router := NewMockLLMRouter()

	t.Run("returns error when registry is nil", func(t *testing.T) {
		engine := &PlanningEngine{
			llmRouter: router,
			templates: make(map[string]*DomainTemplate),
			registry:  nil, // nil registry
		}
		err := engine.ReloadAgentConfigs()
		if err == nil {
			t.Error("expected error for nil registry")
		}
		if !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected error about registry not initialized, got: %v", err)
		}
	})

	t.Run("reloads configs from registry", func(t *testing.T) {
		engine := NewPlanningEngine(router)
		// Should not error even if no configs loaded
		err := engine.ReloadAgentConfigs()
		// This might error if no configDir was set, but should not panic
		if err != nil {
			// Expected - no config directory was set
			t.Logf("expected reload error when no config dir: %v", err)
		}
	})
}

// TestTryLoadAgentConfigs tests the config loading from standard paths
func TestTryLoadAgentConfigs(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	// Should return false when no standard paths exist
	loaded := engine.tryLoadAgentConfigs()
	// May or may not load depending on environment
	t.Logf("tryLoadAgentConfigs returned: %v", loaded)
}

// TestGetDomainTemplateFromRegistry tests getDomainTemplate with registry
func TestGetDomainTemplateFromRegistry(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name     string
		domain   string
		wantNil  bool
	}{
		{"travel domain", "travel", false},
		{"healthcare domain", "healthcare", false},
		{"finance domain", "finance", false},
		{"generic domain", "generic", false},
		{"unknown domain returns generic", "unknown", false}, // Falls back to generic
		{"empty domain returns generic", "", false},          // Falls back to generic
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := engine.getDomainTemplate(tt.domain)
			if tt.wantNil && template != nil {
				t.Errorf("expected nil template for domain %s", tt.domain)
			}
			if !tt.wantNil && template == nil {
				t.Errorf("expected non-nil template for domain %s", tt.domain)
			}
		})
	}
}

// TestInitializeTemplates tests the template initialization
func TestInitializeTemplates(t *testing.T) {
	router := NewMockLLMRouter()
	engine := &PlanningEngine{
		llmRouter: router,
		templates: make(map[string]*DomainTemplate),
		registry:  NewAgentRegistry(),
	}

	// Call initializeTemplates
	engine.initializeTemplates()

	// Check expected domains (travel, healthcare, finance, generic)
	expectedDomains := []string{"travel", "healthcare", "finance", "generic"}
	for _, domain := range expectedDomains {
		if _, ok := engine.templates[domain]; !ok {
			t.Errorf("expected template for domain %s", domain)
		}
	}

	// Verify travel template has expected tasks
	travelTemplate := engine.templates["travel"]
	if travelTemplate == nil {
		t.Fatal("travel template is nil")
	}
	if len(travelTemplate.CommonTasks) == 0 {
		t.Error("expected travel template to have common tasks")
	}
	expectedTasks := []string{"flight-search", "hotel-search"}
	for _, task := range expectedTasks {
		found := false
		for _, ct := range travelTemplate.CommonTasks {
			if ct == task {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected travel template to have task: %s", task)
		}
	}

	// Verify generic template exists and has empty CommonTasks
	genericTemplate := engine.templates["generic"]
	if genericTemplate == nil {
		t.Fatal("generic template is nil")
	}
	if genericTemplate.Domain != "generic" {
		t.Errorf("expected domain to be 'generic', got %s", genericTemplate.Domain)
	}
}

// TestBuildSynthesisPromptWithDifferentInputs tests buildSynthesisPrompt with various inputs
func TestBuildSynthesisPromptWithDifferentInputs(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	tests := []struct {
		name        string
		query       string
		domain      string
		wantContain string
	}{
		{
			name:        "travel query",
			query:       "Plan a trip to Paris with flights and hotels",
			domain:      "travel",
			wantContain: "Paris",
		},
		{
			name:        "healthcare query",
			query:       "Find treatment options for diabetes",
			domain:      "healthcare",
			wantContain: "treatment",
		},
		{
			name:        "finance query",
			query:       "Analyze stock portfolio performance",
			domain:      "finance",
			wantContain: "stock",
		},
		{
			name:        "complex query",
			query:       "Find flights from NYC to LAX, book a hotel, and plan activities",
			domain:      "travel",
			wantContain: "flights",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt := engine.buildSynthesisPrompt(tt.query, tt.domain)
			if prompt == "" {
				t.Error("expected non-empty prompt")
			}
			if tt.wantContain != "" && !strings.Contains(strings.ToLower(prompt), strings.ToLower(tt.wantContain)) {
				t.Errorf("expected prompt to contain %s, got: %s", tt.wantContain, prompt[:min(len(prompt), 200)])
			}
		})
	}
}

// TestGenerateWorkflowDefinitionEdgeCases tests generateWorkflowDefinition with edge cases
func TestGenerateWorkflowDefinitionEdgeCases(t *testing.T) {
	// Create a mock router for testing
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	ctx := context.Background()

	tests := []struct {
		name        string
		req         PlanGenerationRequest
		analysis    *QueryAnalysis
		expectError bool
	}{
		{
			name: "basic travel request",
			req: PlanGenerationRequest{
				Query:     "Plan a trip to Paris",
				Domain:    "travel",
				ClientID:  "test-client",
				RequestID: "test-request-1",
			},
			analysis: &QueryAnalysis{
				Domain:           "travel",
				Complexity:       2,
				RequiresParallel: true,
				SuggestedTasks:   []string{"flight-search", "hotel-search"},
				Reasoning:        "Travel planning requires parallel search",
			},
			expectError: false,
		},
		{
			name: "generic query request",
			req: PlanGenerationRequest{
				Query:    "Help me with this task",
				Domain:   "generic",
				ClientID: "test-client",
			},
			analysis: &QueryAnalysis{
				Domain:     "generic",
				Complexity: 1,
			},
			expectError: false,
		},
		{
			name: "healthcare request",
			req: PlanGenerationRequest{
				Query:    "Find treatment options",
				Domain:   "healthcare",
				ClientID: "test-client",
			},
			analysis: &QueryAnalysis{
				Domain:         "healthcare",
				Complexity:     3,
				SuggestedTasks: []string{"symptom-analysis"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, err := engine.generateWorkflowDefinition(ctx, tt.req, tt.analysis)
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.expectError && workflow == nil {
				t.Error("expected non-nil workflow")
			}
		})
	}
}

// =============================================================================
// Coverage tests for SetPricingConfig, SetConnectorRouter, routeToConnectors,
// and applyConnectorMatch
// =============================================================================

type mockPlanCostEstimator struct{}

func (m *mockPlanCostEstimator) EstimateCost(provider, model string, tokensIn, tokensOut int) float64 {
	return 0.01
}

func TestPlanningEngine_SetPricingConfig(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	estimator := &mockPlanCostEstimator{}
	engine.SetPricingConfig(estimator)

	if engine.pricingConfig != estimator {
		t.Error("Expected pricingConfig to be set")
	}
}

func TestPlanningEngine_SetConnectorRouter(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	cr := NewConnectorRouter()
	engine.SetConnectorRouter(cr)

	if engine.connectorRouter != cr {
		t.Error("Expected connectorRouter to be set")
	}
}

func TestPlanningEngine_RouteToConnectors_NilRouter(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)
	// connectorRouter is nil — should return immediately without panic

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "search-flights", Type: "llm-call", Prompt: "find flights"},
			},
		},
	}

	engine.routeToConnectors(workflow, "find flights to Paris", "test-client", "req-1")

	// Step should remain unchanged
	if workflow.Spec.Steps[0].Type != "llm-call" {
		t.Errorf("Expected type 'llm-call', got %q", workflow.Spec.Steps[0].Type)
	}
}

func TestPlanningEngine_RouteToConnectors_NilWorkflow(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)
	engine.SetConnectorRouter(NewConnectorRouter())

	// nil workflow — should return immediately without panic
	engine.routeToConnectors(nil, "query", "client", "req-1")
}

func TestPlanningEngine_RouteToConnectors_CommunityMode(t *testing.T) {
	// Set community mode
	t.Setenv("DEPLOYMENT_MODE", "community")

	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	cr := NewConnectorRouter()
	cr.RegisterCapability(ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights"},
		Connector:  "amadeus-travel",
		Priority:   1,
	})
	engine.SetConnectorRouter(cr)

	// Use a query without "flight" keyword so only the step name triggers the match
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "search-flights", Type: "llm-call", Prompt: "find options to Paris"},
				{Name: "synthesize", Type: "llm-call", Prompt: "combine results"},
			},
		},
	}

	engine.routeToConnectors(workflow, "plan a trip to Paris", "test-client", "req-1")

	// First step should be converted to connector-call (step name matches "flight" keyword)
	if workflow.Spec.Steps[0].Type != "connector-call" {
		t.Errorf("Step 0: expected type 'connector-call', got %q", workflow.Spec.Steps[0].Type)
	}
	if workflow.Spec.Steps[0].Connector != "amadeus-travel" {
		t.Errorf("Step 0: expected connector 'amadeus-travel', got %q", workflow.Spec.Steps[0].Connector)
	}
	if workflow.Spec.Steps[0].Prompt != "" {
		t.Errorf("Step 0: expected empty prompt after conversion, got %q", workflow.Spec.Steps[0].Prompt)
	}

	// Second step should remain llm-call (no keyword match for "synthesize")
	if workflow.Spec.Steps[1].Type != "llm-call" {
		t.Errorf("Step 1: expected type 'llm-call', got %q", workflow.Spec.Steps[1].Type)
	}
}

func TestPlanningEngine_RouteToConnectors_EnterpriseMode(t *testing.T) {
	// Set enterprise mode
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	cr := NewConnectorRouter()
	cr.RegisterCapability(ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights"},
		Connector:  "amadeus-travel",
		Priority:   1,
	})
	engine.SetConnectorRouter(cr)

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "search-flights", Type: "llm-call", Prompt: "find flights"},
			},
		},
	}

	engine.routeToConnectors(workflow, "find flights to NYC", "test-client", "req-2")

	// Step should be converted via enterprise fallback chain path
	if workflow.Spec.Steps[0].Type != "connector-call" {
		t.Errorf("Expected type 'connector-call', got %q", workflow.Spec.Steps[0].Type)
	}
	if workflow.Spec.Steps[0].Connector != "amadeus-travel" {
		t.Errorf("Expected connector 'amadeus-travel', got %q", workflow.Spec.Steps[0].Connector)
	}
}

func TestPlanningEngine_RouteToConnectors_NoMatch(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	cr := NewConnectorRouter()
	cr.RegisterCapability(ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights"},
		Connector:  "amadeus-travel",
		Priority:   1,
	})
	engine.SetConnectorRouter(cr)

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "analyze-data", Type: "llm-call", Prompt: "analyze sales data"},
			},
		},
	}

	engine.routeToConnectors(workflow, "analyze quarterly sales", "test-client", "req-3")

	// No keyword match — step should remain unchanged
	if workflow.Spec.Steps[0].Type != "llm-call" {
		t.Errorf("Expected type 'llm-call' (no match), got %q", workflow.Spec.Steps[0].Type)
	}
}

func TestPlanningEngine_RouteToConnectors_SkipsNonLLMSteps(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	cr := NewConnectorRouter()
	cr.RegisterCapability(ConnectorCapability{
		Domain:     "travel",
		Operations: []string{"search_flights"},
		Connector:  "amadeus-travel",
		Priority:   1,
	})
	engine.SetConnectorRouter(cr)

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "search-flights", Type: "connector-call", Connector: "existing"},
			},
		},
	}

	engine.routeToConnectors(workflow, "flights to Paris", "test-client", "req-4")

	// Already a connector-call — should not be modified
	if workflow.Spec.Steps[0].Connector != "existing" {
		t.Errorf("Expected connector 'existing' (not modified), got %q", workflow.Spec.Steps[0].Connector)
	}
}

func TestPlanningEngine_ApplyConnectorMatch_FlightOperation(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	step := &WorkflowStep{
		Name:      "find-flights",
		Type:      "llm-call",
		Prompt:    "find flights to Paris",
		MaxTokens: 500,
	}

	match := &ConnectorMatch{
		Connector: "amadeus-travel",
		Operation: "search_flights",
		Domain:    "travel",
	}

	engine.applyConnectorMatch(step, match, "find flights from NYC to Paris on 2026-03-15")

	if step.Type != "connector-call" {
		t.Errorf("Expected type 'connector-call', got %q", step.Type)
	}
	if step.Connector != "amadeus-travel" {
		t.Errorf("Expected connector 'amadeus-travel', got %q", step.Connector)
	}
	if step.Statement != "search_flights" {
		t.Errorf("Expected statement 'search_flights', got %q", step.Statement)
	}
	if step.Prompt != "" {
		t.Errorf("Expected empty prompt, got %q", step.Prompt)
	}
	if step.MaxTokens != 0 {
		t.Errorf("Expected maxTokens 0, got %d", step.MaxTokens)
	}
	if step.Parameters == nil {
		t.Error("Expected non-nil parameters for flight operation")
	}
}

func TestPlanningEngine_ApplyConnectorMatch_HotelOperation(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	step := &WorkflowStep{
		Name: "find-hotels",
		Type: "llm-call",
	}

	match := &ConnectorMatch{
		Connector: "amadeus-travel",
		Operation: "search_hotels",
		Domain:    "travel",
	}

	engine.applyConnectorMatch(step, match, "find hotels in Paris for 3 nights")

	if step.Type != "connector-call" {
		t.Errorf("Expected type 'connector-call', got %q", step.Type)
	}
	if step.Parameters == nil {
		t.Error("Expected non-nil parameters for hotel operation")
	}
}

// =============================================================================
// Tests for estimateStepTokens and prompt-aware cost estimation
// =============================================================================

func TestEstimateStepTokens_WithPrompt(t *testing.T) {
	// 400-char prompt → ~100 tokens + 50 overhead = ~150, NOT 1000
	prompt := strings.Repeat("a", 400)
	step := WorkflowStep{
		Name:   "analyze",
		Type:   "llm-call",
		Prompt: prompt,
	}

	tokensIn, tokensOut := estimateStepTokens(step)

	expectedIn := len(prompt)/4 + 50 // 100 + 50 = 150
	if tokensIn != expectedIn {
		t.Errorf("Expected tokensIn=%d, got %d", expectedIn, tokensIn)
	}
	if tokensIn >= 1000 {
		t.Errorf("With a 400-char prompt, tokensIn should be well below default 1000, got %d", tokensIn)
	}

	// No MaxTokens set → should fall back to 500
	if tokensOut != 500 {
		t.Errorf("Expected default tokensOut=500, got %d", tokensOut)
	}
}

func TestEstimateStepTokens_WithMaxTokens(t *testing.T) {
	step := WorkflowStep{
		Name:      "summarize",
		Type:      "llm-call",
		Prompt:    "Summarize the results.",
		MaxTokens: 2000,
	}

	_, tokensOut := estimateStepTokens(step)

	if tokensOut != 2000 {
		t.Errorf("Expected tokensOut=2000 (from MaxTokens), got %d", tokensOut)
	}
}

func TestEstimateStepTokens_EmptyPrompt(t *testing.T) {
	step := WorkflowStep{
		Name: "generic-step",
		Type: "llm-call",
		// No prompt, no max_tokens
	}

	tokensIn, tokensOut := estimateStepTokens(step)

	if tokensIn != 1000 {
		t.Errorf("Expected default tokensIn=1000 for empty prompt, got %d", tokensIn)
	}
	if tokensOut != 500 {
		t.Errorf("Expected default tokensOut=500 for no MaxTokens, got %d", tokensOut)
	}
}

func TestEstimateStepTokens_MultibyteCJK(t *testing.T) {
	// 100 CJK characters = 300 bytes in UTF-8.
	// With len() (bytes): 300/4 + 50 = 125
	// With RuneCount (chars): 100/4 + 50 = 75
	// Must use rune count so CJK isn't overestimated.
	cjkPrompt := strings.Repeat("漢", 100) // 100 CJK characters, 300 UTF-8 bytes
	step := WorkflowStep{
		Name:   "analyze-cjk",
		Type:   "llm-call",
		Prompt: cjkPrompt,
	}

	tokensIn, _ := estimateStepTokens(step)

	expectedIn := 100/4 + 50 // 25 + 50 = 75 (rune-based)
	wrongByteIn := 300/4 + 50 // 75 + 50 = 125 (byte-based, wrong)

	if tokensIn != expectedIn {
		t.Errorf("Expected tokensIn=%d (rune-based), got %d", expectedIn, tokensIn)
	}
	if tokensIn == wrongByteIn {
		t.Errorf("tokensIn=%d matches byte-based calculation — len() is being used instead of RuneCount", tokensIn)
	}
}

func TestEstimateStepTokens_WithOutputSchema(t *testing.T) {
	step := WorkflowStep{
		Name:   "structured-output",
		Type:   "llm-call",
		Prompt: "Analyze this data.",
		Output: map[string]interface{}{
			"summary":         "string",
			"confidence_score": "float",
			"categories":      []string{"a", "b", "c"},
		},
	}

	tokensIn, _ := estimateStepTokens(step)

	// Should be prompt-based tokens + output schema tokens
	promptOnly := len(step.Prompt)/4 + 50
	if tokensIn <= promptOnly {
		t.Errorf("Expected tokensIn > %d (prompt-only) when Output schema is present, got %d", promptOnly, tokensIn)
	}
}

func TestEstimatePlanCost_VariesByPromptLength(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)
	engine.SetPricingConfig(&mockPlanCostEstimator{})

	shortPrompt := "Summarize."
	longPrompt := strings.Repeat("Analyze the comprehensive dataset with detailed instructions. ", 20)

	workflowShort := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step-1", Type: "llm-call", Prompt: shortPrompt, MaxTokens: 500},
			},
		},
	}

	workflowLong := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step-1", Type: "llm-call", Prompt: longPrompt, MaxTokens: 500},
			},
		},
	}

	resultShort := engine.EstimatePlanCost(workflowShort)
	resultLong := engine.EstimatePlanCost(workflowLong)

	if len(resultShort.Breakdown) != 1 || len(resultLong.Breakdown) != 1 {
		t.Fatal("Expected exactly 1 breakdown entry per workflow")
	}

	shortTokensIn := resultShort.Breakdown[0].EstimatedTokensIn
	longTokensIn := resultLong.Breakdown[0].EstimatedTokensIn

	if longTokensIn <= shortTokensIn {
		t.Errorf("Long prompt should produce more estimated input tokens than short prompt: long=%d, short=%d",
			longTokensIn, shortTokensIn)
	}
}

func TestPlanningEngine_ApplyConnectorMatch_GenericOperation(t *testing.T) {
	router := NewMockLLMRouter()
	engine := NewPlanningEngine(router)

	step := &WorkflowStep{
		Name: "run-query",
		Type: "llm-call",
	}

	match := &ConnectorMatch{
		Connector: "my-connector",
		Operation: "analyze_data",
		Domain:    "analytics",
	}

	engine.applyConnectorMatch(step, match, "analyze quarterly sales")

	if step.Type != "connector-call" {
		t.Errorf("Expected type 'connector-call', got %q", step.Type)
	}
	// Generic operation: parameters should just have the query
	if step.Parameters == nil {
		t.Fatal("Expected non-nil parameters")
	}
	if step.Parameters["query"] != "analyze quarterly sales" {
		t.Errorf("Expected query parameter, got %v", step.Parameters)
	}
}
