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

/*
Package usage provides usage metering and billing support for AxonFlow.

# Overview

The usage package records usage events to PostgreSQL for billing and analytics.
It supports two types of usage events:

  - API calls: HTTP request metrics for request-based billing
  - LLM requests: Token usage and cost tracking for LLM API calls

# Usage Recording

Create a recorder with a database connection:

	recorder := usage.NewUsageRecorder(db)

Record API calls:

	err := recorder.RecordAPICall(usage.APICallEvent{
	    OrgID:          "org-123",
	    ClientID:       "client-456",
	    InstanceID:     "agent-001",
	    InstanceType:   "agent",
	    HTTPMethod:     "POST",
	    HTTPPath:       "/api/v1/process",
	    HTTPStatusCode: 200,
	    LatencyMs:      45,
	})

Record LLM requests with automatic cost calculation:

	err := recorder.RecordLLMRequest(usage.LLMRequestEvent{
	    OrgID:            "org-123",
	    ClientID:         "client-456",
	    InstanceID:       "orchestrator-001",
	    InstanceType:     "orchestrator",
	    LLMProvider:      "openai",
	    LLMModel:         "gpt-4",
	    PromptTokens:     150,
	    CompletionTokens: 200,
	    TotalTokens:      350,
	    LatencyMs:        1200,
	    HTTPStatusCode:   200,
	})

# Cost Calculation

LLM costs are calculated automatically based on the pricing module:

	costCents := usage.CalculateCost("openai", "gpt-4", promptTokens, completionTokens)

Supported providers and their pricing are defined in pricing.go.

# Database Schema

Events are stored in the usage_events table with columns for:
  - Organization and client identification
  - Event type (api_call or llm_request)
  - Instance metadata (ID, type)
  - HTTP metrics (method, path, status, latency)
  - LLM metrics (provider, model, tokens, cost)

# Thread Safety

UsageRecorder is safe for concurrent use. Recording methods can be called
from multiple goroutines simultaneously.

# Best Practices

Record usage asynchronously to avoid blocking request processing:

	go func() {
	    if err := recorder.RecordAPICall(event); err != nil {
	        log.Printf("Failed to record usage: %v", err)
	    }
	}()
*/
package usage
