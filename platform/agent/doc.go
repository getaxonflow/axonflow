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
Package agent provides the AxonFlow Agent service - the authentication,
authorization, and static policy enforcement gateway for AI applications.

# Overview

The Agent is the first line of defense in the AxonFlow architecture. It sits
between client applications and the Orchestrator, handling:

  - Client authentication via license keys and API tokens
  - User authentication via JWT tokens
  - Multi-tenant isolation and verification
  - Static policy enforcement (SQL injection, PII detection)
  - Rate limiting (in-memory or Redis-backed)
  - Gateway Mode for sub-10ms latency scenarios

# Architecture

The Agent operates in two primary modes:

Proxy Mode (default): All requests flow through the Agent to the Orchestrator.
The Agent handles authentication, static policy evaluation, and forwards
approved requests to the Orchestrator for LLM processing.

	Client → Agent (auth + static policies) → Orchestrator (LLM) → Response

Gateway Mode: For latency-sensitive applications, the SDK calls the Agent's
pre-check endpoint before making direct LLM calls, then reports back for audit.

	Client → Agent (pre-check) → Direct LLM Call → Agent (audit)

# Static Policy Engine

The Agent includes a fast (<1ms) regex-based policy engine that evaluates
requests against security patterns:

  - SQL injection detection (UNION attacks, comment injection, always-true conditions)
  - Dangerous query prevention (DROP TABLE, TRUNCATE, ALTER TABLE)
  - PII detection with validation algorithms for 9 types:
    SSN, credit cards (Luhn), emails, phone numbers, IP addresses,
    IBAN (MOD 97), passport numbers, dates of birth, bank accounts (ABA)
  - Admin access control based on user permissions

# Authentication

The Agent supports multiple authentication strategies:

  - License key validation (X-License-Key header)
  - JWT token validation for user identity
  - Database-backed client registration
  - Self-hosted mode for Community deployments

# Gateway Mode API

Gateway Mode provides two endpoints for latency-sensitive applications:

	POST /api/policy/pre-check   - Get policy approval before LLM call
	POST /api/audit/llm-call     - Report LLM call completion for audit

These endpoints use the AuditQueue for reliable persistence with retry
and fallback to JSONL files when the database is unavailable.

# Usage

	// Start the Agent service
	agent.Run()

	// The Agent reads configuration from environment variables:
	// PORT             - HTTP server port (default: 8080)
	// DATABASE_URL     - PostgreSQL connection string
	// ORCHESTRATOR_URL - Orchestrator service URL
	// REDIS_URL        - Redis URL for distributed rate limiting
	// JWT_SECRET       - Secret for JWT token validation

# Thread Safety

All exported functions and types in this package are safe for concurrent use.
The Agent handles multiple simultaneous requests using goroutines with proper
synchronization via sync.RWMutex for metrics and state management.

# Metrics

The Agent exposes Prometheus metrics at /prometheus and JSON metrics at /metrics:

  - axonflow_agent_requests_total - Total requests by status
  - axonflow_agent_request_duration_milliseconds - Request latency histogram
  - axonflow_agent_policy_evaluations_total - Policy evaluation count
  - axonflow_agent_blocked_requests_total - Blocked request count
*/
package agent
