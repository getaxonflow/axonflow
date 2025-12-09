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

/*
Package orchestrator provides the AxonFlow Orchestrator service - the
intelligent LLM routing and dynamic policy enforcement engine.

# Overview

The Orchestrator is the brain of the AxonFlow system. It receives
authenticated requests from the Agent and handles:

  - Multi-provider LLM routing with failover
  - Dynamic policy evaluation against database-backed rules
  - Response processing with PII detection and redaction
  - Multi-Agent Planning (MAP) for complex workflows
  - MCP connector management for data source access
  - Comprehensive audit logging

# Architecture

The Orchestrator processes requests through a pipeline:

	Request → Dynamic Policy Engine → LLM Router → Response Processor → Audit

Each stage is instrumented with metrics and can be customized via policies.

# LLM Router

The LLMRouter provides intelligent routing across multiple LLM providers:

  - OpenAI (GPT-4, GPT-3.5-turbo)
  - Anthropic (Claude 3)
  - AWS Bedrock (Claude, Titan, Llama)
  - Ollama (self-hosted models)

Features include:

  - Weighted load balancing across providers
  - Automatic failover on provider errors
  - Health checking with circuit breaker pattern
  - Cost tracking per request

Example:

	router := NewLLMRouter(LoadLLMConfig())
	response, providerInfo, err := router.RouteRequest(ctx, request)

# Dynamic Policy Engine

The DatabaseDynamicPolicyEngine evaluates requests against policies stored
in PostgreSQL:

  - Risk scoring based on query patterns
  - Time-based access controls
  - Department and role-based restrictions
  - Custom policy conditions via SQL expressions

Policies are cached for performance with configurable TTL.

# Multi-Agent Planning (MAP)

The PlanningEngine decomposes complex queries into executable workflows:

	POST /api/v1/plan
	{
	    "query": "Plan a trip from NYC to Paris next week",
	    "domain": "travel"
	}

The engine:

  - Analyzes the query to identify required tasks
  - Creates a workflow with parallel and sequential steps
  - Executes tasks via the WorkflowEngine
  - Aggregates results using the ResultAggregator

# MCP Connector Support

The Orchestrator integrates with MCP (Model Context Protocol) connectors
for data access:

  - Query routing to Agent's MCP handlers
  - Connector marketplace for discovery and installation
  - Health monitoring for all registered connectors

# Policy Management API

CRUD operations for policy management:

	GET    /api/v1/policies         - List all policies
	POST   /api/v1/policies         - Create new policy
	GET    /api/v1/policies/{id}    - Get policy details
	PUT    /api/v1/policies/{id}    - Update policy
	DELETE /api/v1/policies/{id}    - Delete policy
	POST   /api/v1/policies/{id}/test - Test policy against sample input

# Usage

	// Start the Orchestrator service
	orchestrator.Run()

	// The Orchestrator reads configuration from environment variables:
	// PORT           - HTTP server port (default: 8081)
	// DATABASE_URL   - PostgreSQL connection string
	// OPENAI_API_KEY - OpenAI API key (optional)
	// ANTHROPIC_API_KEY - Anthropic API key (optional)
	// BEDROCK_REGION - AWS Bedrock region (optional)
	// OLLAMA_ENDPOINT - Ollama endpoint URL (optional)

# Thread Safety

All exported functions and types in this package are safe for concurrent use.
The Orchestrator handles multiple simultaneous requests using goroutines with
proper synchronization via sync.RWMutex.

# Metrics

The Orchestrator exposes Prometheus metrics at /prometheus:

  - axonflow_orchestrator_requests_total - Total requests by status
  - axonflow_orchestrator_request_duration_milliseconds - Request latency
  - axonflow_orchestrator_llm_calls_total - LLM calls by provider/status
  - axonflow_orchestrator_policy_evaluations_total - Policy evaluations
*/
package orchestrator
