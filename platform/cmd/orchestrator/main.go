// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package main is the entry point for the AxonFlow Orchestrator service.
//
// The Orchestrator is a Multi-Agent Planning (MAP) service that:
// - Decomposes complex queries into executable task plans
// - Routes requests to appropriate LLM providers (OpenAI, Bedrock, Ollama)
// - Manages dynamic policy evaluation
// - Coordinates workflow execution with dependency management
// - Aggregates results from parallel task execution
//
// Usage:
//
//	./orchestrator
//
// Environment Variables:
//
//	PORT - HTTP server port (default: 8081)
//	DATABASE_URL - PostgreSQL connection string
//	OPENAI_API_KEY - OpenAI API key (optional)
//	BEDROCK_REGION - AWS Bedrock region (optional)
//	OLLAMA_ENDPOINT - Ollama endpoint URL (optional)
//
// For more information, see https://docs.getaxonflow.com
package main

import (
	"axonflow/platform/orchestrator"
)

func main() {
	orchestrator.Run()
}
