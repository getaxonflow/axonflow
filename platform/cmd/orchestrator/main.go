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
