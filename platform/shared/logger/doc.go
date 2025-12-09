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
Package logger provides structured JSON logging with multi-tenant support
for AxonFlow components.

# Overview

The logger package provides structured logging that outputs JSON to stdout,
making logs easily consumable by CloudWatch, ELK stack, or other log
aggregation systems.

Each log entry includes:
  - Timestamp (RFC3339Nano format)
  - Log level (DEBUG, INFO, WARN, ERROR)
  - Component name (agent, orchestrator, etc.)
  - Instance ID and container name (for distributed tracing)
  - Client ID (for multi-tenant isolation)
  - Request ID (for request correlation)
  - Custom fields

# Usage

Create a logger for your component:

	log := logger.New("agent")

Log messages with client and request context:

	log.Info("client-123", "req-456", "Processing request", map[string]interface{}{
	    "method": "POST",
	    "path":   "/api/v1/process",
	})

Log errors with status codes:

	log.ErrorWithCode("client-123", "req-456", "Request failed", 500, err, map[string]interface{}{
	    "endpoint": "/api/v1/process",
	})

Log with duration tracking:

	start := time.Now()
	// ... do work ...
	log.InfoWithDuration("client-123", "req-456", "Request completed",
	    float64(time.Since(start).Milliseconds()), nil)

# Output Format

Log entries are output as single-line JSON:

	{"timestamp":"2025-01-15T10:30:00.123456789Z","level":"INFO",
	 "component":"agent","instance_id":"i-abc123","container":"agent-xyz",
	 "client_id":"client-123","request_id":"req-456",
	 "message":"Processing request","fields":{"method":"POST"}}

# Environment Variables

The logger reads these environment variables:

  - INSTANCE_ID: Deployment instance identifier
  - HOSTNAME: Container hostname (auto-detected)

# Thread Safety

Logger instances are safe for concurrent use from multiple goroutines.
*/
package logger
