// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package main

// Enterprise imports - these packages register themselves via init()
import (
	// Enterprise connector factory registration (Slack, Salesforce, Amadeus, etc.)
	_ "axonflow/ee/platform/agent/connectors"

	// Advanced SQL injection scanner (ML-based)
	_ "axonflow/ee/platform/agent/sqli"
)
