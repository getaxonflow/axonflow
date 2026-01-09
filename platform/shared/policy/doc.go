// Package policy provides a unified policy evaluation engine for AxonFlow.
//
// This package implements phase-aware policy enforcement for MCP (Model Context Protocol)
// requests, providing both REQUEST-phase blocking and RESPONSE-phase redaction capabilities.
//
// # Architecture
//
// The package follows ADR-022 (MCP Policy Enforcement Architecture) and provides:
//
//   - Request-phase evaluation: Fast block/allow decisions before connector execution (<5ms p99)
//   - Response-phase evaluation: PII detection and redaction after connector execution
//   - Database-driven policies: All patterns loaded from static_policies table
//   - Performance optimization: Compiled regex caching and policy caching with 5-min TTL
//   - Observability: Prometheus metrics and AuditQueue integration
//
// # Usage
//
// Create a new engine:
//
//	engine := policy.NewUnifiedPolicyEngine(db, policy.DefaultEngineConfig(), auditQueue)
//
// Evaluate request phase (before connector.Query):
//
//	result := engine.EvaluateRequest(ctx, queryStatement, policy.EvalOptions{
//	    TenantID:      "tenant-123",
//	    ConnectorName: "postgres",
//	    Categories:    []policy.PolicyCategory{policy.CategorySecuritySQLi, policy.CategoryPIIGlobal},
//	})
//	if result.Blocked {
//	    // Return 403 with result.BlockReason
//	}
//
// Evaluate response phase (after connector.Query):
//
//	result := engine.EvaluateResponse(ctx, rows, policy.EvalOptions{
//	    TenantID:      "tenant-123",
//	    ConnectorName: "postgres",
//	    Categories:    []policy.PolicyCategory{policy.CategoryPIIGlobal, policy.CategoryPIIUS},
//	})
//	// result.Content contains redacted data
//	// result.RedactedFields lists what was redacted
//
// # Thread Safety
//
// All methods on UnifiedPolicyEngine are safe for concurrent use from multiple goroutines.
// The engine uses sync.RWMutex for cache access and atomic operations for metrics.
//
// # Performance
//
// The engine is designed for high-throughput production use:
//   - Policy cache with configurable TTL (default 5 minutes)
//   - Pre-compiled regex patterns with LRU cache
//   - Async metrics collection via AuditQueue
//   - Background policy refresh every 30 seconds
//
// Benchmarks show <5ms p99 for request evaluation and <10ms p99 for response evaluation
// with typical policy sets (50-100 policies).
package policy
