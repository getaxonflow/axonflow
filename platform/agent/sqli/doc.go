// Package sqli provides SQL injection detection for AxonFlow.
//
// This package implements configurable SQL injection scanning with three modes:
//   - off: No scanning (for performance-critical use cases)
//   - basic: Pattern matching using regex (fast, good accuracy)
//   - advanced: ML/heuristic analysis (slower, best accuracy) - Enterprise only
//
// # Usage
//
// Create a scanner using the factory function:
//
//	scanner, err := sqli.NewScanner(sqli.ModeBasic)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result := scanner.Scan(ctx, input, sqli.ScanTypeInput)
//	if result.Detected {
//	    log.Printf("SQL injection detected: %s", result.Pattern)
//	}
//
// Or use the middleware for MCP connector response scanning:
//
//	middleware, err := sqli.NewScanningMiddleware()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	scanResult, err := middleware.ScanQueryResponse(ctx, "postgresql", rows)
//	if scanResult.Blocked {
//	    // Handle blocked response
//	}
//
// # Configuration
//
// Scanning can be configured separately for input (user prompts) and output
// (MCP connector responses):
//
//	config := sqli.DefaultConfig().
//	    WithInputMode(sqli.ModeBasic).
//	    WithResponseMode(sqli.ModeBasic).
//	    WithBlockOnDetection(true)  // Enable blocking (default is monitoring mode)
//
// # Community vs Enterprise
//
// The basic scanner is available in the Community edition.
// The advanced scanner (ML/heuristic) requires an Enterprise license.
//
// # Compliance Integration
//
// Detection events can be logged to the audit trail for compliance with:
//   - EU AI Act (Article 15 - Accuracy)
//   - RBI FREE-AI Framework (Data Integrity)
//   - SEBI AI/ML Guidelines (Audit Trail)
package sqli
