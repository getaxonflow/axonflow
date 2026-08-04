// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

// Package masfeat provides MAS FEAT compliance functionality for the Orchestrator.
//
// This package implements the AI System Registry, FEAT Assessments, and Kill Switch
// features required for MAS (Monetary Authority of Singapore) FEAT compliance.
// These features are strategic/batch operations that belong in the Orchestrator,
// as opposed to real-time policy enforcement features that remain in the Agent.
//
// # Architecture
//
// The masfeat package follows the Repository/Service/Handler pattern used throughout
// the Orchestrator codebase, similar to the EU AI Act compliance module.
//
// # MAS FEAT Principles Covered
//
// This package supports compliance with the MAS FEAT framework:
//
//   - Fairness: Bias detection, demographic parity monitoring, fairness assessments
//   - Ethics: Data protection, PDPA compliance, responsible AI practices
//   - Accountability: Decision audit trails, model governance, kill switch capability
//   - Transparency: AI disclosure, explainability requirements, customer recourse
//
// # MAS AI Risk Management Guidelines 2025
//
// This package implements the 3-dimensional risk rating approach:
//
//   - Impact: Potential harm to customers/market (1-5 scale)
//   - Complexity: Technical complexity and opacity of the AI system (1-5 scale)
//   - Reliance: Degree of human reliance on AI outputs (1-5 scale)
//
// Materiality Classification:
//   - High: Sum >= 12
//   - Medium: Sum >= 8
//   - Low: Sum < 8
//
// # Components
//
// AI System Registry:
//   - Register AI systems with MAS-required metadata
//   - Track 3-dimensional risk ratings and materiality
//   - Monitor assessment schedules and compliance status
//   - Support lifecycle management (draft → active → suspended → retired)
//
// FEAT Assessments:
//   - Create and manage 4-pillar FEAT assessments
//   - Track scores for Fairness, Ethics, Accountability, Transparency
//   - Document findings and recommendations
//   - Support assessment workflow (pending → in_progress → completed → approved)
//
// Kill Switch:
//   - Emergency disable capability per MAS requirements
//   - Auto-trigger based on configurable thresholds
//   - Full audit trail of all state changes
//   - Runtime enforcement integration
//
// # Usage
//
// Initialize the module using NewModule:
//
//	config := masfeat.ModuleConfig{
//	    DB: database,
//	    DefaultBiasThreshold: 0.10,
//	}
//	module, err := masfeat.NewModule(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	module.RegisterRoutes(router)
//
// # API Endpoints
//
// AI System Registry:
//   - POST /api/v1/masfeat/registry - Register AI system
//   - GET  /api/v1/masfeat/registry - List registered systems
//   - GET  /api/v1/masfeat/registry/{id} - Get system details
//   - PUT  /api/v1/masfeat/registry/{id} - Update system
//   - GET  /api/v1/masfeat/registry/summary - Get registry summary
//
// FEAT Assessments:
//   - POST /api/v1/masfeat/assessments - Create assessment
//   - GET  /api/v1/masfeat/assessments - List assessments
//   - GET  /api/v1/masfeat/assessments/{id} - Get assessment
//   - PUT  /api/v1/masfeat/assessments/{id} - Update assessment
//   - POST /api/v1/masfeat/assessments/{id}/submit - Submit for review
//   - POST /api/v1/masfeat/assessments/{id}/approve - Approve assessment
//   - POST /api/v1/masfeat/assessments/{id}/reject - Reject assessment
//
// Kill Switch:
//   - GET  /api/v1/masfeat/killswitch/{system_id} - Get kill switch status
//   - POST /api/v1/masfeat/killswitch/{system_id}/configure - Configure thresholds
//   - POST /api/v1/masfeat/killswitch/{system_id}/trigger - Trigger kill switch
//   - POST /api/v1/masfeat/killswitch/{system_id}/restore - Restore system
//   - GET  /api/v1/masfeat/killswitch/{system_id}/history - Get state change history
//
// Export (#3241, epic #2892):
//
// This module has NO export endpoints of its own. Regulator-facing MAS FEAT
// artifacts are produced by the unified compliance report facade:
//
//   - POST /api/v1/compliance/reports        - create (regulator=masfeat), 202
//   - GET  /api/v1/compliance/reports/{id}          - poll
//   - GET  /api/v1/compliance/reports/{id}/download - presigned artifact
//
// The facade reads this module's registry, assessment and kill-switch services
// read-only (platform/orchestrator/compliancereport/provider_masfeat.go) and
// renders PDF, CSV or JSON.
//
// Until that change this section documented three endpoints -
// POST /api/v1/masfeat/export and two /export/{id} routes - that were never
// implemented, alongside three /api/v1/masfeat/bias routes that likewise do not
// exist: a grep for either path across the tree returns only this file. Both
// sets are removed rather than left as aspirations, because a documented
// endpoint that 404s reads to an integrator as a broken deployment.
//
// On bias specifically: migration 400 creates a mas_bias_metrics table and
// RLS-gates it, but the table has no repository, no reader and no writer
// anywhere in this tree - TestMASFEAT_BiasMetricsHasNoGoCallSite pins that. So
// the removed routes were not "not yet exposed", they had nothing behind them.
// Bias and fairness ARE assessed, through the FEAT assessment pillars above.
//go:build enterprise

package masfeat
