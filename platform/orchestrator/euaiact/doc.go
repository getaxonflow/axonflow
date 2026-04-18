// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

// Package euaiact provides EU AI Act compliance functionality for the Orchestrator.
//
// This package implements the export, conformity assessment, and accuracy tracking
// features required for EU AI Act compliance. These features are strategic/batch
// operations that belong in the Orchestrator, as opposed to real-time enforcement
// features (HITL, Circuit Breaker) that remain in the Agent.
//
// # Architecture
//
// The euaiact package follows the Repository/Service/Handler pattern used throughout
// the Orchestrator codebase, similar to the RBI compliance module.
//
// # EU AI Act Articles Covered
//
// This package supports compliance with the following EU AI Act articles:
//
//   - Article 9: Risk Management System - Documented through conformity assessments
//   - Article 10: Data Governance - Export of training data lineage and quality metrics
//   - Article 11: Technical Documentation - Structured export of system documentation
//   - Article 12: Record-keeping - 10-year audit trail with decision chain tracing
//   - Article 13: Transparency - Export of AI decision explanations and rationale
//   - Article 15: Accuracy - Metrics tracking, bias detection, and alerting
//   - Article 17: Quality Management - Conformity assessment workflow
//   - Article 43: Conformity Assessment - Full assessment lifecycle management
//
// # Components
//
// Export (Articles 11, 12, 13):
//   - Generates compliance reports in multiple formats (JSON, CSV, XML, PDF)
//   - Supports various export types: full_audit, conformity_evidence, hitl_summary,
//     decision_chain, policy_violations, accuracy_metrics
//   - Handles asynchronous export with progress tracking
//
// Conformity Assessment (Articles 9, 17, 43):
//   - Manages assessment lifecycle: draft → in_progress → submitted → approved/rejected
//   - Tracks evidence collection and requirement compliance
//   - Supports multi-assessor workflows with approval chains
//
// Accuracy Tracking (Article 15):
//   - Records model accuracy metrics (precision, recall, F1, AUC-ROC, etc.)
//   - Detects bias across demographic groups using demographic parity
//   - Generates alerts when thresholds are violated
//   - Provides historical analysis and trend tracking
//
// # Usage
//
// Initialize the module using NewModule:
//
//	config := euaiact.ModuleConfig{
//	    DB: database,
//	    DefaultAccuracyMin: 0.80,
//	    DefaultBiasMax: 0.10,
//	}
//	module, err := euaiact.NewModule(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	module.RegisterRoutes(mux)
//
// # API Endpoints
//
// Export:
//   - POST /api/v1/euaiact/export - Create new export
//   - GET  /api/v1/euaiact/export - List exports
//   - GET  /api/v1/euaiact/export/{id} - Get export status
//   - GET  /api/v1/euaiact/export/{id}/download - Download export
//
// Conformity Assessment:
//   - POST /api/v1/euaiact/conformity - Create assessment
//   - GET  /api/v1/euaiact/conformity - List assessments
//   - GET  /api/v1/euaiact/conformity/{id} - Get assessment
//   - PUT  /api/v1/euaiact/conformity/{id} - Update assessment
//   - POST /api/v1/euaiact/conformity/{id}/submit - Submit for review
//   - POST /api/v1/euaiact/conformity/{id}/approve - Approve assessment
//   - POST /api/v1/euaiact/conformity/{id}/reject - Reject assessment
//
// Accuracy Tracking:
//   - GET  /api/v1/euaiact/accuracy - Get accuracy summary
//   - POST /api/v1/euaiact/accuracy/record - Record metric
//   - POST /api/v1/euaiact/accuracy/bias - Record bias measurement
//   - GET  /api/v1/euaiact/accuracy/history - Get metric history
//   - GET  /api/v1/euaiact/accuracy/alerts - Get active alerts
//   - POST /api/v1/euaiact/accuracy/alerts/{id}/acknowledge - Acknowledge alert
//   - POST /api/v1/euaiact/accuracy/alerts/{id}/resolve - Resolve alert
//go:build enterprise

package euaiact
