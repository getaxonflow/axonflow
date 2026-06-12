// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package ojk provides OJK compliance audit export functionality for
// Indonesian regulatory requirements under OJK AI Governance (April 2025),
// BI payment system regulations, and UU PDP (Law No. 27 of 2022).
//
// This package is Enterprise-only and implements:
//
//   - OJK AI Governance: audit trail, model registry, human oversight
//   - BI PJP (PBI 23/6/PBI/2021): payment system IS audits, incident reporting
//   - UU PDP: breach notification (Art. 46, 3x24h), cross-border transfer logging (Art. 56)
//
// # API Endpoints
//
//   - POST /api/v1/ojk/audit/export             - Export audit data for OJK compliance
//   - GET  /api/v1/ojk/audit/export/{id}        - Get status of an async export
//   - GET  /api/v1/ojk/audit/retention          - Get retention status for audit data
//   - GET  /api/v1/ojk/audit/readiness          - Check compliance readiness
//   - POST /api/v1/ojk/breach/notify            - Submit UU PDP breach notification
//   - POST /api/v1/ojk/breach/acknowledge       - Record authority acknowledgement
//   - POST /api/v1/ojk/breach/evaluate-deadlines - Flip lapsed un-submitted breaches to overdue
//   - GET  /api/v1/ojk/dashboard                - Get OJK compliance dashboard
//
// # Breach Notification Lifecycle (UU PDP Art. 46)
//
// notification_deadline = discovery_time + 72h (3x24h). The status column is a
// gated lifecycle — never a hard-coded literal — and is the evidence artifact
// distinguishing a timely report from an overdue/failed/never-sent one:
//
//	draft ──submit──▶ submitted ──acknowledge──▶ acknowledged   (terminal success)
//	  │                   │
//	  └──fail──▶ failed ◀─┘                       (terminal)
//	  └─(deadline evaluator)─▶ overdue            (never submitted in time)
//
// submitted/acknowledged are outputs of ApplyBreachTransition; overdue is set
// only by the deadline evaluator (EvaluateBreachStatus on read, or
// EvaluateBreachDeadlines durably) when now() passes notification_deadline
// without a timely submission. submitted_at / acknowledged_at are written on the
// respective transitions and read back by the exporter and dashboard.
//
// # Compliance Frameworks
//
//   - OJK_AI_GOVERNANCE: OJK AI Governance guidance (5-year retention)
//   - UU_PDP: Personal Data Protection law (breach notification + cross-border)
//   - BI_PJP: Bank Indonesia payment system governance
//   - OJK_BI_COMBINED: Combined compliance for all frameworks
//
//go:build enterprise

package ojk
