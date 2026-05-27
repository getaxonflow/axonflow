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
//   - POST /api/v1/ojk/audit/export       - Export audit data for OJK compliance
//   - GET  /api/v1/ojk/audit/export/{id}  - Get status of an async export
//   - GET  /api/v1/ojk/audit/retention     - Get retention status for audit data
//   - GET  /api/v1/ojk/audit/readiness     - Check compliance readiness
//   - POST /api/v1/ojk/breach/notify       - Submit UU PDP breach notification
//   - GET  /api/v1/ojk/dashboard           - Get OJK compliance dashboard
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
