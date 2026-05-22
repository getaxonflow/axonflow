// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sebi provides SEBI compliance audit export functionality for
// Indian regulatory requirements under the SEBI AI/ML Guidelines (June 2025).
//
// This package is Enterprise-only and implements the Auditability pillar of
// the SEBI AI/ML Guidelines, which requires:
//
//   - 5-year retention of all AI/ML decision records
//   - Complete audit trail of model inputs, outputs, and actions taken
//   - Exportable audit data for regulatory submissions
//   - PII detection and redaction tracking (PAN, Aadhaar under DPDP Act 2023)
//
// # API Endpoints
//
// The package provides the following API endpoints:
//
//   - POST /api/v1/sebi/audit/export    - Export audit data for SEBI compliance
//   - GET  /api/v1/sebi/audit/export/{id} - Get status of an async export
//   - GET  /api/v1/sebi/audit/retention   - Get retention status for audit data
//   - GET  /api/v1/sebi/audit/readiness   - Check compliance readiness
//
// # Data Types
//
// The export supports the following audit data types:
//
//   - policy_violations: All policy violation records
//   - llm_calls: LLM call audit records with tokens, cost, latency
//   - decision_chain: AI/ML decision chain tracing records
//   - hitl_oversight: Human-in-the-loop oversight records
//   - pii_redactions: PII redaction activity logs
//
// # Export Formats
//
// Audit data can be exported in the following formats:
//
//   - JSON (default): For programmatic access and integration
//   - CSV: For spreadsheet analysis
//   - XML: For legacy system compatibility
//
// # Compliance Frameworks
//
// The package supports the following compliance frameworks:
//
//   - SEBI_AI_ML: SEBI AI/ML Guidelines (5-year retention)
//   - DPDP_ACT_2023: Digital Personal Data Protection Act
//   - SEBI_DPDP_COMBINED: Combined compliance for both frameworks
//
// # Usage Example
//
//	// Create the service (pass nil for storageBackend to disable cloud uploads)
//	service := sebi.NewSEBIAuditExportService(db, storageBackend)
//
//	// Create the handler
//	handler := sebi.NewSEBIAuditExportHandler(service)
//
//	// Register routes
//	handler.RegisterRoutes(mux)
//
// # Compliance Readiness
//
// The package provides a compliance readiness check that validates:
//
//   - Retention configuration (5-year minimum for SEBI)
//   - PII detection policies (PAN, Aadhaar)
//   - Human oversight configuration
//   - Audit logging status
//   - Decision chain tracing
//
// # Security Considerations
//
// All exports include:
//
//   - SHA-256 checksums for data integrity verification
//   - Optional PII redaction for external auditor sharing
//   - Organization isolation via org_id context
//   - CORS validation for web clients
//
// # Database Dependencies
//
// This package requires the following database tables:
//
//   - audit_retention_config (from migration 026)
//   - policy_violations
//   - llm_call_audits
//   - decision_chain
//   - hitl_queue
//   - pii_redaction_log
//
// See migrations/core/026_audit_retention_config.sql for schema details.
//go:build enterprise

package sebi
