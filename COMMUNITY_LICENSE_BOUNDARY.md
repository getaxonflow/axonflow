# Community Edition: what you get, and what needs a license

**Applies to:** AxonFlow Platform v10.0.0

> **This document is product documentation, not a license term.** It is **not**
> incorporated into the Business Source License or the Additional Use Grant, it
> is **not** exhaustive, and it does not create or limit any right. `LICENSE` is
> the only thing that governs your use of AxonFlow. Where this page and `LICENSE`
> differ, `LICENSE` controls.
>
> It exists because "what is in Community?" is a fair question that should have a
> straight answer, and because you should be able to check that answer against the
> source rather than take our word for it. Where the implementation is published,
> entries identify it. Three entries below point at source that is not in the
> public repository, because it is enterprise-build-gated or lives under `ee/`;
> each of those three says so rather than pretending otherwise.
>
> If something is missing or wrong here, that is a documentation bug. Tell us at
> licensing@getaxonflow.com and we will fix it.

## How to read this

- **Community limits** are the numeric ceilings the Community build applies.
- The right-hand column points at where each value or gate is defined, so you can verify it. Three entries name source that is not in the public repository and say so; the rest are publicly checkable. It is a pointer for verification only. It does not enumerate every place the value is read, and it is not a claim that the named file is the sole enforcement site.
- **Licensed capabilities** are ones the Community build does not provide.
- A value of `0` means the capability is unavailable at Community.
- Whether your use is permitted is determined by `LICENSE` alone, not by this page.
- An AxonFlow-issued license key may cause the software to apply higher ceilings or enable additional tier-gated capabilities. **That key is not necessarily a paid one:** AxonFlow issues free, time-limited Evaluation keys that raise several of these ceilings. `EvaluationLimits` (`platform/agent/license/tier.go`) sets 50 tenant policies, 5 organization policies and 14-day audit retention, and enables policy simulation and evidence export.
- **A key is not a contract.** What the software does when it reads a key, and what you are permitted to do, are different questions. The applicable software license governs whether production use is permitted; neither this document nor possession of a key independently grants any right. Ask licensing@getaxonflow.com what a given key enables rather than reading the tier table as a promise: the enforcement floor differs by plane, and the agent plane applies a higher floor than the orchestrator plane for tenant-tier and organization-tier policies (`platform/agent/static_policy_repository.go`).
- **A key and a distribution are two different things.** An Evaluation key may cause the software to apply the higher ceilings above and enable tier-gated capabilities. It does not add code that is absent from the Community distribution: capabilities marked below as build-gated are not present in the Community build at all, and running them additionally requires the distribution AxonFlow provides with that key. Compliance reporting is both, for example: it is tier-gated and build-gated.
- Whether production use is permitted is governed by `LICENSE`; read the Additional Use Grant there. Separate commercial terms may provide different rights. Contact licensing@getaxonflow.com.

## Community limits

| Limit | Value | Implementation pointer |
|---|---:|---|
| Tenant-tier policies | 20 | `platform/agent/static_policy_repository.go` (`MaxTenantPoliciesCommunity`); reported by `platform/agent/license/tier.go` (`CommunityLimits.TenantPolicies`) |
| Organization-tier policies | 0 | `platform/orchestrator/policy_api_service.go` (`!license.IsEvaluationOrHigher(licenseTier)` refuses org-tier creation with `ErrCodeOrgTierEvaluationOrHigher`); reported by `platform/orchestrator/policy_tier_support.go` (`DefaultLicenseChecker.OrgPolicyLimit`, which returns a literal `0`) |
| Policy version history returned per policy | 5 | `platform/agent/static_policy_repository.go` (`MaxVersionHistoryCommunity`), applied by `GetVersions`. This caps what a read returns; it does not delete stored versions |
| Custom policy connectors | 2 | Defaulted by `DefaultDynamicPolicyConfig` in `platform/shared/policy/types.go`; applied by `EnforceCustomPolicyConnectorLimit` in `dynamic_evaluator.go`. The production constructor does not load any external override for this ceiling, so the `json` tag on the field is not a supported configuration surface. Enforcement of this ceiling is not fully centralized and a known discrepancy is tracked internally; where the ceiling does apply it truncates silently rather than erroring, and `MCP_DYNAMIC_POLICIES_CONNECTORS` ordering decides which connectors survive |
| Audit retention (days), `audit_logs` only | 3 | `platform/agent/license/tier.go` (`CommunityLimits.AuditRetentionDays`), applied to the `audit_logs` table by `platform/orchestrator/audit_cleanup.go`. **Six other audit tables are not governed by this number:** they run off `audit_retention_config` with a five-year fallback (`defaultRetentionDaysFallback = 1825`) and are dry-run unless `AXONFLOW_AUDIT_RETENTION_ENFORCE` is set. Do not read 3 days as the retention of your whole audit estate |
| LLM providers | 2 | `platform/agent/license/tier.go` (`CommunityLimits.MaxLLMProviders`) |
| Execution history retained | 50 | `platform/agent/license/tier.go` (`CommunityLimits.MaxExecutionHistory`) |
| Concurrent executions | 5 | `platform/agent/license/tier.go` (`CommunityLimits.MaxConcurrentExec`) |
| Plans | 25 | `platform/orchestrator/planning/types.go` (`MaxCommunityPlans`); reported by `CommunityLimits.MaxPlans` |
| Versions per plan | 10 | `platform/orchestrator/planning/types.go` (`MaxCommunityVersionsPerPlan`); reported by `CommunityLimits.MaxVersionsPerPlan` |
| Concurrent SSE connections | 5 | `platform/agent/license/tier.go` (`CommunityLimits.MaxSSEConnections`) |
| Cost estimates per day | 10 | `platform/agent/license/tier.go` (`CommunityLimits.MaxCostEstimatesPerDay`) |
| Pending approvals | 5 | `platform/agent/license/tier.go` (`CommunityLimits.MaxPendingApprovals`). Dormant at Community, on both planes, and in fact unreachable at every shipped tier. The agent build ships a stub that rejects creation outright (`platform/agent/hitl/hitl_community.go`). The workflow-control initializer installs the approval adapter unconditionally on both build tags (`platform/orchestrator/hitl_wcp_community.go` and `hitl_wcp_enterprise.go`, `InitializeWCPHITL`); the entitlement is applied per call at the chokepoint instead, so an unentitled tier is refused with `approval_enqueue: "tier_disabled"` rather than being silently unwired. Since the 2026-08-26 decision the entitled set is Professional, Enterprise and Enterprise Plus, all of which resolve to `EnterpriseLimits.MaxPendingApprovals: -1` (unlimited), while every tier declaring a finite cap (Community, Free, Pro, Premium at 5, Evaluation at 25) is refused by the tier gate before it can spend one. No configuration reaches this number; `TestNoShippedTierCanReachTheCap` fails if that stops being true |
| Decision list lookback (hours) | 24 | `platform/agent/license/tier.go` (`CommunityLimits.DecisionListWindowHours`) |
| Decision list rows per page | 5 | `platform/agent/license/tier.go` (`CommunityLimits.DecisionListMaxPage`) |
| Media analyzers (when media governance is enabled) | 2 | `platform/orchestrator/media/license_gating.go` (`CommunityAnalyzerValidator.GetMaxAnalyzers`). One Community analyzer type currently exists (local OCR), so this ceiling is not presently reachable |

## Available at Community, stated to avoid doubt

These are **not** licensed capabilities. They are listed because they are easy to mistake for one.

| Capability | Note |
|---|---|
| Media governance | Available at Community. Disabled by default; opt in with `MEDIA_GOVERNANCE_ENABLED=true`. Includes local OCR (Tesseract), PII detection on extracted text, image type/size/dimension validation, SHA-256 audit hashing, aggregate cost estimation, and the 5 seeded system media policies. Note that only `sys_media_pii_block` can actually fire at Community: the other four key on NSFW, violence, biometric and sensitive-document fields that only the licensed cloud analyzers populate. Subject to the 2-analyzer limit above and fail-open enforcement (`CommunityAnalyzerValidator`). |
| Core policy enforcement engine | Gateway pre-check, PII detection patterns including Indonesia patterns, basic audit logging |

## Licensed capabilities

| Licensed capability | Implementation pointer |
|---|---|
| Compliance report generation | Build-gated `//go:build enterprise`; the Community distribution ships the stub `platform/orchestrator/compliancereport/compliancereport_community.go`, whose module registers no routes and reports unhealthy |
| Regulatory compliance modules (OJK, SEBI, EU AI Act, MAS FEAT, RBI) | Build-gated `//go:build enterprise`; absent from the Community distribution |
| Customer portal (web UI, dashboards, policy and RBAC administration) | Enterprise-only source tree (`ee/platform/customer-portal/`), which is excluded from the public repository. Not verifiable against published source |
| SCIM provisioning | Enterprise-only source tree (`ee/platform/customer-portal/scim`), not present in the Community distribution. Not verifiable against published source |
| SCIM-backed segment resolution | Build-gated `//go:build enterprise` (`platform/shared/identity/scim_role_resolver.go`, `segment_cache.go`); both are enterprise-tagged and so are not verifiable against published source. The segment *gate* itself ships in Community untagged and proceeds org-only when the resolver is absent |
| Circuit breaker / emergency stop (EU AI Act Article 14) | Community stub, `platform/agent/circuitbreaker/circuitbreaker_community.go` |
| Human-in-the-loop step approvals | `platform/agent/license/tier.go` (`CommunityLimits.HITLApprovalEnabled = false`) |
| Policy simulation and impact reporting | `CommunityLimits.PolicySimulationEnabled = false`, `MaxSimulationsPerDay = 0`, `MaxImpactReportInputs = 0` |
| Evidence export | `CommunityLimits.EvidenceExportEnabled = false`, `MaxEvidenceExportRecords = 0`, `MaxEvidenceWindowDays = 0`, `MaxEvidenceExportsPerDay = 0` |
| Cloud media analyzers (AWS Rekognition, Google Vision, Azure Computer Vision) and custom analyzer plugins | `platform/orchestrator/media/license_gating.go` (`analyzerTierRequirement`) |
| Cowork and Claude Code OTLP ingest | Community stub returns HTTP 501, `platform/agent/cowork_otel_ingest_community.go` |
| Session summary reporting | Community stub returns HTTP 501, `platform/orchestrator/session_summary_handler_community.go` |
| Usage recording | Community stub, `platform/common/usage/recorder_community.go` |
| Amadeus, HubSpot, Jira, Salesforce, ServiceNow, Slack and Snowflake connectors | Community stubs returning `ErrEnterpriseFeature`, `platform/connectors/{amadeus,hubspot,jira,salesforce,servicenow,slack,snowflake}/connector.go` |
| Fraud and risk add-on (FinCrime policy pack, ML risk scoring) | Build-gated `//go:build enterprise`; separately licensed add-on |

## License validation

AxonFlow license keys carry tier information, and the canonical validator verifies their Ed25519 signature and expiry against a public key compiled into the published binaries, with a grace period after expiry. Many limit and feature-gating paths use that validated tier.

**Enforcement is not yet fully centralized.** Not every limit and gate resolves the tier the same way, and known discrepancies are tracked internally. Until that work lands, treat the table above as describing the intended Community posture rather than a guarantee about every code path.

It is **not** the only thing enforcing this boundary. Capabilities absent from the Community distribution are excluded by build tag rather than by the key, and several numeric ceilings are applied by code that does not consult the key at all. The operative wording about license key functionality is in `LICENSE`.

## How we intend to handle this in practice

**A statement of intent, not a contractual commitment, and not a term of any license.**

Our interest is in talking to you, not in catching you out. If we believe a deployment has moved outside the Community boundary, we intend to raise it with you directly before pursuing any remedy. Note that the License terminates rights automatically on a violation and contains no reinstatement mechanism, so nothing here can restore rights the License has ended: any reinstatement or permission has to be confirmed by us in writing. We may change this practice, and it does not limit any right or remedy available to us.

## Changes

This page is versioned with the product and describes the release it ships with. It is documentation, so correcting it does not change anyone's rights; `LICENSE` governs those, and licence changes are prospective in the ordinary way.
