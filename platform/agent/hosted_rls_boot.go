// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"unicode"
)

// hostedCustomerDataTables is the database-enforced tenant boundary for the
// shared Community SaaS database. Boot refuses traffic if a migration drifted,
// a policy was dropped, or FORCE RLS was relaxed on any table in this set.
var hostedCustomerDataTables = []string{
	"hosted_subscriptions", "hosted_governance_events",
	"audit_logs", "admin_audit_log", "llm_call_audits",
	"plans", "plan_versions", "workflows", "workflow_steps", "workflow_checkpoints",
	"evidence_exports", "plugin_user_licenses", "community_saas_daily_usage",
	"tenant_deletion_log", "community_saas_deletion_tokens",
	"budgets", "usage_records", "usage_aggregates",
	"webhook_subscriptions", "webhook_deliveries", "execution_summaries",
	"execution_snapshots", "gateway_contexts", "policy_template_usage",
	"media_governance_config", "budget_alerts",
	// Tables that already had tenant policies before migration 192. Hosted
	// additionally requires FORCE so table-owner credentials cannot bypass
	// them, and boot must detect either a missing policy or a relaxed flag.
	"agent_audit_logs", "orchestrator_audit_logs", "audit_archive",
	"audit_retention_config", "mcp_query_audits", "decision_chain",
	"static_policies", "dynamic_policies", "policy_evaluation_cache",
	"policy_metrics", "policy_violations", "policy_evaluations",
	"policy_overrides", "static_policy_versions", "policy_versions",
	"service_identities", "license_keys", "custom_roles", "role_assignments",
	"user_sessions", "execution_history", "hitl_approval_queue",
	"hitl_approval_history", "llm_providers", "llm_provider_usage",
	"usage_events", "usage_hourly", "usage_daily", "usage_monthly",
	"grafana_organizations", "api_keys", "hosted_portal_members",
	"hosted_portal_login_tokens",
}

func verifyHostedCustomerDataRLS(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("hosted RLS verification requires a database")
	}
	for _, table := range hostedCustomerDataTables {
		var enabled, forced, hasPermissive, hasRestrictive bool
		var keyColumn, guardUsing, guardCheck string
		err := db.QueryRowContext(ctx, `
            SELECT c.relrowsecurity,
                   c.relforcerowsecurity,
                   EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid AND p.polpermissive),
                   EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid AND NOT p.polpermissive),
                   COALESCE((
                       SELECT a.attname FROM pg_catalog.pg_attribute a
                        WHERE a.attrelid = c.oid AND NOT a.attisdropped
                          AND a.attname IN ('org_id', 'tenant_id')
                          AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'bpchar'::regtype)
                        ORDER BY CASE a.attname WHEN 'org_id' THEN 0 ELSE 1 END
                        LIMIT 1), ''),
                   COALESCE((
                       SELECT pg_catalog.pg_get_expr(p.polqual, p.polrelid)
                         FROM pg_catalog.pg_policy p
                        WHERE p.polrelid = c.oid
                          AND p.polname = c.relname || '_hosted_guard'
                          AND NOT p.polpermissive
                        LIMIT 1), ''),
                   COALESCE((
                       SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)
                         FROM pg_catalog.pg_policy p
                        WHERE p.polrelid = c.oid
                          AND p.polname = c.relname || '_hosted_guard'
                          AND NOT p.polpermissive
                        LIMIT 1), '')
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = $1 AND c.relkind = 'r'`, table).
			Scan(&enabled, &forced, &hasPermissive, &hasRestrictive, &keyColumn, &guardUsing, &guardCheck)
		if err == sql.ErrNoRows {
			return fmt.Errorf("hosted tenant-data table %q is missing", table)
		}
		if err != nil {
			return fmt.Errorf("verify hosted RLS on %q: %w", table, err)
		}
		hasTenantGuard := validHostedGuardExpression(table, keyColumn, guardUsing, guardCheck)
		if !enabled || !forced || !hasPermissive || !hasRestrictive || !hasTenantGuard {
			return fmt.Errorf("hosted tenant-data table %q is unsafe (enabled=%t forced=%t permissive=%t restrictive=%t tenant_guard=%t)", table, enabled, forced, hasPermissive, hasRestrictive, hasTenantGuard)
		}
	}

	// The explicit list covers known child tables whose ownership is inherited
	// by a parent join. This schema census also covers every direct AxonFlow
	// customer-keyed table introduced by future migrations. Hosted customer IDs
	// are text cs_* identifiers. Grafana shares this database and also has tables
	// named org_id, but its organization IDs are BIGINT and are not AxonFlow
	// tenant keys. Requiring a restrictive policy prevents a later permissive
	// policy from widening visibility through PostgreSQL's OR semantics. For
	// indirect tables, any policy that references the AxonFlow tenant GUC or
	// helper classifies the table even when RLS is disabled. Certification then
	// requires ENABLE, FORCE, at least one permissive policy, and a restrictive
	// tenant guard that actually references that identity boundary.
	rows, err := db.QueryContext(ctx, `
			SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
			       EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid AND p.polpermissive),
			       EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid AND NOT p.polpermissive),
			       COALESCE((
			           SELECT a.attname FROM pg_catalog.pg_attribute a
			            WHERE a.attrelid = c.oid AND NOT a.attisdropped
			              AND a.attname IN ('org_id', 'tenant_id')
			              AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'bpchar'::regtype)
			            ORDER BY CASE a.attname WHEN 'org_id' THEN 0 ELSE 1 END
			            LIMIT 1), ''),
			       COALESCE((
			           SELECT pg_catalog.pg_get_expr(p.polqual, p.polrelid)
			             FROM pg_catalog.pg_policy p
			            WHERE p.polrelid = c.oid
			              AND p.polname = c.relname || '_hosted_guard'
			              AND NOT p.polpermissive
			            LIMIT 1), ''),
			       COALESCE((
			           SELECT pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid)
			             FROM pg_catalog.pg_policy p
			            WHERE p.polrelid = c.oid
			              AND p.polname = c.relname || '_hosted_guard'
			              AND NOT p.polpermissive
			            LIMIT 1), '')
			  FROM pg_catalog.pg_class c
			  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			 WHERE n.nspname = 'public'
			   AND c.relkind = 'r'
			   AND (EXISTS (
			               SELECT 1 FROM pg_catalog.pg_attribute a
			                WHERE a.attrelid = c.oid AND NOT a.attisdropped
			                  AND a.attname IN ('org_id', 'tenant_id')
			                  AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'bpchar'::regtype))
			       OR EXISTS (
			               SELECT 1
			                 FROM pg_catalog.pg_policy p
			                WHERE p.polrelid = c.oid
			                  AND (
			                      COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '') LIKE '%app.current_org_id%'
			                      OR COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '') LIKE '%app.current_org_id%'
			                      OR COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '') LIKE '%get_current_org_id%'
				                      OR COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '') LIKE '%get_current_org_id%')))
			 ORDER BY c.relname`)
	if err != nil {
		return fmt.Errorf("census hosted tenant-data RLS: %w", err)
	}
	defer rows.Close()
	var unsafe []string
	for rows.Next() {
		var table, keyColumn, guardUsing, guardCheck string
		var enabled, forced, hasPermissive, hasRestrictive bool
		if err := rows.Scan(&table, &enabled, &forced, &hasPermissive, &hasRestrictive, &keyColumn, &guardUsing, &guardCheck); err != nil {
			return fmt.Errorf("scan hosted RLS census: %w", err)
		}
		if !enabled || !forced || !hasPermissive || !hasRestrictive ||
			!validHostedGuardExpression(table, keyColumn, guardUsing, guardCheck) {
			unsafe = append(unsafe, table)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate hosted RLS census: %w", err)
	}
	if len(unsafe) != 0 {
		return fmt.Errorf("hosted RLS schema contains unsafe tables: %s", strings.Join(unsafe, ", "))
	}
	return nil
}

var hostedIndirectGuardExpressions = map[string]string{
	"workflow_steps":             `EXISTS (SELECT 1 FROM workflows w WHERE w.workflow_id = workflow_steps.workflow_id AND w.org_id = current_setting('app.current_org_id', true))`,
	"webhook_deliveries":         `EXISTS (SELECT 1 FROM webhook_subscriptions s WHERE s.id = webhook_deliveries.subscription_id AND s.org_id = current_setting('app.current_org_id', true))`,
	"execution_snapshots":        `EXISTS (SELECT 1 FROM execution_summaries s WHERE s.request_id = execution_snapshots.request_id AND s.org_id = current_setting('app.current_org_id', true))`,
	"gateway_contexts":           `EXISTS (SELECT 1 FROM community_saas_registrations r WHERE r.client_id = gateway_contexts.client_id AND r.org_id = current_setting('app.current_org_id', true))`,
	"budget_alerts":              `EXISTS (SELECT 1 FROM budgets b WHERE b.id = budget_alerts.budget_id AND b.org_id = current_setting('app.current_org_id', true))`,
	"hosted_portal_login_tokens": `EXISTS (SELECT 1 FROM hosted_portal_members m WHERE m.member_id = hosted_portal_login_tokens.member_id AND m.org_id = current_setting('app.current_org_id', true))`,
	"static_policy_versions":     `EXISTS (SELECT 1 FROM static_policies p WHERE p.id = static_policy_versions.policy_id AND p.org_id = current_setting('app.current_org_id', true))`,
	"policy_versions":            `EXISTS (SELECT 1 FROM dynamic_policies p WHERE p.policy_id = policy_versions.policy_id AND p.org_id = current_setting('app.current_org_id', true))`,
}

var hostedCompositeGuardExpressions = map[string]string{
	"hosted_outcome_cases": `org_id = current_setting('app.current_org_id', true)
		AND tenant_id = current_setting('app.current_tenant_id', true)`,
	"hosted_outcome_action_results": `org_id = current_setting('app.current_org_id', true)
		AND tenant_id = current_setting('app.current_tenant_id', true)`,
}

func validHostedGuardExpression(table, keyColumn, usingExpr, checkExpr string) bool {
	expected := hostedCompositeGuardExpressions[table]
	if expected != "" {
		// Composite org+tenant guards are stricter than the default direct-key
		// form and protect multiple tenant identities inside one organization.
	} else if keyColumn != "" {
		expected = fmt.Sprintf(`%s::text = current_setting('app.current_org_id', true)`, keyColumn)
	} else {
		expected = hostedIndirectGuardExpressions[table]
	}
	if expected == "" {
		return false
	}
	want := normalizeHostedGuardExpression(expected)
	return normalizeHostedGuardExpression(usingExpr) == want &&
		normalizeHostedGuardExpression(checkExpr) == want
}

func normalizeHostedGuardExpression(expr string) string {
	expr = strings.ToLower(expr)
	expr = strings.ReplaceAll(expr, "::character varying", "")
	expr = strings.ReplaceAll(expr, "::text", "")
	expr = strings.ReplaceAll(expr, `"`, "")
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '(' || r == ')' {
			return -1
		}
		return r
	}, expr)
}
