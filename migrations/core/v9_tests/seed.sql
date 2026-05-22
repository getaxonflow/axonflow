-- Canonical seed data for v9 migration assertion suite.
-- Applied AFTER all base migrations (001-085) and BEFORE migrations 088-095.
-- Mirrors a realistic community-saas + self-hosted hybrid deployment.

-- ----------------------------------------------------------------------------
-- Organizations — must exist before tenants FK can be satisfied
-- ----------------------------------------------------------------------------
INSERT INTO organizations (org_id, name, tier, max_nodes, license_key) VALUES
    ('community-saas', 'Community-SaaS Platform', 'Community', 999999, ''),
    ('acme-corp',      'Acme Corporation',         'Enterprise', 10, ''),
    ('community',      'Self-Hosted Community',    'Community', 2, '')
ON CONFLICT (org_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- Community-SaaS rows (org_id = shared 'community-saas' sentinel, will be
-- remapped by 094 Pass-1 to per-customer cs_<uuid>)
-- ----------------------------------------------------------------------------

INSERT INTO community_saas_registrations (tenant_id, secret_hash, secret_prefix, label, org_id) VALUES
    ('cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'bcrypt$placeholder1', 'cs_aaaa', 'rehearsal-customer-1', 'community-saas'),
    ('cs_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2', 'bcrypt$placeholder2', 'cs_bbbb', 'rehearsal-customer-2', 'community-saas'),
    ('cs_cccccccc-cccc-cccc-cccc-ccccccccccc3', 'bcrypt$placeholder3', 'cs_cccc', 'rehearsal-customer-3', 'community-saas')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO tenants (tenant_id, org_id, name, environment) VALUES
    ('cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'community-saas', 'rehearsal-customer-1', 'prod'),
    ('cs_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2', 'community-saas', 'rehearsal-customer-2', 'prod'),
    ('acme-prod-api', 'acme-corp', 'Acme Production', 'prod'),
    ('beta-staging',  'community', 'Beta Staging',  'staging')
ON CONFLICT (tenant_id) DO NOTHING;

-- Audit rows with empty org_id — exercises 094 Pass-1 (cs_*) + Pass-2 (self-hosted)
INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role, client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision)
VALUES
    ('seed-aud-1', 'req-aaa-1', NOW(), 1, 'a@example.com', 'admin', 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', NULL, 'llm_call', 'select 1', 'sha-1', 'allow'),
    ('seed-aud-2', 'req-bbb-2', NOW(), 2, 'b@example.com', 'user',  'cs_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2', 'cs_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2', NULL, 'llm_call', 'select 2', 'sha-2', 'allow'),
    ('seed-aud-3', 'req-acm-3', NOW(), 3, 'c@example.com', 'admin', 'acme-prod-api', 'acme-prod-api', NULL, 'llm_call', 'select 3', 'sha-3', 'allow')
ON CONFLICT (id) DO NOTHING;

-- mcp_query_audits
INSERT INTO mcp_query_audits (audit_id, tenant_id, client_id, connector_name, operation, success)
VALUES
    ('seed-mcp-1', 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'salesforce', 'query', true),
    ('seed-mcp-2', 'acme-prod-api', 'acme-prod-api', 'salesforce', 'query', true)
ON CONFLICT (audit_id) DO NOTHING;

-- llm_call_audits
INSERT INTO llm_call_audits (audit_id, client_id, provider, model)
VALUES
    ('seed-llm-1', 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'openai',    'gpt-4'),
    ('seed-llm-2', 'acme-prod-api',                            'anthropic', 'claude-3-sonnet')
ON CONFLICT (audit_id) DO NOTHING;

-- agent_audit_logs
INSERT INTO agent_audit_logs (client_id, action, resource) VALUES
    ('cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'request', 'mcp:salesforce:query'),
    ('acme-prod-api',                            'request', 'mcp:slack:post');

-- Static policies — exercise 'global' sentinel preservation
INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tenant_id, org_id) VALUES
    ('seed-static-1', 'block-ssn', 'pii-us', '\\d{3}-\\d{2}-\\d{4}', 'high', 'block', 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', NULL),
    ('seed-static-2', 'block-cc',  'pii-us', '\\d{16}',              'high', 'block', 'global',                                   NULL),
    ('seed-static-3', 'block-pwd', 'security', 'password=.+',        'medium', 'redact', 'acme-prod-api',                         NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- Dynamic policies
INSERT INTO dynamic_policies (policy_id, name, policy_type, conditions, actions, tenant_id, org_id) VALUES
    ('seed-dyn-1', 'cost-cap', 'workflow', '[]'::jsonb, '[]'::jsonb, 'cs_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2', NULL),
    ('seed-dyn-2', 'risk-eval', 'risk_based', '[]'::jsonb, '[]'::jsonb, 'global',                              NULL)
ON CONFLICT (policy_id) DO NOTHING;

-- policy_evaluations
INSERT INTO policy_evaluations (evaluation_type, tenant_id, processing_time_ms) VALUES
    ('request',  'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 5),
    ('response', 'acme-prod-api',                            7);

-- service_identities
INSERT INTO service_identities (tenant_id, service_name, service_type, permissions)
VALUES
    ('cs_cccccccc-cccc-cccc-cccc-ccccccccccc3', 'plugin-svc', 'backend-service', ARRAY['mcp:salesforce:query']),
    ('acme-prod-api',                            'trip-svc',  'client-application', ARRAY['mcp:amadeus:*'])
ON CONFLICT (tenant_id, service_name) DO NOTHING;

-- execution_history (column shape: tenant_id, org_id, client_id all present
-- from migration 042; we leave client_id NULL on one row to exercise 092 backfill)
INSERT INTO execution_history (id, execution_type, external_id, name, tenant_id, org_id, client_id, status) VALUES
    ('seed-exec-1', 'map_plan', 'plan-1', 'Rehearsal MAP plan', 'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', NULL, NULL, 'completed'),
    ('seed-exec-2', 'wcp_workflow', 'wf-2', 'Rehearsal WCP', 'acme-prod-api', NULL, NULL, 'running')
ON CONFLICT (id) DO NOTHING;

-- plugin_user_licenses (FK to community_saas_registrations(tenant_id))
INSERT INTO plugin_user_licenses (tenant_id, claimed_by_email, tier, license_token_jti)
VALUES
    ('cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'a@example.com', 'Pro', 'jti-aaa-1'),
    ('cs_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb2', 'b@example.com', 'Pro', 'jti-bbb-2')
ON CONFLICT (license_token_jti) DO NOTHING;

-- saml_configurations (class b — must stay populated with non-empty org_id)
INSERT INTO saml_configurations (org_id, provider, idp_metadata_url, idp_entity_id, idp_sso_url, idp_certificate, sp_entity_id, sp_acs_url)
VALUES
    ('acme-corp', 'okta', 'https://acme.okta.com/metadata', 'https://acme.okta.com', 'https://acme.okta.com/sso', '----cert----', 'axonflow', 'https://axonflow.acme/acs')
ON CONFLICT (org_id) DO NOTHING;

-- usage_records — exercise the team_id classification COMMENT
INSERT INTO usage_records (request_id, org_id, tenant_id, team_id, provider, model, tokens_in, tokens_out, cost_usd)
VALUES
    ('seed-usage-1', NULL,        'cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1', 'team-a', 'openai', 'gpt-4', 100, 200, 0.05),
    ('seed-usage-2', 'acme-corp', 'acme-prod-api',                            'team-b', 'anthropic', 'claude-3-sonnet', 100, 200, 0.04);

DO $$
BEGIN
    RAISE NOTICE 'v9 test seed applied — community_saas_registrations(3), tenants(4), audit_logs(3), mcp_query_audits(2), llm_call_audits(2), agent_audit_logs(2), static_policies(3 including global), dynamic_policies(2 including global), policy_evaluations(2), service_identities(2), execution_history(2), plugin_user_licenses(2), saml_configurations(1), usage_records(2)';
END $$;
