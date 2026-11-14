CREATE TABLE IF NOT EXISTS governed_model_attempts (
    request_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    trace_id CHAR(32) NOT NULL CHECK (trace_id ~ '^[0-9a-f]{32}$'),
    module VARCHAR(64) NOT NULL,
    case_id VARCHAR(255) NOT NULL,
    evidence_version CHAR(64) NOT NULL CHECK (evidence_version ~ '^[0-9a-f]{64}$'),
    investigation_key CHAR(64) NOT NULL CHECK (investigation_key ~ '^[0-9a-f]{64}$'),
    status VARCHAR(32) NOT NULL CHECK (status IN
        ('forwarding','completed','provider_rejected','outcome_unknown','usage_record_failed')),
    provider_info JSONB NOT NULL DEFAULT '{}'::jsonb,
    usage_receipt JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_text TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, tenant_id, request_id),
    UNIQUE (org_id, tenant_id, investigation_key)
);

ALTER TABLE governed_model_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE governed_model_attempts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS governed_model_attempts_org_isolation ON governed_model_attempts;
CREATE POLICY governed_model_attempts_org_isolation ON governed_model_attempts
    USING (org_id = current_setting('app.current_org_id', true)
       AND tenant_id = current_setting('app.current_tenant_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true)
            AND tenant_id = current_setting('app.current_tenant_id', true));
DROP POLICY IF EXISTS governed_model_attempts_hosted_guard ON governed_model_attempts;
CREATE POLICY governed_model_attempts_hosted_guard ON governed_model_attempts
    AS RESTRICTIVE
    USING (org_id = current_setting('app.current_org_id', true)
       AND tenant_id = current_setting('app.current_tenant_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true)
            AND tenant_id = current_setting('app.current_tenant_id', true));
REVOKE ALL ON governed_model_attempts FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON governed_model_attempts TO axonflow_app_role;

COMMENT ON TABLE governed_model_attempts IS
    'Pre-forward intent and terminal outcome journal for governed model calls; outcome_unknown means provider spend may require reconciliation.';
