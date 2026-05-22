-- Rollback for migration 107: misc customer-scope tables FORCE RLS

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connectors') THEN
        ALTER TABLE connectors NO FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS connectors_org_id_isolation ON connectors;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'connector_configs') THEN
        ALTER TABLE connector_configs NO FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS connector_configs_org_id_isolation ON connector_configs;
        ALTER TABLE connector_configs DROP COLUMN IF EXISTS org_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_heartbeats') THEN
        ALTER TABLE agent_heartbeats NO FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS agent_heartbeats_org_id_isolation ON agent_heartbeats;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'node_violations') THEN
        ALTER TABLE node_violations NO FORCE ROW LEVEL SECURITY;
        DROP POLICY IF EXISTS node_violations_org_id_isolation ON node_violations;
    END IF;
END
$$;

COMMIT;
