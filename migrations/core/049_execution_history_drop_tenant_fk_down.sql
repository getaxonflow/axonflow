-- Rollback: 049_execution_history_drop_tenant_fk_down.sql
-- Re-adds the FK constraint on execution_history.tenant_id

ALTER TABLE execution_history
    ADD CONSTRAINT execution_history_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES organizations(org_id);
