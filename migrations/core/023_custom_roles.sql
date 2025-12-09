-- Migration 023: Custom Roles and Permissions (RBAC)
-- Enables creation of custom roles with granular permissions
-- Part of Track B: Policy Management Database Schema

-- Custom roles table
CREATE TABLE IF NOT EXISTS custom_roles (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(200),
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_system BOOLEAN DEFAULT false, -- System roles can't be deleted
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(255),

    CONSTRAINT uq_custom_roles_tenant_name UNIQUE(tenant_id, name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_custom_roles_tenant_id ON custom_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_custom_roles_is_system ON custom_roles(is_system);

-- Role assignments (user to role mapping)
CREATE TABLE IF NOT EXISTS role_assignments (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    role_id VARCHAR(255) NOT NULL,
    assigned_by VARCHAR(255),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional expiration

    CONSTRAINT fk_role_assignments_role
        FOREIGN KEY (role_id)
        REFERENCES custom_roles(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_role_assignments_user_role
        UNIQUE(tenant_id, user_email, role_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_role_assignments_tenant_id ON role_assignments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_user_email ON role_assignments(user_email);
CREATE INDEX IF NOT EXISTS idx_role_assignments_role_id ON role_assignments(role_id);
CREATE INDEX IF NOT EXISTS idx_role_assignments_expires_at ON role_assignments(expires_at)
    WHERE expires_at IS NOT NULL;

-- RLS policies
-- Note: Uses app.current_org_id to match existing RLS middleware (see middleware/rls.go)
ALTER TABLE custom_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_assignments ENABLE ROW LEVEL SECURITY;

CREATE POLICY custom_roles_tenant_isolation ON custom_roles
    USING (tenant_id = current_setting('app.current_org_id', true));

CREATE POLICY role_assignments_tenant_isolation ON role_assignments
    USING (tenant_id = current_setting('app.current_org_id', true));

-- Insert default system roles for existing tenants
-- Admin role
INSERT INTO custom_roles (id, tenant_id, name, display_name, description, permissions, is_system)
SELECT
    'role_admin_' || tenant_id,
    tenant_id,
    'admin',
    'Administrator',
    'Full system access',
    '["*"]'::jsonb,
    true
FROM (SELECT DISTINCT tenant_id FROM dynamic_policies) AS tenants
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Policy Admin role
INSERT INTO custom_roles (id, tenant_id, name, display_name, description, permissions, is_system)
SELECT
    'role_policy_admin_' || tenant_id,
    tenant_id,
    'policy_admin',
    'Policy Administrator',
    'Can manage policies',
    '["policy:read", "policy:write", "policy:delete", "audit:read"]'::jsonb,
    true
FROM (SELECT DISTINCT tenant_id FROM dynamic_policies) AS tenants
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Viewer role
INSERT INTO custom_roles (id, tenant_id, name, display_name, description, permissions, is_system)
SELECT
    'role_viewer_' || tenant_id,
    tenant_id,
    'viewer',
    'Viewer',
    'Read-only access',
    '["policy:read", "connector:read", "audit:read"]'::jsonb,
    true
FROM (SELECT DISTINCT tenant_id FROM dynamic_policies) AS tenants
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Comments
COMMENT ON TABLE custom_roles IS 'Custom roles with granular permissions per tenant';
COMMENT ON TABLE role_assignments IS 'Maps users to roles within a tenant';
COMMENT ON COLUMN custom_roles.permissions IS 'JSON array of permission strings: ["policy:read", "policy:write", ...]';
