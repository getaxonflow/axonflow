-- Migration 024: Policy Templates (OSS)
-- Base table structure and general-purpose templates
-- Part of Track B: Policy Management Database Schema

-- Policy templates table
CREATE TABLE IF NOT EXISTS policy_templates (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(100) NOT NULL, -- general, custom (compliance categories added by enterprise)
    subcategory VARCHAR(100),
    template JSONB NOT NULL,
    variables JSONB DEFAULT '[]'::jsonb,
    is_builtin BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    version VARCHAR(50) DEFAULT '1.0',
    tags JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT uq_policy_templates_name_category UNIQUE(name, category)
);

-- Template usage tracking
CREATE TABLE IF NOT EXISTS policy_template_usage (
    id VARCHAR(255) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    template_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    policy_id VARCHAR(255),
    used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_template_usage_template
        FOREIGN KEY (template_id)
        REFERENCES policy_templates(id)
        ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_policy_templates_category ON policy_templates(category);
CREATE INDEX IF NOT EXISTS idx_policy_templates_is_builtin ON policy_templates(is_builtin);
CREATE INDEX IF NOT EXISTS idx_policy_templates_tags ON policy_templates USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_policy_template_usage_template_id ON policy_template_usage(template_id);
CREATE INDEX IF NOT EXISTS idx_policy_template_usage_tenant_id ON policy_template_usage(tenant_id);

-- Insert general-purpose templates (OSS)
INSERT INTO policy_templates (id, name, display_name, description, category, subcategory, template, variables, is_builtin, tags)
VALUES
(
    'tpl_general_rate_limiting',
    'general_rate_limiting',
    'Rate Limiting',
    'Enforces rate limits per user/tenant to prevent abuse',
    'general',
    'security',
    '{
        "name": "Rate Limiting",
        "type": "user",
        "conditions": [
            {
                "field": "user.request_count_1h",
                "operator": "greater_than",
                "value": "{{max_requests_per_hour}}"
            }
        ],
        "actions": [
            {
                "type": "block",
                "config": {
                    "message": "Rate limit exceeded. Please try again later.",
                    "retry_after_seconds": 3600
                }
            },
            {
                "type": "log",
                "config": {
                    "audit_type": "rate_limit_exceeded"
                }
            }
        ],
        "priority": 95
    }'::jsonb,
    '[{"name": "max_requests_per_hour", "default": 1000, "description": "Maximum requests per user per hour"}]'::jsonb,
    true,
    '["security", "rate_limiting", "abuse_prevention"]'::jsonb
),
(
    'tpl_general_content_filter',
    'general_content_filter',
    'Content Safety Filter',
    'Blocks requests containing prohibited content patterns',
    'general',
    'content_safety',
    '{
        "name": "Content Safety Filter",
        "type": "content",
        "conditions": [
            {
                "field": "query",
                "operator": "contains_any",
                "value": ["{{prohibited_patterns}}"]
            }
        ],
        "actions": [
            {
                "type": "block",
                "config": {
                    "message": "Request blocked due to content policy violation"
                }
            },
            {
                "type": "log",
                "config": {
                    "audit_type": "content_policy_violation"
                }
            }
        ],
        "priority": 100
    }'::jsonb,
    '[{"name": "prohibited_patterns", "default": ["jailbreak", "ignore_instructions", "override_safety"], "description": "Content patterns to block"}]'::jsonb,
    true,
    '["security", "content_safety", "abuse_prevention"]'::jsonb
);

-- Comments
COMMENT ON TABLE policy_templates IS 'Policy templates - base templates in OSS, compliance templates added by Enterprise';
COMMENT ON TABLE policy_template_usage IS 'Tracks which templates have been used by tenants';
