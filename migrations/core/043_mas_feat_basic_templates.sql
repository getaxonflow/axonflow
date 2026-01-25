-- Migration 043: MAS FEAT Basic Policy Templates
-- Created: 2026-01-24
-- Purpose: Add basic MAS FEAT trigger policies for detection in Community Edition
-- Related: Issue #1076 - MAS FEAT PII detection patterns
-- Parent EPIC: #1034 - MAS FEAT Community Edition
--
-- These templates detect high-risk AI use cases that may require MAS FEAT compliance:
-- 1. Credit Scoring - AI-driven credit decisions
-- 2. Trading Algorithms - Automated trading systems
-- 3. Insurance Underwriting - AI risk assessment
-- 4. Robo-Advisory - Automated investment advice
-- 5. AML/CFT - Anti-money laundering & counter-terrorism financing
--
-- Note: These are detection-only policies. Full FEAT assessment workflows
-- are Enterprise-only (AI System Registry, FEAT Assessments, Kill Switches).

-- =============================================================================
-- MAS FEAT Use Case Detection Templates (5 templates)
-- Category: mas_feat
-- Purpose: Detect AI use cases that may require MAS FEAT compliance
-- =============================================================================

-- Ensure policy_templates table exists (it should from earlier migrations)
-- This migration only inserts data

INSERT INTO policy_templates (
    id, name, display_name, description, category, subcategory,
    template, variables, is_builtin, tags
) VALUES
-- Credit Scoring Detection
-- Triggers when AI is used for credit/loan decisions
(
    'tpl_mas_credit_scoring',
    'mas_credit_scoring',
    'MAS FEAT - Credit Scoring Trigger',
    'Detects AI-driven credit scoring and loan decisions that may require MAS FEAT compliance. Singapore financial institutions using AI for credit decisions must document FEAT principles.',
    'mas_feat',
    'credit_scoring',
    '{
        "conditions": [
            {"field": "query", "operator": "contains_any", "value": ["credit score", "credit rating", "loan decision", "lending decision", "creditworthiness", "credit assessment", "loan approval", "credit limit"]}
        ],
        "actions": [
            {"type": "log", "config": {"compliance": "mas_feat", "use_case": "credit_scoring", "message": "AI credit scoring detected - may require MAS FEAT compliance"}},
            {"type": "alert", "config": {"severity": "info", "message": "Credit scoring AI use case detected"}}
        ],
        "priority": 80
    }',
    '[{"name": "additional_keywords", "type": "array", "description": "Additional keywords to detect", "default": []}]',
    true,
    '["mas_feat", "singapore", "financial", "credit", "compliance"]'::jsonb
),

-- Trading Algorithm Detection
-- Triggers when AI is used for automated trading
(
    'tpl_mas_trading_algo',
    'mas_trading_algo',
    'MAS FEAT - Trading Algorithm Trigger',
    'Detects AI-driven trading algorithms and automated investment decisions. Singapore financial institutions using AI for trading must ensure transparency and accountability.',
    'mas_feat',
    'trading',
    '{
        "conditions": [
            {"field": "query", "operator": "contains_any", "value": ["trading algorithm", "algo trading", "automated trading", "trade execution", "market making", "order routing", "price prediction", "stock prediction"]}
        ],
        "actions": [
            {"type": "log", "config": {"compliance": "mas_feat", "use_case": "trading_algorithm", "message": "AI trading algorithm detected - may require MAS FEAT compliance"}},
            {"type": "alert", "config": {"severity": "info", "message": "Trading algorithm AI use case detected"}}
        ],
        "priority": 85
    }',
    '[{"name": "additional_keywords", "type": "array", "description": "Additional keywords to detect", "default": []}]',
    true,
    '["mas_feat", "singapore", "financial", "trading", "compliance"]'::jsonb
),

-- Insurance Underwriting Detection
-- Triggers when AI is used for insurance risk assessment
(
    'tpl_mas_insurance_uw',
    'mas_insurance_underwriting',
    'MAS FEAT - Insurance Underwriting Trigger',
    'Detects AI-driven insurance underwriting and risk assessment. Singapore insurers using AI for underwriting must ensure fairness and avoid discrimination.',
    'mas_feat',
    'insurance',
    '{
        "conditions": [
            {"field": "query", "operator": "contains_any", "value": ["insurance underwriting", "risk assessment", "premium calculation", "claims assessment", "policy pricing", "actuarial", "risk scoring", "loss prediction"]}
        ],
        "actions": [
            {"type": "log", "config": {"compliance": "mas_feat", "use_case": "insurance_underwriting", "message": "AI insurance underwriting detected - may require MAS FEAT compliance"}},
            {"type": "alert", "config": {"severity": "info", "message": "Insurance underwriting AI use case detected"}}
        ],
        "priority": 80
    }',
    '[{"name": "additional_keywords", "type": "array", "description": "Additional keywords to detect", "default": []}]',
    true,
    '["mas_feat", "singapore", "financial", "insurance", "compliance"]'::jsonb
),

-- Robo-Advisory Detection
-- Triggers when AI is used for investment advice
(
    'tpl_mas_robo_advisory',
    'mas_robo_advisory',
    'MAS FEAT - Robo-Advisory Trigger',
    'Detects AI-driven robo-advisory and automated investment recommendations. Singapore financial advisors using AI must ensure suitability and transparency.',
    'mas_feat',
    'advisory',
    '{
        "conditions": [
            {"field": "query", "operator": "contains_any", "value": ["robo advisor", "robo-advisor", "investment advice", "portfolio recommendation", "asset allocation", "investment recommendation", "wealth management", "financial planning"]}
        ],
        "actions": [
            {"type": "log", "config": {"compliance": "mas_feat", "use_case": "robo_advisory", "message": "AI robo-advisory detected - may require MAS FEAT compliance"}},
            {"type": "alert", "config": {"severity": "info", "message": "Robo-advisory AI use case detected"}}
        ],
        "priority": 80
    }',
    '[{"name": "additional_keywords", "type": "array", "description": "Additional keywords to detect", "default": []}]',
    true,
    '["mas_feat", "singapore", "financial", "advisory", "compliance"]'::jsonb
),

-- AML/CFT Detection
-- Triggers when AI is used for anti-money laundering
(
    'tpl_mas_aml_cft',
    'mas_aml_cft',
    'MAS FEAT - AML/CFT Trigger',
    'Detects AI-driven AML/CFT monitoring and suspicious transaction detection. Singapore financial institutions using AI for AML must ensure effectiveness and fairness.',
    'mas_feat',
    'aml_cft',
    '{
        "conditions": [
            {"field": "query", "operator": "contains_any", "value": ["anti-money laundering", "AML", "suspicious transaction", "STR", "CTF", "counter terrorism", "know your customer", "KYC", "transaction monitoring", "fraud detection"]}
        ],
        "actions": [
            {"type": "log", "config": {"compliance": "mas_feat", "use_case": "aml_cft", "message": "AI AML/CFT monitoring detected - may require MAS FEAT compliance"}},
            {"type": "alert", "config": {"severity": "info", "message": "AML/CFT AI use case detected"}}
        ],
        "priority": 85
    }',
    '[{"name": "additional_keywords", "type": "array", "description": "Additional keywords to detect", "default": []}]',
    true,
    '["mas_feat", "singapore", "financial", "aml", "compliance"]'::jsonb
)

ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    template = EXCLUDED.template,
    variables = EXCLUDED.variables,
    tags = EXCLUDED.tags,
    updated_at = NOW();

-- =============================================================================
-- Documentation
-- =============================================================================

COMMENT ON TABLE policy_templates IS
'Policy templates for compliance frameworks including HIPAA, GDPR, PCI-DSS, SOC2, DORA, RBI, SEBI, MAS FEAT (new in #1076)';
