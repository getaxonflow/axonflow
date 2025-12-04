-- Migration 014: EU AI Act Compliance Policy Templates for Travel Platforms
-- Date: 2025-11-20
-- Purpose: Pre-built policies for travel booking platforms (like Serko)
-- EU AI Act Articles: 13 (Transparency), 14 (Human Oversight), 15 (Accuracy)
-- GDPR Articles: 5 (Data Minimization), 44-50 (International Transfers)

-- ============================================================================
-- POLICY 1: High-Value Transaction Oversight
-- EU AI Act Article 14: Human Oversight
-- ============================================================================
INSERT INTO static_policies (
    policy_id,
    name,
    category,
    pattern,
    severity,
    description,
    action,
    tenant_id,
    metadata
) VALUES (
    'eu_ai_act_high_value_transaction',
    'High-Value Transaction Oversight',
    'eu_ai_act_compliance',
    '(€|EUR|euro|euros?)\s*[,\d]*[5-9]\d{3,}|(£|GBP|pound)\s*[,\d]*[4-9]\d{3,}|(\$|USD|dollar)\s*[,\d]*[6-9]\d{3,}',
    'high',
    'EU AI Act Article 14: High-value bookings (>€5,000, >£4,000, >$6,000) require human oversight. Flags transactions for manual approval to ensure transparency and prevent automated high-risk decisions.',
    'alert',
    'global',
    '{
        "eu_ai_act_article": "14",
        "article_name": "Human Oversight",
        "applies_to": ["flight_bookings", "hotel_bookings", "full_itineraries"],
        "threshold_eur": 5000,
        "threshold_gbp": 4000,
        "threshold_usd": 6000,
        "required_action": "manual_approval",
        "compliance_framework": "EU_AI_Act",
        "risk_level": "high-risk_ai_system"
    }'::jsonb
) ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    pattern = EXCLUDED.pattern,
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- ============================================================================
-- POLICY 2: Cross-Border PII Minimization (NZ/AU → EU)
-- GDPR Articles 44-50: International Data Transfers
-- EU AI Act Article 10: Data Governance
-- ============================================================================
INSERT INTO static_policies (
    policy_id,
    name,
    category,
    pattern,
    severity,
    description,
    action,
    tenant_id,
    metadata
) VALUES (
    'eu_gdpr_cross_border_pii',
    'Cross-Border PII Minimization',
    'eu_ai_act_compliance',
    '(transfer|send|transmit|share).*(EU|Europe|European)|(EU|Europe|European).*(transfer|send|transmit|share)',
    'high',
    'GDPR Articles 44-50: Cross-border data transfers to EU require data minimization. Redacts non-essential PII (passport, loyalty numbers) before international transfer. Logs all cross-border data flows for compliance audits.',
    'redact',
    'global',
    '{
        "eu_ai_act_article": "10",
        "gdpr_articles": ["44", "45", "46", "47", "48", "49", "50"],
        "article_name": "Data Governance & International Transfers",
        "applies_to": ["nz_to_eu_bookings", "au_to_eu_bookings", "cross_region_queries"],
        "redaction_targets": ["passport_number", "loyalty_number", "payment_details"],
        "retention_period_days": 30,
        "compliance_framework": "GDPR",
        "data_flow_logging": true
    }'::jsonb
) ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    pattern = EXCLUDED.pattern,
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- ============================================================================
-- POLICY 3: Passport Number Detection & Redaction
-- GDPR Article 5: Data Minimization
-- EU AI Act Article 13: Transparency
-- ============================================================================
INSERT INTO static_policies (
    policy_id,
    name,
    category,
    pattern,
    severity,
    description,
    action,
    tenant_id,
    metadata
) VALUES (
    'eu_gdpr_passport_detection',
    'Passport Number PII Detection',
    'pii_detection',
    '\b[A-Z]{1,2}[0-9]{6,9}\b|passport[:\s]+[A-Z0-9]{6,12}',
    'high',
    'GDPR Article 5 & EU AI Act Article 13: Detects passport numbers in queries/responses. Redacts before AI processing to minimize PII exposure. Common formats: UK (123456789), US (C12345678), AU (N1234567), NZ (LA123456).',
    'redact',
    'global',
    '{
        "eu_ai_act_article": "13",
        "gdpr_article": "5",
        "article_name": "Transparency & Data Minimization",
        "pii_type": "passport_number",
        "applies_to": ["booking_queries", "chat_messages", "api_requests"],
        "redaction_format": "[PASSPORT_REDACTED]",
        "patterns_covered": ["UK", "US", "AU", "NZ", "EU_formats"],
        "compliance_framework": "GDPR"
    }'::jsonb
) ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    pattern = EXCLUDED.pattern,
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- ============================================================================
-- POLICY 4: Credit Card PII Detection
-- GDPR Article 5: Data Minimization
-- PCI-DSS Compliance
-- ============================================================================
INSERT INTO static_policies (
    policy_id,
    name,
    category,
    pattern,
    severity,
    description,
    action,
    tenant_id,
    metadata
) VALUES (
    'eu_gdpr_credit_card_detection',
    'Credit Card Number PII Detection',
    'pii_detection',
    '\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,16}\b',
    'critical',
    'GDPR Article 5 & PCI-DSS: Detects credit card numbers (Visa, Mastercard, Amex, Discover). Immediately redacts before AI processing. Logs detection events for compliance audits.',
    'redact',
    'global',
    '{
        "eu_ai_act_article": "13",
        "gdpr_article": "5",
        "pci_dss_requirement": "3.4",
        "article_name": "PII Protection & Data Minimization",
        "pii_type": "credit_card",
        "applies_to": ["payment_flows", "booking_queries", "chat_messages"],
        "redaction_format": "[CARD_REDACTED]",
        "card_types": ["Visa", "Mastercard", "Amex", "Discover"],
        "compliance_framework": "GDPR+PCI-DSS"
    }'::jsonb
) ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    pattern = EXCLUDED.pattern,
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- ============================================================================
-- POLICY 5: Pricing Fairness & Non-Discrimination
-- EU AI Act Article 15: Accuracy & Robustness
-- ============================================================================
INSERT INTO static_policies (
    policy_id,
    name,
    category,
    pattern,
    severity,
    description,
    action,
    tenant_id,
    metadata
) VALUES (
    'eu_ai_act_pricing_fairness',
    'Pricing Fairness Validation',
    'eu_ai_act_compliance',
    '(recommend|suggest|best|cheapest|premium).*(price|cost|rate|fare)',
    'medium',
    'EU AI Act Article 15: Validates AI pricing recommendations for fairness and non-discrimination. Logs feature importance (route, date, class) to detect regional/demographic bias. Ensures accuracy in price comparisons.',
    'log',
    'global',
    '{
        "eu_ai_act_article": "15",
        "article_name": "Accuracy, Robustness & Non-Discrimination",
        "applies_to": ["flight_recommendations", "hotel_recommendations", "pricing_comparisons"],
        "validation_checks": ["regional_bias", "demographic_bias", "price_accuracy"],
        "log_requirements": ["feature_importance", "recommendation_reasoning", "price_delta"],
        "compliance_framework": "EU_AI_Act",
        "audit_retention_days": 90
    }'::jsonb
) ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    pattern = EXCLUDED.pattern,
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- ============================================================================
-- POLICY 6: Sustainability Claims Verification
-- EU AI Act Article 13: Transparency
-- EU Green Claims Directive
-- ============================================================================
INSERT INTO static_policies (
    policy_id,
    name,
    category,
    pattern,
    severity,
    description,
    action,
    tenant_id,
    metadata
) VALUES (
    'eu_ai_act_sustainability_claims',
    'Sustainability Claims Verification',
    'eu_ai_act_compliance',
    '(carbon|CO2|offset|sustainable|green|eco-friendly|emissions?).*(ton|kg|reduction|neutral)',
    'medium',
    'EU AI Act Article 13 & Green Claims Directive: Validates sustainability claims (carbon offsets, emissions). Requires verifiable sources for environmental impact calculations. Logs all sustainability-related AI outputs.',
    'log',
    'global',
    '{
        "eu_ai_act_article": "13",
        "article_name": "Transparency & Accountability",
        "eu_directive": "Green_Claims_Directive_2023",
        "applies_to": ["carbon_offset_claims", "sustainability_scores", "eco_friendly_labels"],
        "validation_requirements": ["verifiable_source", "calculation_methodology", "third_party_certification"],
        "log_requirements": ["claim_text", "data_source", "calculation_method"],
        "compliance_framework": "EU_AI_Act",
        "audit_retention_days": 365
    }'::jsonb
) ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    pattern = EXCLUDED.pattern,
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- ============================================================================
-- POLICY 7: Loyalty Number PII Detection
-- GDPR Article 5: Data Minimization
-- ============================================================================
INSERT INTO static_policies (
    policy_id,
    name,
    category,
    pattern,
    severity,
    description,
    action,
    tenant_id,
    metadata
) VALUES (
    'eu_gdpr_loyalty_number_detection',
    'Loyalty Number PII Detection',
    'pii_detection',
    '(frequent\s+flyer|loyalty|membership|miles?|points?)[:\s#]*[A-Z0-9]{6,15}',
    'medium',
    'GDPR Article 5: Detects airline/hotel loyalty numbers. Redacts before AI processing to minimize PII exposure. Applies to frequent flyer numbers, hotel membership IDs, and reward program identifiers.',
    'redact',
    'global',
    '{
        "eu_ai_act_article": "13",
        "gdpr_article": "5",
        "article_name": "Data Minimization",
        "pii_type": "loyalty_membership_number",
        "applies_to": ["booking_queries", "profile_updates", "rewards_redemption"],
        "redaction_format": "[LOYALTY_REDACTED]",
        "programs_covered": ["airline_frequent_flyer", "hotel_loyalty", "car_rental_rewards"],
        "compliance_framework": "GDPR"
    }'::jsonb
) ON CONFLICT (policy_id) DO UPDATE SET
    name = EXCLUDED.name,
    pattern = EXCLUDED.pattern,
    description = EXCLUDED.description,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();

-- ============================================================================
-- Update policy metrics table to track EU AI Act compliance
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_static_policies_eu_compliance
ON static_policies(category)
WHERE category = 'eu_ai_act_compliance' AND enabled = true;

-- ============================================================================
-- Create view for EU AI Act compliance reporting
-- ============================================================================
CREATE OR REPLACE VIEW eu_ai_act_compliance_summary AS
SELECT
    policy_id,
    name,
    metadata->>'eu_ai_act_article' as article,
    metadata->>'article_name' as article_name,
    metadata->>'compliance_framework' as framework,
    severity,
    action,
    enabled,
    created_at,
    updated_at
FROM static_policies
WHERE category = 'eu_ai_act_compliance'
   OR (metadata->>'eu_ai_act_article') IS NOT NULL
ORDER BY metadata->>'eu_ai_act_article';

-- ============================================================================
-- Success Message
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '✅ EU AI Act Travel Platform Policy Templates Created Successfully';
    RAISE NOTICE '';
    RAISE NOTICE 'Templates Created:';
    RAISE NOTICE '  1. High-Value Transaction Oversight (Article 14)';
    RAISE NOTICE '  2. Cross-Border PII Minimization (GDPR 44-50)';
    RAISE NOTICE '  3. Passport Number Detection (Article 13)';
    RAISE NOTICE '  4. Credit Card Detection (GDPR + PCI-DSS)';
    RAISE NOTICE '  5. Pricing Fairness Validation (Article 15)';
    RAISE NOTICE '  6. Sustainability Claims Verification (Article 13)';
    RAISE NOTICE '  7. Loyalty Number Detection (GDPR Article 5)';
    RAISE NOTICE '';
    RAISE NOTICE 'Query compliance summary: SELECT * FROM eu_ai_act_compliance_summary;';
END $$;
