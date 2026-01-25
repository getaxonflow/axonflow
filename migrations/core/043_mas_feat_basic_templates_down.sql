-- Migration 043 DOWN: Remove MAS FEAT Basic Policy Templates
-- Related: Issue #1076 - MAS FEAT PII detection patterns

-- Remove MAS FEAT templates
DELETE FROM policy_templates WHERE id IN (
    'tpl_mas_credit_scoring',
    'tpl_mas_trading_algo',
    'tpl_mas_insurance_uw',
    'tpl_mas_robo_advisory',
    'tpl_mas_aml_cft'
);

-- Revert table comment
COMMENT ON TABLE policy_templates IS
'Policy templates for compliance frameworks including HIPAA, GDPR, PCI-DSS, SOC2, DORA, RBI, SEBI';
