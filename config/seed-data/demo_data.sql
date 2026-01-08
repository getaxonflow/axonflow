-- AxonFlow Community Demo - Seed Data
-- Creates sample data for AI Customer Support Assistant scenario
--
-- Tables:
--   - support_tickets: Customer support tickets for PostgreSQL connector demo
--   - audit_logs: Sample audit entries for Grafana dashboard visualization
--
-- Run with: psql -h localhost -U axonflow -d axonflow -f demo_data.sql

-- ============================================================================
-- SUPPORT TICKETS TABLE
-- Used by PostgreSQL connector demo (Part 4 of demo)
-- ============================================================================

CREATE TABLE IF NOT EXISTS support_tickets (
    ticket_id SERIAL PRIMARY KEY,
    customer_name VARCHAR(100) NOT NULL,
    customer_email VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL,
    priority VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    assigned_agent VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    satisfaction_score INTEGER CHECK (satisfaction_score >= 1 AND satisfaction_score <= 5)
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_tickets_status ON support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_priority ON support_tickets(priority);
CREATE INDEX IF NOT EXISTS idx_tickets_category ON support_tickets(category);
CREATE INDEX IF NOT EXISTS idx_tickets_created_at ON support_tickets(created_at);
CREATE INDEX IF NOT EXISTS idx_tickets_assigned_agent ON support_tickets(assigned_agent);

-- Clear existing demo data
TRUNCATE support_tickets RESTART IDENTITY;

-- Insert realistic support ticket data
-- Mix of statuses, priorities, and categories for interesting queries
INSERT INTO support_tickets (customer_name, customer_email, subject, description, category, priority, status, assigned_agent, created_at, resolved_at, satisfaction_score) VALUES

-- Today's tickets (recent activity)
('Alice Johnson', 'alice.j@techcorp.com', 'Cannot access dashboard after update',
 'Since the latest update, I get a 403 error when trying to access the analytics dashboard. This is blocking my quarterly report.',
 'technical', 'high', 'open', 'Sarah Miller', NOW() - INTERVAL '2 hours', NULL, NULL),

('Bob Smith', 'bob.smith@startup.io', 'Billing discrepancy on invoice #4521',
 'My invoice shows charges for 150 users but we only have 120 active users. Please review and adjust.',
 'billing', 'medium', 'in_progress', 'Tom Chen', NOW() - INTERVAL '4 hours', NULL, NULL),

('Carol Williams', 'cwilliams@enterprise.net', 'API rate limiting too aggressive',
 'We are hitting rate limits during normal business hours. Current limit of 100 req/min is insufficient for our use case.',
 'technical', 'high', 'open', NULL, NOW() - INTERVAL '1 hour', NULL, NULL),

('David Brown', 'david.b@agency.com', 'Feature request: Dark mode',
 'Many of our team members work late hours. A dark mode option would reduce eye strain significantly.',
 'feature_request', 'low', 'open', NULL, NOW() - INTERVAL '30 minutes', NULL, NULL),

('Emma Davis', 'emma@retailco.com', 'Password reset not working',
 'I have tried resetting my password three times but never receive the reset email. Checked spam folder too.',
 'account', 'high', 'in_progress', 'Sarah Miller', NOW() - INTERVAL '3 hours', NULL, NULL),

-- Yesterday's tickets
('Frank Garcia', 'fgarcia@consulting.biz', 'Integration with Salesforce failing',
 'The Salesforce integration stopped syncing contacts yesterday. Error message: CONNECTION_TIMEOUT.',
 'integration', 'critical', 'in_progress', 'Mike Johnson', NOW() - INTERVAL '1 day', NULL, NULL),

('Grace Lee', 'grace.lee@fintech.co', 'Need to upgrade plan',
 'We need to upgrade from Professional to Enterprise tier. What is the process and timeline?',
 'billing', 'medium', 'resolved', 'Tom Chen', NOW() - INTERVAL '1 day', NOW() - INTERVAL '18 hours', 5),

('Henry Martinez', 'hmartinez@healthcare.org', 'HIPAA compliance documentation',
 'We need official HIPAA compliance documentation for our audit. Can you provide BAA and SOC2 reports?',
 'compliance', 'high', 'resolved', 'Sarah Miller', NOW() - INTERVAL '1 day', NOW() - INTERVAL '20 hours', 5),

-- This week's tickets
('Isabel Chen', 'ichen@manufacturing.com', 'Slow performance on reports page',
 'The monthly reports page takes over 30 seconds to load. This started about a week ago.',
 'technical', 'medium', 'resolved', 'Mike Johnson', NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', 4),

('Jack Wilson', 'jwilson@education.edu', 'Bulk user import failing',
 'Trying to import 500 users via CSV but process fails at around 200 users. Need this done before semester start.',
 'technical', 'critical', 'resolved', 'Sarah Miller', NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', 5),

('Karen Thompson', 'kthompson@media.com', 'Mobile app crashes on iOS 17',
 'App crashes immediately after login on iPhone 15 Pro running iOS 17.2. Works fine on older iOS versions.',
 'technical', 'high', 'in_progress', 'Mike Johnson', NOW() - INTERVAL '2 days', NULL, NULL),

('Leo Patel', 'leo.p@logistics.net', 'Webhook notifications delayed',
 'Webhook events are arriving 5-10 minutes after the actual event. This breaks our real-time tracking system.',
 'integration', 'high', 'resolved', 'Tom Chen', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', 4),

-- Older resolved tickets (for historical data)
('Maria Rodriguez', 'mrodriguez@legal.law', 'Data export for GDPR request',
 'Customer has requested all their data under GDPR. Need to export complete history.',
 'compliance', 'critical', 'resolved', 'Sarah Miller', NOW() - INTERVAL '1 week', NOW() - INTERVAL '6 days', 5),

('Nathan Kim', 'nkim@gaming.gg', 'Latency issues in Asia region',
 'Users in Singapore and Japan experiencing 500ms+ latency. US users are fine.',
 'technical', 'high', 'resolved', 'Mike Johnson', NOW() - INTERVAL '1 week', NOW() - INTERVAL '5 days', 4),

('Olivia White', 'owhite@nonprofit.org', 'Nonprofit discount inquiry',
 'We are a registered 501(c)(3). Do you offer nonprofit pricing?',
 'billing', 'low', 'resolved', 'Tom Chen', NOW() - INTERVAL '2 weeks', NOW() - INTERVAL '13 days', 5),

('Peter Zhang', 'pzhang@tech.io', 'Two-factor authentication not sending SMS',
 '2FA setup fails - never receive SMS code. Tried multiple phone numbers.',
 'account', 'high', 'resolved', 'Sarah Miller', NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', 4),

('Quinn Adams', 'qadams@restaurant.biz', 'Training video access expired',
 'My team lost access to the onboarding training videos. We still have active subscriptions.',
 'account', 'medium', 'resolved', 'Tom Chen', NOW() - INTERVAL '2 weeks', NOW() - INTERVAL '12 days', 5),

('Rachel Green', 'rgreen@fashion.style', 'Custom branding options',
 'Can we customize the customer-facing portal with our brand colors and logo?',
 'feature_request', 'low', 'resolved', 'Sarah Miller', NOW() - INTERVAL '3 weeks', NOW() - INTERVAL '18 days', 4),

('Samuel Clark', 'sclark@construction.build', 'Cannot download invoices',
 'The download button on the billing page does nothing. Need invoices for expense reporting.',
 'billing', 'medium', 'resolved', 'Tom Chen', NOW() - INTERVAL '3 weeks', NOW() - INTERVAL '20 days', 5),

('Tina Baker', 'tbaker@events.live', 'Concurrent user limit exceeded error',
 'Getting concurrent user limit error even though we are well under our plan limit.',
 'technical', 'critical', 'resolved', 'Mike Johnson', NOW() - INTERVAL '2 weeks', NOW() - INTERVAL '13 days', 3);

-- ============================================================================
-- AUDIT LOGS TABLE
-- Sample data for Grafana dashboard visualization
-- Note: This supplements any audit_logs created by the agent during the demo
-- ============================================================================

-- Ensure audit_logs table exists (created by agent migrations, but ensuring for seed)
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(255) PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    user_role VARCHAR(50) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    request_type VARCHAR(50) NOT NULL,
    query TEXT NOT NULL,
    query_hash VARCHAR(255) NOT NULL,
    policy_decision VARCHAR(50) NOT NULL,
    policy_details JSONB,
    provider VARCHAR(50),
    model VARCHAR(100),
    response_time_ms BIGINT,
    tokens_used INTEGER,
    cost DECIMAL(10, 6),
    redacted_fields JSONB,
    error_message TEXT,
    response_sample TEXT,
    compliance_flags JSONB,
    security_metrics JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample audit logs for dashboard visualization
-- Mix of allowed, blocked, and various policy triggers
INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role, client_id, tenant_id, request_type, query, query_hash, policy_decision, policy_details, provider, model, response_time_ms, tokens_used, cost, redacted_fields, compliance_flags, created_at) VALUES

-- Recent allowed requests
('audit_001', 'req_001', NOW() - INTERVAL '5 minutes', 1, 'agent@support.com', 'agent', 'demo-client', 'demo-tenant', 'query',
 'What are the open tickets assigned to me today?', 'hash_001', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection"], "all_passed": true}',
 'openai', 'gpt-4', 45, 150, 0.004500, NULL, '{"gdpr": true, "ccpa": true}', NOW() - INTERVAL '5 minutes'),

('audit_002', 'req_002', NOW() - INTERVAL '10 minutes', 2, 'supervisor@support.com', 'supervisor', 'demo-client', 'demo-tenant', 'query',
 'Show me tickets with critical priority from the last 24 hours', 'hash_002', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection"], "all_passed": true}',
 'openai', 'gpt-4', 52, 180, 0.005400, NULL, '{"gdpr": true, "ccpa": true}', NOW() - INTERVAL '10 minutes'),

('audit_003', 'req_003', NOW() - INTERVAL '15 minutes', 1, 'agent@support.com', 'agent', 'demo-client', 'demo-tenant', 'query',
 'What is the average resolution time for billing tickets?', 'hash_003', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection"], "all_passed": true}',
 'anthropic', 'claude-3-sonnet', 38, 120, 0.003600, NULL, '{"gdpr": true, "ccpa": true}', NOW() - INTERVAL '15 minutes'),

-- Blocked SQL injection attempts
('audit_004', 'req_004', NOW() - INTERVAL '20 minutes', 3, 'external@attacker.com', 'guest', 'demo-client', 'demo-tenant', 'query',
 'SELECT * FROM users WHERE 1=1 UNION SELECT password FROM admin_users', 'hash_004', 'blocked',
 '{"policy_violated": "sql_injection_union", "block_reason": "UNION-based SQL injection detected", "severity": "critical"}',
 NULL, NULL, 3, 0, 0, NULL, '{"security_violation": true}', NOW() - INTERVAL '20 minutes'),

('audit_005', 'req_005', NOW() - INTERVAL '25 minutes', 3, 'external@attacker.com', 'guest', 'demo-client', 'demo-tenant', 'query',
 'Get tickets; DROP TABLE support_tickets; --', 'hash_005', 'blocked',
 '{"policy_violated": "drop_table_prevention", "block_reason": "DROP TABLE command detected", "severity": "critical"}',
 NULL, NULL, 2, 0, 0, NULL, '{"security_violation": true}', NOW() - INTERVAL '25 minutes'),

-- PII detection (flagged, not necessarily blocked)
('audit_006', 'req_006', NOW() - INTERVAL '30 minutes', 1, 'agent@support.com', 'agent', 'demo-client', 'demo-tenant', 'query',
 'Customer card number is 4111-1111-1111-1111, process refund', 'hash_006', 'flagged',
 '{"policy_violated": "pii_credit_card", "pii_type": "credit_card", "action": "redact", "severity": "high"}',
 'openai', 'gpt-4', 48, 95, 0.002850, '["credit_card"]', '{"gdpr": true, "pci_dss": true}', NOW() - INTERVAL '30 minutes'),

('audit_007', 'req_007', NOW() - INTERVAL '35 minutes', 2, 'supervisor@support.com', 'supervisor', 'demo-client', 'demo-tenant', 'query',
 'Update customer SSN to 123-45-6789 in the system', 'hash_007', 'blocked',
 '{"policy_violated": "pii_ssn_detection", "pii_type": "ssn", "action": "block", "severity": "critical"}',
 NULL, NULL, 4, 0, 0, NULL, '{"gdpr": true, "hipaa": true}', NOW() - INTERVAL '35 minutes'),

-- More allowed requests for variety
('audit_008', 'req_008', NOW() - INTERVAL '40 minutes', 4, 'manager@support.com', 'manager', 'demo-client', 'demo-tenant', 'query',
 'Generate weekly performance report for the support team', 'hash_008', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection", "data_access"], "all_passed": true}',
 'anthropic', 'claude-3-opus', 125, 450, 0.022500, NULL, '{"gdpr": true}', NOW() - INTERVAL '40 minutes'),

('audit_009', 'req_009', NOW() - INTERVAL '45 minutes', 1, 'agent@support.com', 'agent', 'demo-client', 'demo-tenant', 'query',
 'How many tickets did I resolve this week?', 'hash_009', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection"], "all_passed": true}',
 'openai', 'gpt-3.5-turbo', 28, 80, 0.000160, NULL, '{"gdpr": true}', NOW() - INTERVAL '45 minutes'),

('audit_010', 'req_010', NOW() - INTERVAL '50 minutes', 2, 'supervisor@support.com', 'supervisor', 'demo-client', 'demo-tenant', 'query',
 'List customers who have submitted more than 5 tickets this month', 'hash_010', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection"], "all_passed": true}',
 'openai', 'gpt-4', 62, 200, 0.006000, NULL, '{"gdpr": true}', NOW() - INTERVAL '50 minutes'),

-- Older audit entries for historical trends
('audit_011', 'req_011', NOW() - INTERVAL '2 hours', 1, 'agent@support.com', 'agent', 'demo-client', 'demo-tenant', 'query',
 'Find tickets mentioning payment issues', 'hash_011', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection"], "all_passed": true}',
 'openai', 'gpt-4', 55, 165, 0.004950, NULL, '{"gdpr": true}', NOW() - INTERVAL '2 hours'),

('audit_012', 'req_012', NOW() - INTERVAL '3 hours', 3, 'external@unknown.com', 'guest', 'demo-client', 'demo-tenant', 'query',
 'TRUNCATE audit_logs', 'hash_012', 'blocked',
 '{"policy_violated": "truncate_prevention", "block_reason": "TRUNCATE command detected", "severity": "critical"}',
 NULL, NULL, 2, 0, 0, NULL, '{"security_violation": true}', NOW() - INTERVAL '3 hours'),

('audit_013', 'req_013', NOW() - INTERVAL '4 hours', 4, 'manager@support.com', 'manager', 'demo-client', 'demo-tenant', 'query',
 'What percentage of tickets are resolved within 24 hours?', 'hash_013', 'allowed',
 '{"policies_checked": ["sql_injection", "pii_detection"], "all_passed": true}',
 'anthropic', 'claude-3-sonnet', 42, 140, 0.004200, NULL, '{"gdpr": true}', NOW() - INTERVAL '4 hours'),

('audit_014', 'req_014', NOW() - INTERVAL '5 hours', 1, 'agent@support.com', 'agent', 'demo-client', 'demo-tenant', 'query',
 'Customer Aadhaar number is 2345 6789 0123 for verification', 'hash_014', 'blocked',
 '{"policy_violated": "pii_aadhaar_detection", "pii_type": "aadhaar", "action": "block", "severity": "high"}',
 NULL, NULL, 3, 0, 0, NULL, '{"rbi_compliance": true}', NOW() - INTERVAL '5 hours'),

('audit_015', 'req_015', NOW() - INTERVAL '6 hours', 2, 'supervisor@support.com', 'supervisor', 'demo-client', 'demo-tenant', 'query',
 'Customer PAN is ABCDE1234F for tax records', 'hash_015', 'flagged',
 '{"policy_violated": "pii_pan_detection", "pii_type": "pan", "action": "redact", "severity": "medium"}',
 'openai', 'gpt-4', 51, 130, 0.003900, '["pan_number"]', '{"rbi_compliance": true}', NOW() - INTERVAL '6 hours');

-- ============================================================================
-- SUMMARY
-- ============================================================================
-- Support tickets: 20 records across various statuses/priorities/categories
-- Audit logs: 15 records with mix of allowed, blocked, and flagged decisions
--
-- Sample queries you can run:
--   SELECT COUNT(*), status FROM support_tickets GROUP BY status;
--   SELECT COUNT(*), priority FROM support_tickets GROUP BY priority;
--   SELECT COUNT(*), policy_decision FROM audit_logs GROUP BY policy_decision;
-- ============================================================================
