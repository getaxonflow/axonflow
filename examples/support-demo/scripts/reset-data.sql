-- Reset Data Script: Clear inconsistencies and set proper demo data
-- This ensures Total Queries (All Time) > Queries Today

-- Clear existing data
TRUNCATE TABLE audit_log CASCADE;
TRUNCATE TABLE policy_metrics CASCADE;
TRUNCATE TABLE recent_activity CASCADE;
TRUNCATE TABLE performance_metrics CASCADE;
TRUNCATE TABLE performance_summary CASCADE;

-- Insert historical audit log data (to make Total Queries > Queries Today)
-- Adding 150 historical queries from past 30 days
DO $$
DECLARE
    i INTEGER;
    days_ago INTEGER;
    user_emails TEXT[] := ARRAY['john.doe@company.com', 'sarah.manager@company.com', 'admin@company.com'];
    query_types TEXT[] := ARRAY[
        'SELECT * FROM support_tickets WHERE status = ''open''',
        'SELECT * FROM customers WHERE region = ''us-west''',
        'SELECT COUNT(*) FROM support_tickets',
        'SELECT * FROM customers WHERE created_at > NOW() - INTERVAL ''7 days''',
        'SELECT id, email FROM customers LIMIT 10'
    ];
BEGIN
    FOR i IN 1..150 LOOP
        days_ago := floor(random() * 30)::INTEGER;
        INSERT INTO audit_log (
            user_email, 
            query_text, 
            results_count, 
            pii_detected, 
            pii_redacted, 
            access_granted, 
            created_at
        ) VALUES (
            user_emails[1 + floor(random() * 3)::INTEGER],
            query_types[1 + floor(random() * 5)::INTEGER],
            floor(random() * 20)::INTEGER,
            CASE WHEN random() < 0.3 THEN ARRAY['email', 'phone'] ELSE ARRAY[]::TEXT[] END,
            random() < 0.3,
            true,
            NOW() - INTERVAL '1 day' * days_ago - INTERVAL '1 hour' * floor(random() * 24)::INTEGER
        );
    END LOOP;
END $$;

-- Insert today's audit log data (47 queries to match policy_metrics)
DO $$
DECLARE
    i INTEGER;
    user_emails TEXT[] := ARRAY['john.doe@company.com', 'sarah.manager@company.com', 'admin@company.com'];
    query_types TEXT[] := ARRAY[
        'SELECT * FROM support_tickets WHERE status = ''open''',
        'SELECT * FROM customers WHERE region = ''us-west''',
        'SELECT COUNT(*) FROM support_tickets',
        'SELECT * FROM customers WHERE created_at > NOW() - INTERVAL ''7 days''',
        'SELECT id, email FROM customers LIMIT 10'
    ];
BEGIN
    FOR i IN 1..47 LOOP
        INSERT INTO audit_log (
            user_email, 
            query_text, 
            results_count, 
            pii_detected, 
            pii_redacted, 
            access_granted, 
            created_at
        ) VALUES (
            user_emails[1 + floor(random() * 3)::INTEGER],
            query_types[1 + floor(random() * 5)::INTEGER],
            floor(random() * 20)::INTEGER,
            CASE WHEN random() < 0.3 THEN ARRAY['email', 'phone'] ELSE ARRAY[]::TEXT[] END,
            random() < 0.3,
            true,
            NOW() - INTERVAL '1 minute' * i
        );
    END LOOP;
END $$;

-- Insert today's policy metrics (matching the 47 queries today)
INSERT INTO policy_metrics (
    date, total_policies_enforced, ai_queries, pii_redacted, regional_blocks,
    agent_health, orchestrator_health
) VALUES (
    CURRENT_DATE, 47, 23, 8, 3, 'healthy', 'healthy'
) ON CONFLICT (date) DO UPDATE SET
    total_policies_enforced = EXCLUDED.total_policies_enforced,
    ai_queries = EXCLUDED.ai_queries,
    pii_redacted = EXCLUDED.pii_redacted,
    regional_blocks = EXCLUDED.regional_blocks,
    agent_health = EXCLUDED.agent_health,
    orchestrator_health = EXCLUDED.orchestrator_health,
    updated_at = NOW();

-- Insert recent activity data
INSERT INTO recent_activity (activity_type, query_text, user_email, provider, timestamp)
VALUES 
    ('natural_query', 'Show me customer support tickets from this week', 'john.doe@company.com', 'Local', NOW() - INTERVAL '5 minutes'),
    ('sql_query', 'SELECT * FROM customers WHERE region = ''us-west''', 'sarah.manager@company.com', 'direct', NOW() - INTERVAL '3 minutes'),
    ('natural_query', 'Find customers with high priority tickets', 'admin@company.com', 'OpenAI', NOW() - INTERVAL '2 minutes'),
    ('sql_query', 'SELECT COUNT(*) FROM support_tickets WHERE status = ''open''', 'john.doe@company.com', 'direct', NOW() - INTERVAL '1 minute');

-- Insert performance metrics data
INSERT INTO performance_summary (
    date, avg_response_time, p95_response_time, p99_response_time, 
    requests_per_second, error_rate, total_requests,
    agent_avg_latency, orchestrator_avg_latency
) VALUES (
    CURRENT_DATE, 145.5, 167, 169, 12.5, 0.2, 197, 41.2, 107.8
) ON CONFLICT (date) DO UPDATE SET
    avg_response_time = EXCLUDED.avg_response_time,
    p95_response_time = EXCLUDED.p95_response_time,
    p99_response_time = EXCLUDED.p99_response_time,
    requests_per_second = EXCLUDED.requests_per_second,
    error_rate = EXCLUDED.error_rate,
    total_requests = EXCLUDED.total_requests,
    agent_avg_latency = EXCLUDED.agent_avg_latency,
    orchestrator_avg_latency = EXCLUDED.orchestrator_avg_latency,
    updated_at = NOW();

-- Verify the data
SELECT 'Total Queries (All Time):' as metric, COUNT(*) as value FROM audit_log
UNION ALL
SELECT 'Queries Today:' as metric, COUNT(*) as value FROM audit_log WHERE DATE(created_at) = CURRENT_DATE
UNION ALL
SELECT 'Policy Metrics - Queries Today:' as metric, total_policies_enforced as value FROM policy_metrics WHERE date = CURRENT_DATE;