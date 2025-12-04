-- Policy Metrics Table for persistent Live Monitor data
CREATE TABLE IF NOT EXISTS policy_metrics (
    id SERIAL PRIMARY KEY,
    date DATE DEFAULT CURRENT_DATE,
    total_policies_enforced INTEGER DEFAULT 0,
    ai_queries INTEGER DEFAULT 0,
    pii_redacted INTEGER DEFAULT 0,
    regional_blocks INTEGER DEFAULT 0,
    agent_health VARCHAR(20) DEFAULT 'healthy',
    orchestrator_health VARCHAR(20) DEFAULT 'healthy',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(date)
);

-- Recent Activity Table for Live Monitor activity feed
CREATE TABLE IF NOT EXISTS recent_activity (
    id SERIAL PRIMARY KEY,
    activity_type VARCHAR(50), -- 'natural_query' or 'sql_query'
    query_text TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_email VARCHAR(255),
    provider VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for better query performance
CREATE INDEX IF NOT EXISTS idx_policy_metrics_date ON policy_metrics(date);
CREATE INDEX IF NOT EXISTS idx_recent_activity_timestamp ON recent_activity(timestamp);
CREATE INDEX IF NOT EXISTS idx_recent_activity_type ON recent_activity(activity_type);

-- Insert today's policy metrics with demo values
INSERT INTO policy_metrics (
    date, total_policies_enforced, ai_queries, pii_redacted, regional_blocks,
    agent_health, orchestrator_health
) VALUES (
    CURRENT_DATE, 47, 23, 8, 3, 'healthy', 'healthy'
) ON CONFLICT (date) DO UPDATE SET
    total_policies_enforced = COALESCE(policy_metrics.total_policies_enforced, EXCLUDED.total_policies_enforced),
    ai_queries = COALESCE(policy_metrics.ai_queries, EXCLUDED.ai_queries),
    pii_redacted = COALESCE(policy_metrics.pii_redacted, EXCLUDED.pii_redacted),
    regional_blocks = COALESCE(policy_metrics.regional_blocks, EXCLUDED.regional_blocks),
    agent_health = EXCLUDED.agent_health,
    orchestrator_health = EXCLUDED.orchestrator_health,
    updated_at = NOW();

-- Insert some recent activity demo data
INSERT INTO recent_activity (activity_type, query_text, user_email, provider, timestamp)
VALUES 
    ('natural_query', 'Show me customer support tickets from this week', 'john.doe@company.com', 'Local', NOW() - INTERVAL '5 minutes'),
    ('sql_query', 'SELECT * FROM customers WHERE region = ''us-west''', 'sarah.manager@company.com', 'direct', NOW() - INTERVAL '3 minutes'),
    ('natural_query', 'Find customers with high priority tickets', 'admin@company.com', 'OpenAI', NOW() - INTERVAL '2 minutes'),
    ('sql_query', 'SELECT COUNT(*) FROM support_tickets WHERE status = ''open''', 'john.doe@company.com', 'direct', NOW() - INTERVAL '1 minute');