-- Performance Metrics Table for persistent storage
CREATE TABLE IF NOT EXISTS performance_metrics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    endpoint VARCHAR(255),
    method VARCHAR(10),
    response_time_ms INTEGER,
    status_code INTEGER,
    user_email VARCHAR(255),
    client_id VARCHAR(255) DEFAULT 'support-demo-client',
    agent_latency_ms INTEGER DEFAULT 0,
    orchestrator_latency_ms INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance Summary Table for aggregated metrics
CREATE TABLE IF NOT EXISTS performance_summary (
    id SERIAL PRIMARY KEY,
    date DATE DEFAULT CURRENT_DATE,
    avg_response_time DECIMAL(10,2),
    p95_response_time INTEGER,
    p99_response_time INTEGER,
    requests_per_second DECIMAL(10,2),
    error_rate DECIMAL(5,2),
    total_requests INTEGER,
    agent_avg_latency DECIMAL(10,2),
    orchestrator_avg_latency DECIMAL(10,2),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(date)
);

-- Index for better query performance
CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_endpoint ON performance_metrics(endpoint);
CREATE INDEX IF NOT EXISTS idx_performance_summary_date ON performance_summary(date);

-- Insert initial demo data for today
INSERT INTO performance_metrics (endpoint, method, response_time_ms, status_code, user_email, agent_latency_ms, orchestrator_latency_ms, timestamp)
VALUES 
    ('/api/dashboard', 'GET', 120, 200, 'john.doe@company.com', 35, 85, NOW() - INTERVAL '19 minutes'),
    ('/api/query', 'POST', 135, 200, 'sarah.manager@company.com', 40, 95, NOW() - INTERVAL '18 minutes'),
    ('/api/llm/chat', 'POST', 158, 200, 'admin@company.com', 45, 113, NOW() - INTERVAL '17 minutes'),
    ('/api/dashboard', 'GET', 142, 200, 'john.doe@company.com', 38, 104, NOW() - INTERVAL '16 minutes'),
    ('/api/query', 'POST', 167, 200, 'sarah.manager@company.com', 42, 125, NOW() - INTERVAL '15 minutes'),
    ('/api/llm/chat', 'POST', 145, 200, 'john.doe@company.com', 35, 110, NOW() - INTERVAL '14 minutes'),
    ('/api/dashboard', 'GET', 139, 200, 'admin@company.com', 39, 100, NOW() - INTERVAL '13 minutes'),
    ('/api/query', 'POST', 152, 200, 'sarah.manager@company.com', 41, 111, NOW() - INTERVAL '12 minutes'),
    ('/api/llm/chat', 'POST', 161, 200, 'john.doe@company.com', 46, 115, NOW() - INTERVAL '11 minutes'),
    ('/api/dashboard', 'GET', 148, 200, 'admin@company.com', 43, 105, NOW() - INTERVAL '10 minutes'),
    ('/api/query', 'POST', 134, 200, 'sarah.manager@company.com', 34, 100, NOW() - INTERVAL '9 minutes'),
    ('/api/llm/chat', 'POST', 156, 200, 'john.doe@company.com', 44, 112, NOW() - INTERVAL '8 minutes'),
    ('/api/dashboard', 'GET', 143, 200, 'admin@company.com', 37, 106, NOW() - INTERVAL '7 minutes'),
    ('/api/query', 'POST', 169, 200, 'sarah.manager@company.com', 49, 120, NOW() - INTERVAL '6 minutes'),
    ('/api/llm/chat', 'POST', 137, 200, 'john.doe@company.com', 32, 105, NOW() - INTERVAL '5 minutes'),
    ('/api/dashboard', 'GET', 154, 200, 'admin@company.com', 44, 110, NOW() - INTERVAL '4 minutes'),
    ('/api/query', 'POST', 162, 200, 'sarah.manager@company.com', 47, 115, NOW() - INTERVAL '3 minutes'),
    ('/api/llm/chat', 'POST', 141, 200, 'john.doe@company.com', 36, 105, NOW() - INTERVAL '2 minutes'),
    ('/api/dashboard', 'GET', 149, 200, 'admin@company.com', 41, 108, NOW() - INTERVAL '1 minute'),
    ('/api/query', 'POST', 145, 200, 'sarah.manager@company.com', 40, 105, NOW());

-- Insert today's summary data
INSERT INTO performance_summary (
    date, avg_response_time, p95_response_time, p99_response_time, 
    requests_per_second, error_rate, total_requests,
    agent_avg_latency, orchestrator_avg_latency
) VALUES (
    CURRENT_DATE, 145.5, 167, 169, 12.5, 0.2, 1247, 41.2, 107.8
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