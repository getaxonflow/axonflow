-- AxonFlow Demo Database Schema
-- Realistic customer support data with PII for demo

-- Users table (employees who can query the system)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    department VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL,
    region VARCHAR(50) NOT NULL,
    permissions TEXT[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Customers table (contains PII that needs protection)
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    credit_card VARCHAR(19),
    ssn VARCHAR(11),
    address TEXT,
    region VARCHAR(50) NOT NULL,
    support_tier VARCHAR(20) DEFAULT 'standard',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Support tickets table
CREATE TABLE support_tickets (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'open',
    priority VARCHAR(20) DEFAULT 'medium',
    region VARCHAR(50) NOT NULL,
    assigned_to VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL
);

-- Audit log for tracking all queries
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    user_email VARCHAR(255) NOT NULL,
    query_text TEXT NOT NULL,
    results_count INTEGER DEFAULT 0,
    pii_detected TEXT[] DEFAULT '{}',
    pii_redacted BOOLEAN DEFAULT FALSE,
    access_granted BOOLEAN DEFAULT TRUE,
    ip_address INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert demo users with different permission levels
INSERT INTO users (email, password_hash, name, department, role, region, permissions) VALUES
('john.doe@company.com', '$2a$10$rZ5F7YKmH5VwGzL3Nv9K4uLm8qP3jQ2xR6sT9hU4eW7fX1cY5dZ8g', 'John Doe', 'support', 'agent', 'us-west', ARRAY['read_customers', 'read_tickets']),
('sarah.manager@company.com', '$2a$10$rZ5F7YKmH5VwGzL3Nv9K4uLm8qP3jQ2xR6sT9hU4eW7fX1cY5dZ8g', 'Sarah Manager', 'support', 'manager', 'us-west', ARRAY['read_customers', 'read_tickets', 'read_pii']),
('admin@company.com', '$2a$10$rZ5F7YKmH5VwGzL3Nv9K4uLm8qP3jQ2xR6sT9hU4eW7fX1cY5dZ8g', 'Admin User', 'it', 'admin', 'global', ARRAY['read_customers', 'read_tickets', 'read_pii', 'admin']),
('eu.agent@company.com', '$2a$10$rZ5F7YKmH5VwGzL3Nv9K4uLm8qP3jQ2xR6sT9hU4eW7fX1cY5dZ8g', 'EU Agent', 'support', 'agent', 'eu-west', ARRAY['read_customers', 'read_tickets']);

-- Insert realistic customer data with PII
INSERT INTO customers (name, email, phone, credit_card, ssn, address, region, support_tier) VALUES
('Alice Johnson', 'alice.johnson@email.com', '555-123-4567', '4532-1234-5678-9012', '123-45-6789', '123 Main St, San Francisco, CA 94105', 'us-west', 'premium'),
('Bob Smith', 'bob.smith@email.com', '555-234-5678', '5432-2345-6789-0123', '234-56-7890', '456 Oak Ave, Los Angeles, CA 90210', 'us-west', 'standard'),
('Carol Davis', 'carol.davis@email.com', '555-345-6789', '4111-3456-7890-1234', '345-67-8901', '789 Pine St, Seattle, WA 98101', 'us-west', 'enterprise'),
('David Wilson', 'david.wilson@email.com', '555-456-7890', '4000-4567-8901-2345', '456-78-9012', '321 Elm St, Portland, OR 97201', 'us-west', 'standard'),
('Eva Brown', 'eva.brown@email.com', '+44-20-7123-4567', '5555-5678-9012-3456', null, '10 Downing St, London, UK', 'eu-west', 'premium'),
('Frank Miller', 'frank.miller@email.com', '+44-20-7234-5678', '4444-6789-0123-4567', null, '221B Baker St, London, UK', 'eu-west', 'standard'),
('Grace Lee', 'grace.lee@email.com', '555-567-8901', '3782-7890-1234-5678', '567-89-0123', '555 Market St, San Francisco, CA 94105', 'us-west', 'enterprise'),
('Henry Taylor', 'henry.taylor@email.com', '555-678-9012', '6011-8901-2345-6789', '678-90-1234', '777 Broadway, New York, NY 10001', 'us-east', 'premium'),
('Iris Wang', 'iris.wang@email.com', '555-789-0123', '3566-9012-3456-7890', '789-01-2345', '999 Tech Blvd, Austin, TX 78701', 'us-central', 'standard'),
('Jack Black', 'jack.black@email.com', '+49-30-1234-5678', '5105-0123-4567-8901', null, 'Unter den Linden 1, Berlin, Germany', 'eu-central', 'enterprise');

-- Insert support tickets
INSERT INTO support_tickets (customer_id, title, description, status, priority, region, assigned_to) VALUES
(1, 'Cannot access premium features', 'Customer Alice Johnson reports that premium features are not working after recent update. She has provided her credit card ending in 9012 for verification.', 'open', 'high', 'us-west', 'john.doe@company.com'),
(2, 'Billing inquiry', 'Bob Smith (SSN: 234-56-7890) is questioning a charge on his account. He can be reached at 555-234-5678.', 'in_progress', 'medium', 'us-west', 'john.doe@company.com'),
(3, 'Data export request', 'Enterprise customer Carol Davis needs to export all her data for compliance audit. Contact: carol.davis@email.com', 'open', 'high', 'us-west', 'sarah.manager@company.com'),
(4, 'Password reset issues', 'David Wilson cannot reset password. Phone: 555-456-7890, Address: 321 Elm St, Portland, OR 97201', 'resolved', 'low', 'us-west', 'john.doe@company.com'),
(5, 'GDPR data deletion request', 'Eva Brown from UK (eva.brown@email.com) requests deletion of personal data per GDPR Article 17.', 'open', 'high', 'eu-west', 'eu.agent@company.com'),
(6, 'Account verification needed', 'Frank Miller needs account verification. Credit card: 4444-6789-0123-4567, Phone: +44-20-7234-5678', 'open', 'medium', 'eu-west', 'eu.agent@company.com'),
(7, 'Enterprise integration support', 'Grace Lee (grace.lee@email.com) needs help with API integration. SSN: 567-89-0123 for verification.', 'in_progress', 'high', 'us-west', 'sarah.manager@company.com'),
(8, 'Premium upgrade request', 'Henry Taylor wants to upgrade to enterprise tier. Contact: 555-678-9012', 'open', 'medium', 'us-east', 'john.doe@company.com'),
(9, 'Technical issue with dashboard', 'Iris Wang reports dashboard loading issues. Phone: 555-789-0123, Card: 3566-9012-3456-7890', 'open', 'low', 'us-central', 'john.doe@company.com'),
(10, 'Contract renewal discussion', 'Enterprise customer Jack Black needs contract renewal. Email: jack.black@email.com, Berlin office.', 'open', 'high', 'eu-central', 'eu.agent@company.com');

-- Create indexes for better performance
CREATE INDEX idx_customers_region ON customers(region);
CREATE INDEX idx_tickets_region ON support_tickets(region);
CREATE INDEX idx_tickets_status ON support_tickets(status);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);