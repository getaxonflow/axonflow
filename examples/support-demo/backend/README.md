# Support Demo Backend

Go backend for the AxonFlow Customer Support Demo, demonstrating AI governance patterns.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Backend Server                          │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐    │
│  │   main.go   │──│ PolicyEngine │──│   LLMRouter     │    │
│  │  (HTTP API) │  │ (DLP + RBAC) │  │ (Multi-provider)│    │
│  └─────────────┘  └──────────────┘  └─────────────────┘    │
│         │                │                   │              │
│         ▼                ▼                   ▼              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐    │
│  │ PostgreSQL  │  │  Audit Log   │  │ OpenAI/Anthropic│    │
│  │   (Data)    │  │  (Security)  │  │    /Local       │    │
│  └─────────────┘  └──────────────┘  └─────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### PolicyEngine (`policy_engine.go`)

Three-layer security enforcement:

1. **Blocked Query Rules** - Prevents SQL injection and dangerous operations
   - DROP TABLE, TRUNCATE, DELETE without WHERE
   - UNION SELECT, information_schema access
   - Admin bypass attempts

2. **Security Policies** - Role-based access control
   - PII access requires manager+ role
   - Admin tables require admin role
   - Cross-region access monitoring

3. **DLP Rules** - PII detection and redaction
   - SSN: `123-45-6789` → `[REDACTED_SSN]`
   - Credit Cards: `4111-1111-1111-1111` → `[REDACTED_CARD]`
   - Phone, Email, API Keys, Medical Records

### LLMRouter (`llm_router.go`)

Intelligent provider routing based on:

| Priority | Condition | Provider | Reason |
|----------|-----------|----------|--------|
| 1 | EU Region | Local | GDPR compliance |
| 2 | PII in query | Local | Data sovereignty |
| 3 | Confidential data | Anthropic | Safety-focused |
| 4 | Manager/Admin role | OpenAI | Full access |
| 5 | Agent/Unknown role | Anthropic | Restricted |

### Natural Language to SQL

Converts natural language queries to secure PostgreSQL:

```
User: "Show open tickets for premium customers"
  ↓
SQL: SELECT st.* FROM support_tickets st
     JOIN customers c ON st.customer_id = c.id
     WHERE st.status = 'open' AND c.support_tier = 'premium'
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate user |
| POST | `/api/query` | Execute natural language query |
| GET | `/api/audit` | Get audit log entries |
| GET | `/api/health` | Health check |
| GET | `/api/policies` | List active policies |
| GET | `/api/performance` | Get performance metrics |

## Running Locally

```bash
# Install dependencies
go mod download

# Set environment variables
export OPENAI_API_KEY=sk-your-key
# OR
export ANTHROPIC_API_KEY=sk-ant-your-key

# Run (requires PostgreSQL)
go run .

# Run tests
go test -v ./...
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | One of these | - | OpenAI API key |
| `ANTHROPIC_API_KEY` | required | - | Anthropic API key |
| `DATABASE_URL` | No | postgres://axonflow:axonflow_demo@localhost:5432/support_demo | PostgreSQL connection |
| `JWT_SECRET` | No | demo-secret | JWT signing secret |
| `PORT` | No | 8080 | Server port |

## Database Schema

```sql
-- Users (support staff)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    name VARCHAR(255),
    role VARCHAR(50),        -- agent, manager, admin
    region VARCHAR(50),      -- us-west, eu-central, etc.
    permissions TEXT[]       -- read_pii, admin, etc.
);

-- Customers (contains PII)
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255),
    phone VARCHAR(20),       -- PII
    credit_card VARCHAR(19), -- PII
    ssn VARCHAR(11),         -- PII
    support_tier VARCHAR(20) -- standard, premium, enterprise
);

-- Support Tickets
CREATE TABLE support_tickets (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    title VARCHAR(500),
    status VARCHAR(50),      -- open, in_progress, resolved
    priority VARCHAR(20)     -- low, medium, high
);

-- Audit Log
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255),
    query_text TEXT,
    pii_detected TEXT[],
    pii_redacted BOOLEAN,
    created_at TIMESTAMP
);
```

## Testing

```bash
# Run all tests
go test -v ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v -run TestEvaluateQuery_BlockedQueries ./...
```

## Demo Users

| Email | Role | Permissions |
|-------|------|-------------|
| john.doe@company.com | agent | Limited PII, US West |
| sarah.manager@company.com | manager | Full PII, escalation |
| admin@company.com | admin | Global access |

Password for all: `demo123`

## License

Apache License 2.0 - See [LICENSE](../LICENSE)
