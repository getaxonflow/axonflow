# SQL Injection Detection Examples

Demonstrates AxonFlow's SQL injection detection capabilities for both input queries and response scanning.

## What This Example Shows

AxonFlow detects and blocks SQL injection patterns:

| Detection Type | Description |
|----------------|-------------|
| Input Query | Blocks SQLi in user queries before LLM processing |
| Response Scan | Detects SQLi payloads in MCP connector responses |

### Input SQLi Patterns Detected

- `DROP TABLE`, `DELETE FROM`, `TRUNCATE`
- `UNION SELECT`, `OR 1=1`
- Comment injection (`--`, `/* */`)
- Stacked queries (`;`)
- Time-based blind SQLi (`SLEEP`, `WAITFOR`)

### Response SQLi Detection

When MCP connectors return data from databases, AxonFlow scans responses for SQLi payloads that could indicate:
- Compromised data being exfiltrated
- Injected malicious payloads in stored data
- Second-order SQL injection attempts

## Prerequisites

```bash
# Start AxonFlow
cd /path/to/axonflow
docker compose up -d

# Verify it's running
curl http://localhost:8080/health
```

## Run Examples

### Go
```bash
cd go
go run main.go
```

### Python
```bash
cd python
pip install -r requirements.txt
python main.py
```

### TypeScript
```bash
cd typescript
npm install
npx ts-node index.ts
```

### Java
```bash
cd java
mvn compile exec:java
```

### HTTP (curl)
```bash
cd http
chmod +x sqli-detection.sh
./sqli-detection.sh
```

## Expected Output

Each example tests multiple SQLi patterns:
- Safe query - APPROVED
- DROP TABLE - BLOCKED
- UNION SELECT - BLOCKED
- OR 1=1 - BLOCKED
- Comment injection - BLOCKED
- Stacked queries - BLOCKED

## How It Works

1. Client sends query to AxonFlow
2. Policy engine scans for SQLi patterns using regex + heuristics
3. If SQLi detected, request is blocked before reaching LLM
4. Block reason indicates the SQLi type detected

## Policy Configuration

SQLi detection is enabled by default via system policies:
- `sqli_detection` - Basic SQLi patterns
- `sqli_advanced_detection` - ML-assisted (Enterprise)

## Next Steps

- [PII Detection](../pii-detection/) - Block sensitive data
- [Policies Example](../policies/) - Create custom policies
- [MCP Connectors](../mcp-connectors/) - Database integrations
