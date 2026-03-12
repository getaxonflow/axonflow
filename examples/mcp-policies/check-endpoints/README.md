# MCP Policy Check Endpoints — Examples

Standalone policy-check endpoints for external orchestrators (LangGraph, CrewAI, custom pipelines).

These endpoints validate MCP requests and responses against AxonFlow policies **without executing
any connector queries**. Use them when your orchestrator manages MCP connector execution natively
but needs AxonFlow as a policy gate.

## Endpoints

| Endpoint | Purpose | Key Policies |
|----------|---------|-------------|
| `POST /api/v1/mcp/check-input` | Validate input before execution | SQLi blocking, dangerous queries, **parameter scanning**, dynamic policies |
| `POST /api/v1/mcp/check-output` | Validate output after execution | PII redaction, exfiltration limits, SQLi response scanning |

## Parameter Scanning (Issue #1287)

The `check-input` endpoint scans `parameters` values individually for SQLi, PII, and compliance
violations. This prevents attackers from passing a clean `statement` while embedding payloads in
parameter values. Each parameter value is scanned independently (not concatenated with the statement)
to avoid false positives from concatenation artifacts.

## Prerequisites

```bash
# Start AxonFlow in community mode
docker compose up -d

# Or use the E2E setup script
./scripts/setup-e2e-testing.sh community
```

## HTTP Examples (curl)

```bash
# Check-input: validates SQL statements
bash http/check-input.sh

# Check-output: validates response data (PII, exfiltration)
bash http/check-output.sh
```

## Python Examples

**Raw HTTP (requests library):**
```bash
cd python-http
pip install -r requirements.txt
python main.py
```

**SDK:**
```bash
cd python
pip install -r requirements.txt
python main.py
```

## Go Example (SDK)

```bash
cd go
go run main.go
```

## TypeScript Example (SDK)

```bash
cd typescript
npm install
npm start
```

## Java Example (SDK)

```bash
cd java
mvn exec:java
```

## When to Use

| Scenario | Use Check Endpoints | Use mcpQuery/mcpExecute |
|----------|:------------------:|:----------------------:|
| External orchestrator runs MCP | ✅ | |
| AxonFlow manages full MCP flow | | ✅ |
| Pre-validate before execution | ✅ | |
| Post-validate fetched data | ✅ | |
| Need both policy + execution | | ✅ |
