# ComputerUseGovernor: Governance for Anthropic Computer Use

Demonstrates `ComputerUseGovernor` — middleware for the Computer Use sampling loop that evaluates tool_use blocks against AxonFlow policies before execution and scans results before feeding back to Claude.

## Prerequisites

- AxonFlow running locally (`docker compose up -d`)
- Python 3.10+
- `pip install axonflow`

## Examples

### Python E2E

10 tests covering all Computer Use governance scenarios:

```bash
cd python
pip install -r requirements.txt
python main.py
```

Tests:
1. Screenshot action allowed (read-only)
2. Click action allowed
3. Clean bash command allowed
4. Destructive bash (rm -rf) blocked locally
5. Credential exfiltration (cat ~/.ssh/) blocked
6. Remote code execution (curl|bash) blocked
7. PII in type action detected
8. Clean tool result allowed
9. PII in tool result redacted
10. Connector type derivation verified

## How It Works

```
Claude returns tool_use blocks
    |
    v
+-----------------------------------------------+
| ComputerUseGovernor.check_tool_use(block)     |
| 1. Local bash pattern check (fast, no network)|
|    - rm -rf, dd if=, cat ~/.ssh/, curl|bash   |
| 2. mcp_check_input(computer_use.{action})     |
|    - PII in type text, SQLi, secrets          |
| Decision: ALLOW or BLOCK                       |
+-----------------------------------------------+
    |
    v  (if allowed)
Execute tool (screenshot, click, type, bash)
    |
    v
+-----------------------------------------------+
| ComputerUseGovernor.check_result(name, result)|
| mcp_check_output(computer_use.{name})         |
| Decision: ALLOW, REDACT, or BLOCK             |
+-----------------------------------------------+
    |
    v  (clean/redacted result)
Feed result back to Claude
```
