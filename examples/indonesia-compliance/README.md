# Indonesia Compliance Examples

Demonstrates AxonFlow's Indonesia compliance features: PII detection (OJK/UU PDP),
Decision Mode integration, OJK audit export, and UU PDP Art. 46 breach notifications.

## Prerequisites

```bash
docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d
./scripts/setup-e2e-testing.sh enterprise
source /tmp/axonflow-e2e-env.sh
export PII_ACTION=block  # Required for deny-path tests
```

## Examples

| Example | Description |
|---------|-------------|
| `http/decision-mode-indonesia-pii.sh` | Decision Mode deny/allow for NIK and NPWP |
| `http/ojk-audit-export.sh` | OJK audit export, readiness scoring, dashboard |
| `http/ojk-breach-notification.sh` | UU PDP Art. 46 breach notification with 72h deadline |

## SDK Examples

Go and Python SDK examples are in their respective SDK repositories:

- **Go**: `axonflow-sdk-go/examples/indonesia_compliance/main.go`
- **Python**: `axonflow-sdk-python/examples/indonesia_compliance.py`
