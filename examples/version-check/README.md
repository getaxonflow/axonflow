# Version Discovery Examples

Demonstrates SDK-platform version compatibility and capability discovery.

Starting with platform v4.8.0, the `/health` endpoint returns:
- **`version`**: Real platform version (from `AXONFLOW_VERSION` env var)
- **`capabilities`**: Array of supported features with version introduced
- **`sdk_compatibility`**: Minimum and recommended SDK versions

## Prerequisites

```bash
docker compose up -d
```

## Examples

### HTTP (curl + jq)

```bash
bash http/check-version.sh
```

### Go SDK

```bash
cd go
# For local SDK testing: add replace directive to go.mod
go run main.go
```

### Python SDK

```bash
cd python
pip install -r requirements.txt
# For local SDK testing: pip install -e /path/to/axonflow-sdk-python
python main.py
```

### TypeScript SDK

```bash
cd typescript
npm install
# For local SDK testing: npm link @axonflow/sdk
npx tsx index.ts
```

### Java SDK

```bash
cd java
mvn compile exec:java
```

## What Each Example Tests

| Test | Description |
|------|-------------|
| Version | Platform returns non-empty version string |
| Capabilities | Non-empty capabilities array in health response |
| SDK Compatibility | `min_sdk_version` and `recommended_sdk_version` present |
| hasCapability | `health_check` and `version_discovery` capabilities exist |
| Negative check | `nonexistent_feature` correctly returns false |
| SDK version | SDK version constant is accessible |
