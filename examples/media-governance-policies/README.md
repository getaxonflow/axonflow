# Media Governance Policies Examples

Demonstrates and validates AxonFlow's media governance **policy management** capabilities — creating, toggling, and evaluating media-specific governance policies.

> For media **analysis** capabilities (PII detection, content safety, hashing), see [`../media-governance/`](../media-governance/).

## What This Example Shows

| Test | Description |
|------|-------------|
| System media policies exist | Verifies 5 seeded system policies (NSFW block, violence warn, biometric log, PII block, sensitive doc warn) |
| NSFW policy evaluation | Sends a clean image and confirms it passes system NSFW policy |
| Custom media policy CRUD | Creates a tenant policy, verifies it in the list, processes an image, then deletes it |
| Media governance config/status | Reads tier-level status and per-tenant configuration via SDK |
| Policy toggle lifecycle | Creates a policy, disables it, re-enables it, then deletes it |
| Per-tenant governance toggle | Enterprise only: disables/enables media governance per-tenant and verifies behavior |
| Non-media request unaffected | Sends a text-only query and confirms media policies have no effect |

## Prerequisites

```bash
# Start AxonFlow (v4.5.0+ required for system media policies)
cd /path/to/axonflow
docker compose up -d

# Verify it's running
curl http://localhost:8080/health
curl http://localhost:8081/health
```

**Two endpoints are required:**
- **Agent** (default `:8080`) — for proxy LLM calls that trigger media analysis
- **Orchestrator** (default `:8081`) — for policy CRUD, media governance config, and status

## Run Examples

### HTTP/curl
```bash
cd http
bash media-governance-policies.sh
```

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
npx ts-node main.ts
```

### Java
```bash
cd java
mvn compile exec:java
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_ENDPOINT` | `http://localhost:8080` | Agent endpoint for proxy LLM calls |
| `AXONFLOW_ORCHESTRATOR_ENDPOINT` | `http://localhost:8081` | Orchestrator endpoint for policy CRUD |
| `AXONFLOW_CLIENT_ID` | `demo` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | `demo` | Client secret for authentication |
| `AXONFLOW_TENANT` | (same as client ID) | Tenant ID for multi-tenant deployments |
| `AXONFLOW_DEBUG` | (empty) | Set to `true` for verbose logging |

## System Media Policies (v4.5.0+)

These 5 policies are seeded by platform migrations and active by default:

| Policy ID | Category | Condition | Action | Priority |
|-----------|----------|-----------|--------|----------|
| `sys_media_nsfw_block` | media-safety | `media.nsfw_score > 0.8` | block | 1000 |
| `sys_media_violence_warn` | media-safety | `media.violence_score > 0.7` | alert + log | 950 |
| `sys_media_biometric_log` | media-biometric | `media.has_biometric_data == true` | log | 900 |
| `sys_media_pii_block` | media-pii | `media.has_pii == true` | block | 950 |
| `sys_media_sensitive_doc_warn` | media-document | `media.is_sensitive_document == true` | alert + log | 900 |

## Tier Capabilities

| Capability | Community | Evaluation | Enterprise |
|------------|-----------|------------|------------|
| System media policies active | When governance enabled | Yes | Yes |
| Toggle system policies | Global enable/disable | Yes | Yes |
| Custom media policies | Up to 20 | Up to 50 | Unlimited |
| Per-tenant config API | No | No | Yes |
| Modify system policy actions | No | No | Yes |

## Next Steps

- [Media Governance Analysis](../media-governance/) — Image analysis capabilities (PII, content safety, hashing)
- [Dynamic Policies](../dynamic-policies/) — Text-based dynamic policy management
- [Media Governance Guide](../../docs/guides/media-governance.md) — Full configuration reference
