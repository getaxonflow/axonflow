# Media Governance Examples

Demonstrates AxonFlow's multimodal media governance capabilities for images.

## What This Example Shows

AxonFlow analyzes images attached to LLM requests for governance compliance:

| Analysis | Description |
|----------|-------------|
| PII Detection | OCR-based detection of PII in image text (SSN, credit cards, etc.) |
| Content Safety | NSFW and violence scoring with configurable thresholds |
| Face/Biometric Detection | Face counting and biometric data flagging (GDPR Art. 9) |
| Document Classification | Detection of sensitive documents (ID cards, bank statements) |
| Integrity Hashing | SHA-256 hash of each image for audit trails |

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

## Expected Output

Each example sends image data through AxonFlow's Proxy Mode and validates the response:

1. **Single image** - Sends a base64-encoded image and validates that media analysis results are returned with expected fields (SHA-256 hash, content safety, PII detection, face detection)
2. **Multiple images** - Sends two images in a single request and validates that each receives individual analysis results
3. **URL-sourced image** - Sends an image by URL reference and validates the response structure
4. **Non-media baseline** - Sends a text-only request and confirms no media analysis is returned
5. **Policy evaluation metadata** - Verifies that `policy_info` is present when media is analyzed, confirming system media policies were evaluated

## How It Works

1. Client sends a multimodal request (text query + images) to AxonFlow via Proxy Mode
2. AxonFlow's media governance pipeline analyzes each image:
   - Computes SHA-256 hash for audit trail
   - Runs OCR and checks for PII patterns
   - Evaluates content safety (NSFW, violence)
   - Detects faces and biometric data
   - Classifies document type
3. Analysis results are returned alongside the LLM response in the `media_analysis` field
4. If any image violates policy (e.g., unsafe content), the request may be blocked

## Policy Configuration

Media governance is controlled by these policies:

| Policy | Default | Description |
|--------|---------|-------------|
| `media_content_safety` | `block` | Block requests with unsafe content (NSFW > 0.7 or violence > 0.8) |
| `media_pii_detection` | `redact` | Flag images containing PII text |
| `media_biometric_detection` | `log` | Log biometric data detection for GDPR compliance |
| `media_document_classification` | `log` | Log sensitive document detection |

> **Note:** In Community mode, all media policies use fail-open enforcement (warn + log). The block/redact actions shown above are available in Enterprise mode only.

## Next Steps

- [PII Detection](../pii-detection/) - Text-based PII detection
- [Media Governance Guide](../../docs/guides/media-governance.md) - Full configuration reference
- [Gateway Mode](../integrations/gateway-mode/) - Full LLM integration
