---
title: Media Governance
description: Image analysis and governance for multimodal LLM requests
---

# Media Governance

AxonFlow provides governance for images sent to multimodal LLMs (GPT-4o, Claude, Gemini). Images are analyzed for PII, content safety, biometric data, and sensitive documents before reaching the LLM provider.

## Supported Formats

| Format | MIME Type |
|--------|-----------|
| JPEG | `image/jpeg` |
| PNG | `image/png` |
| GIF | `image/gif` |
| WebP | `image/webp` |

**Limits:** Max 20MB per image, max 8192px dimension, max 10 images per request.

## How It Works

1. Client sends images (base64 or URL) alongside the query
2. AxonFlow validates format, size, and dimensions
3. Configured analyzers run (OCR, content safety, face detection, document classification)
4. Results are aggregated and evaluated against media policies (including system media policies)
5. Request proceeds, is warned, or is blocked depending on policy actions and tier configuration

## Community Features

All tiers include:
- Image type/size/dimension validation
- Local OCR via Tesseract for text extraction
- PII detection on extracted text (reuses existing PII pipeline)
- SHA-256 hash stored in audit trail
- Aggregate cost estimation
- 5 system media policies seeded by default (NSFW blocking, violence warning, biometric audit, PII blocking, sensitive document detection)
- Toggle system media policies on/off
- Media governance disabled by default on Community (opt-in via `MEDIA_GOVERNANCE_ENABLED=true`)

## Enterprise Features

Enterprise tier adds:
- Cloud analyzers: AWS Rekognition, Google Vision, Azure Computer Vision
- Face detection and biometric data governance (GDPR Article 9)
- NSFW and content safety scoring
- Document classification (ID cards, passports, bank statements, medical records)
- Custom analyzer plugins
- Configurable enforcement (fail-closed mode)
- Full media audit trail with per-analyzer metadata
- Batch and async analysis pipelines
- Per-tenant media governance configuration (enable/disable, restrict analyzers)
- Modify actions and priority on system media policies
- Media governance audit export for compliance reporting

## System Media Policies

AxonFlow seeds 5 system media policies by default when media governance is enabled. These policies provide baseline governance out of the box and can be toggled on/off at any tier.

| Policy Name | Condition | Action | Priority | Category |
|-------------|-----------|--------|----------|----------|
| `sys_media_nsfw_block` | `media.nsfw_score > 0.8` | Block | 1000 | `media-safety` |
| `sys_media_violence_warn` | `media.violence_score > 0.7` | Alert + Log | 950 | `media-safety` |
| `sys_media_biometric_log` | `media.has_biometric_data == true` | Log | 900 | `media-biometric` |
| `sys_media_pii_block` | `media.has_pii == true` | Block | 950 | `media-pii` |
| `sys_media_sensitive_doc_warn` | `media.is_sensitive_document == true` | Alert + Log | 900 | `media-document` |

System media policies live in the same `dynamic_policies` table as all other dynamic policies. They use the same `DynamicPolicyEngine` evaluation, same CRUD API (`/api/v1/dynamic-policies`), and same audit trail.

### Media Policy Categories

- `media-safety` -- Content safety signals (NSFW, violence)
- `media-biometric` -- Biometric data detection (GDPR Article 9, BIPA)
- `media-pii` -- PII detected via OCR in images
- `media-document` -- Sensitive document classification

### Modifying System Media Policies

What can be changed depends on the license tier (see Tier Capabilities below). At a minimum, all tiers can toggle system media policies enabled/disabled. No tier can modify the condition expression, name, description, or type of a system media policy.

## Per-Tenant Configuration

Enterprise deployments can configure media governance on a per-tenant basis using the media governance config API.

### Get Configuration

```bash
curl -X GET https://orchestrator.getaxonflow.com/api/v1/media-governance/config \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "tenant_id": "tenant-123",
  "enabled": true,
  "allowed_analyzers": [],
  "updated_at": "2026-02-19T10:00:00Z",
  "updated_by": "admin@example.com"
}
```

An empty `allowed_analyzers` array means all registered analyzers are available.

### Update Configuration

```bash
curl -X PUT https://orchestrator.getaxonflow.com/api/v1/media-governance/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "allowed_analyzers": ["local-ocr", "aws-rekognition"]
  }'
```

### Check Feature Status

```bash
curl -X GET https://orchestrator.getaxonflow.com/api/v1/media-governance/status \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{
  "available": true,
  "enabled_by_default": true,
  "per_tenant_control": true,
  "tier": "enterprise"
}
```

## Tier Capabilities

| Capability | Community | Evaluation | Enterprise |
|------------|-----------|------------|------------|
| Media governance enabled by default | No (opt-in via `MEDIA_GOVERNANCE_ENABLED=true`) | Yes | Yes |
| System media policies seeded | Yes (when enabled) | Yes | Yes |
| Toggle system media policies on/off | Yes | Yes | Yes |
| Modify actions/priority on system media policies | No | No | Yes |
| Modify conditions/name/description/type | No | No | No |
| Per-tenant config API | No | No | Yes |
| Restrict allowed analyzers per tenant | No | No | Yes |
| Media governance audit export | No | No | Yes |

## SDK Usage

### Go

```go
resp, err := client.ProxyLLMCallWithMedia(ctx, axonflow.ClientRequest{
    Query:       "What's in this image?",
    UserToken:   "user-123",
    RequestType: "chat",
    Media: []axonflow.MediaContent{{
        Source:   "base64",
        MIMEType: "image/jpeg",
        Base64Data: encodedImage,
    }},
})

if resp.MediaAnalysis != nil {
    for _, result := range resp.MediaAnalysis.Results {
        fmt.Printf("Image %d: safe=%v, hasPII=%v\n",
            result.MediaIndex, result.ContentSafe, result.HasPII)
    }
}
```

### Python

```python
resp = client.proxy_llm_call_with_media(
    query="What's in this image?",
    user_token="user-123",
    request_type="chat",
    media=[MediaContent(
        source="base64",
        mime_type="image/jpeg",
        base64_data=encoded_image,
    )],
)

if resp.media_analysis:
    for result in resp.media_analysis.results:
        print(f"Image {result.media_index}: safe={result.content_safe}, pii={result.has_pii}")
```

### TypeScript

```typescript
const resp = await axonflow.proxyLLMCall({
  query: "What's in this image?",
  userToken: "user-123",
  requestType: "chat",
  media: [{
    source: "base64",
    mimeType: "image/jpeg",
    base64Data: encodedImage,
  }],
});

if (resp.mediaAnalysis) {
  for (const result of resp.mediaAnalysis.results) {
    console.log(`Image ${result.mediaIndex}: safe=${result.contentSafe}, pii=${result.hasPII}`);
  }
}
```

### Java

```java
ClientRequest request = ClientRequest.builder()
    .query("What's in this image?")
    .userToken("user-123")
    .requestType(RequestType.CHAT)
    .media(List.of(MediaContent.builder()
        .source("base64")
        .mimeType("image/jpeg")
        .base64Data(encodedImage)
        .build()))
    .build();

ClientResponse resp = client.proxyLLMCall(request);

if (resp.getMediaAnalysis() != null) {
    for (MediaAnalysisResult result : resp.getMediaAnalysis().getResults()) {
        System.out.printf("Image %d: safe=%b, pii=%b%n",
            result.getMediaIndex(), result.isContentSafe(), result.isHasPII());
    }
}
```

## Media Policy Conditions

Use these fields in dynamic policies to create media governance rules:

| Field | Type | Description |
|-------|------|-------------|
| `media.has_faces` | bool | Faces detected in any image |
| `media.face_count` | int | Total faces across all images |
| `media.has_biometric_data` | bool | Biometric data detected |
| `media.nsfw_score` | float | Highest NSFW score (0-1) |
| `media.violence_score` | float | Highest violence score (0-1) |
| `media.content_safe` | bool | All images pass content safety |
| `media.has_pii` | bool | PII detected via OCR |
| `media.pii_types` | []string | Types of PII found |
| `media.document_type` | string | Classified document type |
| `media.is_sensitive_document` | bool | Sensitive document detected |
| `media.has_extracted_text` | bool | Whether OCR text was extracted |
| `media.extracted_text_length` | int | Length of OCR-extracted text |

### Example Policy: Block Biometric Data

```json
{
  "name": "block-biometric-images",
  "description": "Block images containing biometric data (GDPR Art. 9)",
  "conditions": {
    "media.has_biometric_data": true
  },
  "action": "block",
  "message": "Images containing biometric data are not permitted"
}
```

### Example Policy: Warn on PII

```json
{
  "name": "warn-pii-in-images",
  "description": "Warn when PII is detected in image text",
  "conditions": {
    "media.has_pii": true
  },
  "action": "warn",
  "message": "PII detected in image content"
}
```

## API Reference

### Request: `POST /api/request`

Add `media` array to existing request body:

```json
{
  "query": "Analyze this document",
  "user_token": "user-123",
  "request_type": "chat",
  "media": [
    {
      "source": "base64",
      "mime_type": "image/jpeg",
      "base64_data": "..."
    }
  ]
}
```

### Response

The response includes `media_analysis` when media was submitted:

```json
{
  "success": true,
  "data": "...",
  "media_analysis": {
    "results": [
      {
        "media_index": 0,
        "sha256_hash": "abc123...",
        "content_safe": true,
        "has_pii": false,
        "has_faces": false,
        "estimated_cost_usd": 0.001,
        "warnings": []
      }
    ],
    "total_cost_usd": 0.001,
    "analysis_time_ms": 250
  }
}
```

### Enterprise Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/media/analyzers` | List registered analyzers |
| GET | `/api/v1/media/analyzers/{name}/health` | Check analyzer health |
| POST | `/api/v1/media/analyze` | Standalone media analysis |

## Audit Trail

All media analysis results are recorded in the audit trail:

- **All tiers:** SHA-256 hash, MIME type, file size, PII flags, content safety, warnings
- **Enterprise:** Face detection, biometric flags, NSFW/violence scores, document classification, per-analyzer details
