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
4. Results are aggregated and evaluated against media policies
5. Request proceeds (Community: fail-open with warnings) or is blocked (Enterprise: configurable)

## Community Features

All tiers include:
- Image type/size/dimension validation
- Local OCR via Tesseract for text extraction
- PII detection on extracted text (reuses existing PII pipeline)
- SHA-256 hash stored in audit trail
- Aggregate cost estimation
- Fail-open enforcement (warnings logged, never blocks)

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
