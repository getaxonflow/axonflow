# AxonFlow Policy API - OpenAPI Specification

This directory contains the OpenAPI 3.0 specification for the AxonFlow Policy Management API.

## Files

| File | Description |
|------|-------------|
| `policy-api.yaml` | Complete OpenAPI 3.0 specification |

## API Overview

The Policy API provides programmatic access to:

- **Policy CRUD** - Create, read, update, and delete policies
- **Policy Testing** - Test policies against sample inputs
- **Version History** - Track policy changes for audit
- **Import/Export** - Bulk policy operations
- **Templates** - Pre-built policy templates for common use cases

## Quick Start

### Authentication

All endpoints require tenant identification via headers:

```bash
curl -H "X-Tenant-ID: your-tenant-id" \
     -H "X-User-ID: user@example.com" \
     https://api.getaxonflow.com/api/v1/policies
```

### List Policies

```bash
curl -X GET "https://api.getaxonflow.com/api/v1/policies" \
  -H "X-Tenant-ID: tenant-123"
```

### Create a Policy

```bash
curl -X POST "https://api.getaxonflow.com/api/v1/policies" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -H "X-User-ID: admin@company.com" \
  -d '{
    "name": "Block PII Access",
    "description": "Prevent unauthorized access to PII",
    "type": "content",
    "conditions": [
      {
        "field": "query",
        "operator": "contains_any",
        "value": ["ssn", "social security", "credit card"]
      }
    ],
    "actions": [
      {
        "type": "block",
        "config": {
          "message": "Access to PII is restricted"
        }
      }
    ],
    "priority": 100,
    "enabled": true
  }'
```

### Test a Policy

```bash
curl -X POST "https://api.getaxonflow.com/api/v1/policies/pol_abc123def456/test" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -d '{
    "query": "Show me the customer SSN",
    "user": {
      "email": "analyst@company.com",
      "role": "analyst"
    }
  }'
```

## Viewing Interactive Documentation

### Online

Visit [docs.getaxonflow.com/api](https://docs.getaxonflow.com/api) for interactive API documentation.

> **Note:** The hosted documentation is planned for a future release. For now, use the local options below.

### Local with Swagger UI

```bash
# Using Docker
docker run -p 8080:8080 \
  -e SWAGGER_JSON=/spec/policy-api.yaml \
  -v $(pwd):/spec \
  swaggerapi/swagger-ui

# Open http://localhost:8080
```

### Local with Redoc

```bash
# Install redoc-cli
npm install -g @redocly/cli

# Preview
redocly preview-docs policy-api.yaml

# Or generate static HTML
redocly build-docs policy-api.yaml -o api-docs.html
```

## Generating Client Libraries

Use OpenAPI Generator to create client libraries:

```bash
# Install OpenAPI Generator
npm install -g @openapitools/openapi-generator-cli

# TypeScript/JavaScript
openapi-generator-cli generate \
  -i policy-api.yaml \
  -g typescript-fetch \
  -o ./clients/typescript

# Python
openapi-generator-cli generate \
  -i policy-api.yaml \
  -g python \
  -o ./clients/python

# Go
openapi-generator-cli generate \
  -i policy-api.yaml \
  -g go \
  -o ./clients/go

# Java
openapi-generator-cli generate \
  -i policy-api.yaml \
  -g java \
  -o ./clients/java
```

## Validation

Validate the specification using swagger-cli:

```bash
# Install
npm install -g @apidevtools/swagger-cli

# Validate
swagger-cli validate policy-api.yaml
```

Or use Spectral for linting:

```bash
# Install
npm install -g @stoplight/spectral-cli

# Lint
spectral lint policy-api.yaml
```

## API Endpoints

### Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/policies` | List policies |
| POST | `/api/v1/policies` | Create a policy |
| GET | `/api/v1/policies/{id}` | Get a policy |
| PUT | `/api/v1/policies/{id}` | Update a policy |
| DELETE | `/api/v1/policies/{id}` | Delete a policy |
| POST | `/api/v1/policies/{id}/test` | Test a policy |
| GET | `/api/v1/policies/{id}/versions` | Get version history |

### Bulk Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/policies/import` | Import policies |
| GET | `/api/v1/policies/export` | Export policies |

### Templates

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/templates` | List templates |
| GET | `/api/v1/templates/{id}` | Get a template |
| POST | `/api/v1/templates/{id}/apply` | Apply a template |
| GET | `/api/v1/templates/categories` | List categories |
| GET | `/api/v1/templates/stats` | Usage statistics |

## Error Handling

All errors follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "name",
        "message": "Name must be between 3 and 100 characters"
      }
    ]
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid tenant ID |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `INTERNAL_ERROR` | 500 | Internal server error |

## Rate Limits

> **Note:** Rate limits may vary by deployment type (SaaS vs In-VPC). Contact your administrator for specific limits.

Default rate limits for SaaS deployments:

- **Standard endpoints**: 1000 requests/minute per tenant
- **Bulk operations** (import/export): 10 requests/minute per tenant
- **Test endpoint**: 100 requests/minute per tenant

Rate limit headers are included in responses when limits are enforced:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1699459200
```

## Contributing

When updating the OpenAPI specification:

1. Make changes to `policy-api.yaml`
2. Validate: `swagger-cli validate policy-api.yaml`
3. Lint: `spectral lint policy-api.yaml`
4. Update this README if adding new endpoints
5. Submit a PR with the changes

## Resources

- [OpenAPI 3.0 Specification](https://spec.openapis.org/oas/v3.0.3)
- [Swagger UI](https://swagger.io/tools/swagger-ui/)
- [OpenAPI Generator](https://openapi-generator.tech/)
- [Spectral Linting](https://stoplight.io/open-source/spectral)
