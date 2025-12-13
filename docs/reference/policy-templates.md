# Policy Templates API

The Policy Templates API enables programmatic access to pre-defined policy templates. Templates provide a starting point for creating policies with configurable variables, reducing the complexity of policy creation.

## Base URL

All endpoints are prefixed with `/api/v1/templates`.

## Authentication

All endpoints require authentication via the `X-Tenant-ID` header. Some endpoints also accept `X-User-ID` for audit tracking.

```
X-Tenant-ID: your-tenant-id
X-User-ID: user-identifier (optional)
```

## Endpoints

### List Templates

Retrieve a paginated list of policy templates with optional filtering.

**Endpoint:** `GET /api/v1/templates`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `category` | string | - | Filter by category (e.g., `security`, `rate_limiting`) |
| `search` | string | - | Search in name, display_name, and description |
| `tags` | string | - | Comma-separated tags to filter by |
| `active` | boolean | true | Filter by active status |
| `builtin` | boolean | - | Filter by builtin status |
| `page` | integer | 1 | Page number |
| `page_size` | integer | 20 | Items per page (max 100) |

**Example Request:**

```bash
curl -X GET "http://localhost:8080/api/v1/templates?category=rate_limiting&page=1&page_size=10" \
  -H "X-Tenant-ID: tenant-123"
```

**Example Response:**

```json
{
  "templates": [
    {
      "id": "general_rate_limiting",
      "name": "general_rate_limiting",
      "display_name": "General Rate Limiting",
      "description": "Basic rate limiting template for API requests",
      "category": "rate_limiting",
      "subcategory": "basic",
      "template": {
        "type": "rate_limit",
        "conditions": [
          {
            "field": "requests",
            "operator": "gt",
            "value": "{{threshold}}"
          }
        ],
        "actions": [
          {
            "type": "rate_limit",
            "config": {
              "limit": "{{threshold}}",
              "window": "{{window_seconds}}"
            }
          }
        ]
      },
      "variables": [
        {
          "name": "threshold",
          "type": "number",
          "required": true,
          "default": 100,
          "description": "Maximum requests allowed"
        },
        {
          "name": "window_seconds",
          "type": "number",
          "required": false,
          "default": 60,
          "description": "Time window in seconds"
        }
      ],
      "is_builtin": true,
      "is_active": true,
      "version": "1.0",
      "tags": ["rate-limiting", "security"],
      "created_at": "2025-01-15T10:00:00Z",
      "updated_at": "2025-01-15T10:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 10,
    "total_items": 1,
    "total_pages": 1
  }
}
```

### Get Template

Retrieve a single template by its ID.

**Endpoint:** `GET /api/v1/templates/{id}`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template identifier |

**Example Request:**

```bash
curl -X GET "http://localhost:8080/api/v1/templates/general_rate_limiting" \
  -H "X-Tenant-ID: tenant-123"
```

**Example Response:**

```json
{
  "template": {
    "id": "general_rate_limiting",
    "name": "general_rate_limiting",
    "display_name": "General Rate Limiting",
    "description": "Basic rate limiting template for API requests",
    "category": "rate_limiting",
    "template": { ... },
    "variables": [ ... ],
    "is_builtin": true,
    "is_active": true,
    "version": "1.0",
    "tags": ["rate-limiting", "security"],
    "created_at": "2025-01-15T10:00:00Z",
    "updated_at": "2025-01-15T10:00:00Z"
  }
}
```

### Apply Template

Create a new policy from a template by providing variable values.

**Endpoint:** `POST /api/v1/templates/{id}/apply`

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Template identifier |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy_name` | string | Yes | Name for the new policy (3-100 chars) |
| `description` | string | No | Policy description (max 500 chars) |
| `variables` | object | Yes | Key-value pairs for template variables |
| `enabled` | boolean | No | Whether the policy is enabled (default: false) |
| `priority` | integer | No | Policy priority (overrides template default) |

**Example Request:**

```bash
curl -X POST "http://localhost:8080/api/v1/templates/general_rate_limiting/apply" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -H "X-User-ID: user-456" \
  -d '{
    "policy_name": "API Rate Limit - Production",
    "description": "Rate limiting for production API endpoints",
    "variables": {
      "threshold": 1000,
      "window_seconds": 60
    },
    "enabled": true,
    "priority": 75
  }'
```

**Example Response:**

```json
{
  "success": true,
  "policy": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "API Rate Limit - Production",
    "description": "Rate limiting for production API endpoints",
    "type": "rate_limit",
    "conditions": [
      {
        "field": "requests",
        "operator": "gt",
        "value": 1000
      }
    ],
    "actions": [
      {
        "type": "rate_limit",
        "config": {
          "limit": 1000,
          "window": 60
        }
      }
    ],
    "priority": 75,
    "enabled": true,
    "tenant_id": "tenant-123",
    "created_by": "user-456",
    "created_at": "2025-01-15T12:00:00Z",
    "updated_at": "2025-01-15T12:00:00Z"
  },
  "usage_id": "660e8400-e29b-41d4-a716-446655440001",
  "message": "Successfully created policy 'API Rate Limit - Production' from template 'general_rate_limiting'"
}
```

### Get Categories

Retrieve all available template categories.

**Endpoint:** `GET /api/v1/templates/categories`

**Example Request:**

```bash
curl -X GET "http://localhost:8080/api/v1/templates/categories" \
  -H "X-Tenant-ID: tenant-123"
```

**Example Response:**

```json
{
  "categories": [
    "general",
    "security",
    "compliance",
    "content_safety",
    "rate_limiting",
    "access_control",
    "data_protection",
    "custom"
  ]
}
```

### Get Usage Statistics

Retrieve template usage statistics for your tenant.

**Endpoint:** `GET /api/v1/templates/stats`

**Example Request:**

```bash
curl -X GET "http://localhost:8080/api/v1/templates/stats" \
  -H "X-Tenant-ID: tenant-123"
```

**Example Response:**

```json
{
  "stats": [
    {
      "template_id": "general_rate_limiting",
      "template_name": "general_rate_limiting",
      "usage_count": 15,
      "last_used_at": "2025-01-15T11:30:00Z"
    },
    {
      "template_id": "general_content_filter",
      "template_name": "general_content_filter",
      "usage_count": 8,
      "last_used_at": "2025-01-14T16:45:00Z"
    }
  ]
}
```

## Error Responses

All error responses follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": []
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `NOT_FOUND` | 404 | Template not found |
| `UNAUTHORIZED` | 401 | Missing or invalid tenant ID |
| `METHOD_NOT_ALLOWED` | 405 | HTTP method not supported |
| `INVALID_JSON` | 400 | Request body is not valid JSON |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `INTERNAL_ERROR` | 500 | Internal server error |

### Validation Error Example

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "policy_name",
        "message": "Policy name must be between 3 and 100 characters"
      },
      {
        "field": "variables.threshold",
        "message": "Required variable 'threshold' is missing"
      }
    ]
  }
}
```

## Template Variables

Template variables use the `{{variable_name}}` syntax within the template JSON. Variables support:

- **Type preservation**: When a variable is the entire value (e.g., `"value": "{{threshold}}"`), the original type is preserved (number, boolean, array)
- **String interpolation**: When embedded in strings (e.g., `"message": "Limit: {{threshold}} requests"`), variables are converted to strings
- **Default values**: Variables can have default values that are used when not provided
- **Validation patterns**: Variables can specify regex patterns for validation

### Variable Types

| Type | Description | Example |
|------|-------------|---------|
| `string` | Text value | `"api-key"` |
| `number` | Numeric value | `100` |
| `boolean` | True/false | `true` |
| `array` | List of values | `["a", "b", "c"]` |

## CORS Support

All endpoints support CORS with the following headers:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-Tenant-ID, X-User-ID
```

Preflight requests (`OPTIONS`) return `200 OK` with the appropriate CORS headers.
