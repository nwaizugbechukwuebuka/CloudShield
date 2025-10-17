# CloudShield API Reference

This document provides comprehensive API documentation for CloudShield's REST API endpoints.

## Base URL

```
http://localhost:8000/api
```

## Authentication

CloudShield uses JWT (JSON Web Tokens) for API authentication. Include the token in the `Authorization` header:

```
Authorization: Bearer <your_jwt_token>
```

## Rate Limiting

- **General API**: 100 requests per minute per IP
- **Authentication**: 10 requests per minute per IP
- **Scanning**: 20 requests per minute per user

## Response Format

All API responses follow a consistent format:

```json
{
  "success": true,
  "data": { /* Response data */ },
  "message": "Operation completed successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

Error responses include additional error details:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": { /* Specific error information */ }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Endpoints

### Authentication

#### POST /auth/register

Register a new user account.

**Request Body:**
```json
{
  "email": "user@company.com",
  "username": "johndoe",
  "password": "secure_password123"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@company.com",
    "username": "johndoe",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

#### POST /auth/login

Authenticate user and receive access token.

**Request Body (Form Data):**
```
username=user@company.com&password=secure_password123
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

#### GET /auth/me

Get current user information.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@company.com",
    "username": "johndoe",
    "is_active": true,
    "is_superuser": false,
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

#### GET /auth/{provider}/login

Initiate OAuth flow for supported providers.

**Providers:** `google`, `microsoft`, `slack`, `github`, `notion`

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "auth_url": "https://accounts.google.com/oauth/authorize?client_id=...",
    "state": "random_state_string"
  }
}
```

#### GET /auth/{provider}/callback

Handle OAuth callback (called automatically by provider).

**Query Parameters:**
- `code`: Authorization code from provider
- `state`: State parameter for CSRF protection

### Integrations

#### GET /integrations

List all user integrations.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "provider": "google",
      "status": "active",
      "config": {
        "account_name": "company@gmail.com",
        "permissions": ["drive.readonly", "admin.directory.user.readonly"]
      },
      "last_scan": "2024-01-15T09:00:00Z",
      "next_scan": "2024-01-16T09:00:00Z",
      "scan_count": 15,
      "findings_count": 8,
      "risk_score": 65,
      "created_at": "2024-01-01T10:00:00Z"
    }
  ]
}
```

#### DELETE /integrations/{integration_id}

Remove an integration.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (204 No Content)**

### Scanning

#### POST /scan/integration/{integration_id}

Trigger manual scan for specific integration.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (202 Accepted):**
```json
{
  "success": true,
  "data": {
    "task_id": "scan_550e8400-e29b-41d4-a716-446655440001",
    "status": "pending",
    "message": "Scan initiated successfully"
  }
}
```

#### GET /scan/findings

Retrieve security findings with filtering and pagination.

**Headers:**
```
Authorization: Bearer <token>
```

**Query Parameters:**
- `page` (int, default=1): Page number
- `limit` (int, default=20): Results per page
- `risk_level` (enum): Filter by risk level (`low`, `medium`, `high`, `critical`)
- `provider` (enum): Filter by provider (`google`, `microsoft`, `slack`, `github`, `notion`)
- `finding_type` (enum): Filter by type (`misconfiguration`, `inactive_user`, `public_share`, `overprivileged_token`, `suspicious_activity`, `compliance_violation`)

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "findings": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440002",
        "title": "Public Google Drive Folder Detected",
        "description": "A Google Drive folder is publicly accessible without restrictions",
        "finding_type": "public_share",
        "risk_level": "high",
        "risk_score": 85,
        "provider": "google",
        "resource_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
        "metadata": {
          "folder_name": "Company Documents",
          "file_count": 25,
          "external_shares": 5
        },
        "remediation": "Review folder permissions and restrict public access",
        "created_at": "2024-01-15T08:30:00Z",
        "integration": {
          "id": "550e8400-e29b-41d4-a716-446655440001",
          "provider": "google"
        }
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 45,
      "pages": 3
    }
  }
}
```

#### GET /scan/stats

Get security statistics and metrics.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "total_findings": 45,
    "critical_count": 3,
    "high_count": 12,
    "medium_count": 18,
    "low_count": 12,
    "resolved_count": 8,
    "integrations_count": 4,
    "last_scan": "2024-01-15T09:00:00Z",
    "risk_trend": "improving",
    "compliance_score": 78
  }
}
```

#### GET /scan/task/{task_id}

Get status of a background scan task.

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "task_id": "scan_550e8400-e29b-41d4-a716-446655440001",
    "status": "completed",
    "progress": 100,
    "result": {
      "findings_discovered": 5,
      "scan_duration": 45.2,
      "errors": []
    },
    "started_at": "2024-01-15T10:00:00Z",
    "completed_at": "2024-01-15T10:00:45Z"
  }
}
```

### Health and System

#### GET /health

System health check endpoint.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "celery": "healthy"
  }
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `AUTHENTICATION_REQUIRED` | 401 | Missing or invalid token |
| `PERMISSION_DENIED` | 403 | Insufficient permissions |
| `RESOURCE_NOT_FOUND` | 404 | Requested resource not found |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server internal error |
| `SERVICE_UNAVAILABLE` | 503 | External service unavailable |

## Data Models

### User
```json
{
  "id": "uuid",
  "email": "string",
  "username": "string", 
  "is_active": "boolean",
  "is_superuser": "boolean",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### Integration
```json
{
  "id": "uuid",
  "provider": "enum[google|microsoft|slack|github|notion]",
  "status": "enum[active|inactive|error|pending]",
  "config": "object",
  "last_scan": "datetime|null",
  "next_scan": "datetime|null",
  "scan_count": "integer",
  "findings_count": "integer",
  "risk_score": "integer",
  "error_message": "string|null",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### Finding
```json
{
  "id": "uuid",
  "title": "string",
  "description": "string",
  "finding_type": "enum[misconfiguration|inactive_user|public_share|overprivileged_token|suspicious_activity|compliance_violation]",
  "risk_level": "enum[low|medium|high|critical]",
  "risk_score": "integer",
  "provider": "string",
  "resource_id": "string",
  "metadata": "object",
  "remediation": "string|null",
  "resolved": "boolean",
  "resolved_at": "datetime|null",
  "created_at": "datetime"
}
```

## SDK Examples

### Python SDK

```python
import requests

class CloudShieldAPI:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {'Authorization': f'Bearer {token}'}
    
    def get_findings(self, page=1, risk_level=None):
        params = {'page': page}
        if risk_level:
            params['risk_level'] = risk_level
        
        response = requests.get(
            f'{self.base_url}/scan/findings',
            headers=self.headers,
            params=params
        )
        return response.json()
    
    def trigger_scan(self, integration_id):
        response = requests.post(
            f'{self.base_url}/scan/integration/{integration_id}',
            headers=self.headers
        )
        return response.json()

# Usage
api = CloudShieldAPI('http://localhost:8000/api', 'your_token_here')
findings = api.get_findings(risk_level='high')
```

### JavaScript SDK

```javascript
class CloudShieldAPI {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl;
    this.headers = {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    };
  }

  async getFindings(page = 1, riskLevel = null) {
    const params = new URLSearchParams({ page });
    if (riskLevel) params.append('risk_level', riskLevel);

    const response = await fetch(
      `${this.baseUrl}/scan/findings?${params}`,
      { headers: this.headers }
    );
    return response.json();
  }

  async triggerScan(integrationId) {
    const response = await fetch(
      `${this.baseUrl}/scan/integration/${integrationId}`,
      { method: 'POST', headers: this.headers }
    );
    return response.json();
  }
}

// Usage
const api = new CloudShieldAPI('http://localhost:8000/api', 'your_token_here');
const findings = await api.getFindings(1, 'high');
```

## Rate Limit Headers

API responses include rate limit information:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 85
X-RateLimit-Reset: 1642248000
```
