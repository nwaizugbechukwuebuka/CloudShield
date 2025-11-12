# CloudShield API Documentation

## Overview

CloudShield provides a comprehensive RESTful API for SaaS security configuration analysis. This document covers authentication, endpoints, request/response formats, and integration examples.

**Base URL:** `https://api.cloudshield.io/v1`  
**Authentication:** JWT Bearer Token  
**API Version:** 1.0.0

---

## Table of Contents

1. [Authentication](#authentication)
2. [User Management](#user-management)
3. [Integrations](#integrations)
4. [Security Scanning](#security-scanning)
5. [Findings](#findings)
6. [Alerts](#alerts)
7. [Dashboard](#dashboard)
8. [Error Handling](#error-handling)
9. [Rate Limiting](#rate-limiting)
10. [Webhooks](#webhooks)

---

## Authentication

### Register New User

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}
```

**Response:** `201 Created`
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "viewer",
  "is_active": true,
  "is_verified": false,
  "created_at": "2025-01-15T10:30:00Z"
}
```

### Login

**Endpoint:** `POST /auth/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Refresh Token

**Endpoint:** `POST /auth/refresh`

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

---

## Integrations

### List All Integrations

**Endpoint:** `GET /integrations`

**Headers:**
```
Authorization: Bearer {access_token}
```

**Query Parameters:**
- `platform` (optional): Filter by platform (google_workspace, microsoft_365, slack, github, notion)
- `status` (optional): Filter by status (active, inactive, error)

**Response:** `200 OK`
```json
{
  "integrations": [
    {
      "id": 1,
      "platform": "google_workspace",
      "name": "Acme Corp Workspace",
      "status": "active",
      "connected_at": "2025-01-10T14:20:00Z",
      "last_scan": "2025-01-15T09:00:00Z",
      "findings_count": 45,
      "critical_findings": 3
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 20
}
```

### Connect New Integration

**Endpoint:** `POST /integrations/connect/{platform}`

**Path Parameters:**
- `platform`: google_workspace | microsoft_365 | slack | github | notion

**Response:** `200 OK`
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...",
  "state": "random_state_token_for_csrf_protection"
}
```

### Get Integration Details

**Endpoint:** `GET /integrations/{integration_id}`

**Response:** `200 OK`
```json
{
  "id": 1,
  "platform": "google_workspace",
  "name": "Acme Corp Workspace",
  "status": "active",
  "connected_at": "2025-01-10T14:20:00Z",
  "last_scan": "2025-01-15T09:00:00Z",
  "configuration": {
    "domain": "acme.com",
    "user_count": 250,
    "admin_count": 5
  },
  "scan_frequency_hours": 24,
  "next_scan_at": "2025-01-16T09:00:00Z"
}
```

### Delete Integration

**Endpoint:** `DELETE /integrations/{integration_id}`

**Response:** `204 No Content`

---

## Security Scanning

### Initiate Scan

**Endpoint:** `POST /scans/start`

**Request Body:**
```json
{
  "integration_id": 1,
  "scan_type": "full",
  "platforms": ["google_workspace"],
  "options": {
    "deep_scan": true,
    "compliance_frameworks": ["SOC2", "GDPR"]
  }
}
```

**Response:** `202 Accepted`
```json
{
  "scan_id": "scan_abc123def456",
  "status": "queued",
  "integration_id": 1,
  "platform": "google_workspace",
  "started_at": "2025-01-15T10:45:00Z",
  "estimated_duration_minutes": 5
}
```

### Get Scan Status

**Endpoint:** `GET /scans/{scan_id}`

**Response:** `200 OK`
```json
{
  "scan_id": "scan_abc123def456",
  "status": "in_progress",
  "progress_percentage": 45,
  "current_step": "Scanning OneDrive files",
  "findings_detected": 12,
  "started_at": "2025-01-15T10:45:00Z",
  "estimated_completion": "2025-01-15T10:50:00Z"
}
```

### List Scans

**Endpoint:** `GET /scans`

**Query Parameters:**
- `integration_id` (optional): Filter by integration
- `status` (optional): Filter by status
- `limit`: Number of results (default: 20, max: 100)
- `offset`: Pagination offset

**Response:** `200 OK`
```json
{
  "scans": [
    {
      "scan_id": "scan_abc123def456",
      "integration_id": 1,
      "platform": "google_workspace",
      "status": "completed",
      "findings_count": 47,
      "critical_count": 3,
      "high_count": 12,
      "medium_count": 22,
      "low_count": 10,
      "started_at": "2025-01-15T10:45:00Z",
      "completed_at": "2025-01-15T10:52:00Z",
      "duration_seconds": 420
    }
  ],
  "total": 156,
  "page": 1,
  "per_page": 20
}
```

---

## Findings

### List Findings

**Endpoint:** `GET /findings`

**Query Parameters:**
- `integration_id` (optional): Filter by integration
- `risk_level` (optional): critical | high | medium | low
- `status` (optional): open | in_progress | resolved | ignored | false_positive
- `finding_type` (optional): See finding types below
- `limit`: Number of results (default: 20, max: 100)
- `offset`: Pagination offset

**Finding Types:**
- `misconfiguration`
- `inactive_user`
- `public_share`
- `overpermissive_token`
- `weak_password_policy`
- `mfa_disabled`
- `excessive_permissions`
- `external_sharing`
- `unencrypted_data`
- `outdated_software`

**Response:** `200 OK`
```json
{
  "findings": [
    {
      "id": 123,
      "title": "MFA Disabled for Admin User",
      "description": "Administrator account does not have multi-factor authentication enabled",
      "type": "mfa_disabled",
      "risk_level": "critical",
      "risk_score": 95.0,
      "status": "open",
      "integration": {
        "id": 1,
        "platform": "google_workspace",
        "name": "Acme Corp Workspace"
      },
      "resource": {
        "id": "user_12345",
        "name": "admin@acme.com",
        "type": "user"
      },
      "evidence": {
        "is_admin": true,
        "last_login": "2025-01-14T08:30:00Z",
        "login_methods": ["password"]
      },
      "remediation_steps": "1. Navigate to Admin Console\\n2. Select the user\\n3. Enable 2-Step Verification",
      "first_seen_at": "2025-01-15T10:52:00Z",
      "last_seen_at": "2025-01-15T10:52:00Z",
      "occurrence_count": 1
    }
  ],
  "total": 47,
  "page": 1,
  "per_page": 20,
  "statistics": {
    "critical": 3,
    "high": 12,
    "medium": 22,
    "low": 10
  }
}
```

### Get Finding Details

**Endpoint:** `GET /findings/{finding_id}`

**Response:** `200 OK`
```json
{
  "id": 123,
  "title": "MFA Disabled for Admin User",
  "description": "Administrator account does not have multi-factor authentication enabled",
  "type": "mfa_disabled",
  "risk_level": "critical",
  "risk_score": 95.0,
  "status": "open",
  "integration": {
    "id": 1,
    "platform": "google_workspace",
    "name": "Acme Corp Workspace"
  },
  "resource": {
    "id": "user_12345",
    "name": "admin@acme.com",
    "type": "user"
  },
  "evidence": {
    "is_admin": true,
    "last_login": "2025-01-14T08:30:00Z",
    "login_methods": ["password"],
    "account_created": "2023-06-15T09:00:00Z"
  },
  "remediation_steps": "1. Navigate to Admin Console\\n2. Select the user\\n3. Enable 2-Step Verification",
  "remediation_priority": 9,
  "compliance_impact": {
    "SOC2": "CC6.1 - Logical and Physical Access Controls",
    "GDPR": "Article 32 - Security of Processing",
    "HIPAA": "164.312(a)(2)(i) - Unique User Identification"
  },
  "first_seen_at": "2025-01-15T10:52:00Z",
  "last_seen_at": "2025-01-15T10:52:00Z",
  "occurrence_count": 1,
  "history": [
    {
      "timestamp": "2025-01-15T10:52:00Z",
      "action": "detected",
      "user": "system"
    }
  ]
}
```

### Update Finding Status

**Endpoint:** `PATCH /findings/{finding_id}`

**Request Body:**
```json
{
  "status": "resolved",
  "resolution_notes": "MFA has been enabled for this user account"
}
```

**Response:** `200 OK`
```json
{
  "id": 123,
  "status": "resolved",
  "resolved_at": "2025-01-15T14:30:00Z",
  "resolved_by": "john.doe@acme.com",
  "resolution_notes": "MFA has been enabled for this user account"
}
```

---

## Alerts

### Configure Alert Rules

**Endpoint:** `POST /alerts/rules`

**Request Body:**
```json
{
  "name": "Critical Findings Alert",
  "enabled": true,
  "conditions": {
    "risk_level": ["critical"],
    "finding_types": ["mfa_disabled", "public_share"]
  },
  "channels": [
    {
      "type": "email",
      "recipients": ["security@acme.com"]
    },
    {
      "type": "slack",
      "webhook_url": "https://hooks.slack.com/services/..."
    }
  ],
  "throttle_minutes": 60
}
```

**Response:** `201 Created`
```json
{
  "id": 1,
  "name": "Critical Findings Alert",
  "enabled": true,
  "created_at": "2025-01-15T11:00:00Z"
}
```

### List Alert History

**Endpoint:** `GET /alerts`

**Query Parameters:**
- `severity` (optional): info | warning | error | critical
- `status` (optional): sent | failed | pending
- `limit`: Number of results
- `offset`: Pagination offset

**Response:** `200 OK`
```json
{
  "alerts": [
    {
      "id": 456,
      "rule_id": 1,
      "severity": "critical",
      "title": "Critical Security Finding Detected",
      "message": "MFA Disabled for Admin User: admin@acme.com",
      "channels_sent": ["email", "slack"],
      "status": "sent",
      "created_at": "2025-01-15T10:53:00Z",
      "sent_at": "2025-01-15T10:53:15Z",
      "finding_id": 123
    }
  ],
  "total": 89,
  "page": 1,
  "per_page": 20
}
```

---

## Dashboard

### Get Security Overview

**Endpoint:** `GET /dashboard/overview`

**Response:** `200 OK`
```json
{
  "summary": {
    "total_integrations": 5,
    "active_integrations": 5,
    "total_findings": 234,
    "open_findings": 187,
    "critical_findings": 12,
    "high_findings": 45,
    "medium_findings": 89,
    "low_findings": 41
  },
  "risk_score": {
    "current": 72,
    "trend": "improving",
    "change_percentage": -5.2
  },
  "recent_scans": [
    {
      "scan_id": "scan_abc123",
      "platform": "google_workspace",
      "completed_at": "2025-01-15T10:52:00Z",
      "findings": 47
    }
  ],
  "compliance_status": {
    "SOC2": {
      "compliant_controls": 18,
      "total_controls": 23,
      "percentage": 78.3
    },
    "GDPR": {
      "compliant_controls": 15,
      "total_controls": 20,
      "percentage": 75.0
    }
  }
}
```

### Get Risk Trends

**Endpoint:** `GET /dashboard/risk-trends`

**Query Parameters:**
- `period`: 7d | 30d | 90d | 1y
- `granularity`: day | week | month

**Response:** `200 OK`
```json
{
  "period": "30d",
  "data_points": [
    {
      "date": "2024-12-16",
      "risk_score": 78,
      "findings": {
        "critical": 15,
        "high": 52,
        "medium": 98,
        "low": 45
      }
    },
    {
      "date": "2024-12-23",
      "risk_score": 75,
      "findings": {
        "critical": 14,
        "high": 48,
        "medium": 95,
        "low": 43
      }
    }
  ]
}
```

---

## Error Handling

All API errors follow a consistent format:

**Error Response:**
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or expired token",
    "details": {
      "token_expired_at": "2025-01-15T09:00:00Z"
    },
    "request_id": "req_xyz789",
    "timestamp": "2025-01-15T11:30:00Z"
  }
}
```

### HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `202 Accepted` - Request accepted for processing
- `204 No Content` - Successful deletion
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

### Error Codes

- `VALIDATION_ERROR` - Request validation failed
- `UNAUTHORIZED` - Authentication required
- `FORBIDDEN` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `RATE_LIMIT_EXCEEDED` - Too many requests
- `INTEGRATION_ERROR` - External service error
- `SCAN_ERROR` - Scanning operation failed
- `INTERNAL_ERROR` - Internal server error

---

## Rate Limiting

API requests are rate-limited to ensure fair usage:

- **Default Limit:** 100 requests per minute per IP
- **Authenticated Limit:** 500 requests per minute per user
- **Burst Limit:** 20 requests per second

**Rate Limit Headers:**
```
X-RateLimit-Limit: 500
X-RateLimit-Remaining: 485
X-RateLimit-Reset: 1705318200
```

When rate limit is exceeded:
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Please try again later.",
    "retry_after": 60
  }
}
```

---

## Webhooks

Configure webhooks to receive real-time notifications:

### Create Webhook

**Endpoint:** `POST /webhooks`

**Request Body:**
```json
{
  "url": "https://your-app.com/webhooks/cloudshield",
  "events": ["finding.created", "scan.completed", "integration.connected"],
  "secret": "your_webhook_secret_for_verification"
}
```

### Webhook Events

- `finding.created` - New security finding detected
- `finding.updated` - Finding status changed
- `scan.started` - Security scan initiated
- `scan.completed` - Security scan finished
- `scan.failed` - Security scan encountered error
- `integration.connected` - New integration added
- `integration.disconnected` - Integration removed
- `alert.triggered` - Security alert sent

### Webhook Payload Example

```json
{
  "event": "finding.created",
  "timestamp": "2025-01-15T10:52:00Z",
  "data": {
    "finding_id": 123,
    "type": "mfa_disabled",
    "risk_level": "critical",
    "integration_id": 1,
    "platform": "google_workspace"
  },
  "signature": "sha256=abc123..."
}
```

---

## Code Examples

### Python

```python
import requests

# Authentication
response = requests.post(
    'https://api.cloudshield.io/v1/auth/login',
    json={
        'email': 'user@example.com',
        'password': 'SecurePassword123!'
    }
)
token = response.json()['access_token']

# List findings
headers = {'Authorization': f'Bearer {token}'}
findings = requests.get(
    'https://api.cloudshield.io/v1/findings',
    headers=headers,
    params={'risk_level': 'critical'}
)

print(findings.json())
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

const API_BASE = 'https://api.cloudshield.io/v1';

// Authentication
const login = async () => {
  const response = await axios.post(`${API_BASE}/auth/login`, {
    email: 'user@example.com',
    password: 'SecurePassword123!'
  });
  return response.data.access_token;
};

// Get findings
const getFindings = async (token) => {
  const response = await axios.get(`${API_BASE}/findings`, {
    headers: { Authorization: `Bearer ${token}` },
    params: { risk_level: 'critical' }
  });
  return response.data;
};
```

### cURL

```bash
# Login
curl -X POST https://api.cloudshield.io/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePassword123!"}'

# Get findings
curl -X GET "https://api.cloudshield.io/v1/findings?risk_level=critical" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## Support

For API support:
- **Email:** api-support@cloudshield.io
- **Documentation:** https://docs.cloudshield.io
- **Status Page:** https://status.cloudshield.io
- **Community:** https://community.cloudshield.io

**API Status:** All systems operational ✅
