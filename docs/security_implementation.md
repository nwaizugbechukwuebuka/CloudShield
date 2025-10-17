# CloudShield - Security Implementation & Best Practices

## 🔒 Security Architecture Overview

CloudShield implements defense-in-depth security principles with multiple layers of protection, secure coding practices, and comprehensive threat mitigation strategies.

## 🛡️ Authentication & Authorization

### Multi-Factor Authentication Framework
```python
# JWT Token Implementation with Security Features
class SecurityTokenManager:
    def __init__(self):
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        self.refresh_token_expire_days = 7
        
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": str(uuid4()),  # Unique token ID for blacklisting
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=self.algorithm)
        return encoded_jwt
```

### OAuth 2.0 Security Implementation
| Platform | Security Features | Scopes | Validation |
|----------|------------------|--------|------------|
| **Google Workspace** | PKCE + State validation | `https://www.googleapis.com/auth/admin.directory.user.readonly` | Tenant verification |
| **Microsoft 365** | PKCE + State validation | `User.Read.All`, `Files.Read.All` | Tenant isolation |
| **Slack** | State validation | `users:read`, `channels:read`, `files:read` | Workspace verification |
| **GitHub** | State validation | `repo`, `read:org`, `read:user` | App installation check |
| **Notion** | State validation | `read_content` | Workspace permission validation |

### Role-Based Access Control (RBAC)
```python
# Enhanced RBAC Implementation
class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    VIEWER = "viewer"
    INTEGRATION_MANAGER = "integration_manager"

class Permission(str, Enum):
    READ_FINDINGS = "read:findings"
    WRITE_FINDINGS = "write:findings"
    DELETE_FINDINGS = "delete:findings"
    MANAGE_INTEGRATIONS = "manage:integrations"
    MANAGE_USERS = "manage:users"
    VIEW_ADMIN_PANEL = "view:admin_panel"

ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        Permission.READ_FINDINGS,
        Permission.WRITE_FINDINGS,
        Permission.DELETE_FINDINGS,
        Permission.MANAGE_INTEGRATIONS,
        Permission.MANAGE_USERS,
        Permission.VIEW_ADMIN_PANEL
    ],
    UserRole.SECURITY_ANALYST: [
        Permission.READ_FINDINGS,
        Permission.WRITE_FINDINGS,
        Permission.MANAGE_INTEGRATIONS
    ],
    UserRole.VIEWER: [
        Permission.READ_FINDINGS
    ],
    UserRole.INTEGRATION_MANAGER: [
        Permission.READ_FINDINGS,
        Permission.MANAGE_INTEGRATIONS
    ]
}
```

## 🔐 Data Protection & Encryption

### Data Encryption Strategy
```python
# AES-256 Encryption for Sensitive Data
class DataEncryption:
    def __init__(self):
        self.key = self._derive_key_from_settings()
        self.cipher_suite = Fernet(self.key)
    
    def encrypt_oauth_token(self, token_data: dict) -> str:
        """Encrypt OAuth tokens before database storage"""
        token_json = json.dumps(token_data)
        encrypted_token = self.cipher_suite.encrypt(token_json.encode())
        return base64.b64encode(encrypted_token).decode()
    
    def decrypt_oauth_token(self, encrypted_token: str) -> dict:
        """Decrypt OAuth tokens for API calls"""
        encrypted_data = base64.b64decode(encrypted_token.encode())
        decrypted_token = self.cipher_suite.decrypt(encrypted_data)
        return json.loads(decrypted_token.decode())
```

### Database Security Configuration
```sql
-- PostgreSQL Security Settings
-- Enable row-level security
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Create security policies
CREATE POLICY user_data_isolation ON integrations
    FOR ALL TO authenticated_users
    USING (user_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY findings_access_policy ON findings  
    FOR ALL TO authenticated_users
    USING (integration_id IN (
        SELECT id FROM integrations 
        WHERE user_id = current_setting('app.current_user_id')::uuid
    ));

-- Audit logging
CREATE TABLE security_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT NOW(),
    details JSONB
);
```

## 🚨 Input Validation & Sanitization

### Comprehensive Input Validation
```python
# Pydantic Models for Input Validation
class UserRegistration(BaseModel):
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=2, max_length=100, regex=r'^[a-zA-Z\s\-\.]+$')
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Enforce strong password requirements"""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

class FindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    notes: Optional[str] = Field(None, max_length=1000)
    remediation_date: Optional[datetime] = None
    
    @validator('notes')
    def sanitize_notes(cls, v):
        """Sanitize input to prevent XSS"""
        if v:
            return bleach.clean(v, tags=[], attributes={}, strip=True)
        return v
```

### SQL Injection Prevention
```python
# Parameterized Queries with SQLAlchemy
def get_findings_by_severity(db: Session, user_id: UUID, severity: RiskLevel) -> List[Finding]:
    """Secure query with parameterized inputs"""
    return db.query(Finding).join(Integration).filter(
        and_(
            Integration.user_id == user_id,  # Parameterized
            Finding.severity == severity     # Enum validation
        )
    ).order_by(Finding.created_at.desc()).all()

# Input sanitization for search queries
def sanitize_search_input(search_term: str) -> str:
    """Sanitize search input to prevent injection attacks"""
    # Remove SQL special characters
    sanitized = re.sub(r"[';\"\\--/*]", "", search_term)
    # Limit length
    return sanitized[:100]
```

## 🌐 API Security & Rate Limiting

### Rate Limiting Implementation
```python
# Advanced Rate Limiting
class RateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Check if request is within rate limit"""
        current = await self.redis.get(key)
        if current is None:
            await self.redis.setex(key, window, 1)
            return True
        elif int(current) < limit:
            await self.redis.incr(key)
            return True
        else:
            return False

# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    endpoint = request.url.path
    
    # Different limits for different endpoints
    limits = {
        "/auth/login": (5, 300),      # 5 attempts per 5 minutes
        "/auth/register": (3, 3600),  # 3 attempts per hour
        "/api/": (100, 60),           # 100 requests per minute for API
    }
    
    for path_prefix, (limit, window) in limits.items():
        if endpoint.startswith(path_prefix):
            key = f"rate_limit:{client_ip}:{path_prefix}"
            if not await rate_limiter.check_rate_limit(key, limit, window):
                raise HTTPException(
                    status_code=429, 
                    detail="Rate limit exceeded. Please try again later."
                )
            break
    
    response = await call_next(request)
    return response
```

### CORS Security Configuration
```python
# Secure CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cloudshield.yourdomain.com",
        "https://app.cloudshield.com"
    ],  # No wildcards in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Requested-With",
        "X-CSRF-Token"
    ],
    max_age=86400,  # 24 hours
)
```

## 🔍 Security Monitoring & Logging

### Security Event Logging
```python
# Structured Security Logging
class SecurityLogger:
    def __init__(self):
        self.logger = structlog.get_logger("security")
    
    def log_authentication_event(self, user_id: UUID, success: bool, ip: str, user_agent: str):
        """Log authentication attempts"""
        self.logger.info(
            "authentication_attempt",
            user_id=str(user_id),
            success=success,
            ip_address=ip,
            user_agent=user_agent,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_oauth_token_refresh(self, user_id: UUID, platform: str, success: bool):
        """Log OAuth token refresh events"""
        self.logger.info(
            "oauth_token_refresh",
            user_id=str(user_id),
            platform=platform,
            success=success,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def log_suspicious_activity(self, user_id: UUID, activity_type: str, details: dict):
        """Log potentially malicious activities"""
        self.logger.warning(
            "suspicious_activity_detected",
            user_id=str(user_id),
            activity_type=activity_type,
            details=details,
            timestamp=datetime.utcnow().isoformat()
        )
```

### Intrusion Detection
```python
# Anomaly Detection for Security Events
class SecurityAnomalyDetector:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def detect_brute_force(self, ip_address: str) -> bool:
        """Detect brute force login attempts"""
        key = f"failed_logins:{ip_address}"
        failed_attempts = await self.redis.get(key) or 0
        
        if int(failed_attempts) >= 5:
            # Block IP for 1 hour
            await self.redis.setex(f"blocked_ip:{ip_address}", 3600, 1)
            return True
        return False
    
    async def detect_token_abuse(self, user_id: UUID) -> bool:
        """Detect suspicious API token usage patterns"""
        key = f"api_calls:{user_id}"
        calls_last_minute = await self.redis.get(key) or 0
        
        # Alert if more than 200 API calls per minute
        if int(calls_last_minute) > 200:
            security_logger.log_suspicious_activity(
                user_id, 
                "excessive_api_calls", 
                {"calls_per_minute": calls_last_minute}
            )
            return True
        return False
```

## 🔒 OAuth Token Security

### Secure Token Management
```python
# OAuth Token Lifecycle Management
class OAuthTokenManager:
    def __init__(self, encryption_service: DataEncryption):
        self.encryption = encryption_service
    
    async def store_oauth_token(self, user_id: UUID, platform: str, token_data: dict):
        """Securely store OAuth tokens"""
        # Encrypt sensitive data
        encrypted_token = self.encryption.encrypt_oauth_token(token_data)
        
        # Store with metadata
        token_record = OAuthToken(
            user_id=user_id,
            platform=platform,
            encrypted_token=encrypted_token,
            expires_at=self._calculate_expiry(token_data),
            scopes=token_data.get('scope', '').split(','),
            created_at=datetime.utcnow()
        )
        
        await self._save_to_database(token_record)
        
        # Log security event
        security_logger.log_oauth_token_refresh(user_id, platform, True)
    
    async def refresh_token_if_needed(self, integration: Integration):
        """Automatically refresh OAuth tokens before expiry"""
        if self._token_expires_soon(integration.oauth_token):
            try:
                new_token = await self._refresh_oauth_token(integration)
                await self.store_oauth_token(
                    integration.user_id, 
                    integration.platform, 
                    new_token
                )
            except Exception as e:
                security_logger.log_oauth_token_refresh(
                    integration.user_id, 
                    integration.platform, 
                    False
                )
                raise
```

## 🛡️ Security Headers & CSP

### Content Security Policy
```python
# Security Headers Middleware
@app.middleware("http") 
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    
    # Comprehensive security headers
    security_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block", 
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.cloudshield.com; "
            "frame-ancestors 'none';"
        ),
        "X-Permitted-Cross-Domain-Policies": "none"
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response
```

## 🔐 Vulnerability Scanning & Assessment

### Automated Security Scanning
```python
# Security Vulnerability Scanner
class SecurityScanner:
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
    
    async def scan_for_misconfigurations(self, integration: Integration) -> List[SecurityFinding]:
        """Scan for security misconfigurations across platforms"""
        scanner_map = {
            PlatformType.GOOGLE: self._scan_google_workspace,
            PlatformType.MICROSOFT: self._scan_microsoft_365,
            PlatformType.SLACK: self._scan_slack_workspace,
            PlatformType.GITHUB: self._scan_github_organization,
            PlatformType.NOTION: self._scan_notion_workspace
        }
        
        scanner = scanner_map.get(integration.platform)
        if not scanner:
            raise ValueError(f"No scanner available for platform: {integration.platform}")
        
        findings = await scanner(integration)
        
        # Apply risk scoring
        for finding in findings:
            finding.risk_score = self._calculate_risk_score(finding)
            finding.severity = self._determine_severity(finding.risk_score)
        
        return findings
    
    def _calculate_risk_score(self, finding: SecurityFinding) -> int:
        """Calculate contextual risk score"""
        base_score = self.vulnerability_patterns[finding.type]['base_score']
        
        # Apply contextual multipliers
        multipliers = {
            'data_sensitivity': self._assess_data_sensitivity(finding),
            'exposure_scope': self._assess_exposure_scope(finding),
            'exploitability': self._assess_exploitability(finding),
            'business_impact': self._assess_business_impact(finding)
        }
        
        # Calculate weighted score
        weighted_score = base_score
        for factor, multiplier in multipliers.items():
            weighted_score *= multiplier
        
        return min(100, max(0, int(weighted_score)))
```

## 📊 Security Metrics & KPIs

### Security Monitoring Dashboard
```python
# Security Metrics Collection
class SecurityMetrics:
    def __init__(self, db: Session, redis_client):
        self.db = db
        self.redis = redis_client
    
    async def get_security_posture_score(self, user_id: UUID) -> dict:
        """Calculate overall security posture score"""
        findings = self._get_active_findings(user_id)
        
        total_findings = len(findings)
        critical_findings = len([f for f in findings if f.severity == RiskLevel.CRITICAL])
        high_findings = len([f for f in findings if f.severity == RiskLevel.HIGH])
        
        # Calculate posture score (0-100)
        if total_findings == 0:
            posture_score = 100
        else:
            penalty = (critical_findings * 20) + (high_findings * 10)
            posture_score = max(0, 100 - penalty)
        
        return {
            "posture_score": posture_score,
            "total_findings": total_findings,
            "critical_count": critical_findings,
            "high_count": high_findings,
            "trend": self._calculate_trend(user_id)
        }
    
    async def get_compliance_status(self, user_id: UUID) -> dict:
        """Check compliance with security frameworks"""
        compliance_checks = {
            "SOC2": self._check_soc2_compliance(user_id),
            "GDPR": self._check_gdpr_compliance(user_id),
            "HIPAA": self._check_hipaa_compliance(user_id),
            "PCI_DSS": self._check_pci_compliance(user_id)
        }
        
        return {
            framework: {
                "compliant": status["compliant"],
                "score": status["score"],
                "violations": status["violations"]
            }
            for framework, status in compliance_checks.items()
        }
```

## 🚨 Incident Response & Alerting

### Security Incident Response
```python
# Automated Incident Response
class SecurityIncidentHandler:
    def __init__(self, alert_service: AlertService):
        self.alert_service = alert_service
    
    async def handle_critical_finding(self, finding: SecurityFinding):
        """Handle critical security findings with immediate response"""
        # Log incident
        security_logger.log_suspicious_activity(
            finding.integration.user_id,
            "critical_security_finding",
            {
                "finding_id": str(finding.id),
                "type": finding.type,
                "risk_score": finding.risk_score
            }
        )
        
        # Send immediate alerts
        await self.alert_service.send_critical_alert(finding)
        
        # Trigger automated remediation if available
        if finding.auto_fixable:
            await self._attempt_auto_remediation(finding)
    
    async def _attempt_auto_remediation(self, finding: SecurityFinding):
        """Attempt automated remediation for specific finding types"""
        remediation_handlers = {
            "public_file_share": self._revoke_public_access,
            "overpermissive_token": self._revoke_excessive_permissions,
            "inactive_user_access": self._disable_inactive_user
        }
        
        handler = remediation_handlers.get(finding.type)
        if handler:
            try:
                await handler(finding)
                finding.status = FindingStatus.AUTO_RESOLVED
                security_logger.log_security_event(
                    "auto_remediation_success",
                    {"finding_id": str(finding.id)}
                )
            except Exception as e:
                security_logger.log_security_event(
                    "auto_remediation_failed", 
                    {"finding_id": str(finding.id), "error": str(e)}
                )
```

---

**CloudShield implements enterprise-grade security practices ensuring comprehensive protection across all layers**  
**Security Architecture by Chukwuebuka Tobiloba Nwaizugbe**