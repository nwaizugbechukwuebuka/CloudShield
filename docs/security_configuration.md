# CloudShield Security Configuration Guide

## 🔐 Secrets Management

### Supported Backends

CloudShield supports multiple secrets management backends:

1. **AWS Secrets Manager** (Recommended for AWS deployments)
2. **HashiCorp Vault** (Recommended for multi-cloud/on-premise)
3. **Azure Key Vault** (Recommended for Azure deployments)
4. **Local Environment Variables** (Development only)

### Configuration

#### 1. AWS Secrets Manager Setup

```bash
# Install AWS CLI
pip install boto3

# Configure AWS credentials
aws configure

# Create secrets
aws secretsmanager create-secret \
    --name cloudshield/DATABASE_PASSWORD \
    --secret-string "your-secure-password"

aws secretsmanager create-secret \
    --name cloudshield/JWT_SECRET_KEY \
    --secret-string "your-jwt-secret"

aws secretsmanager create-secret \
    --name cloudshield/GOOGLE_OAUTH_CLIENT_SECRET \
    --secret-string "your-oauth-secret"
```

**Environment Variables:**
```env
SECRET_BACKEND=aws_secrets_manager
AWS_REGION=us-east-1
```

#### 2. HashiCorp Vault Setup

```bash
# Start Vault server (development)
vault server -dev

# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='your-vault-token'

# Enable KV v2 secrets engine
vault secrets enable -version=2 -path=secret kv

# Store secrets
vault kv put secret/cloudshield/DATABASE_PASSWORD value="your-secure-password"
vault kv put secret/cloudshield/JWT_SECRET_KEY value="your-jwt-secret"
vault kv put secret/cloudshield/GOOGLE_OAUTH_CLIENT_SECRET value="your-oauth-secret"
```

**Environment Variables:**
```env
SECRET_BACKEND=hashicorp_vault
VAULT_ADDR=http://vault.yourcompany.com:8200
VAULT_TOKEN=your-vault-token
VAULT_MOUNT_POINT=secret
VAULT_SECRET_PATH=cloudshield
```

**Production Vault Setup (Kubernetes):**
```yaml
# vault-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: vault
        image: vault:1.15.0
        env:
        - name: VAULT_ADDR
          value: "http://127.0.0.1:8200"
        - name: VAULT_API_ADDR
          value: "http://vault.vault.svc.cluster.local:8200"
```

#### 3. Azure Key Vault Setup

```bash
# Install Azure CLI
pip install azure-identity azure-keyvault-secrets

# Login to Azure
az login

# Create Key Vault
az keyvault create \
    --name cloudshield-vault \
    --resource-group cloudshield-rg \
    --location eastus

# Store secrets
az keyvault secret set \
    --vault-name cloudshield-vault \
    --name DATABASE-PASSWORD \
    --value "your-secure-password"

az keyvault secret set \
    --vault-name cloudshield-vault \
    --name JWT-SECRET-KEY \
    --value "your-jwt-secret"
```

**Environment Variables:**
```env
SECRET_BACKEND=azure_key_vault
AZURE_KEY_VAULT_URL=https://cloudshield-vault.vault.azure.net/
```

### Usage in Code

```python
from src.api.utils.secrets import get_secret, set_secret, secrets_manager

# Get secrets
database_password = get_secret("DATABASE_PASSWORD")
jwt_secret = get_secret("JWT_SECRET_KEY")
oauth_client_secret = get_secret("GOOGLE_OAUTH_CLIENT_SECRET")

# Set/Rotate secrets
set_secret("NEW_API_KEY", "new-value-here")
secrets_manager.rotate_secret("OLD_API_KEY", "new-rotated-value")

# Clear cache (force refresh)
secrets_manager.clear_cache()
```

---

## 🛡️ Web Application Firewall (WAF)

### ModSecurity Setup with Nginx

#### 1. Install ModSecurity

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y libmodsecurity3 libmodsecurity-dev

# Download OWASP Core Rule Set
cd /etc/nginx
sudo git clone https://github.com/coreruleset/coreruleset.git modsec/coreruleset
cd modsec/coreruleset
sudo mv crs-setup.conf.example crs-setup.conf
```

#### 2. Nginx Configuration

```nginx
# /etc/nginx/nginx.conf
load_module modules/ngx_http_modsecurity_module.so;

http {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
    
    # ... rest of nginx config
}
```

#### 3. ModSecurity Main Config

```nginx
# /etc/nginx/modsec/main.conf
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/coreruleset/crs-setup.conf
Include /etc/nginx/modsec/coreruleset/rules/*.conf
Include /etc/nginx/modsec/waf-rules.conf  # CloudShield custom rules
```

Copy the `deployment/security/waf-rules.conf` file to `/etc/nginx/modsec/waf-rules.conf`.

#### 4. Test Configuration

```bash
# Test Nginx configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

# Monitor WAF logs
tail -f /var/log/modsec_audit.log
```

### AWS WAF Setup (Alternative)

For AWS deployments, use AWS WAF with CloudFront/ALB:

```bash
# Create WAF Web ACL
aws wafv2 create-web-acl \
    --name cloudshield-waf \
    --scope REGIONAL \
    --default-action Block={} \
    --rules file://waf-rules.json

# Associate with ALB
aws wafv2 associate-web-acl \
    --web-acl-arn arn:aws:wafv2:us-east-1:123456789012:regional/webacl/cloudshield-waf/... \
    --resource-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/cloudshield-alb/...
```

**WAF Rules JSON:**
```json
{
  "Name": "SQLInjectionRule",
  "Priority": 1,
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesSQLiRuleSet"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "SQLInjectionRule"
  }
}
```

---

## 🔒 Security Headers Implementation

The security middleware is already implemented in `src/api/middleware/security_middleware.py`. To enable it, update `src/api/main.py`:

```python
from src.api.middleware.security_middleware import setup_security_middleware

app = FastAPI(title="CloudShield API")

# Setup security middleware
setup_security_middleware(app)
```

### Environment Configuration

Add these to `.env`:

```env
# Security Settings
ENABLE_IP_BLOCKING=true
ENABLE_PATTERN_DETECTION=true
RATE_LIMIT_PER_MINUTE=100
AUTH_RATE_LIMIT=10
DEBUG=false
```

---

## 🔑 Secrets Rotation Policy

### Automated Rotation

Create a rotation schedule for critical secrets:

```python
# scripts/rotate_secrets.py
from src.api.utils.secrets import secrets_manager
import secrets
import string

def generate_secure_secret(length=32):
    """Generate cryptographically secure random string"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def rotate_jwt_secret():
    """Rotate JWT secret key"""
    new_secret = generate_secure_secret(64)
    success = secrets_manager.rotate_secret("JWT_SECRET_KEY", new_secret)
    if success:
        print("✓ JWT secret rotated successfully")
    else:
        print("✗ Failed to rotate JWT secret")

def rotate_database_password():
    """Rotate database password"""
    new_password = generate_secure_secret(32)
    
    # 1. Update secret in vault
    secrets_manager.rotate_secret("DATABASE_PASSWORD", new_password)
    
    # 2. Update database user password
    # TODO: Implement database password update
    
    print("✓ Database password rotated")

if __name__ == "__main__":
    rotate_jwt_secret()
    # rotate_database_password()  # Uncomment when database rotation is implemented
```

### Rotation Schedule (Cron)

```bash
# /etc/cron.d/cloudshield-secrets-rotation

# Rotate JWT secret every 90 days
0 0 1 */3 * python /app/scripts/rotate_secrets.py rotate_jwt_secret

# Rotate database password every 180 days
0 0 1 */6 * python /app/scripts/rotate_secrets.py rotate_database_password
```

---

## 📋 Security Compliance Checklist

### Pre-Production Deployment

- [ ] All secrets moved to secure vault (AWS/Vault/Azure)
- [ ] No hardcoded credentials in code
- [ ] WAF rules configured and tested
- [ ] Security headers middleware enabled
- [ ] Rate limiting configured
- [ ] IP blocking enabled for known threats
- [ ] SSL/TLS certificates valid and configured
- [ ] Database connections encrypted
- [ ] OAuth tokens encrypted at rest
- [ ] Audit logging enabled
- [ ] Security monitoring alerts configured

### Ongoing Security Maintenance

- [ ] Quarterly security audits
- [ ] Monthly dependency updates
- [ ] Automated vulnerability scanning (CI/CD)
- [ ] Secret rotation (90-day cycle for critical secrets)
- [ ] WAF rules review and updates
- [ ] Incident response plan tested
- [ ] Security training for team

---

## 🚨 Security Incident Response

### Immediate Response Steps

1. **Detect**: Alert received from monitoring (Sentry, Prometheus, WAF logs)
2. **Assess**: Determine severity and scope
3. **Contain**: Block malicious IPs, disable compromised accounts
4. **Investigate**: Review logs, identify attack vector
5. **Remediate**: Apply fixes, rotate compromised secrets
6. **Document**: Create incident report
7. **Review**: Post-mortem and preventive measures

### Emergency Contacts

```env
SECURITY_TEAM_EMAIL=security@cloudshield.io
ON_CALL_PHONE=+1-555-0123
SECURITY_VENDOR=security-firm@example.com
```

---

## 📚 References

- [OWASP Top 10](https://owasp.org/Top10/)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [HashiCorp Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [ModSecurity Handbook](https://www.feistyduck.com/books/modsecurity-handbook/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
