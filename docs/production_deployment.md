# CloudShield - Production Deployment Guide

## 🚀 Overview

This guide covers deploying **CloudShield** in production environments using Docker, Kubernetes, and cloud platforms. CloudShield is designed for enterprise-grade security monitoring with high availability and scalability.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS, Windows Server
- **Memory**: Minimum 8GB RAM (16GB+ recommended for production)
- **CPU**: 4+ cores recommended
- **Storage**: 50GB+ available disk space
- **Network**: Outbound HTTPS access to SaaS platforms

### Required Software
- **Docker**: Version 20.10+
- **Docker Compose**: Version 2.0+
- **Kubernetes**: Version 1.20+ (for K8s deployment)
- **PostgreSQL**: Version 13+ (if not using containerized)
- **Redis**: Version 6+ (if not using containerized)

## 🐳 Docker Deployment (Recommended)

### Quick Production Deployment

1. **Clone and Configure**
```bash
git clone <repository-url>
cd cloudshield
cp .env.example .env.production
```

2. **Configure Environment Variables**
```bash
# Edit production environment
nano .env.production

# Required production settings:
ENVIRONMENT=production
DEBUG=false
DATABASE_URL=postgresql://user:password@postgres:5432/cloudshield
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-ultra-secure-production-key-here

# OAuth Credentials (obtain from respective platforms)
GOOGLE_CLIENT_ID=your-google-workspace-client-id
GOOGLE_CLIENT_SECRET=your-google-workspace-secret
MICROSOFT_CLIENT_ID=your-microsoft365-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft365-secret
SLACK_CLIENT_ID=your-slack-app-client-id
SLACK_CLIENT_SECRET=your-slack-app-secret
GITHUB_CLIENT_ID=your-github-oauth-app-id
GITHUB_CLIENT_SECRET=your-github-oauth-secret
NOTION_CLIENT_ID=your-notion-integration-id
NOTION_CLIENT_SECRET=your-notion-integration-secret

# Alert Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=alerts@yourcompany.com
SMTP_PASSWORD=your-app-password
```

3. **Deploy with Docker Compose**
```bash
# Production deployment
docker-compose -f docker-compose.yml --env-file .env.production up -d

# Verify deployment
docker-compose ps
docker-compose logs cloudshield-api
```

4. **Initialize Database**
```bash
# Run database migrations
docker-compose exec cloudshield-api alembic upgrade head

# Verify database setup
docker-compose exec postgres psql -U cloudshield_user -d cloudshield -c "\\dt"
```

### Production Docker Compose Configuration

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  cloudshield-api:
    image: cloudshield/api:latest
    restart: unless-stopped
    environment:
      - ENVIRONMENT=production
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - SECRET_KEY=${SECRET_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    volumes:
      - ./logs:/app/logs
      - ./backups:/app/backups

  postgres:
    image: postgres:13
    restart: unless-stopped
    environment:
      POSTGRES_DB: cloudshield
      POSTGRES_USER: cloudshield_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./deployment/init_db.sql:/docker-entrypoint-initdb.d/init.sql
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cloudshield_user -d cloudshield"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  postgres_data:
    driver: local
```

## ☸️ Kubernetes Deployment

### Production Kubernetes Setup

1. **Apply Secrets**
```bash
# Create namespace
kubectl create namespace cloudshield

# Apply secrets (update values in k8s/ingress.yaml first)
kubectl apply -f deployment/k8s/ingress.yaml -n cloudshield
```

2. **Deploy Application**
```bash
# Deploy all components
kubectl apply -f deployment/k8s/ -n cloudshield

# Verify deployment
kubectl get pods -n cloudshield
kubectl get services -n cloudshield
kubectl get ingress -n cloudshield
```

3. **Configure Ingress & SSL**
```bash
# Install cert-manager for SSL certificates
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml

# Create ClusterIssuer for Let's Encrypt
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourcompany.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

### Kubernetes Monitoring & Scaling

```bash
# Monitor pods
kubectl get pods -n cloudshield -w

# Scale components
kubectl scale deployment cloudshield-api --replicas=5 -n cloudshield
kubectl scale deployment cloudshield-worker --replicas=3 -n cloudshield

# View logs
kubectl logs -f deployment/cloudshield-api -n cloudshield
kubectl logs -f deployment/cloudshield-worker -n cloudshield

# Check resource usage
kubectl top pods -n cloudshield
kubectl top nodes
```

## 🌐 Cloud Platform Deployment

### AWS EKS Deployment

1. **Create EKS Cluster**
```bash
# Install eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Create cluster
eksctl create cluster \
  --name cloudshield-cluster \
  --version 1.21 \
  --region us-west-2 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 4 \
  --managed
```

2. **Configure RDS & ElastiCache**
```bash
# Create RDS PostgreSQL instance
aws rds create-db-instance \
  --db-instance-identifier cloudshield-postgres \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username cloudshield \
  --master-user-password YourSecurePassword \
  --allocated-storage 20 \
  --vpc-security-group-ids sg-xxxxxxxx

# Create ElastiCache Redis cluster
aws elasticache create-cache-cluster \
  --cache-cluster-id cloudshield-redis \
  --cache-node-type cache.t3.micro \
  --engine redis \
  --num-cache-nodes 1
```

### Google GKE Deployment

1. **Create GKE Cluster**
```bash
# Create cluster
gcloud container clusters create cloudshield-cluster \
  --zone us-central1-a \
  --machine-type e2-standard-2 \
  --num-nodes 3 \
  --enable-autoscaling \
  --min-nodes 1 \
  --max-nodes 10

# Get credentials
gcloud container clusters get-credentials cloudshield-cluster --zone us-central1-a
```

2. **Configure Cloud SQL & Memorystore**
```bash
# Create Cloud SQL PostgreSQL instance
gcloud sql instances create cloudshield-postgres \
  --database-version=POSTGRES_13 \
  --cpu=1 \
  --memory=3840MB \
  --region=us-central1

# Create Memorystore Redis instance
gcloud redis instances create cloudshield-redis \
  --size=1 \
  --region=us-central1 \
  --redis-version=redis_6_x
```

## 🔧 Production Configuration

### Environment Security

```bash
# Generate secure secrets
openssl rand -hex 32  # For SECRET_KEY
openssl rand -hex 16  # For DATABASE_PASSWORD

# Set proper file permissions
chmod 600 .env.production
chmod 700 deployment/
chmod 600 deployment/k8s/ingress.yaml
```

### Database Optimization

```sql
-- PostgreSQL production tuning
-- /etc/postgresql/13/main/postgresql.conf

shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB
max_connections = 200
random_page_cost = 1.1

-- Enable connection pooling
max_pool_size = 20
min_pool_size = 5
```

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/cloudshield
server {
    listen 80;
    server_name cloudshield.yourcompany.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cloudshield.yourcompany.com;

    ssl_certificate /etc/letsencrypt/live/cloudshield.yourcompany.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloudshield.yourcompany.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # API proxy
    location /api/ {
        proxy_pass http://cloudshield-api:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Frontend
    location / {
        proxy_pass http://cloudshield-frontend:80/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 📊 Monitoring & Observability

### Health Checks

```bash
# API health check
curl -f https://cloudshield.yourcompany.com/health

# Database connectivity
curl -f https://cloudshield.yourcompany.com/health/db

# Redis connectivity  
curl -f https://cloudshield.yourcompany.com/health/redis

# OAuth platform connectivity
curl -f https://cloudshield.yourcompany.com/health/integrations
```

### Logging Configuration

```yaml
# docker-compose.yml logging
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
    labels: "service"
```

### Backup Strategy

```bash
#!/bin/bash
# backup.sh - Database backup script

DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="/app/backups"

# PostgreSQL backup
docker-compose exec postgres pg_dump -U cloudshield_user cloudshield | gzip > "$BACKUP_DIR/cloudshield_db_$DATE.sql.gz"

# Redis backup
docker-compose exec redis redis-cli BGSAVE
docker cp $(docker-compose ps -q redis):/data/dump.rdb "$BACKUP_DIR/redis_$DATE.rdb"

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete
find $BACKUP_DIR -name "*.rdb" -mtime +30 -delete
```

## 🔒 Security Considerations

### SSL/TLS Configuration

```bash
# Generate SSL certificates with Let's Encrypt
certbot --nginx -d cloudshield.yourcompany.com -d api.cloudshield.yourcompany.com

# Auto-renewal cron job
echo "0 3 * * * /usr/bin/certbot renew --quiet" | crontab -
```

### Firewall Configuration

```bash
# UFW firewall rules
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 8000/tcp  # Block direct API access
ufw deny 5432/tcp  # Block direct database access
ufw deny 6379/tcp  # Block direct Redis access
ufw enable
```

### OAuth Security

```bash
# Verify OAuth redirect URIs match deployment
echo "Production OAuth Redirect URIs:"
echo "Google: https://cloudshield.yourcompany.com/auth/google/callback"
echo "Microsoft: https://cloudshield.yourcompany.com/auth/microsoft/callback"
echo "Slack: https://cloudshield.yourcompany.com/auth/slack/callback"
echo "GitHub: https://cloudshield.yourcompany.com/auth/github/callback"
echo "Notion: https://cloudshield.yourcompany.com/auth/notion/callback"
```

## 📈 Performance Optimization

### Database Indexing

```sql
-- Create performance indexes
CREATE INDEX CONCURRENTLY idx_findings_integration_severity ON findings(integration_id, severity);
CREATE INDEX CONCURRENTLY idx_findings_created_at ON findings(created_at DESC);
CREATE INDEX CONCURRENTLY idx_integrations_user_platform ON integrations(user_id, platform);
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM findings WHERE severity = 'critical' ORDER BY created_at DESC LIMIT 10;
```

### Redis Optimization

```bash
# Redis production configuration
echo "maxmemory 512mb" >> /etc/redis/redis.conf
echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf
echo "save 900 1" >> /etc/redis/redis.conf
echo "save 300 10" >> /etc/redis/redis.conf
echo "save 60 10000" >> /etc/redis/redis.conf
```

## 🚨 Troubleshooting

### Common Issues

1. **OAuth Callback Errors**
```bash
# Check redirect URI configuration
docker-compose logs cloudshield-api | grep "oauth"
```

2. **Database Connection Issues**
```bash
# Test database connectivity
docker-compose exec postgres psql -U cloudshield_user -d cloudshield -c "SELECT 1"
```

3. **Redis Connection Issues**
```bash
# Test Redis connectivity
docker-compose exec redis redis-cli ping
```

4. **Celery Worker Issues**
```bash
# Check worker status
docker-compose exec cloudshield-worker celery -A tasks.celery_app inspect active
```

### Log Analysis

```bash
# Centralized log analysis
docker-compose logs --tail=100 -f cloudshield-api
docker-compose logs --tail=100 -f cloudshield-worker

# Error pattern matching
docker-compose logs cloudshield-api | grep -i "error\|exception\|failed"
```

## 📞 Production Support

For production deployment assistance:
- 📧 **Support**: support@cloudshield.com
- 📖 **Documentation**: https://docs.cloudshield.com
- 🐛 **Issues**: https://github.com/cloudshield/cloudshield/issues
- 💬 **Community**: Join our Slack workspace

---

**Developed by Chukwuebuka Tobiloba Nwaizugbe** - Demonstrating Enterprise-Grade DevSecOps and Security Engineering Skills