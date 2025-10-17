# CloudShield - SaaS Security Configuration Analyzer

![CloudShield Logo](docs/assets/cloudshield-logo.png)

**A comprehensive security monitoring platform for SaaS applications with automated scanning, risk assessment, and compliance monitoring.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/release/python-311/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.2.0-blue.svg)](https://reactjs.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## 🚀 Overview

CloudShield is an enterprise-grade SaaS security analyzer that helps organizations identify and remediate security misconfigurations across their cloud services. With support for Google Workspace, Microsoft 365, Slack, GitHub, and Notion, CloudShield provides comprehensive security monitoring and compliance tracking.

### ✨ Key Features

- **🔐 Multi-Platform OAuth Integration** - Secure authentication with 5 major SaaS providers
- **🔍 Automated Security Scanning** - Detect misconfigurations, public shares, inactive users, and compliance violations
- **📊 Advanced Risk Engine** - Contextual risk scoring with industry-specific assessments
- **⚡ Real-time Monitoring** - Background task processing with Celery and Redis
- **📱 Modern Dashboard** - Responsive React interface with comprehensive security insights
- **🔔 Smart Alerting** - Slack webhooks and email notifications for critical findings
- **📈 Compliance Tracking** - GDPR, SOX, HIPAA, and PCI DSS compliance monitoring
- **🐳 Docker Ready** - Complete containerized deployment with docker-compose

## 🏗️ Architecture

CloudShield follows a modern microservices architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React SPA     │    │   FastAPI       │    │   PostgreSQL    │
│   (Frontend)    │◄──►│   (Backend)     │◄──►│   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐    ┌─────────────────┐
         │              │     Celery      │    │     Redis       │
         └──────────────►│   (Tasks)       │◄──►│   (Broker)      │
                        └─────────────────┘    └─────────────────┘
```

### Core Components

- **Backend API**: FastAPI with SQLAlchemy ORM, JWT authentication, and comprehensive REST endpoints
- **Frontend**: Modern React SPA with Tailwind CSS, React Query, and responsive design
- **Task Queue**: Celery workers for background scanning and alert processing
- **Database**: PostgreSQL with proper indexing and relationship management
- **Caching**: Redis for session management and task result storage

## 🛠️ Technology Stack

### Backend
- **FastAPI 0.104.1** - High-performance async Python web framework
- **SQLAlchemy 2.0.23** - Modern ORM with async support
- **Celery 5.3.4** - Distributed task queue for background processing
- **PostgreSQL** - Primary database with advanced querying capabilities
- **Redis** - Task broker and caching layer
- **Pydantic** - Data validation and settings management
- **Alembic** - Database migration management

### Frontend
- **React 18.2.0** - Modern component-based UI framework
- **Vite 4.4.5** - Fast build tool and development server
- **Tailwind CSS 3.3.0** - Utility-first CSS framework
- **React Router 6.16.0** - Client-side routing
- **React Query 4.35.0** - Server state management
- **React Hook Form** - Efficient form handling

### Infrastructure
- **Docker & Docker Compose** - Containerized deployment
- **Nginx** - Reverse proxy and load balancing
- **Gunicorn** - Production WSGI server
- **Flower** - Celery monitoring dashboard

## 📋 Prerequisites

- **Docker Desktop** (recommended) or Docker + Docker Compose
- **Python 3.11+** (for local development)
- **Node.js 18+** (for frontend development)
- **Git** for version control

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/cloudshield.git
cd cloudshield
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your OAuth credentials
nano .env
```

### 3. Deploy with Docker

**Windows:**
```cmd
deploy.bat
```

**Linux/macOS:**
```bash
chmod +x deploy.sh
./deploy.sh
```

**Manual Docker:**
```bash
docker-compose build
docker-compose up -d
```

### 4. Access the Application

- **🌐 Web Dashboard**: http://localhost:3000
- **🔌 API Documentation**: http://localhost:8000/docs
- **📊 Celery Monitor**: http://localhost:5555
- **🗄️ Database**: localhost:5432
- **📡 Redis**: localhost:6379

## 🔧 Configuration

### OAuth Provider Setup

CloudShield requires OAuth applications for each supported provider:

#### Google Workspace
1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create project and enable Workspace Admin SDK API
3. Create OAuth 2.0 credentials with redirect URI: `http://localhost:8000/api/auth/google/callback`

#### Microsoft 365
1. Register app at [Azure Portal](https://portal.azure.com/)
2. Configure Microsoft Graph permissions
3. Set redirect URI: `http://localhost:8000/api/auth/microsoft/callback`

#### GitHub
1. Go to Settings → Developer settings → OAuth Apps
2. Create new app with callback: `http://localhost:8000/api/auth/github/callback`

#### Slack
1. Create app at [Slack API](https://api.slack.com/apps)
2. Add scopes: `users:read`, `channels:read`, `files:read`
3. Set redirect URL: `http://localhost:8000/api/auth/slack/callback`

#### Notion
1. Create integration at [Notion Developers](https://www.notion.so/my-integrations)
2. Set redirect URI: `http://localhost:8000/api/auth/notion/callback`

### Environment Variables

```bash
# Database Configuration
DATABASE_URL=postgresql://cloudshield:password@db:5432/cloudshield

# OAuth Credentials
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
SLACK_CLIENT_ID=your-slack-client-id
SLACK_CLIENT_SECRET=your-slack-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
NOTION_CLIENT_ID=your-notion-client-id
NOTION_CLIENT_SECRET=your-notion-client-secret

# Alert Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SMTP_USERNAME=alerts@company.com
SMTP_PASSWORD=your-app-password
```

## 📊 Features Deep Dive

### Security Scanning

CloudShield performs comprehensive security assessments across multiple dimensions:

#### **Configuration Analysis**
- Permission auditing across all connected services
- Public sharing detection with risk assessment
- Admin privilege monitoring and alerting
- API token and access key validation

#### **User Security Monitoring**
- Inactive user detection with configurable thresholds
- External user access tracking
- Multi-factor authentication compliance
- Suspicious login pattern detection

#### **Compliance Frameworks**
- **GDPR**: Data protection and privacy compliance
- **SOX**: Financial reporting security controls
- **HIPAA**: Healthcare data security requirements
- **PCI DSS**: Payment card industry standards

#### **Risk Assessment Engine**

The advanced risk engine considers multiple factors:

```python
Risk Score = Base Score × Temporal Multiplier × Context Multiplier × Compliance Impact

Where:
- Base Score: Finding type severity (0-100)
- Temporal Multiplier: Time-based risk degradation
- Context Multiplier: Environment-specific factors
- Compliance Impact: Regulatory requirement multipliers
```

### Real-time Monitoring

- **Automated Scanning**: Configurable intervals (6h, 12h, 24h, 48h, weekly)
- **Background Processing**: Non-blocking scan execution with progress tracking
- **Smart Alerting**: Risk-based notification thresholds
- **Audit Logging**: Comprehensive activity tracking

## 🔌 API Reference

### Authentication Endpoints

```bash
# User Registration
POST /api/auth/register
{
  "email": "user@company.com",
  "username": "username", 
  "password": "secure_password"
}

# User Login
POST /api/auth/login
Form Data: {username, password}

# OAuth Initiation
GET /api/auth/{provider}/login
Providers: google, microsoft, slack, github, notion

# OAuth Callback
GET /api/auth/{provider}/callback?code=auth_code
```

### Integration Management

```bash
# List User Integrations
GET /api/integrations
Headers: {Authorization: "Bearer <token>"}

# Delete Integration
DELETE /api/integrations/{integration_id}
Headers: {Authorization: "Bearer <token>"}
```

### Scanning Operations

```bash
# Manual Scan Trigger
POST /api/scan/integration/{integration_id}
Headers: {Authorization: "Bearer <token>"}

# Get Findings
GET /api/scan/findings?page=1&limit=20&risk_level=high
Headers: {Authorization: "Bearer <token>"}

# Security Statistics
GET /api/scan/stats
Headers: {Authorization: "Bearer <token>"}
```

## 🧪 Testing

### Running Tests

```bash
# Backend Tests
docker-compose exec backend pytest src/tests/ -v --cov=src

# Frontend Tests  
docker-compose exec frontend npm test

# Integration Tests
docker-compose exec backend pytest src/tests/test_integration.py -v
```

### Test Coverage

The test suite covers:
- ✅ **API Endpoints**: Authentication, integrations, scanning
- ✅ **Security Scanning**: Provider-specific scan logic
- ✅ **Risk Engine**: Score calculation and risk assessment
- ✅ **Database Models**: Relationship integrity and constraints
- ✅ **OAuth Flows**: Token handling and user authentication

## 📈 Monitoring & Operations

### Production Deployment

```bash
# Production Environment Setup
export NODE_ENV=production
export DEBUG=False
export DATABASE_URL=postgresql://user:pass@prod-db:5432/cloudshield

# SSL Configuration (nginx.conf)
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/cloudshield.crt;
    ssl_certificate_key /etc/ssl/private/cloudshield.key;
}

# Health Check Monitoring
curl -f http://localhost:8000/health
```

### Logging & Debugging

```bash
# Service Logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f celery_worker

# Database Operations
docker-compose exec db psql -U cloudshield -d cloudshield

# Redis Monitoring
docker-compose exec redis redis-cli monitor
```

### Performance Optimization

- **Database**: Indexed queries, connection pooling
- **Caching**: Redis-backed session and result caching
- **Frontend**: Code splitting, lazy loading, CDN assets
- **API**: Response compression, request throttling

## 🔐 Security Considerations

### Production Security Checklist

- [ ] **Strong Secret Keys**: Generate cryptographically secure keys
- [ ] **SSL/TLS**: Enable HTTPS for all communications
- [ ] **Database Security**: Encrypted connections, limited privileges
- [ ] **OAuth Security**: Validate redirect URIs, secure token storage
- [ ] **Rate Limiting**: API endpoint protection
- [ ] **Input Validation**: Comprehensive request sanitization
- [ ] **Audit Logging**: Security event tracking
- [ ] **Container Security**: Non-root users, minimal base images

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Backend Development
cd src/api
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend Development
cd src/frontend
npm install
npm run dev
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **FastAPI** - For the excellent async Python framework
- **React** - For the powerful frontend library
- **Tailwind CSS** - For beautiful, responsive designs
- **Docker** - For seamless containerization
- **The Open Source Community** - For continuous inspiration

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-username/cloudshield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/cloudshield/discussions)

---

**⭐ Star this repository if CloudShield helps secure your SaaS infrastructure!**

Built with ❤️ for the cybersecurity community.
