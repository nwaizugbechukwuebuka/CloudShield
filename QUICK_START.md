# CloudShield Quick Start Guide

## 🚀 Getting Started

This guide will help you get CloudShield running locally in under 10 minutes.

---

## Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15
- Redis 7
- Docker & Docker Compose (recommended)

---

## Option 1: Docker Compose (Recommended)

The fastest way to get CloudShield running:

```bash
# Clone the repository
git clone https://github.com/your-org/cloudshield.git
cd cloudshield

# Create .env file
cp .env.example .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Access the application
# Frontend: http://localhost:3000
# API: http://localhost:8000
# API Docs: http://localhost:8000/docs
# Grafana: http://localhost:3001 (admin/admin)
# Prometheus: http://localhost:9090
```

That's it! CloudShield is now running.

---

## Option 2: Local Development Setup

### Step 1: Database Setup

```bash
# Start PostgreSQL
# Windows (PowerShell):
docker run -d --name cloudshield-postgres `
  -e POSTGRES_USER=cloudshield `
  -e POSTGRES_PASSWORD=cloudshield `
  -e POSTGRES_DB=cloudshield `
  -p 5432:5432 postgres:15

# Linux/Mac:
docker run -d --name cloudshield-postgres \
  -e POSTGRES_USER=cloudshield \
  -e POSTGRES_PASSWORD=cloudshield \
  -e POSTGRES_DB=cloudshield \
  -p 5432:5432 postgres:15

# Start Redis
docker run -d --name cloudshield-redis -p 6379:6379 redis:7
```

### Step 2: Backend Setup

```bash
# Navigate to project root
cd cloudshield

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Edit .env with your configuration
# Required variables:
#   DATABASE_URL=postgresql://cloudshield:cloudshield@localhost:5432/cloudshield
#   REDIS_URL=redis://localhost:6379/0
#   SECRET_KEY=your-secret-key-change-this

# Run database migrations
alembic upgrade head

# Start backend server
cd src/api
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# API is now running at http://localhost:8000
```

### Step 3: Frontend Setup

```bash
# Open a new terminal
cd cloudshield/src/frontend

# Install dependencies
npm install

# Start development server
npm run dev

# Frontend is now running at http://localhost:3000
```

### Step 4: Celery Workers (Optional)

```bash
# Open a new terminal
cd cloudshield
source venv/bin/activate  # or .\venv\Scripts\activate on Windows

# Start Celery worker
celery -A src.tasks worker --loglevel=info

# Start Celery beat (for scheduled tasks)
celery -A src.tasks beat --loglevel=info
```

---

## 🔑 Initial Setup

### Create Admin User

```bash
# Using Python shell
python -c "
from src.api.database import SessionLocal
from src.api.models.user import User
from src.api.utils.auth import get_password_hash

db = SessionLocal()
admin = User(
    email='admin@cloudshield.com',
    hashed_password=get_password_hash('Admin123!'),
    is_active=True,
    role='admin'
)
db.add(admin)
db.commit()
print('Admin user created: admin@cloudshield.com / Admin123!')
"
```

Or use the API:

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@cloudshield.com",
    "password": "Admin123!",
    "full_name": "Admin User"
  }'
```

---

## 🧪 Testing

### Run Backend Tests

```bash
# Activate virtual environment
source venv/bin/activate  # or .\venv\Scripts\activate

# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_auth.py

# View coverage report
# Open htmlcov/index.html in browser
```

### Run Frontend Tests

```bash
cd src/frontend

# Run tests
npm test

# Run with coverage
npm test -- --coverage
```

### Load Testing

```bash
# Install Locust
pip install locust

# Run load test
locust -f tests/load/locustfile.py --host=http://localhost:8000

# Open browser to http://localhost:8089
# Configure users and spawn rate, then start test
```

---

## 📖 API Documentation

Once the backend is running, access interactive API documentation:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

Or import the Postman collection:
- `docs/CloudShield_API.postman_collection.json`

---

## 🔧 Common Tasks

### Add OAuth Integration

1. Register your application with the provider (Google, Microsoft, etc.)
2. Get OAuth credentials (Client ID, Client Secret)
3. Add to `.env`:
   ```env
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback
   ```
4. Restart the backend

### Run Security Scan

```bash
# Via API
curl -X POST http://localhost:8000/scans \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "integration_id": 1,
    "scan_type": "full"
  }'

# Or via frontend at http://localhost:3000/scans
```

### View Monitoring Dashboards

```bash
# Start monitoring stack (if using Docker Compose)
docker-compose --profile monitoring up -d

# Access dashboards:
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3001 (admin/admin)
```

Import Grafana dashboard from: `deployment/monitoring/grafana-dashboard.json`

---

## 🐛 Troubleshooting

### Database Connection Error

```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# View PostgreSQL logs
docker logs cloudshield-postgres

# Test connection
psql postgresql://cloudshield:cloudshield@localhost:5432/cloudshield
```

### Redis Connection Error

```bash
# Check if Redis is running
docker ps | grep redis

# Test connection
redis-cli ping
# Should return: PONG
```

### Import Errors

```bash
# Make sure you're in the correct directory
cd cloudshield

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Port Already in Use

```bash
# Windows - Find process using port 8000:
netstat -ano | findstr :8000

# Kill process:
taskkill /PID <PID> /F

# Linux/Mac - Find and kill process:
lsof -ti:8000 | xargs kill -9
```

---

## 📚 Next Steps

1. **Read the Documentation**
   - `docs/api_documentation.md` - API reference
   - `docs/security_configuration.md` - Security setup
   - `docs/production_optimization.md` - Performance tuning

2. **Configure Integrations**
   - Set up OAuth credentials for Google Workspace, Microsoft 365, etc.
   - Test security scans

3. **Customize**
   - Modify scan rules in `src/scanner/`
   - Customize alerting thresholds
   - Add custom risk scoring logic

4. **Deploy to Production**
   - Follow `docs/deployment_guide.md`
   - Configure secrets management (Vault/AWS/Azure)
   - Set up monitoring and alerting
   - Run load tests

---

## 🆘 Getting Help

- **Documentation:** `/docs` directory
- **API Issues:** Check `logs/cloudshield.log`
- **GitHub Issues:** https://github.com/your-org/cloudshield/issues
- **Security Issues:** security@cloudshield.com

---

## 🔐 Security Note

**Never commit `.env` files or secrets to Git!**

The `.env.example` file shows required variables. Create your own `.env` file with actual values.

For production, use a secrets manager:
- AWS Secrets Manager
- HashiCorp Vault  
- Azure Key Vault

See `docs/security_configuration.md` for details.

---

## 📋 Environment Variables Reference

### Required
```env
DATABASE_URL=postgresql://user:password@localhost:5432/cloudshield
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=generate-a-secure-random-key
```

### Optional (Development)
```env
DEBUG=true
FRONTEND_URL=http://localhost:3000
SMTP_HOST=localhost
SMTP_PORT=1025  # MailHog for testing
```

### Optional (OAuth)
```env
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
SLACK_CLIENT_ID=your-slack-client-id
SLACK_CLIENT_SECRET=your-slack-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### Optional (Monitoring)
```env
SENTRY_DSN=your-sentry-dsn
```

---

**Happy Coding!** 🎉

For more detailed information, see `DEPLOYMENT_SUMMARY.md` and the `/docs` directory.
