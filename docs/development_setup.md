# CloudShield Development Setup

This guide will help you set up CloudShield for development on your local machine.

## Prerequisites

- Docker Desktop (Windows/Mac) or Docker + Docker Compose (Linux)
- Git
- Code editor (VS Code recommended)

## Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd cloudshield

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment Variables

Edit `.env` file with your OAuth credentials:

```bash
# Required: OAuth Configuration
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

# Optional: Alert Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SMTP_USERNAME=your-email@example.com
SMTP_PASSWORD=your-app-password
```

### 3. Deploy with Docker

**Windows:**
```cmd
deploy.bat
```

**Linux/Mac:**
```bash
chmod +x deploy.sh
./deploy.sh
```

**Manual Docker Commands:**
```bash
docker-compose build
docker-compose up -d
docker-compose exec backend python -m alembic upgrade head
```

### 4. Access the Application

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs
- **Flower (Celery Monitor):** http://localhost:5555

## OAuth Setup Guide

### Google Workspace

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google Workspace Admin SDK API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Set authorized redirect URI: `http://localhost:8000/api/auth/google/callback`

### Microsoft 365

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" → "App registrations"
3. Create new registration
4. Add redirect URI: `http://localhost:8000/api/auth/microsoft/callback`
5. Grant necessary Microsoft Graph permissions

### Slack

1. Go to [Slack API](https://api.slack.com/apps)
2. Create new app
3. Configure OAuth & Permissions
4. Add redirect URL: `http://localhost:8000/api/auth/slack/callback`
5. Add required scopes: `users:read`, `channels:read`, `files:read`

### GitHub

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create new OAuth app
3. Set callback URL: `http://localhost:8000/api/auth/github/callback`

### Notion

1. Go to [Notion Developers](https://www.notion.so/my-integrations)
2. Create new integration
3. Set redirect URI: `http://localhost:8000/api/auth/notion/callback`

## Development Workflow

### Backend Development

```bash
# View backend logs
docker-compose logs -f backend

# Run backend commands
docker-compose exec backend bash
docker-compose exec backend python -c "from src.api.database import create_tables; create_tables()"

# Run tests
docker-compose exec backend pytest src/tests/ -v

# Database migrations
docker-compose exec backend alembic revision --autogenerate -m "Add new table"
docker-compose exec backend alembic upgrade head
```

### Frontend Development

```bash
# View frontend logs
docker-compose logs -f frontend

# Install new packages
docker-compose exec frontend npm install package-name

# Run frontend tests
docker-compose exec frontend npm test

# Build for production
docker-compose exec frontend npm run build
```

### Celery Tasks

```bash
# Monitor Celery workers
docker-compose logs -f celery_worker

# Monitor Celery beat scheduler
docker-compose logs -f celery_beat

# Access Flower UI
# Visit http://localhost:5555
```

## Database Management

### PostgreSQL

```bash
# Connect to database
docker-compose exec db psql -U cloudshield -d cloudshield

# Backup database
docker-compose exec db pg_dump -U cloudshield cloudshield > backup.sql

# Restore database
docker-compose exec -T db psql -U cloudshield -d cloudshield < backup.sql

# Reset database
docker-compose down -v
docker-compose up -d
```

## Troubleshooting

### Common Issues

1. **Port conflicts**
   ```bash
   # Check what's using the ports
   netstat -tulpn | grep :3000
   netstat -tulpn | grep :8000
   
   # Kill processes or change ports in docker-compose.yml
   ```

2. **Database connection issues**
   ```bash
   # Restart database
   docker-compose restart db
   
   # Check database logs
   docker-compose logs db
   ```

3. **OAuth callback errors**
   - Ensure redirect URIs match exactly in OAuth provider settings
   - Check that `CORS_ORIGINS` includes your frontend URL
   - Verify OAuth credentials are correct

4. **Celery not processing tasks**
   ```bash
   # Restart Celery services
   docker-compose restart celery_worker celery_beat
   
   # Check Redis connection
   docker-compose exec redis redis-cli ping
   ```

### Logs and Debugging

```bash
# View all service logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f celery_worker

# Follow logs in real-time
docker-compose logs -f --tail=100
```

## Production Deployment

For production deployment:

1. Use proper SSL certificates
2. Set `DEBUG=False` in environment
3. Use strong `SECRET_KEY`
4. Configure proper database connection
5. Set up monitoring and logging
6. Use environment-specific OAuth URLs

## Testing

```bash
# Run all tests
docker-compose exec backend pytest

# Run with coverage
docker-compose exec backend pytest --cov=src

# Run specific tests
docker-compose exec backend pytest src/tests/test_auth.py -v

# Run frontend tests
docker-compose exec frontend npm test
```

## API Usage Examples

### Authentication

```bash
# Login
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# OAuth redirect
curl "http://localhost:8000/api/auth/google/login"
```

### Integrations

```bash
# List integrations
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/integrations/"

# Start scan
curl -X POST -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8000/api/scan/integration/INTEGRATION_ID"
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

## Support

For issues and questions:
- Check logs first: `docker-compose logs -f`
- Review this documentation
- Create GitHub issue with full error details