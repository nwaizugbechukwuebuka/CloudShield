# CloudShield System Architecture

This document provides a comprehensive overview of CloudShield's system architecture, design patterns, and technical decisions.

## System Overview

CloudShield is designed as a modern, scalable SaaS security monitoring platform following microservices principles with clear separation of concerns.

```
                                   ┌─────────────────────────────────────────────────────────┐
                                   │                    Internet                             │
                                   └─────────────────────────────────────────────────────────┘
                                                         │
                                                         │ HTTPS/SSL
                                                         ▼
                                   ┌─────────────────────────────────────────────────────────┐
                                   │                Nginx Reverse Proxy                     │
                                   │          (Load Balancer & SSL Termination)             │
                                   └─────────────────────────────────────────────────────────┘
                                                         │
                         ┌───────────────────────────────┼───────────────────────────────┐
                         │                               │                               │
                         ▼                               ▼                               ▼
           ┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
           │     React Frontend      │     │     FastAPI Backend     │     │     Flower Monitor      │
           │   (Static Assets)       │     │    (REST API Server)    │     │   (Celery Dashboard)    │
           │                         │     │                         │     │                         │
           │ • Component-based UI    │     │ • JWT Authentication    │     │ • Task Monitoring       │
           │ • Responsive Design     │     │ • OAuth Integration     │     │ • Performance Metrics   │
           │ • Real-time Updates     │     │ • API Rate Limiting     │     │ • Worker Management     │
           └─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
                         │                               │
                         │                               │
                         └───────────────┬───────────────┘
                                         │
                                         ▼
                         ┌─────────────────────────────────────────────────────────┐
                         │                   Business Logic Layer                   │
                         │                                                         │
                         │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
                         │  │    OAuth    │  │    Risk     │  │   Scanner   │     │
                         │  │  Services   │  │   Engine    │  │  Framework  │     │
                         │  └─────────────┘  └─────────────┘  └─────────────┘     │
                         └─────────────────────────────────────────────────────────┘
                                         │
                         ┌───────────────┼───────────────┐
                         │               │               │
                         ▼               ▼               ▼
           ┌─────────────────────────┐ ┌─────────────────┐ ┌─────────────────────────┐
           │     PostgreSQL          │ │      Redis      │ │     Celery Workers      │
           │    (Primary DB)         │ │   (Cache/Broker)│ │  (Background Tasks)     │
           │                         │ │                 │ │                         │
           │ • User Data            │ │ • Session Store │ │ • Scheduled Scanning    │
           │ • Integration Configs  │ │ • Task Queue    │ │ • Alert Processing      │
           │ • Security Findings    │ │ • Rate Limiting │ │ • Data Cleanup          │
           │ • Audit Logs          │ │ • Caching Layer │ │ • Report Generation     │
           └─────────────────────────┘ └─────────────────┘ └─────────────────────────┘
```

## Core Components

### 1. Frontend Layer (React SPA)

**Technology Stack:**
- React 18.2.0 with functional components and hooks
- Vite for fast development and optimized builds
- Tailwind CSS for utility-first styling
- React Router for client-side navigation
- React Query for server state management

**Architecture Patterns:**
- **Component Composition**: Reusable UI components with clear props interfaces
- **Custom Hooks**: Business logic abstraction (useAuth, useApi)
- **Context Providers**: Global state management for authentication
- **Lazy Loading**: Code splitting for optimal bundle sizes

**Key Features:**
```javascript
// Authentication Context Pattern
const AuthContext = createContext();
export const useAuth = () => useContext(AuthContext);

// API Integration with React Query
const useFindings = (filters) => {
  return useQuery(['findings', filters], 
    () => api.getFindings(filters),
    { staleTime: 5 * 60 * 1000 }
  );
};
```

### 2. Backend API Layer (FastAPI)

**Technology Stack:**
- FastAPI 0.104.1 with async/await support
- Pydantic for data validation and serialization
- SQLAlchemy 2.0 with async session management
- Alembic for database migrations
- JWT for stateless authentication

**Architecture Patterns:**
- **Dependency Injection**: Database sessions, current user context
- **Repository Pattern**: Data access abstraction
- **Service Layer**: Business logic encapsulation
- **Factory Pattern**: Scanner and OAuth service creation

**Request Flow:**
```python
@router.post("/scan/integration/{integration_id}")
async def trigger_scan(
    integration_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Dependency injection provides user context and DB session
    service = ScanService(db)
    task = await service.initiate_scan(integration_id, current_user.id)
    return {"task_id": task.id, "status": "initiated"}
```

### 3. Background Processing (Celery)

**Technology Stack:**
- Celery 5.3.4 with Redis broker
- Flower for monitoring and management
- Custom task routing and retry policies
- Distributed task execution

**Task Categories:**
- **Scanning Tasks**: OAuth-authenticated API calls to SaaS providers
- **Alert Tasks**: Notification dispatch via Slack/email
- **Cleanup Tasks**: Data retention and maintenance
- **Report Tasks**: Scheduled report generation

**Task Pattern:**
```python
@celery.task(bind=True, max_retries=3)
def scan_integration_task(self, integration_id: str):
    try:
        scanner = ScannerFactory.create(integration_id)
        findings = scanner.scan()
        return {"findings_count": len(findings), "status": "completed"}
    except Exception as exc:
        self.retry(countdown=60 * 2 ** self.request.retries, exc=exc)
```

### 4. Data Layer (PostgreSQL + Redis)

**PostgreSQL Schema Design:**
- **Users**: Authentication and profile data
- **Integrations**: OAuth configurations and connection status
- **Findings**: Security discoveries with rich metadata
- **Audit Logs**: System activity tracking

**Redis Usage Patterns:**
- **Session Storage**: JWT token blacklisting
- **Task Queue**: Celery message broker
- **Rate Limiting**: API endpoint protection
- **Caching**: Expensive query results

## Security Architecture

### Authentication & Authorization

**JWT Token Flow:**
```
1. User Login → FastAPI validates credentials
2. Generate JWT with user claims → Return to client
3. Client stores token → Include in Authorization header
4. FastAPI validates token → Extract user context
5. Dependency injection provides current_user
```

**OAuth Integration:**
```python
class BaseOAuthService:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
    
    async def get_authorization_url(self) -> str:
        # Generate state for CSRF protection
        # Return provider-specific auth URL
    
    async def exchange_code_for_token(self, code: str) -> dict:
        # Exchange auth code for access token
        # Validate and return token data
```

### Data Security

**Encryption at Rest:**
- Database connections use TLS encryption
- Sensitive configuration in environment variables
- OAuth tokens encrypted using Fernet symmetric encryption

**Encryption in Transit:**
- HTTPS/TLS for all client communications
- Secure WebSocket connections for real-time updates
- Provider API calls over HTTPS

## Scanning Architecture

### Scanner Framework

**Base Scanner Pattern:**
```python
class BaseScanner(ABC):
    def __init__(self, integration: Integration):
        self.integration = integration
        self.provider = integration.provider
    
    @abstractmethod
    async def scan(self) -> List[Finding]:
        pass
    
    def create_finding(self, finding_type: FindingType, 
                      title: str, description: str, 
                      metadata: dict = None) -> Finding:
        # Common finding creation logic
        # Risk scoring integration
```

**Provider-Specific Implementations:**
- **GoogleWorkspaceScanner**: Drive API, Admin SDK, Gmail API
- **MicrosoftScanner**: Graph API, Azure AD, SharePoint
- **SlackScanner**: Web API, RTM API, Audit Logs
- **GitHubScanner**: REST API, GraphQL API, Webhooks
- **NotionScanner**: Public API, Database queries

### Risk Assessment Engine

**Multi-Factor Risk Scoring:**
```python
class RiskEngine:
    def calculate_risk_score(self, finding: Finding, context: RiskContext) -> int:
        base_score = self._get_base_risk_score(finding.finding_type)
        temporal_multiplier = self._calculate_temporal_multiplier(finding.created_at)
        context_multiplier = self._calculate_context_multiplier(finding.finding_type, context)
        compliance_impact = self._assess_compliance_impact(finding, context)
        
        final_score = min(100, base_score * temporal_multiplier * context_multiplier * compliance_impact)
        return int(final_score)
```

**Risk Factors:**
- **Base Risk**: Finding type severity (0-100)
- **Temporal**: Time-based risk degradation
- **Contextual**: Environment-specific multipliers
- **Compliance**: Regulatory requirement impact

## Data Flow Architecture

### Request Processing Flow

```
Client Request → Nginx → FastAPI → Authentication Middleware → Route Handler → Service Layer → Repository → Database
                    ↓                                                             ↓
                 Rate Limiting                                                  Cache Layer (Redis)
                    ↓                                                             ↓
                 SSL Termination                                              Task Queue (Celery)
```

### Scanning Data Flow

```
1. User Initiates Scan → FastAPI Endpoint
2. Create Celery Task → Redis Queue
3. Worker Picks Up Task → OAuth API Calls
4. Process Findings → Risk Assessment
5. Store Results → PostgreSQL
6. Send Alerts → Slack/Email
7. Update UI → WebSocket/Polling
```

## Performance Considerations

### Database Optimization

**Indexing Strategy:**
```sql
-- User lookup optimization
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;

-- Finding queries optimization
CREATE INDEX idx_findings_user_risk ON findings(user_id, risk_level);
CREATE INDEX idx_findings_created ON findings(created_at DESC);
CREATE INDEX idx_findings_provider ON findings(provider, finding_type);
```

**Query Optimization:**
- Lazy loading of relationships
- Selective field loading
- Query result pagination
- Database connection pooling

### Caching Strategy

**Multi-Level Caching:**
1. **Application Cache**: In-memory Python objects
2. **Redis Cache**: Cross-request data sharing
3. **Database Cache**: PostgreSQL query plans
4. **CDN Cache**: Static asset delivery

### Scalability Patterns

**Horizontal Scaling:**
- Stateless FastAPI applications
- Multiple Celery worker processes
- Database read replicas
- Redis clustering for high availability

**Vertical Scaling:**
- Async/await for I/O-bound operations
- Connection pooling optimization
- Memory-efficient data structures
- Optimized database queries

## Monitoring & Observability

### Application Metrics

**Performance Monitoring:**
- Request/response latencies
- Database query performance
- Celery task execution times
- Error rates and patterns

**Business Metrics:**
- User registration and activity
- Integration connection success rates
- Security finding discovery rates
- Alert delivery success rates

### Logging Architecture

**Structured Logging:**
```python
import structlog

logger = structlog.get_logger(__name__)

logger.info(
    "scan_completed",
    integration_id=integration.id,
    findings_count=len(findings),
    scan_duration=scan_time,
    user_id=user.id
)
```

**Log Aggregation:**
- Centralized logging with structured data
- Error tracking and alerting
- Performance correlation analysis
- Security event monitoring

## Deployment Architecture

### Container Strategy

**Multi-Stage Docker Builds:**
- Separate build and runtime environments
- Minimal production images
- Layer caching optimization
- Security scanning integration

**Service Orchestration:**
```yaml
# docker-compose.yml architecture
services:
  nginx:      # Reverse proxy & load balancer
  backend:    # FastAPI application server
  frontend:   # React static asset server
  worker:     # Celery background workers
  beat:       # Celery task scheduler
  flower:     # Task monitoring dashboard
  db:         # PostgreSQL database
  redis:      # Cache and message broker
```

### Production Considerations

**High Availability:**
- Multi-instance deployment
- Database clustering
- Redis sentinel for failover
- Health check endpoints

**Security Hardening:**
- Non-root container users
- Network segmentation
- Secrets management
- Regular security updates

## Technology Decisions & Trade-offs

### Framework Choices

**FastAPI vs Django:**
- ✅ **FastAPI**: Better async support, automatic API docs, modern Python features
- ❌ **Django**: More mature ecosystem, built-in admin interface

**React vs Vue.js:**
- ✅ **React**: Larger ecosystem, better TypeScript support, job market demand
- ❌ **Vue.js**: Simpler learning curve, better template syntax

**PostgreSQL vs MongoDB:**
- ✅ **PostgreSQL**: ACID compliance, complex queries, mature tooling
- ❌ **MongoDB**: Schema flexibility, horizontal scaling

### Performance Trade-offs

**Async vs Sync:**
- ✅ **Async**: Better I/O concurrency for API calls
- ❌ **Sync**: Simpler debugging and testing

**Real-time vs Polling:**
- ✅ **Polling**: Simpler implementation, better browser compatibility
- ❌ **WebSockets**: Lower latency, more complex infrastructure

This architecture provides a solid foundation for scalable, secure SaaS security monitoring while maintaining developer productivity and operational simplicity.
