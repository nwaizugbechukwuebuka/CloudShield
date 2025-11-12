# CloudShield Production Optimization & Deployment Guide

## 🎯 Overview

This guide covers production-ready optimizations, error handling enhancements, and deployment best practices for CloudShield.

---

## 🔧 Production Optimizations Implemented

### 1. Resilience Patterns

#### Retry Logic with Exponential Backoff
```python
from src.api.utils.resilience import retry_with_backoff, timeout

@retry_with_backoff(max_retries=3, base_delay=1.0, exceptions=(ConnectionError,))
@timeout(30.0)
async def fetch_user_data(integration_id: str):
    """
    Automatically retries on connection errors with exponential backoff
    Times out after 30 seconds
    """
    # Your implementation
    pass
```

**Configuration:**
- `max_retries`: 3 attempts (default)
- `base_delay`: 1 second initial delay
- `max_delay`: 60 seconds maximum
- `exponential_base`: 2.0 (doubles each retry)

#### Circuit Breaker Pattern
```python
from src.api.utils.resilience import CircuitBreaker

# Create circuit breaker for external APIs
google_api_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60,
    expected_exception=Exception,
    name="google_workspace_api"
)

async def call_google_api():
    async def _call():
        # Your API call
        pass
    
    return await google_api_breaker.call_async(_call)
```

**When circuit opens:**
- After 5 consecutive failures
- Rejects all requests for 60 seconds
- Attempts recovery (half-open state)
- Closes circuit if recovery successful

#### Graceful Degradation
```python
from src.api.utils.resilience import GracefulDegradation

def get_dashboard_stats():
    with GracefulDegradation(fallback_value={"stats": []}) as gd:
        # Attempt to fetch from cache
        stats = fetch_from_cache()
    
    # Returns fallback if fetch fails
    return gd.get_value(default={"stats": []})
```

### 2. Database Query Optimization

#### Query Performance Monitoring
```python
from src.api.utils.db_optimization import setup_query_monitoring, query_monitor

# In database initialization
setup_query_monitoring(engine)

# View slow queries
slow_queries = query_monitor.get_slow_queries()
for query in slow_queries:
    print(f"Query: {query['query']}")
    print(f"Avg Time: {query['avg_time']:.3f}s")
    print(f"Slow Count: {query['slow_count']}")
```

#### Query Analysis and Recommendations
```python
from src.api.utils.db_optimization import QueryOptimizer

optimizer = QueryOptimizer()

# Analyze specific query
analysis = optimizer.analyze_query(
    db,
    "SELECT * FROM findings WHERE user_id = 123 AND risk_level = 'critical'"
)

print("Execution Time:", analysis['execution_time_ms'], "ms")
print("Recommendations:", analysis['recommendations'])

# Get index suggestions
suggestions = optimizer.suggest_indexes(db, "findings")
```

#### Efficient Pagination
```python
from src.api.utils.db_optimization import QueryPatterns

# Instead of loading all records
query = db.query(Finding).filter(Finding.user_id == user_id)

# Use efficient pagination
result = QueryPatterns.paginate_efficiently(query, page=1, page_size=20)
# Returns: items, total, page, page_size, total_pages
```

#### Bulk Operations
```python
from src.api.utils.db_optimization import QueryPatterns

# Bulk insert (much faster than individual inserts)
findings = [
    {"title": "Finding 1", "risk_level": "high"},
    {"title": "Finding 2", "risk_level": "medium"},
    # ... thousands of records
]

QueryPatterns.bulk_insert_optimized(db, Finding, findings)

# Bulk update
updates = [
    {"id": 1, "status": "resolved"},
    {"id": 2, "status": "acknowledged"},
    # ... many updates
]

QueryPatterns.bulk_update_optimized(db, Finding, updates)
```

### 3. Connection Pool Optimization

**Recommended settings for production:**

```python
# src/api/database.py
from sqlalchemy import create_engine

engine = create_engine(
    DATABASE_URL,
    # Connection pool settings
    pool_size=20,              # Base number of connections
    max_overflow=10,           # Additional connections when pool exhausted
    pool_recycle=3600,         # Recycle connections after 1 hour
    pool_pre_ping=True,        # Test connection before use
    pool_timeout=30,           # Wait 30s for connection
    echo=False,                # Disable SQL echo in production
    
    # Performance tuning
    connect_args={
        "connect_timeout": 10,
        "application_name": "cloudshield",
        "options": "-c statement_timeout=30000"  # 30s query timeout
    }
)
```

### 4. Caching Strategy

#### Redis Caching Implementation
```python
import redis
from functools import wraps
import json

redis_client = redis.Redis(
    host='localhost',
    port=6379,
    db=0,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5
)

def cache_result(ttl: int = 300):  # 5 minutes default
    """Decorator to cache function results in Redis"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Try to get from cache
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
            
            # Execute function
            result = await func(*args, **kwargs)
            
            # Store in cache
            redis_client.setex(cache_key, ttl, json.dumps(result))
            
            return result
        return wrapper
    return decorator

# Usage
@cache_result(ttl=600)  # Cache for 10 minutes
async def get_integration_statistics(user_id: int):
    # Expensive database query
    pass
```

#### Cache Invalidation
```python
def invalidate_cache(pattern: str):
    """Invalidate cache entries matching pattern"""
    for key in redis_client.scan_iter(match=pattern):
        redis_client.delete(key)

# Example: Invalidate user's cache when data changes
invalidate_cache(f"get_integration_statistics:{user_id}:*")
```

---

## 📊 Performance Monitoring

### Key Metrics to Track

1. **API Response Times**
   - P50, P95, P99 latencies
   - Endpoint-specific metrics
   - Alert threshold: P95 > 2s

2. **Database Performance**
   - Query execution time
   - Connection pool usage
   - Slow query count
   - Alert threshold: > 10 slow queries/min

3. **Scan Performance**
   - Scan duration by integration type
   - Concurrent scans
   - Finding detection rate
   - Alert threshold: > 5 min/scan

4. **Error Rates**
   - 4xx vs 5xx errors
   - Circuit breaker state changes
   - Alert threshold: > 5% error rate

5. **Infrastructure**
   - CPU usage
   - Memory usage
   - Disk I/O
   - Network throughput

### Grafana Dashboard Queries

```promql
# Average API response time
rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])

# Slow query rate
rate(db_slow_queries_total[5m])

# Circuit breaker state
circuit_breaker_state{name="external_api"}

# Error rate
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))
```

---

## 🚀 Deployment Checklist

### Pre-Deployment

- [ ] All environment variables configured in secrets manager
- [ ] Database migrations tested and ready
- [ ] Connection pool settings optimized
- [ ] Caching layer configured (Redis)
- [ ] Rate limiting enabled
- [ ] Security middleware activated
- [ ] Monitoring dashboards created
- [ ] Alert rules configured
- [ ] Load testing completed successfully
- [ ] Security audit passed
- [ ] Backup strategy in place
- [ ] Rollback plan documented

### Database Optimizations

```sql
-- Add indexes for frequently queried columns
CREATE INDEX idx_findings_user_id ON findings(user_id);
CREATE INDEX idx_findings_risk_level ON findings(risk_level);
CREATE INDEX idx_findings_created_at ON findings(created_at DESC);
CREATE INDEX idx_findings_status ON findings(status);

-- Composite indexes for common query patterns
CREATE INDEX idx_findings_user_risk ON findings(user_id, risk_level);
CREATE INDEX idx_findings_user_status ON findings(user_id, status);

-- Indexes for integrations
CREATE INDEX idx_integrations_user_id ON integrations(user_id);
CREATE INDEX idx_integrations_type ON integrations(integration_type);
CREATE INDEX idx_integrations_user_type ON integrations(user_id, integration_type);

-- Indexes for scans
CREATE INDEX idx_scans_integration_id ON scans(integration_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);

-- Indexes for alerts
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);

-- Analyze tables for query planner
ANALYZE findings;
ANALYZE integrations;
ANALYZE scans;
ANALYZE alerts;
```

### PostgreSQL Configuration (`postgresql.conf`)

```ini
# Connection settings
max_connections = 200
superuser_reserved_connections = 3

# Memory settings (for 16GB RAM server)
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
work_mem = 52MB

# Checkpoint settings
checkpoint_completion_target = 0.9
wal_buffers = 16MB
min_wal_size = 1GB
max_wal_size = 4GB

# Query planner
random_page_cost = 1.1  # For SSD
effective_io_concurrency = 200

# Logging
log_min_duration_statement = 1000  # Log queries > 1s
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_checkpoints = on
log_connections = on
log_disconnections = on
log_duration = off
log_lock_waits = on

# Autovacuum
autovacuum = on
autovacuum_max_workers = 3
autovacuum_naptime = 10s
```

### Application Configuration

**Environment Variables (.env.production):**
```env
# Application
APP_NAME=CloudShield Security Analyzer
APP_VERSION=1.0.0
DEBUG=false
ENVIRONMENT=production

# Security
SECRET_KEY=<use secrets manager>
JWT_SECRET_KEY=<use secrets manager>
ENABLE_IP_BLOCKING=true
ENABLE_PATTERN_DETECTION=true
RATE_LIMIT_PER_MINUTE=100
AUTH_RATE_LIMIT=10

# Database
DATABASE_URL=postgresql://user:pass@postgres:5432/cloudshield
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10
DB_POOL_RECYCLE=3600
DB_POOL_PRE_PING=true

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_MAX_CONNECTIONS=50

# Secrets Management
SECRET_BACKEND=hashicorp_vault  # or aws_secrets_manager
VAULT_ADDR=https://vault.yourcompany.com:8200
VAULT_SECRET_PATH=cloudshield

# Monitoring
SENTRY_DSN=<your-sentry-dsn>
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.1

# CORS
BACKEND_CORS_ORIGINS=["https://app.cloudshield.com"]

# Email
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USE_TLS=true
FROM_EMAIL=noreply@cloudshield.com
```

---

## 🔄 Graceful Shutdown

```python
# src/api/main.py
import signal
import sys

shutdown_event = asyncio.Event()

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Shutdown signal received, cleaning up...")
    shutdown_event.set()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

@app.on_event("shutdown")
async def graceful_shutdown():
    """Graceful shutdown handler"""
    logger.info("Starting graceful shutdown...")
    
    # Wait for ongoing requests to complete (max 30s)
    await asyncio.sleep(5)
    
    # Close database connections
    await database.disconnect()
    logger.info("Database connections closed")
    
    # Close Redis connections
    redis_client.close()
    logger.info("Redis connections closed")
    
    # Flush logs
    logging.shutdown()
    
    logger.info("Graceful shutdown completed")
```

---

## 📈 Performance Benchmarks

### Target Metrics

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| API Response Time (P95) | < 500ms | < 2s |
| API Response Time (P99) | < 1s | < 5s |
| Database Query Time (P95) | < 100ms | < 500ms |
| Scan Completion Time | < 2 min | < 5 min |
| Error Rate | < 1% | < 5% |
| CPU Usage | < 70% | < 90% |
| Memory Usage | < 80% | < 95% |
| Connection Pool Usage | < 80% | < 95% |

### Load Testing Results

Run load tests before production:
```bash
# Locust load test
locust -f tests/load/locustfile.py --host=https://api.cloudshield.com

# K6 load test
k6 run tests/load/k6-load-test.js
```

**Expected Results:**
- 100 concurrent users: < 500ms avg response time
- 1000 concurrent users: < 1s avg response time
- Error rate: < 1%
- No circuit breakers triggered under normal load

---

## 🛡️ Security Hardening

### Final Security Checklist

- [ ] All secrets in vault (no .env in production)
- [ ] WAF rules configured and tested
- [ ] Security headers enabled
- [ ] Rate limiting active
- [ ] HTTPS enforced
- [ ] OAuth tokens encrypted
- [ ] Audit logging enabled
- [ ] IP allowlist configured (if applicable)
- [ ] Security scanning in CI/CD
- [ ] Penetration testing completed
- [ ] Incident response plan ready

---

## 📝 Post-Deployment Tasks

1. **Monitor for 24 hours**
   - Watch error rates
   - Check database performance
   - Monitor memory/CPU usage
   - Verify alerts are working

2. **Performance Tuning**
   - Review slow query logs
   - Optimize identified bottlenecks
   - Adjust connection pool if needed

3. **Documentation**
   - Update runbooks
   - Document any production issues
   - Create knowledge base articles

4. **Backup Verification**
   - Test database restore
   - Verify backup schedule
   - Test disaster recovery plan

---

## 🔍 Troubleshooting

### High Database Load
```bash
# Check active connections
SELECT count(*) FROM pg_stat_activity WHERE state = 'active';

# Find long-running queries
SELECT pid, now() - query_start as duration, query
FROM pg_stat_activity
WHERE state = 'active'
ORDER BY duration DESC;

# Kill problematic query
SELECT pg_terminate_backend(pid);
```

### High Memory Usage
```bash
# Check Python memory usage
import tracemalloc
tracemalloc.start()
# ... run code ...
snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')
for stat in top_stats[:10]:
    print(stat)
```

### Circuit Breaker Stuck Open
```python
# Manually reset circuit breaker
from src.api.utils.resilience import api_circuit_breaker
api_circuit_breaker.reset()
```

---

## 📚 Additional Resources

- [PostgreSQL Performance Tuning](https://wiki.postgresql.org/wiki/Performance_Optimization)
- [FastAPI Best Practices](https://fastapi.tiangolo.com/deployment/concepts/)
- [Kubernetes Production Best Practices](https://kubernetes.io/docs/setup/best-practices/)
- [Twelve-Factor App](https://12factor.net/)

---

**Document Version:** 1.0.0  
**Last Updated:** 2025-01-15  
**Next Review:** 2025-02-15
