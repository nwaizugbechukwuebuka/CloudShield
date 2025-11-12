"""
Prometheus Metrics Collection for CloudShield
"""
from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest
from prometheus_client import REGISTRY, CollectorRegistry
from functools import wraps
import time
from typing import Callable
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# Application info
app_info = Info('cloudshield_app', 'CloudShield application information')
app_info.info({
    'version': '1.0.0',
    'environment': 'production'
})

# HTTP Request metrics
http_requests_total = Counter(
    'cloudshield_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'cloudshield_http_request_duration_seconds',
    'HTTP request latency in seconds',
    ['method', 'endpoint'],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0]
)

http_requests_in_progress = Gauge(
    'cloudshield_http_requests_in_progress',
    'Number of HTTP requests in progress',
    ['method', 'endpoint']
)

# Authentication metrics
auth_attempts_total = Counter(
    'cloudshield_auth_attempts_total',
    'Total authentication attempts',
    ['status', 'method']
)

auth_failures_total = Counter(
    'cloudshield_auth_failures_total',
    'Total authentication failures',
    ['reason']
)

# Security scanning metrics
scans_total = Counter(
    'cloudshield_scans_total',
    'Total security scans performed',
    ['platform', 'status']
)

scan_duration_seconds = Histogram(
    'cloudshield_scan_duration_seconds',
    'Security scan duration in seconds',
    ['platform'],
    buckets=[10, 30, 60, 120, 300, 600, 1800, 3600]
)

findings_detected = Counter(
    'cloudshield_findings_detected_total',
    'Total security findings detected',
    ['platform', 'risk_level', 'finding_type']
)

active_scans = Gauge(
    'cloudshield_active_scans',
    'Number of active security scans',
    ['platform']
)

# Database metrics
db_connections_active = Gauge(
    'cloudshield_db_connections_active',
    'Number of active database connections'
)

db_query_duration_seconds = Histogram(
    'cloudshield_db_query_duration_seconds',
    'Database query duration in seconds',
    ['operation'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
)

db_errors_total = Counter(
    'cloudshield_db_errors_total',
    'Total database errors',
    ['operation', 'error_type']
)

# Cache metrics
cache_hits_total = Counter(
    'cloudshield_cache_hits_total',
    'Total cache hits',
    ['cache_type']
)

cache_misses_total = Counter(
    'cloudshield_cache_misses_total',
    'Total cache misses',
    ['cache_type']
)

# Background task metrics
celery_tasks_total = Counter(
    'cloudshield_celery_tasks_total',
    'Total Celery tasks',
    ['task_name', 'status']
)

celery_task_duration_seconds = Histogram(
    'cloudshield_celery_task_duration_seconds',
    'Celery task duration in seconds',
    ['task_name'],
    buckets=[1, 5, 10, 30, 60, 300, 600, 1800, 3600]
)

celery_queue_length = Gauge(
    'cloudshield_celery_queue_length',
    'Number of tasks in Celery queue',
    ['queue_name']
)

# Integration metrics
integration_api_calls_total = Counter(
    'cloudshield_integration_api_calls_total',
    'Total API calls to external integrations',
    ['platform', 'status']
)

integration_api_errors_total = Counter(
    'cloudshield_integration_api_errors_total',
    'Total API errors from external integrations',
    ['platform', 'error_type']
)

# Alert metrics
alerts_sent_total = Counter(
    'cloudshield_alerts_sent_total',
    'Total alerts sent',
    ['channel', 'severity']
)

alerts_failed_total = Counter(
    'cloudshield_alerts_failed_total',
    'Total failed alert deliveries',
    ['channel', 'reason']
)

# User metrics
active_users = Gauge(
    'cloudshield_active_users',
    'Number of active users in the system'
)

user_sessions_active = Gauge(
    'cloudshield_user_sessions_active',
    'Number of active user sessions'
)


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Middleware to collect HTTP metrics"""
    
    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path
        
        # Track request in progress
        http_requests_in_progress.labels(method=method, endpoint=path).inc()
        
        # Track request duration
        start_time = time.time()
        
        try:
            response = await call_next(request)
            status = response.status_code
            
            # Record metrics
            http_requests_total.labels(
                method=method,
                endpoint=path,
                status=status
            ).inc()
            
            duration = time.time() - start_time
            http_request_duration_seconds.labels(
                method=method,
                endpoint=path
            ).observe(duration)
            
            return response
            
        finally:
            http_requests_in_progress.labels(method=method, endpoint=path).dec()


def track_scan_metrics(platform: str):
    """Decorator to track security scan metrics"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            active_scans.labels(platform=platform).inc()
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                scans_total.labels(platform=platform, status='success').inc()
                return result
                
            except Exception as e:
                scans_total.labels(platform=platform, status='error').inc()
                raise
                
            finally:
                duration = time.time() - start_time
                scan_duration_seconds.labels(platform=platform).observe(duration)
                active_scans.labels(platform=platform).dec()
        
        return wrapper
    return decorator


def track_db_query(operation: str):
    """Decorator to track database query metrics"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                db_query_duration_seconds.labels(operation=operation).observe(duration)
                return result
                
            except Exception as e:
                db_errors_total.labels(
                    operation=operation,
                    error_type=type(e).__name__
                ).inc()
                raise
        
        return wrapper
    return decorator
