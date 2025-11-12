"""
Sentry Integration for Error Tracking and Performance Monitoring
"""
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from typing import Optional
import logging

from .config import settings


def initialize_sentry(
    dsn: Optional[str] = None,
    environment: str = 'production',
    release: Optional[str] = None,
    traces_sample_rate: float = 0.1,
    profiles_sample_rate: float = 0.1
):
    """
    Initialize Sentry for error tracking and performance monitoring
    
    Args:
        dsn: Sentry DSN (Data Source Name)
        environment: Environment name (production, staging, development)
        release: Application release version
        traces_sample_rate: Percentage of transactions to trace (0.0 to 1.0)
        profiles_sample_rate: Percentage of transactions to profile (0.0 to 1.0)
    """
    
    sentry_dsn = dsn or getattr(settings, 'SENTRY_DSN', None)
    
    if not sentry_dsn:
        logging.warning("Sentry DSN not configured. Error tracking disabled.")
        return
    
    # Configure logging integration
    logging_integration = LoggingIntegration(
        level=logging.INFO,        # Capture info and above as breadcrumbs
        event_level=logging.ERROR  # Send errors as events
    )
    
    sentry_sdk.init(
        dsn=sentry_dsn,
        environment=environment,
        release=release or settings.APP_VERSION,
        
        # Integrations
        integrations=[
            FastApiIntegration(transaction_style="endpoint"),
            SqlalchemyIntegration(),
            RedisIntegration(),
            CeleryIntegration(),
            logging_integration,
        ],
        
        # Performance monitoring
        traces_sample_rate=traces_sample_rate,
        profiles_sample_rate=profiles_sample_rate,
        
        # Additional options
        send_default_pii=False,  # Don't send personally identifiable information
        attach_stacktrace=True,
        
        # Before send hook to filter sensitive data
        before_send=before_send_hook,
        
        # Performance monitoring options
        _experiments={
            "profiles_sample_rate": profiles_sample_rate,
        },
    )
    
    logging.info(f"Sentry initialized for environment: {environment}")


def before_send_hook(event, hint):
    """
    Hook to filter sensitive data before sending to Sentry
    """
    # Remove sensitive headers
    if 'request' in event and 'headers' in event['request']:
        sensitive_headers = ['Authorization', 'Cookie', 'X-Api-Key']
        for header in sensitive_headers:
            if header in event['request']['headers']:
                event['request']['headers'][header] = '[Filtered]'
    
    # Filter sensitive data from extra context
    if 'extra' in event:
        sensitive_keys = ['password', 'token', 'secret', 'api_key', 'access_token']
        for key in sensitive_keys:
            if key in event['extra']:
                event['extra'][key] = '[Filtered]'
    
    return event


def capture_security_event(
    event_type: str,
    severity: str = 'warning',
    user_id: Optional[int] = None,
    **extra_data
):
    """
    Capture security-related events in Sentry
    
    Args:
        event_type: Type of security event
        severity: Event severity (info, warning, error, critical)
        user_id: User ID associated with the event
        **extra_data: Additional context data
    """
    with sentry_sdk.configure_scope() as scope:
        scope.set_tag('event_category', 'security')
        scope.set_tag('event_type', event_type)
        
        if user_id:
            scope.set_user({'id': user_id})
        
        scope.set_context('security_event', extra_data)
        
        sentry_sdk.capture_message(
            f"Security Event: {event_type}",
            level=severity
        )


def capture_scan_error(
    platform: str,
    scan_id: str,
    error: Exception,
    user_id: Optional[int] = None,
    **extra_data
):
    """
    Capture security scan errors with context
    
    Args:
        platform: SaaS platform being scanned
        scan_id: Unique scan identifier
        error: Exception that occurred
        user_id: User ID who initiated the scan
        **extra_data: Additional context
    """
    with sentry_sdk.configure_scope() as scope:
        scope.set_tag('scan_platform', platform)
        scope.set_tag('scan_id', scan_id)
        
        if user_id:
            scope.set_user({'id': user_id})
        
        scope.set_context('scan_context', {
            'platform': platform,
            'scan_id': scan_id,
            **extra_data
        })
        
        sentry_sdk.capture_exception(error)


def set_user_context(user_id: int, email: Optional[str] = None, **extra):
    """Set user context for error tracking"""
    sentry_sdk.set_user({
        'id': user_id,
        'email': email,
        **extra
    })


def add_breadcrumb(
    message: str,
    category: str = 'default',
    level: str = 'info',
    **data
):
    """Add a breadcrumb for debugging context"""
    sentry_sdk.add_breadcrumb(
        message=message,
        category=category,
        level=level,
        data=data
    )
