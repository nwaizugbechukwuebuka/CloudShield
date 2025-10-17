"""
Logging configuration using structlog
"""
import logging
import sys
from typing import Any, Dict
import structlog
from structlog.stdlib import filter_by_level
from structlog.dev import ConsoleRenderer


def configure_logging(debug: bool = False) -> None:
    """Configure structured logging"""
    
    # Set log level
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Configure structlog
    structlog.configure(
        processors=[
            filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            ConsoleRenderer() if debug else structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str = __name__) -> structlog.BoundLogger:
    """Get a configured logger"""
    return structlog.get_logger(name)


# Request ID context for tracing
def add_request_id(logger: structlog.BoundLogger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add request ID to log context"""
    # This would be enhanced with actual request ID from middleware
    return event_dict


# Security-focused logging utilities
class SecurityLogger:
    """Logger for security events"""
    
    def __init__(self):
        self.logger = get_logger("security")
    
    def log_auth_success(self, user_email: str, provider: str = None):
        """Log successful authentication"""
        self.logger.info(
            "authentication_success",
            user_email=user_email,
            provider=provider,
            event_type="auth_success"
        )
    
    def log_auth_failure(self, email: str, reason: str, provider: str = None):
        """Log authentication failure"""
        self.logger.warning(
            "authentication_failure",
            email=email,
            reason=reason,
            provider=provider,
            event_type="auth_failure"
        )
    
    def log_oauth_start(self, provider: str, user_email: str = None):
        """Log OAuth flow start"""
        self.logger.info(
            "oauth_flow_started",
            provider=provider,
            user_email=user_email,
            event_type="oauth_start"
        )
    
    def log_oauth_success(self, provider: str, user_email: str, organization: str = None):
        """Log successful OAuth integration"""
        self.logger.info(
            "oauth_integration_success",
            provider=provider,
            user_email=user_email,
            organization=organization,
            event_type="oauth_success"
        )
    
    def log_scan_started(self, integration_id: int, integration_type: str, user_email: str):
        """Log security scan start"""
        self.logger.info(
            "security_scan_started",
            integration_id=integration_id,
            integration_type=integration_type,
            user_email=user_email,
            event_type="scan_start"
        )
    
    def log_scan_completed(self, integration_id: int, findings_count: int, duration_seconds: float):
        """Log security scan completion"""
        self.logger.info(
            "security_scan_completed",
            integration_id=integration_id,
            findings_count=findings_count,
            duration_seconds=duration_seconds,
            event_type="scan_complete"
        )
    
    def log_finding_created(self, finding_type: str, risk_level: str, integration_type: str, user_email: str):
        """Log security finding creation"""
        self.logger.warning(
            "security_finding_created",
            finding_type=finding_type,
            risk_level=risk_level,
            integration_type=integration_type,
            user_email=user_email,
            event_type="finding_created"
        )
    
    def log_critical_finding(self, finding_id: int, finding_type: str, resource_name: str, user_email: str):
        """Log critical security finding"""
        self.logger.error(
            "critical_security_finding",
            finding_id=finding_id,
            finding_type=finding_type,
            resource_name=resource_name,
            user_email=user_email,
            event_type="critical_finding"
        )
    
    def log_api_access(self, endpoint: str, method: str, user_email: str, status_code: int):
        """Log API access"""
        self.logger.info(
            "api_access",
            endpoint=endpoint,
            method=method,
            user_email=user_email,
            status_code=status_code,
            event_type="api_access"
        )


# Global security logger instance
security_logger = SecurityLogger()
