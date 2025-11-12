"""
Centralized Logging Configuration with Structured Logging
"""
import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict, Optional
import structlog
from pythonjsonlogger import jsonlogger


class CloudShieldLogger:
    """Enhanced structured logging for CloudShield"""
    
    def __init__(self, name: str):
        self.logger = structlog.get_logger(name)
        self.name = name
    
    def _add_context(self, event: str, **kwargs) -> Dict[str, Any]:
        """Add common context to all log entries"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'logger': self.name,
            'event': event,
            **kwargs
        }
    
    def debug(self, event: str, **kwargs):
        """Log debug message"""
        self.logger.debug(event, **self._add_context(event, **kwargs))
    
    def info(self, event: str, **kwargs):
        """Log info message"""
        self.logger.info(event, **self._add_context(event, **kwargs))
    
    def warning(self, event: str, **kwargs):
        """Log warning message"""
        self.logger.warning(event, **self._add_context(event, **kwargs))
    
    def error(self, event: str, exception: Optional[Exception] = None, **kwargs):
        """Log error message"""
        context = self._add_context(event, **kwargs)
        if exception:
            context['exception_type'] = type(exception).__name__
            context['exception_message'] = str(exception)
            context['exception_traceback'] = self._format_exception(exception)
        self.logger.error(event, **context)
    
    def critical(self, event: str, exception: Optional[Exception] = None, **kwargs):
        """Log critical message"""
        context = self._add_context(event, **kwargs)
        if exception:
            context['exception_type'] = type(exception).__name__
            context['exception_message'] = str(exception)
            context['exception_traceback'] = self._format_exception(exception)
        self.logger.critical(event, **context)
    
    def _format_exception(self, exception: Exception) -> str:
        """Format exception for logging"""
        import traceback
        return ''.join(traceback.format_exception(
            type(exception),
            exception,
            exception.__traceback__
        ))
    
    def log_api_request(self, method: str, path: str, status_code: int, 
                       duration: float, user_id: Optional[int] = None, **kwargs):
        """Log API request with standard fields"""
        self.info(
            'api_request',
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=round(duration * 1000, 2),
            user_id=user_id,
            **kwargs
        )
    
    def log_security_event(self, event_type: str, severity: str = 'info', **kwargs):
        """Log security-related events"""
        self.logger.bind(
            event_category='security',
            event_type=event_type,
            severity=severity
        ).info('security_event', **self._add_context(event_type, **kwargs))
    
    def log_scan_event(self, platform: str, scan_id: str, status: str, **kwargs):
        """Log security scan events"""
        self.info(
            'security_scan',
            platform=platform,
            scan_id=scan_id,
            status=status,
            **kwargs
        )
    
    def log_finding(self, finding_type: str, risk_level: str, resource: str, **kwargs):
        """Log security finding detection"""
        self.logger.bind(
            event_category='finding',
            finding_type=finding_type,
            risk_level=risk_level
        ).warning('finding_detected', resource=resource, **kwargs)


def configure_advanced_logging(
    log_level: str = 'INFO',
    json_logs: bool = True,
    log_file: Optional[str] = None
):
    """Configure advanced structured logging"""
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper())
    )
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        if json_logs:
            formatter = jsonlogger.JsonFormatter(
                '%(timestamp)s %(level)s %(name)s %(message)s'
            )
            file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)


def get_enhanced_logger(name: str) -> CloudShieldLogger:
    """Get an enhanced CloudShield logger instance"""
    return CloudShieldLogger(name)
