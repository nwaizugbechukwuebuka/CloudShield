"""
Audit Logging System for Security Events
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
from enum import Enum as PyEnum
import uuid
import json
from typing import Dict, Any, Optional, List
import asyncio

from ..models.base import BaseModel
from ..database import get_db_session
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AuditEventType(PyEnum):
    """Types of audit events"""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure" 
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    
    # User management
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"
    ROLE_CHANGED = "role_changed"
    
    # Integration events
    INTEGRATION_CONNECTED = "integration_connected"
    INTEGRATION_DISCONNECTED = "integration_disconnected"
    INTEGRATION_ERROR = "integration_error"
    OAUTH_AUTHORIZED = "oauth_authorized"
    OAUTH_REVOKED = "oauth_revoked"
    
    # Scanning events
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    FINDING_CREATED = "finding_created"
    FINDING_RESOLVED = "finding_resolved"
    
    # Security events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"
    IP_BLOCKED = "ip_blocked"
    MALICIOUS_REQUEST = "malicious_request"
    
    # System events
    SYSTEM_ERROR = "system_error"
    CONFIGURATION_CHANGED = "configuration_changed"
    DATA_EXPORT = "data_export"
    API_ACCESS = "api_access"


class AuditSeverity(PyEnum):
    """Audit event severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditLog(BaseModel):
    """Audit log entry model"""
    __tablename__ = "audit_logs"
    
    # Event identification
    event_id = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, index=True)
    event_type = Column(Enum(AuditEventType), nullable=False, index=True)
    severity = Column(Enum(AuditSeverity), default=AuditSeverity.LOW, nullable=False)
    
    # Actor information
    user_id = Column(Integer, nullable=True, index=True)  # Can be null for system events
    user_email = Column(String(255), nullable=True)
    session_id = Column(String(255), nullable=True)
    
    # Request context
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    request_method = Column(String(10), nullable=True)
    request_path = Column(Text, nullable=True)
    request_id = Column(String(255), nullable=True, index=True)
    
    # Event details
    resource_type = Column(String(100), nullable=True)  # user, integration, scan, etc.
    resource_id = Column(String(255), nullable=True)
    action = Column(String(100), nullable=True)
    
    # Event data
    event_data = Column(JSON, nullable=True)  # Flexible event-specific data
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)
    
    # Geolocation (optional)
    country = Column(String(2), nullable=True)
    region = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    
    # Additional metadata
    metadata = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)  # Array of tags for categorization


class AuditLogger:
    """Centralized audit logging service"""
    
    def __init__(self):
        self.logger = get_logger("audit")
    
    async def log_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity = AuditSeverity.LOW,
        user_id: Optional[int] = None,
        user_email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_method: Optional[str] = None,
        request_path: Optional[str] = None,
        request_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Log an audit event
        Returns the event_id if successful, None otherwise
        """
        
        try:
            # Create audit log entry
            audit_entry = AuditLog(
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                user_email=user_email,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_method=request_method,
                request_path=request_path,
                request_id=request_id,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                event_data=event_data,
                success=success,
                error_message=error_message,
                metadata=metadata,
                tags=tags
            )
            
            # Save to database
            from sqlalchemy.orm import sessionmaker
            from ..database import engine
            
            SessionLocal = sessionmaker(bind=engine)
            with SessionLocal() as db:
                db.add(audit_entry)
                db.commit()
                event_id = str(audit_entry.event_id)
            
            # Log to application logger as well
            log_message = f"AUDIT: {event_type.value}"
            if user_email:
                log_message += f" | User: {user_email}"
            if resource_type and resource_id:
                log_message += f" | Resource: {resource_type}:{resource_id}"
            if not success and error_message:
                log_message += f" | Error: {error_message}"
            
            if severity == AuditSeverity.CRITICAL:
                self.logger.critical(log_message, extra=event_data or {})
            elif severity == AuditSeverity.HIGH:
                self.logger.error(log_message, extra=event_data or {})
            elif severity == AuditSeverity.MEDIUM:
                self.logger.warning(log_message, extra=event_data or {})
            else:
                self.logger.info(log_message, extra=event_data or {})
            
            return event_id
            
        except Exception as e:
            self.logger.error(f"Failed to create audit log entry: {str(e)}")
            return None
    
    async def log_authentication_event(
        self,
        event_type: AuditEventType,
        user_email: str,
        ip_address: str,
        success: bool = True,
        error_message: Optional[str] = None,
        user_agent: Optional[str] = None,
        additional_data: Optional[Dict] = None
    ):
        """Log authentication-related events"""
        
        severity = AuditSeverity.MEDIUM if success else AuditSeverity.HIGH
        
        event_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "authentication_method": additional_data.get("method", "password") if additional_data else "password"
        }
        
        if additional_data:
            event_data.update(additional_data)
        
        await self.log_event(
            event_type=event_type,
            severity=severity,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="authentication",
            action="authenticate",
            event_data=event_data,
            success=success,
            error_message=error_message,
            tags=["authentication", "security"]
        )
    
    async def log_user_management_event(
        self,
        event_type: AuditEventType,
        actor_user_id: int,
        actor_email: str,
        target_user_id: Optional[int] = None,
        target_email: Optional[str] = None,
        changes: Optional[Dict] = None,
        ip_address: Optional[str] = None
    ):
        """Log user management events"""
        
        event_data = {
            "actor": {"id": actor_user_id, "email": actor_email},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if target_user_id:
            event_data["target"] = {"id": target_user_id, "email": target_email}
        
        if changes:
            event_data["changes"] = changes
        
        await self.log_event(
            event_type=event_type,
            severity=AuditSeverity.MEDIUM,
            user_id=actor_user_id,
            user_email=actor_email,
            ip_address=ip_address,
            resource_type="user",
            resource_id=str(target_user_id) if target_user_id else str(actor_user_id),
            action=event_type.value,
            event_data=event_data,
            tags=["user_management", "administration"]
        )
    
    async def log_security_event(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        ip_address: str,
        details: Dict[str, Any],
        user_id: Optional[int] = None,
        user_email: Optional[str] = None,
        request_path: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Log security-related events"""
        
        event_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "security_event": True,
            **details
        }
        
        await self.log_event(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            request_path=request_path,
            resource_type="security",
            action=event_type.value,
            event_data=event_data,
            tags=["security", "threat_detection"]
        )
    
    async def log_integration_event(
        self,
        event_type: AuditEventType,
        user_id: int,
        user_email: str,
        platform: str,
        integration_id: Optional[int] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        additional_data: Optional[Dict] = None
    ):
        """Log integration-related events"""
        
        severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
        
        event_data = {
            "platform": platform,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if additional_data:
            event_data.update(additional_data)
        
        await self.log_event(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            user_email=user_email,
            resource_type="integration",
            resource_id=str(integration_id) if integration_id else None,
            action=event_type.value,
            event_data=event_data,
            success=success,
            error_message=error_message,
            tags=["integration", platform]
        )


# Global audit logger instance
audit_logger = AuditLogger()


# Convenience functions
async def log_authentication_success(
    user_email: str, 
    ip_address: str, 
    user_agent: Optional[str] = None
):
    """Log successful authentication"""
    await audit_logger.log_authentication_event(
        AuditEventType.LOGIN_SUCCESS,
        user_email,
        ip_address,
        success=True,
        user_agent=user_agent
    )


async def log_authentication_failure(
    user_email: str, 
    ip_address: str, 
    reason: str,
    user_agent: Optional[str] = None
):
    """Log failed authentication"""
    await audit_logger.log_authentication_event(
        AuditEventType.LOGIN_FAILURE,
        user_email,
        ip_address,
        success=False,
        error_message=reason,
        user_agent=user_agent
    )


async def log_security_violation(
    ip_address: str,
    violation_type: str,
    details: Dict[str, Any],
    severity: AuditSeverity = AuditSeverity.HIGH
):
    """Log security violations"""
    await audit_logger.log_security_event(
        AuditEventType.SECURITY_VIOLATION,
        severity,
        ip_address,
        {"violation_type": violation_type, **details}
    )