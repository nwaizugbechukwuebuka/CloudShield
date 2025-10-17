"""
Findings model for security issues and misconfigurations
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Enum, JSON, Float
from sqlalchemy.orm import relationship
from .base import BaseModel
import enum


class FindingType(enum.Enum):
    MISCONFIGURATION = "misconfiguration"
    INACTIVE_USER = "inactive_user"
    PUBLIC_SHARE = "public_share"
    OVERPERMISSIVE_TOKEN = "overpermissive_token"
    WEAK_PASSWORD_POLICY = "weak_password_policy"
    MFA_DISABLED = "mfa_disabled"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    EXTERNAL_SHARING = "external_sharing"
    UNENCRYPTED_DATA = "unencrypted_data"
    OUTDATED_SOFTWARE = "outdated_software"


class RiskLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


class Finding(BaseModel):
    __tablename__ = "findings"
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    integration_id = Column(Integer, ForeignKey("integrations.id"), nullable=False)
    
    # Finding details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    type = Column(Enum(FindingType), nullable=False)
    risk_level = Column(Enum(RiskLevel), nullable=False)
    risk_score = Column(Float, nullable=False)  # 0.0 to 100.0
    
    # Status and resolution
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    resolution_notes = Column(Text)
    resolved_at = Column(DateTime)
    resolved_by = Column(String(255))
    
    # Technical details
    resource_id = Column(String(255))  # Service-specific resource identifier
    resource_name = Column(String(255))  # Human-readable resource name
    resource_type = Column(String(100))  # e.g., "user", "file", "repository"
    
    # Evidence and metadata
    evidence = Column(JSON)  # Structured evidence data
    metadata = Column(JSON)  # Additional service-specific data
    
    # Remediation
    remediation_steps = Column(Text)
    remediation_priority = Column(Integer, default=5)  # 1-10 scale
    
    # Tracking
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False)
    occurrence_count = Column(Integer, default=1, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="findings")
    integration = relationship("Integration", back_populates="findings")
    
    def __repr__(self):
        return f"<Finding {self.title} ({self.risk_level.value})>"
    
    @property
    def is_critical(self):
        """Check if finding is critical risk"""
        return self.risk_level == RiskLevel.CRITICAL
    
    @property
    def is_high_risk(self):
        """Check if finding is high or critical risk"""
        return self.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    
    @property
    def days_open(self):
        """Calculate days since finding was first seen"""
        from datetime import datetime, timezone
        if self.status != FindingStatus.OPEN:
            return 0
        now = datetime.now(timezone.utc)
        return (now - self.first_seen_at).days
