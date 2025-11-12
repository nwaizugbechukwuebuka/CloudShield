"""
Integration model for connected services (Google Workspace, Microsoft 365, etc.)
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship
from .base import BaseModel
import enum


class IntegrationType(enum.Enum):
    GOOGLE_WORKSPACE = "google_workspace"
    MICROSOFT_365 = "microsoft_365"
    SLACK = "slack"
    GITHUB = "github"
    NOTION = "notion"


class IntegrationStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


class Integration(BaseModel):
    __tablename__ = "integrations"
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)  # User-friendly name
    type = Column(Enum(IntegrationType), nullable=False)
    status = Column(Enum(IntegrationStatus), default=IntegrationStatus.PENDING, nullable=False)
    
    # OAuth credentials (encrypted)
    access_token = Column(Text)  # Encrypted access token
    refresh_token = Column(Text)  # Encrypted refresh token
    expires_at = Column(DateTime)
    
    # Service-specific configuration
    config = Column(JSON)  # Service-specific settings
    
    # Metadata
    organization_name = Column(String(255))  # e.g., company name
    organization_id = Column(String(255))    # Service-specific org ID
    
    # Scanning settings
    scan_enabled = Column(Boolean, default=True, nullable=False)
    last_scan_at = Column(DateTime)
    next_scan_at = Column(DateTime)
    scan_frequency_hours = Column(Integer, default=24, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="integrations")
    findings = relationship("Finding", back_populates="integration", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="integration", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Integration {self.name} ({self.type.value})>"
