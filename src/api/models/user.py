"""
User model for authentication and authorization
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .base import BaseModel
import enum


class UserRole(enum.Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    COMPLIANCE_OFFICER = "compliance_officer"
    USER = "user"
    READ_ONLY = "read_only"


class User(BaseModel):
    __tablename__ = "users"
    
    # Basic user information
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)  # Renamed from hashed_password
    full_name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    
    # OAuth fields
    oauth_provider = Column(String(50))  # google, github, etc.
    oauth_id = Column(String(255))  # OAuth provider user ID
    avatar_url = Column(String(500))
    
    # Security & tracking fields
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)  # IPv6 compatible
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime(timezone=True), nullable=True)
    email_verification_token = Column(String(255), nullable=True)
    email_verification_expires = Column(DateTime(timezone=True), nullable=True)
    
    # User preferences
    timezone = Column(String(50), default="UTC")
    notification_preferences = Column(Text)  # JSON string
    
    # Multi-factor authentication
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32), nullable=True)  # TOTP secret
    backup_codes = Column(Text, nullable=True)  # JSON array of backup codes
    
    # Relationships
    integrations = relationship("Integration", back_populates="user", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    alerts = relationship("Alert", foreign_keys="[Alert.user_id]", back_populates="user", cascade="all, delete-orphan")
    assigned_alerts = relationship("Alert", foreign_keys="[Alert.assignee_id]", back_populates="assignee")
    
    @property
    def is_admin(self) -> bool:
        """Check if user has admin role"""
        return self.role == UserRole.ADMIN
    
    @property
    def is_security_analyst(self) -> bool:
        """Check if user has security analyst role"""
        return self.role in [UserRole.ADMIN, UserRole.SECURITY_ANALYST]
    
    @property
    def can_manage_users(self) -> bool:
        """Check if user can manage other users"""
        return self.role == UserRole.ADMIN
    
    @property
    def can_create_scans(self) -> bool:
        """Check if user can create scans"""
        return self.role in [UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.USER]
    
    @property
    def display_name(self) -> str:
        """Get display name for user"""
        return self.full_name or self.email.split("@")[0]
    
    def update_last_login(self, ip_address: str = None):
        """Update last login timestamp and IP"""
        self.last_login_at = datetime.now(timezone.utc)
        if ip_address:
            self.last_login_ip = ip_address
    
    def __repr__(self):
        return f"<User {self.email} ({self.role.value})>"
