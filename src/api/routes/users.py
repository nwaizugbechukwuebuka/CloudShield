"""
Enhanced User Management Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Optional, Dict
from datetime import datetime, timedelta, timezone
import json
from pydantic import BaseModel, EmailStr, validator, Field

from ..database import get_db
from ..models.user import User, UserRole
from ..utils.auth import get_current_user, require_permission, Permission, auth_manager
from ..utils.logger import get_logger
from ..utils.rate_limiting import RateLimiter

logger = get_logger(__name__)
router = APIRouter(prefix="/users", tags=["users"])
rate_limiter = RateLimiter()


# Pydantic models for request/response
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=255)
    role: UserRole = UserRole.USER
    timezone: str = "UTC"
    send_welcome_email: bool = True
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v)
        
        if not all([has_upper, has_lower, has_digit, has_special]):
            raise ValueError(
                'Password must contain at least one uppercase letter, '
                'one lowercase letter, one digit, and one special character'
            )
        
        return v


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    timezone: Optional[str] = None
    notification_preferences: Optional[Dict] = None


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    is_verified: bool
    oauth_provider: Optional[str]
    avatar_url: Optional[str]
    last_login_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    timezone: str
    mfa_enabled: bool
    
    class Config:
        orm_mode = True


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    size: int
    pages: int


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
    
    @validator('new_password')
    def validate_new_password(cls, v):
        """Validate new password strength"""
        return UserCreate.validate_password(v)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)
    
    @validator('new_password')
    def validate_new_password(cls, v):
        return UserCreate.validate_password(v)


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user's profile"""
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_current_user_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update current user's profile"""
    
    # Users can only update certain fields for themselves
    allowed_fields = ['full_name', 'timezone', 'notification_preferences']
    
    for field, value in user_update.dict(exclude_unset=True).items():
        if field in allowed_fields and value is not None:
            if field == 'notification_preferences':
                setattr(current_user, field, json.dumps(value))
            else:
                setattr(current_user, field, value)
    
    current_user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(current_user)
    
    logger.info(f"User profile updated: {current_user.email}")
    return current_user


@router.post("/change-password")
async def change_password(
    password_request: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change current user's password"""
    
    # Verify current password
    if not current_user.password_hash or not auth_manager.verify_password(
        password_request.current_password, current_user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    current_user.password_hash = auth_manager.hash_password(password_request.new_password)
    current_user.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    logger.info(f"Password changed for user: {current_user.email}")
    
    return {"message": "Password updated successfully"}


@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    search: Optional[str] = Query(None, description="Search by email or name"),
    role: Optional[UserRole] = Query(None, description="Filter by role"),
    active_only: bool = Query(True, description="Show only active users"),
    current_user: User = Depends(require_permission(Permission.USER_READ)),
    db: Session = Depends(get_db)
):
    """List users with filtering and pagination"""
    
    # Build query
    query = db.query(User)
    
    # Apply filters
    if active_only:
        query = query.filter(User.is_active == True)
    
    if role:
        query = query.filter(User.role == role)
    
    if search:
        search_pattern = f"%{search.lower()}%"
        query = query.filter(
            or_(
                User.email.ilike(search_pattern),
                User.full_name.ilike(search_pattern)
            )
        )
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * size
    users = query.offset(offset).limit(size).all()
    
    pages = (total + size - 1) // size
    
    return UserListResponse(
        users=users,
        total=total,
        page=page,
        size=size,
        pages=pages
    )


@router.post("/", response_model=UserResponse)
async def create_user(
    user_create: UserCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission(Permission.USER_CREATE)),
    db: Session = Depends(get_db)
):
    """Create a new user"""
    
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user_create.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    user = User(
        email=user_create.email,
        password_hash=auth_manager.hash_password(user_create.password),
        full_name=user_create.full_name,
        role=user_create.role,
        timezone=user_create.timezone,
        is_active=True,
        is_verified=False
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    logger.info(f"User created: {user.email} by {current_user.email}")
    
    # Send welcome email in background
    if user_create.send_welcome_email:
        background_tasks.add_task(send_welcome_email, user.email, user.full_name)
    
    return user


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(require_permission(Permission.USER_READ)),
    db: Session = Depends(get_db)
):
    """Get user by ID"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    current_user: User = Depends(require_permission(Permission.USER_UPDATE)),
    db: Session = Depends(get_db)
):
    """Update user by ID"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent users from updating their own role (unless admin)
    if user.id == current_user.id and user_update.role and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot update your own role"
        )
    
    # Update fields
    for field, value in user_update.dict(exclude_unset=True).items():
        if value is not None:
            if field == 'notification_preferences':
                setattr(user, field, json.dumps(value))
            else:
                setattr(user, field, value)
    
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    
    logger.info(f"User updated: {user.email} by {current_user.email}")
    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_permission(Permission.USER_DELETE)),
    db: Session = Depends(get_db)
):
    """Soft delete user by ID"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent users from deleting themselves
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete your own account"
        )
    
    # Soft delete (deactivate)
    user.is_active = False
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    logger.info(f"User deleted: {user.email} by {current_user.email}")
    
    return {"message": "User deleted successfully"}


@router.post("/reset-password")
async def request_password_reset(
    request_data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db)
):
    """Request password reset"""
    
    # Rate limiting for password reset requests
    client_ip = request.client.host
    is_limited, _ = await rate_limiter.check_rate_limit(
        identifier=client_ip,
        endpoint_type="auth"
    )
    
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please try again later."
        )
    
    user = db.query(User).filter(User.email == request_data.email).first()
    
    # Always return success to prevent email enumeration
    if user and user.is_active:
        # Generate reset token
        reset_token = auth_manager.generate_password_reset_token()
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        db.commit()
        
        # Send reset email in background
        background_tasks.add_task(
            send_password_reset_email, 
            user.email, 
            user.full_name, 
            reset_token
        )
        
        logger.info(f"Password reset requested for: {user.email}")
    
    return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/reset-password/confirm")
async def confirm_password_reset(
    reset_data: PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """Confirm password reset with token"""
    
    user = db.query(User).filter(
        and_(
            User.password_reset_token == reset_data.token,
            User.password_reset_expires > datetime.now(timezone.utc)
        )
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    # Update password and clear reset token
    user.password_hash = auth_manager.hash_password(reset_data.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    
    logger.info(f"Password reset completed for: {user.email}")
    
    return {"message": "Password reset successful"}


@router.get("/{user_id}/activity")
async def get_user_activity(
    user_id: int,
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    current_user: User = Depends(require_permission(Permission.USER_READ)),
    db: Session = Depends(get_db)
):
    """Get user activity summary"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Calculate date range
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)
    
    # Get activity data (you'll need to implement based on your audit log system)
    activity_summary = {
        "user_id": user_id,
        "period_days": days,
        "start_date": start_date,
        "end_date": end_date,
        "last_login": user.last_login_at,
        "total_scans": 0,  # Implement based on your scan history
        "total_findings": 0,  # Implement based on your findings
        "integrations_count": len(user.integrations) if user.integrations else 0
    }
    
    return activity_summary


# Background task functions
async def send_welcome_email(email: str, full_name: str):
    """Send welcome email to new user"""
    # Implement email sending logic
    logger.info(f"Sending welcome email to: {email}")


async def send_password_reset_email(email: str, full_name: str, reset_token: str):
    """Send password reset email"""
    # Implement email sending logic
    logger.info(f"Sending password reset email to: {email}")
    # In production, you'd include the reset_token in the email link