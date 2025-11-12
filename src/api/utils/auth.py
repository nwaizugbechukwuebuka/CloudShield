"""
Enhanced Authentication & Authorization System
"""
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
import secrets
import redis.asyncio as redis
from enum import Enum

from ..models.user import User
from ..database import get_db
from ..utils.config import settings
from ..utils.logger import get_logger
from ..utils.rate_limiting import RateLimiter

logger = get_logger(__name__)


class UserRole(str, Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    COMPLIANCE_OFFICER = "compliance_officer"
    USER = "user"
    READ_ONLY = "read_only"


class Permission(str, Enum):
    """Granular permissions"""
    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Scan operations
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    
    # Integration management
    INTEGRATION_CREATE = "integration:create"
    INTEGRATION_READ = "integration:read"
    INTEGRATION_UPDATE = "integration:update"
    INTEGRATION_DELETE = "integration:delete"
    
    # Alert management
    ALERT_CREATE = "alert:create"
    ALERT_READ = "alert:read"
    ALERT_UPDATE = "alert:update"
    ALERT_DELETE = "alert:delete"
    
    # System administration
    SYSTEM_CONFIG = "system:config"
    SYSTEM_MONITOR = "system:monitor"
    SYSTEM_AUDIT = "system:audit"


# Role-Permission mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [p for p in Permission],  # All permissions
    UserRole.SECURITY_ANALYST: [
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE,
        Permission.ALERT_CREATE, Permission.ALERT_READ, Permission.ALERT_UPDATE,
        Permission.INTEGRATION_READ, Permission.USER_READ,
        Permission.SYSTEM_MONITOR
    ],
    UserRole.COMPLIANCE_OFFICER: [
        Permission.SCAN_READ, Permission.ALERT_READ,
        Permission.INTEGRATION_READ, Permission.USER_READ,
        Permission.SYSTEM_AUDIT, Permission.SYSTEM_MONITOR
    ],
    UserRole.USER: [
        Permission.SCAN_CREATE, Permission.SCAN_READ,
        Permission.ALERT_READ, Permission.INTEGRATION_READ,
        Permission.USER_READ
    ],
    UserRole.READ_ONLY: [
        Permission.SCAN_READ, Permission.ALERT_READ,
        Permission.INTEGRATION_READ, Permission.USER_READ
    ]
}


class AuthManager:
    """Enhanced authentication and authorization manager"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.rate_limiter = RateLimiter()
        self.redis_url = settings.REDIS_URL
        
        # JWT settings
        self.secret_key = settings.SECRET_KEY
        self.algorithm = "HS256"
        self.access_token_expire = timedelta(minutes=30)
        self.refresh_token_expire = timedelta(days=7)
    
    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def generate_password_reset_token(self) -> str:
        """Generate secure password reset token"""
        return secrets.token_urlsafe(32)
    
    async def create_access_token(self, user_id: int, user_email: str, user_role: str) -> Dict[str, str]:
        """Create JWT access token with enhanced claims"""
        
        now = datetime.now(timezone.utc)
        
        # Access token payload
        access_payload = {
            "sub": str(user_id),
            "email": user_email,
            "role": user_role,
            "permissions": [p.value for p in ROLE_PERMISSIONS.get(UserRole(user_role), [])],
            "iat": now,
            "exp": now + self.access_token_expire,
            "type": "access"
        }
        
        # Refresh token payload
        refresh_payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + self.refresh_token_expire,
            "type": "refresh"
        }
        
        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)
        
        # Store refresh token in Redis
        try:
            redis_client = redis.from_url(self.redis_url)
            await redis_client.setex(
                f"refresh_token:{user_id}",
                self.refresh_token_expire,
                refresh_token
            )
            await redis_client.close()
        except Exception as e:
            logger.error(f"Failed to store refresh token: {str(e)}")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": int(self.access_token_expire.total_seconds())
        }
    
    async def verify_token(self, token: str) -> Dict:
        """Verify and decode JWT token"""
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if token is blacklisted
            if await self.is_token_blacklisted(token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
            
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        """Refresh access token using refresh token"""
        
        try:
            payload = jwt.decode(refresh_token, self.secret_key, algorithms=[self.algorithm])
            
            if payload.get("type") != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            user_id = int(payload.get("sub"))
            
            # Verify refresh token exists in Redis
            redis_client = redis.from_url(self.redis_url)
            stored_token = await redis_client.get(f"refresh_token:{user_id}")
            await redis_client.close()
            
            if not stored_token or stored_token.decode() != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token"
                )
            
            # Get user details from database
            from sqlalchemy.orm import sessionmaker
            from ..database import engine
            
            SessionLocal = sessionmaker(bind=engine)
            with SessionLocal() as db:
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User not found or inactive"
                    )
                
                # Create new access token
                return await self.create_access_token(user.id, user.email, user.role)
            
        except JWTError as e:
            logger.warning(f"Refresh token verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """Add token to blacklist"""
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            exp = payload.get("exp")
            
            if exp:
                # Calculate TTL for blacklist entry
                now = datetime.now(timezone.utc).timestamp()
                ttl = int(exp - now)
                
                if ttl > 0:
                    redis_client = redis.from_url(self.redis_url)
                    await redis_client.setex(f"blacklist:{token}", ttl, "revoked")
                    await redis_client.close()
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {str(e)}")
            return False
    
    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            result = await redis_client.get(f"blacklist:{token}")
            await redis_client.close()
            return result is not None
        except Exception as e:
            logger.error(f"Failed to check blacklist: {str(e)}")
            return False
    
    async def authenticate_user(self, email: str, password: str, request: Request) -> Optional[User]:
        """Authenticate user with enhanced security checks"""
        
        client_ip = request.client.host
        
        # Check rate limiting for authentication attempts
        is_limited, limit_info = await self.rate_limiter.check_rate_limit(
            identifier=client_ip,
            endpoint_type="auth"
        )
        
        if is_limited:
            logger.warning(f"Authentication rate limited for IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please try again later."
            )
        
        # Get user from database
        from sqlalchemy.orm import sessionmaker
        from ..database import engine
        
        SessionLocal = sessionmaker(bind=engine)
        with SessionLocal() as db:
            user = db.query(User).filter(User.email == email).first()
            
            if not user:
                # Log failed attempt
                await self.log_auth_attempt(email, client_ip, False, "user_not_found")
                return None
            
            if not user.is_active:
                await self.log_auth_attempt(email, client_ip, False, "user_inactive")
                return None
            
            # Check account lockout
            if await self.is_account_locked(user.id):
                await self.log_auth_attempt(email, client_ip, False, "account_locked")
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked due to multiple failed attempts"
                )
            
            # Verify password
            if not self.verify_password(password, user.password_hash):
                await self.record_failed_attempt(user.id, client_ip)
                await self.log_auth_attempt(email, client_ip, False, "invalid_password")
                return None
            
            # Reset failed attempts on successful authentication
            await self.reset_failed_attempts(user.id)
            await self.log_auth_attempt(email, client_ip, True, "success")
            
            # Update last login
            user.last_login_at = datetime.now(timezone.utc)
            user.last_login_ip = client_ip
            db.commit()
            
            return user
    
    async def record_failed_attempt(self, user_id: int, ip_address: str):
        """Record failed authentication attempt"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            
            # Increment failed attempts counter
            key = f"failed_attempts:{user_id}"
            failed_count = await redis_client.incr(key)
            await redis_client.expire(key, 3600)  # 1 hour window
            
            # Lock account after 5 failed attempts
            if failed_count >= 5:
                await redis_client.setex(f"account_locked:{user_id}", 1800, "locked")  # 30 min lock
            
            await redis_client.close()
            
        except Exception as e:
            logger.error(f"Failed to record authentication attempt: {str(e)}")
    
    async def reset_failed_attempts(self, user_id: int):
        """Reset failed attempts counter"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            await redis_client.delete(f"failed_attempts:{user_id}")
            await redis_client.close()
        except Exception as e:
            logger.error(f"Failed to reset failed attempts: {str(e)}")
    
    async def is_account_locked(self, user_id: int) -> bool:
        """Check if account is locked"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            result = await redis_client.get(f"account_locked:{user_id}")
            await redis_client.close()
            return result is not None
        except Exception as e:
            logger.error(f"Failed to check account lock status: {str(e)}")
            return False
    
    async def log_auth_attempt(self, email: str, ip_address: str, success: bool, reason: str):
        """Log authentication attempt for auditing"""
        
        try:
            redis_client = redis.from_url(self.redis_url)
            
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "email": email,
                "ip_address": ip_address,
                "success": success,
                "reason": reason
            }
            
            # Store in Redis list (keep last 1000 entries)
            await redis_client.lpush("auth_logs", str(log_entry))
            await redis_client.ltrim("auth_logs", 0, 999)
            
            await redis_client.close()
            
            logger.info(f"Auth attempt: {email} from {ip_address} - {'SUCCESS' if success else 'FAILED'} ({reason})")
            
        except Exception as e:
            logger.error(f"Failed to log auth attempt: {str(e)}")


# Security dependencies
security = HTTPBearer()
auth_manager = AuthManager()


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    
    try:
        # Verify token
        payload = await auth_manager.verify_token(credentials.credentials)
        user_id = int(payload.get("sub"))
        
        # Get user from database
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Add permissions to user object for easy access
        user.permissions = payload.get("permissions", [])
        
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )


def require_permission(permission: Permission):
    """Dependency factory for permission-based authorization"""
    
    async def check_permission(current_user: User = Depends(get_current_user)):
        if permission.value not in getattr(current_user, 'permissions', []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission.value}' required"
            )
        return current_user
    
    return check_permission


def require_role(role: UserRole):
    """Dependency factory for role-based authorization"""
    
    async def check_role(current_user: User = Depends(get_current_user)):
        if current_user.role != role.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role.value}' required"
            )
        return current_user
    
    return check_role


async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db = Depends(get_db)
) -> Optional[User]:
    """Get current user if authenticated, otherwise return None"""
    
    if not credentials:
        return None
    
    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None


# Alias for compatibility
get_current_active_user = get_current_user