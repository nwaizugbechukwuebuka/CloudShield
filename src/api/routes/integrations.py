"""
Integration management routes for OAuth connections
"""
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
import secrets

from ..database import get_db
from ..models.user import User
from ..models.integration import Integration, IntegrationType, IntegrationStatus
from ..services.oauth_services import get_oauth_service, OAuthError
from ..utils.logger import get_logger, security_logger
from .auth import get_current_active_user

logger = get_logger(__name__)
router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationResponse(BaseModel):
    id: int
    name: str
    type: str
    status: str
    organization_name: Optional[str] = None
    scan_enabled: bool
    last_scan_at: Optional[datetime] = None
    next_scan_at: Optional[datetime] = None
    scan_frequency_hours: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class IntegrationCreate(BaseModel):
    name: str
    type: IntegrationType
    scan_frequency_hours: int = 24


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    scan_enabled: Optional[bool] = None
    scan_frequency_hours: Optional[int] = None


class OAuthAuthorizationResponse(BaseModel):
    authorization_url: str
    state: str


# In-memory store for OAuth states (in production, use Redis or database)
oauth_states = {}


@router.get("/", response_model=List[IntegrationResponse])
async def list_integrations(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all integrations for the current user"""
    integrations = db.query(Integration).filter(Integration.user_id == current_user.id).all()
    return integrations


@router.get("/{integration_id}", response_model=IntegrationResponse)
async def get_integration(
    integration_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific integration"""
    integration = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.user_id == current_user.id
    ).first()
    
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found"
        )
    
    return integration


@router.post("/oauth/{provider}/authorize", response_model=OAuthAuthorizationResponse)
async def start_oauth_flow(
    provider: str,
    integration_name: str = Query(..., description="Name for the integration"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Start OAuth authorization flow for a provider"""
    
    # Validate provider
    valid_providers = ["google", "microsoft", "slack", "github", "notion"]
    if provider not in valid_providers:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider: {provider}"
        )
    
    try:
        # Get OAuth service
        oauth_service = get_oauth_service(provider)
        
        # Generate authorization URL
        state = secrets.token_urlsafe(32)
        authorization_url, state = oauth_service.generate_authorization_url(state)
        
        # Store state information
        oauth_states[state] = {
            "user_id": current_user.id,
            "provider": provider,
            "integration_name": integration_name,
            "created_at": datetime.utcnow()
        }
        
        security_logger.log_oauth_start(provider, current_user.email)
        
        return {
            "authorization_url": authorization_url,
            "state": state
        }
        
    except OAuthError as e:
        logger.error(f"OAuth error for {provider}", error=str(e), user_email=current_user.email)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth configuration error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error starting OAuth for {provider}", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start OAuth flow"
        )


@router.post("/oauth/{provider}/callback", response_model=IntegrationResponse)
async def oauth_callback(
    provider: str,
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db)
):
    """Handle OAuth callback and create integration"""
    
    # Verify state
    state_info = oauth_states.get(state)
    if not state_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state"
        )
    
    # Check state expiration (15 minutes max)
    if datetime.utcnow() - state_info["created_at"] > timedelta(minutes=15):
        oauth_states.pop(state, None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state expired"
        )
    
    # Verify provider matches
    if state_info["provider"] != provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provider mismatch"
        )
    
    try:
        # Get user
        user = db.query(User).filter(User.id == state_info["user_id"]).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Exchange code for tokens
        oauth_service = get_oauth_service(provider)
        token_data = await oauth_service.exchange_code_for_tokens(code, state)
        
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")
        
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to obtain access token"
            )
        
        # Get user info from provider
        user_info = await oauth_service.get_user_info(access_token)
        
        # Get organization info (if available)
        organization_name = "Unknown"
        organization_id = None
        
        try:
            if hasattr(oauth_service, 'get_organization_info'):
                org_info = await oauth_service.get_organization_info(access_token)
                organization_name = org_info.get("name", "Unknown")
                organization_id = org_info.get("domain", None)
        except Exception as e:
            logger.warning(f"Failed to get organization info for {provider}", error=str(e))
        
        # Calculate token expiration
        expires_at = None
        if expires_in:
            expires_at = datetime.utcnow() + timedelta(seconds=int(expires_in))
        
        # Map provider to integration type
        provider_type_map = {
            "google": IntegrationType.GOOGLE_WORKSPACE,
            "microsoft": IntegrationType.MICROSOFT_365,
            "slack": IntegrationType.SLACK,
            "github": IntegrationType.GITHUB,
            "notion": IntegrationType.NOTION
        }
        
        integration_type = provider_type_map.get(provider)
        if not integration_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported integration type: {provider}"
            )
        
        # Create integration
        integration = Integration(
            user_id=user.id,
            name=state_info["integration_name"],
            type=integration_type,
            status=IntegrationStatus.ACTIVE,
            access_token=access_token,  # In production, encrypt this
            refresh_token=refresh_token,  # In production, encrypt this
            expires_at=expires_at,
            organization_name=organization_name,
            organization_id=organization_id,
            scan_enabled=True,
            scan_frequency_hours=24,
            next_scan_at=datetime.utcnow() + timedelta(hours=1)  # First scan in 1 hour
        )
        
        db.add(integration)
        db.commit()
        db.refresh(integration)
        
        # Clean up OAuth state
        oauth_states.pop(state, None)
        
        security_logger.log_oauth_success(provider, user.email, organization_name)
        
        logger.info(
            "Integration created successfully",
            integration_id=integration.id,
            provider=provider,
            user_email=user.email,
            organization=organization_name
        )
        
        return integration
        
    except OAuthError as e:
        logger.error(f"OAuth callback error for {provider}", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Integration creation failed for {provider}", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create integration"
        )


@router.put("/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: int,
    update_data: IntegrationUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update an integration"""
    integration = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.user_id == current_user.id
    ).first()
    
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found"
        )
    
    # Update fields
    update_dict = update_data.dict(exclude_unset=True)
    
    for field, value in update_dict.items():
        if field == "scan_frequency_hours" and value:
            # Update next scan time when frequency changes
            integration.next_scan_at = datetime.utcnow() + timedelta(hours=value)
        setattr(integration, field, value)
    
    db.commit()
    db.refresh(integration)
    
    logger.info(
        "Integration updated",
        integration_id=integration_id,
        user_email=current_user.email,
        updates=update_dict
    )
    
    return integration


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete an integration"""
    integration = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.user_id == current_user.id
    ).first()
    
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found"
        )
    
    db.delete(integration)
    db.commit()
    
    logger.info(
        "Integration deleted",
        integration_id=integration_id,
        user_email=current_user.email
    )
    
    return {"message": "Integration deleted successfully"}


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test integration connection"""
    integration = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.user_id == current_user.id
    ).first()
    
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Integration not found"
        )
    
    try:
        # Map integration type to provider name
        type_provider_map = {
            IntegrationType.GOOGLE_WORKSPACE: "google",
            IntegrationType.MICROSOFT_365: "microsoft",
            IntegrationType.SLACK: "slack",
            IntegrationType.GITHUB: "github",
            IntegrationType.NOTION: "notion"
        }
        
        provider = type_provider_map.get(integration.type)
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported integration type"
            )
        
        # Test authentication
        oauth_service = get_oauth_service(provider)
        is_valid = await oauth_service.validate_token(integration.access_token)
        
        if is_valid:
            integration.status = IntegrationStatus.ACTIVE
            status_message = "Integration is working correctly"
        else:
            integration.status = IntegrationStatus.ERROR
            status_message = "Integration authentication failed"
        
        db.commit()
        
        return {
            "status": integration.status.value,
            "message": status_message,
            "tested_at": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(
            "Integration test failed",
            integration_id=integration_id,
            error=str(e)
        )
        
        integration.status = IntegrationStatus.ERROR
        db.commit()
        
        return {
            "status": "error",
            "message": f"Test failed: {str(e)}",
            "tested_at": datetime.utcnow()
        }
