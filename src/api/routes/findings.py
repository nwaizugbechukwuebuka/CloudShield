"""
CloudShield Findings Routes
FastAPI routes for security findings management and analysis.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel

from ..database import get_db
from ..models.findings import Finding, RiskLevel, FindingType
from ..models.integration import Integration
from ..utils.auth import get_current_user
from ..utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingResponse(BaseModel):
    """Response model for finding data"""
    id: str
    title: str
    description: str
    finding_type: str
    risk_level: str
    resource_name: str
    resource_type: str
    location: str
    remediation: str
    integration_id: str
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


@router.get("/", response_model=List[FindingResponse])
def list_findings(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Items per page"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    integration_id: Optional[str] = Query(None, description="Filter by integration"),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get a paginated list of security findings.
    """
    try:
        query = select(Finding)
        
        # Apply filters
        if risk_level:
            query = query.where(Finding.risk_level == RiskLevel(risk_level))
        
        if finding_type:
            query = query.where(Finding.finding_type == FindingType(finding_type))
        
        if integration_id:
            query = query.where(Finding.integration_id == integration_id)
        
        # Order by creation date
        query = query.order_by(desc(Finding.created_at))
        
        # Apply pagination
        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)
        
        # Execute query
        result = db.execute(query)
        findings = result.scalars().all()
        
        return [
            FindingResponse(
                id=finding.id,
                title=finding.title,
                description=finding.description,
                finding_type=finding.finding_type.value,
                risk_level=finding.risk_level.value,
                resource_name=finding.resource_name,
                resource_type=finding.resource_type,
                location=finding.location,
                remediation=finding.remediation,
                integration_id=finding.integration_id,
                created_at=finding.created_at,
                updated_at=finding.updated_at
            )
            for finding in findings
        ]
        
    except Exception as e:
        logger.error(f"Failed to list findings: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve findings")


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get detailed information for a specific finding.
    """
    try:
        result = db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        return FindingResponse(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            finding_type=finding.finding_type.value,
            risk_level=finding.risk_level.value,
            resource_name=finding.resource_name,
            resource_type=finding.resource_type,
            location=finding.location,
            remediation=finding.remediation,
            integration_id=finding.integration_id,
            created_at=finding.created_at,
            updated_at=finding.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get finding {finding_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve finding")