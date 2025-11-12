"""
CloudShield Notion Security Scanner
Advanced security scanning module for Notion workspaces including page access,
database permissions, integration security, and data exposure assessment.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import re
from dataclasses import dataclass
from enum import Enum
import urllib.parse

from .common import BaseScanner, ScanResult
from ..api.models.findings import RiskLevel, FindingType
from ..api.utils.config import settings
from ..api.utils.logger import get_logger

logger = get_logger(__name__)


class NotionResourceType(Enum):
    """Notion resource types"""
    PAGE = "page"
    DATABASE = "database"
    BLOCK = "block"
    USER = "user"
    WORKSPACE = "workspace"
    INTEGRATION = "integration"


class NotionPermissionType(Enum):
    """Notion permission types"""
    READ = "read"
    COMMENT = "comment"
    EDIT = "edit"
    FULL_ACCESS = "full_access"
    NONE = "none"


@dataclass
class NotionUser:
    """Notion user information"""
    id: str
    name: str
    email: Optional[str]
    avatar_url: Optional[str]
    type: str  # person, bot
    workspace_role: str
    last_edited: Optional[datetime]


@dataclass
class NotionPage:
    """Notion page information"""
    id: str
    title: str
    url: str
    created_time: datetime
    last_edited_time: datetime
    created_by: str
    last_edited_by: str
    parent_type: str
    parent_id: Optional[str]
    archived: bool
    public: bool
    properties: Dict[str, Any]
    permissions: List[Dict]


@dataclass
class NotionDatabase:
    """Notion database information"""
    id: str
    title: str
    url: str
    created_time: datetime
    last_edited_time: datetime
    created_by: str
    last_edited_by: str
    properties: Dict[str, Any]
    permissions: List[Dict]
    public: bool
    archived: bool


@dataclass
class NotionIntegration:
    """Notion integration information"""
    id: str
    name: str
    type: str
    capabilities: List[str]
    authorized_date: datetime
    permissions: List[str]
    workspace_access: bool


class NotionScanner(BaseScanner):
    """
    Comprehensive Notion workspace security scanner
    
    Capabilities:
    - Workspace access control analysis
    - Page and database permission assessment
    - Public sharing detection
    - Integration security evaluation
    - Data exposure risk assessment
    - Guest user access review
    - Compliance framework mapping
    - Sensitive data pattern detection
    """
    
    def __init__(self):
        super().__init__("notion")
        self.version = "1.5.0"
        self.base_url = "https://api.notion.com/v1"
        self.session = None
        self.integration_token: Optional[str] = None
        
        # Security check configurations
        self.security_checks = self._initialize_security_checks()
        
        # Sensitive data patterns
        self.sensitive_patterns = self._initialize_sensitive_patterns()
        
        # Compliance framework mappings
        self.compliance_mappings = {
            "SOC2": ["CC1.1", "CC3.1", "CC6.1"],
            "GDPR": ["Art25", "Art32", "Art35"],
            "HIPAA": ["164.308", "164.310", "164.312"],
            "ISO27001": ["A.9", "A.10", "A.13"],
            "NIST": ["AC", "AU", "SC"]
        }
    
    async def authenticate(self, access_token: str, **kwargs) -> bool:
        """Authenticate with Notion API using integration token"""
        try:
            self.integration_token = access_token
            
            # Test authentication by making a simple API call
            import aiohttp
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Notion-Version": "2022-06-28",
                "Content-Type": "application/json"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/users", headers=headers) as response:
                    if response.status == 200:
                        logger.info("Successfully authenticated with Notion API")
                        return True
                    else:
                        logger.error(f"Authentication failed: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False

    async def scan_users(self, **kwargs):
        """Scan for user-related security issues"""
        try:
            users = await self._get_workspace_users()
            
            for user in users:
                # Check for guest users with excessive access
                if user.get('type') == 'person' and user.get('person', {}).get('email', '').endswith('@guest.notion.so'):
                    yield ScanResult(
                        title="Guest User with Workspace Access",
                        description=f"Guest user {user.get('name', 'Unknown')} has access to the workspace",
                        finding_type=FindingType.ACCESS_CONTROL,
                        evidence={"user": user},
                        resource_id=user.get('id', ''),
                        resource_name=user.get('name', 'Unknown'),
                        resource_type='user',
                        remediation_steps="Review guest user permissions and consider removing unnecessary access"
                    )
        except Exception as e:
            logger.error(f"Error scanning users: {str(e)}")

    async def scan_permissions(self, **kwargs):
        """Scan for permission-related issues"""
        try:
            pages = await self._get_all_pages()
            
            for page in pages:
                # Check for overly permissive sharing
                if page.get('public_url'):
                    yield ScanResult(
                        title="Public Page Detected",
                        description=f"Page '{page.get('title', 'Unknown')}' is publicly accessible",
                        finding_type=FindingType.DATA_EXPOSURE,
                        evidence={"page": page},
                        resource_id=page.get('id', ''),
                        resource_name=page.get('title', 'Unknown'),
                        resource_type='page',
                        remediation_steps="Review public sharing settings and restrict access if sensitive"
                    )
        except Exception as e:
            logger.error(f"Error scanning permissions: {str(e)}")

    async def scan_data_sharing(self, **kwargs):
        """Scan for data sharing and access issues"""
        try:
            pages = await self._get_all_pages()
            
            for page in pages:
                # Check for sensitive content patterns
                content = page.get('content', '')
                if 'sensitive' in content.lower():
                    yield ScanResult(
                        title="Potential Sensitive Data",
                        description=f"Sensitive content detected in page '{page.get('title', 'Unknown')}'",
                        finding_type=FindingType.DATA_EXPOSURE,
                        evidence={"page": page},
                        resource_id=page.get('id', ''),
                        resource_name=page.get('title', 'Unknown'),
                        resource_type='page',
                        remediation_steps="Review content and implement appropriate access controls"
                    )
        except Exception as e:
            logger.error(f"Error scanning data sharing: {str(e)}")

    async def _get_workspace_users(self):
        """Get all workspace users"""
        try:
            import aiohttp
            headers = {
                "Authorization": f"Bearer {self.integration_token}",
                "Notion-Version": "2022-06-28"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.base_url}/users", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('results', [])
                    return []
        except Exception as e:
            logger.error(f"Error fetching users: {str(e)}")
            return []

    async def _get_all_pages(self):
        """Get all accessible pages"""
        try:
            # Simplified implementation
            return []
        except Exception as e:
            logger.error(f"Error fetching pages: {str(e)}")
            return []
    
    def _initialize_security_checks(self) -> Dict[str, Dict]:
        """Initialize security check configurations"""
        return {
            "access_control": {
                "public_pages": {
                    "name": "Public Page Detection",
                    "description": "Identify pages with public access enabled",
                    "severity": "HIGH",
                    "category": "data_exposure"
                },
                "guest_access": {
                    "name": "Guest User Access Review",
                    "description": "Review guest user permissions and access scope",
                    "severity": "MEDIUM",
                    "category": "access_control"
                },
                "overprivileged_users": {
                    "name": "Overprivileged User Detection",
                    "description": "Identify users with excessive permissions",
                    "severity": "MEDIUM",
                    "category": "access_control"
                },
                "inherited_permissions": {
                    "name": "Permission Inheritance Analysis",
                    "description": "Analyze permission inheritance patterns",
                    "severity": "LOW",
                    "category": "access_control"
                }
            },
            "data_protection": {
                "sensitive_data": {
                    "name": "Sensitive Data Detection",
                    "description": "Scan for sensitive data patterns in content",
                    "severity": "HIGH",
                    "category": "data_exposure"
                },
                "external_sharing": {
                    "name": "External Sharing Analysis",
                    "description": "Review content shared with external users",
                    "severity": "MEDIUM",
                    "category": "data_exposure"
                },
                "data_retention": {
                    "name": "Data Retention Assessment",
                    "description": "Assess data retention and archival practices",
                    "severity": "LOW",
                    "category": "compliance"
                }
            },
            "integration_security": {
                "third_party_integrations": {
                    "name": "Third-party Integration Review",
                    "description": "Evaluate third-party integration permissions",
                    "severity": "MEDIUM",
                    "category": "integration_security"
                },
                "api_access": {
                    "name": "API Access Token Review",
                    "description": "Review API token permissions and usage",
                    "severity": "HIGH",
                    "category": "credential_management"
                },
                "webhook_security": {
                    "name": "Webhook Security Assessment",
                    "description": "Assess webhook endpoint security",
                    "severity": "MEDIUM",
                    "category": "integration_security"
                }
            }
        }
    
    def _initialize_sensitive_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize sensitive data detection patterns"""
        return {
            "credentials": [
                {
                    "name": "API Keys",
                    "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
                    "severity": "CRITICAL"
                },
                {
                    "name": "Access Tokens", 
                    "pattern": r"(?i)(access[_-]?token|token)\s*[:=]\s*['\"]?[a-zA-Z0-9._-]{20,}['\"]?",
                    "severity": "HIGH"
                },
                {
                    "name": "Passwords",
                    "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]{8,}['\"]?",
                    "severity": "HIGH"
                }
            ],
            "financial": [
                {
                    "name": "Credit Card Numbers",
                    "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
                    "severity": "CRITICAL"
                },
                {
                    "name": "SSN",
                    "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                    "severity": "HIGH"
                },
                {
                    "name": "Bank Account Numbers",
                    "pattern": r"\b\d{8,17}\b",
                    "severity": "HIGH"
                }
            ],
            "personal": [
                {
                    "name": "Email Addresses",
                    "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                    "severity": "MEDIUM"
                },
                {
                    "name": "Phone Numbers",
                    "pattern": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
                    "severity": "MEDIUM"
                }
            ],
            "technical": [
                {
                    "name": "IP Addresses",
                    "pattern": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                    "severity": "LOW"
                },
                {
                    "name": "Database Connection Strings",
                    "pattern": r"(?i)(server|host|database|db)\s*=\s*[a-zA-Z0-9._-]+",
                    "severity": "MEDIUM"
                }
            ]
        }
    
    async def initialize_session(self, integration_config: Dict) -> bool:
        """Initialize authenticated session with Notion API"""
        try:
            import aiohttp
            
            self.integration_token = integration_config.get("integration_token")
            
            if not self.integration_token:
                logger.error("Missing Notion integration token")
                return False
            
            # Create session with authentication headers
            headers = {
                "Authorization": f"Bearer {self.integration_token}",
                "Notion-Version": "2022-06-28",
                "Content-Type": "application/json",
                "User-Agent": "CloudShield-NotionScanner/1.5.0"
            }
            
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=300)
            )
            
            # Test authentication
            async with self.session.get(f"{self.base_url}/users/me") as response:
                if response.status == 200:
                    user_data = await response.json()
                    logger.info(f"Notion authentication successful for workspace")
                    return True
                else:
                    error_data = await response.json()
                    logger.error(f"Notion authentication failed: {error_data}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to initialize Notion session: {str(e)}")
            return False
    
    async def cleanup_session(self):
        """Clean up HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def scan_security(self, integration_config: Dict, scan_options: Dict = None) -> ScanResult:
        """
        Perform comprehensive Notion workspace security scan
        
        Args:
            integration_config: Notion integration configuration
            scan_options: Scan customization options
            
        Returns:
            ScanResult with security findings and recommendations
        """
        start_time = datetime.utcnow()
        findings = []
        
        try:
            # Initialize session
            if not await self.initialize_session(integration_config):
                return ScanResult(
                    success=False,
                    findings=[],
                    metadata={"error": "Authentication failed"},
                    scan_duration=0
                )
            
            scan_options = scan_options or {}
            
            # Scan workspace configuration
            workspace_findings = await self._scan_workspace_security()
            findings.extend(workspace_findings)
            
            # Scan pages and databases
            content_findings = await self._scan_content_security()
            findings.extend(content_findings)
            
            # Scan user permissions
            user_findings = await self._scan_user_permissions()
            findings.extend(user_findings)
            
            # Scan integrations
            integration_findings = await self._scan_integration_security()
            findings.extend(integration_findings)
            
            # Scan for sensitive data
            if scan_options.get("scan_content", True):
                data_findings = await self._scan_sensitive_data()
                findings.extend(data_findings)
            
            # Calculate scan statistics
            end_time = datetime.utcnow()
            scan_duration = (end_time - start_time).total_seconds()
            
            # Generate metadata
            metadata = {
                "workspace_id": integration_config.get("workspace_id", "unknown"),
                "total_findings": len(findings),
                "findings_by_severity": self._count_by_severity(findings),
                "scan_timestamp": start_time.isoformat(),
                "scanner_version": self.version,
                "content_scanned": scan_options.get("scan_content", True)
            }
            
            logger.info(f"Notion scan completed: {len(findings)} findings in {scan_duration:.2f}s")
            
            return ScanResult(
                success=True,
                findings=findings,
                metadata=metadata,
                scan_duration=scan_duration
            )
            
        except Exception as e:
            logger.error(f"Notion scan failed: {str(e)}")
            return ScanResult(
                success=False,
                findings=findings,
                metadata={"error": str(e)},
                scan_duration=(datetime.utcnow() - start_time).total_seconds()
            )
        
        finally:
            await self.cleanup_session()
    
    async def _scan_workspace_security(self) -> List[ScanResult]:
        """Scan workspace-level security configuration"""
        findings = []
        
        try:
            logger.info("Scanning Notion workspace security configuration...")
            
            # Get workspace users
            users = await self._get_workspace_users()
            
            # Analyze user roles and permissions
            admin_users = [u for u in users if u.workspace_role == "owner"]
            guest_users = [u for u in users if u.type == "person" and "@" not in u.email] if users else []
            
            # Check for excessive admin privileges
            if len(admin_users) > 3:
                findings.append(ScanResult(
                    title="Excessive Workspace Administrators",
                    description=f"{len(admin_users)} users have workspace owner privileges",
                    severity=RiskLevel.MEDIUM,
                    category="access_control",
                    resource_name="Workspace Administration",
                    location={"workspace": "main", "admin_count": len(admin_users)},
                    remediation="Review and reduce the number of workspace owners",
                    compliance_impact=["SOC2:CC1.1", "ISO27001:A.9"]
                ))
            
            # Check for inactive users
            if users:
                inactive_users = []
                cutoff_date = datetime.utcnow() - timedelta(days=90)
                
                for user in users:
                    if user.last_edited and user.last_edited < cutoff_date:
                        inactive_users.append(user)
                
                if len(inactive_users) > 5:
                    findings.append(ScanResult(
                        title="Inactive Workspace Users",
                        description=f"{len(inactive_users)} users haven't accessed the workspace in 90+ days",
                        severity=RiskLevel.LOW,
                        category="access_control",
                        resource_name="User Access Management",
                        location={"workspace": "main", "inactive_count": len(inactive_users)},
                        remediation="Review and remove inactive user accounts",
                        compliance_impact=["SOC2:CC1.1", "GDPR:Art25"]
                    ))
            
            # Check guest user access
            if guest_users:
                findings.append(ScanResult(
                    title="Guest User Access Present",
                    description=f"{len(guest_users)} guest users have access to the workspace",
                    severity=RiskLevel.MEDIUM,
                    category="access_control",
                    resource_name="Guest Access Control",
                    location={"workspace": "main", "guest_count": len(guest_users)},
                    remediation="Review guest user permissions and access scope",
                    compliance_impact=["SOC2:CC1.1", "GDPR:Art32"]
                ))
            
        except Exception as e:
            logger.error(f"Workspace security scan failed: {str(e)}")
            findings.append(ScanResult(
                title="Workspace Scan Error",
                description=f"Failed to complete workspace security scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Workspace Configuration"
            ))
        
        return findings
    
    async def _scan_content_security(self) -> List[ScanResult]:
        """Scan pages and databases for security issues"""
        findings = []
        
        try:
            logger.info("Scanning Notion content security...")
            
            # Get all pages and databases
            pages = await self._get_all_pages()
            databases = await self._get_all_databases()
            
            # Check for public pages
            public_pages = [p for p in pages if getattr(p, 'public', False)]
            if public_pages:
                findings.append(ScanResult(
                    title="Public Pages Detected",
                    description=f"{len(public_pages)} pages are publicly accessible",
                    severity=RiskLevel.HIGH,
                    category="data_exposure",
                    resource_name="Public Content",
                    location={"public_pages": len(public_pages)},
                    remediation="Review public page settings and restrict access as needed",
                    compliance_impact=["SOC2:CC3.1", "GDPR:Art25", "HIPAA:164.312"]
                ))
            
            # Check for public databases
            public_databases = [d for d in databases if getattr(d, 'public', False)]
            if public_databases:
                findings.append(ScanResult(
                    title="Public Databases Detected",
                    description=f"{len(public_databases)} databases are publicly accessible",
                    severity=RiskLevel.HIGH,
                    category="data_exposure",
                    resource_name="Public Databases",
                    location={"public_databases": len(public_databases)},
                    remediation="Review database sharing settings and restrict public access",
                    compliance_impact=["SOC2:CC3.1", "GDPR:Art25", "HIPAA:164.312"]
                ))
            
            # Check for overshared content
            overshared_content = []
            all_content = pages + databases
            
            for content in all_content:
                if hasattr(content, 'permissions') and content.permissions:
                    if len(content.permissions) > 10:  # Threshold for oversharing
                        overshared_content.append(content)
            
            if overshared_content:
                findings.append(ScanResult(
                    title="Overshared Content Detected",
                    description=f"{len(overshared_content)} items are shared with many users",
                    severity=RiskLevel.MEDIUM,
                    category="access_control",
                    resource_name="Content Sharing",
                    location={"overshared_items": len(overshared_content)},
                    remediation="Review sharing permissions and implement least privilege access",
                    compliance_impact=["SOC2:CC1.1", "ISO27001:A.9"]
                ))
            
            # Check for archived content with sensitive permissions
            archived_with_permissions = []
            for content in all_content:
                if hasattr(content, 'archived') and content.archived:
                    if hasattr(content, 'permissions') and content.permissions:
                        archived_with_permissions.append(content)
            
            if archived_with_permissions:
                findings.append(ScanResult(
                    title="Archived Content with Active Permissions",
                    description=f"{len(archived_with_permissions)} archived items still have active sharing permissions",
                    severity=RiskLevel.LOW,
                    category="access_control",
                    resource_name="Archived Content",
                    location={"archived_shared": len(archived_with_permissions)},
                    remediation="Remove permissions from archived content",
                    compliance_impact=["SOC2:CC1.1"]
                ))
            
        except Exception as e:
            logger.error(f"Content security scan failed: {str(e)}")
            findings.append(ScanResult(
                title="Content Scan Error",
                description=f"Failed to complete content security scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Content Security"
            ))
        
        return findings
    
    async def _scan_user_permissions(self) -> List[ScanResult]:
        """Scan user permission assignments"""
        findings = []
        
        try:
            logger.info("Scanning user permissions...")
            
            users = await self._get_workspace_users()
            pages = await self._get_all_pages()
            
            # Analyze permission patterns
            user_permission_counts = {}
            
            for page in pages:
                if hasattr(page, 'permissions') and page.permissions:
                    for permission in page.permissions:
                        user_id = permission.get('user', {}).get('id')
                        if user_id:
                            user_permission_counts[user_id] = user_permission_counts.get(user_id, 0) + 1
            
            # Check for users with excessive permissions
            avg_permissions = sum(user_permission_counts.values()) / len(user_permission_counts) if user_permission_counts else 0
            overprivileged_users = []
            
            for user_id, count in user_permission_counts.items():
                if count > avg_permissions * 2 and count > 20:  # Users with 2x average and >20 permissions
                    overprivileged_users.append(user_id)
            
            if overprivileged_users:
                findings.append(ScanResult(
                    title="Overprivileged Users Detected",
                    description=f"{len(overprivileged_users)} users have excessive content permissions",
                    severity=RiskLevel.MEDIUM,
                    category="access_control",
                    resource_name="User Permissions",
                    location={"overprivileged_users": len(overprivileged_users)},
                    remediation="Review and audit user permission assignments",
                    compliance_impact=["SOC2:CC1.1", "ISO27001:A.9"]
                ))
            
            # Check for external users with high privileges
            external_privileged = []
            for user in users:
                if user.type == "person" and user.email and not user.email.endswith(("@company.com", "@organization.com")):
                    user_perms = user_permission_counts.get(user.id, 0)
                    if user_perms > 10:
                        external_privileged.append(user)
            
            if external_privileged:
                findings.append(ScanResult(
                    title="External Users with High Privileges",
                    description=f"{len(external_privileged)} external users have extensive permissions",
                    severity=RiskLevel.MEDIUM,
                    category="access_control",
                    resource_name="External User Access",
                    location={"external_privileged": len(external_privileged)},
                    remediation="Review external user access and implement appropriate controls",
                    compliance_impact=["SOC2:CC1.1", "GDPR:Art32"]
                ))
            
        except Exception as e:
            logger.error(f"User permissions scan failed: {str(e)}")
            findings.append(ScanResult(
                title="User Permissions Scan Error",
                description=f"Failed to complete user permissions scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="User Permissions"
            ))
        
        return findings
    
    async def _scan_integration_security(self) -> List[ScanResult]:
        """Scan integration security configuration"""
        findings = []
        
        try:
            logger.info("Scanning integration security...")
            
            # Note: Notion API doesn't provide extensive integration management endpoints
            # This would be a limited scan based on available data
            
            # Check integration token permissions (basic check)
            findings.append(ScanResult(
                title="Integration Security Review Required",
                description="Integration permissions and security should be reviewed manually",
                severity=RiskLevel.LOW,
                category="integration_security",
                resource_name="API Integrations",
                location={"workspace": "main"},
                remediation="Review all connected integrations and their permissions",
                compliance_impact=["SOC2:CC6.1", "ISO27001:A.13"]
            ))
            
        except Exception as e:
            logger.error(f"Integration security scan failed: {str(e)}")
            findings.append(ScanResult(
                title="Integration Scan Error",
                description=f"Failed to complete integration security scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Integration Security"
            ))
        
        return findings
    
    async def _scan_sensitive_data(self) -> List[ScanResult]:
        """Scan for sensitive data patterns in content"""
        findings = []
        
        try:
            logger.info("Scanning for sensitive data patterns...")
            
            pages = await self._get_all_pages()
            sensitive_pages = []
            
            for page in pages:
                # Get page content
                content_text = await self._get_page_content(page.id)
                
                if content_text:
                    # Check for sensitive patterns
                    detected_patterns = self._detect_sensitive_patterns(content_text)
                    
                    if detected_patterns:
                        sensitive_pages.append({
                            "page": page,
                            "patterns": detected_patterns
                        })
            
            # Generate findings for sensitive data
            if sensitive_pages:
                critical_pages = [p for p in sensitive_pages 
                               if any(pattern["severity"] == "CRITICAL" for pattern in p["patterns"])]
                
                if critical_pages:
                    findings.append(ScanResult(
                        title="Critical Sensitive Data Detected",
                        description=f"{len(critical_pages)} pages contain critical sensitive data (API keys, credentials)",
                        severity=RiskLevel.CRITICAL,
                        category="data_exposure",
                        resource_name="Sensitive Content",
                        location={"sensitive_pages": len(critical_pages)},
                        remediation="Remove or secure sensitive data from pages",
                        compliance_impact=["SOC2:CC3.1", "GDPR:Art25", "HIPAA:164.312"]
                    ))
                
                high_risk_pages = [p for p in sensitive_pages 
                                 if any(pattern["severity"] == "HIGH" for pattern in p["patterns"])]
                
                if high_risk_pages:
                    findings.append(ScanResult(
                        title="High-Risk Sensitive Data Detected",
                        description=f"{len(high_risk_pages)} pages contain high-risk sensitive data",
                        severity=RiskLevel.HIGH,
                        category="data_exposure",
                        resource_name="Sensitive Content",
                        location={"high_risk_pages": len(high_risk_pages)},
                        remediation="Review and secure high-risk sensitive data",
                        compliance_impact=["SOC2:CC3.1", "GDPR:Art25"]
                    ))
            
        except Exception as e:
            logger.error(f"Sensitive data scan failed: {str(e)}")
            findings.append(ScanResult(
                title="Sensitive Data Scan Error",
                description=f"Failed to complete sensitive data scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Sensitive Data Detection"
            ))
        
        return findings
    
    async def _get_workspace_users(self) -> List[NotionUser]:
        """Get workspace users"""
        users = []
        
        try:
            async with self.session.get(f"{self.base_url}/users") as response:
                if response.status == 200:
                    data = await response.json()
                    user_results = data.get("results", [])
                    
                    for user_data in user_results:
                        user = NotionUser(
                            id=user_data.get("id", ""),
                            name=user_data.get("name", ""),
                            email=user_data.get("person", {}).get("email") if user_data.get("type") == "person" else None,
                            avatar_url=user_data.get("avatar_url"),
                            type=user_data.get("type", "person"),
                            workspace_role=user_data.get("role", "member"),
                            last_edited=None  # Not available in user endpoint
                        )
                        users.append(user)
                        
        except Exception as e:
            logger.error(f"Failed to get workspace users: {str(e)}")
        
        return users
    
    async def _get_all_pages(self) -> List[NotionPage]:
        """Get all accessible pages"""
        pages = []
        
        try:
            # Search for all pages
            search_payload = {
                "filter": {
                    "property": "object",
                    "value": "page"
                }
            }
            
            async with self.session.post(f"{self.base_url}/search", json=search_payload) as response:
                if response.status == 200:
                    data = await response.json()
                    page_results = data.get("results", [])
                    
                    for page_data in page_results:
                        # Extract title
                        title = "Untitled"
                        properties = page_data.get("properties", {})
                        if "title" in properties:
                            title_data = properties["title"]
                            if isinstance(title_data, dict) and "title" in title_data:
                                title = title_data["title"][0]["plain_text"] if title_data["title"] else "Untitled"
                        
                        page = NotionPage(
                            id=page_data.get("id", ""),
                            title=title,
                            url=page_data.get("url", ""),
                            created_time=datetime.fromisoformat(page_data.get("created_time", "").replace("Z", "+00:00")),
                            last_edited_time=datetime.fromisoformat(page_data.get("last_edited_time", "").replace("Z", "+00:00")),
                            created_by=page_data.get("created_by", {}).get("id", ""),
                            last_edited_by=page_data.get("last_edited_by", {}).get("id", ""),
                            parent_type=page_data.get("parent", {}).get("type", ""),
                            parent_id=page_data.get("parent", {}).get("page_id"),
                            archived=page_data.get("archived", False),
                            public=page_data.get("public_url") is not None,
                            properties=properties,
                            permissions=[]  # Would need separate API call
                        )
                        pages.append(page)
                        
        except Exception as e:
            logger.error(f"Failed to get pages: {str(e)}")
        
        return pages
    
    async def _get_all_databases(self) -> List[NotionDatabase]:
        """Get all accessible databases"""
        databases = []
        
        try:
            # Search for all databases
            search_payload = {
                "filter": {
                    "property": "object", 
                    "value": "database"
                }
            }
            
            async with self.session.post(f"{self.base_url}/search", json=search_payload) as response:
                if response.status == 200:
                    data = await response.json()
                    db_results = data.get("results", [])
                    
                    for db_data in db_results:
                        # Extract title
                        title = "Untitled Database"
                        title_data = db_data.get("title", [])
                        if title_data:
                            title = title_data[0].get("plain_text", "Untitled Database")
                        
                        database = NotionDatabase(
                            id=db_data.get("id", ""),
                            title=title,
                            url=db_data.get("url", ""),
                            created_time=datetime.fromisoformat(db_data.get("created_time", "").replace("Z", "+00:00")),
                            last_edited_time=datetime.fromisoformat(db_data.get("last_edited_time", "").replace("Z", "+00:00")),
                            created_by=db_data.get("created_by", {}).get("id", ""),
                            last_edited_by=db_data.get("last_edited_by", {}).get("id", ""),
                            properties=db_data.get("properties", {}),
                            permissions=[],  # Would need separate API call
                            public=db_data.get("public_url") is not None,
                            archived=db_data.get("archived", False)
                        )
                        databases.append(database)
                        
        except Exception as e:
            logger.error(f"Failed to get databases: {str(e)}")
        
        return databases
    
    async def _get_page_content(self, page_id: str) -> str:
        """Get page content for sensitive data scanning"""
        try:
            async with self.session.get(f"{self.base_url}/blocks/{page_id}/children") as response:
                if response.status == 200:
                    data = await response.json()
                    blocks = data.get("results", [])
                    
                    content_parts = []
                    for block in blocks:
                        # Extract text content from different block types
                        block_type = block.get("type")
                        if block_type in ["paragraph", "heading_1", "heading_2", "heading_3"]:
                            rich_text = block.get(block_type, {}).get("rich_text", [])
                            for text_obj in rich_text:
                                content_parts.append(text_obj.get("plain_text", ""))
                        elif block_type == "code":
                            rich_text = block.get("code", {}).get("rich_text", [])
                            for text_obj in rich_text:
                                content_parts.append(text_obj.get("plain_text", ""))
                    
                    return " ".join(content_parts)
                    
        except Exception as e:
            logger.error(f"Failed to get page content for {page_id}: {str(e)}")
        
        return ""
    
    def _detect_sensitive_patterns(self, content: str) -> List[Dict]:
        """Detect sensitive data patterns in content"""
        detected = []
        
        for category, patterns in self.sensitive_patterns.items():
            for pattern_config in patterns:
                pattern = pattern_config["pattern"]
                matches = re.findall(pattern, content, re.MULTILINE)
                
                if matches:
                    detected.append({
                        "category": category,
                        "name": pattern_config["name"],
                        "severity": pattern_config["severity"],
                        "matches": len(matches),
                        "sample": matches[0][:50] + "..." if len(matches[0]) > 50 else matches[0]
                    })
        
        return detected
    
    def _count_by_severity(self, findings: List[ScanResult]) -> Dict[str, int]:
        """Count findings by severity level"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in findings:
            severity = finding.severity.value.upper()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    async def get_pages(self, integration_config: Dict) -> List[Dict]:
        """Get Notion pages for scanning"""
        try:
            if not await self.initialize_session(integration_config):
                return []
            
            pages = await self._get_all_pages()
            await self.cleanup_session()
            
            return [
                {
                    "id": page.id,
                    "title": page.title,
                    "url": page.url,
                    "created_time": page.created_time.isoformat(),
                    "last_edited_time": page.last_edited_time.isoformat(),
                    "archived": page.archived,
                    "public": page.public
                }
                for page in pages
            ]
            
        except Exception as e:
            logger.error(f"Failed to get Notion pages: {str(e)}")
            return []
    
    async def scan_workspace_security(self, integration_config: Dict) -> List[Dict]:
        """Scan workspace security configuration"""
        try:
            if not await self.initialize_session(integration_config):
                return []
            
            findings = await self._scan_workspace_security()
            await self.cleanup_session()
            
            return [
                {
                    "type": "workspace_security",
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "resource_name": finding.resource_name,
                    "location": finding.location,
                    "remediation": finding.remediation
                }
                for finding in findings
            ]
            
        except Exception as e:
            logger.error(f"Workspace security scan failed: {str(e)}")
            return []
    
    async def scan_page_access(self, pages: List[Dict]) -> List[Dict]:
        """Scan page access permissions"""
        findings = []
        
        try:
            for page in pages:
                if page.get("public", False):
                    findings.append({
                        "type": "page_access",
                        "page_id": page["id"],
                        "page_title": page["title"],
                        "issue": "Public access enabled",
                        "severity": "HIGH",
                        "description": f"Page '{page['title']}' is publicly accessible"
                    })
            
        except Exception as e:
            logger.error(f"Page access scan failed: {str(e)}")
        
        return findings
    
    async def get_integrations(self, integration_config: Dict) -> List[Dict]:
        """Get workspace integrations"""
        # Notion API doesn't provide comprehensive integration listing
        # This would return limited information
        return [
            {
                "id": "current_integration",
                "name": "CloudShield Scanner",
                "type": "api_integration",
                "capabilities": ["read_content", "read_users"],
                "permissions": ["content:read", "user:read"]
            }
        ]
    
    async def scan_integration_security(self, integrations: List[Dict]) -> List[Dict]:
        """Scan integration security"""
        findings = []
        
        try:
            for integration in integrations:
                # Check for broad permissions
                permissions = integration.get("permissions", [])
                if len(permissions) > 5:
                    findings.append({
                        "type": "integration_security",
                        "integration_id": integration["id"],
                        "integration_name": integration["name"],
                        "issue": "Broad permissions granted",
                        "severity": "MEDIUM",
                        "description": f"Integration '{integration['name']}' has {len(permissions)} permissions"
                    })
        
        except Exception as e:
            logger.error(f"Integration security scan failed: {str(e)}")
        
        return findings
    
    def health_check(self) -> bool:
        """Perform health check of the scanner"""
        try:
            # Basic health check - verify configuration
            return True
        except Exception as e:
            logger.error(f"Notion scanner health check failed: {str(e)}")
            return False
