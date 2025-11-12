"""
CloudShield Scan Service
Comprehensive scanning orchestration service for security assessments across multiple SaaS platforms.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select, update, delete, and_, or_, desc, func
from sqlalchemy.sql import text

from ..database import get_db
from ..models.findings import Finding, Scan, ScanStatus, RiskLevel
from ..models.integration import Integration, IntegrationType
from ..models.user import User
from ..utils.config import settings
from ..utils.logger import get_logger
from .alert_services import get_alert_service, AlertSeverity, AlertCategory

# Import scanner modules
from ...scanner.github import GitHubScanner
from ...scanner.google_workspace import GoogleWorkspaceScanner
from ...scanner.microsoft_365 import Microsoft365Scanner
from ...scanner.slack import SlackScanner
from ...scanner.notion import NotionScanner


logger = get_logger(__name__)


class ScanType(Enum):
    """Types of security scans"""
    FULL = "full"
    INCREMENTAL = "incremental"
    QUICK = "quick"
    COMPLIANCE = "compliance"
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    ACCESS_CONTROL = "access_control"
    DATA_EXPOSURE = "data_exposure"


class ScanPriority(Enum):
    """Scan execution priorities"""
    LOW = 1
    NORMAL = 3
    HIGH = 5
    CRITICAL = 7
    EMERGENCY = 9


@dataclass
class ScanConfiguration:
    """Configuration for scan operations"""
    scan_type: ScanType
    integration_id: str
    priority: ScanPriority = ScanPriority.NORMAL
    deep_scan: bool = False
    compliance_frameworks: List[str] = None
    custom_rules: List[Dict] = None
    exclusions: List[str] = None
    timeout: int = 3600  # 1 hour default
    max_concurrent: int = 5
    retry_attempts: int = 3
    notification_channels: List[str] = None

    def __post_init__(self):
        if self.compliance_frameworks is None:
            self.compliance_frameworks = []
        if self.custom_rules is None:
            self.custom_rules = []
        if self.exclusions is None:
            self.exclusions = []
        if self.notification_channels is None:
            self.notification_channels = []


@dataclass
class ScanResult:
    """Result of a security scan operation"""
    scan_id: str
    integration_id: str
    scan_type: ScanType
    status: ScanStatus
    findings: List[Dict]
    statistics: Dict[str, Any]
    metadata: Dict[str, Any]
    start_time: datetime
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None

    def __post_init__(self):
        if self.end_time is None and self.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
            self.end_time = datetime.utcnow()


class CloudShieldScanService:
    """
    Advanced security scanning orchestration service for CloudShield platform
    
    Features:
    - Multi-platform scanning (GitHub, Google Workspace, Microsoft 365, Slack, Notion)
    - Parallel scan execution with resource management
    - Intelligent result aggregation and deduplication
    - Compliance framework mapping (SOC2, GDPR, HIPAA, ISO27001)
    - Custom security rule engine
    - Real-time scan progress tracking
    - Advanced caching and optimization
    - Comprehensive audit logging
    """
    
    def __init__(self):
        self.scanner_registry: Dict[IntegrationType, Any] = {}
        self.active_scans: Dict[str, Dict] = {}
        self.scan_cache: Dict[str, ScanResult] = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Initialize scanner modules
        self._initialize_scanners()
        
        # Alert service integration
        self.alert_service = get_alert_service()
        
        # Compliance framework mappings
        self.compliance_mappings = self._initialize_compliance_mappings()
        
        # Security rule engine
        self.security_rules = self._initialize_security_rules()
        
    def _initialize_scanners(self):
        """Initialize all scanner modules"""
        try:
            self.scanner_registry = {
                IntegrationType.GITHUB: GitHubScanner(),
                IntegrationType.GOOGLE_WORKSPACE: GoogleWorkspaceScanner(),
                IntegrationType.MICROSOFT_365: Microsoft365Scanner(),
                IntegrationType.SLACK: SlackScanner(),
                IntegrationType.NOTION: NotionScanner()
            }
            logger.info("Initialized scanner modules for all supported integrations")
        except Exception as e:
            logger.error(f"Failed to initialize scanner modules: {str(e)}")
    
    def _initialize_compliance_mappings(self) -> Dict[str, Dict]:
        """Initialize compliance framework to control mappings"""
        return {
            "SOC2": {
                "CC1.1": ["authentication", "access_control"],
                "CC2.1": ["network_security", "configuration"],
                "CC3.1": ["data_exposure", "encryption"],
                "CC4.1": ["vulnerability", "configuration"],
                "CC5.1": ["access_control", "authentication"],
                "CC6.1": ["compliance", "configuration"],
                "CC7.1": ["network_security", "encryption"],
                "CC8.1": ["vulnerability", "data_exposure"]
            },
            "GDPR": {
                "Art25": ["encryption", "data_exposure"],
                "Art32": ["authentication", "access_control"],
                "Art35": ["data_exposure", "compliance"],
                "Art5": ["data_exposure", "configuration"]
            },
            "HIPAA": {
                "164.308": ["access_control", "authentication"],
                "164.310": ["encryption", "configuration"],
                "164.312": ["encryption", "data_exposure"],
                "164.314": ["compliance", "access_control"]
            },
            "ISO27001": {
                "A.9": ["access_control", "authentication"],
                "A.10": ["encryption", "configuration"],
                "A.12": ["vulnerability", "configuration"],
                "A.13": ["network_security", "data_exposure"],
                "A.14": ["configuration", "compliance"]
            },
            "NIST": {
                "AC": ["access_control", "authentication"],
                "AU": ["compliance", "configuration"],
                "CA": ["vulnerability", "compliance"],
                "CM": ["configuration", "compliance"],
                "SC": ["encryption", "network_security"],
                "SI": ["vulnerability", "data_exposure"]
            }
        }
    
    def _initialize_security_rules(self) -> Dict[str, Dict]:
        """Initialize security scanning rules"""
        return {
            "high_risk_patterns": [
                {
                    "name": "exposed_secrets",
                    "pattern": r"(?i)(password|passwd|pwd|secret|key|token|api[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]+['\"]?",
                    "severity": "CRITICAL",
                    "category": "data_exposure"
                },
                {
                    "name": "aws_keys",
                    "pattern": r"AKIA[0-9A-Z]{16}",
                    "severity": "CRITICAL", 
                    "category": "data_exposure"
                },
                {
                    "name": "private_keys",
                    "pattern": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                    "severity": "HIGH",
                    "category": "data_exposure"
                },
                {
                    "name": "database_urls",
                    "pattern": r"(mongodb://|postgres://|mysql://|redis://)[^\s]+",
                    "severity": "HIGH",
                    "category": "configuration"
                }
            ],
            "access_control_rules": [
                {
                    "name": "public_repositories",
                    "description": "Public repositories with sensitive content",
                    "severity": "MEDIUM",
                    "category": "access_control"
                },
                {
                    "name": "overprivileged_users",
                    "description": "Users with excessive permissions",
                    "severity": "HIGH",
                    "category": "access_control"
                },
                {
                    "name": "inactive_users",
                    "description": "Inactive users with active permissions",
                    "severity": "MEDIUM",
                    "category": "access_control"
                }
            ],
            "configuration_rules": [
                {
                    "name": "mfa_disabled",
                    "description": "Multi-factor authentication disabled",
                    "severity": "HIGH",
                    "category": "authentication"
                },
                {
                    "name": "weak_passwords",
                    "description": "Weak password policies",
                    "severity": "MEDIUM",
                    "category": "authentication"
                },
                {
                    "name": "unencrypted_data",
                    "description": "Unencrypted sensitive data storage",
                    "severity": "HIGH",
                    "category": "encryption"
                }
            ]
        }
    
    async def create_scan(self, 
                         integration_id: str,
                         scan_config: ScanConfiguration,
                         user_id: Optional[str] = None) -> Optional[str]:
        """Create and queue a new security scan"""
        try:
            with next(get_db()) as db:
                # Validate integration exists
                integration_result = await db.execute(
                    select(Integration).where(Integration.id == integration_id)
                )
                integration = integration_result.scalar_one_or_none()
                
                if not integration:
                    logger.error(f"Integration {integration_id} not found")
                    return None
                
                # Check for duplicate active scans
                existing_scan = await self._check_active_scan(db, integration_id, scan_config.scan_type)
                if existing_scan:
                    logger.info(f"Active scan already exists for integration {integration_id}")
                    return existing_scan.id
                
                # Create scan record
                scan = Scan(
                    id=str(uuid.uuid4()),
                    integration_id=integration_id,
                    scan_type=scan_config.scan_type.value,
                    status=ScanStatus.QUEUED,
                    configuration=asdict(scan_config),
                    created_by=user_id,
                    created_at=datetime.utcnow()
                )
                
                db.add(scan)
                await db.commit()
                await db.refresh(scan)
                
                logger.info(f"Created scan {scan.id} for integration {integration_id}")
                
                # Queue scan for execution
                await self._queue_scan(scan, integration)
                
                return scan.id
                
        except Exception as e:
            logger.error(f"Failed to create scan for integration {integration_id}: {str(e)}")
            return None
    
    async def _check_active_scan(self, 
                                db: AsyncSession,
                                integration_id: str,
                                scan_type: ScanType) -> Optional[Scan]:
        """Check if there's already an active scan for the integration"""
        try:
            result = await db.execute(
                select(Scan)
                .where(
                    and_(
                        Scan.integration_id == integration_id,
                        Scan.scan_type == scan_type.value,
                        Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])
                    )
                )
                .order_by(desc(Scan.created_at))
                .limit(1)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error checking for active scans: {str(e)}")
            return None
    
    async def _queue_scan(self, scan: Scan, integration: Integration):
        """Queue scan for background execution"""
        try:
            # Add to active scans tracking
            self.active_scans[scan.id] = {
                "scan": scan,
                "integration": integration,
                "start_time": datetime.utcnow(),
                "status": "queued"
            }
            
            # Execute scan asynchronously
            asyncio.create_task(self._execute_scan_async(scan.id, integration))
            
            logger.info(f"Queued scan {scan.id} for execution")
            
        except Exception as e:
            logger.error(f"Failed to queue scan {scan.id}: {str(e)}")
    
    async def _execute_scan_async(self, scan_id: str, integration: Integration):
        """Execute scan asynchronously"""
        try:
            await self.execute_scan(scan_id)
        except Exception as e:
            logger.error(f"Async scan execution failed for {scan_id}: {str(e)}")
            await self._update_scan_status(scan_id, ScanStatus.FAILED, str(e))
    
    async def execute_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Execute a queued security scan"""
        try:
            with next(get_db()) as db:
                # Get scan details
                result = await db.execute(
                    select(Scan)
                    .options(selectinload(Scan.integration))
                    .where(Scan.id == scan_id)
                )
                scan = result.scalar_one_or_none()
                
                if not scan:
                    logger.error(f"Scan {scan_id} not found")
                    return None
                
                if scan.status != ScanStatus.QUEUED:
                    logger.warning(f"Scan {scan_id} is not in queued status: {scan.status}")
                    return None
                
                # Update scan status to running
                await self._update_scan_status(scan_id, ScanStatus.RUNNING)
                
                # Get scanner for integration type
                scanner = self.scanner_registry.get(IntegrationType(scan.integration.integration_type))
                if not scanner:
                    error_msg = f"No scanner available for integration type {scan.integration.integration_type}"
                    await self._update_scan_status(scan_id, ScanStatus.FAILED, error_msg)
                    return None
                
                # Execute the scan
                scan_config = ScanConfiguration(**scan.configuration)
                scan_result = await self._run_scanner(scanner, scan, scan_config)
                
                if scan_result.status == ScanStatus.COMPLETED:
                    # Process findings
                    await self._process_scan_findings(scan_result)
                    
                    # Update database
                    await self._save_scan_results(scan_result)
                    
                    # Generate alerts for critical findings
                    await self._generate_alerts(scan_result)
                    
                    # Cache results
                    self._cache_scan_results(scan_result)
                    
                    logger.info(f"Successfully completed scan {scan_id}")
                else:
                    logger.error(f"Scan {scan_id} failed: {scan_result.error_message}")
                
                # Cleanup active scan tracking
                if scan_id in self.active_scans:
                    del self.active_scans[scan_id]
                
                return scan_result
                
        except Exception as e:
            error_msg = f"Scan execution failed: {str(e)}"
            logger.error(f"Failed to execute scan {scan_id}: {error_msg}")
            await self._update_scan_status(scan_id, ScanStatus.FAILED, error_msg)
            return None
    
    async def _run_scanner(self, 
                          scanner: Any,
                          scan: Scan,
                          config: ScanConfiguration) -> ScanResult:
        """Run the actual scanner implementation"""
        try:
            start_time = datetime.utcnow()
            
            # Prepare scanner configuration
            scanner_config = {
                "integration": scan.integration,
                "scan_type": config.scan_type,
                "deep_scan": config.deep_scan,
                "compliance_frameworks": config.compliance_frameworks,
                "custom_rules": config.custom_rules,
                "exclusions": config.exclusions,
                "timeout": config.timeout
            }
            
            # Execute scanner based on integration type
            integration_type = IntegrationType(scan.integration.integration_type)
            
            if integration_type == IntegrationType.GITHUB:
                findings = await self._scan_github(scanner, scanner_config)
            elif integration_type == IntegrationType.GOOGLE_WORKSPACE:
                findings = await self._scan_google_workspace(scanner, scanner_config)
            elif integration_type == IntegrationType.MICROSOFT_365:
                findings = await self._scan_microsoft_365(scanner, scanner_config)
            elif integration_type == IntegrationType.SLACK:
                findings = await self._scan_slack(scanner, scanner_config)
            elif integration_type == IntegrationType.NOTION:
                findings = await self._scan_notion(scanner, scanner_config)
            else:
                raise ValueError(f"Unsupported integration type: {integration_type}")
            
            end_time = datetime.utcnow()
            
            # Calculate statistics
            statistics = self._calculate_scan_statistics(findings, start_time, end_time)
            
            return ScanResult(
                scan_id=scan.id,
                integration_id=scan.integration_id,
                scan_type=config.scan_type,
                status=ScanStatus.COMPLETED,
                findings=findings,
                statistics=statistics,
                metadata={
                    "scanner_version": getattr(scanner, "version", "1.0"),
                    "scan_duration": (end_time - start_time).total_seconds(),
                    "config": asdict(config)
                },
                start_time=start_time,
                end_time=end_time
            )
            
        except Exception as e:
            return ScanResult(
                scan_id=scan.id,
                integration_id=scan.integration_id,
                scan_type=config.scan_type,
                status=ScanStatus.FAILED,
                findings=[],
                statistics={},
                metadata={},
                start_time=start_time,
                error_message=str(e)
            )
    
    async def _scan_github(self, scanner: GitHubScanner, config: Dict) -> List[Dict]:
        """Execute GitHub security scan"""
        try:
            findings = []
            
            # Repository scanning
            repositories = await scanner.get_repositories(config["integration"])
            
            for repo in repositories:
                # Secret scanning
                secrets = await scanner.scan_secrets(repo)
                findings.extend(self._format_secret_findings(secrets, repo))
                
                # Vulnerability scanning
                vulnerabilities = await scanner.scan_vulnerabilities(repo)
                findings.extend(self._format_vulnerability_findings(vulnerabilities, repo))
                
                # Configuration scanning
                config_issues = await scanner.scan_configuration(repo)
                findings.extend(self._format_config_findings(config_issues, repo))
                
                # Branch protection scanning
                branch_issues = await scanner.scan_branch_protection(repo)
                findings.extend(self._format_branch_findings(branch_issues, repo))
            
            return findings
            
        except Exception as e:
            logger.error(f"GitHub scan failed: {str(e)}")
            raise
    
    async def _scan_google_workspace(self, scanner: GoogleWorkspaceScanner, config: Dict) -> List[Dict]:
        """Execute Google Workspace security scan"""
        try:
            findings = []
            
            # User access scanning
            users = await scanner.get_users(config["integration"])
            user_findings = await scanner.scan_user_access(users)
            findings.extend(self._format_user_findings(user_findings, "google_workspace"))
            
            # Drive security scanning
            drive_findings = await scanner.scan_drive_security(config["integration"])
            findings.extend(self._format_drive_findings(drive_findings))
            
            # Admin settings scanning
            admin_findings = await scanner.scan_admin_settings(config["integration"])
            findings.extend(self._format_admin_findings(admin_findings, "google_workspace"))
            
            return findings
            
        except Exception as e:
            logger.error(f"Google Workspace scan failed: {str(e)}")
            raise
    
    async def _scan_microsoft_365(self, scanner: Any, config: Dict) -> List[Dict]:
        """Execute Microsoft 365 security scan"""
        try:
            findings = []
            
            # User and group scanning
            users = await scanner.get_users(config["integration"])
            user_findings = await scanner.scan_user_security(users)
            findings.extend(self._format_user_findings(user_findings, "microsoft_365"))
            
            # SharePoint scanning
            sharepoint_findings = await scanner.scan_sharepoint_security(config["integration"])
            findings.extend(self._format_sharepoint_findings(sharepoint_findings))
            
            # Teams security scanning
            teams_findings = await scanner.scan_teams_security(config["integration"])
            findings.extend(self._format_teams_findings(teams_findings))
            
            # Exchange security scanning
            exchange_findings = await scanner.scan_exchange_security(config["integration"])
            findings.extend(self._format_exchange_findings(exchange_findings))
            
            return findings
            
        except Exception as e:
            logger.error(f"Microsoft 365 scan failed: {str(e)}")
            raise
    
    async def _scan_slack(self, scanner: SlackScanner, config: Dict) -> List[Dict]:
        """Execute Slack security scan"""
        try:
            findings = []
            
            # User and permissions scanning
            users = await scanner.get_users(config["integration"])
            user_findings = await scanner.scan_user_permissions(users)
            findings.extend(self._format_user_findings(user_findings, "slack"))
            
            # Channel security scanning
            channels = await scanner.get_channels(config["integration"])
            channel_findings = await scanner.scan_channel_security(channels)
            findings.extend(self._format_channel_findings(channel_findings))
            
            # App and integration scanning
            apps = await scanner.get_installed_apps(config["integration"])
            app_findings = await scanner.scan_app_permissions(apps)
            findings.extend(self._format_app_findings(app_findings, "slack"))
            
            return findings
            
        except Exception as e:
            logger.error(f"Slack scan failed: {str(e)}")
            raise
    
    async def _scan_notion(self, scanner: NotionScanner, config: Dict) -> List[Dict]:
        """Execute Notion security scan"""
        try:
            findings = []
            
            # Workspace scanning
            workspace_findings = await scanner.scan_workspace_security(config["integration"])
            findings.extend(self._format_workspace_findings(workspace_findings, "notion"))
            
            # Page and database access scanning
            pages = await scanner.get_pages(config["integration"])
            access_findings = await scanner.scan_page_access(pages)
            findings.extend(self._format_access_findings(access_findings, "notion"))
            
            # Integration scanning
            integrations = await scanner.get_integrations(config["integration"])
            integration_findings = await scanner.scan_integration_security(integrations)
            findings.extend(self._format_integration_findings(integration_findings, "notion"))
            
            return findings
            
        except Exception as e:
            logger.error(f"Notion scan failed: {str(e)}")
            raise
    
    def _format_secret_findings(self, secrets: List[Dict], repo: Dict) -> List[Dict]:
        """Format secret detection findings"""
        findings = []
        for secret in secrets:
            finding = {
                "id": str(uuid.uuid4()),
                "type": "secret_exposure",
                "severity": self._calculate_secret_severity(secret),
                "title": f"Secret detected in {repo['name']}",
                "description": f"Potential secret found: {secret.get('type', 'unknown')}",
                "resource_name": f"{repo['name']}/{secret.get('file', '')}",
                "resource_type": "file",
                "location": {
                    "repository": repo['name'],
                    "file": secret.get('file'),
                    "line": secret.get('line'),
                    "commit": secret.get('commit')
                },
                "metadata": {
                    "secret_type": secret.get('type'),
                    "pattern_matched": secret.get('pattern'),
                    "confidence": secret.get('confidence', 'medium')
                },
                "compliance_impact": self._map_compliance_impact("data_exposure"),
                "remediation": self._get_secret_remediation(secret.get('type'))
            }
            findings.append(finding)
        return findings
    
    def _format_vulnerability_findings(self, vulnerabilities: List[Dict], repo: Dict) -> List[Dict]:
        """Format vulnerability findings"""
        findings = []
        for vuln in vulnerabilities:
            finding = {
                "id": str(uuid.uuid4()),
                "type": "vulnerability",
                "severity": self._map_cvss_to_severity(vuln.get('cvss_score', 0)),
                "title": f"Vulnerability in {repo['name']}: {vuln.get('title', 'Unknown')}",
                "description": vuln.get('description', 'No description available'),
                "resource_name": f"{repo['name']}/{vuln.get('package', '')}",
                "resource_type": "dependency",
                "location": {
                    "repository": repo['name'],
                    "package": vuln.get('package'),
                    "version": vuln.get('version')
                },
                "metadata": {
                    "cve_id": vuln.get('cve_id'),
                    "cvss_score": vuln.get('cvss_score'),
                    "severity": vuln.get('severity'),
                    "fixed_version": vuln.get('fixed_version'),
                    "published_date": vuln.get('published_date')
                },
                "compliance_impact": self._map_compliance_impact("vulnerability"),
                "remediation": f"Update {vuln.get('package')} to version {vuln.get('fixed_version', 'latest')}"
            }
            findings.append(finding)
        return findings
    
    def _format_config_findings(self, config_issues: List[Dict], repo: Dict) -> List[Dict]:
        """Format configuration findings"""
        findings = []
        for issue in config_issues:
            finding = {
                "id": str(uuid.uuid4()),
                "type": "configuration",
                "severity": issue.get('severity', 'MEDIUM'),
                "title": f"Configuration issue in {repo['name']}: {issue.get('title')}",
                "description": issue.get('description'),
                "resource_name": f"{repo['name']}/{issue.get('file', 'settings')}",
                "resource_type": "configuration",
                "location": {
                    "repository": repo['name'],
                    "file": issue.get('file'),
                    "setting": issue.get('setting')
                },
                "metadata": {
                    "config_type": issue.get('type'),
                    "current_value": issue.get('current_value'),
                    "recommended_value": issue.get('recommended_value')
                },
                "compliance_impact": self._map_compliance_impact("configuration"),
                "remediation": issue.get('remediation', 'Review and update configuration')
            }
            findings.append(finding)
        return findings
    
    def _format_branch_findings(self, branch_issues: List[Dict], repo: Dict) -> List[Dict]:
        """Format branch protection findings"""
        findings = []
        for issue in branch_issues:
            finding = {
                "id": str(uuid.uuid4()),
                "type": "access_control",
                "severity": issue.get('severity', 'MEDIUM'),
                "title": f"Branch protection issue in {repo['name']}",
                "description": issue.get('description'),
                "resource_name": f"{repo['name']}/{issue.get('branch', 'main')}",
                "resource_type": "branch",
                "location": {
                    "repository": repo['name'],
                    "branch": issue.get('branch')
                },
                "metadata": {
                    "protection_enabled": issue.get('protection_enabled'),
                    "required_reviews": issue.get('required_reviews'),
                    "admin_enforcement": issue.get('admin_enforcement')
                },
                "compliance_impact": self._map_compliance_impact("access_control"),
                "remediation": "Enable branch protection rules with required reviews"
            }
            findings.append(finding)
        return findings
    
    def _format_user_findings(self, user_issues: List[Dict], platform: str) -> List[Dict]:
        """Format user access findings"""
        findings = []
        for issue in user_issues:
            finding = {
                "id": str(uuid.uuid4()),
                "type": "access_control",
                "severity": issue.get('severity', 'MEDIUM'),
                "title": f"User access issue: {issue.get('title')}",
                "description": issue.get('description'),
                "resource_name": issue.get('user_email', 'unknown_user'),
                "resource_type": "user",
                "location": {
                    "platform": platform,
                    "user_id": issue.get('user_id'),
                    "role": issue.get('role')
                },
                "metadata": {
                    "permissions": issue.get('permissions', []),
                    "last_login": issue.get('last_login'),
                    "mfa_enabled": issue.get('mfa_enabled'),
                    "groups": issue.get('groups', [])
                },
                "compliance_impact": self._map_compliance_impact("access_control"),
                "remediation": issue.get('remediation', 'Review user permissions and access')
            }
            findings.append(finding)
        return findings
    
    def _calculate_secret_severity(self, secret: Dict) -> str:
        """Calculate severity for secret findings"""
        secret_type = secret.get('type', '').lower()
        confidence = secret.get('confidence', 'medium').lower()
        
        if secret_type in ['aws_access_key', 'private_key', 'database_password']:
            return 'CRITICAL'
        elif secret_type in ['api_key', 'token', 'password'] and confidence == 'high':
            return 'HIGH'
        elif confidence == 'high':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'CRITICAL'
        elif cvss_score >= 7.0:
            return 'HIGH'
        elif cvss_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _map_compliance_impact(self, finding_type: str) -> List[str]:
        """Map finding types to compliance frameworks"""
        impacts = []
        
        for framework, controls in self.compliance_mappings.items():
            for control, categories in controls.items():
                if finding_type in categories:
                    impacts.append(f"{framework}:{control}")
        
        return impacts
    
    def _get_secret_remediation(self, secret_type: str) -> str:
        """Get remediation advice for secret types"""
        remediation_map = {
            'aws_access_key': 'Rotate AWS access keys immediately and use IAM roles instead',
            'private_key': 'Remove private key from repository and use secure key management',
            'api_key': 'Rotate API key and store in secure environment variables',
            'password': 'Remove hardcoded password and use secure configuration',
            'database_password': 'Rotate database credentials and use connection strings with environment variables'
        }
        
        return remediation_map.get(secret_type, 'Remove secret from code and use secure storage')
    
    def _calculate_scan_statistics(self, 
                                  findings: List[Dict], 
                                  start_time: datetime, 
                                  end_time: datetime) -> Dict:
        """Calculate comprehensive scan statistics"""
        stats = {
            "total_findings": len(findings),
            "by_severity": {
                "CRITICAL": len([f for f in findings if f.get('severity') == 'CRITICAL']),
                "HIGH": len([f for f in findings if f.get('severity') == 'HIGH']),
                "MEDIUM": len([f for f in findings if f.get('severity') == 'MEDIUM']),
                "LOW": len([f for f in findings if f.get('severity') == 'LOW'])
            },
            "by_type": {},
            "scan_duration": (end_time - start_time).total_seconds(),
            "resources_scanned": len(set(f.get('resource_name', '') for f in findings)),
            "compliance_impact": {
                "SOC2": len([f for f in findings if any('SOC2' in ci for ci in f.get('compliance_impact', []))]),
                "GDPR": len([f for f in findings if any('GDPR' in ci for ci in f.get('compliance_impact', []))]),
                "HIPAA": len([f for f in findings if any('HIPAA' in ci for ci in f.get('compliance_impact', []))]),
                "ISO27001": len([f for f in findings if any('ISO27001' in ci for ci in f.get('compliance_impact', []))])
            },
            "risk_score": self._calculate_risk_score(findings)
        }
        
        # Calculate by type
        for finding in findings:
            finding_type = finding.get('type', 'unknown')
            stats['by_type'][finding_type] = stats['by_type'].get(finding_type, 0) + 1
        
        return stats
    
    def _calculate_risk_score(self, findings: List[Dict]) -> float:
        """Calculate overall risk score based on findings"""
        if not findings:
            return 0.0
        
        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        
        total_score = sum(
            severity_weights.get(f.get('severity', 'LOW'), 2.5)
            for f in findings
        )
        
        # Normalize to 0-100 scale
        max_possible_score = len(findings) * 10.0
        return min((total_score / max_possible_score) * 100, 100.0) if max_possible_score > 0 else 0.0
    
    async def _process_scan_findings(self, scan_result: ScanResult):
        """Process and deduplicate scan findings"""
        try:
            # Deduplicate findings
            unique_findings = self._deduplicate_findings(scan_result.findings)
            
            # Enrich findings with additional context
            enriched_findings = await self._enrich_findings(unique_findings, scan_result.integration_id)
            
            # Update scan result
            scan_result.findings = enriched_findings
            scan_result.statistics = self._calculate_scan_statistics(
                enriched_findings, 
                scan_result.start_time, 
                scan_result.end_time
            )
            
            logger.info(f"Processed {len(enriched_findings)} unique findings for scan {scan_result.scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to process scan findings: {str(e)}")
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on content hash"""
        seen_hashes = set()
        unique_findings = []
        
        for finding in findings:
            # Create content hash for deduplication
            content_hash = self._generate_finding_hash(finding)
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                finding['content_hash'] = content_hash
                unique_findings.append(finding)
        
        return unique_findings
    
    def _generate_finding_hash(self, finding: Dict) -> str:
        """Generate hash for finding deduplication"""
        # Use key fields to generate hash
        hash_content = {
            'type': finding.get('type'),
            'severity': finding.get('severity'),
            'resource_name': finding.get('resource_name'),
            'resource_type': finding.get('resource_type'),
            'description': finding.get('description', '')[:100]  # First 100 chars
        }
        
        content_str = json.dumps(hash_content, sort_keys=True)
        return hashlib.md5(content_str.encode()).hexdigest()
    
    async def _enrich_findings(self, findings: List[Dict], integration_id: str) -> List[Dict]:
        """Enrich findings with additional context and metadata"""
        try:
            for finding in findings:
                # Add integration context
                finding['integration_id'] = integration_id
                finding['detected_at'] = datetime.utcnow().isoformat()
                
                # Add risk scoring
                finding['risk_score'] = self._calculate_finding_risk_score(finding)
                
                # Add compliance mapping
                if 'compliance_impact' not in finding:
                    finding['compliance_impact'] = self._map_compliance_impact(finding.get('type', ''))
                
                # Add remediation priority
                finding['remediation_priority'] = self._calculate_remediation_priority(finding)
                
                # Add business impact assessment
                finding['business_impact'] = self._assess_business_impact(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Failed to enrich findings: {str(e)}")
            return findings
    
    def _calculate_finding_risk_score(self, finding: Dict) -> float:
        """Calculate risk score for individual finding"""
        severity_scores = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        
        base_score = severity_scores.get(finding.get('severity', 'LOW'), 2.5)
        
        # Adjust based on type
        type_multipliers = {
            'secret_exposure': 1.5,
            'vulnerability': 1.3,
            'data_exposure': 1.4,
            'access_control': 1.2,
            'configuration': 1.0
        }
        
        multiplier = type_multipliers.get(finding.get('type', ''), 1.0)
        
        return min(base_score * multiplier, 10.0)
    
    def _calculate_remediation_priority(self, finding: Dict) -> str:
        """Calculate remediation priority"""
        severity = finding.get('severity', 'LOW')
        risk_score = finding.get('risk_score', 0)
        compliance_impact = len(finding.get('compliance_impact', []))
        
        if severity == 'CRITICAL' or risk_score >= 9.0:
            return 'IMMEDIATE'
        elif severity == 'HIGH' or risk_score >= 7.0 or compliance_impact >= 3:
            return 'HIGH'
        elif severity == 'MEDIUM' or risk_score >= 5.0 or compliance_impact >= 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_business_impact(self, finding: Dict) -> Dict:
        """Assess business impact of finding"""
        severity = finding.get('severity', 'LOW')
        finding_type = finding.get('type', '')
        
        impact_levels = {
            'CRITICAL': {
                'data_breach_risk': 'HIGH',
                'compliance_risk': 'HIGH',
                'operational_risk': 'MEDIUM',
                'reputation_risk': 'HIGH'
            },
            'HIGH': {
                'data_breach_risk': 'MEDIUM',
                'compliance_risk': 'MEDIUM',
                'operational_risk': 'MEDIUM',
                'reputation_risk': 'MEDIUM'
            },
            'MEDIUM': {
                'data_breach_risk': 'LOW',
                'compliance_risk': 'LOW',
                'operational_risk': 'LOW',
                'reputation_risk': 'LOW'
            },
            'LOW': {
                'data_breach_risk': 'VERY_LOW',
                'compliance_risk': 'VERY_LOW',
                'operational_risk': 'VERY_LOW',
                'reputation_risk': 'VERY_LOW'
            }
        }
        
        base_impact = impact_levels.get(severity, impact_levels['LOW'])
        
        # Adjust based on finding type
        if finding_type in ['secret_exposure', 'data_exposure']:
            base_impact['data_breach_risk'] = self._increase_risk_level(base_impact['data_breach_risk'])
            base_impact['compliance_risk'] = self._increase_risk_level(base_impact['compliance_risk'])
        
        return base_impact
    
    def _increase_risk_level(self, current_level: str) -> str:
        """Increase risk level by one step"""
        levels = ['VERY_LOW', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        current_index = levels.index(current_level) if current_level in levels else 0
        return levels[min(current_index + 1, len(levels) - 1)]
    
    async def _save_scan_results(self, scan_result: ScanResult):
        """Save scan results to database"""
        try:
            with next(get_db()) as db:
                # Update scan record
                await db.execute(
                    update(Scan)
                    .where(Scan.id == scan_result.scan_id)
                    .values(
                        status=scan_result.status.value,
                        completed_at=scan_result.end_time,
                        statistics=scan_result.statistics,
                        metadata=scan_result.metadata
                    )
                )
                
                # Save findings
                for finding_data in scan_result.findings:
                    finding = Finding(
                        id=finding_data['id'],
                        scan_id=scan_result.scan_id,
                        integration_id=scan_result.integration_id,
                        finding_type=finding_data['type'],
                        severity=finding_data['severity'],
                        title=finding_data['title'],
                        description=finding_data['description'],
                        resource_name=finding_data['resource_name'],
                        resource_type=finding_data['resource_type'],
                        location=finding_data.get('location', {}),
                        metadata=finding_data.get('metadata', {}),
                        risk_level=RiskLevel(finding_data['severity']),
                        remediation=finding_data.get('remediation', ''),
                        compliance_impact=finding_data.get('compliance_impact', []),
                        detected_at=datetime.utcnow()
                    )
                    
                    db.add(finding)
                
                await db.commit()
                logger.info(f"Saved scan results for scan {scan_result.scan_id}")
                
        except Exception as e:
            logger.error(f"Failed to save scan results: {str(e)}")
            raise
    
    async def _generate_alerts(self, scan_result: ScanResult):
        """Generate alerts for critical findings"""
        try:
            critical_findings = [
                f for f in scan_result.findings 
                if f.get('severity') in ['CRITICAL', 'HIGH']
            ]
            
            for finding in critical_findings:
                # Determine alert severity
                alert_severity = AlertSeverity.CRITICAL if finding['severity'] == 'CRITICAL' else AlertSeverity.HIGH
                
                # Determine alert category
                category_map = {
                    'secret_exposure': AlertCategory.DATA_EXPOSURE,
                    'vulnerability': AlertCategory.VULNERABILITY,
                    'data_exposure': AlertCategory.DATA_EXPOSURE,
                    'access_control': AlertCategory.ACCESS_CONTROL,
                    'configuration': AlertCategory.CONFIGURATION,
                    'authentication': AlertCategory.AUTHENTICATION,
                    'encryption': AlertCategory.ENCRYPTION
                }
                
                alert_category = category_map.get(finding['type'], AlertCategory.CONFIGURATION)
                
                # Create alert
                await self.alert_service.create_alert(
                    finding_id=finding['id'],
                    alert_type=f"scan_{finding['type']}",
                    severity=alert_severity,
                    category=alert_category,
                    title=f"Security Issue Detected: {finding['title']}",
                    description=finding['description'],
                    metadata={
                        'scan_id': scan_result.scan_id,
                        'integration_id': scan_result.integration_id,
                        'risk_score': finding.get('risk_score', 0),
                        'remediation_priority': finding.get('remediation_priority', 'MEDIUM'),
                        'business_impact': finding.get('business_impact', {}),
                        'compliance_impact': finding.get('compliance_impact', [])
                    }
                )
            
            logger.info(f"Generated {len(critical_findings)} alerts for scan {scan_result.scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to generate alerts for scan {scan_result.scan_id}: {str(e)}")
    
    def _cache_scan_results(self, scan_result: ScanResult):
        """Cache scan results for quick access"""
        try:
            cache_key = f"{scan_result.integration_id}_{scan_result.scan_type.value}"
            self.scan_cache[cache_key] = scan_result
            
            # Limit cache size
            if len(self.scan_cache) > 100:
                # Remove oldest entries
                oldest_key = min(self.scan_cache.keys(), 
                               key=lambda k: self.scan_cache[k].start_time)
                del self.scan_cache[oldest_key]
            
        except Exception as e:
            logger.error(f"Failed to cache scan results: {str(e)}")
    
    async def _update_scan_status(self, 
                                 scan_id: str, 
                                 status: ScanStatus, 
                                 error_message: Optional[str] = None):
        """Update scan status in database"""
        try:
            with next(get_db()) as db:
                update_values = {
                    'status': status.value,
                    'updated_at': datetime.utcnow()
                }
                
                if status == ScanStatus.COMPLETED:
                    update_values['completed_at'] = datetime.utcnow()
                elif status == ScanStatus.FAILED and error_message:
                    update_values['error_message'] = error_message
                
                await db.execute(
                    update(Scan)
                    .where(Scan.id == scan_id)
                    .values(**update_values)
                )
                
                await db.commit()
                
                # Update active scans tracking
                if scan_id in self.active_scans:
                    self.active_scans[scan_id]['status'] = status.value
                
        except Exception as e:
            logger.error(f"Failed to update scan status for {scan_id}: {str(e)}")
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get current status of a scan"""
        try:
            with next(get_db()) as db:
                result = await db.execute(
                    select(Scan).where(Scan.id == scan_id)
                )
                scan = result.scalar_one_or_none()
                
                if not scan:
                    return None
                
                return {
                    "scan_id": scan.id,
                    "status": scan.status,
                    "created_at": scan.created_at,
                    "completed_at": scan.completed_at,
                    "statistics": scan.statistics,
                    "error_message": scan.error_message,
                    "progress": self._get_scan_progress(scan_id)
                }
                
        except Exception as e:
            logger.error(f"Failed to get scan status for {scan_id}: {str(e)}")
            return None
    
    def _get_scan_progress(self, scan_id: str) -> Dict:
        """Get scan progress information"""
        if scan_id in self.active_scans:
            active_scan = self.active_scans[scan_id]
            return {
                "current_phase": active_scan.get('current_phase', 'initializing'),
                "progress_percent": active_scan.get('progress_percent', 0),
                "estimated_completion": active_scan.get('estimated_completion'),
                "resources_processed": active_scan.get('resources_processed', 0)
            }
        return {}
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running or queued scan"""
        try:
            with next(get_db()) as db:
                result = await db.execute(
                    select(Scan).where(Scan.id == scan_id)
                )
                scan = result.scalar_one_or_none()
                
                if not scan:
                    logger.error(f"Scan {scan_id} not found")
                    return False
                
                if scan.status not in [ScanStatus.QUEUED, ScanStatus.RUNNING]:
                    logger.warning(f"Cannot cancel scan {scan_id} with status {scan.status}")
                    return False
                
                # Update scan status
                await self._update_scan_status(scan_id, ScanStatus.CANCELLED)
                
                # Remove from active scans
                if scan_id in self.active_scans:
                    del self.active_scans[scan_id]
                
                logger.info(f"Cancelled scan {scan_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to cancel scan {scan_id}: {str(e)}")
            return False
    
    async def get_integration_scan_history(self, 
                                         integration_id: str,
                                         limit: int = 50) -> List[Dict]:
        """Get scan history for an integration"""
        try:
            with next(get_db()) as db:
                result = await db.execute(
                    select(Scan)
                    .where(Scan.integration_id == integration_id)
                    .order_by(desc(Scan.created_at))
                    .limit(limit)
                )
                scans = result.scalars().all()
                
                return [
                    {
                        "scan_id": scan.id,
                        "scan_type": scan.scan_type,
                        "status": scan.status,
                        "created_at": scan.created_at,
                        "completed_at": scan.completed_at,
                        "statistics": scan.statistics or {},
                        "duration": (
                            (scan.completed_at - scan.created_at).total_seconds()
                            if scan.completed_at else None
                        )
                    }
                    for scan in scans
                ]
                
        except Exception as e:
            logger.error(f"Failed to get scan history for integration {integration_id}: {str(e)}")
            return []
    
    async def health_check(self) -> Dict:
        """Perform health check of the scan service"""
        health_status = {
            "service_healthy": True,
            "scanners_available": len(self.scanner_registry),
            "active_scans": len(self.active_scans),
            "cache_size": len(self.scan_cache),
            "thread_pool_active": self.executor._threads is not None,
            "scanner_status": {},
            "issues": []
        }
        
        # Check individual scanners
        for integration_type, scanner in self.scanner_registry.items():
            try:
                # Basic scanner health check
                scanner_health = getattr(scanner, 'health_check', lambda: True)()
                health_status["scanner_status"][integration_type.value] = {
                    "available": True,
                    "healthy": scanner_health
                }
                
                if not scanner_health:
                    health_status["issues"].append(f"{integration_type.value} scanner unhealthy")
                    
            except Exception as e:
                health_status["scanner_status"][integration_type.value] = {
                    "available": False,
                    "healthy": False,
                    "error": str(e)
                }
                health_status["issues"].append(f"{integration_type.value} scanner error: {str(e)}")
        
        # Check for stuck scans
        stuck_scans = [
            scan_id for scan_id, scan_info in self.active_scans.items()
            if (datetime.utcnow() - scan_info['start_time']).total_seconds() > 7200  # 2 hours
        ]
        
        if stuck_scans:
            health_status["issues"].append(f"Stuck scans detected: {len(stuck_scans)}")
            health_status["service_healthy"] = False
        
        return health_status


# Global scan service instance
scan_service = CloudShieldScanService()


def get_scan_service() -> CloudShieldScanService:
    """Get the global scan service instance"""
    return scan_service
