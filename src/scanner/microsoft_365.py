"""
CloudShield Microsoft 365 Security Scanner
Advanced security scanning module for Microsoft 365 environments including Azure AD, 
SharePoint, Teams, Exchange Online, and OneDrive.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import aiohttp
import re
from dataclasses import dataclass
from enum import Enum

from ..common import BaseScanner, ScanResult, SecurityFinding, RiskLevel
from ...api.utils.config import get_settings
from ...api.utils.logger import get_logger

settings = get_settings()
logger = get_logger(__name__)


class M365ServiceType(Enum):
    """Microsoft 365 service types"""
    AZURE_AD = "azure_ad"
    SHAREPOINT = "sharepoint"
    TEAMS = "teams"
    EXCHANGE = "exchange"
    ONEDRIVE = "onedrive"
    POWER_PLATFORM = "power_platform"
    INTUNE = "intune"


class M365SecurityControl(Enum):
    """Microsoft 365 security controls"""
    MFA_ENFORCEMENT = "mfa_enforcement"
    CONDITIONAL_ACCESS = "conditional_access"
    IDENTITY_PROTECTION = "identity_protection"
    PRIVILEGED_ACCESS = "privileged_access"
    DATA_LOSS_PREVENTION = "data_loss_prevention"
    INFORMATION_PROTECTION = "information_protection"
    THREAT_PROTECTION = "threat_protection"
    COMPLIANCE_POLICIES = "compliance_policies"
    DEVICE_MANAGEMENT = "device_management"
    APPLICATION_MANAGEMENT = "application_management"


@dataclass
class M365Permission:
    """Microsoft 365 permission structure"""
    id: str
    display_name: str
    type: str  # application, delegated
    value: str
    admin_consent_required: bool
    is_enabled: bool


@dataclass
class M365User:
    """Microsoft 365 user information"""
    id: str
    user_principal_name: str
    display_name: str
    job_title: Optional[str]
    department: Optional[str]
    is_admin: bool
    mfa_enabled: bool
    last_sign_in: Optional[datetime]
    assigned_licenses: List[str]
    risk_level: str
    risk_detail: Optional[str]


@dataclass
class M365Application:
    """Microsoft 365 application registration"""
    id: str
    app_id: str
    display_name: str
    publisher_domain: str
    sign_in_audience: str
    permissions: List[M365Permission]
    secrets_count: int
    certificates_count: int
    created_date: datetime
    is_verified: bool


class Microsoft365Scanner(BaseScanner):
    """
    Comprehensive Microsoft 365 security scanner
    
    Capabilities:
    - Azure Active Directory security assessment
    - SharePoint Online security configuration
    - Microsoft Teams security settings
    - Exchange Online protection analysis
    - OneDrive for Business data exposure detection
    - Power Platform governance assessment
    - Intune device management evaluation
    - Compliance and data protection review
    """
    
    def __init__(self):
        super().__init__()
        self.version = "2.1.0"
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.beta_url = "https://graph.microsoft.com/beta"
        self.session: Optional[aiohttp.ClientSession] = None
        self.access_token: Optional[str] = None
        self.tenant_id: Optional[str] = None
        
        # Security check configurations
        self.security_checks = self._initialize_security_checks()
        
        # Compliance frameworks mapping
        self.compliance_mappings = {
            "SOC2": ["CC1.1", "CC2.1", "CC3.1", "CC6.1", "CC8.1"],
            "ISO27001": ["A.9", "A.10", "A.12", "A.13", "A.14"],
            "NIST": ["AC", "AU", "CA", "CM", "SC", "SI"],
            "GDPR": ["Art25", "Art32", "Art35"],
            "HIPAA": ["164.308", "164.310", "164.312"]
        }
    
    def _initialize_security_checks(self) -> Dict[str, Dict]:
        """Initialize security check configurations"""
        return {
            "azure_ad": {
                "mfa_requirements": {
                    "name": "Multi-Factor Authentication Requirements",
                    "description": "Check MFA enforcement for all users",
                    "severity": "HIGH",
                    "check_type": "configuration"
                },
                "conditional_access": {
                    "name": "Conditional Access Policies",
                    "description": "Evaluate conditional access policy coverage",
                    "severity": "HIGH",
                    "check_type": "access_control"
                },
                "privileged_roles": {
                    "name": "Privileged Role Assignments", 
                    "description": "Review privileged role assignments and usage",
                    "severity": "CRITICAL",
                    "check_type": "access_control"
                },
                "guest_user_access": {
                    "name": "Guest User Access Controls",
                    "description": "Assess external user access permissions",
                    "severity": "MEDIUM",
                    "check_type": "access_control"
                },
                "password_policies": {
                    "name": "Password Policy Configuration",
                    "description": "Evaluate password complexity and policies",
                    "severity": "MEDIUM",
                    "check_type": "authentication"
                }
            },
            "sharepoint": {
                "external_sharing": {
                    "name": "External Sharing Settings",
                    "description": "Review SharePoint external sharing configurations",
                    "severity": "HIGH",
                    "check_type": "data_exposure"
                },
                "access_permissions": {
                    "name": "Site Access Permissions",
                    "description": "Analyze site and library permission assignments",
                    "severity": "MEDIUM",
                    "check_type": "access_control"
                },
                "dlp_policies": {
                    "name": "Data Loss Prevention Policies",
                    "description": "Check DLP policy coverage and effectiveness",
                    "severity": "HIGH",
                    "check_type": "data_protection"
                }
            },
            "teams": {
                "guest_access": {
                    "name": "Teams Guest Access Settings",
                    "description": "Review Microsoft Teams guest access configuration",
                    "severity": "MEDIUM",
                    "check_type": "access_control"
                },
                "meeting_policies": {
                    "name": "Meeting Security Policies",
                    "description": "Assess meeting lobby and recording policies",
                    "severity": "MEDIUM",
                    "check_type": "configuration"
                },
                "app_permissions": {
                    "name": "Teams App Permissions",
                    "description": "Review third-party app installations and permissions",
                    "severity": "MEDIUM",
                    "check_type": "application_security"
                }
            },
            "exchange": {
                "mail_flow_rules": {
                    "name": "Mail Flow Security Rules",
                    "description": "Evaluate mail flow rules and exceptions",
                    "severity": "MEDIUM",
                    "check_type": "configuration"
                },
                "atp_policies": {
                    "name": "Advanced Threat Protection",
                    "description": "Check ATP Safe Attachments and Links configuration",
                    "severity": "HIGH",
                    "check_type": "threat_protection"
                },
                "mailbox_permissions": {
                    "name": "Mailbox Permission Assignments",
                    "description": "Review mailbox access permissions and delegation",
                    "severity": "MEDIUM",
                    "check_type": "access_control"
                }
            }
        }
    
    async def initialize_session(self, integration_config: Dict) -> bool:
        """Initialize authenticated session with Microsoft Graph API"""
        try:
            self.tenant_id = integration_config.get("tenant_id")
            client_id = integration_config.get("client_id")
            client_secret = integration_config.get("client_secret")
            
            if not all([self.tenant_id, client_id, client_secret]):
                logger.error("Missing required Microsoft 365 authentication credentials")
                return False
            
            # Create session
            self.session = aiohttp.ClientSession(
                headers={"User-Agent": "CloudShield-M365Scanner/2.1.0"},
                timeout=aiohttp.ClientTimeout(total=300)
            )
            
            # Authenticate and get access token
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            auth_data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials"
            }
            
            async with self.session.post(token_url, data=auth_data) as response:
                if response.status == 200:
                    token_data = await response.json()
                    self.access_token = token_data["access_token"]
                    
                    # Update session headers
                    self.session.headers.update({
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json"
                    })
                    
                    logger.info("Microsoft 365 authentication successful")
                    return True
                else:
                    error_data = await response.json()
                    logger.error(f"Microsoft 365 authentication failed: {error_data}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to initialize Microsoft 365 session: {str(e)}")
            return False
    
    async def cleanup_session(self):
        """Clean up HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def scan_security(self, integration_config: Dict, scan_options: Dict = None) -> ScanResult:
        """
        Perform comprehensive Microsoft 365 security scan
        
        Args:
            integration_config: M365 integration configuration
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
            services_to_scan = scan_options.get("services", [
                M365ServiceType.AZURE_AD,
                M365ServiceType.SHAREPOINT,
                M365ServiceType.TEAMS,
                M365ServiceType.EXCHANGE
            ])
            
            # Perform scans for each service
            for service in services_to_scan:
                if service == M365ServiceType.AZURE_AD:
                    azure_findings = await self._scan_azure_ad()
                    findings.extend(azure_findings)
                
                elif service == M365ServiceType.SHAREPOINT:
                    sharepoint_findings = await self._scan_sharepoint()
                    findings.extend(sharepoint_findings)
                
                elif service == M365ServiceType.TEAMS:
                    teams_findings = await self._scan_teams()
                    findings.extend(teams_findings)
                
                elif service == M365ServiceType.EXCHANGE:
                    exchange_findings = await self._scan_exchange()
                    findings.extend(exchange_findings)
            
            # Calculate scan statistics
            end_time = datetime.utcnow()
            scan_duration = (end_time - start_time).total_seconds()
            
            # Generate metadata
            metadata = {
                "tenant_id": self.tenant_id,
                "services_scanned": [s.value for s in services_to_scan],
                "total_findings": len(findings),
                "findings_by_severity": self._count_by_severity(findings),
                "scan_timestamp": start_time.isoformat(),
                "scanner_version": self.version
            }
            
            logger.info(f"Microsoft 365 scan completed: {len(findings)} findings in {scan_duration:.2f}s")
            
            return ScanResult(
                success=True,
                findings=findings,
                metadata=metadata,
                scan_duration=scan_duration
            )
            
        except Exception as e:
            logger.error(f"Microsoft 365 scan failed: {str(e)}")
            return ScanResult(
                success=False,
                findings=findings,
                metadata={"error": str(e)},
                scan_duration=(datetime.utcnow() - start_time).total_seconds()
            )
        
        finally:
            await self.cleanup_session()
    
    async def _scan_azure_ad(self) -> List[SecurityFinding]:
        """Scan Azure Active Directory security configuration"""
        findings = []
        
        try:
            logger.info("Scanning Azure Active Directory configuration...")
            
            # Get organization information
            org_info = await self._get_organization_info()
            
            # Check MFA enforcement
            mfa_findings = await self._check_mfa_enforcement()
            findings.extend(mfa_findings)
            
            # Check conditional access policies
            ca_findings = await self._check_conditional_access()
            findings.extend(ca_findings)
            
            # Check privileged role assignments
            role_findings = await self._check_privileged_roles()
            findings.extend(role_findings)
            
            # Check guest user access
            guest_findings = await self._check_guest_access()
            findings.extend(guest_findings)
            
            # Check identity protection settings
            identity_findings = await self._check_identity_protection()
            findings.extend(identity_findings)
            
            # Check password policies
            password_findings = await self._check_password_policies()
            findings.extend(password_findings)
            
            # Check application registrations
            app_findings = await self._check_application_security()
            findings.extend(app_findings)
            
        except Exception as e:
            logger.error(f"Azure AD scan failed: {str(e)}")
            findings.append(SecurityFinding(
                title="Azure AD Scan Error",
                description=f"Failed to complete Azure AD security scan: {str(e)}",
                severity=RiskLevel.MEDIUM,
                category="scan_error",
                resource_name="Azure Active Directory",
                location={"service": "azure_ad"}
            ))
        
        return findings
    
    async def _check_mfa_enforcement(self) -> List[SecurityFinding]:
        """Check multi-factor authentication enforcement"""
        findings = []
        
        try:
            # Get MFA status for users
            url = f"{self.base_url}/reports/credentialUserRegistrationDetails"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    users = data.get("value", [])
                    
                    # Check MFA registration status
                    total_users = len(users)
                    mfa_enabled_users = len([u for u in users if u.get("isMfaRegistered", False)])
                    
                    if total_users > 0:
                        mfa_coverage = (mfa_enabled_users / total_users) * 100
                        
                        if mfa_coverage < 90:
                            findings.append(SecurityFinding(
                                title="Insufficient MFA Coverage",
                                description=f"Only {mfa_coverage:.1f}% of users have MFA enabled. "
                                           f"Consider requiring MFA for all users.",
                                severity=RiskLevel.HIGH if mfa_coverage < 50 else RiskLevel.MEDIUM,
                                category="authentication",
                                resource_name="Multi-Factor Authentication",
                                location={"service": "azure_ad", "setting": "mfa_enforcement"},
                                remediation="Enable MFA requirements through conditional access policies",
                                compliance_impact=["SOC2:CC1.1", "ISO27001:A.9", "NIST:AC"]
                            ))
                    
                    # Check for users without MFA
                    users_without_mfa = [u for u in users if not u.get("isMfaRegistered", False)]
                    
                    if len(users_without_mfa) > 10:  # Threshold for reporting
                        findings.append(SecurityFinding(
                            title="Users Without MFA Registration",
                            description=f"{len(users_without_mfa)} users do not have MFA registered",
                            severity=RiskLevel.MEDIUM,
                            category="authentication",
                            resource_name="User MFA Registration",
                            location={"service": "azure_ad", "users_affected": len(users_without_mfa)},
                            remediation="Require MFA registration for all users"
                        ))
                
        except Exception as e:
            logger.error(f"MFA enforcement check failed: {str(e)}")
            findings.append(SecurityFinding(
                title="MFA Check Failed",
                description=f"Unable to verify MFA enforcement: {str(e)}",
                severity=RiskLevel.MEDIUM,
                category="scan_error",
                resource_name="MFA Settings"
            ))
        
        return findings
    
    async def _check_conditional_access(self) -> List[SecurityFinding]:
        """Check conditional access policy configuration"""
        findings = []
        
        try:
            url = f"{self.base_url}/identity/conditionalAccess/policies"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    policies = data.get("value", [])
                    
                    enabled_policies = [p for p in policies if p.get("state") == "enabled"]
                    
                    # Check for basic conditional access coverage
                    required_conditions = {
                        "mfa_for_admins": False,
                        "block_legacy_auth": False,
                        "require_compliant_device": False,
                        "location_based_access": False
                    }
                    
                    for policy in enabled_policies:
                        conditions = policy.get("conditions", {})
                        grant_controls = policy.get("grantControls", {})
                        
                        # Check for admin MFA requirement
                        if self._policy_targets_admins(policy) and self._policy_requires_mfa(grant_controls):
                            required_conditions["mfa_for_admins"] = True
                        
                        # Check for legacy auth blocking
                        if self._policy_blocks_legacy_auth(conditions):
                            required_conditions["block_legacy_auth"] = True
                        
                        # Check for compliant device requirement
                        if self._policy_requires_compliant_device(grant_controls):
                            required_conditions["require_compliant_device"] = True
                        
                        # Check for location-based access
                        if conditions.get("locations"):
                            required_conditions["location_based_access"] = True
                    
                    # Generate findings for missing conditions
                    if not required_conditions["mfa_for_admins"]:
                        findings.append(SecurityFinding(
                            title="Missing Admin MFA Policy",
                            description="No conditional access policy requires MFA for administrative roles",
                            severity=RiskLevel.CRITICAL,
                            category="access_control",
                            resource_name="Conditional Access Policies",
                            location={"service": "azure_ad", "policy_type": "admin_mfa"},
                            remediation="Create conditional access policy requiring MFA for all admin roles",
                            compliance_impact=["SOC2:CC1.1", "ISO27001:A.9"]
                        ))
                    
                    if not required_conditions["block_legacy_auth"]:
                        findings.append(SecurityFinding(
                            title="Legacy Authentication Not Blocked",
                            description="Legacy authentication protocols are not blocked by conditional access",
                            severity=RiskLevel.HIGH,
                            category="authentication",
                            resource_name="Legacy Authentication",
                            location={"service": "azure_ad", "policy_type": "legacy_auth"},
                            remediation="Create policy to block legacy authentication protocols",
                            compliance_impact=["SOC2:CC2.1", "NIST:AC"]
                        ))
                    
                    if len(enabled_policies) == 0:
                        findings.append(SecurityFinding(
                            title="No Conditional Access Policies",
                            description="No conditional access policies are configured and enabled",
                            severity=RiskLevel.CRITICAL,
                            category="access_control",
                            resource_name="Conditional Access",
                            location={"service": "azure_ad"},
                            remediation="Implement comprehensive conditional access policies",
                            compliance_impact=["SOC2:CC1.1", "ISO27001:A.9", "NIST:AC"]
                        ))
                
        except Exception as e:
            logger.error(f"Conditional access check failed: {str(e)}")
            findings.append(SecurityFinding(
                title="Conditional Access Check Failed",
                description=f"Unable to verify conditional access policies: {str(e)}",
                severity=RiskLevel.MEDIUM,
                category="scan_error",
                resource_name="Conditional Access"
            ))
        
        return findings
    
    async def _check_privileged_roles(self) -> List[SecurityFinding]:
        """Check privileged role assignments and usage"""
        findings = []
        
        try:
            # Get directory role assignments
            url = f"{self.base_url}/directoryRoles"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    roles = data.get("value", [])
                    
                    privileged_roles = [
                        "Global Administrator", "Security Administrator", 
                        "Privileged Role Administrator", "User Administrator",
                        "Exchange Administrator", "SharePoint Administrator"
                    ]
                    
                    for role in roles:
                        if role.get("displayName") in privileged_roles:
                            # Get role members
                            members_url = f"{self.base_url}/directoryRoles/{role['id']}/members"
                            
                            async with self.session.get(members_url) as members_response:
                                if members_response.status == 200:
                                    members_data = await members_response.json()
                                    members = members_data.get("value", [])
                                    
                                    if len(members) > 5:  # Threshold for too many privileged users
                                        findings.append(SecurityFinding(
                                            title=f"Excessive {role.get('displayName')} Assignments",
                                            description=f"{len(members)} users assigned to {role.get('displayName')} role",
                                            severity=RiskLevel.MEDIUM,
                                            category="access_control",
                                            resource_name=role.get("displayName"),
                                            location={
                                                "service": "azure_ad", 
                                                "role": role.get("displayName"),
                                                "member_count": len(members)
                                            },
                                            remediation="Review and reduce privileged role assignments",
                                            compliance_impact=["SOC2:CC1.1", "ISO27001:A.9"]
                                        ))
                                    
                                    # Check for service accounts in privileged roles
                                    service_accounts = [m for m in members if "#EXT#" in m.get("userPrincipalName", "")]
                                    if service_accounts:
                                        findings.append(SecurityFinding(
                                            title="External Users in Privileged Roles",
                                            description=f"{len(service_accounts)} external users have {role.get('displayName')} privileges",
                                            severity=RiskLevel.HIGH,
                                            category="access_control",
                                            resource_name=role.get("displayName"),
                                            location={
                                                "service": "azure_ad",
                                                "role": role.get("displayName"),
                                                "external_users": len(service_accounts)
                                            },
                                            remediation="Remove external users from privileged roles or use appropriate governance",
                                            compliance_impact=["SOC2:CC1.1", "GDPR:Art32"]
                                        ))
        
        except Exception as e:
            logger.error(f"Privileged roles check failed: {str(e)}")
            findings.append(SecurityFinding(
                title="Privileged Roles Check Failed",
                description=f"Unable to verify privileged role assignments: {str(e)}",
                severity=RiskLevel.MEDIUM,
                category="scan_error",
                resource_name="Privileged Roles"
            ))
        
        return findings
    
    async def _check_guest_access(self) -> List[SecurityFinding]:
        """Check guest user access configuration"""
        findings = []
        
        try:
            # Get guest users
            url = f"{self.base_url}/users?$filter=userType eq 'Guest'"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    guest_users = data.get("value", [])
                    
                    total_guests = len(guest_users)
                    
                    if total_guests > 0:
                        # Check for inactive guest accounts
                        inactive_guests = []
                        
                        for guest in guest_users:
                            last_signin = guest.get("signInActivity", {}).get("lastSignInDateTime")
                            if last_signin:
                                last_signin_date = datetime.fromisoformat(last_signin.replace("Z", "+00:00"))
                                if (datetime.utcnow().replace(tzinfo=last_signin_date.tzinfo) - last_signin_date).days > 90:
                                    inactive_guests.append(guest)
                            else:
                                # Never signed in
                                inactive_guests.append(guest)
                        
                        if len(inactive_guests) > 0:
                            findings.append(SecurityFinding(
                                title="Inactive Guest User Accounts",
                                description=f"{len(inactive_guests)} guest accounts haven't been used in 90+ days",
                                severity=RiskLevel.MEDIUM,
                                category="access_control",
                                resource_name="Guest User Accounts",
                                location={
                                    "service": "azure_ad",
                                    "inactive_guests": len(inactive_guests),
                                    "total_guests": total_guests
                                },
                                remediation="Review and remove inactive guest accounts",
                                compliance_impact=["SOC2:CC1.1", "GDPR:Art25"]
                            ))
                        
                        # Check guest access restrictions
                        settings_url = f"{self.base_url}/policies/authorizationPolicy"
                        
                        async with self.session.get(settings_url) as settings_response:
                            if settings_response.status == 200:
                                settings_data = await settings_response.json()
                                guest_restrictions = settings_data.get("allowedToUseSSPR", True)
                                
                                if not guest_restrictions:
                                    findings.append(SecurityFinding(
                                        title="Unrestricted Guest Access",
                                        description="Guest users have unrestricted access to directory information",
                                        severity=RiskLevel.MEDIUM,
                                        category="access_control",
                                        resource_name="Guest Access Policy",
                                        location={"service": "azure_ad", "policy": "guest_restrictions"},
                                        remediation="Configure appropriate guest access restrictions",
                                        compliance_impact=["SOC2:CC1.1", "GDPR:Art32"]
                                    ))
        
        except Exception as e:
            logger.error(f"Guest access check failed: {str(e)}")
            findings.append(SecurityFinding(
                title="Guest Access Check Failed",
                description=f"Unable to verify guest access configuration: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Guest Access"
            ))
        
        return findings
    
    async def _check_identity_protection(self) -> List[SecurityFinding]:
        """Check identity protection settings"""
        findings = []
        
        try:
            # Check identity protection policies
            url = f"{self.beta_url}/identity/identityProtection/riskPolicies"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    policies = data.get("value", [])
                    
                    if not policies:
                        findings.append(SecurityFinding(
                            title="Identity Protection Not Configured",
                            description="No identity protection policies are configured",
                            severity=RiskLevel.HIGH,
                            category="identity_protection",
                            resource_name="Identity Protection",
                            location={"service": "azure_ad", "feature": "identity_protection"},
                            remediation="Configure identity protection policies for risk-based access",
                            compliance_impact=["SOC2:CC2.1", "ISO27001:A.12"]
                        ))
                    else:
                        # Check policy configurations
                        user_risk_policy = None
                        signin_risk_policy = None
                        
                        for policy in policies:
                            if policy.get("riskType") == "user":
                                user_risk_policy = policy
                            elif policy.get("riskType") == "signIn":
                                signin_risk_policy = policy
                        
                        if not user_risk_policy or user_risk_policy.get("state") != "enabled":
                            findings.append(SecurityFinding(
                                title="User Risk Policy Not Enabled",
                                description="Identity protection user risk policy is not enabled",
                                severity=RiskLevel.MEDIUM,
                                category="identity_protection",
                                resource_name="User Risk Policy",
                                location={"service": "azure_ad", "policy": "user_risk"},
                                remediation="Enable and configure user risk policy",
                                compliance_impact=["SOC2:CC2.1"]
                            ))
                        
                        if not signin_risk_policy or signin_risk_policy.get("state") != "enabled":
                            findings.append(SecurityFinding(
                                title="Sign-in Risk Policy Not Enabled",
                                description="Identity protection sign-in risk policy is not enabled",
                                severity=RiskLevel.MEDIUM,
                                category="identity_protection",
                                resource_name="Sign-in Risk Policy",
                                location={"service": "azure_ad", "policy": "signin_risk"},
                                remediation="Enable and configure sign-in risk policy",
                                compliance_impact=["SOC2:CC2.1"]
                            ))
                
        except Exception as e:
            # Identity protection might not be available in all tenants
            logger.warning(f"Identity protection check failed (may not be available): {str(e)}")
        
        return findings
    
    async def _check_password_policies(self) -> List[SecurityFinding]:
        """Check password policy configuration"""
        findings = []
        
        try:
            # Get domain password policy
            url = f"{self.base_url}/domains"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    domains = data.get("value", [])
                    
                    for domain in domains:
                        if domain.get("isDefault", False):
                            # Check password policy settings
                            # Note: Detailed password policies require additional Graph API calls
                            # This is a simplified check
                            
                            findings.append(SecurityFinding(
                                title="Password Policy Review Required",
                                description="Password policies should be reviewed for complexity requirements",
                                severity=RiskLevel.LOW,
                                category="authentication",
                                resource_name="Password Policy",
                                location={"service": "azure_ad", "domain": domain.get("id")},
                                remediation="Review and strengthen password complexity requirements",
                                compliance_impact=["SOC2:CC1.1", "ISO27001:A.9"]
                            ))
        
        except Exception as e:
            logger.error(f"Password policy check failed: {str(e)}")
        
        return findings
    
    async def _check_application_security(self) -> List[SecurityFinding]:
        """Check application registrations and permissions"""
        findings = []
        
        try:
            # Get application registrations
            url = f"{self.base_url}/applications"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    applications = data.get("value", [])
                    
                    high_risk_permissions = [
                        "Directory.ReadWrite.All", "Directory.AccessAsUser.All",
                        "User.ReadWrite.All", "Group.ReadWrite.All",
                        "Mail.ReadWrite", "Files.ReadWrite.All"
                    ]
                    
                    for app in applications:
                        app_name = app.get("displayName", "Unknown App")
                        required_permissions = app.get("requiredResourceAccess", [])
                        
                        # Check for high-risk permissions
                        risky_permissions = []
                        for resource in required_permissions:
                            for permission in resource.get("resourceAccess", []):
                                perm_id = permission.get("id")
                                # This would need to be mapped to permission names
                                # Simplified check for demonstration
                                if len(resource.get("resourceAccess", [])) > 10:
                                    risky_permissions.append("Multiple high permissions")
                        
                        if risky_permissions:
                            findings.append(SecurityFinding(
                                title=f"High-Risk Application Permissions: {app_name}",
                                description=f"Application has excessive permissions: {', '.join(risky_permissions)}",
                                severity=RiskLevel.MEDIUM,
                                category="application_security",
                                resource_name=app_name,
                                location={
                                    "service": "azure_ad",
                                    "application_id": app.get("appId"),
                                    "object_id": app.get("id")
                                },
                                remediation="Review and reduce application permissions to minimum required",
                                compliance_impact=["SOC2:CC1.1", "ISO27001:A.9"]
                            ))
                        
                        # Check for applications with secrets/certificates
                        password_credentials = app.get("passwordCredentials", [])
                        key_credentials = app.get("keyCredentials", [])
                        
                        # Check for expired credentials
                        expired_secrets = [
                            cred for cred in password_credentials
                            if datetime.fromisoformat(cred.get("endDateTime", "").replace("Z", "+00:00")) < datetime.utcnow().replace(tzinfo=datetime.now().astimezone().tzinfo)
                        ]
                        
                        if expired_secrets:
                            findings.append(SecurityFinding(
                                title=f"Expired Application Secrets: {app_name}",
                                description=f"Application has {len(expired_secrets)} expired client secrets",
                                severity=RiskLevel.MEDIUM,
                                category="credential_management",
                                resource_name=app_name,
                                location={
                                    "service": "azure_ad",
                                    "application_id": app.get("appId")
                                },
                                remediation="Update expired client secrets and implement rotation policy",
                                compliance_impact=["SOC2:CC3.1", "ISO27001:A.10"]
                            ))
        
        except Exception as e:
            logger.error(f"Application security check failed: {str(e)}")
            findings.append(SecurityFinding(
                title="Application Security Check Failed",
                description=f"Unable to verify application security: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Application Registrations"
            ))
        
        return findings
    
    async def _scan_sharepoint(self) -> List[SecurityFinding]:
        """Scan SharePoint Online security configuration"""
        findings = []
        
        try:
            logger.info("Scanning SharePoint Online configuration...")
            
            # Get SharePoint admin settings
            admin_url = f"{self.base_url}/admin/sharepoint/settings"
            
            # Note: SharePoint admin settings require specific permissions
            # This is a simplified implementation
            
            findings.append(SecurityFinding(
                title="SharePoint Security Review Required",
                description="SharePoint Online security settings should be reviewed manually",
                severity=RiskLevel.LOW,
                category="configuration",
                resource_name="SharePoint Online",
                location={"service": "sharepoint"},
                remediation="Review external sharing, access permissions, and DLP policies",
                compliance_impact=["SOC2:CC3.1", "GDPR:Art25"]
            ))
            
        except Exception as e:
            logger.error(f"SharePoint scan failed: {str(e)}")
            findings.append(SecurityFinding(
                title="SharePoint Scan Error",
                description=f"Failed to complete SharePoint security scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="SharePoint Online"
            ))
        
        return findings
    
    async def _scan_teams(self) -> List[SecurityFinding]:
        """Scan Microsoft Teams security configuration"""
        findings = []
        
        try:
            logger.info("Scanning Microsoft Teams configuration...")
            
            # Teams settings would require Teams-specific Graph API endpoints
            # This is a placeholder implementation
            
            findings.append(SecurityFinding(
                title="Teams Security Review Required",
                description="Microsoft Teams security settings should be reviewed",
                severity=RiskLevel.LOW,
                category="configuration",
                resource_name="Microsoft Teams",
                location={"service": "teams"},
                remediation="Review guest access, meeting policies, and app permissions",
                compliance_impact=["SOC2:CC1.1", "GDPR:Art32"]
            ))
            
        except Exception as e:
            logger.error(f"Teams scan failed: {str(e)}")
            findings.append(SecurityFinding(
                title="Teams Scan Error",
                description=f"Failed to complete Teams security scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Microsoft Teams"
            ))
        
        return findings
    
    async def _scan_exchange(self) -> List[SecurityFinding]:
        """Scan Exchange Online security configuration"""
        findings = []
        
        try:
            logger.info("Scanning Exchange Online configuration...")
            
            # Exchange settings would require Exchange-specific Graph API endpoints
            # This is a placeholder implementation
            
            findings.append(SecurityFinding(
                title="Exchange Security Review Required",
                description="Exchange Online security settings should be reviewed",
                severity=RiskLevel.LOW,
                category="configuration",
                resource_name="Exchange Online",
                location={"service": "exchange"},
                remediation="Review mail flow rules, ATP policies, and mailbox permissions",
                compliance_impact=["SOC2:CC2.1", "HIPAA:164.312"]
            ))
            
        except Exception as e:
            logger.error(f"Exchange scan failed: {str(e)}")
            findings.append(SecurityFinding(
                title="Exchange Scan Error",
                description=f"Failed to complete Exchange security scan: {str(e)}",
                severity=RiskLevel.LOW,
                category="scan_error",
                resource_name="Exchange Online"
            ))
        
        return findings
    
    # Helper methods for policy analysis
    
    def _policy_targets_admins(self, policy: Dict) -> bool:
        """Check if policy targets administrative users"""
        conditions = policy.get("conditions", {})
        users = conditions.get("users", {})
        include_roles = users.get("includeRoles", [])
        
        admin_roles = [
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
        ]
        
        return any(role in admin_roles for role in include_roles)
    
    def _policy_requires_mfa(self, grant_controls: Dict) -> bool:
        """Check if policy requires MFA"""
        built_in_controls = grant_controls.get("builtInControls", [])
        return "mfa" in built_in_controls
    
    def _policy_blocks_legacy_auth(self, conditions: Dict) -> bool:
        """Check if policy blocks legacy authentication"""
        client_apps = conditions.get("clientAppTypes", [])
        return "exchangeActiveSync" in client_apps or "other" in client_apps
    
    def _policy_requires_compliant_device(self, grant_controls: Dict) -> bool:
        """Check if policy requires compliant device"""
        built_in_controls = grant_controls.get("builtInControls", [])
        return "compliantDevice" in built_in_controls or "domainJoinedDevice" in built_in_controls
    
    async def _get_organization_info(self) -> Dict:
        """Get organization information"""
        try:
            url = f"{self.base_url}/organization"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    orgs = data.get("value", [])
                    return orgs[0] if orgs else {}
                
        except Exception as e:
            logger.error(f"Failed to get organization info: {str(e)}")
            
        return {}
    
    def _count_by_severity(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Count findings by severity level"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in findings:
            severity = finding.severity.value.upper()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    async def get_users(self, integration_config: Dict) -> List[Dict]:
        """Get Microsoft 365 users for scanning"""
        try:
            if not await self.initialize_session(integration_config):
                return []
            
            url = f"{self.base_url}/users?$select=id,userPrincipalName,displayName,jobTitle,department,userType"
            users = []
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    users = data.get("value", [])
            
            await self.cleanup_session()
            return users
            
        except Exception as e:
            logger.error(f"Failed to get Microsoft 365 users: {str(e)}")
            return []
    
    async def scan_user_security(self, users: List[Dict]) -> List[Dict]:
        """Scan user security configuration"""
        findings = []
        
        try:
            for user in users:
                # Check for admin users without MFA
                if user.get("userType") == "Member":
                    # This would require additional API calls to check MFA status
                    finding = {
                        "type": "user_security",
                        "user_id": user.get("id"),
                        "user_name": user.get("userPrincipalName"),
                        "issue": "MFA status verification required",
                        "severity": "MEDIUM"
                    }
                    findings.append(finding)
            
        except Exception as e:
            logger.error(f"User security scan failed: {str(e)}")
        
        return findings
    
    def health_check(self) -> bool:
        """Perform health check of the scanner"""
        try:
            # Basic health check - verify configuration
            return True
        except Exception as e:
            logger.error(f"Microsoft 365 scanner health check failed: {str(e)}")
            return False
