"""
Common scanner framework and utilities
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, AsyncGenerator
from datetime import datetime, timedelta
import asyncio
from dataclasses import dataclass

from ..api.models.findings import FindingType, RiskLevel
from ..api.services.risk_engine import risk_engine
from ..api.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Represents a single scan result/finding"""
    title: str
    description: str
    finding_type: FindingType
    evidence: Dict[str, Any]
    resource_id: str
    resource_name: str
    resource_type: str
    remediation_steps: str
    metadata: Optional[Dict[str, Any]] = None


class BaseScannerError(Exception):
    """Base exception for scanner errors"""
    pass


class ScannerAuthError(BaseScannerError):
    """Authentication/authorization error"""
    pass


class ScannerRateLimitError(BaseScannerError):
    """Rate limit exceeded error"""
    pass


class BaseScanner(ABC):
    """Base class for all service scanners"""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.logger = logger.bind(scanner=service_name)
    
    @abstractmethod
    async def authenticate(self, access_token: str, **kwargs) -> bool:
        """Authenticate with the service"""
        pass
    
    @abstractmethod
    async def scan_users(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for user-related security issues"""
        pass
    
    @abstractmethod
    async def scan_permissions(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for permission-related issues"""
        pass
    
    @abstractmethod
    async def scan_data_sharing(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for data sharing and access issues"""
        pass
    
    async def scan_all(self, access_token: str, **kwargs) -> List[ScanResult]:
        """Run comprehensive scan across all categories"""
        self.logger.info("Starting comprehensive scan")
        
        # Authenticate first
        if not await self.authenticate(access_token, **kwargs):
            raise ScannerAuthError(f"Authentication failed for {self.service_name}")
        
        all_results = []
        
        try:
            # Run all scan types
            scan_methods = [
                self.scan_users,
                self.scan_permissions,
                self.scan_data_sharing
            ]
            
            for scan_method in scan_methods:
                scan_name = scan_method.__name__
                self.logger.info(f"Running {scan_name}")
                
                try:
                    async for result in scan_method(**kwargs):
                        all_results.append(result)
                        self.logger.debug(
                            "Found security issue",
                            title=result.title,
                            type=result.finding_type.value,
                            resource=result.resource_name
                        )
                except Exception as e:
                    self.logger.error(
                        f"Error in {scan_name}",
                        error=str(e),
                        scan_method=scan_name
                    )
                    # Continue with other scans even if one fails
                    continue
            
            self.logger.info(
                "Scan completed",
                total_findings=len(all_results),
                service=self.service_name
            )
            
        except Exception as e:
            self.logger.error("Comprehensive scan failed", error=str(e))
            raise BaseScannerError(f"Scan failed for {self.service_name}: {str(e)}")
        
        return all_results
    
    def _create_inactive_user_finding(
        self, 
        user_data: Dict[str, Any],
        days_inactive: int = 0
    ) -> ScanResult:
        """Helper to create inactive user finding"""
        user_name = user_data.get("name", "Unknown User")
        user_email = user_data.get("email", "unknown@example.com")
        
        evidence = {
            "user_id": user_data.get("id"),
            "email": user_email,
            "last_login_days": days_inactive,
            "is_admin": user_data.get("is_admin", False),
            "has_admin_roles": user_data.get("admin_roles", []),
            "account_created": user_data.get("created_date"),
            "last_activity": user_data.get("last_activity")
        }
        
        return ScanResult(
            title=f"Inactive User Account: {user_name}",
            description=f"User {user_email} has been inactive for {days_inactive} days but still has active account access.",
            finding_type=FindingType.INACTIVE_USER,
            evidence=evidence,
            resource_id=str(user_data.get("id", "")),
            resource_name=user_email,
            resource_type="user",
            remediation_steps=f"Review and consider deactivating inactive user account for {user_email}. "
                            f"Verify with user's manager if access is still needed.",
            metadata={"service": self.service_name}
        )
    
    def _create_public_share_finding(
        self, 
        resource_data: Dict[str, Any],
        share_type: str = "file"
    ) -> ScanResult:
        """Helper to create public sharing finding"""
        resource_name = resource_data.get("name", "Unknown Resource")
        
        evidence = {
            "resource_id": resource_data.get("id"),
            "sharing_permissions": resource_data.get("permissions", []),
            "public_access": resource_data.get("public_access", True),
            "external_sharing": resource_data.get("external_sharing", False),
            "access_count": resource_data.get("access_count", 0),
            "created_by": resource_data.get("owner"),
            "sensitive_content": resource_data.get("contains_sensitive_data", False)
        }
        
        return ScanResult(
            title=f"Public {share_type.title()}: {resource_name}",
            description=f"Resource '{resource_name}' is publicly accessible or shared externally, "
                       f"potentially exposing sensitive information.",
            finding_type=FindingType.PUBLIC_SHARE,
            evidence=evidence,
            resource_id=str(resource_data.get("id", "")),
            resource_name=resource_name,
            resource_type=share_type,
            remediation_steps=f"Review sharing permissions for '{resource_name}' and restrict access "
                            f"to only necessary users or groups.",
            metadata={"service": self.service_name}
        )
    
    def _create_overpermissive_token_finding(
        self, 
        token_data: Dict[str, Any]
    ) -> ScanResult:
        """Helper to create overpermissive token finding"""
        app_name = token_data.get("app_name", "Unknown Application")
        
        evidence = {
            "app_id": token_data.get("app_id"),
            "scopes": token_data.get("scopes", []),
            "permissions": token_data.get("permissions", []),
            "created_date": token_data.get("created"),
            "last_used": token_data.get("last_used"),
            "never_used": not token_data.get("last_used"),
            "admin_access": any("admin" in str(scope).lower() for scope in token_data.get("scopes", []))
        }
        
        return ScanResult(
            title=f"Overpermissive Token: {app_name}",
            description=f"Application '{app_name}' has been granted excessive permissions that "
                       f"may pose security risks.",
            finding_type=FindingType.OVERPERMISSIVE_TOKEN,
            evidence=evidence,
            resource_id=str(token_data.get("app_id", "")),
            resource_name=app_name,
            resource_type="application_token",
            remediation_steps=f"Review and reduce permissions granted to '{app_name}'. "
                            f"Apply principle of least privilege.",
            metadata={"service": self.service_name}
        )
    
    def _create_mfa_disabled_finding(
        self, 
        user_data: Dict[str, Any]
    ) -> ScanResult:
        """Helper to create MFA disabled finding"""
        user_name = user_data.get("name", "Unknown User")
        user_email = user_data.get("email", "unknown@example.com")
        
        evidence = {
            "user_id": user_data.get("id"),
            "email": user_email,
            "mfa_enabled": False,
            "is_admin": user_data.get("is_admin", False),
            "login_methods": user_data.get("login_methods", []),
            "last_login": user_data.get("last_login")
        }
        
        return ScanResult(
            title=f"MFA Disabled: {user_name}",
            description=f"Multi-factor authentication is not enabled for user {user_email}, "
                       f"increasing account compromise risk.",
            finding_type=FindingType.MFA_DISABLED,
            evidence=evidence,
            resource_id=str(user_data.get("id", "")),
            resource_name=user_email,
            resource_type="user",
            remediation_steps=f"Enable multi-factor authentication for {user_email}. "
                            f"Configure backup authentication methods.",
            metadata={"service": self.service_name}
        )
    
    def _create_excessive_permissions_finding(
        self, 
        user_data: Dict[str, Any]
    ) -> ScanResult:
        """Helper to create excessive permissions finding"""
        user_name = user_data.get("name", "Unknown User")
        user_email = user_data.get("email", "unknown@example.com")
        
        evidence = {
            "user_id": user_data.get("id"),
            "email": user_email,
            "roles": user_data.get("roles", []),
            "permissions": user_data.get("permissions", []),
            "admin_privileges": user_data.get("is_admin", False),
            "group_memberships": user_data.get("groups", []),
            "last_role_change": user_data.get("last_role_change")
        }
        
        return ScanResult(
            title=f"Excessive Permissions: {user_name}",
            description=f"User {user_email} has been granted permissions that exceed typical requirements "
                       f"for their role or recent activity.",
            finding_type=FindingType.EXCESSIVE_PERMISSIONS,
            evidence=evidence,
            resource_id=str(user_data.get("id", "")),
            resource_name=user_email,
            resource_type="user",
            remediation_steps=f"Review permissions for {user_email} and apply principle of least privilege. "
                            f"Remove unnecessary roles and access rights.",
            metadata={"service": self.service_name}
        )


class ScannerRegistry:
    """Registry for managing scanner instances"""
    
    def __init__(self):
        self._scanners: Dict[str, BaseScanner] = {}
        self.logger = logger.bind(component="scanner_registry")
    
    def register_scanner(self, service_name: str, scanner: BaseScanner):
        """Register a scanner for a service"""
        self._scanners[service_name] = scanner
        self.logger.info(f"Registered scanner for {service_name}")
    
    def get_scanner(self, service_name: str) -> Optional[BaseScanner]:
        """Get scanner for a service"""
        return self._scanners.get(service_name)
    
    def list_scanners(self) -> List[str]:
        """List all registered scanner services"""
        return list(self._scanners.keys())
    
    async def run_scan(
        self, 
        service_name: str, 
        access_token: str, 
        **kwargs
    ) -> List[ScanResult]:
        """Run scan for a specific service"""
        scanner = self.get_scanner(service_name)
        if not scanner:
            raise BaseScannerError(f"No scanner registered for {service_name}")
        
        return await scanner.scan_all(access_token, **kwargs)


# Global scanner registry
scanner_registry = ScannerRegistry()
