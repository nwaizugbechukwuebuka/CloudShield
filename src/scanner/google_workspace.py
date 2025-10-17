"""
Google Workspace security scanner
"""
import httpx
from typing import Dict, Any, AsyncGenerator, List
from datetime import datetime, timedelta
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

from .common import BaseScanner, ScanResult, ScannerAuthError, FindingType, scanner_registry
from ..api.utils.logger import get_logger

logger = get_logger(__name__)


class GoogleWorkspaceScanner(BaseScanner):
    """Scanner for Google Workspace security issues"""
    
    def __init__(self):
        super().__init__("google_workspace")
        self.credentials = None
        self.admin_service = None
        self.drive_service = None
        self.reports_service = None
    
    async def authenticate(self, access_token: str, **kwargs) -> bool:
        """Authenticate with Google Workspace APIs"""
        try:
            # Create credentials object
            self.credentials = Credentials(token=access_token)
            
            # Build API service clients
            self.admin_service = build('admin', 'directory_v1', credentials=self.credentials)
            self.drive_service = build('drive', 'v3', credentials=self.credentials)
            self.reports_service = build('admin', 'reports_v1', credentials=self.credentials)
            
            # Test authentication by making a simple API call
            result = self.admin_service.users().list(domain='', maxResults=1).execute()
            
            self.logger.info("Google Workspace authentication successful")
            return True
            
        except Exception as e:
            self.logger.error("Google Workspace authentication failed", error=str(e))
            return False
    
    async def scan_users(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for user-related security issues"""
        if not self.admin_service:
            raise ScannerAuthError("Not authenticated with Google Workspace")
        
        try:
            # Get all users
            users_result = self.admin_service.users().list(
                domain='',
                maxResults=500,
                orderBy='email'
            ).execute()
            
            users = users_result.get('users', [])
            
            for user in users:
                user_email = user.get('primaryEmail', '')
                
                # Check for inactive users
                last_login_time = user.get('lastLoginTime')
                if last_login_time:
                    last_login = datetime.fromisoformat(last_login_time.replace('Z', '+00:00'))
                    days_inactive = (datetime.now().replace(tzinfo=None) - last_login.replace(tzinfo=None)).days
                    
                    if days_inactive > 90:  # Inactive for more than 90 days
                        yield self._create_inactive_user_finding({
                            "id": user.get('id'),
                            "name": user.get('name', {}).get('fullName', ''),
                            "email": user_email,
                            "is_admin": user.get('isAdmin', False),
                            "admin_roles": user.get('isMailboxSetup', False),
                            "created_date": user.get('creationTime'),
                            "last_activity": last_login_time
                        }, days_inactive)
                
                # Check for users without 2FA
                if not user.get('isEnrolledIn2Sv', False):
                    yield self._create_mfa_disabled_finding({
                        "id": user.get('id'),
                        "name": user.get('name', {}).get('fullName', ''),
                        "email": user_email,
                        "is_admin": user.get('isAdmin', False),
                        "login_methods": ["password"],
                        "last_login": last_login_time
                    })
                
                # Check for excessive admin permissions
                if user.get('isAdmin', False):
                    yield self._create_excessive_permissions_finding({
                        "id": user.get('id'),
                        "name": user.get('name', {}).get('fullName', ''),
                        "email": user_email,
                        "roles": ["admin"],
                        "permissions": ["full_admin_access"],
                        "is_admin": True,
                        "groups": [],
                        "last_role_change": user.get('lastLoginTime')
                    })
        
        except Exception as e:
            self.logger.error("Error scanning Google Workspace users", error=str(e))
            raise
    
    async def scan_permissions(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for permission-related issues"""
        if not self.admin_service or not self.drive_service:
            raise ScannerAuthError("Not authenticated with Google Workspace")
        
        try:
            # Scan OAuth applications with excessive permissions
            tokens_result = self.admin_service.tokens().list(userKey='all').execute()
            tokens = tokens_result.get('items', [])
            
            for token in tokens:
                scopes = token.get('scopes', [])
                
                # Check for overly broad scopes
                high_risk_scopes = [
                    'https://www.googleapis.com/auth/admin.directory.user',
                    'https://www.googleapis.com/auth/admin.directory.group',
                    'https://www.googleapis.com/auth/drive',
                    'https://www.googleapis.com/auth/admin.reports.audit.readonly'
                ]
                
                if any(scope in high_risk_scopes for scope in scopes):
                    yield self._create_overpermissive_token_finding({
                        "app_id": token.get('clientId'),
                        "app_name": token.get('displayText', 'Unknown App'),
                        "scopes": scopes,
                        "permissions": scopes,
                        "created": None,
                        "last_used": None
                    })
        
        except Exception as e:
            self.logger.error("Error scanning Google Workspace permissions", error=str(e))
            raise
    
    async def scan_data_sharing(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for data sharing and access issues"""
        if not self.drive_service:
            raise ScannerAuthError("Not authenticated with Google Workspace")
        
        try:
            # Scan for publicly shared files
            files_result = self.drive_service.files().list(
                q="visibility='anyoneWithLink' or visibility='anyoneCanFind'",
                fields='files(id,name,permissions,owners,shared,webViewLink)',
                pageSize=100
            ).execute()
            
            files = files_result.get('files', [])
            
            for file in files:
                # Get detailed permissions
                permissions_result = self.drive_service.permissions().list(
                    fileId=file['id'],
                    fields='permissions(type,role,emailAddress)'
                ).execute()
                
                permissions = permissions_result.get('permissions', [])
                
                # Check for public access
                public_access = any(
                    perm.get('type') == 'anyone' 
                    for perm in permissions
                )
                
                if public_access:
                    yield self._create_public_share_finding({
                        "id": file.get('id'),
                        "name": file.get('name'),
                        "permissions": permissions,
                        "public_access": True,
                        "external_sharing": True,
                        "access_count": 0,  # Google doesn't provide this easily
                        "owner": file.get('owners', [{}])[0].get('emailAddress'),
                        "contains_sensitive_data": self._check_sensitive_content(file.get('name', ''))
                    }, "file")
        
        except Exception as e:
            self.logger.error("Error scanning Google Workspace data sharing", error=str(e))
            raise
    
    def _check_sensitive_content(self, filename: str) -> bool:
        """Check if filename suggests sensitive content"""
        sensitive_keywords = [
            'password', 'secret', 'private', 'confidential', 'ssn', 'tax',
            'salary', 'payroll', 'financial', 'bank', 'credit', 'personal'
        ]
        
        filename_lower = filename.lower()
        return any(keyword in filename_lower for keyword in sensitive_keywords)


# Register the scanner
scanner_registry.register_scanner("google_workspace", GoogleWorkspaceScanner())
