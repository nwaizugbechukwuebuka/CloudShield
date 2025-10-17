"""
Slack security scanner
"""
import httpx
from typing import Dict, Any, AsyncGenerator, List
from datetime import datetime, timedelta
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from .common import BaseScanner, ScanResult, ScannerAuthError, FindingType, scanner_registry
from ..api.utils.logger import get_logger

logger = get_logger(__name__)


class SlackScanner(BaseScanner):
    """Scanner for Slack security issues"""
    
    def __init__(self):
        super().__init__("slack")
        self.client = None
        self.team_info = None
    
    async def authenticate(self, access_token: str, **kwargs) -> bool:
        """Authenticate with Slack API"""
        try:
            self.client = WebClient(token=access_token)
            
            # Test authentication
            response = self.client.auth_test()
            if not response["ok"]:
                return False
            
            # Get team info
            team_response = self.client.team_info()
            if team_response["ok"]:
                self.team_info = team_response["team"]
            
            self.logger.info("Slack authentication successful")
            return True
            
        except SlackApiError as e:
            self.logger.error("Slack authentication failed", error=str(e))
            return False
        except Exception as e:
            self.logger.error("Slack authentication error", error=str(e))
            return False
    
    async def scan_users(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for user-related security issues"""
        if not self.client:
            raise ScannerAuthError("Not authenticated with Slack")
        
        try:
            # Get all users
            response = self.client.users_list()
            if not response["ok"]:
                raise ScannerAuthError("Failed to get Slack users")
            
            users = response["members"]
            
            for user in users:
                # Skip bots and deleted users
                if user.get("is_bot") or user.get("deleted"):
                    continue
                
                profile = user.get("profile", {})
                user_email = profile.get("email", "")
                user_name = profile.get("real_name", user.get("name", ""))
                
                # Check for inactive users
                # Slack doesn't provide last login directly, so we use presence
                try:
                    presence_response = self.client.users_getPresence(user=user["id"])
                    if presence_response["ok"]:
                        # If user has been away for a long time or never set presence
                        presence = presence_response.get("presence", "away")
                        
                        # This is a simplified check - in practice you'd want more sophisticated logic
                        if presence == "away":
                            # Check if user has 2FA enabled (if available in profile)
                            has_2fa = user.get("has_2fa", False)
                            
                            if not has_2fa:
                                yield self._create_mfa_disabled_finding({
                                    "id": user["id"],
                                    "name": user_name,
                                    "email": user_email,
                                    "is_admin": user.get("is_admin", False),
                                    "login_methods": ["password"],
                                    "last_login": None
                                })
                
                except SlackApiError:
                    # Might not have permission to check presence
                    pass
                
                # Check for admin users (potential excessive permissions)
                if user.get("is_admin") or user.get("is_owner"):
                    yield self._create_excessive_permissions_finding({
                        "id": user["id"],
                        "name": user_name,
                        "email": user_email,
                        "roles": ["admin" if user.get("is_admin") else "owner"],
                        "permissions": ["workspace_admin"],
                        "is_admin": True,
                        "groups": [],
                        "last_role_change": None
                    })
        
        except SlackApiError as e:
            self.logger.error("Error scanning Slack users", error=str(e))
            raise
        except Exception as e:
            self.logger.error("Error scanning Slack users", error=str(e))
            raise
    
    async def scan_permissions(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for permission-related issues"""
        if not self.client:
            raise ScannerAuthError("Not authenticated with Slack")
        
        try:
            # Scan apps and integrations
            apps_response = self.client.apps_list()
            if apps_response["ok"]:
                apps = apps_response.get("apps", [])
                
                for app in apps:
                    app_name = app.get("name", "Unknown App")
                    scopes = app.get("scopes", {})
                    
                    # Check for overpermissive scopes
                    high_risk_scopes = [
                        "admin", "channels:write", "groups:write", "im:write",
                        "mpim:write", "files:write:user", "users:write"
                    ]
                    
                    bot_scopes = scopes.get("bot", [])
                    user_scopes = scopes.get("user", [])
                    all_scopes = bot_scopes + user_scopes
                    
                    if any(scope in all_scopes for scope in high_risk_scopes):
                        yield self._create_overpermissive_token_finding({
                            "app_id": app.get("id"),
                            "app_name": app_name,
                            "scopes": all_scopes,
                            "permissions": all_scopes,
                            "created": None,
                            "last_used": None
                        })
        
        except SlackApiError as e:
            self.logger.error("Error scanning Slack permissions", error=str(e))
            raise
        except Exception as e:
            self.logger.error("Error scanning Slack permissions", error=str(e))
            raise
    
    async def scan_data_sharing(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for data sharing and access issues"""
        if not self.client:
            raise ScannerAuthError("Not authenticated with Slack")
        
        try:
            # Check public channels that might contain sensitive information
            channels_response = self.client.conversations_list(
                types="public_channel",
                exclude_archived=True
            )
            
            if channels_response["ok"]:
                channels = channels_response["channels"]
                
                for channel in channels:
                    channel_name = channel.get("name", "")
                    
                    # Flag channels with potentially sensitive names
                    if self._has_sensitive_channel_name(channel_name):
                        yield self._create_public_share_finding({
                            "id": channel["id"],
                            "name": channel_name,
                            "permissions": ["public"],
                            "public_access": True,
                            "external_sharing": False,
                            "access_count": channel.get("num_members", 0),
                            "owner": channel.get("creator"),
                            "contains_sensitive_data": True
                        }, "channel")
            
            # Check for files shared publicly
            files_response = self.client.files_list(
                count=100,
                page=1
            )
            
            if files_response["ok"]:
                files = files_response.get("files", [])
                
                for file in files:
                    # Check if file is shared publicly or externally
                    if file.get("public_url_shared", False):
                        yield self._create_public_share_finding({
                            "id": file["id"],
                            "name": file.get("name", "Unknown File"),
                            "permissions": ["public"],
                            "public_access": True,
                            "external_sharing": True,
                            "access_count": 0,
                            "owner": file.get("user"),
                            "contains_sensitive_data": self._is_sensitive_file(file.get("name", ""))
                        }, "file")
        
        except SlackApiError as e:
            self.logger.error("Error scanning Slack data sharing", error=str(e))
            raise
        except Exception as e:
            self.logger.error("Error scanning Slack data sharing", error=str(e))
            raise
    
    def _has_sensitive_channel_name(self, channel_name: str) -> bool:
        """Check if channel name suggests sensitive content"""
        sensitive_keywords = [
            "secret", "private", "confidential", "internal", "password",
            "admin", "security", "finance", "payroll", "hr", "legal"
        ]
        
        channel_name_lower = channel_name.lower()
        return any(keyword in channel_name_lower for keyword in sensitive_keywords)
    
    def _is_sensitive_file(self, filename: str) -> bool:
        """Check if filename suggests sensitive content"""
        sensitive_keywords = [
            "password", "secret", "private", "confidential", "financial",
            "payroll", "ssn", "tax", "contract", "agreement"
        ]
        
        filename_lower = filename.lower()
        return any(keyword in filename_lower for keyword in sensitive_keywords)


# Register the scanner
scanner_registry.register_scanner("slack", SlackScanner())
