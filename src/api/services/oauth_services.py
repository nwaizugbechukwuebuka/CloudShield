"""
OAuth authentication services for various providers
"""
import httpx
import secrets
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlencode
from authlib.integrations.httpx_client import OAuth2Client
from ..utils.config import settings, get_oauth_config
from ..utils.logger import get_logger, security_logger

logger = get_logger(__name__)


class OAuthError(Exception):
    """OAuth-related errors"""
    pass


class BaseOAuthService:
    """Base OAuth service class"""
    
    def __init__(self, provider: str):
        self.provider = provider
        self.config = get_oauth_config(provider)
        if not self.config:
            raise OAuthError(f"OAuth configuration not found for provider: {provider}")
    
    def generate_authorization_url(self, state: str = None) -> Tuple[str, str]:
        """Generate OAuth authorization URL"""
        if not state:
            state = secrets.token_urlsafe(32)
        
        params = {
            "client_id": self.config["client_id"],
            "redirect_uri": self.config["redirect_uri"],
            "response_type": "code",
            "state": state,
            "scope": " ".join(self.config["scope"])
        }
        
        # Provider-specific parameters
        if self.provider == "microsoft":
            params["response_mode"] = "query"
        
        authorization_url = f"{self.config['authorization_url']}?{urlencode(params)}"
        return authorization_url, state
    
    async def exchange_code_for_tokens(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange authorization code for access tokens"""
        token_data = {
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.config["redirect_uri"]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config["token_url"],
                data=token_data,
                headers={"Accept": "application/json"}
            )
            
            if response.status_code != 200:
                logger.error(
                    "Token exchange failed",
                    provider=self.provider,
                    status_code=response.status_code,
                    response=response.text
                )
                raise OAuthError(f"Token exchange failed for {self.provider}")
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information using access token - to be implemented by subclasses"""
        raise NotImplementedError
    
    async def validate_token(self, access_token: str) -> bool:
        """Validate access token"""
        try:
            await self.get_user_info(access_token)
            return True
        except Exception:
            return False


class GoogleOAuthService(BaseOAuthService):
    """Google Workspace OAuth service"""
    
    def __init__(self):
        super().__init__("google")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Google user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise OAuthError("Failed to get Google user info")
            
            return response.json()
    
    async def get_organization_info(self, access_token: str) -> Dict[str, Any]:
        """Get Google Workspace organization information"""
        async with httpx.AsyncClient() as client:
            # Get domain info
            response = await client.get(
                "https://admin.googleapis.com/admin/directory/v1/users",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"maxResults": 1}
            )
            
            if response.status_code == 200:
                data = response.json()
                users = data.get("users", [])
                if users:
                    domain = users[0].get("primaryEmail", "").split("@")[-1]
                    return {"domain": domain, "name": domain}
            
            return {"domain": "unknown", "name": "Google Workspace"}


class MicrosoftOAuthService(BaseOAuthService):
    """Microsoft 365 OAuth service"""
    
    def __init__(self):
        super().__init__("microsoft")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Microsoft user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise OAuthError("Failed to get Microsoft user info")
            
            return response.json()
    
    async def get_organization_info(self, access_token: str) -> Dict[str, Any]:
        """Get Microsoft 365 organization information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code == 200:
                data = response.json()
                orgs = data.get("value", [])
                if orgs:
                    org = orgs[0]
                    return {
                        "name": org.get("displayName", "Microsoft 365"),
                        "domain": org.get("verifiedDomains", [{}])[0].get("name", "unknown")
                    }
            
            return {"name": "Microsoft 365", "domain": "unknown"}


class SlackOAuthService(BaseOAuthService):
    """Slack OAuth service"""
    
    def __init__(self):
        super().__init__("slack")
    
    async def exchange_code_for_tokens(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange authorization code for Slack tokens"""
        token_data = {
            "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"],
            "code": code,
            "redirect_uri": self.config["redirect_uri"]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://slack.com/api/oauth.v2.access",
                data=token_data,
                headers={"Accept": "application/json"}
            )
            
            if response.status_code != 200:
                raise OAuthError("Slack token exchange failed")
            
            data = response.json()
            if not data.get("ok"):
                raise OAuthError(f"Slack OAuth error: {data.get('error', 'Unknown error')}")
            
            return data
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Slack user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise OAuthError("Failed to get Slack user info")
            
            data = response.json()
            if not data.get("ok"):
                raise OAuthError(f"Slack API error: {data.get('error', 'Unknown error')}")
            
            return data
    
    async def get_organization_info(self, access_token: str) -> Dict[str, Any]:
        """Get Slack team information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://slack.com/api/team.info",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("ok"):
                    team = data.get("team", {})
                    return {
                        "name": team.get("name", "Slack Workspace"),
                        "domain": team.get("domain", "unknown")
                    }
            
            return {"name": "Slack Workspace", "domain": "unknown"}


class GitHubOAuthService(BaseOAuthService):
    """GitHub OAuth service"""
    
    def __init__(self):
        super().__init__("github")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get GitHub user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if response.status_code != 200:
                raise OAuthError("Failed to get GitHub user info")
            
            return response.json()
    
    async def get_user_email(self, access_token: str) -> str:
        """Get GitHub user primary email"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if response.status_code == 200:
                emails = response.json()
                for email in emails:
                    if email.get("primary", False):
                        return email.get("email", "")
            
            return ""
    
    async def get_organization_info(self, access_token: str) -> Dict[str, Any]:
        """Get GitHub organization information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user/orgs",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if response.status_code == 200:
                orgs = response.json()
                if orgs:
                    org = orgs[0]  # Take first organization
                    return {
                        "name": org.get("login", "GitHub"),
                        "domain": org.get("login", "unknown")
                    }
            
            return {"name": "GitHub", "domain": "unknown"}


class NotionOAuthService(BaseOAuthService):
    """Notion OAuth service"""
    
    def __init__(self):
        super().__init__("notion")
    
    async def exchange_code_for_tokens(self, code: str, state: str = None) -> Dict[str, Any]:
        """Exchange authorization code for Notion tokens"""
        import base64
        
        # Notion requires basic auth
        credentials = base64.b64encode(
            f"{self.config['client_id']}:{self.config['client_secret']}".encode()
        ).decode()
        
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config["redirect_uri"]
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.notion.com/v1/oauth/token",
                json=token_data,
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Accept": "application/json",
                    "Notion-Version": "2022-06-28"
                }
            )
            
            if response.status_code != 200:
                raise OAuthError("Notion token exchange failed")
            
            return response.json()
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Notion user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.notion.com/v1/users/me",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Notion-Version": "2022-06-28"
                }
            )
            
            if response.status_code != 200:
                raise OAuthError("Failed to get Notion user info")
            
            return response.json()


# OAuth service factory
def get_oauth_service(provider: str):
    """Get OAuth service for provider"""
    services = {
        "google": GoogleOAuthService,
        "microsoft": MicrosoftOAuthService,
        "slack": SlackOAuthService,
        "github": GitHubOAuthService,
        "notion": NotionOAuthService
    }
    
    service_class = services.get(provider)
    if not service_class:
        raise OAuthError(f"Unsupported OAuth provider: {provider}")
    
    return service_class()
