"""
GitHub security scanner
"""
import httpx
from typing import Dict, Any, AsyncGenerator, List
from datetime import datetime, timedelta
from github import Github, GithubException

from .common import BaseScanner, ScanResult, ScannerAuthError, FindingType, scanner_registry
from ..api.utils.logger import get_logger

logger = get_logger(__name__)


class GitHubScanner(BaseScanner):
    """Scanner for GitHub security issues"""
    
    def __init__(self):
        super().__init__("github")
        self.github = None
        self.authenticated_user = None
    
    async def authenticate(self, access_token: str, **kwargs) -> bool:
        """Authenticate with GitHub API"""
        try:
            self.github = Github(access_token)
            self.authenticated_user = self.github.get_user()
            
            # Test authentication
            _ = self.authenticated_user.login
            
            self.logger.info("GitHub authentication successful")
            return True
            
        except GithubException as e:
            self.logger.error("GitHub authentication failed", error=str(e))
            return False
        except Exception as e:
            self.logger.error("GitHub authentication error", error=str(e))
            return False
    
    async def scan_users(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for user-related security issues"""
        if not self.github:
            raise ScannerAuthError("Not authenticated with GitHub")
        
        try:
            # Get organizations the user belongs to
            for org in self.authenticated_user.get_orgs():
                try:
                    # Get organization members (requires admin access)
                    members = org.get_members()
                    
                    for member in members:
                        # Check for inactive users (last activity)
                        # Note: GitHub API has limited activity data
                        user_data = {
                            "id": member.id,
                            "name": member.name or member.login,
                            "email": member.email or f"{member.login}@github.com",
                            "login": member.login,
                            "created_at": member.created_at,
                            "updated_at": member.updated_at
                        }
                        
                        # Check if user hasn't updated profile in a long time
                        if member.updated_at:
                            days_since_update = (datetime.now() - member.updated_at).days
                            if days_since_update > 180:  # 6 months
                                yield self._create_inactive_user_finding(user_data, days_since_update)
                
                except GithubException as e:
                    if e.status == 403:
                        self.logger.warning(f"Insufficient permissions to scan org {org.login}")
                        continue
                    else:
                        raise
        
        except Exception as e:
            self.logger.error("Error scanning GitHub users", error=str(e))
            raise
    
    async def scan_permissions(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for permission-related issues"""
        if not self.github:
            raise ScannerAuthError("Not authenticated with GitHub")
        
        try:
            # Scan repositories for security issues
            for repo in self.authenticated_user.get_repos(affiliation="owner,collaborator,organization_member"):
                
                # Check repository permissions and collaborators
                try:
                    collaborators = repo.get_collaborators()
                    
                    for collaborator in collaborators:
                        permissions = repo.get_collaborator_permission(collaborator)
                        
                        # Check for excessive permissions (admin on multiple repos)
                        if permissions.permission == "admin" and collaborator.login != repo.owner.login:
                            yield self._create_excessive_permissions_finding({
                                "id": collaborator.id,
                                "name": collaborator.name or collaborator.login,
                                "email": collaborator.email or f"{collaborator.login}@github.com",
                                "roles": ["admin"],
                                "permissions": [permissions.permission],
                                "is_admin": True,
                                "groups": [repo.full_name],
                                "last_role_change": None
                            })
                
                except GithubException as e:
                    if e.status == 403:
                        continue  # Skip repos we can't access
                    else:
                        raise
                
                # Check for security vulnerabilities (if available)
                try:
                    alerts = repo.get_vulnerability_alert()
                    if alerts:
                        yield ScanResult(
                            title=f"Security Vulnerability in {repo.name}",
                            description=f"Repository {repo.full_name} has known security vulnerabilities.",
                            finding_type=FindingType.OUTDATED_SOFTWARE,
                            evidence={
                                "repository": repo.full_name,
                                "vulnerability_alerts": True,
                                "private": repo.private
                            },
                            resource_id=str(repo.id),
                            resource_name=repo.full_name,
                            resource_type="repository",
                            remediation_steps=f"Review and update dependencies in {repo.full_name} to address security vulnerabilities.",
                            metadata={"service": self.service_name}
                        )
                
                except GithubException:
                    # Vulnerability alerts might not be available for all repos
                    pass
        
        except Exception as e:
            self.logger.error("Error scanning GitHub permissions", error=str(e))
            raise
    
    async def scan_data_sharing(self, **kwargs) -> AsyncGenerator[ScanResult, None]:
        """Scan for data sharing and access issues"""
        if not self.github:
            raise ScannerAuthError("Not authenticated with GitHub")
        
        try:
            # Scan for public repositories that might contain sensitive data
            for repo in self.authenticated_user.get_repos(visibility="public"):
                
                # Check repository contents for potential secrets
                sensitive_files = []
                try:
                    contents = repo.get_contents("")
                    
                    for content in contents:
                        if self._is_potentially_sensitive_file(content.name):
                            sensitive_files.append(content.name)
                
                except GithubException:
                    # Might not have access to contents
                    pass
                
                # Flag public repositories with potentially sensitive content
                if sensitive_files or self._has_sensitive_name(repo.name):
                    yield self._create_public_share_finding({
                        "id": repo.id,
                        "name": repo.name,
                        "permissions": ["public"],
                        "public_access": True,
                        "external_sharing": True,
                        "access_count": repo.stargazers_count + repo.forks_count,
                        "owner": repo.owner.login,
                        "contains_sensitive_data": len(sensitive_files) > 0,
                        "sensitive_files": sensitive_files
                    }, "repository")
                
                # Check for exposed secrets in public repos
                if repo.private == False:
                    # This would require deeper content analysis
                    # For now, flag repos with common secret file patterns
                    secret_patterns = ['.env', 'config.json', 'secrets.json', '.aws', '.ssh']
                    
                    try:
                        for pattern in secret_patterns:
                            try:
                                repo.get_contents(pattern)
                                # If we can get the file, it exists and is public
                                yield ScanResult(
                                    title=f"Potential Secrets Exposure: {repo.name}",
                                    description=f"Public repository {repo.full_name} contains files that might expose secrets or credentials.",
                                    finding_type=FindingType.MISCONFIGURATION,
                                    evidence={
                                        "repository": repo.full_name,
                                        "secret_files": [pattern],
                                        "public": True,
                                        "stars": repo.stargazers_count
                                    },
                                    resource_id=str(repo.id),
                                    resource_name=repo.full_name,
                                    resource_type="repository",
                                    remediation_steps=f"Review {pattern} in {repo.full_name} and remove any exposed secrets. Consider making repository private.",
                                    metadata={"service": self.service_name}
                                )
                            except GithubException:
                                continue  # File doesn't exist
                    
                    except Exception:
                        continue  # Skip this repo
        
        except Exception as e:
            self.logger.error("Error scanning GitHub data sharing", error=str(e))
            raise
    
    def _is_potentially_sensitive_file(self, filename: str) -> bool:
        """Check if filename suggests sensitive content"""
        sensitive_patterns = [
            '.env', 'config', 'secret', 'password', 'key', 'token',
            'credential', 'private', 'cert', 'pem', 'p12', 'keystore'
        ]
        
        filename_lower = filename.lower()
        return any(pattern in filename_lower for pattern in sensitive_patterns)
    
    def _has_sensitive_name(self, repo_name: str) -> bool:
        """Check if repository name suggests sensitive content"""
        sensitive_keywords = [
            'secret', 'password', 'private', 'internal', 'confidential',
            'backup', 'production', 'prod', 'staging'
        ]
        
        repo_name_lower = repo_name.lower()
        return any(keyword in repo_name_lower for keyword in sensitive_keywords)


# Register the scanner
scanner_registry.register_scanner("github", GitHubScanner())
