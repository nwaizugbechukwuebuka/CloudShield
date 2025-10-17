"""
Configuration management using environment variables
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "CloudShield Security Analyzer"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./cloudshield.db")
    
    # Redis (for Celery)
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = [
        "http://localhost:3000",  # React dev server
        "http://localhost:8000",  # FastAPI
        "http://localhost:8080"   # Alternative frontend port
    ]
    
    # OAuth Configuration - Google Workspace
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
    
    # OAuth Configuration - Microsoft 365
    MICROSOFT_CLIENT_ID: str = os.getenv("MICROSOFT_CLIENT_ID", "")
    MICROSOFT_CLIENT_SECRET: str = os.getenv("MICROSOFT_CLIENT_SECRET", "")
    MICROSOFT_REDIRECT_URI: str = os.getenv("MICROSOFT_REDIRECT_URI", "http://localhost:8000/auth/microsoft/callback")
    
    # OAuth Configuration - Slack
    SLACK_CLIENT_ID: str = os.getenv("SLACK_CLIENT_ID", "")
    SLACK_CLIENT_SECRET: str = os.getenv("SLACK_CLIENT_SECRET", "")
    SLACK_REDIRECT_URI: str = os.getenv("SLACK_REDIRECT_URI", "http://localhost:8000/auth/slack/callback")
    
    # OAuth Configuration - GitHub
    GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    GITHUB_REDIRECT_URI: str = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/auth/github/callback")
    
    # OAuth Configuration - Notion
    NOTION_CLIENT_ID: str = os.getenv("NOTION_CLIENT_ID", "")
    NOTION_CLIENT_SECRET: str = os.getenv("NOTION_CLIENT_SECRET", "")
    NOTION_REDIRECT_URI: str = os.getenv("NOTION_REDIRECT_URI", "http://localhost:8000/auth/notion/callback")
    
    # Email Configuration (for alerts)
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "noreply@cloudshield.com")
    
    # Slack Webhook (for alerts)
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
    
    # Scanning Configuration
    DEFAULT_SCAN_FREQUENCY_HOURS: int = 24
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT_MINUTES: int = 30
    
    # Risk Scoring
    CRITICAL_RISK_THRESHOLD: float = 80.0
    HIGH_RISK_THRESHOLD: float = 60.0
    MEDIUM_RISK_THRESHOLD: float = 40.0
    
    # Rate Limiting
    API_RATE_LIMIT: str = "100/minute"
    
    class Config:
        case_sensitive = True
        env_file = ".env"


# Global settings instance
settings = Settings()


def get_oauth_config(provider: str) -> dict:
    """Get OAuth configuration for a specific provider"""
    configs = {
        "google": {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "scope": [
                "openid",
                "email",
                "profile",
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "https://www.googleapis.com/auth/admin.directory.group.readonly",
                "https://www.googleapis.com/auth/drive.readonly",
                "https://www.googleapis.com/auth/admin.reports.audit.readonly"
            ],
            "authorization_url": "https://accounts.google.com/o/oauth2/auth",
            "token_url": "https://oauth2.googleapis.com/token"
        },
        "microsoft": {
            "client_id": settings.MICROSOFT_CLIENT_ID,
            "client_secret": settings.MICROSOFT_CLIENT_SECRET,
            "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
            "scope": [
                "openid",
                "profile",
                "email",
                "User.Read.All",
                "Group.Read.All",
                "Sites.Read.All",
                "Files.Read.All",
                "SecurityEvents.Read.All"
            ],
            "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        },
        "slack": {
            "client_id": settings.SLACK_CLIENT_ID,
            "client_secret": settings.SLACK_CLIENT_SECRET,
            "redirect_uri": settings.SLACK_REDIRECT_URI,
            "scope": [
                "identity.basic",
                "identity.email",
                "users:read",
                "channels:read",
                "groups:read",
                "files:read",
                "admin"
            ],
            "authorization_url": "https://slack.com/oauth/v2/authorize",
            "token_url": "https://slack.com/api/oauth.v2.access"
        },
        "github": {
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "redirect_uri": settings.GITHUB_REDIRECT_URI,
            "scope": [
                "user:email",
                "read:org",
                "repo",
                "admin:org"
            ],
            "authorization_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token"
        },
        "notion": {
            "client_id": settings.NOTION_CLIENT_ID,
            "client_secret": settings.NOTION_CLIENT_SECRET,
            "redirect_uri": settings.NOTION_REDIRECT_URI,
            "authorization_url": "https://api.notion.com/v1/oauth/authorize",
            "token_url": "https://api.notion.com/v1/oauth/token"
        }
    }
    
    return configs.get(provider, {})
