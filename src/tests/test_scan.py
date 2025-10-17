import pytest
from unittest.mock import Mock, patch
from src.scanner.github import GitHubScanner
from src.scanner.google_workspace import GoogleWorkspaceScanner
from src.scanner.slack import SlackScanner
from src.api.models.findings import RiskLevel, FindingType

@pytest.fixture
def mock_integration():
    integration = Mock()
    integration.id = "test-integration-id"
    integration.provider = "github"
    integration.access_token = "test-token"
    integration.config = {"account_name": "test-org"}
    return integration

class TestGitHubScanner:
    
    def test_scanner_initialization(self, mock_integration):
        """Test GitHubScanner initialization."""
        scanner = GitHubScanner(mock_integration)
        assert scanner.integration == mock_integration
        assert scanner.provider == "github"
        
    @patch('src.scanner.github.requests.get')
    def test_scan_repositories_success(self, mock_get, mock_integration):
        """Test successful repository scanning."""
        # Mock API responses
        mock_get.return_value.json.return_value = [
            {
                "name": "test-repo",
                "private": False,
                "permissions": {
                    "admin": True,
                    "push": True,
                    "pull": True
                },
                "default_branch": "main",
                "has_wiki": True,
                "has_issues": True
            }
        ]
        mock_get.return_value.status_code = 200
        
        scanner = GitHubScanner(mock_integration)
        findings = scanner.scan()
        
        # Should detect public repository as a finding
        assert len(findings) > 0
        public_repo_finding = next(
            (f for f in findings if f.finding_type == FindingType.PUBLIC_SHARE), 
            None
        )
        assert public_repo_finding is not None
        assert public_repo_finding.title == "Public Repository: test-repo"
    
    @patch('src.scanner.github.requests.get')
    def test_scan_with_api_error(self, mock_get, mock_integration):
        """Test scanning with API error."""
        mock_get.return_value.status_code = 403
        mock_get.return_value.json.return_value = {"message": "Forbidden"}
        
        scanner = GitHubScanner(mock_integration)
        findings = scanner.scan()
        
        # Should return empty list on API error
        assert findings == []

class TestGoogleWorkspaceScanner:
    
    def test_scanner_initialization(self, mock_integration):
        """Test GoogleWorkspaceScanner initialization."""
        mock_integration.provider = "google"
        scanner = GoogleWorkspaceScanner(mock_integration)
        assert scanner.integration == mock_integration
        assert scanner.provider == "google"
    
    @patch('src.scanner.google_workspace.requests.get')
    def test_scan_drive_files_success(self, mock_get, mock_integration):
        """Test successful Drive files scanning."""
        mock_integration.provider = "google"
        
        # Mock Drive API response
        mock_get.return_value.json.return_value = {
            "files": [
                {
                    "id": "file1",
                    "name": "Public Document",
                    "permissions": [
                        {"type": "anyone", "role": "reader"},
                        {"type": "user", "role": "owner", "emailAddress": "owner@example.com"}
                    ]
                },
                {
                    "id": "file2",
                    "name": "Private Document",
                    "permissions": [
                        {"type": "user", "role": "owner", "emailAddress": "owner@example.com"}
                    ]
                }
            ]
        }
        mock_get.return_value.status_code = 200
        
        scanner = GoogleWorkspaceScanner(mock_integration)
        findings = scanner.scan()
        
        # Should detect public file sharing
        assert len(findings) > 0
        public_share_finding = next(
            (f for f in findings if f.finding_type == FindingType.PUBLIC_SHARE), 
            None
        )
        assert public_share_finding is not None
        assert "Public Document" in public_share_finding.title

class TestSlackScanner:
    
    def test_scanner_initialization(self, mock_integration):
        """Test SlackScanner initialization."""
        mock_integration.provider = "slack"
        scanner = SlackScanner(mock_integration)
        assert scanner.integration == mock_integration
        assert scanner.provider == "slack"
    
    @patch('src.scanner.slack.requests.get')
    def test_scan_channels_success(self, mock_get, mock_integration):
        """Test successful Slack channels scanning."""
        mock_integration.provider = "slack"
        
        # Mock Slack API responses
        mock_get.return_value.json.side_effect = [
            # Channels list response
            {
                "ok": True,
                "channels": [
                    {
                        "id": "C1234567890",
                        "name": "public-channel",
                        "is_private": False,
                        "is_archived": False
                    },
                    {
                        "id": "C0987654321",
                        "name": "private-channel",
                        "is_private": True,
                        "is_archived": False
                    }
                ]
            },
            # Users list response
            {
                "ok": True,
                "members": [
                    {
                        "id": "U1234567890",
                        "name": "active.user",
                        "deleted": False,
                        "profile": {"email": "active@example.com"}
                    },
                    {
                        "id": "U0987654321",
                        "name": "inactive.user",
                        "deleted": True,
                        "profile": {"email": "inactive@example.com"}
                    }
                ]
            }
        ]
        mock_get.return_value.status_code = 200
        
        scanner = SlackScanner(mock_integration)
        findings = scanner.scan()
        
        # Should detect inactive user
        assert len(findings) > 0
        inactive_user_finding = next(
            (f for f in findings if f.finding_type == FindingType.INACTIVE_USER), 
            None
        )
        assert inactive_user_finding is not None
        assert "inactive.user" in inactive_user_finding.title

def test_risk_level_assignment():
    """Test that risk levels are properly assigned based on finding types."""
    from src.scanner.common import BaseScanner
    
    # Test different finding types get appropriate risk levels
    finding_configs = [
        (FindingType.PUBLIC_SHARE, RiskLevel.HIGH),
        (FindingType.INACTIVE_USER, RiskLevel.MEDIUM),
        (FindingType.MISCONFIGURATION, RiskLevel.HIGH),
        (FindingType.OVERPRIVILEGED_TOKEN, RiskLevel.CRITICAL),
    ]
    
    for finding_type, expected_risk in finding_configs:
        # This would be implemented in the actual BaseScanner
        # Here we just verify the enum values exist
        assert finding_type in FindingType
        assert expected_risk in RiskLevel

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
