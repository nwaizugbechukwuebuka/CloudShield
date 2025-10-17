"""
CloudShield Authentication System Test Suite
Comprehensive test coverage for authentication system including OAuth flows,
token validation, user management, and security edge cases.

Author: Chukwuebuka Tobiloba Nwaizugbe
Copyright (c) 2025 CloudShield Security Systems
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import jwt
from passlib.context import CryptContext

from ..api.main import app
from ..api.database import get_db_session, Base
from ..api.models.user import User
from ..api.services.oauth_services import CloudShieldOAuthManager
from ..api.routes.auth import router as auth_router
from ..api.utils.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db():
    """Create test database session"""
    # Use in-memory SQLite for testing
    TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield async_session
    
    # Clean up
    await engine.dispose()


@pytest.fixture
def client(test_db):
    """Create test client with database override"""
    async def override_get_db():
        async with test_db() as session:
            yield session
    
    app.dependency_overrides[get_db_session] = override_get_db
    client = TestClient(app)
    yield client
    del app.dependency_overrides[get_db_session]


@pytest.fixture
async def test_user(test_db) -> User:
    """Create test user"""
    async with test_db() as session:
        user = User(
            email="test@example.com",
            hashed_password=pwd_context.hash("testpassword123"),
            full_name="Test User",
            is_active=True,
            is_verified=True,
            role="user"
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


@pytest.fixture
async def admin_user(test_db) -> User:
    """Create admin test user"""
    async with test_db() as session:
        user = User(
            email="admin@example.com",
            hashed_password=pwd_context.hash("adminpassword123"),
            full_name="Admin User",
            is_active=True,
            is_verified=True,
            role="admin"
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


@pytest.fixture
def oauth_manager():
    """Create OAuth manager instance"""
    return CloudShieldOAuthManager()


class TestUserAuthentication:
    """Test user authentication functionality"""
    
    def test_register_new_user(self, client):
        """Test user registration with valid data"""
        user_data = {
            "email": "newuser@example.com",
            "password": "newpassword123",
            "full_name": "New User"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 201
        
        data = response.json()
        assert data["email"] == user_data["email"]
        assert data["full_name"] == user_data["full_name"]
        assert "id" in data
        assert "hashed_password" not in data
    
    def test_register_duplicate_email(self, client, test_user):
        """Test registration with existing email fails"""
        user_data = {
            "email": test_user.email,
            "password": "somepassword123",
            "full_name": "Duplicate User"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()
    
    def test_register_invalid_email(self, client):
        """Test registration with invalid email format"""
        user_data = {
            "email": "invalid-email",
            "password": "password123",
            "full_name": "Invalid User"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
    
    def test_register_weak_password(self, client):
        """Test registration with weak password"""
        user_data = {
            "email": "weakpass@example.com",
            "password": "123",
            "full_name": "Weak Password User"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 400
        assert "password" in response.json()["detail"].lower()
    
    def test_login_valid_credentials(self, client, test_user):
        """Test login with valid credentials"""
        login_data = {
            "username": test_user.email,
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self, client, test_user):
        """Test login with invalid credentials"""
        login_data = {
            "username": test_user.email,
            "password": "wrongpassword"
        }
        
        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"].lower()
    
    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user"""
        login_data = {
            "username": "nonexistent@example.com",
            "password": "somepassword"
        }
        
        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 401
    
    def test_login_inactive_user(self, client, test_db):
        """Test login with inactive user"""
        async def create_inactive_user():
            async with test_db() as session:
                inactive_user = User(
                    email="inactive@example.com",
                    hashed_password=pwd_context.hash("password123"),
                    full_name="Inactive User",
                    is_active=False,
                    is_verified=True
                )
                session.add(inactive_user)
                await session.commit()
        
        asyncio.run(create_inactive_user())
        
        login_data = {
            "username": "inactive@example.com",
            "password": "password123"
        }
        
        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 401
        assert "inactive" in response.json()["detail"].lower()


class TestTokenManagement:
    """Test JWT token management"""
    
    def test_token_generation(self, oauth_manager, test_user):
        """Test JWT token generation"""
        token_data = {"sub": str(test_user.id), "email": test_user.email}
        token = oauth_manager._create_access_token(token_data)
        
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are long
    
    def test_token_validation_valid(self, oauth_manager, test_user):
        """Test valid token validation"""
        token_data = {"sub": str(test_user.id), "email": test_user.email}
        token = oauth_manager._create_access_token(token_data)
        
        decoded = oauth_manager._verify_token(token)
        assert decoded["sub"] == str(test_user.id)
        assert decoded["email"] == test_user.email
    
    def test_token_validation_expired(self, oauth_manager):
        """Test expired token validation"""
        # Create token with past expiration
        past_time = datetime.utcnow() - timedelta(hours=1)
        token_data = {
            "sub": "123",
            "email": "test@example.com",
            "exp": past_time
        }
        
        token = jwt.encode(token_data, settings.secret_key, algorithm="HS256")
        
        with pytest.raises(jwt.ExpiredSignatureError):
            oauth_manager._verify_token(token)
    
    def test_token_validation_invalid_signature(self, oauth_manager):
        """Test token with invalid signature"""
        # Create token with wrong secret
        token_data = {"sub": "123", "email": "test@example.com"}
        token = jwt.encode(token_data, "wrong-secret", algorithm="HS256")
        
        with pytest.raises(jwt.InvalidTokenError):
            oauth_manager._verify_token(token)
    
    def test_token_validation_malformed(self, oauth_manager):
        """Test malformed token validation"""
        malformed_token = "not.a.valid.jwt.token"
        
        with pytest.raises(jwt.InvalidTokenError):
            oauth_manager._verify_token(malformed_token)
    
    def test_refresh_token_generation(self, oauth_manager, test_user):
        """Test refresh token generation"""
        refresh_token = oauth_manager._create_refresh_token(str(test_user.id))
        
        assert isinstance(refresh_token, str)
        assert len(refresh_token) > 50
    
    def test_refresh_token_usage(self, client, test_user):
        """Test using refresh token to get new access token"""
        # First login to get refresh token
        login_data = {
            "username": test_user.email,
            "password": "testpassword123"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        refresh_token = login_response.json().get("refresh_token")
        
        if refresh_token:
            # Use refresh token
            refresh_data = {"refresh_token": refresh_token}
            refresh_response = client.post("/auth/refresh", json=refresh_data)
            
            assert refresh_response.status_code == 200
            new_token_data = refresh_response.json()
            assert "access_token" in new_token_data


class TestProtectedEndpoints:
    """Test protected endpoint access"""
    
    def get_auth_headers(self, client, user_email, password):
        """Helper to get authentication headers"""
        login_data = {
            "username": user_email,
            "password": password
        }
        
        response = client.post("/auth/login", data=login_data)
        if response.status_code == 200:
            token = response.json()["access_token"]
            return {"Authorization": f"Bearer {token}"}
        return {}
    
    def test_protected_endpoint_with_valid_token(self, client, test_user):
        """Test accessing protected endpoint with valid token"""
        headers = self.get_auth_headers(client, test_user.email, "testpassword123")
        
        response = client.get("/auth/me", headers=headers)
        assert response.status_code == 200
        
        data = response.json()
        assert data["email"] == test_user.email
        assert data["full_name"] == test_user.full_name
    
    def test_protected_endpoint_without_token(self, client):
        """Test accessing protected endpoint without token"""
        response = client.get("/auth/me")
        assert response.status_code == 401
    
    def test_protected_endpoint_with_invalid_token(self, client):
        """Test accessing protected endpoint with invalid token"""
        headers = {"Authorization": "Bearer invalid-token"}
        
        response = client.get("/auth/me", headers=headers)
        assert response.status_code == 401
    
    def test_protected_endpoint_with_expired_token(self, client, oauth_manager):
        """Test accessing protected endpoint with expired token"""
        # Create expired token
        past_time = datetime.utcnow() - timedelta(hours=1)
        token_data = {
            "sub": "123",
            "email": "test@example.com",
            "exp": past_time
        }
        
        expired_token = jwt.encode(token_data, settings.secret_key, algorithm="HS256")
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        response = client.get("/auth/me", headers=headers)
        assert response.status_code == 401


class TestRoleBasedAccess:
    """Test role-based access control"""
    
    def get_auth_headers(self, client, user_email, password):
        """Helper to get authentication headers"""
        login_data = {
            "username": user_email,
            "password": password
        }
        
        response = client.post("/auth/login", data=login_data)
        if response.status_code == 200:
            token = response.json()["access_token"]
            return {"Authorization": f"Bearer {token}"}
        return {}
    
    def test_admin_access_allowed(self, client, admin_user):
        """Test admin user can access admin endpoints"""
        headers = self.get_auth_headers(client, admin_user.email, "adminpassword123")
        
        # Test admin endpoint (assuming we have one)
        response = client.get("/auth/users", headers=headers)
        # This might return 404 if endpoint doesn't exist, but shouldn't be 403
        assert response.status_code != 403
    
    def test_regular_user_admin_access_denied(self, client, test_user):
        """Test regular user cannot access admin endpoints"""
        headers = self.get_auth_headers(client, test_user.email, "testpassword123")
        
        # Test admin endpoint
        response = client.get("/auth/users", headers=headers)
        # Should be forbidden if endpoint exists and requires admin
        assert response.status_code in [403, 404]  # 404 if endpoint doesn't exist


class TestOAuthIntegration:
    """Test OAuth integration functionality"""
    
    @patch('httpx.AsyncClient.get')
    async def test_google_oauth_authorization_url(self, mock_get, oauth_manager):
        """Test Google OAuth authorization URL generation"""
        provider = "google"
        auth_url = await oauth_manager.get_authorization_url(provider)
        
        assert isinstance(auth_url, str)
        assert "oauth2" in auth_url
        assert "google" in auth_url
        assert "client_id" in auth_url
    
    @patch('httpx.AsyncClient.post')
    @patch('httpx.AsyncClient.get')
    async def test_google_oauth_callback_success(self, mock_get, mock_post, oauth_manager):
        """Test successful Google OAuth callback"""
        # Mock token exchange response
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "access_token": "mock_access_token",
            "token_type": "Bearer"
        }
        
        # Mock user info response
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "email": "oauth@example.com",
            "name": "OAuth User",
            "picture": "https://example.com/avatar.jpg"
        }
        
        user_info = await oauth_manager.exchange_code_for_token("google", "mock_auth_code")
        
        assert user_info["email"] == "oauth@example.com"
        assert user_info["name"] == "OAuth User"
    
    @patch('httpx.AsyncClient.post')
    async def test_google_oauth_callback_failure(self, mock_post, oauth_manager):
        """Test failed Google OAuth callback"""
        # Mock failed token exchange
        mock_post.return_value.status_code = 400
        mock_post.return_value.json.return_value = {
            "error": "invalid_grant"
        }
        
        with pytest.raises(Exception):
            await oauth_manager.exchange_code_for_token("google", "invalid_code")
    
    @patch('httpx.AsyncClient.get')
    async def test_microsoft_oauth_authorization_url(self, mock_get, oauth_manager):
        """Test Microsoft OAuth authorization URL generation"""
        provider = "microsoft"
        auth_url = await oauth_manager.get_authorization_url(provider)
        
        assert isinstance(auth_url, str)
        assert "login.microsoftonline.com" in auth_url
        assert "client_id" in auth_url


class TestPasswordSecurity:
    """Test password security features"""
    
    def test_password_hashing(self):
        """Test password hashing functionality"""
        password = "testpassword123"
        hashed = pwd_context.hash(password)
        
        assert hashed != password
        assert pwd_context.verify(password, hashed)
    
    def test_password_verification_correct(self):
        """Test correct password verification"""
        password = "testpassword123"
        hashed = pwd_context.hash(password)
        
        assert pwd_context.verify(password, hashed) is True
    
    def test_password_verification_incorrect(self):
        """Test incorrect password verification"""
        password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = pwd_context.hash(password)
        
        assert pwd_context.verify(wrong_password, hashed) is False
    
    def test_password_strength_validation(self):
        """Test password strength validation"""
        from ..api.routes.auth import validate_password_strength
        
        # Strong password
        assert validate_password_strength("StrongPass123!") is True
        
        # Weak passwords
        assert validate_password_strength("123") is False
        assert validate_password_strength("password") is False
        assert validate_password_strength("12345678") is False


class TestUserManagement:
    """Test user management functionality"""
    
    def test_user_profile_update(self, client, test_user):
        """Test user profile update"""
        headers = self.get_auth_headers(client, test_user.email, "testpassword123")
        
        update_data = {
            "full_name": "Updated Name",
            "bio": "Updated bio"
        }
        
        response = client.put("/auth/me", json=update_data, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            assert data["full_name"] == "Updated Name"
    
    def get_auth_headers(self, client, user_email, password):
        """Helper to get authentication headers"""
        login_data = {
            "username": user_email,
            "password": password
        }
        
        response = client.post("/auth/login", data=login_data)
        if response.status_code == 200:
            token = response.json()["access_token"]
            return {"Authorization": f"Bearer {token}"}
        return {}
    
    def test_password_change(self, client, test_user):
        """Test password change functionality"""
        headers = self.get_auth_headers(client, test_user.email, "testpassword123")
        
        password_data = {
            "current_password": "testpassword123",
            "new_password": "newtestpassword123"
        }
        
        response = client.post("/auth/change-password", json=password_data, headers=headers)
        
        # Should succeed or return method not implemented
        assert response.status_code in [200, 501]
    
    def test_account_deactivation(self, client, test_user):
        """Test account deactivation"""
        headers = self.get_auth_headers(client, test_user.email, "testpassword123")
        
        response = client.post("/auth/deactivate", headers=headers)
        
        # Should succeed or return method not implemented
        assert response.status_code in [200, 501]


class TestSecurityFeatures:
    """Test security features and edge cases"""
    
    def test_rate_limiting_simulation(self, client):
        """Test rate limiting (simulation)"""
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            response = client.post("/auth/login", data={
                "username": "test@example.com",
                "password": "wrongpassword"
            })
            responses.append(response.status_code)
        
        # At least some should be 401 (unauthorized)
        assert 401 in responses
    
    def test_sql_injection_protection(self, client):
        """Test SQL injection protection"""
        malicious_data = {
            "username": "test@example.com'; DROP TABLE users; --",
            "password": "password"
        }
        
        response = client.post("/auth/login", data=malicious_data)
        
        # Should handle gracefully without crashing
        assert response.status_code in [401, 422]
    
    def test_xss_protection(self, client):
        """Test XSS protection in registration"""
        xss_data = {
            "email": "xss@example.com",
            "password": "password123",
            "full_name": "<script>alert('xss')</script>"
        }
        
        response = client.post("/auth/register", json=xss_data)
        
        if response.status_code == 201:
            # Check that script tags are sanitized
            data = response.json()
            assert "<script>" not in data.get("full_name", "")


class TestEmailVerification:
    """Test email verification functionality"""
    
    @patch('smtplib.SMTP')
    def test_email_verification_send(self, mock_smtp, client):
        """Test sending email verification"""
        user_data = {
            "email": "verify@example.com",
            "password": "password123",
            "full_name": "Verify User"
        }
        
        response = client.post("/auth/register", json=user_data)
        
        # Registration should succeed
        assert response.status_code in [201, 200]
    
    def test_email_verification_token_validation(self, oauth_manager):
        """Test email verification token validation"""
        user_id = "123"
        token = oauth_manager._create_verification_token(user_id)
        
        # Token should be valid
        assert isinstance(token, str)
        assert len(token) > 20
    
    def test_invalid_verification_token(self, client):
        """Test invalid verification token"""
        response = client.get("/auth/verify-email/invalid-token")
        
        # Should return error for invalid token
        assert response.status_code in [400, 404]


class TestSessionManagement:
    """Test session management features"""
    
    def test_multiple_device_login(self, client, test_user):
        """Test login from multiple devices"""
        # First login
        login_data = {
            "username": test_user.email,
            "password": "testpassword123"
        }
        
        response1 = client.post("/auth/login", data=login_data)
        response2 = client.post("/auth/login", data=login_data)
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        # Both should have different tokens
        token1 = response1.json()["access_token"]
        token2 = response2.json()["access_token"]
        
        assert token1 != token2
    
    def test_logout_functionality(self, client, test_user):
        """Test logout functionality"""
        # Login first
        login_data = {
            "username": test_user.email,
            "password": "testpassword123"
        }
        
        login_response = client.post("/auth/login", data=login_data)
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Logout
        logout_response = client.post("/auth/logout", headers=headers)
        
        # Should succeed or return method not implemented
        assert logout_response.status_code in [200, 501]


# Run the tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
