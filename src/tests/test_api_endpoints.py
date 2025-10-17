import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.main import app
from src.api.database import get_db, Base
from src.api.models.user import User
from src.api.models.integration import Integration
from src.api.models.findings import Finding

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def test_user(test_db):
    db = TestingSessionLocal()
    user = User(
        email="test@example.com",
        username="testuser",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeXGthXE2/C.X.uby",  # "password"
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user

def test_health_check():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_user_registration():
    """Test user registration endpoint."""
    user_data = {
        "email": "newuser@example.com",
        "username": "newuser",
        "password": "password123"
    }
    response = client.post("/api/auth/register", json=user_data)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["username"] == user_data["username"]
    assert "id" in data

def test_user_login(test_user):
    """Test user login endpoint."""
    login_data = {
        "username": "test@example.com",
        "password": "password"
    }
    response = client.post("/api/auth/login", data=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_protected_route_without_token():
    """Test accessing protected route without authentication."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401

def test_protected_route_with_token(test_user):
    """Test accessing protected route with valid token."""
    # First login to get token
    login_data = {
        "username": "test@example.com",
        "password": "password"
    }
    login_response = client.post("/api/auth/login", data=login_data)
    token = login_response.json()["access_token"]
    
    # Then access protected route
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"

def test_get_integrations_empty(test_user):
    """Test getting integrations when none exist."""
    # Login to get token
    login_data = {
        "username": "test@example.com",
        "password": "password"
    }
    login_response = client.post("/api/auth/login", data=login_data)
    token = login_response.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/integrations", headers=headers)
    assert response.status_code == 200
    assert response.json() == []

def test_get_findings_empty(test_user):
    """Test getting findings when none exist."""
    # Login to get token
    login_data = {
        "username": "test@example.com",
        "password": "password"
    }
    login_response = client.post("/api/auth/login", data=login_data)
    token = login_response.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/scan/findings", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["findings"] == []
    assert data["total"] == 0

def test_get_stats_empty(test_user):
    """Test getting statistics when no findings exist."""
    # Login to get token
    login_data = {
        "username": "test@example.com",
        "password": "password"
    }
    login_response = client.post("/api/auth/login", data=login_data)
    token = login_response.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/scan/stats", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 0
    assert data["critical_count"] == 0
    assert data["high_count"] == 0
    assert data["medium_count"] == 0
    assert data["low_count"] == 0

def test_invalid_login():
    """Test login with invalid credentials."""
    login_data = {
        "username": "invalid@example.com",
        "password": "wrongpassword"
    }
    response = client.post("/api/auth/login", data=login_data)
    assert response.status_code == 401

def test_duplicate_user_registration():
    """Test registering user with duplicate email."""
    user_data = {
        "email": "duplicate@example.com",
        "username": "user1",
        "password": "password123"
    }
    
    # First registration should succeed
    response1 = client.post("/api/auth/register", json=user_data)
    assert response1.status_code == 201
    
    # Second registration with same email should fail
    user_data["username"] = "user2"
    response2 = client.post("/api/auth/register", json=user_data)
    assert response2.status_code == 400

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
