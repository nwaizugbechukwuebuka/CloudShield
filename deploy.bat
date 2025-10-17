@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   CloudShield SaaS Security Analyzer
echo ========================================
echo.

:: Colors for output (Windows)
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "NC=[0m"

:: Check if Docker is installed and running
echo %BLUE%[INFO]%NC% Checking Docker installation...
docker --version >nul 2>&1
if !errorlevel! neq 0 (
    echo %RED%[ERROR]%NC% Docker is not installed or not in PATH
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

docker info >nul 2>&1
if !errorlevel! neq 0 (
    echo %RED%[ERROR]%NC% Docker daemon is not running
    echo Please start Docker Desktop first
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%NC% Docker is installed and running

:: Check if docker-compose is available
echo %BLUE%[INFO]%NC% Checking docker-compose...
docker-compose --version >nul 2>&1
if !errorlevel! neq 0 (
    echo %RED%[ERROR]%NC% docker-compose is not available
    echo Please install docker-compose or use Docker Desktop
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%NC% docker-compose is available

:: Create .env file if it doesn't exist
if not exist .env (
    echo %BLUE%[INFO]%NC% Creating .env file from template...
    copy .env.example .env >nul
    echo %YELLOW%[WARNING]%NC% Please edit .env file with your actual configuration values
    echo %YELLOW%[WARNING]%NC% Especially important: OAuth client IDs and secrets
) else (
    echo %GREEN%[SUCCESS]%NC% .env file already exists
)

:: Ask user if they want to continue
set /p "continue=Continue with deployment? (y/N): "
if /i not "%continue%"=="y" (
    echo %YELLOW%[WARNING]%NC% Deployment cancelled
    pause
    exit /b 0
)

:: Build and start services
echo %BLUE%[INFO]%NC% Building Docker images...
docker-compose build
if !errorlevel! neq 0 (
    echo %RED%[ERROR]%NC% Failed to build Docker images
    pause
    exit /b 1
)

echo %BLUE%[INFO]%NC% Starting services...
docker-compose up -d
if !errorlevel! neq 0 (
    echo %RED%[ERROR]%NC% Failed to start services
    pause
    exit /b 1
)

echo %BLUE%[INFO]%NC% Waiting for services to be ready...
timeout /t 15 /nobreak >nul

:: Check service status
echo %BLUE%[INFO]%NC% Checking service health...
docker-compose ps

:: Run database migrations (might fail on first run)
echo %BLUE%[INFO]%NC% Running database migrations...
docker-compose exec -T backend python -m alembic upgrade head
if !errorlevel! neq 0 (
    echo %YELLOW%[WARNING]%NC% Migration failed - this is normal on first run
)

:: Show service URLs
echo.
echo %GREEN%[SUCCESS]%NC% 🎉 CloudShield is now running!
echo.
echo Services available at:
echo   📱 Frontend:     http://localhost:3000
echo   🔌 Backend API:  http://localhost:8000
echo   📚 API Docs:     http://localhost:8000/docs
echo   🌸 Flower:       http://localhost:5555
echo   🗄️  Database:     localhost:5432
echo   📡 Redis:        localhost:6379
echo.
echo To stop all services: docker-compose down
echo To view logs: docker-compose logs -f [service_name]
echo To restart a service: docker-compose restart [service_name]
echo.

pause