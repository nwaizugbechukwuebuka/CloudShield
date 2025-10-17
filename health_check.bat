@echo off
echo ============================================
echo   CloudShield System Health Check
echo ============================================
echo.

:: Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.11+
    pause
    exit /b 1
)

:: Install required packages for health check
echo [INFO] Installing health check dependencies...
pip install requests >nul 2>&1

:: Run the health check
echo [INFO] Running system health check...
python health_check.py

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] All health checks passed! CloudShield is ready to use.
    echo.
    echo Quick Start:
    echo   Web Dashboard: http://localhost:3000
    echo   API Documentation: http://localhost:8000/docs  
    echo   Task Monitor: http://localhost:5555
    echo.
) else (
    echo.
    echo [WARNING] Some health checks failed. Please review the output above.
    echo Check the health_check_report.json file for detailed results.
    echo.
)

pause