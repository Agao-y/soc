@echo off
title SOC Demo Launcher

echo.
echo ==========================================
echo   Dragon Guardian - LLM SIEM Platform
echo   Competition Demo Mode
echo ==========================================
echo.

set "ROOT=%~dp0"

echo [1/3] Checking backend environment...
if not exist "%ROOT%backend\.venv_new\Scripts\python.exe" (
    echo   [ERROR] Virtual environment not found: backend\.venv_new
    echo   Please create the venv first.
    pause
    exit /b 1
)

echo [2/3] Starting backend (demo mode, port 8000)...
copy /Y "%ROOT%backend\.env.demo" "%ROOT%backend\.env" >nul 2>&1
start "SOC-Backend" /D "%ROOT%backend" "%ROOT%backend\.venv_new\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
echo   Backend starting... http://127.0.0.1:8000/health

echo [3/3] Starting frontend (port 5173)...
start "SOC-Frontend" /D "%ROOT%frontend" cmd /c "npm run dev"
echo   Frontend starting... http://127.0.0.1:5173

echo.
echo ==========================================
echo   Services starting, please wait...
echo   http://127.0.0.1:5173
echo   Login: admin / admin123
echo ==========================================
echo.
echo Press any key to open browser...
pause >nul
start http://127.0.0.1:5173
