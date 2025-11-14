@echo off
REM Build and serve AURA on a single port (5000) - Windows PowerShell version
REM This script builds the React frontend and serves it + API from Flask on port 5000

echo === AURA Single-Port Build ^& Serve ===
echo.

REM Step 1: Build frontend
echo [1/4] Building React frontend...
cd frontend
call npm install > nul 2>&1
call npm run build > nul 2>&1
echo ✓ Frontend built to frontend\dist\
cd ..

REM Step 2: Clear and copy frontend to Flask static
echo [2/4] Copying frontend to Flask static folder...
if exist static rmdir /s /q static
mkdir static
xcopy frontend\dist\* static\ /E /I /Y > nul
echo ✓ Frontend assets copied to static\

REM Step 3: Create Python venv if not present
if not exist venv (
  echo [3/4] Creating Python virtual environment...
  python -m venv venv
  call venv\Scripts\Activate.ps1
  pip install -r requirements.txt > nul 2>&1
  echo ✓ Virtual environment created and dependencies installed
) else (
  echo [3/4] Activating existing Python virtual environment...
  call venv\Scripts\Activate.ps1
  echo ✓ Virtual environment activated
)

REM Step 4: Run Flask server
echo [4/4] Starting Flask server on port 5000...
echo.
echo ===================================
echo ✨ AURA is running at: http://127.0.0.1:5000
echo ===================================
echo.
python run_integrated_system.py
