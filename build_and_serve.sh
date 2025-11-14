#!/bin/bash
# Build and serve AURA on a single port (5000)
# This script builds the React frontend and serves it + API from Flask on port 5000

set -e

echo "=== AURA Single-Port Build & Serve ==="
echo ""

# Step 1: Build frontend
echo "[1/4] Building React frontend..."
cd frontend
npm install > /dev/null 2>&1
npm run build > /dev/null 2>&1
echo "✓ Frontend built to frontend/dist/"
cd ..

# Step 2: Clear and copy frontend to Flask static
echo "[2/4] Copying frontend to Flask static folder..."
rm -rf static/*
cp -r frontend/dist/* static/
echo "✓ Frontend assets copied to static/"

# Step 3: Create Python venv if not present
if [ ! -d "venv" ]; then
  echo "[3/4] Creating Python virtual environment..."
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt > /dev/null 2>&1
  echo "✓ Virtual environment created and dependencies installed"
else
  echo "[3/4] Activating existing Python virtual environment..."
  source venv/bin/activate
  echo "✓ Virtual environment activated"
fi

# Step 4: Run Flask server
echo "[4/4] Starting Flask server on port 5000..."
echo ""
echo "==================================="
echo "✨ AURA is running at: http://127.0.0.1:5000"
echo "==================================="
echo ""
python run_integrated_system.py
