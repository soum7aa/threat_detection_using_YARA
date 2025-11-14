# Adaptive Unified Real-time Analyzer (AURA)

**A modern threat detection system combining YARA signatures, anomaly detection, and heuristic analysis with a polished React frontend.**

## 🛡️ Overview

AURA is a real-time security monitoring system that combines multiple detection engines to identify and analyze threats across processes, network connections, and file systems. The new React frontend provides real-time SSE monitoring, file scanning, and URL safety analysis with a modern dark UI.

---

## ✨ Key Features

- **Multi-Engine Detection**: YARA signatures, anomaly detection (Isolation Forest), heuristics
- **File Type Support**: PDF, DOCX, XLSX, PPTX, ZIP, RAR, 7Z, TAR.GZ, JSON, XML, PNG, JPG, EXE, DLL, PS1, BAT, and more
- **Smart File Classification**: MIME-type first (via `python-magic`), with extension fallback
- **Archive Extraction**: Native ZIP/TAR, py7zr for 7z, rarfile for RAR (with 7z.exe fallback on Windows)
- **Document Analysis**: Macro detection, Office structure inspection, PDF active content checks
- **Real-time Monitoring**: Process, network, and file system event streaming (Server-Sent Events)
- **React Frontend**: Modern dark UI with live event tabs, file upload, URL testing, incident tracking
- **Mitigation Actions**: Quarantine files, terminate processes, manage watch paths

---

## ✅ Prerequisites

- **Python 3.7+** (backend)
- **Node.js 16+** (frontend)
- Administrator/root privileges recommended for full monitoring
- **Optional**: 7z or unrar for enhanced archive support (Windows/Linux)

---

## 🚀 Quick Start

### Backend Setup

1) Clone/navigate to project:
```bash
cd threat_detection_using_YARA
```

2) Create Python virtual environment:

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows PowerShell:**
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If you run into false negatives or MIME-related warnings on Windows, install the optional `filetype` package or `python-magic` with a system libmagic. Example:

```powershell
pip install filetype
# or if you prefer libmagic-backed detection and have Chocolatey:
choco install libmagic
pip install python-magic
```

3) Start the Flask backend:
```bash
python run_integrated_system.py
```

Backend runs on `http://127.0.0.1:5000`

### Frontend Setup

4) In another terminal, navigate to frontend and install:
```bash
cd frontend
npm install
```

5) Start Vite dev server:
```bash
npm run dev
```

Frontend runs on `http://127.0.0.1:5173` (proxies API calls to backend)

6) Open `http://127.0.0.1:5173` in your browser

---

## 🧭 Common Commands

**Backend:**
```bash
# Activate venv (Windows)
.\venv\Scripts\Activate.ps1

# Activate venv (Linux/Mac)
source venv/bin/activate

# Deactivate
deactivate

# Check YARA status
python -c "import yara; print('YARA OK')"
```

**Frontend:**
```bash
# Development
npm run dev

# Production build
npm run build
```

---

## 📦 System Components

### Backend
- `app.py`: Flask application and REST API
- `run_integrated_system.py`: Server launcher
- `detection/`: YARA scanner and anomaly detection (Isolation Forest)
- `monitor/`: Process, network, file system monitors (watchdog, psutil)
- `mitigation/`: Threat response actions (kill process, quarantine)
- `utils/`: Modular file scanner (MIME detection, archive extraction, heuristics)
- `yara_rules/`: Signature rules (PE, UPX, PowerShell, crypto miner, EICAR test)

### Frontend
- `frontend/src/App.jsx`: Main app router
- `frontend/src/pages/`: Dashboard, FileScanPage, URLTestPage
- `frontend/src/components/`: Reusable UI components (Card, Badge, EventCards, Layout)
- `frontend/src/store.js`: Zustand state management (events, incidents, filters)
- `frontend/src/api.js`: Axios client with endpoint definitions
- `frontend/src/index.css`: TailwindCSS + custom animations

---

## 🧪 Testing

### File Scan Test
1. Go to File Scan page in the React app
2. Upload a test file (e.g., a ZIP with suspicious content, EICAR, etc.)
3. View YARA matches, heuristics, macro indicators, archive contents

### Create EICAR Test File
```bash
# Linux/Mac
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > test_eicar.txt

# Windows PowerShell
@'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
'@ > test_eicar.txt

# Test via Python script
python test_upload.py test_eicar.txt
```

### Live Monitoring Test
1. Open Dashboard in React app
2. Click "Connect" to start SSE stream
3. Generate activity (file operations, network connections) on your system
4. Observe real-time events appearing in the dashboard

---

## 🔌 API Endpoints

### Stream & Events
- `GET /api/stream` — SSE real-time event stream (process/network/file samples)
- `GET /api/incidents` — Retrieve all stored incidents

### File Scanning
- `POST /api/upload_scan` — Upload file, return scan results with YARA/heuristics/verdict

### URL Analysis
- `POST /api/test_url` — URL safety analysis (domain reputation, phishing patterns, threat intel)

### Mitigation
- `POST /api/mitigate` — Kill process or quarantine file

### YARA Management
- `POST /api/yara/reload` — Reload YARA rules from disk
- `GET /api/yara/status` — Check YARA engine (yara/fallback/none)

### Path Management
- `GET /api/paths` — Get monitored paths and access status
- `POST /api/paths` — Update monitored paths

### Background Scanning
- `POST /api/scan_paths/start` — Start background directory scan
- `GET /api/scan_paths/status` — Check scan progress
- `POST /api/scan_paths/cancel` — Cancel running scan

---

## 🛠️ Troubleshooting

### Port 5000 already in use
Edit `app.py` and change `app.run(port=5001)`

### Port 5173 already in use (frontend)
Vite will auto-increment; check console output for actual port

### YARA module not found
Fallback to string matching is automatic. Install `yara-python` for full signatures:
```bash
pip install yara-python
```

### Permission errors on file/process monitoring
Run with administrator/root privileges for full system monitoring

### React dev server not proxying API calls
1. Check that Flask backend is running on `http://127.0.0.1:5000`
2. Verify `frontend/vite.config.js` proxy settings point to correct backend
3. Check browser console for CORS errors

### PowerShell execution policy blocks activation
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
```

### RAR extraction fails on Windows
Install 7-Zip or UnRAR and ensure `7z.exe` or `unrar.exe` is in PATH. The scanner will attempt automatic fallback to 7z CLI.

---

## ⚠️ Notes

- **Elevated Privileges**: Full process/network monitoring requires admin/root
- **Development System**: Intended for learning; harden before production
- **False Positives**: YARA rules and heuristics may flag benign files; tune as needed
- **Archive Extraction**: RAR requires 7z.exe or unrar in PATH; graceful fallback if unavailable
- **MIME Detection**: Uses `python-magic` for libmagic-backed detection. If `python-magic` is not available or `libmagic` isn't present on Windows, AURA will automatically fall back to the pure-Python `filetype` library (included in `requirements.txt`) for basic MIME detection. If you'd like `python-magic` on Windows, install a system `libmagic` (e.g. via Chocolatey) or try `python-magic-bin` if your Python version supports it.
- **Removed PyQt6**: Desktop launcher replaced by modern React frontend

---

## 📊 File Type Support Matrix

| Type | YARA | Heuristics | Entropy | Decode | Macros | EXIF | Archive |
|------|------|-----------|--------|--------|--------|------|---------|
| Executable (.exe, .dll) | ✅ | ✅ | ✅ | — | — | — | — |
| Script (.ps1, .bat, .js, .vbs) | ✅ | ✅ | ✅ | ✅ | — | — | — |
| Document (.pdf, .docx, .xlsx, .json, .xml) | — | ✅ | ❌ | — | ✅ | — | — |
| Archive (.zip, .tar, .tar.gz, .7z, .rar) | — | ✅ | — | — | — | — | ✅ |
| Image (.png, .jpg, .jpeg, .gif) | — | — | — | — | — | ✅ | — |

---

## 🚀 Production Deployment

### Build React Frontend
```bash
cd frontend
npm run build
# Output in frontend/dist/
```

### Serve from Flask
Copy frontend build to static folder and update Flask to serve React index.html, or use separate nginx reverse proxy.

### Set Environment Variables
```bash
FLASK_ENV=production
YARA_RULES_PATH=/path/to/yara/rules
WATCH_PATHS=/critical/paths/to/monitor
```

---

Happy Monitoring! 🛡️


